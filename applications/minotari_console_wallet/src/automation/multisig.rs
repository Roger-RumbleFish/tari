use chrono::Utc;


use sha2::Sha256;
use digest::Digest;
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch, tari_address::TariAddress, transaction::TxId, types::{CompressedPublicKey, FixedHash, UncompressedCommitment, UncompressedPublicKey}
};

use tari_core::{borsh::SerializedSize, consensus::{ConsensusConstants}, covenants::Covenant, transactions::{fee::Fee, transaction_components::{KernelFeatures, Transaction}, transaction_key_manager::TariKeyAndId, transaction_protocol::sender::TransactionSenderMessage, CryptoFactories, ReceiverTransactionProtocol, SenderTransactionProtocol}};

use tari_core::transactions::transaction_components::RangeProofType;

use tari_common_types::{
    types::{
        CompressedCommitment,
    },
};

use tari_core::transactions::{
    transaction_components::{

        OutputFeatures,

    },
};

use tari_comms::types::CommsDHKE;
use tari_utilities::hex::{self, Hex};
use tari_script::{push_pubkey_script, script, CompressedCheckSigSchnorrSignature, ExecutionStack, Opcode, StackItem, TariScript};


use tari_crypto::{compressed_key::CompressedKey, ristretto::{RistrettoPublicKey, RistrettoSecretKey}};

use std::{collections::HashMap, fs};
use minotari_wallet::{
    output_manager_service::{error::OutputManagerError, handle::OutputManagerHandle, storage::{models::DbWalletOutput}, UtxoSelectionCriteria},
    storage::{sqlite_utilities::WalletDbConnection}, transaction_service::handle::TransactionServiceHandle,
};
use tari_core::{one_sided::{public_key_to_output_encryption_key, shared_secret_to_output_encryption_key, shared_secret_to_output_spending_key}, transactions::{
    tari_amount::{self, MicroMinotari}, transaction_components::{encrypted_data::PaymentId, EncryptedData, WalletOutput, WalletOutputBuilder}, transaction_key_manager::{
        storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
        TariKeyId,
        TransactionKeyManagerInterface,
        TransactionKeyManagerWrapper,
    }
}};
use tari_utilities::ByteArray;
use crate::{automation::{error::CommandError}, cli::{ CreateMultisigUtxoTransferLeaderArgs, LeaderCommitmentSignature, MemberCommitmentSignature, MultisigEncumberOutput, MultisigLeaderPartyOutput, MultisigMemberPartyOutput, MultisigPartyOutput}};
use crate::cli::{MultisigOutput};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AggregatedSignature {
    pub aggregated_signature: CompressedCheckSigSchnorrSignature,
    pub aggregated_nonce: TariKeyId,
    pub public_keys: Vec<CompressedKey<RistrettoPublicKey>>,
}

#[allow(dead_code)]
pub async fn select_utxos_for_amount(
    output_service: &mut OutputManagerHandle,
    target: u64,
) -> Result<Vec<minotari_wallet::output_manager_service::storage::models::DbWalletOutput>, CommandError> {
    let mut utxos = output_service.get_unspent_outputs().await
        .map_err(CommandError::OutputManagerError)?;

    // Sort UTXOs by value (ascending)
    utxos.sort_by(|a, b| a.wallet_output.value.cmp(&b.wallet_output.value));

    let mut selected_utxos = Vec::new();
    let mut total = 0u64;

    for utxo in &utxos {
        selected_utxos.push(utxo.clone());
        total += utxo.wallet_output.value.as_u64();
        if total >= target {
            break;
        }
    }

    if total < target {
        eprintln!("Not enough funds: needed {}, available {}", target, total);
        return Err(CommandError::OutputManagerError(
            minotari_wallet::output_manager_service::error::OutputManagerError::NotEnoughFunds,
        ));
    }


    Ok(selected_utxos)
}

pub async fn create_multisig_output(output_service: &mut OutputManagerHandle, args: CreateMultisigUtxoTransferLeaderArgs) -> Result<MultisigOutput, CommandError> {
    let date_time = Utc::now();
    let session_id = format!("{}", date_time.format("%Y%m%d%H%M%S"));

    let utxos = output_service.get_unspent_outputs().await
        .map_err(CommandError::OutputManagerError)?;

    let selected_utxo = get_utxo_by_commitment_hash(&utxos, args.utxo_commitment_hash.clone()).ok_or(CommandError::General(format!(
        "UTXO with commitment hash {} not found",
        args.utxo_commitment_hash
    )))?;

    let utxo_hashes = vec![selected_utxo.hash.to_hex()];
    let utxo_commitments = vec![selected_utxo.commitment.to_hex()];

    // Bring back later on when resolve multiple utxos
    // let utxo_hashes = utxos.iter().map(|utxo| utxo.hash.to_hex()).collect::<Vec<_>>();

    // let utxo_commitments = utxos.iter()
    //     .map(|utxo| utxo.commitment.to_hex())
    //     .collect::<Vec<_>>();

    let multisig_output = MultisigOutput {
        session_id: session_id.clone(),
        utxos: utxo_hashes,
        commitments: utxo_commitments,
        fee_per_gram: tari_amount::MicroMinotari::from(1),
        minimum_signatures: args.m,
        recipient_address: args.recipient_address.clone(),
        parties_public_keys: args.public_keys,
        value: selected_utxo.wallet_output.value,
    };


    Ok(multisig_output)
}

pub async fn create_multisig_party_member_output(key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>, session_id: String) -> Result<MultisigPartyOutput, CommandError> {
    let spend_key = key_manager_service.get_spend_key().await?;
    let public_key = spend_key.pub_key.clone();

    let config = read_multisig_output(session_id.clone()).await
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        print!("User public key: {}", public_key.to_hex());
    let member_public_key = config.parties_public_keys.iter()
        .find(|key| key.as_compressed().eq(&public_key))
        .ok_or(CommandError::PartyMemberNotFound)?;

    let recipient_public_view_key = config.recipient_address.public_view_key()
        .ok_or(CommandError::InvalidArgument("Missing public view key".to_string()))?;

    let mut leader_commitment_signatures: Vec<LeaderCommitmentSignature> = Vec::new();
    let mut member_commitment_signatures: Vec<MemberCommitmentSignature> = Vec::new();

    for (output_index, commitment_hex) in config.commitments.iter().enumerate() {
        let script_nonce_key = key_manager_service.get_random_key().await?;
        let sender_offset_key = key_manager_service.get_random_key().await?;
        let sender_offset_nonce_key = key_manager_service.get_random_key().await?;

        let commitment_bytes = hex::from_hex(commitment_hex)
            .map_err(|e| CommandError::InvalidArgument(format!("Invalid commitment hex: {}", e)))?;


        let script_key_id = TariKeyId::Managed {
            branch: TransactionKeyManagerBranch::Spend.get_branch_key(),
            index: output_index as u64,
        };

        let script_input_signature = key_manager_service
            .sign_script_message(&script_key_id, &commitment_bytes)
            .await?;

        // Computes a Diffie-Hellman shared secret with the recipient's public view key.
        let shared_secret = key_manager_service
            .get_diffie_hellman_shared_secret(
                &sender_offset_key.key_id,
                &recipient_public_view_key,
            )
            .await?;

        let shared_secret_public_key = CompressedPublicKey::from_canonical_bytes(shared_secret.as_bytes())?;

        leader_commitment_signatures.push(LeaderCommitmentSignature {
            signature: script_input_signature.clone(),
            shared_secret_public_key: shared_secret_public_key,
            script_nonce_key: script_nonce_key.pub_key,
            sender_offset_public_key: sender_offset_key.pub_key,
            sender_offset_public_nonce_key: sender_offset_nonce_key.pub_key,
        });

        member_commitment_signatures.push(MemberCommitmentSignature {
            signature: script_input_signature.clone(),
            script_nonce_key_id: script_nonce_key.key_id,
            secret_key: script_key_id,
            sender_offset_key: sender_offset_key.key_id,
            sender_offset_nonce_key: sender_offset_nonce_key.key_id,
        });
    }

    let multisig_leader_party_output = MultisigLeaderPartyOutput {
        session_id: session_id.clone(),
        commitment_signatures: leader_commitment_signatures,
        member_public_key: member_public_key.as_compressed().clone(),
    };

    let multisig_member_party_output = MultisigMemberPartyOutput {
        session_id: session_id.clone(),
        member_public_key: member_public_key.as_compressed().clone(),
        commitment_signatures: member_commitment_signatures,
    };

    Ok(MultisigPartyOutput { leader: multisig_leader_party_output, member: multisig_member_party_output })
}

pub async fn save_multisig_output(multisig_output: MultisigOutput) -> Result<(), CommandError> {
    let output = multisig_output.clone();

    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let out_file = out_dir.join(format!("multisig_output-{}.json", output.session_id));

    print!("Saving multisig output to: {}", out_file.display());
    let file = fs::File::create(&out_file)?;
    serde_json::to_writer_pretty(file, &output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub async fn save_multisig_party_output(multisig_output: MultisigPartyOutput) -> Result<(), CommandError> {
    let leader_output = multisig_output.leader.clone();
    let member_output = multisig_output.member.clone();

    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

   // Save leader output (include user address in filename)
    let leader_file = out_dir.join(format!(
        "multisig_party_output-leader-{}-{}.json",
        leader_output.session_id,
        leader_output.member_public_key.to_hex()
    ));
    println!("Saving multisig leader party output to: {}", leader_file.display());
    let file = fs::File::create(&leader_file)?;
    serde_json::to_writer_pretty(file, &leader_output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Save member output (also include user address in filename)
    let member_file = out_dir.join(format!(
        "multisig_party_output-member-{}-{}.json",
        member_output.session_id,
        member_output.member_public_key.to_hex()
    ));
    println!("Saving multisig member party output to: {}", member_file.display());
    let file = fs::File::create(&member_file)?;
    serde_json::to_writer_pretty(file, &member_output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub async fn read_multisig_output(session_id: String) -> Result<MultisigOutput, CommandError> {

    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let file_path = std::path::Path::new("/wallet_data").join(format!("multisig_output-{}.json", session_id));


    let file = fs::File::open(file_path)?;
    let multisig_output: MultisigOutput = serde_json::from_reader(file)
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    Ok(multisig_output)
}

pub fn load_leader_party_output(
    session_id: &str,
    pubkey: CompressedKey<RistrettoPublicKey>,
) -> Result<MultisigLeaderPartyOutput, CommandError> {
        let out_dir = std::path::Path::new("/wallet_data");

    let member_file = out_dir.join(format!(
        "multisig_party_output-leader-{}-{}.json",
        session_id,
        pubkey.to_hex(),
    ));
    if !member_file.exists() {
        return Err(CommandError::General(format!(
            "Missing member file: {}",
            member_file.display()
        )));
    }

    let file: fs::File = std::fs::File::open(&member_file)?;
    let member_output: MultisigLeaderPartyOutput = serde_json::from_reader(file)
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    Ok(member_output)
}

pub fn is_multisig_utxo(tari_script: &TariScript) -> bool {
    tari_script.script.iter().any(|op| matches!(op, Opcode::CheckMultiSigVerifyAggregatePubKey(..)))
}

pub fn get_utxo_by_commitment_hash(
    utxos: &[minotari_wallet::output_manager_service::storage::models::DbWalletOutput],
    commitment_hash: String,
) -> Option<&minotari_wallet::output_manager_service::storage::models::DbWalletOutput> {
    utxos.iter().find(|utxo| utxo.commitment.to_hex() == commitment_hash)
}

fn sum_public_keys(public_keys: &[CompressedKey<RistrettoPublicKey>]) -> Result<RistrettoPublicKey, CommandError> {
    let mut sum = UncompressedPublicKey::default();
    for key in public_keys {
        sum = &sum + key.to_public_key()?;
    }
    Ok(sum)
}

fn sum_public_keys_to_encryption_key(public_keys: &[CompressedKey<RistrettoPublicKey>]) -> Result<(RistrettoSecretKey), CommandError> {
    let sum_public_keys = sum_public_keys(public_keys)?;

    let encryption_private_key =
        public_key_to_output_encryption_key(&CompressedPublicKey::new_from_pk(sum_public_keys))?;

    Ok(encryption_private_key)
}

pub async fn derive_multisig_recovery_key_id<KM: TransactionKeyManagerInterface>(
    public_keys: &[CompressedKey<RistrettoPublicKey>],
    key_manager: &KM,
) -> Result<TariKeyId, CommandError> {
    let encryption_key = sum_public_keys_to_encryption_key(public_keys)
        .map_err(|e| CommandError::General(format!("Failed to sum public keys: {}", e)))?;

    let encryption_key_id = key_manager.import_key(encryption_key).await?;

    Ok(encryption_key_id) 
}

pub async fn make_utxo_multisig(
    output_service: &mut OutputManagerHandle,
    transaction_service: &mut TransactionServiceHandle,
    key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    utxo: DbWalletOutput,
    m: u8,
    n: u8,
    public_keys: Vec<CompressedKey<RistrettoPublicKey>>,
) -> Result<TxId, CommandError> {
        let commitment_bytes: [u8; 32] = utxo.commitment.as_bytes().try_into()
            .map_err(|_| CommandError::General("Commitment is not 32 bytes".to_string()))?;
        let message: Box<[u8; 32]> = Box::new(commitment_bytes);
    
        let script = TariScript::new(vec![
            Opcode::CheckMultiSigVerifyAggregatePubKey(m, n, public_keys.clone(), message),
        ])?;

        let script_key = key_manager_service
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .unwrap();


        let utxo_value = MicroMinotari::from(utxo.wallet_output.value);
        let commitment_mask = key_manager_service.get_next_key(TransactionKeyManagerBranch::CommitmentMask.get_branch_key()).await.unwrap();
        let input_selection = UtxoSelectionCriteria::default();
        let payment_id = PaymentId::default();
        let custom_recover_key = derive_multisig_recovery_key_id(
            &public_keys.clone(),
            &key_manager_service,
        ).await?;

        // Create the unblinded output
        let output_builder = WalletOutputBuilder::new(utxo_value, commitment_mask.key_id)
            .with_script(script.clone())
            .with_features(OutputFeatures::default())
            .with_script_key(script_key.key_id)
            .with_input_data(ExecutionStack::default())
            .encrypt_data_for_recovery(
                &key_manager_service,                
                Some(&custom_recover_key),
                payment_id.clone(),
            ).await
            .unwrap();

        let (tx_id, transaction) = output_service.create_send_to_self_with_output(vec![output_builder], MicroMinotari::from(1), input_selection, payment_id.clone())
        .await
        .map_err(|e| CommandError::General(format!("Failed to send to self: {}", e)))?;

        println!("Transaction created with ID: {}", tx_id);

        transaction_service
            .submit_transaction(tx_id, transaction, utxo_value, payment_id.clone())
            .await
            .map_err(|e| CommandError::General(format!("Failed to submit transaction: {}", e)))?;

         Ok(tx_id)
}

pub async fn collect_multisig_utxo_encumber(
    output_service:  OutputManagerHandle,
    key_manager: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    consensus_constants: &ConsensusConstants,
    session_id: String,
    own_address: TariAddress) -> Result<Vec<MultisigEncumberOutput>, CommandError> {

    // Read multisig session config
    let output: MultisigOutput = read_multisig_output(session_id.clone()).await
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    // Prepare containers for all shares
    let mut signatures = Vec::new();
    let mut public_sender_nonces = Vec::new();
    let mut public_offset_nonces = Vec::new();
    let mut public_keys = Vec::new();
    let mut public_offset_public_keys = Vec::new();
    let mut shared_secret_public_keys = Vec::new();
    let mut input_shares = HashMap::new();

    for pubkey in &output.parties_public_keys {

        // skip own address

        if own_address.public_spend_key() == pubkey.as_compressed() {
            println!("Skipping own address: {}", own_address);
            continue;
        }
    
        let member_output = load_leader_party_output(&session_id, pubkey.as_compressed().clone())?;

        for sig in member_output.commitment_signatures {
            signatures.push(sig.signature.clone());
            public_sender_nonces.push(sig.script_nonce_key.clone());
            public_offset_nonces.push(sig.sender_offset_public_nonce_key.clone());
            public_keys.push(member_output.member_public_key.clone());
            shared_secret_public_keys.push(sig.shared_secret_public_key.clone());
            public_offset_public_keys.push(sig.sender_offset_public_key.clone());
            input_shares.insert(pubkey.as_compressed().clone(), sig.signature.clone());
        }
    }

    let utxos = output_service.clone().get_unspent_outputs().await
            .map_err(CommandError::OutputManagerError)?;
        

    let mut encumber_outputs = Vec::new();

    for (current_index, commitment) in output.commitments.iter().enumerate() {
        println!("\nProcessing UTXO commitment {} of {}: {}", current_index + 1, output.utxos.len(), commitment);
        let utxo = get_utxo_by_commitment_hash(&utxos, commitment.clone())
            .ok_or_else(|| CommandError::General(format!("UTXO not found in output: {}", commitment)))?;

        println!("\nUTXO found: {} with commitment: {}", utxo.hash.to_hex(), utxo.commitment.to_hex());
      
        let result = encumber_aggregate_utxo(
            output_service.clone(),
            key_manager.clone(),
            consensus_constants.clone(),
            false,
            own_address.clone(),
            &session_id,
            MicroMinotari::from(1),
            utxo.commitment.clone(),
            input_shares.clone(),
            public_sender_nonces.clone(),
            public_offset_public_keys.clone(),
            public_offset_nonces.clone(), // good
            shared_secret_public_keys.clone(), // good
            output.recipient_address.clone(),
            utxo.payment_id.clone(), // ??
            utxo.mined_height.ok_or(CommandError::General("UTXO mined height is missing".to_string()))?, // good
            RangeProofType::BulletProofPlus,
            MicroMinotari::zero(), // minimum value promise, can be zero for now
            utxo.hash,
        ).await;

        match result {
            Ok((
                transaction,
                _amount,
                _fee,
                total_script_public_key,
                total_metadata_ephemeral_public_key,
                total_script_nonce,
                shared_secret_public_key,
            )) => {
                println!("\nEncumbered aggregate transaction successfully created with ID: {}", transaction);
                encumber_outputs.push(MultisigEncumberOutput {
                    output_index: current_index,
                    input_stack: transaction.body.inputs()[0].clone().input_data,
                    input_script: transaction.body.inputs()[0].script().unwrap().clone(),
                    total_script_key: total_script_public_key,
                    script_signature_ephemeral_commitment: transaction.body.inputs()[0]
                        .script_signature
                        .ephemeral_commitment()
                        .clone(),
                    script_signature_ephemeral_pubkey: total_script_nonce,
                    output_commitment: transaction.body.outputs()[0].commitment().clone(),
                    sender_offset_pubkey: transaction.body.outputs()[0].clone().sender_offset_public_key,
                    metadata_signature_ephemeral_commitment: transaction.body.outputs()[0]
                        .metadata_signature
                        .ephemeral_commitment()
                        .clone(),
                    metadata_signature_ephemeral_pubkey: total_metadata_ephemeral_public_key,
                    encrypted_data: transaction.body.outputs()[0].clone().encrypted_data,
                    output_features: transaction.body.outputs()[0].clone().features,
                    shared_secret: shared_secret_public_key,
                });
            },
            Err(e) => {
                eprintln!("\nError: Encumber aggregate transaction error! {}\n", e);
            },
        }
    }

    Ok(encumber_outputs)
}

pub async fn save_multisig_utxo_encumber(
   outputs: Vec<MultisigEncumberOutput>
) -> Result<(), CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    println!("Saving multisig encumber length: {}", outputs.len());

    // Save all encumber outputs to a single file
    let out_file = out_dir.join("multisig_utxo_encumber_outputs.json");
    println!("Saving multisig encumber outputs to: {}", out_file.display());
    let file = fs::File::create(&out_file)?;
    serde_json::to_writer_pretty(file, &outputs)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}


fn get_multi_sig_script_components(
    script: &TariScript,
    tx_id: TxId,
) -> Result<(Vec<CompressedPublicKey>, u8), OutputManagerError> {
    for op in script.as_slice() {
        if let Opcode::CheckMultiSigVerifyAggregatePubKey(m, _n, keys, _msg) = op {
            return Ok((keys.clone(), *m));
        }
    }
    Err(OutputManagerError::ServiceError(format!(
        "Invalid script (TxId: {})",
        tx_id
    )))
}

async fn get_multisig_script_key(
    key_manager: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    session_id: &str,
) -> Result<TariKeyAndId, CommandError> {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    let hash = hasher.finalize();
    let index = u64::from_le_bytes(hash[..8].try_into().unwrap());
    let script_key_id = TariKeyId::Managed {
        branch: TransactionKeyManagerBranch::SenderOffset.get_branch_key(),
        index,
    };

    let pub_key = key_manager
        .get_public_key_at_key_id(&script_key_id)
        .await
        .map_err(|e| CommandError::General(format!("Failed to get public key: {}", e)))?;

    Ok(TariKeyAndId {
        pub_key,
        key_id: script_key_id,
    })
}

/// Create a partial transaction in order to prepare output
#[allow(clippy::too_many_lines)]
#[allow(clippy::mutable_key_type)]
pub async fn encumber_aggregate_utxo(
    output_service: OutputManagerHandle,
    key_manager: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    consensus_constants: ConsensusConstants,
    prevent_fee_gt_amount: bool,
    own_address: TariAddress,
    session_id: &str,
    fee_per_gram: MicroMinotari,
    expected_commitment: CompressedCommitment,
    mut script_input_shares: HashMap<CompressedPublicKey, CompressedCheckSigSchnorrSignature>,
    script_signature_public_nonces: Vec<CompressedPublicKey>,
    sender_offset_public_key_shares: Vec<CompressedPublicKey>,
    metadata_ephemeral_public_key_shares: Vec<CompressedPublicKey>,
    dh_shared_secret_shares: Vec<CompressedPublicKey>,
    recipient_address: TariAddress,
    tx_payment_id: PaymentId,
    original_maturity: u64,
    range_proof_type: RangeProofType,
    minimum_value_promise: MicroMinotari,
    output_hash: FixedHash,
) -> Result<
    (
        Transaction,
        MicroMinotari,
        MicroMinotari,
        CompressedPublicKey,
        CompressedPublicKey,
        CompressedPublicKey,
        CompressedPublicKey,
    ),
    CommandError,
> {

    let tx_id = TxId::new_random();
    let mut current_output_service = output_service.clone();
    let key_manager = key_manager.clone();
    // Fetch the output from the blockchain
    let output = current_output_service
        .fetch_unspent_outputs_from_node(vec![output_hash])
        .await?
        .pop()
        .ok_or_else(|| {
            CommandError::InvalidArgument(format!(
                "Output with hash {} not found in blockchain (TxId: {})",
                output_hash, tx_id
            ))
        })?;

    if output.commitment != expected_commitment {
        return Err(CommandError::InvalidArgument(format!(
            "Output commitment does not match expected commitment (TxId: {})",
            tx_id
        )));
    }

    // Retrieve the list of n public keys from the script
    let (multi_sig_public_keys, threshold) = get_multi_sig_script_components(&output.script, tx_id)?;
    let encryption_private_key = sum_public_keys_to_encryption_key(&multi_sig_public_keys)?;

    println!("encryption_private_key: {}", encryption_private_key.to_hex());
    println!("output.encrypted_data: {}", output.encrypted_data.to_hex());
    let mut aggregated_script_public_key_shares = UncompressedPublicKey::default();


    // Decrypt the output secrets and create a new input as WalletOutput (unblinded)
    let (input, payment_id) = if let Ok((amount, commitment_mask, payment_id)) =
        EncryptedData::decrypt_data(&encryption_private_key, &output.commitment, &output.encrypted_data)
    {
        println!("encumber_aggregate_utxo: decrypted output {} {} {}", amount, commitment_mask.to_hex(), payment_id);
        let factories = CryptoFactories::default();
        let range_proof_factory = factories.range_proof.clone();

        if output.verify_mask(&range_proof_factory, &commitment_mask, amount.as_u64())? {
            let script_key = get_multisig_script_key(key_manager.clone(), session_id).await?;
            let script_key_id = script_key.key_id.clone();

            let mut script_signatures = Vec::new();
            // lets add our own signature to the list
            let self_signature = key_manager
                .sign_script_message(&script_key_id, output.commitment.as_bytes())
                .await?;

            script_input_shares.insert(script_key.pub_key.clone(), self_signature);

            // the order here is important, we need to add the signatures in the same order as public keys were
            // added to the script originally
            for key in &multi_sig_public_keys {
                if let Some(signature) = script_input_shares.get(key) {
                    script_signatures.push(StackItem::Signature(signature.clone()));
                    // our own key should not be aggregated yet, it will be added with the script signing
                    if key != &script_key.pub_key {
                        aggregated_script_public_key_shares =
                            aggregated_script_public_key_shares + key.to_public_key()?;
                    }
                }
            }

            if script_signatures.len() != usize::from(threshold) {
                return Err(CommandError::InvalidArgument(format!(
                    "Invalid number of signatures (TxId: {}), expected {}, received {}",
                    tx_id,
                    threshold,
                    script_signatures.len()
                )));
            }

            let commitment_mask_key_id = key_manager.import_key(commitment_mask).await?;
            (
                WalletOutput::new_with_rangeproof(
                    output.version,
                    amount,
                    commitment_mask_key_id,
                    output.features,
                    output.script,
                    ExecutionStack::new(script_signatures),
                    script_key.key_id.clone(), // Only of the master wallet
                    output.sender_offset_public_key,
                    output.metadata_signature,
                    0,
                    output.covenant,
                    output.encrypted_data,
                    output.minimum_value_promise,
                    output.proof,
                    payment_id.clone(),
                ),
                payment_id,
            )
        } else {
            return Err(CommandError::InvalidArgument(format!(
                "Could not verify mask (TxId: {})",
                tx_id
            )));
        }
    } else {
        return Err(CommandError::InvalidArgument(format!(
            "Could not decrypt output (TxId: {})",
            tx_id
        )));
    };

        // The entire input will be spent to a single recipient with no change
        let output_features = OutputFeatures {
            maturity: original_maturity,
            range_proof_type: range_proof_type,
            ..Default::default()
        };

        // we assign a temp script to calculate all the sizes for now, we override this with the stealth one later if needed
        let temp_script = script!(PushPubKey(Box::new(recipient_address.public_spend_key().clone())))?;

        let metadata_byte_size = consensus_constants
            .transaction_weight_params()
            .round_up_features_and_scripts_size(
                output_features.get_serialized_size()? +
                    temp_script.get_serialized_size()? +
                    Covenant::default().get_serialized_size()?,
            );

        let fee = Fee::new(*consensus_constants.transaction_weight_params());
        let fee = fee.calculate(fee_per_gram, 1, 1, 1, metadata_byte_size);
        let amount = input.value - fee;
    
        // Create sender transaction protocol builder with recipient data and no change
        let mut builder = SenderTransactionProtocol::builder(
            consensus_constants.clone(),
            key_manager.clone(),
        );

        builder
            .with_lock_height(0)
            .with_fee_per_gram(fee_per_gram)
            .with_kernel_features(KernelFeatures::empty())
            .with_prevent_fee_gt_amount(prevent_fee_gt_amount)
            .with_input(input.clone())
            .await?
            .with_recipient_data(
                push_pubkey_script(recipient_address.public_spend_key()),
                output_features,
                Covenant::default(),
                minimum_value_promise,
                amount,
                recipient_address.clone(),
            )
            .await?
            .with_change_data(
                script!(PushPubKey(Box::default()))?,
                ExecutionStack::default(),
                TariKeyId::default(),
                TariKeyId::default(),
                Covenant::default(),
                own_address,
            )
            .with_payment_id(payment_id);

        let mut stp = builder
            .build()
            .await
            .map_err(|e| OutputManagerError::BuildError(e.message))?;

        stp.change_recipient_sender_offset_private_key(
            key_manager
                .get_next_key(TransactionKeyManagerBranch::OneSidedSenderOffset.get_branch_key())
                .await?
                .key_id,
        ).map_err(|e| CommandError::General(format!("Failed to change recipient sender offset private key: {}", e)))?;

        // This call is needed to advance the state from `SingleRoundMessageReady` to `SingleRoundMessageReady`,
        // but the returned value is not used
        let _single_round_sender_data = stp
            .build_single_round_message(&key_manager)
            .await
            .map_err(|e| CommandError::General(format!("Failed to build single round message: {}", e)))?;
  

         current_output_service.confirm_encumberance(tx_id)
            .await?;

        // Prepare receiver part of the transaction
        // Diffie-Hellman shared secret `k_Ob * K_Sb = K_Ob * k_Sb` results in a public key, which is fed into
        // KDFs to produce the spending and encryption keys. All player's shares are added together to produce the
        // shared secret.
        let sender_offset_private_key_id_self =
            stp.get_recipient_sender_offset_private_key()
                .map_err(|e| CommandError::General(format!("Failed to get recipient sender offset private key (TxId: {}): {}", tx_id, e)))?
                .ok_or(CommandError::General(format!(
                    "Missing sender offset private key ID (TxId: {})",
                    tx_id

                )))?;

        let shared_secret = {
            let mut key_sum = UncompressedPublicKey::default();
            for key in &dh_shared_secret_shares {
                key_sum = key_sum + key.to_public_key()?;
            }

            let shared_secret_self = key_manager
                .get_diffie_hellman_shared_secret(
                    &sender_offset_private_key_id_self,
                    recipient_address
                        .public_view_key()
                        .ok_or(CommandError::General(format!(
                            "Missing public view key (TxId: {})",
                            tx_id
                        )))?,
                )
                .await?;
            key_sum = key_sum + &UncompressedPublicKey::from_vec(&shared_secret_self.as_bytes().to_vec())?;
            CommsDHKE::from_canonical_bytes(key_sum.as_bytes())?
        };

        let spending_key = shared_secret_to_output_spending_key(&shared_secret)?;
        let spending_key_id = key_manager.import_key(spending_key).await?;

        let encryption_private_key = shared_secret_to_output_encryption_key(&shared_secret)?;
        let encryption_key_id = key_manager.import_key(encryption_private_key).await?;

        let sender_offset_public_key_self = key_manager
            .get_public_key_at_key_id(&sender_offset_private_key_id_self)
            .await?;

        let aggregated_sender_offset_public_key_shares = sum_public_keys(&sender_offset_public_key_shares)?;

        let sender_offset_public_key =
            &aggregated_sender_offset_public_key_shares + sender_offset_public_key_self.to_public_key()?;

        let sender_message = TransactionSenderMessage::new_single_round_message(
            stp.get_single_round_message(&key_manager)
                .await
                .map_err(|e| CommandError::General(format!("Failed to get single round message: {}", e)))?,
        );

        let aggregated_metadata_ephemeral_public_key_shares = sum_public_keys(&metadata_ephemeral_public_key_shares)?;

        let script_spending_key = key_manager
            .stealth_address_script_spending_key(&spending_key_id, recipient_address.public_spend_key())
            .await?;

        let script = push_pubkey_script(&script_spending_key);

        // Create the output with a partially signed metadata signature
        let output = WalletOutputBuilder::new(amount, spending_key_id)
            .with_features(
                sender_message
                    .single()
                    .ok_or(
                        OutputManagerError::InvalidSenderMessage)?
                    .features
                    .clone(),
            )
            .with_script(script)
            .encrypt_data_for_recovery(
                &key_manager,
                Some(&encryption_key_id),
                tx_payment_id.clone(),
            )
            .await?
            .with_input_data(ExecutionStack::default()) // Just a placeholder in the wallet
            .with_sender_offset_public_key(CompressedPublicKey::new_from_pk(sender_offset_public_key))
            .with_script_key(key_manager.get_spend_key().await?.key_id)
            .with_minimum_value_promise(minimum_value_promise)
            .sign_partial_as_sender_and_receiver(
                &key_manager,
                &sender_offset_private_key_id_self,
                &CompressedPublicKey::new_from_pk(aggregated_sender_offset_public_key_shares),
                &CompressedPublicKey::new_from_pk(aggregated_metadata_ephemeral_public_key_shares.clone()),
            )
            .await
            .map_err(|e| CommandError::General(format!("Error (TxId: {}): {}", tx_id, e)))?
            .try_build(&key_manager)
            .await
            .map_err(|e| CommandError::General(format!("Error (TxId: {}): {}", tx_id, e)))?;


        let total_metadata_ephemeral_public_key = aggregated_metadata_ephemeral_public_key_shares +
            &output.metadata_signature.ephemeral_pubkey().to_public_key()?;

        // Finalize the partial transaction - it will not be valid at this stage as the metadata and script
        // signatures are not yet complete.
        let rtp = ReceiverTransactionProtocol::new(
            sender_message,
            output,
            &key_manager,
            &consensus_constants,
        )
        .await;

        let recipient_reply = rtp.get_signed_data()
            .map_err(|e| CommandError::General(format!("Failed to get signed data: {}", e)))?
            .clone();

        stp.add_presigned_recipient_info(recipient_reply)
            .map_err(|e| CommandError::General(format!("Failed to add presigned recipient info: {}", e)))?;

        stp.finalize(&key_manager)
            .await
            .map_err(|e| CommandError::General(format!("Failed to finalize transaction (TxId: {}): {}", tx_id, e)))?;

        let aggregated_script_signature_public_nonces = sum_public_keys(&script_signature_public_nonces)?;

        // Update the input's script signature
        let (updated_input, total_script_public_key) = input
            .to_transaction_input_with_multi_party_script_signature(
                &CompressedPublicKey::new_from_pk(aggregated_script_signature_public_nonces.clone()),
                &CompressedPublicKey::new_from_pk(aggregated_script_public_key_shares),
                &key_manager,
            )
            .await?;

        let total_script_nonce = aggregated_script_signature_public_nonces +
            &updated_input.script_signature.ephemeral_pubkey().to_public_key()?;

        let mut tx = stp.get_transaction()
            .map_err(|e| CommandError::General(format!("Failed to get transaction: {}", e)))?
            .clone();

        let mut tx_body = tx.body;

        tx_body.update_script_signature(updated_input.commitment()?, updated_input.script_signature.clone())?;
        tx.body = tx_body;

        let fee = stp.get_fee_amount().map_err(|e| CommandError::General(format!("Failed to get fee amount: {}", e)))?;

        // shared secret does not support debug so we manually convert this to a public key
        let shared_secret_bytes = shared_secret.as_bytes();
        let shared_secret_public_key = CompressedPublicKey::from_canonical_bytes(shared_secret_bytes)?;

        // Transaction balance log
        //   sum(output commitments) - sum(input  commitments) =  sum(kernel excesses) + total_offset
        let mut utxo_sum = UncompressedCommitment::default();
        for output in tx.body.outputs() {
            utxo_sum = &utxo_sum + &output.commitment.to_commitment()?;
        }
        for input in tx.body.inputs() {
            utxo_sum = &utxo_sum - &input.commitment()?.to_commitment()?;
        }
        let mut kernel_sum = UncompressedCommitment::default();

        for kernel in tx.body.kernels() {
            kernel_sum = &kernel_sum + &kernel.excess.to_commitment()?;
        }

        Ok((
            tx,
            amount,
            fee,
            total_script_public_key,
            CompressedPublicKey::new_from_pk(total_metadata_ephemeral_public_key),
            CompressedPublicKey::new_from_pk(total_script_nonce),
            shared_secret_public_key,
    ))
    }