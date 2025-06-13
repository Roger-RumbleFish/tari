use chrono::Utc;

use tari_common_types::{
    key_branches::TransactionKeyManagerBranch, tari_address::TariAddress, transaction::TxId, types::{CompressedCommitment, CompressedPublicKey}
};

use tari_script::{CompressedCheckSigSchnorrSignature, ExecutionStack, Opcode, TariScript};
use tari_utilities::hex::{self, Hex};

use tari_crypto::{compressed_key::CompressedKey, keys::PublicKey, ristretto::RistrettoPublicKey};

use std::fs;
use minotari_wallet::{
    output_manager_service::{handle::OutputManagerHandle, storage::models::DbWalletOutput, UtxoSelectionCriteria},
    storage::sqlite_utilities::WalletDbConnection, transaction_service::handle::TransactionServiceHandle,
};
use tari_core::transactions::{
    tari_amount::{self, MicroMinotari, Minotari}, transaction_components::{encrypted_data::PaymentId, WalletOutputBuilder}, transaction_key_manager::{
        storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
        TariKeyId,
        TransactionKeyManagerInterface,
        TransactionKeyManagerWrapper,
    }
};
use tari_utilities::ByteArray;
use crate::{automation::{error::CommandError, utils::out_dir}, cli::{ CreateMultisigUtxoTransferLeaderArgs, LeaderCommitmentSignature, MemberCommitmentSignature, MultisigLeaderPartyOutput, MultisigMemberPartyOutput, MultisigPartyOutput}};
use crate::cli::{CreateMultisigUtxoArgs, MultisigOutput};

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
            sender_offset_public_key: sender_offset_key.pub_key,
            sender_offset_public_nonce_key: sender_offset_nonce_key.pub_key,
        });

        member_commitment_signatures.push(MemberCommitmentSignature {
            signature: script_input_signature.clone(),
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

pub fn is_multisig_utxo(tari_script: &TariScript) -> bool {
    tari_script.script.iter().any(|op| matches!(op, Opcode::CheckMultiSigVerifyAggregatePubKey(..)))
}

pub fn get_utxo_by_commitment_hash(
    utxos: &[minotari_wallet::output_manager_service::storage::models::DbWalletOutput],
    commitment_hash: String,
) -> Option<&minotari_wallet::output_manager_service::storage::models::DbWalletOutput> {
    utxos.iter().find(|utxo| utxo.commitment.to_hex() == commitment_hash)
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
            Opcode::CheckMultiSigVerifyAggregatePubKey(m, n, public_keys, message),
        ])?;

        let script_key = key_manager_service
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .unwrap();


        let utxo_value = MicroMinotari::from(utxo.wallet_output.value);
        let commitment_mask = key_manager_service.get_next_key(TransactionKeyManagerBranch::CommitmentMask.get_branch_key()).await.unwrap();
        let input_selection = UtxoSelectionCriteria::default();
        let payment_id = PaymentId::default();
        // Create the unblinded output
        let output_builder = WalletOutputBuilder::new(utxo_value, commitment_mask.key_id)
            .with_script(script.clone())
            .with_script_key(script_key.key_id)
            .with_input_data(ExecutionStack::default());


        let (tx_id, transaction) = output_service.create_send_to_self_with_output(vec![output_builder], MicroMinotari::from(1), input_selection, payment_id.clone())
        .await
        .map_err(|e| CommandError::General(format!("Failed to send to self: {}", e)))?;

        transaction_service
            .submit_transaction(tx_id, transaction, utxo_value, payment_id.clone())
            .await
            .map_err(|e| CommandError::General(format!("Failed to submit transaction: {}", e)))?;

         Ok(tx_id)
}

pub async fn collect_multisig_utxo_encumber(session_id: String) -> Result<(), CommandError> {
    let mut signatures = Vec::new();
    let mut public_nonces = Vec::new();
    let mut public_keys = Vec::new();

    let output: MultisigOutput = read_multisig_output(session_id.clone()).await
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;


    let user_keys = output.parties_public_keys;

    let out_dir = std::path::Path::new("/wallet_data");

    for pubkey in &user_keys {
        let member_file = out_dir.join(format!(
            "multisig_party_output-member-{}-{}.json",
            session_id,
            pubkey.as_compressed().to_hex()
        ));
        if !member_file.exists() {
            return Err(CommandError::General(format!(
                "Missing member file: {}",
                member_file.display()
            )));
        }
    
        let file: fs::File = std::fs::File::open(&member_file)?;
        let member_output: MultisigMemberPartyOutput = serde_json::from_reader(file)
            .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        for sig in member_output.commitment_signatures {
            signatures.push(sig.signature.clone());
            public_nonces.push(sig.sender_offset_nonce_key.clone());
            public_keys.push(member_output.member_public_key.clone());
        }
    }


    print!("Collected {} signatures, {} public nonces, and {} public keys for session {}", signatures.len(), public_nonces.len(), public_keys.len(), session_id);
    Ok(())
}