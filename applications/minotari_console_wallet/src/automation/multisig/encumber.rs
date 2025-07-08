use std::collections::HashMap;

use chrono::Utc;
use minotari_wallet::{
    output_manager_service::{error::OutputManagerError, handle::OutputManagerHandle},
    storage::sqlite_utilities::WalletDbConnection,
    transaction_service::{handle::TransactionServiceHandle, storage::models::CompletedTransaction},
};
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch,
    tari_address::TariAddress,
    transaction::{TransactionDirection, TransactionStatus, TxId},
    types::{
        CompressedCommitment,
        CompressedPublicKey,
        FixedHash,
        HashOutput,
        UncompressedCommitment,
        UncompressedPublicKey,
    },
};
use tari_comms::types::CommsDHKE;
use tari_core::{
    borsh::SerializedSize,
    consensus::ConsensusConstants,
    covenants::Covenant,
    one_sided::{shared_secret_to_output_encryption_key, shared_secret_to_output_spending_key},
    transactions::{
        fee::Fee,
        tari_amount::MicroMinotari,
        transaction_components::{
            payment_id::PaymentId,
            EncryptedData,
            KernelFeatures,
            OutputFeatures,
            RangeProofType,
            Transaction,
            WalletOutput,
            WalletOutputBuilder,
        },
        transaction_key_manager::{
            storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
            TariKeyId,
            TransactionKeyManagerInterface,
            TransactionKeyManagerWrapper,
        },
        transaction_protocol::sender::TransactionSenderMessage,
        CryptoFactories,
        ReceiverTransactionProtocol,
        SenderTransactionProtocol,
    },
};
use tari_script::{push_pubkey_script, script, CompressedCheckSigSchnorrSignature, ExecutionStack, StackItem};
use tari_utilities::{hex::Hex, ByteArray};

use crate::automation::{
    error::CommandError,
    multisig::{
        io::{load_leader_party_output, load_multisig_output},
        script::{
            get_multi_sig_script_components,
            get_utxo_by_commitment_hash,
            sum_public_keys,
            sum_public_keys_to_encryption_key,
        },
        types::{MultisigEncumberOutput, MultisigOutput},
    },
};

pub async fn collect_multisig_utxo_encumber(
    output_service: OutputManagerHandle,
    transaction_service: TransactionServiceHandle,
    key_manager: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    consensus_constants: &ConsensusConstants,
    session_id: String,
    own_address: TariAddress,
) -> Result<Vec<MultisigEncumberOutput>, CommandError> {
    // Read multisig session config
    let config: MultisigOutput = load_multisig_output(&session_id).await.map_err(|e| {
        eprintln!("Error reading multisig output for session {}: {}", session_id, e);
        CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e))
    })?;

    // Prepare containers for all shares
    let mut public_sender_nonces = Vec::new();
    let mut public_offset_nonces = Vec::new();
    let mut public_offset_public_keys = Vec::new();
    let mut dh_shared_secret_public_keys = Vec::new();
    let mut input_shares = HashMap::new();

    for pubkey in &config.parties_public_keys {
        // skip own address
        if own_address.public_spend_key() == &CompressedPublicKey::from(pubkey.clone()) {
            println!("Skipping own address: {}", own_address);
            continue;
        }

        let member_output = match load_leader_party_output(&session_id, CompressedPublicKey::from(pubkey.clone())) {
            Ok(output) => output,
            Err(e) => {
                println!(
                    "Warning: Could not load leader party output for {}: {}. Skipping.",
                    CompressedPublicKey::from(pubkey.clone()).to_public_key()?.to_hex(),
                    e
                );
                continue;
            },
        };

        for sig in member_output.commitment_signatures {
            public_sender_nonces.push(sig.script_nonce_key.clone());
            public_offset_nonces.push(sig.sender_offset_public_nonce_key.clone());
            dh_shared_secret_public_keys.push(sig.dh_shared_secret_public_key.clone());
            public_offset_public_keys.push(sig.sender_offset_public_key.clone());
            input_shares.insert(sig.ephemeral_pubkey.clone(), sig.signature.clone());
        }
    }

    let utxos = output_service
        .clone()
        .get_unspent_outputs()
        .await
        .map_err(CommandError::OutputManagerError)?;

    let mut encumber_outputs = Vec::new();

    for (current_index, commitment) in config.commitments.iter().enumerate() {
        let utxo = get_utxo_by_commitment_hash(&utxos, commitment.clone())
            .ok_or_else(|| CommandError::General(format!("UTXO not found in output: {}", commitment)))?;

        let result = encumber_aggregate_utxo(
            output_service.clone(),
            transaction_service.clone(),
            key_manager.clone(),
            consensus_constants.clone(),
            false,
            own_address.clone(),
            MicroMinotari::from(1),
            utxo.commitment.clone(),
            input_shares.clone(),
            public_sender_nonces.clone(),
            public_offset_public_keys.clone(),
            public_offset_nonces.clone(), // good
            dh_shared_secret_public_keys.clone(),
            config.recipient_address.clone(),
            utxo.payment_id.clone(), // ??
            utxo.mined_height
                .ok_or(CommandError::General("UTXO mined height is missing".to_string()))?, // good
            RangeProofType::BulletProofPlus,
            MicroMinotari::zero(), // minimum value promise, can be zero for now
            utxo.hash,
        )
        .await;

        match result {
            Ok((
                tx_id,
                transaction,
                _amount,
                _fee,
                total_script_public_key,
                total_metadata_ephemeral_public_key,
                total_script_nonce,
                shared_secret_public_key,
            )) => {
                encumber_outputs.push(MultisigEncumberOutput {
                    tx_id,
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

/// Create a partial transaction in order to prepare output
#[allow(clippy::too_many_lines)]
#[allow(clippy::mutable_key_type)]
pub async fn encumber_aggregate_utxo(
    output_service: OutputManagerHandle,
    transaction_service: TransactionServiceHandle,
    key_manager: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    consensus_constants: ConsensusConstants,
    prevent_fee_gt_amount: bool,
    own_address: TariAddress,
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
        TxId,
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
    let mut transaction_service = transaction_service.clone();
    let mut output_service = output_service.clone();
    let key_manager = key_manager.clone();
    // Fetch the output from the blockchain
    let output = output_service
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
    let (multi_sig_public_keys, threshold) = get_multi_sig_script_components(&output.script)?;

    let encryption_private_key = sum_public_keys_to_encryption_key(&multi_sig_public_keys)?;
    let mut aggregated_script_public_key_shares = UncompressedPublicKey::default();

    // Decrypt the output secrets and create a new input as WalletOutput (unblinded)
    let (input, payment_id) = if let Ok((amount, commitment_mask, payment_id)) =
        EncryptedData::decrypt_data(&encryption_private_key, &output.commitment, &output.encrypted_data)
    {
        let factories = CryptoFactories::default();
        let range_proof_factory = factories.range_proof.clone();

        if output.verify_mask(&range_proof_factory, &commitment_mask, amount.as_u64())? {
            // let script_key = key_manager.get_random_key().await?;
            let spend_key = key_manager.get_spend_key().await?;
            let public_key = spend_key.pub_key.clone();

            let commitment_mask_key_id = key_manager.import_key(commitment_mask.clone().into()).await?;
            let ephemeral_pubkey = key_manager
                .stealth_address_script_spending_key(&commitment_mask_key_id, &public_key.clone())
                .await?;

            let ephemeral_private_key = key_manager
                .stealth_address_script_spending_key_id(&commitment_mask_key_id, &spend_key.key_id)
                .await?;

            let key_id = key_manager.import_key(ephemeral_private_key).await?;

            let mut script_signatures = Vec::new();

            let mut commitment_bytes = [0u8; 32];
            commitment_bytes.clone_from_slice(&output.commitment.as_bytes());

            // lets add our own signature to the list
            let self_signature = key_manager.sign_script_message(&key_id, &commitment_bytes).await?;

            script_input_shares.insert(ephemeral_pubkey.clone(), self_signature);

            // the order here is important, we need to add the signatures in the same order as public keys were
            // added to the script originally
            for key in &multi_sig_public_keys {
                if let Some(signature) = script_input_shares.get(&key) {
                    script_signatures.push(StackItem::Signature(signature.clone()));
                    // our own key should not be aggregated yet, it will be added with the script signing
                    if key != &ephemeral_pubkey {
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
                    key_id.clone(), // Only of the master wallet
                    output.sender_offset_public_key,
                    output.metadata_signature,
                    0,
                    output.covenant,
                    output.encrypted_data,
                    output.minimum_value_promise,
                    output.proof,
                    payment_id.clone(),
                ),
                payment_id.clone(),
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
        range_proof_type,
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
    let mut builder = SenderTransactionProtocol::builder(consensus_constants.clone(), key_manager.clone());

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
            own_address.clone(),
        )
        .with_payment_id(payment_id.clone());

    let mut stp = builder
        .build()
        .await
        .map_err(|e| OutputManagerError::BuildError(e.message))?;

    stp.change_recipient_sender_offset_private_key(
        key_manager
            .get_next_key(TransactionKeyManagerBranch::OneSidedSenderOffset.get_branch_key())
            .await?
            .key_id,
    )
    .map_err(|e| CommandError::General(format!("Failed to change recipient sender offset private key: {}", e)))?;

    // This call is needed to advance the state from `SingleRoundMessageReady` to `SingleRoundMessageReady`,
    // but the returned value is not used
    let _single_round_sender_data = stp
        .build_single_round_message(&key_manager)
        .await
        .map_err(|e| CommandError::General(format!("Failed to build single round message: {}", e)))?;

    output_service.confirm_encumbrance(tx_id, Vec::new()).await?;

    // Prepare receiver part of the transaction
    // Diffie-Hellman shared secret `k_Ob * K_Sb = K_Ob * k_Sb` results in a public key, which is fed into
    // KDFs to produce the spending and encryption keys. All player's shares are added together to produce the
    // shared secret.
    let sender_offset_private_key_id_self = stp
        .get_recipient_sender_offset_private_key()
        .map_err(|e| {
            CommandError::General(format!(
                "Failed to get recipient sender offset private key (TxId: {}): {}",
                tx_id, e
            ))
        })?
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
    let rtp = ReceiverTransactionProtocol::new(sender_message, output, &key_manager, &consensus_constants).await;

    let recipient_reply = rtp
        .get_signed_data()
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

    let mut tx = stp
        .get_transaction()
        .map_err(|e| CommandError::General(format!("Failed to get transaction: {}", e)))?
        .clone();

    let mut tx_body = tx.body;

    tx_body.update_script_signature(updated_input.commitment()?, updated_input.script_signature.clone())?;
    tx.body = tx_body;

    let fee = stp
        .get_fee_amount()
        .map_err(|e| CommandError::General(format!("Failed to get fee amount: {}", e)))?;

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

    let all_outputs = tx.body.outputs().iter().map(|o| o.hash()).collect::<Vec<HashOutput>>();

    let completed_tx = CompletedTransaction::new_with_output_hashes(
        tx_id,
        own_address.clone(),
        recipient_address,
        amount,
        fee,
        tx.clone(),
        TransactionStatus::Pending,
        Utc::now(),
        TransactionDirection::Outbound,
        None,
        None,
        payment_id.clone(),
        all_outputs,
        vec![],
        vec![],
    )
    .map_err(|e| CommandError::General(format!("{}: {}", tx_id, e)))?;

    transaction_service
        .insert_completed_transaction(tx_id, completed_tx)
        .await
        .map_err(|e| CommandError::General(format!("Failed to insert completed transaction: {}", e)))?;

    Ok((
        tx_id,
        tx,
        amount,
        fee,
        total_script_public_key,
        CompressedPublicKey::new_from_pk(total_metadata_ephemeral_public_key),
        CompressedPublicKey::new_from_pk(total_script_nonce),
        shared_secret_public_key,
    ))
}
