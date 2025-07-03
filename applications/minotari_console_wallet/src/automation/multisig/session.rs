use chrono::Utc;
use minotari_wallet::{output_manager_service::{handle::OutputManagerHandle, storage::models::DbWalletOutput, UtxoSelectionCriteria}, storage::sqlite_utilities::WalletDbConnection, transaction_service::handle::TransactionServiceHandle};

use tari_common_types::{transaction::TxId};
use tari_core::transactions::{tari_amount::MicroMinotari, transaction_components::{encrypted_data::PaymentId, EncryptedData, WalletOutputBuilder}, transaction_key_manager::{storage::sqlite_db::TransactionKeyManagerSqliteDatabase, TransactionKeyManagerInterface, TransactionKeyManagerWrapper}};
use tari_crypto::{compressed_key::CompressedKey, ristretto::RistrettoPublicKey};
use tari_script::{Opcode, TariScript};
use tari_utilities::hex::Hex;
use tari_core::transactions::{
    transaction_components::{

        OutputFeatures,

    },
};
use tari_script::{ExecutionStack};
use tari_utilities::ByteArray;
use crate::automation::{error::CommandError, multisig::script::{derive_multisig_recovery_key_id, get_multi_sig_script_components, sum_public_keys_to_encryption_key}};
use crate::{automation::{multisig::{script::{get_utxo_by_commitment_hash}, types::MultisigOutput}}, cli::CreateMultisigUtxoTransferLeaderArgs};

pub async fn make_utxo_multisig(
    output_service: &mut OutputManagerHandle,
    transaction_service: &mut TransactionServiceHandle,
    key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    utxo: DbWalletOutput,
    m: u8,
    n: u8,
    public_keys: Vec<CompressedKey<RistrettoPublicKey>>,
) -> Result<TxId, CommandError> {
        let utxo_value = MicroMinotari::from(utxo.wallet_output.value);

        let (commitment_mask, script_key) = key_manager_service
        .get_next_commitment_mask_and_script_key()
        .await?;

        let commitment = key_manager_service
        .get_commitment(&commitment_mask.key_id, &utxo_value.into())
        .await?;

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.clone_from_slice(commitment.as_bytes());

        let message: Box<[u8; 32]> = Box::new(commitment_bytes);

        let mut ephemeral_pubkeys = Vec::new();
        for pk in &public_keys {
            // Derive a unique ephemeral key for this output and participant
            let ephemeral_pubkey = key_manager_service
                .stealth_address_script_spending_key(&commitment_mask.key_id, pk)
                .await?;
            ephemeral_pubkeys.push(ephemeral_pubkey);
        }
    
        let script = TariScript::new(vec![
            Opcode::CheckMultiSigVerifyAggregatePubKey(m, n, ephemeral_pubkeys.clone(), message),
        ])?;

        let input_selection = UtxoSelectionCriteria::default();
        let payment_id = PaymentId::default();
        let custom_recover_key = derive_multisig_recovery_key_id(
            &ephemeral_pubkeys.clone(),
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

        let fee_per_gram = MicroMinotari::from(1);

        let (tx_id, transaction) = output_service.create_send_to_self_with_output(vec![output_builder], fee_per_gram, input_selection, payment_id.clone())
        .await
        .map_err(|e| CommandError::General(format!("Failed to send to self: {}", e)))?;

        transaction_service
            .submit_transaction(tx_id, transaction, utxo_value, payment_id.clone())
            .await
            .map_err(|e| CommandError::General(format!("Failed to submit transaction: {}", e)))?;

         Ok(tx_id)
}

pub async fn create_multisig_output(output_service: &mut OutputManagerHandle,
    args: CreateMultisigUtxoTransferLeaderArgs) -> Result<MultisigOutput, CommandError> {
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

    let utxo_output = selected_utxo.wallet_output.clone();

    let (multi_sig_public_keys, _threshold) = get_multi_sig_script_components(&utxo_output.script)?;

    let encryption_private_key = sum_public_keys_to_encryption_key(&multi_sig_public_keys)?;

    match EncryptedData::decrypt_data(
        &encryption_private_key,
        &selected_utxo.commitment,
        &utxo_output.encrypted_data,
    ) {
        Ok((_amount, commitment_mask, _payment_id)) => {
            let multisig_output = MultisigOutput {
                session_id: session_id.clone(),
                utxos: utxo_hashes,
                commitments: utxo_commitments,
                fee_per_gram: MicroMinotari::from(1),
                minimum_signatures: args.m,
                recipient_address: args.recipient_address.clone(),
                parties_public_keys: args.public_keys,
                value: selected_utxo.wallet_output.value,
                commitment_mask: commitment_mask,
            };
            Ok(multisig_output)
        },
        Err(_) => {
            Err(CommandError::General("Failed to decrypt output secrets".into()))
        }
    }

}
