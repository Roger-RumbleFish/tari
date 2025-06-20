use minotari_wallet::{output_manager_service::{error::OutputManagerError, handle::OutputManagerHandle, storage::models::DbWalletOutput}, storage::sqlite_utilities::WalletDbConnection};
use sha2::Sha256;
use digest::Digest;
use tari_common_types::{key_branches::TransactionKeyManagerBranch, transaction::TxId, types::{CompressedPublicKey, UncompressedPublicKey}};
use tari_core::{one_sided::public_key_to_output_encryption_key, transactions::transaction_key_manager::{storage::sqlite_db::TransactionKeyManagerSqliteDatabase, TariKeyAndId, TariKeyId, TransactionKeyManagerInterface, TransactionKeyManagerWrapper}};
use tari_crypto::{compressed_key::CompressedKey, ristretto::{RistrettoPublicKey, RistrettoSecretKey}};
use tari_script::{Opcode, TariScript};
use tari_utilities::hex::Hex;

use crate::automation::error::CommandError;

pub fn is_multisig_utxo(tari_script: &TariScript) -> bool {
    tari_script.script.iter().any(|op| matches!(op, Opcode::CheckMultiSigVerifyAggregatePubKey(..)))
}

pub fn get_multi_sig_script_components(
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

pub async fn get_multisig_script_key(
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

pub fn sum_public_keys(public_keys: &[CompressedKey<RistrettoPublicKey>]) -> Result<RistrettoPublicKey, CommandError> {
    let mut sum = UncompressedPublicKey::default();
    for key in public_keys {
        sum = &sum + key.to_public_key()?;
    }
    Ok(sum)
}

pub fn sum_public_keys_to_encryption_key(public_keys: &[CompressedKey<RistrettoPublicKey>]) -> Result<RistrettoSecretKey, CommandError> {
    let sum_public_keys = sum_public_keys(public_keys)?;

    let encryption_private_key =
        public_key_to_output_encryption_key(&CompressedPublicKey::new_from_pk(sum_public_keys))?;

    Ok(encryption_private_key)
}

pub fn get_utxo_by_commitment_hash(
    utxos: &[DbWalletOutput],
    commitment_hash: String,
) -> Option<&DbWalletOutput> {
    utxos.iter().find(|utxo| utxo.commitment.to_hex() == commitment_hash)
}


#[allow(dead_code)]
pub async fn select_utxos_for_amount(
    output_service: &mut OutputManagerHandle,
    target: u64,
) -> Result<Vec<DbWalletOutput>, CommandError> {
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

pub async fn derive_multisig_recovery_key_id<KM: TransactionKeyManagerInterface>(
    public_keys: &[CompressedKey<RistrettoPublicKey>],
    key_manager: &KM,
) -> Result<TariKeyId, CommandError> {
    let encryption_key = sum_public_keys_to_encryption_key(public_keys)
        .map_err(|e| CommandError::General(format!("Failed to sum public keys: {}", e)))?;

    let encryption_key_id = key_manager.import_key(encryption_key).await?;

    Ok(encryption_key_id) 
}