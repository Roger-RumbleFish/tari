use std::collections::HashMap;

use tari_common_types::{
    types::{CompressedCommitment, CompressedPublicKey, PrivateKey, Signature, UncompressedPublicKey}
};
use tari_crypto::{compressed_key::CompressedKey, dhke::DiffieHellmanSharedSecret, ristretto::RistrettoPublicKey};
use tari_script::push_pubkey_script;
use tari_utilities::hex::{self, Hex};
use minotari_wallet::{
    storage::sqlite_utilities::WalletDbConnection, transaction_service::{handle::TransactionServiceHandle}
};
use tari_core::{covenants::Covenant, one_sided::shared_secret_to_output_encryption_key, transactions::{tari_amount::MicroMinotari, transaction_components::{EncryptedData, TransactionInput, TransactionInputVersion, TransactionOutput, TransactionOutputVersion}, transaction_key_manager::{
        storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
        TransactionKeyManagerInterface,
        TransactionKeyManagerWrapper,
    }}};
use tari_utilities::ByteArray;
use crate::automation::{error::CommandError, multisig::{io::{load_member_party_output, load_multisig_member_signatures, load_multisig_utxo_encumber, read_multisig_output}, script::{finalize_aggregate_utxo}, types::{LeaderCommitmentSignature, MemberCommitmentSignature, MemberMultisigSignature, MultisigLeaderPartyOutput, MultisigMemberPartyOutput, MultisigPartyOutput}}};

pub async fn create_multisig_party_member_output(key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>, session_id: String) -> Result<MultisigPartyOutput, CommandError> {
    let spend_key = key_manager_service.get_spend_key().await?;
    let public_key = spend_key.pub_key.clone();

    let config = read_multisig_output(&session_id).await
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    let member_public_key = config.parties_public_keys.iter()
        .find(|key| key.as_compressed().eq(&public_key))
        .ok_or(CommandError::PartyMemberNotFound)?;

    let recipient_public_view_key = config.recipient_address.public_view_key()
        .ok_or(CommandError::InvalidArgument("Missing public view key".to_string()))?;

    let mut leader_commitment_signatures: Vec<LeaderCommitmentSignature> = Vec::new();
    let mut member_commitment_signatures: Vec<MemberCommitmentSignature> = Vec::new();


    for commitment_hex in config.commitments {
        let script_nonce_key = key_manager_service.get_random_key().await?;
        // blinding factor
        let sender_offset_key = key_manager_service.get_random_key().await?;
        let sender_offset_nonce_key = key_manager_service.get_random_key().await?;
        let commitment_mask_key_id = key_manager_service.import_key(config.commitment_mask.clone().into()).await?;


        let spend_key = key_manager_service.get_spend_key().await?;

        if spend_key.pub_key != *member_public_key.as_compressed() {
            return Err(CommandError::InvalidArgument("Spend key does not match member public key".to_string()));
        }

        let ephemeral_pubkey = key_manager_service
        .stealth_address_script_spending_key(&commitment_mask_key_id, member_public_key.as_compressed())
        .await?;

        let ephemeral_private_key = key_manager_service
        .stealth_address_script_spending_key_id(&commitment_mask_key_id, &spend_key.key_id)
        .await?;

        let key_id = key_manager_service.import_key(ephemeral_private_key).await?;

        let commitment = hex::from_hex(&commitment_hex)
            .map_err(|e| CommandError::InvalidArgument(format!("Invalid commitment hex: {}", e)))?;

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.clone_from_slice(&commitment);

        let script_input_signature = key_manager_service
            .sign_script_message(&key_id, &commitment_bytes)
            .await?;

        // Computes a Diffie-Hellman shared secret with the recipient's public view key.
        let shared_secret = key_manager_service
            .get_diffie_hellman_shared_secret(
                &sender_offset_key.key_id,
                &recipient_public_view_key,
            )
            .await?;

        let dh_shared_secret_public_key = CompressedPublicKey::from_canonical_bytes(shared_secret.as_bytes())?;

        leader_commitment_signatures.push(LeaderCommitmentSignature {
            ephemeral_pubkey: ephemeral_pubkey.clone(),
            signature: script_input_signature.clone(),
            dh_shared_secret_public_key: dh_shared_secret_public_key,
            script_nonce_key: script_nonce_key.pub_key,
            sender_offset_public_key: sender_offset_key.pub_key,
            sender_offset_public_nonce_key: sender_offset_nonce_key.pub_key,
        });

        member_commitment_signatures.push(MemberCommitmentSignature {
            ephemeral_pubkey_id: key_id,
            signature: script_input_signature.clone(),
            script_nonce_key_id: script_nonce_key.key_id,
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

pub async fn sign_multisig_utxo_by_member(
    key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    session_id: String) -> Result<Vec<MemberMultisigSignature>, CommandError> {
    let session_id_clone = session_id.clone();
    let multisig_config = read_multisig_output(&session_id_clone).await?;

    let key = key_manager_service.get_spend_key()
        .await
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?.pub_key;


    let config = read_multisig_output(&session_id_clone).await?;
    let member_config = load_member_party_output(&session_id, key.clone())?;
    let encumber_config = load_multisig_utxo_encumber(&session_id).await?;

    let mut output_signatures: Vec<MemberMultisigSignature> = Vec::new();

    for (output_index, encumber) in encumber_config.iter().enumerate() {
        let member_info = &member_config.commitment_signatures[output_index];

       let commitment = CompressedCommitment::from_hex(&config.commitments[output_index])
            .map_err(|e| CommandError::InvalidArgument(format!("Invalid commitment hex: {}", e)))?;

        let challenge = TransactionInput::build_script_signature_challenge(
            &TransactionInputVersion::get_current_version(),
            &encumber.script_signature_ephemeral_commitment,
            &encumber.script_signature_ephemeral_pubkey,
            &encumber.input_script,
            &encumber.input_stack,
            &encumber.total_script_key,
            &commitment,
        );

        let script_signature = match key_manager_service
                .sign_with_nonce_and_challenge(
                    &member_info.ephemeral_pubkey_id,
                    &member_info.script_nonce_key_id,
                    &challenge,
                )
                .await
            {
                Ok(signature) => signature,
                Err(e) => {
                    eprintln!("\nError: Script signature SignMessage error! {}\n", e);

                    break;
                },
        };

        let shared_secret = match DiffieHellmanSharedSecret::<UncompressedPublicKey>::from_canonical_bytes(
                encumber.shared_secret.as_bytes(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("\nError: Could not create shared secret from canonical bytes! {}\n", e);
                    break;
                },
            };

        let encryption_key = shared_secret_to_output_encryption_key(&shared_secret)?;

        let (committed_value, commitment_mask_private_key, _payment_id) = match EncryptedData::decrypt_data(
            &encryption_key,
            &encumber.output_commitment,
            &encumber.encrypted_data,
        ) {
            Ok((value, mask, id)) => (value, mask, id),
            Err(e) => {
                eprintln!("\nError: Could not decrypt data! {}\n", e);
                break;
            },
        };

        let commitment_mask_key_id = &key_manager_service
            .import_key(commitment_mask_private_key.clone())
            .await?;
        
        match key_manager_service
            .verify_mask(
                &encumber.output_commitment,
                commitment_mask_key_id,
                committed_value.as_u64(),
            )
            .await
        {
            Ok(_) => {},
            Err(e) => {
                eprintln!("\nError: Could not verify mask! {}\n", e);
                break;
            },
        }

        // now lets calculate the script with stealth key
        let script_spending_key = key_manager_service
            .stealth_address_script_spending_key(
                commitment_mask_key_id,
                &multisig_config.recipient_address.public_spend_key(),
            )
            .await?;

        let script = push_pubkey_script(&script_spending_key);

        // Metadata signature
        let script_offset = key_manager_service
            .get_script_offset(&vec![member_info.ephemeral_pubkey_id.clone()], &vec![member_info.sender_offset_key.clone()])
            .await?;

        let challenge = TransactionOutput::build_metadata_signature_challenge(
            &TransactionOutputVersion::get_current_version(),
            &script,
            &encumber.output_features,
            &encumber.sender_offset_pubkey,
            &encumber.metadata_signature_ephemeral_commitment,
            &encumber.metadata_signature_ephemeral_pubkey,
            &encumber.output_commitment,
            &Covenant::default(),
            &encumber.encrypted_data,
            MicroMinotari::zero(),
        );

        let metadata_signature = match key_manager_service
            .sign_with_nonce_and_challenge(
                &member_info.sender_offset_key,
                &member_info.sender_offset_nonce_key,
                &challenge,
            )
            .await
            {
                Ok(signature) => signature,
                Err(e) => {
                    eprintln!("\nError: Metadata signature SignMessage error! {}\n", e);

                    break;
                },
            };

        if script_signature.get_signature() == Signature::default().get_signature() ||
                metadata_signature.get_signature() == Signature::default().get_signature()
            {
                eprintln!(
                    "\nError: Script and/or metadata signatures not created (index {})!\n",
                    output_index,
                );
                break;
            }

            output_signatures.push(MemberMultisigSignature {
                output_index,
                script_signature,
                metadata_signature,
                script_offset,
            });
    }

    return Ok(output_signatures);

}

pub async fn send_multisig_utxo_by_leader(
    transaction_service: TransactionServiceHandle,
    key_manager_service: TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
    session_id: &str) -> Result<(), CommandError> {
    let session_id_clone = session_id.to_string();
    let multisig_config = read_multisig_output(&session_id_clone).await?;
    let encumber_config = load_multisig_utxo_encumber(session_id).await?;

    let mut transaction_service = transaction_service.clone();
    let spend_key = key_manager_service.get_spend_key().await?;
    let public_key: tari_crypto::compressed_key::CompressedKey<tari_crypto::ristretto::RistrettoPublicKey> = spend_key.pub_key.clone();

    let mut signatures_map: HashMap<CompressedKey<RistrettoPublicKey>, Vec<MemberMultisigSignature>> = HashMap::new();

    let members_public_keys: Vec<CompressedKey<RistrettoPublicKey>> = multisig_config
        .parties_public_keys
        .iter()
        .map(|k| k.as_compressed().clone())
        .filter(|k| k != &public_key)
        .collect();

     let commitment_mask_key_id = key_manager_service.import_key(multisig_config.commitment_mask.clone().into()).await?;
     
    for pubkey in &members_public_keys {
        let member_signatures = match load_multisig_member_signatures(
            session_id,
            pubkey.clone(),
        ).await {
            Ok(sigs) => sigs,
            Err(e) => {
                println!("Warning: Could not load multisig member signatures for {:?}: {}. Skipping.", pubkey, e);
                continue;
            }
        };

        let ephemeral_pubkey = match key_manager_service
            .stealth_address_script_spending_key(&commitment_mask_key_id, pubkey)
            .await {
                Ok(pk) => pk,
                Err(e) => {
                    println!("Warning: Could not get ephemeral pubkey for {:?}: {}. Skipping.", pubkey, e);
                    continue;
                }
            };

        signatures_map.insert(
            ephemeral_pubkey.clone(),
            member_signatures,
        );
    }

    // Create finalized spend transactions
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut kernels = Vec::new();
    let mut kernel_offset = PrivateKey::default();

    for (_i, pub_key) in members_public_keys.iter().enumerate() {
        let tx_id: tari_common_types::transaction::TxId = encumber_config[0].tx_id.clone();
        let ephemeral_pubkey = match key_manager_service
            .stealth_address_script_spending_key(&commitment_mask_key_id, pub_key)
            .await {
                Ok(pk) => pk,
                Err(e) => {
                    println!("Warning: Could not get ephemeral pubkey for {:?}: {}. Skipping.", pub_key, e);
                    continue;
                }
            };

        let signatures = match signatures_map.get(&ephemeral_pubkey) {
            Some(sigs) => sigs.clone(),
            None => {
                println!("Warning: No signatures found for ephemeral pubkey {:?}. Skipping.", ephemeral_pubkey);
                continue;
            }
        };
        let mut metadata_signatures = Vec::with_capacity(signatures.len());
        let mut script_signatures = Vec::with_capacity(signatures.len());
        let mut offset = PrivateKey::default();

        for party_info in signatures {
            metadata_signatures.push(party_info.metadata_signature.clone());
            script_signatures.push(party_info.script_signature.clone());
            offset = &offset + &party_info.script_offset;
        }

        if let Err(e) = finalize_aggregate_utxo(
            transaction_service.clone(),
            tx_id.as_u64(),
            metadata_signatures,
            script_signatures,
            offset,
        )
        .await
        {
            eprintln!(
                "\nError: Error completing transaction '{}'! ({})\n",
                tx_id, e
            );
            break;
        }
    }

    Ok(())
}