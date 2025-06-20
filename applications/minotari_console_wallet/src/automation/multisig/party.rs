
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch, tari_address::TariAddress, types::CompressedPublicKey
};
use tari_utilities::hex::{self, Hex};
use minotari_wallet::{
    storage::{sqlite_utilities::WalletDbConnection}
};
use tari_core::{transactions::{transaction_key_manager::{
        storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
        TariKeyId,
        TransactionKeyManagerInterface,
        TransactionKeyManagerWrapper,
    }
}};
use tari_utilities::ByteArray;
use crate::automation::{error::CommandError, multisig::{io::{load_member_party_output, read_multisig_output}, types::{LeaderCommitmentSignature, MemberCommitmentSignature, MultisigLeaderPartyOutput, MultisigMemberPartyOutput, MultisigPartyOutput}}};

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

pub async fn sign_multisig_utxo_by_member(session_id: String, own_address: TariAddress) -> Result<(), CommandError> {
        let session_id_clone = session_id.clone();
        let _multisig_config = read_multisig_output(session_id_clone).await?;
        let key = own_address.public_spend_key();
        let _member_config = load_member_party_output(&session_id, key.clone())?;

        println!("Signing multisig UTXO for session: {}", session_id);

        return Ok(())

        //     // Read leader input
        //     let leader_info_indexed = read_and_verify::<PreMineSpendStep3OutputsForParties>(
        //         &session_id,
        //         &get_file_name(SPEND_STEP_3_PARTIES, None),
        //         &session_info,
        //     )?;
        //     // Read own party info
        //     let party_info_indexed = read_and_verify::<PreMineSpendStep2OutputsForSelf>(
        //         &session_id,
        //         &get_file_name(SPEND_STEP_2_SELF, None),
        //         &session_info,
        //     )?;

        //     // Verify index consistency
        //     let session_info_indexes = session_info
        //         .recipient_info
        //         .iter()
        //         .map(|v| v.output_to_be_spend)
        //         .collect::<Vec<_>>();
        //     let leader_info_indexes = leader_info_indexed
        //         .outputs_for_parties
        //         .iter()
        //         .map(|v| v.output_index)
        //         .collect::<Vec<_>>();
        //     let party_info_indexes = party_info_indexed
        //         .outputs_for_self
        //         .iter()
        //         .map(|v| v.output_index)
        //         .collect::<Vec<_>>();
        //     if session_info_indexes != leader_info_indexes || session_info_indexes != party_info_indexes {
        //         eprintln!(
        //             "\nError: Mismatched output indexes detected! session {:?} vs. leader {:?} vs. self {:?}\n",
        //             session_info_indexes, leader_info_indexes, party_info_indexes
        //         );
        //         break;
        //     }

        //     let pre_mine_from_file =
        //         match read_genesis_file_outputs(session_info.use_pre_mine_input_file, args.pre_mine_file_path) {
        //             Ok(outputs) => outputs,
        //             Err(e) => {
        //                 eprintln!("\nError: {}\n", e);
        //                 break;
        //             },
        //         };

        //     println!();
        //     let mut outputs_for_leader = Vec::with_capacity(party_info_indexed.outputs_for_self.len());
        //     let mut error = false;
        //     for (i, (leader_info, party_info)) in leader_info_indexed
        //         .outputs_for_parties
        //         .iter()
        //         .zip(party_info_indexed.outputs_for_self.iter())
        //         .enumerate()
        //     {
        //         let embedded_output = match get_embedded_pre_mine_outputs(
        //             vec![party_info.output_index],
        //             pre_mine_from_file.clone(),
        //         ) {
        //             Ok(outputs) => outputs[0].clone(),
        //             Err(e) => {
        //                 eprintln!("\nError: {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         };

        //         // Script signature
        //         let challenge = TransactionInput::build_script_signature_challenge(
        //             &TransactionInputVersion::get_current_version(),
        //             &leader_info.script_signature_ephemeral_commitment,
        //             &leader_info.script_signature_ephemeral_pubkey,
        //             &leader_info.input_script,
        //             &leader_info.input_stack,
        //             &leader_info.total_script_key,
        //             &embedded_output.commitment,
        //         );

        //         let script_signature = match key_manager_service
        //             .sign_with_nonce_and_challenge(
        //                 &party_info.pre_mine_script_key_id,
        //                 &party_info.script_nonce_key_id,
        //                 &challenge,
        //             )
        //             .await
        //         {
        //             Ok(signature) => signature,
        //             Err(e) => {
        //                 eprintln!("\nError: Script signature SignMessage error! {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         };

        //         // lets verify the script
        //         let shared_secret = match DiffieHellmanSharedSecret::<UncompressedPublicKey>::from_canonical_bytes(
        //             leader_info.shared_secret.as_bytes(),
        //         ) {
        //             Ok(v) => v,
        //             Err(e) => {
        //                 eprintln!("\nError: Could not create shared secret from canonical bytes! {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         };

        //         let encryption_key = shared_secret_to_output_encryption_key(&shared_secret)?;
        //         let (committed_value, commitment_mask_private_key, _payment_id) = match EncryptedData::decrypt_data(
        //             &encryption_key,
        //             &leader_info.output_commitment,
        //             &leader_info.encrypted_data,
        //         ) {
        //             Ok((value, mask, id)) => (value, mask, id),
        //             Err(e) => {
        //                 eprintln!("\nError: Could not decrypt data! {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         };
        //         let commitment_mask_key_id = &key_manager_service
        //             .import_key(commitment_mask_private_key.clone())
        //             .await?;
        //         match key_manager_service
        //             .verify_mask(
        //                 &leader_info.output_commitment,
        //                 commitment_mask_key_id,
        //                 committed_value.as_u64(),
        //             )
        //             .await
        //         {
        //             Ok(_) => {},
        //             Err(e) => {
        //                 eprintln!("\nError: Could not verify mask! {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         }
        //         // now lets calculate the script with stealth key
        //         let script_spending_key = key_manager_service
        //             .stealth_address_script_spending_key(
        //                 commitment_mask_key_id,
        //                 party_info.recipient_address.public_spend_key(),
        //             )
        //             .await?;
        //         let script = push_pubkey_script(&script_spending_key);

        //         // Metadata signature
        //         let script_offset = key_manager_service
        //             .get_script_offset(&vec![party_info.pre_mine_script_key_id.clone()], &vec![party_info
        //                 .sender_offset_key_id
        //                 .clone()])
        //             .await?;
        //         let challenge = TransactionOutput::build_metadata_signature_challenge(
        //             &TransactionOutputVersion::get_current_version(),
        //             &script,
        //             &leader_info.output_features,
        //             &leader_info.sender_offset_pubkey,
        //             &leader_info.metadata_signature_ephemeral_commitment,
        //             &leader_info.metadata_signature_ephemeral_pubkey,
        //             &leader_info.output_commitment,
        //             &Covenant::default(),
        //             &leader_info.encrypted_data,
        //             MicroMinotari::zero(),
        //         );

        //         let metadata_signature = match key_manager_service
        //             .sign_with_nonce_and_challenge(
        //                 &party_info.sender_offset_key_id,
        //                 &party_info.sender_offset_nonce_key_id,
        //                 &challenge,
        //             )
        //             .await
        //         {
        //             Ok(signature) => signature,
        //             Err(e) => {
        //                 eprintln!("\nError: Metadata signature SignMessage error! {}\n", e);
        //                 error = true;
        //                 break;
        //             },
        //         };

        //         if script_signature.get_signature() == Signature::default().get_signature() ||
        //             metadata_signature.get_signature() == Signature::default().get_signature()
        //         {
        //             eprintln!(
        //                 "\nError: Script and/or metadata signatures not created (index {})!\n",
        //                 party_info.output_index
        //             );
        //             error = true;
        //             break;
        //         }

        //         outputs_for_leader.push(Step4OutputsForLeader {
        //             output_index: party_info.output_index,
        //             script_signature,
        //             metadata_signature,
        //             script_offset,
        //         });

        //         println!(
        //             "  Processed {} of {} transactions",
        //             i + 1,
        //             leader_info_indexed.outputs_for_parties.len()
        //         );
        //     }
        //     if error {
        //         break;
        //     }

        //     let out_dir = out_dir(&session_id)?;
        //     let out_file = out_dir.join(get_file_name(
        //         SPEND_STEP_4_LEADER,
        //         Some(party_info_indexed.alias.clone()),
        //     ));
        //     write_json_object_to_file_as_line(&out_file, true, session_info.clone())?;
        //     write_json_object_to_file_as_line(&out_file, false, PreMineSpendStep4OutputsForLeader {
        //         outputs_for_leader,
        //         alias: party_info_indexed.alias.clone(),
        //     })?;

        //     println!();
        //     println!("Concluded step 4 'pre-mine-spend-input-output-sigs'");
        //     println!(
        //         "Send '{}' to leader for step 5",
        //         get_file_name(SPEND_STEP_4_LEADER, Some(party_info_indexed.alias))
        //     );
        //     println!();
}