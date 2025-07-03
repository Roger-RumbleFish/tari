use serde::de::DeserializeOwned;
use tari_common_types::{tari_address::TariAddress, types::CompressedPublicKey};
use tari_utilities::hex::{Hex};
use tari_crypto::{compressed_key::CompressedKey, ristretto::{RistrettoPublicKey}};
use std::{fs};
use crate::automation::{error::CommandError, multisig::types::{MemberMultisigSignature, MultisigEncumberOutput, MultisigLeaderPartyOutput, MultisigMemberPartyOutput, MultisigOutput, MultisigPartyOutput}};

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

pub async fn load_multisig_output(session_id: &str) -> Result<MultisigOutput, CommandError> {

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

fn load_party_output<T: DeserializeOwned>(
    session_id: &str,
    pubkey: CompressedKey<RistrettoPublicKey>,
    prefix: &str,
) -> Result<T, CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    let file_path = out_dir.join(format!(
        "multisig_party_output-{}-{}-{}.json",
        prefix,
        session_id,
        pubkey.to_hex(),
    ));
    if !file_path.exists() {
        return Err(CommandError::General(format!(
            "Missing {} party file: {}",
            prefix,
            file_path.display()
        )));
    }
    let file = std::fs::File::open(&file_path)?;
    let output: T = serde_json::from_reader(file)
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    Ok(output)
}

pub fn load_leader_party_output(
    session_id: &str,
    pubkey: CompressedKey<RistrettoPublicKey>,
) -> Result<MultisigLeaderPartyOutput, CommandError> {
    load_party_output::<MultisigLeaderPartyOutput>(session_id, pubkey, "leader")
}

pub fn load_member_party_output(
    session_id: &str,
    pubkey: CompressedKey<RistrettoPublicKey>,
) -> Result<MultisigMemberPartyOutput, CommandError> {
    load_party_output::<MultisigMemberPartyOutput>(session_id, pubkey, "member")
}

pub async fn save_multisig_utxo_encumber(
    session_id: &str,
    outputs: Vec<MultisigEncumberOutput>
) -> Result<(), CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }
    // Save all encumber outputs to a single file
    let out_file = out_dir.join(format!("multisig_utxo_encumber_outputs-{}.json", session_id));

    let file = fs::File::create(&out_file)?;
    serde_json::to_writer_pretty(file, &outputs)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub async fn load_multisig_utxo_encumber(session_id: &str) -> Result<Vec<MultisigEncumberOutput>, CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let file_path = out_dir.join(format!("multisig_utxo_encumber_outputs-{}.json", session_id));

    if !file_path.exists() {
        return Err(CommandError::General(format!(
            "Missing multisig encumber outputs file: {}",
            file_path.display()
        )));
    }

    let file = fs::File::open(file_path)?;
    let outputs: Vec<MultisigEncumberOutput> = serde_json::from_reader(file)
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(outputs)
}

pub async fn save_multisig_member_signatures(session_id: &str, signatures: Vec<MemberMultisigSignature>, own_address: TariAddress) -> Result<(), CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

   // Save member signatures (include user address in filename)
    let member_file = out_dir.join(format!(
        "multisig_member_signatures-{}-{}.json",
        session_id,
        own_address.public_spend_key().to_hex(),
    ));

    let file = fs::File::create(&member_file)?;
    serde_json::to_writer_pretty(file, &signatures)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub async fn load_multisig_member_signatures(session_id: &str, member_public_key: CompressedPublicKey) -> Result<Vec<MemberMultisigSignature>, CommandError> {
    let out_dir = std::path::Path::new("/wallet_data");
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let file_path = out_dir.join(format!(
        "multisig_member_signatures-{}-{}.json",
        session_id,
        member_public_key.to_hex(),
    ));

    if !file_path.exists() {
        return Err(CommandError::General(format!(
            "Missing multisig member signatures file: {}",
            file_path.display()
        )));
    }

    let file = fs::File::open(file_path)?;
    let signatures: Vec<MemberMultisigSignature> = serde_json::from_reader(file)
        .map_err(|e| CommandError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(signatures)
}
