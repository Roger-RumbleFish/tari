use minotari_app_utilities::utilities::UniPublicKey;
use serde::{Deserialize, Serialize};
use tari_common_types::{
    tari_address::TariAddress,
    transaction::TxId,
    types::{CompressedCommitment, CompressedPublicKey, PrivateKey, Signature},
};
use tari_core::transactions::{
    tari_amount::MicroMinotari,
    transaction_components::{EncryptedData, OutputFeatures},
    transaction_key_manager::TariKeyId,
};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_script::{CompressedCheckSigSchnorrSignature, ExecutionStack, TariScript};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigOutput {
    pub session_id: String,
    pub utxos: Vec<String>,
    pub commitments: Vec<String>,

    pub minimum_signatures: u8,
    pub parties_public_keys: Vec<UniPublicKey>,

    pub fee_per_gram: MicroMinotari,
    pub value: MicroMinotari,
    pub recipient_address: TariAddress,
    pub commitment_mask: RistrettoSecretKey,
}

pub struct MultisigPartyOutput {
    pub leader: MultisigLeaderPartyOutput,
    pub member: MultisigMemberPartyOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigLeaderPartyOutput {
    pub session_id: String,
    pub member_public_key: CompressedPublicKey,
    pub commitment_signatures: Vec<LeaderCommitmentSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMemberPartyOutput {
    pub session_id: String,
    pub member_public_key: CompressedPublicKey,
    pub commitment_signatures: Vec<MemberCommitmentSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderCommitmentSignature {
    pub signature: CompressedCheckSigSchnorrSignature,
    pub ephemeral_pubkey: CompressedPublicKey,
    pub dh_shared_secret_public_key: CompressedPublicKey,
    pub script_nonce_key: CompressedPublicKey,
    pub sender_offset_public_key: CompressedPublicKey,
    pub sender_offset_public_nonce_key: CompressedPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigEncumberOutput {
    pub output_index: usize,
    pub tx_id: TxId,
    pub input_stack: ExecutionStack,
    pub input_script: TariScript,
    pub total_script_key: CompressedPublicKey,
    pub script_signature_ephemeral_commitment: CompressedCommitment,
    pub script_signature_ephemeral_pubkey: CompressedPublicKey,
    pub output_commitment: CompressedCommitment,
    pub sender_offset_pubkey: CompressedPublicKey,
    pub metadata_signature_ephemeral_commitment: CompressedCommitment,
    pub metadata_signature_ephemeral_pubkey: CompressedPublicKey,
    pub encrypted_data: EncryptedData,
    pub output_features: OutputFeatures,
    pub shared_secret: CompressedPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCommitmentSignature {
    pub signature: CompressedCheckSigSchnorrSignature,
    pub script_nonce_key_id: TariKeyId,
    pub ephemeral_pubkey_id: TariKeyId,
    pub sender_offset_key: TariKeyId,
    pub sender_offset_nonce_key: TariKeyId,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberMultisigSignature {
    pub output_index: usize,
    pub script_signature: Signature,
    pub metadata_signature: Signature,
    pub script_offset: PrivateKey,
}
