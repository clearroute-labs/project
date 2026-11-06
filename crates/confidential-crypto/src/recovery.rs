//! Authenticated two-limb recovery for full 63-bit amounts.
//!
//! Direct discrete-log recovery of a Baby-Jubjub ElGamal message is infeasible
//! at 2^63. Every confidential amount therefore carries (or can be reissued
//! with) two authenticated encrypted 32-bit limb records. Each limb is
//! recovered with a 2^16 baby-step/giant-step table, then recombined and
//! checked against the original ciphertext. A record is a wallet aid, never an
//! authority: the main ciphertext, key, profile, context and history remain
//! authoritative.

use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::elgamal::{Ciphertext, PublicKey, SecretKey, discrete_log_bounded};
use crate::encoding::{PointHex, ScalarHex};
use crate::hash_to_curve::encryption_base;
use crate::statement::RecoveryPair;
use crate::{CryptoError, MAX_AMOUNT, PROFILE_ID};

/// Recover a proof-bound limb pair. Unlike `RecoveryRecord`, this function
/// accepts the pair carried in a lending statement; the Groth16 proof has
/// already constrained its limbs to the exact associated amount.
pub fn recover_pair(
    pair: &RecoveryPair,
    recipient_secret: &SecretKey,
    expected_key: &PublicKey,
) -> Result<u64, CryptoError> {
    crate::elgamal::recover_limb_pair(
        &pair.low_limb,
        &pair.high_limb,
        recipient_secret,
        expected_key,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMetadata {
    pub account_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub key_id: [u8; 32],
    #[serde(with = "crate::encoding::decimal_u64")]
    pub ciphertext_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySignature {
    pub commitment: PointHex,
    pub response: ScalarHex,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub profile_id: String,
    pub metadata: RecoveryMetadata,
    pub ciphertext_digest: String,
    pub low_limb: Ciphertext,
    pub high_limb: Ciphertext,
    pub signer: PublicKey,
    pub signature: RecoverySignature,
}

impl std::fmt::Debug for RecoveryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryRecord")
            .field("profile_id", &self.profile_id)
            .field("metadata", &self.metadata)
            .field("ciphertext_digest", &self.ciphertext_digest)
            .field("low_limb", &self.low_limb)
            .field("high_limb", &self.high_limb)
            .field("signer", &self.signer)
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl RecoveryRecord {
    pub fn create<R: RngCore + CryptoRng>(
        amount: u64,
        recipient_key: &PublicKey,
        metadata: RecoveryMetadata,
        main_ciphertext: &Ciphertext,
        signer_secret: &SecretKey,
        rng: &mut R,
    ) -> Result<Self, CryptoError> {
        if amount > MAX_AMOUNT {
            return Err(CryptoError::AmountOutOfRange);
        }
        let (low_limb, _) = Ciphertext::encrypt(recipient_key, amount & u32::MAX as u64, rng)?;
        let (high_limb, _) = Ciphertext::encrypt(recipient_key, amount >> 32, rng)?;
        let unsigned = UnsignedRecovery {
            profile_id: PROFILE_ID.to_string(),
            metadata,
            ciphertext_digest: digest_ciphertext(main_ciphertext),
            low_limb,
            high_limb,
            signer: signer_secret.public_key(),
        };
        let signature = sign(&unsigned, signer_secret, rng)?;
        let mut record = unsigned.into_record();
        record.signature = signature;
        Ok(record)
    }

    pub fn recover(
        &self,
        recipient_secret: &SecretKey,
        expected_recipient_key: &PublicKey,
        main_ciphertext: &Ciphertext,
        expected_metadata: &RecoveryMetadata,
    ) -> Result<u64, CryptoError> {
        self.validate_signature()?;
        if self.profile_id != PROFILE_ID
            || &self.metadata != expected_metadata
            || self.ciphertext_digest != digest_ciphertext(main_ciphertext)
        {
            return Err(CryptoError::RecoveryMismatch);
        }
        if &recipient_secret.public_key() != expected_recipient_key {
            return Err(CryptoError::InvalidKey);
        }
        let low = discrete_log_bounded(
            self.low_limb.decrypt_point(recipient_secret)?,
            u32::MAX as u64,
        )?;
        let high = discrete_log_bounded(
            self.high_limb.decrypt_point(recipient_secret)?,
            u32::MAX as u64,
        )?;
        let amount = low
            .checked_add(
                high.checked_shl(32)
                    .ok_or(CryptoError::RecoveryOutOfRange)?,
            )
            .ok_or(CryptoError::RecoveryOutOfRange)?;
        if amount > MAX_AMOUNT {
            return Err(CryptoError::RecoveryOutOfRange);
        }
        let main_message = main_ciphertext.decrypt_point(recipient_secret)?;
        if main_message != encryption_base() * Fr::from(amount) {
            return Err(CryptoError::RecoveryMismatch);
        }
        Ok(amount)
    }

    pub fn validate_signature(&self) -> Result<(), CryptoError> {
        let unsigned = UnsignedRecovery {
            profile_id: self.profile_id.clone(),
            metadata: self.metadata.clone(),
            ciphertext_digest: self.ciphertext_digest.clone(),
            low_limb: self.low_limb.clone(),
            high_limb: self.high_limb.clone(),
            signer: self.signer.clone(),
        };
        let commitment = self.signature.commitment.to_projective()?;
        let response = self.signature.response.to_scalar()?;
        let challenge = challenge_with_commitment(&unsigned, &commitment)?;
        if encryption_base() * response != commitment + self.signer.to_point()? * challenge {
            return Err(CryptoError::InvalidRecoveryAuthentication);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct UnsignedRecovery {
    profile_id: String,
    metadata: RecoveryMetadata,
    ciphertext_digest: String,
    low_limb: Ciphertext,
    high_limb: Ciphertext,
    signer: PublicKey,
}

impl UnsignedRecovery {
    fn into_record(self) -> RecoveryRecord {
        RecoveryRecord {
            profile_id: self.profile_id,
            metadata: self.metadata,
            ciphertext_digest: self.ciphertext_digest,
            low_limb: self.low_limb,
            high_limb: self.high_limb,
            signer: self.signer,
            signature: RecoverySignature {
                commitment: PointHex(String::new()),
                response: ScalarHex(String::new()),
            },
        }
    }
}

fn sign<R: RngCore + CryptoRng>(
    message: &UnsignedRecovery,
    secret: &SecretKey,
    rng: &mut R,
) -> Result<RecoverySignature, CryptoError> {
    let nonce = loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            break value;
        }
    };
    let commitment = encryption_base() * nonce;
    let challenge = challenge_with_commitment(message, &commitment)?;
    let response = nonce + challenge * secret.scalar();
    Ok(RecoverySignature {
        commitment: PointHex::from(commitment.into_affine()),
        response: ScalarHex::from(response),
    })
}

fn challenge_with_commitment(
    message: &UnsignedRecovery,
    commitment: &EdwardsProjective,
) -> Result<Fr, CryptoError> {
    let mut bytes = canonical_unsigned(message)?;
    let commitment = PointHex::from(commitment.into_affine());
    bytes.extend_from_slice(commitment.0.as_bytes());
    let digest = Sha256::digest(bytes);
    Ok(Fr::from_le_bytes_mod_order(&digest))
}

fn canonical_unsigned(message: &UnsignedRecovery) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NEAR-CONFIDENTIAL-LENDING/RECOVERY/v1");
    bytes.extend_from_slice(&(message.profile_id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(message.profile_id.as_bytes());
    bytes.extend_from_slice(&message.metadata.account_id);
    bytes.extend_from_slice(&message.metadata.asset_id);
    bytes.extend_from_slice(&message.metadata.key_id);
    bytes.extend_from_slice(&message.metadata.ciphertext_version.to_le_bytes());
    bytes.extend_from_slice(&(message.ciphertext_digest.len() as u32).to_le_bytes());
    bytes.extend_from_slice(message.ciphertext_digest.as_bytes());
    bytes.extend_from_slice(message.low_limb.ephemeral.0.as_bytes());
    bytes.extend_from_slice(message.low_limb.message.0.as_bytes());
    bytes.extend_from_slice(message.high_limb.ephemeral.0.as_bytes());
    bytes.extend_from_slice(message.high_limb.message.0.as_bytes());
    bytes.extend_from_slice(message.signer.point.0.as_bytes());
    Ok(bytes)
}

fn digest_ciphertext(ciphertext: &Ciphertext) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"NEAR-CONFIDENTIAL-LENDING/CIPHERTEXT/v1");
    hasher.update(ciphertext.ephemeral.0.as_bytes());
    hasher.update(ciphertext.message.0.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    #[test]
    fn recovers_full_63_bit_amount_and_rejects_tampering() {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        let recipient = SecretKey::from_scalar(Fr::from(29u64)).unwrap();
        let signer = SecretKey::from_scalar(Fr::from(37u64)).unwrap();
        let amount = (1u64 << 62) + 0x1234_5678u64;
        let (ciphertext, _) =
            Ciphertext::encrypt(&recipient.public_key(), amount, &mut rng).unwrap();
        let metadata = RecoveryMetadata {
            account_id: [1; 32],
            asset_id: [2; 32],
            key_id: [3; 32],
            ciphertext_version: 9,
        };
        let record = RecoveryRecord::create(
            amount,
            &recipient.public_key(),
            metadata.clone(),
            &ciphertext,
            &signer,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            record
                .recover(&recipient, &recipient.public_key(), &ciphertext, &metadata)
                .unwrap(),
            amount
        );
        let mut bad = record.clone();
        bad.ciphertext_digest.replace_range(0..2, "00");
        assert!(
            bad.recover(&recipient, &recipient.public_key(), &ciphertext, &metadata)
                .is_err()
        );
    }
}
