use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge},
};
use ark_ff::PrimeField;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commitment::Commitment;
use crate::elgamal::{Ciphertext, PublicKey};
use crate::encoding::{FieldHex, PointHex};
use crate::{CONTEXT_SLOTS, CryptoError, StatementKind};

/// Canonical operation binding.  Identifiers are fixed 32-byte digests so a
/// contract can derive them from account/operation strings without putting
/// variable-length text in a circuit input.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OperationContext {
    pub network_id: [u8; 32],
    pub core_account: [u8; 32],
    pub asset_id: [u8; 32],
    pub operation_id: [u8; 32],
    pub vault_id: [u8; 32],
    pub broker_id: [u8; 32],
    pub loan_id: [u8; 32],
    pub proposal_id: [u8; 32],
    #[serde(with = "crate::encoding::decimal_u64_array8")]
    pub expected_versions: [u64; 8],
    #[serde(with = "crate::encoding::decimal_u64_array4")]
    pub authorization_epochs: [u64; 4],
    #[serde(with = "crate::encoding::decimal_u64")]
    pub expiry: u64,
}
impl std::fmt::Debug for OperationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationContext")
            .field("network_id", &hex::encode(self.network_id))
            .field("core_account", &hex::encode(self.core_account))
            .field("asset_id", &hex::encode(self.asset_id))
            .field("operation_id", &hex::encode(self.operation_id))
            .field("vault_id", &hex::encode(self.vault_id))
            .field("broker_id", &hex::encode(self.broker_id))
            .field("loan_id", &hex::encode(self.loan_id))
            .field("proposal_id", &hex::encode(self.proposal_id))
            .field("expected_versions", &self.expected_versions)
            .field("authorization_epochs", &self.authorization_epochs)
            .field("expiry", &self.expiry)
            .finish()
    }
}
impl Default for OperationContext {
    fn default() -> Self {
        Self {
            network_id: [0; 32],
            core_account: [0; 32],
            asset_id: [0; 32],
            // Keep `Default` useful for deterministic tests and examples while
            // still satisfying the non-zero replay identifier invariant. Real
            // callers must replace this with a deployment-unique operation ID.
            operation_id: identifier_digest(b"operation", "default-example-only"),
            vault_id: [0; 32],
            broker_id: [0; 32],
            loan_id: [0; 32],
            proposal_id: [0; 32],
            expected_versions: [0; 8],
            authorization_epochs: [0; 4],
            expiry: 0,
        }
    }
}

impl OperationContext {
    pub fn from_strings(
        network_id: &str,
        core_account: &str,
        asset_id: &str,
        operation_id: &str,
    ) -> Self {
        let mut context = Self::default();
        context.network_id = identifier_digest(b"network", network_id);
        context.core_account = identifier_digest(b"core", core_account);
        context.asset_id = identifier_digest(b"asset", asset_id);
        context.operation_id = identifier_digest(b"operation", operation_id);
        context
    }

    pub fn with_ids(mut self, vault: &str, broker: &str, loan: &str, proposal: &str) -> Self {
        self.vault_id = identifier_digest(b"vault", vault);
        self.broker_id = identifier_digest(b"broker", broker);
        self.loan_id = identifier_digest(b"loan", loan);
        self.proposal_id = identifier_digest(b"proposal", proposal);
        self
    }

    pub fn canonical_fields(&self) -> Vec<Fr> {
        let mut fields = Vec::with_capacity(8 * 4 + 8 + 4 + 1);
        for id in [
            self.network_id,
            self.core_account,
            self.asset_id,
            self.operation_id,
            self.vault_id,
            self.broker_id,
            self.loan_id,
            self.proposal_id,
        ] {
            for chunk in id.chunks_exact(8) {
                fields.push(Fr::from(u64::from_le_bytes(chunk.try_into().unwrap())));
            }
        }
        fields.extend(self.expected_versions.into_iter().map(Fr::from));
        fields.extend(self.authorization_epochs.into_iter().map(Fr::from));
        fields.push(Fr::from(self.expiry));
        fields
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.operation_id == [0; 32] {
            return Err(CryptoError::InvalidContext);
        }
        Ok(())
    }
}

pub(crate) fn identifier_digest(domain: &[u8], value: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NEAR-CONFIDENTIAL-LENDING/IDENTIFIER/v1");
    h.update((domain.len() as u32).to_le_bytes());
    h.update(domain);
    h.update((value.len() as u32).to_le_bytes());
    h.update(value.as_bytes());
    h.finalize().into()
}

/// Fixed-width public slot builder shared by all circuit families.  The
/// resulting transcript is the actual public input relation checked in-circuit;
/// no caller-selected circuit shape or hidden ad-hoc JSON is accepted.
#[derive(Clone)]
pub struct SlotBuilder {
    pub(crate) values: Vec<Fr>,
}

impl SlotBuilder {
    pub fn new(context: &OperationContext, kind: StatementKind) -> Result<Self, CryptoError> {
        context.validate()?;
        let mut values = context.canonical_fields();
        values.push(Fr::from(kind.as_u8() as u64));
        Ok(Self { values })
    }

    pub fn push_field(&mut self, value: Fr) {
        self.values.push(value);
    }

    pub fn push_u64(&mut self, value: u64) {
        self.values.push(Fr::from(value));
    }

    pub fn push_bytes(&mut self, value: &[u8]) {
        for chunk in value.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.push_u64(u64::from_le_bytes(word));
        }
    }

    pub fn push_point(&mut self, point: &PointHex) -> Result<(), CryptoError> {
        let p = point.to_affine()?;
        self.push_field(p.x);
        self.push_field(p.y);
        Ok(())
    }

    pub fn push_public_key(&mut self, key: &PublicKey) -> Result<(), CryptoError> {
        self.push_point(&key.point)
    }

    pub fn push_ciphertext(&mut self, ciphertext: &Ciphertext) -> Result<(), CryptoError> {
        self.push_point(&ciphertext.ephemeral)?;
        self.push_point(&ciphertext.message)
    }

    pub fn push_recovery_pair(
        &mut self,
        pair: &crate::statement::RecoveryPair,
    ) -> Result<(), CryptoError> {
        self.push_ciphertext(&pair.low_limb)?;
        self.push_ciphertext(&pair.high_limb)
    }

    pub fn push_commitment(&mut self, commitment: &Commitment) -> Result<(), CryptoError> {
        self.push_point(&commitment.point)
    }

    pub fn finish(self) -> Result<PublicSlots, CryptoError> {
        if self.values.len() > CONTEXT_SLOTS {
            return Err(CryptoError::StatementTooLarge);
        }
        let digest = transcript_hash(&self.values);
        Ok(PublicSlots {
            digest,
            values: self.values,
        })
    }
}

#[derive(Clone)]
pub struct PublicSlots {
    pub digest: Fr,
    pub values: Vec<Fr>,
}

impl PublicSlots {
    pub fn public_inputs(&self) -> Vec<Fr> {
        let mut result = Vec::with_capacity(self.values.len() + 1);
        result.push(self.digest);
        result.extend(self.values.iter().copied());
        result
    }

    pub fn digest_wire(&self) -> FieldHex {
        FieldHex::from(self.digest)
    }
}

/// Canonical Poseidon transcript digest for the fixed public-input vector.
/// The same pinned arkworks Poseidon configuration is evaluated by the host
/// and by the R1CS gadget, so changing any context, stored state, output,
/// point, flag, or version changes the constrained digest.
pub fn transcript_hash(values: &[Fr]) -> Fr {
    let mut input = Vec::with_capacity(values.len() + 2);
    input.push(Fr::from_le_bytes_mod_order(
        b"NEAR-CONFIDENTIAL-LENDING/TRANSCRIPT/POSEIDON/v1",
    ));
    input.push(Fr::from(values.len() as u64));
    input.extend_from_slice(values);
    let mut sponge = PoseidonSponge::new(&poseidon_config());
    sponge.absorb(&input);
    sponge.squeeze_field_elements(1)[0]
}

/// Pinned arkworks Poseidon parameters: width 3 (rate 2, capacity 1), alpha
/// 5, 8 full rounds, 57 partial rounds, and Grain-generated ARK/MDS with no
/// matrix skip. This is the arkworks/circomlib-compatible width-3 profile;
/// the exact generated constants are part of the immutable CryptoProfile.
pub(crate) fn poseidon_config() -> PoseidonConfig<Fr> {
    let (ark, mds) = ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        2,
        8,
        57,
        0,
    );
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

#[cfg(test)]
mod poseidon_vectors {
    use super::*;
    use ark_crypto_primitives::sponge::{CryptographicSponge, poseidon::PoseidonSponge};
    use std::str::FromStr;

    #[test]
    fn circomlib_bn254_width3_vector() {
        let mut sponge = PoseidonSponge::new(&poseidon_config());
        let input = vec![Fr::from(0u64), Fr::from(1u64)];
        sponge.absorb(&input);
        let output = sponge.squeeze_field_elements::<Fr>(1)[0];
        assert_eq!(
            output,
            Fr::from_str(
                "9807604810977681540537942462159990591554827872659661794094614452930421286825",
            )
            .unwrap()
        );
    }
}

