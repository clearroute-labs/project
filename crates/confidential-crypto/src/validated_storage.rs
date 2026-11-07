//! Trusted decoder for immutable, previously subgroup-validated Core state.
//!
//! This module is deliberately feature-gated and is not enabled by the
//! browser or native wallet features. Core may enable `validated-storage`
//! only for bytes loaded from authenticated persisted state whose subgroup
//! membership was established when the value was first accepted. The decoder
//! still enforces exact lower-hex encoding, canonical compressed encoding,
//! curve membership, and the public-key identity policy. It only omits the
//! repeated host `[r]P == 0` check and promotes the exact points it parsed;
//! it never promotes the thread-local statement cache wholesale.

use std::ops::Deref;

use crate::encoding::with_statement_point_subgroup_check;
use crate::{Ciphertext, Commitment, CryptoError, PublicKey};

/// A public key parsed from authenticated, previously subgroup-validated
/// persisted state. It dereferences to the ordinary key type so existing
/// homomorphic Core code can consume it without a second decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPublicKey(PublicKey);

impl StoredPublicKey {
    pub fn as_public_key(&self) -> &PublicKey {
        &self.0
    }

    pub fn into_public_key(self) -> PublicKey {
        self.0
    }
}

impl AsRef<PublicKey> for StoredPublicKey {
    fn as_ref(&self) -> &PublicKey {
        self.as_public_key()
    }
}

impl Deref for StoredPublicKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        self.as_public_key()
    }
}

/// A ciphertext parsed from authenticated, previously subgroup-validated
/// persisted state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCiphertext(Ciphertext);

impl StoredCiphertext {
    pub fn as_ciphertext(&self) -> &Ciphertext {
        &self.0
    }

    pub fn into_ciphertext(self) -> Ciphertext {
        self.0
    }
}

impl AsRef<Ciphertext> for StoredCiphertext {
    fn as_ref(&self) -> &Ciphertext {
        self.as_ciphertext()
    }
}

impl Deref for StoredCiphertext {
    type Target = Ciphertext;

    fn deref(&self) -> &Self::Target {
        self.as_ciphertext()
    }
}

/// A commitment parsed from authenticated, previously subgroup-validated
/// persisted state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCommitment(Commitment);

impl StoredCommitment {
    pub fn as_commitment(&self) -> &Commitment {
        &self.0
    }

    pub fn into_commitment(self) -> Commitment {
        self.0
    }
}

impl AsRef<Commitment> for StoredCommitment {
    fn as_ref(&self) -> &Commitment {
        self.as_commitment()
    }
}

impl Deref for StoredCommitment {
    type Target = Commitment;

    fn deref(&self) -> &Self::Target {
        self.as_commitment()
    }
}

/// Parse one persisted public-key point under the trusted-state contract.
pub fn parse_key(point: &str) -> Result<StoredPublicKey, CryptoError> {
    let key = with_statement_point_subgroup_check(|| PublicKey::parse(point))?;
    key.point.promote_after_trusted_validation()?;
    Ok(StoredPublicKey(key))
}

/// Parse both persisted ciphertext points under the trusted-state contract.
/// Identity points remain valid for homomorphic cancellation results.
pub fn parse_ciphertext(ephemeral: &str, message: &str) -> Result<StoredCiphertext, CryptoError> {
    let ciphertext = with_statement_point_subgroup_check(|| Ciphertext::parse(ephemeral, message))?;
    ciphertext.ephemeral.promote_after_trusted_validation()?;
    ciphertext.message.promote_after_trusted_validation()?;
    Ok(StoredCiphertext(ciphertext))
}

/// Parse one persisted commitment point under the trusted-state contract.
pub fn parse_commitment(point: &str) -> Result<StoredCommitment, CryptoError> {
    let commitment = with_statement_point_subgroup_check(|| Commitment::parse(point))?;
    commitment.point.promote_after_trusted_validation()?;
    Ok(StoredCommitment(commitment))
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
    use ark_ff::Zero;

    use super::*;
    use crate::SecretKey;
    use crate::encoding::PointHex;

    #[test]
    fn trusted_decoder_accepts_valid_state_and_generic_parser_remains_strict() {
        let secret = SecretKey::from_scalar(Fr::from(17u64)).unwrap();
        let key = secret.public_key();
        let ciphertext = Ciphertext::encrypt_with_randomness(&key, 9, Fr::from(19u64)).unwrap();
        let commitment = Commitment::commit_with_blinding(9, Fr::from(23u64)).unwrap();

        let stored_key = parse_key(&key.point.0).unwrap();
        let stored_ciphertext =
            parse_ciphertext(&ciphertext.ephemeral.0, &ciphertext.message.0).unwrap();
        let stored_commitment = parse_commitment(&commitment.point.0).unwrap();
        assert_eq!(stored_key.as_public_key(), &key);
        assert_eq!(stored_ciphertext.as_ciphertext(), &ciphertext);
        assert_eq!(stored_commitment.as_commitment(), &commitment);

        let torsion = EdwardsAffine::new_unchecked(Fq::from(0u64), -Fq::from(1u64));
        let torsion_wire = PointHex::from(torsion).0;
        assert!(matches!(
            PublicKey::parse(&torsion_wire),
            Err(CryptoError::MalformedPoint)
        ));
        // The generic parser rejected this untrusted wire before the trusted
        // decoder was invoked. The feature-gated decoder intentionally relies
        // on Core's persisted-state invariant and therefore accepts its
        // canonical/on-curve representation without repeating the subgroup
        // multiplication.
        let stored_torsion = parse_key(&torsion_wire).unwrap();
        assert_eq!(stored_torsion.as_public_key().point.0, torsion_wire);

        // Identity is allowed for a homomorphic result but never for a key.
        let identity = PointHex::from(EdwardsProjective::zero().into_affine()).0;
        assert!(parse_ciphertext(&identity, &identity).is_ok());
        assert!(matches!(
            parse_key(&identity),
            Err(CryptoError::IdentityPoint)
        ));
    }
}
