use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AffineRepr, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, EdwardsProjective, Fq};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use sha2::{Digest, Sha256};

use crate::CryptoError;

/// Domain-separated try-and-increment hash-to-curve used for the Pedersen H
/// generator.  The output is cleared by the Edwards cofactor and then
/// validated in the prime-order subgroup.  It does not multiply the standard
/// generator by a hash-derived scalar, so no discrete logarithm of H is
/// intentionally created by this implementation.
pub const PEDERSEN_DOMAIN: &[u8] = b"NEAR-CONFIDENTIAL-LENDING/PEDERSEN-H/v1";

pub fn encryption_base() -> EdwardsProjective {
    EdwardsProjective::generator()
}

pub fn pedersen_base() -> EdwardsProjective {
    hash_to_curve(PEDERSEN_DOMAIN, b"asset-independent")
        .expect("fixed Pedersen domain must map to a curve point")
}

pub fn hash_to_curve(domain: &[u8], message: &[u8]) -> Result<EdwardsProjective, CryptoError> {
    for counter in 0u32..u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(b"NEAR-CL-H2C-EDWARDS-BN254/v1");
        hasher.update((domain.len() as u32).to_le_bytes());
        hasher.update(domain);
        hasher.update((message.len() as u32).to_le_bytes());
        hasher.update(message);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let x = Fq::from_le_bytes_mod_order(&digest);
        let x2 = x.square();
        // EdwardsConfig: a*x² + y² = 1 + d*x²*y², a = 1.
        let denominator = Fq::ONE - EdwardsConfig::COEFF_D * x2;
        if denominator.is_zero() {
            continue;
        }
        let y2 = (Fq::ONE - x2)
            * denominator
                .inverse()
                .ok_or(CryptoError::InvalidCommitment)?;
        let Some(mut y) = y2.sqrt() else { continue };
        let desired_sign = digest[0] & 1;
        let current_sign = y.into_bigint().is_odd();
        if (current_sign as u8) != desired_sign {
            y = -y;
        }
        let point = EdwardsAffine::new_unchecked(x, y);
        if !point.is_on_curve() {
            continue;
        }
        let point = point.clear_cofactor();
        if point.is_zero() || !point.is_in_correct_subgroup_assuming_on_curve() {
            continue;
        }
        return Ok(point.into());
    }
    Err(CryptoError::InvalidCommitment)
}
