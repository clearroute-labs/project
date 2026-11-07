use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::encoding::PointHex;
use crate::hash_to_curve::{encryption_base, pedersen_base};
use crate::{CryptoError, MAX_AMOUNT};

/// Hiding Pedersen commitment `mG + rH`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub point: PointHex,
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commitment")
            .field("point", &self.point)
            .finish()
    }
}

impl Commitment {
    pub fn commit<R: RngCore + CryptoRng>(
        amount: u64,
        rng: &mut R,
    ) -> Result<(Self, Fr), CryptoError> {
        let mut blind = Fr::rand(rng);
        while blind.is_zero() {
            blind = Fr::rand(rng);
        }
        Ok((Self::commit_with_blinding(amount, blind)?, blind))
    }

    pub fn commit_with_blinding(amount: u64, blind: Fr) -> Result<Self, CryptoError> {
        if amount > MAX_AMOUNT {
            return Err(CryptoError::AmountOutOfRange);
        }
        if blind.is_zero() {
            return Err(CryptoError::ZeroScalar);
        }
        let point = encryption_base() * Fr::from(amount) + pedersen_base() * blind;
        Ok(Self {
            point: PointHex::from_prime_subgroup_affine(point.into_affine()),
        })
    }

    /// Create a hiding commitment for a checked u128 accounting value.
    ///
    /// Aggregate reconciliation values are wider than an individual private
    /// balance, so they deliberately use the BN254 field's canonical encoding
    /// rather than the single-balance `MAX_AMOUNT` bound.
    pub fn commit_u128<R: RngCore + CryptoRng>(
        amount: u128,
        rng: &mut R,
    ) -> Result<(Self, Fr), CryptoError> {
        let mut blind = Fr::rand(rng);
        while blind.is_zero() {
            blind = Fr::rand(rng);
        }
        Ok((Self::commit_u128_with_blinding(amount, blind)?, blind))
    }

    pub fn commit_u128_with_blinding(amount: u128, blind: Fr) -> Result<Self, CryptoError> {
        if blind.is_zero() {
            return Err(CryptoError::ZeroScalar);
        }
        let amount_scalar = Fr::from_le_bytes_mod_order(&amount.to_le_bytes());
        let point = encryption_base() * amount_scalar + pedersen_base() * blind;
        Ok(Self {
            point: PointHex::from_prime_subgroup_affine(point.into_affine()),
        })
    }

    pub fn parse(point: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            point: PointHex::parse(point)?,
        })
    }

    pub fn verify(&self, amount: u64, blind: Fr) -> Result<bool, CryptoError> {
        if amount > MAX_AMOUNT {
            return Err(CryptoError::AmountOutOfRange);
        }
        let expected = Self::commit_with_blinding(amount, blind)?;
        Ok(expected == *self)
    }

    pub fn verify_u128(&self, amount: u128, blind: Fr) -> Result<bool, CryptoError> {
        Ok(Self::commit_u128_with_blinding(amount, blind)? == *self)
    }

    pub fn to_point(&self) -> Result<EdwardsProjective, CryptoError> {
        self.point.to_projective()
    }

    pub fn add(&self, other: &Self) -> Result<Self, CryptoError> {
        Ok(Self {
            point: PointHex::from_prime_subgroup_affine(
                (self.to_point()? + other.to_point()?).into_affine(),
            ),
        })
    }

    pub fn sub(&self, other: &Self) -> Result<Self, CryptoError> {
        let point = self.to_point()? - other.to_point()?;
        Ok(Self {
            point: PointHex::from_prime_subgroup_affine(point.into_affine()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::Fr;

    #[test]
    fn u128_commitment_round_trip_and_zero_blinding_rejection() {
        let amount = u128::from(u64::MAX) + 17;
        let blind = Fr::from(29u64);
        let commitment = Commitment::commit_u128_with_blinding(amount, blind).unwrap();
        assert!(commitment.verify_u128(amount, blind).unwrap());
        assert!(!commitment.verify_u128(amount + 1, blind).unwrap());
        assert!(Commitment::commit_u128_with_blinding(amount, Fr::from(0u64)).is_err());
    }
}
