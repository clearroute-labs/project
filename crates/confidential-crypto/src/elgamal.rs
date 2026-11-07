use std::collections::BTreeMap;

use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::{PointHex, ScalarHex, encode_point};
use crate::hash_to_curve::encryption_base;
use crate::{CryptoError, MAX_AMOUNT};

/// Additive ElGamal public key on the prime-order Baby-Jubjub subgroup.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub point: PointHex,
}
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PublicKey", 1)?;
        state.serialize_field("point", &self.point.0)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            point: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::parse(&wire.point).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("point", &self.point)
            .finish()
    }
}

impl PublicKey {
    pub fn from_secret(secret: &SecretKey) -> Self {
        let point = encryption_base() * secret.scalar;
        Self {
            point: PointHex::from_prime_subgroup_affine(point.into_affine()),
        }
    }

    pub fn parse(point: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            point: PointHex::parse_non_identity(point)?,
        })
    }

    pub fn to_point(&self) -> Result<EdwardsProjective, CryptoError> {
        self.point.to_projective()
    }

    pub fn verify_possession(&self, secret: &SecretKey) -> bool {
        Self::from_secret(secret) == *self
    }
}

/// Secret scalar for an additive ElGamal key.
///
/// The type deliberately does not implement `Serialize` or `Debug`; callers
/// must explicitly opt into the canonical scalar wire value when exporting a
/// secret to a wallet backup.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) scalar: Fr,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("scalar", &"<redacted>")
            .finish()
    }
}

impl SecretKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let scalar = Fr::rand(rng);
            if !scalar.is_zero() {
                return Self { scalar };
            }
        }
    }

    pub fn from_scalar(scalar: Fr) -> Result<Self, CryptoError> {
        if scalar.is_zero() {
            return Err(CryptoError::ZeroScalar);
        }
        Ok(Self { scalar })
    }

    pub fn from_wire(value: &ScalarHex) -> Result<Self, CryptoError> {
        Self::from_scalar(value.to_scalar()?)
    }

    pub fn to_wire(&self) -> ScalarHex {
        ScalarHex::from(self.scalar)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret(self)
    }

    pub(crate) fn scalar(&self) -> Fr {
        self.scalar
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.scalar == other.scalar
    }
}

/// Additive ElGamal ciphertext `(rG, mG + rPK)`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ephemeral: PointHex,
    pub message: PointHex,
}

impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("ephemeral", &self.ephemeral)
            .field("message", &self.message)
            .finish()
    }
}

impl Ciphertext {
    pub fn parse(ephemeral: &str, message: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            // Homomorphic subtraction may legitimately produce the identity
            // ephemeral component (for example C - C = Enc(0; 0)). Fresh
            // encryption still rejects zero randomness in
            // `encrypt_with_randomness`.
            ephemeral: PointHex::parse(ephemeral)?,
            message: PointHex::parse(message)?,
        })
    }

    /// Canonical zero ciphertext for a key and caller-supplied domain. The
    /// deterministic non-zero randomness avoids an identity encoding in
    /// persisted zero balances while remaining publicly reproducible; the
    /// domain must include the deployment/account/asset context.
    pub fn canonical_zero(public_key: &PublicKey, domain: &[u8]) -> Result<Self, CryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(b"NEAR-CONFIDENTIAL-LENDING/CANONICAL-ZERO/v1");
        hasher.update((domain.len() as u32).to_le_bytes());
        hasher.update(domain);
        hasher.update(public_key.point.0.as_bytes());
        let mut randomness = Fr::from_le_bytes_mod_order(&hasher.finalize());
        if randomness.is_zero() {
            randomness = Fr::from(1u64);
        }
        Self::encrypt_with_randomness(public_key, 0, randomness)
    }

    /// Identity encoding used only as the algebraic result of a
    /// homomorphic cancellation. Persistent account state should prefer
    /// `canonical_zero` so its ciphertext remains non-degenerate.
    pub fn zero() -> Self {
        let identity = PointHex::from_prime_subgroup_affine(EdwardsProjective::zero().into_affine());
        Self {
            ephemeral: identity.clone(),
            message: identity,
        }
    }

    pub fn to_points(&self) -> Result<(EdwardsProjective, EdwardsProjective), CryptoError> {
        Ok((
            self.ephemeral.to_projective()?,
            self.message.to_projective()?,
        ))
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        public_key: &PublicKey,
        amount: u64,
        rng: &mut R,
    ) -> Result<(Self, Fr), CryptoError> {
        let randomness = random_nonzero(rng);
        Ok((
            Self::encrypt_with_randomness(public_key, amount, randomness)?,
            randomness,
        ))
    }

    pub fn encrypt_with_randomness(
        public_key: &PublicKey,
        amount: u64,
        randomness: Fr,
    ) -> Result<Self, CryptoError> {
        if amount > MAX_AMOUNT || randomness.is_zero() {
            return Err(if amount > MAX_AMOUNT {
                CryptoError::AmountOutOfRange
            } else {
                CryptoError::ZeroScalar
            });
        }
        let pk = public_key.to_point()?;
        let base = encryption_base();
        let ephemeral = base * randomness;
        let message = base * Fr::from(amount) + pk * randomness;
        Ok(Self {
            ephemeral: PointHex::from_prime_subgroup_affine(ephemeral.into_affine()),
            message: PointHex::from_prime_subgroup_affine(message.into_affine()),
        })
    }

    /// Encrypt an aggregate accounting value with fresh non-zero randomness.
    pub fn encrypt_u128<R: RngCore + CryptoRng>(
        public_key: &PublicKey,
        amount: u128,
        rng: &mut R,
    ) -> Result<(Self, Fr), CryptoError> {
        let randomness = random_nonzero(rng);
        Ok((
            Self::encrypt_u128_with_randomness(public_key, amount, randomness)?,
            randomness,
        ))
    }

    pub fn encrypt_u128_with_randomness(
        public_key: &PublicKey,
        amount: u128,
        randomness: Fr,
    ) -> Result<Self, CryptoError> {
        if randomness.is_zero() {
            return Err(CryptoError::ZeroScalar);
        }
        let pk = public_key.to_point()?;
        let base = encryption_base();
        let amount_scalar = Fr::from_le_bytes_mod_order(&amount.to_le_bytes());
        let ephemeral = base * randomness;
        let message = base * amount_scalar + pk * randomness;
        Ok(Self {
            ephemeral: PointHex::from_prime_subgroup_affine(ephemeral.into_affine()),
            message: PointHex::from_prime_subgroup_affine(message.into_affine()),
        })
    }

    pub fn decrypt_point(&self, secret: &SecretKey) -> Result<EdwardsProjective, CryptoError> {
        let (ephemeral, message) = self.to_points()?;
        Ok(message - ephemeral * secret.scalar())
    }

    /// Check a caller-supplied u128 plaintext against this ciphertext without
    /// performing an infeasible discrete-log recovery. This is useful when a
    /// durable, proof-bound transition record already supplied the amount.
    pub fn verify_plaintext_u128(
        &self,
        secret: &SecretKey,
        amount: u128,
    ) -> Result<bool, CryptoError> {
        let expected = encryption_base() * Fr::from_le_bytes_mod_order(&amount.to_le_bytes());
        Ok(self.decrypt_point(secret)? == expected)
    }

    /// Recover an amount when the caller supplies a realistic bound.  The
    /// implementation uses baby-step/giant-step and is therefore capped at
    /// 2^32 values.  Full 63-bit balances use [`crate::RecoveryRecord`], which
    /// proves and encrypts two 32-bit limbs.
    pub fn decrypt_bounded(&self, secret: &SecretKey, max_amount: u64) -> Result<u64, CryptoError> {
        if max_amount > u32::MAX as u64 {
            return Err(CryptoError::RecoveryRequired);
        }
        let target = self.decrypt_point(secret)?;
        discrete_log_bounded(target, max_amount)
    }

    /// Direct decryption intentionally refuses an infeasible full-range scan.
    /// Wallets should call `decrypt_with_recovery` with the authenticated record
    /// persisted beside the corresponding ciphertext.
    pub fn decrypt(&self, secret: &SecretKey) -> Result<u64, CryptoError> {
        self.decrypt_bounded(secret, u32::MAX as u64)
    }

    pub fn add(&self, other: &Self) -> Result<Self, CryptoError> {
        let (e1, m1) = self.to_points()?;
        let (e2, m2) = other.to_points()?;
        Ok(Self {
            ephemeral: PointHex::from_prime_subgroup_affine((e1 + e2).into_affine()),
            message: PointHex::from_prime_subgroup_affine((m1 + m2).into_affine()),
        })
    }

    pub fn sub(&self, other: &Self) -> Result<Self, CryptoError> {
        let (e1, m1) = self.to_points()?;
        let (e2, m2) = other.to_points()?;
        let ephemeral = e1 - e2;
        Ok(Self {
            ephemeral: PointHex::from_prime_subgroup_affine(ephemeral.into_affine()),
            message: PointHex::from_prime_subgroup_affine((m1 - m2).into_affine()),
        })
    }

    pub fn rerandomize<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Self, Fr), CryptoError> {
        let delta = random_nonzero(rng);
        let (ephemeral, message) = self.to_points()?;
        let pk = public_key.to_point()?;
        let next_ephemeral = ephemeral + encryption_base() * delta;
        let next_message = message + pk * delta;
        // The plaintext contribution is unchanged while the ElGamal
        // randomness changes from r to r + delta.
        Ok((
            Self {
                ephemeral: PointHex::from_prime_subgroup_affine(next_ephemeral.into_affine()),
                message: PointHex::from_prime_subgroup_affine(next_message.into_affine()),
            },
            delta,
        ))
    }
}

fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    loop {
        let scalar = Fr::rand(rng);
        if !scalar.is_zero() {
            return scalar;
        }
    }
}

pub(crate) fn discrete_log_bounded(
    target: EdwardsProjective,
    max_amount: u64,
) -> Result<u64, CryptoError> {
    let m = (max_amount as f64).sqrt().ceil().max(1.0) as u64;
    if m > (1u64 << 16) {
        return Err(CryptoError::RecoveryRequired);
    }
    let base = encryption_base();
    let mut baby = BTreeMap::<String, u64>::new();
    let mut current = EdwardsProjective::zero();
    for j in 0..m {
        baby.entry(encode_point(&current.into_affine())?)
            .or_insert(j);
        current += base;
    }
    let giant_step = -(base * Fr::from(m));
    let mut gamma = target;
    for i in 0..=m {
        if let Some(j) = baby.get(&encode_point(&gamma.into_affine())?) {
            let candidate = i.saturating_mul(m).saturating_add(*j);
            if candidate <= max_amount && base * Fr::from(candidate) == target {
                return Ok(candidate);
            }
        }
        gamma += giant_step;
    }
    Err(CryptoError::DiscreteLogFailed)
}

pub(crate) fn recover_limb_pair(
    low: &Ciphertext,
    high: &Ciphertext,
    secret: &SecretKey,
    expected_key: &PublicKey,
) -> Result<u64, CryptoError> {
    if &secret.public_key() != expected_key {
        return Err(CryptoError::InvalidKey);
    }
    let low = discrete_log_bounded(low.decrypt_point(secret)?, u32::MAX as u64)?;
    let high = discrete_log_bounded(high.decrypt_point(secret)?, u32::MAX as u64)?;
    low.checked_add(
        high.checked_shl(32)
            .ok_or(CryptoError::RecoveryOutOfRange)?,
    )
    .filter(|amount| *amount <= MAX_AMOUNT)
    .ok_or(CryptoError::RecoveryOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::Fr;

    #[test]
    fn homomorphic_subtraction_accepts_identity_and_zero_has_canonical_form() {
        let secret = SecretKey::from_scalar(Fr::from(17u64)).unwrap();
        let key = secret.public_key();
        let ciphertext = Ciphertext::encrypt_with_randomness(&key, 0, Fr::from(19u64)).unwrap();
        let identity = ciphertext.sub(&ciphertext).unwrap();
        assert!(identity.ephemeral.is_identity().unwrap());
        assert!(identity.message.is_identity().unwrap());
        let wire = serde_json::to_string(&identity).unwrap();
        let decoded: Ciphertext = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, identity);

        let canonical = Ciphertext::canonical_zero(&key, b"network/account/asset").unwrap();
        assert!(!canonical.ephemeral.is_identity().unwrap());
        assert!(!canonical.message.is_identity().unwrap());
        assert_eq!(canonical.decrypt_bounded(&secret, 0).unwrap(), 0);
    }

    #[test]
    fn wire_decoding_rejects_noncanonical_key_text() {
        let secret = SecretKey::from_scalar(Fr::from(23u64)).unwrap();
        let key = secret.public_key();
        let encoded = key.point.0.clone();
        assert!(PublicKey::parse(&encoded.to_uppercase()).is_err());
        assert!(PublicKey::parse(&encoded[..encoded.len() - 2]).is_err());
    }
}
