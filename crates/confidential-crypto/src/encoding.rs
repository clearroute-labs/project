use ark_bn254::Fr as CircuitFr;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::AdditiveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{io::Cursor, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use crate::CryptoError;

const MAX_VALIDATED_POINT_CACHE_ENTRIES: usize = 1024;

thread_local! {
    /// Decoding a compressed Edwards point with `Validate::Yes` performs the
    /// subgroup check. Statement deserialization and public-slot derivation
    /// commonly encounter the same point twice, so retain only the affine
    /// result of a *fully validated canonical* wire value. The bounded map is
    /// per execution thread and does not affect the wire format or protocol
    /// state.
    static VALIDATED_POINT_CACHE: RefCell<BTreeMap<String, EdwardsAffine>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Canonical JSON decimal helpers for monetary values, versions, and times.
/// JSON numbers are intentionally rejected so browser code cannot silently
/// round values above JavaScript's 53-bit integer range.
pub mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        parse(&value).map_err(serde::de::Error::custom)
    }

    pub fn parse(value: &str) -> Result<u64, &'static str> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("invalid decimal u64");
        }
        value.parse().map_err(|_| "decimal u64 out of range")
    }
}

pub mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let value = String::deserialize(deserializer)?;
        parse(&value).map_err(serde::de::Error::custom)
    }

    pub fn parse(value: &str) -> Result<u128, &'static str> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("invalid decimal u128");
        }
        value.parse().map_err(|_| "decimal u128 out of range")
    }
}

macro_rules! decimal_array_module {
    ($module:ident, $len:expr) => {
        pub mod $module {
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            pub fn serialize<S: Serializer>(
                value: &[u64; $len],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                value
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .serialize(serializer)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<[u64; $len], D::Error> {
                let values = Vec::<String>::deserialize(deserializer)?;
                if values.len() != $len {
                    return Err(serde::de::Error::custom("invalid decimal array length"));
                }
                let mut result = [0u64; $len];
                for (index, value) in values.iter().enumerate() {
                    result[index] =
                        super::decimal_u64::parse(value).map_err(serde::de::Error::custom)?;
                }
                Ok(result)
            }
        }
    };
}

decimal_array_module!(decimal_u64_array4, 4);
decimal_array_module!(decimal_u64_array8, 8);

/// A canonical compressed Edwards point encoded as lower-case hexadecimal.
///
/// The constructor performs all point validation.  The field remains a string
/// on the wire so a Core contract can persist it without depending on arkworks
/// layout details.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PointHex(pub String);

impl fmt::Debug for PointHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PointHex").field(&self.0).finish()
    }
}

impl Serialize for PointHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PointHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl From<EdwardsAffine> for PointHex {
    fn from(point: EdwardsAffine) -> Self {
        Self(encode_point(&point).expect("valid Edwards point serializes"))
    }
}

impl PointHex {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        // `decode_point` already verifies the compressed representation is
        // canonical, so preserve the validated wire string instead of
        // serializing the affine point a second time. This matters for the
        // contract-side statement parser, where every distinct point is
        // otherwise decompressed and re-encoded during deserialization.
        let _ = decode_point(value, false)?;
        Ok(Self(value.to_owned()))
    }

    pub fn parse_non_identity(value: &str) -> Result<Self, CryptoError> {
        let _ = decode_point(value, true)?;
        Ok(Self(value.to_owned()))
    }

    pub fn to_affine(&self) -> Result<EdwardsAffine, CryptoError> {
        decode_point(&self.0, false)
    }

    pub fn to_projective(&self) -> Result<EdwardsProjective, CryptoError> {
        Ok(self.to_affine()?.into())
    }

    pub fn is_identity(&self) -> Result<bool, CryptoError> {
        Ok(self.to_affine()?.is_zero())
    }
}

/// A canonical compressed scalar encoded as lower-case hexadecimal.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScalarHex(pub String);

impl fmt::Debug for ScalarHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not accidentally expose a secret scalar in debug output.
        f.debug_tuple("ScalarHex").field(&"<redacted>").finish()
    }
}

/// A canonical BN254 scalar used for Groth16 public inputs and transcript
/// digests.  This is intentionally distinct from `ScalarHex`, whose modulus is
/// the scalar field of ark-ed-on-bn254 and is used for encryption randomness.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldHex(pub String);

impl fmt::Debug for FieldHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FieldHex").field(&self.0).finish()
    }
}

impl Serialize for FieldHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FieldHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl From<CircuitFr> for FieldHex {
    fn from(value: CircuitFr) -> Self {
        let mut bytes = Vec::new();
        value
            .serialize_compressed(&mut bytes)
            .expect("valid field serializes");
        Self(hex::encode(bytes))
    }
}

impl FieldHex {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let scalar = decode_circuit_scalar(value)?;
        let mut bytes = Vec::new();
        scalar
            .serialize_compressed(&mut bytes)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(Self(hex::encode(bytes)))
    }

    pub fn to_field(&self) -> Result<CircuitFr, CryptoError> {
        decode_circuit_scalar(&self.0)
    }
}

impl Serialize for ScalarHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ScalarHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl From<Fr> for ScalarHex {
    fn from(value: Fr) -> Self {
        Self(encode_scalar(&value).expect("valid scalar serializes"))
    }
}

impl ScalarHex {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let scalar = decode_scalar(value)?;
        Ok(Self(encode_scalar(&scalar)?))
    }

    pub fn to_scalar(&self) -> Result<Fr, CryptoError> {
        decode_scalar(&self.0)
    }
}

pub(crate) fn encode_point(point: &EdwardsAffine) -> Result<String, CryptoError> {
    let mut bytes = Vec::new();
    point
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(hex::encode(bytes))
}

pub(crate) fn decode_point(value: &str, non_identity: bool) -> Result<EdwardsAffine, CryptoError> {
    if let Some(point) = VALIDATED_POINT_CACHE.with(|cache| cache.borrow().get(value).cloned()) {
        // Identity is valid for generic PointHex values but not for public
        // keys. Re-apply this cheap policy check on every cache hit rather
        // than allowing a generic parse to weaken parse_non_identity.
        if non_identity && point.is_zero() {
            return Err(CryptoError::IdentityPoint);
        }
        return Ok(point);
    }

    // Keep the compressed input on the stack. `decode_lower_hex` returns a
    // fresh Vec because most scalar callers need owned bytes; point parsing
    // is on the contract's hot path and only needs a fixed-size cursor.
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| CryptoError::NonCanonicalEncoding)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    // Canonical deserialization performs field and compressed-coordinate
    // checks. The default arkworks subgroup check uses a bit-by-bit scalar
    // multiplication by `r`; use the equivalent fixed-window multiplication
    // below to retain the same full-order check at lower contract gas.
    let point = EdwardsAffine::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::No)
        .map_err(|_| CryptoError::MalformedPoint)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    if !point.is_on_curve() || !is_in_prime_subgroup(&point) {
        return Err(CryptoError::MalformedPoint);
    }
    let mut encoded = [0_u8; 32];
    point
        .serialize_with_mode(&mut encoded[..], Compress::Yes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    if encoded != bytes {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    // Apply the identity policy before caching so no rejected identity can be
    // promoted to a cached valid public key.
    if non_identity && point.is_zero() {
        return Err(CryptoError::IdentityPoint);
    }
    VALIDATED_POINT_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_VALIDATED_POINT_CACHE_ENTRIES
            && let Some(oldest) = cache.keys().next().cloned()
        {
            cache.remove(&oldest);
        }
        cache.insert(value.to_owned(), point);
    });
    Ok(point)
}

/// Check `[r]P == 0` with a fixed width-4 non-adjacent form. The sparse digit
/// table is the canonical width-4 recoding of the immutable BN254 scalar
/// modulus, so this remains the same subgroup predicate as arkworks while
/// replacing roughly half of the mixed additions in its generic check.
const BN254_SCALAR_WNAF4: &[(usize, i8)] = &[
    (0, 1),
    (4, -1),
    (8, 7),
    (13, -7),
    (17, 1),
    (21, -7),
    (25, -3),
    (30, 1),
    (34, 7),
    (38, -1),
    (43, 3),
    (47, 5),
    (52, 7),
    (56, 7),
    (61, 3),
    (65, 5),
    (73, 7),
    (77, 7),
    (85, -7),
    (89, -3),
    (94, 1),
    (99, 7),
    (103, -5),
    (108, -1),
    (112, -1),
    (118, -3),
    (122, -5),
    (126, -1),
    (130, 3),
    (136, -5),
    (140, 3),
    (148, 3),
    (156, -3),
    (160, 7),
    (164, -5),
    (168, -7),
    (172, 1),
    (177, 5),
    (184, 7),
    (188, 3),
    (192, 5),
    (202, -3),
    (206, -7),
    (211, 5),
    (218, 7),
    (222, -7),
    (228, -3),
    (233, 5),
    (239, -7),
    (244, 1),
    (249, 3),
];

fn is_in_prime_subgroup(point: &EdwardsAffine) -> bool {
    let base = EdwardsProjective::from(*point);
    let twice = base + base;
    let mut table = [EdwardsProjective::default(); 4];
    table[0] = base;
    for index in 1..4 {
        table[index] = table[index - 1] + twice;
    }
    let table = EdwardsProjective::normalize_batch(&table);
    let mut digits = [0_i8; 250];
    for &(index, digit) in BN254_SCALAR_WNAF4 {
        digits[index] = digit;
    }
    let mut result = EdwardsProjective::default();
    for bit in (0..digits.len()).rev() {
        result.double_in_place();
        match digits[bit] {
            digit if digit > 0 => result += &table[((digit - 1) / 2) as usize],
            digit if digit < 0 => result -= &table[((-digit - 1) / 2) as usize],
            _ => {}
        }
    }
    result.is_zero()
}

pub(crate) fn encode_scalar(value: &Fr) -> Result<String, CryptoError> {
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(hex::encode(bytes))
}

pub(crate) fn decode_scalar(value: &str) -> Result<Fr, CryptoError> {
    let bytes = decode_lower_hex(value, 32)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let scalar = Fr::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::Yes)
        .map_err(|_| CryptoError::MalformedScalar)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    if encode_scalar(&scalar)? != value {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    Ok(scalar)
}

fn decode_lower_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, CryptoError> {
    if value.len() != expected_bytes * 2
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    let bytes = hex::decode(value).map_err(|_| CryptoError::NonCanonicalEncoding)?;
    if bytes.len() != expected_bytes {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    Ok(bytes)
}

fn decode_circuit_scalar(value: &str) -> Result<CircuitFr, CryptoError> {
    let bytes = decode_lower_hex(value, 32)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let scalar =
        CircuitFr::deserialize_compressed(&mut cursor).map_err(|_| CryptoError::MalformedScalar)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    let mut encoded = Vec::new();
    scalar
        .serialize_compressed(&mut encoded)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    if hex::encode(encoded) != value {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_ed_on_bn254::Fq;
    use ark_ff::{Field, Zero};

    use super::*;

    #[test]
    fn cached_identity_cannot_satisfy_non_identity_policy() {
        let identity = PointHex::from(EdwardsProjective::zero().into_affine());
        assert!(PointHex::parse(&identity.0).is_ok());
        assert!(matches!(
            PointHex::parse_non_identity(&identity.0),
            Err(CryptoError::IdentityPoint)
        ));
    }

    #[test]
    fn windowed_subgroup_check_matches_arkworks() {
        use ark_ff::UniformRand;
        use ark_std::test_rng;

        let mut rng = test_rng();
        for _ in 0..16 {
            let point = EdwardsProjective::rand(&mut rng).into_affine();
            assert_eq!(
                is_in_prime_subgroup(&point),
                point.is_in_correct_subgroup_assuming_on_curve()
            );
        }
    }

    #[test]
    fn windowed_subgroup_check_rejects_torsion_point() {
        // (0, -1) is the order-two point on Baby-Jubjub and therefore is on
        // the curve but outside its odd prime-order subgroup.
        let torsion = EdwardsAffine::new_unchecked(Fq::ZERO, -Fq::ONE);
        let encoded = encode_point(&torsion).expect("torsion point encodes");
        assert!(!is_in_prime_subgroup(&torsion));
        assert!(matches!(decode_point(&encoded, false), Err(CryptoError::MalformedPoint)));
    }

}
