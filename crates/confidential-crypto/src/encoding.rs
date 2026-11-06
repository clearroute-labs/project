use ark_bn254::Fr as CircuitFr;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use std::fmt;
use ark_std::io::Cursor;

use crate::CryptoError;

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
        let point = decode_point(value, false)?;
        Ok(Self(encode_point(&point)?))
    }

    pub fn parse_non_identity(value: &str) -> Result<Self, CryptoError> {
        let point = decode_point(value, true)?;
        Ok(Self(encode_point(&point)?))
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
    let bytes = decode_lower_hex(value, 32)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let point = EdwardsAffine::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::Yes)
        .map_err(|_| CryptoError::MalformedPoint)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    let encoded = encode_point(&point)?;
    if encoded != value {
        return Err(CryptoError::NonCanonicalEncoding);
    }
    // `Validate::Yes` performs the canonical on-curve and subgroup checks for
    // this arkworks affine type. Do not repeat those checks here: this decoder
    // is also used on every public statement point by the contract adapter.
    if non_identity && point.is_zero() {
        return Err(CryptoError::IdentityPoint);
    }
    Ok(point)
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
