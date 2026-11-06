//! Groth16 verification with canonical arkworks wire values and NEAR's BN254 hosts.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use thiserror::Error;

mod prepared;
pub use prepared::{prepare_key, prepared_key_hash, validate_prepared_key, verify_prepared};

pub const MAX_PUBLIC_INPUTS: usize = 2048;
const MAX_VERIFYING_KEY_BYTES: usize = 128 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid canonical verifying key")]
    InvalidKey,
    #[error("invalid canonical proof")]
    InvalidProof,
    #[error("invalid canonical scalar")]
    InvalidScalar,
    #[error("public input count mismatch or limit exceeded")]
    InputCount,
    #[error("verification failed")]
    Verification,
}

fn decode<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8]) -> Option<T> {
    let mut remaining = bytes;
    let value = T::deserialize_compressed(&mut remaining).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    let mut canonical = Vec::new();
    value.serialize_compressed(&mut canonical).ok()?;
    (canonical == bytes).then_some(value)
}

pub fn validate_verifying_key(bytes: &[u8]) -> Result<usize, VerifyError> {
    if bytes.len() > MAX_VERIFYING_KEY_BYTES {
        return Err(VerifyError::InvalidKey);
    }
    let vk: VerifyingKey<Bn254> = decode(bytes).ok_or(VerifyError::InvalidKey)?;
    validate_decoded_key(&vk)?;
    Ok(vk.gamma_abc_g1.len() - 1)
}

fn validate_decoded_key(vk: &VerifyingKey<Bn254>) -> Result<(), VerifyError> {
    if vk.gamma_abc_g1.is_empty() || vk.gamma_abc_g1.len() > MAX_PUBLIC_INPUTS + 1 {
        return Err(VerifyError::InputCount);
    }
    use ark_ec::AffineRepr;
    if vk.alpha_g1.is_zero()
        || vk.beta_g2.is_zero()
        || vk.gamma_g2.is_zero()
        || vk.delta_g2.is_zero()
    {
        return Err(VerifyError::InvalidKey);
    }
    Ok(())
}

pub fn verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
) -> Result<bool, VerifyError> {
    if public_inputs.len() > MAX_PUBLIC_INPUTS || vk_bytes.len() > MAX_VERIFYING_KEY_BYTES {
        return Err(VerifyError::InputCount);
    }
    if proof_bytes.len() != 128 {
        return Err(VerifyError::InvalidProof);
    }
    let vk: VerifyingKey<Bn254> = decode(vk_bytes).ok_or(VerifyError::InvalidKey)?;
    validate_decoded_key(&vk)?;
    let proof: Proof<Bn254> = decode(proof_bytes).ok_or(VerifyError::InvalidProof)?;
    if vk.gamma_abc_g1.len() != public_inputs.len() + 1 {
        return Err(VerifyError::InputCount);
    }
    let inputs = public_inputs
        .iter()
        .map(|input| decode::<Fr>(input).ok_or(VerifyError::InvalidScalar))
        .collect::<Result<Vec<_>, _>>()?;
    verify_decoded(&vk, &proof, &inputs)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_decoded(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    inputs: &[Fr],
) -> Result<bool, VerifyError> {
    ark_groth16::Groth16::<Bn254>::verify_proof(
        &ark_groth16::prepare_verifying_key(vk),
        proof,
        inputs,
    )
    .map_err(|_| VerifyError::Verification)
}

#[cfg(target_arch = "wasm32")]
fn verify_decoded(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    inputs: &[Fr],
) -> Result<bool, VerifyError> {
    let msm = multiexp_input(vk, inputs);
    let accumulated = near_sdk::env::alt_bn128_g1_multiexp(msm);
    let accumulated = decode_host_g1(&accumulated).ok_or(VerifyError::Verification)?;
    Ok(near_sdk::env::alt_bn128_pairing_check(pairing_input(
        vk,
        proof,
        accumulated,
    )))
}

fn field_bytes<F: PrimeField>(field: F) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_le();
    let mut result = [0u8; 32];
    result[..bytes.len()].copy_from_slice(&bytes);
    result
}

/// NEAR uses little-endian x, y; infinity is the all-zero pair.
pub fn host_g1(point: G1Affine) -> [u8; 64] {
    use ark_ec::AffineRepr;
    let mut out = [0u8; 64];
    if !point.is_zero() {
        out[..32].copy_from_slice(&field_bytes(point.x));
        out[32..].copy_from_slice(&field_bytes(point.y));
    }
    out
}

/// Fq2 coefficients are real then imaginary, each little-endian.
pub fn host_g2(point: G2Affine) -> [u8; 128] {
    use ark_ec::AffineRepr;
    let mut out = [0u8; 128];
    if !point.is_zero() {
        for (chunk, coordinate) in out
            .chunks_exact_mut(32)
            .zip([point.x.c0, point.x.c1, point.y.c0, point.y.c1])
        {
            chunk.copy_from_slice(&field_bytes(coordinate));
        }
    }
    out
}

#[cfg(any(test, target_arch = "wasm32"))]
fn decode_host_g1(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != 64 {
        return None;
    }
    if bytes.iter().all(|b| *b == 0) {
        return Some(G1Affine::identity());
    }
    let x = decode::<ark_bn254::Fq>(&bytes[..32])?;
    let y = decode::<ark_bn254::Fq>(&bytes[32..])?;
    let point = G1Affine::new_unchecked(x, y);
    (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve()).then_some(point)
}

pub fn multiexp_input(vk: &VerifyingKey<Bn254>, inputs: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity((inputs.len() + 1) * 96);
    for (point, scalar) in vk
        .gamma_abc_g1
        .iter()
        .zip(std::iter::once(Fr::from(1u64)).chain(inputs.iter().copied()))
    {
        out.extend_from_slice(&host_g1(*point));
        out.extend_from_slice(&field_bytes(scalar));
    }
    out
}

pub fn pairing_input(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    accumulated: G1Affine,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * 192);
    for (g1, g2) in [
        (proof.a, proof.b),
        (-vk.alpha_g1, vk.beta_g2),
        (-accumulated, vk.gamma_g2),
        (-proof.c, vk.delta_g2),
    ] {
        out.extend_from_slice(&host_g1(g1));
        out.extend_from_slice(&host_g2(g2));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };

    #[derive(Clone)]
    struct Product {
        a: Fr,
        b: Fr,
    }

    impl ConstraintSynthesizer<Fr> for Product {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(self.a))?;
            let b = cs.new_witness_variable(|| Ok(self.b))?;
            let product = cs.new_input_variable(|| Ok(self.a * self.b))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + product)
        }
    }

    fn bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
        let mut result = vec![];
        value.serialize_compressed(&mut result).unwrap();
        result
    }

    #[test]
    fn valid_proof_and_context_mutation() {
        let mut rng = rand::thread_rng();
        let circuit = Product {
            a: Fr::from(6u64),
            b: Fr::from(7u64),
        };
        let pk = ark_groth16::Groth16::<Bn254>::generate_random_parameters_with_reduction(
            circuit.clone(),
            &mut rng,
        )
        .unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit, &pk, &mut rng,
        )
        .unwrap();
        assert_eq!(validate_verifying_key(&bytes(&pk.vk)), Ok(1));
        let prepared = prepare_key(&bytes(&pk.vk)).unwrap();
        assert_eq!(validate_prepared_key(&prepared), Ok(1));
        assert_eq!(
            verify_prepared(&prepared, &bytes(&proof), &[field_bytes(Fr::from(42u64))]),
            Ok(true)
        );
        assert_eq!(
            verify_prepared(&prepared, &bytes(&proof), &[field_bytes(Fr::from(43u64))]),
            Ok(false)
        );
        let mut bad_prepared = prepared.clone();
        *bad_prepared.last_mut().unwrap() ^= 1;
        assert_eq!(
            validate_prepared_key(&bad_prepared),
            Err(VerifyError::InvalidKey)
        );
        assert_eq!(
            verify(
                &bytes(&pk.vk),
                &bytes(&proof),
                &[field_bytes(Fr::from(42u64))]
            ),
            Ok(true)
        );
        assert_eq!(
            verify(
                &bytes(&pk.vk),
                &bytes(&proof),
                &[field_bytes(Fr::from(43u64))]
            ),
            Ok(false)
        );
        assert_eq!(
            verify(&bytes(&pk.vk), &bytes(&proof), &[[255; 32]]),
            Err(VerifyError::InvalidScalar)
        );
        let mut padded = bytes(&proof);
        padded.push(0);
        assert_eq!(
            verify(&bytes(&pk.vk), &padded, &[field_bytes(Fr::from(42u64))]),
            Err(VerifyError::InvalidProof)
        );
        let accumulated =
            (pk.vk.gamma_abc_g1[0] + pk.vk.gamma_abc_g1[1] * Fr::from(42u64)).into_affine();
        assert_eq!(pairing_input(&pk.vk, &proof, accumulated).len(), 768);
        assert_eq!(multiexp_input(&pk.vk, &[Fr::from(42u64)]).len(), 192);
    }

    #[test]
    fn host_coordinates_are_little_endian_and_canonical() {
        let g = G1Affine::generator();
        let encoded = host_g1(g);
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[32], 2);
        assert_eq!(decode_host_g1(&encoded), Some(g));
        assert_eq!(decode_host_g1(&[0; 64]), Some(G1Affine::identity()));
        assert_eq!(decode_host_g1(&[255; 64]), None);
    }
}
