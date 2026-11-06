use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use crate::field_bytes;
use crate::{MAX_PUBLIC_INPUTS, VerifyError, decode, host_g1, host_g2, validate_verifying_key};

const PREFIX: &[u8; 8] = b"NCLVK001";
const HEADER: usize = 8 + 64 + 3 * 128 + 4;

struct Prepared<'a> {
    alpha: &'a [u8],
    beta: &'a [u8],
    gamma: &'a [u8],
    delta: &'a [u8],
    coefficients: &'a [u8],
    hash: [u8; 32],
}

fn parse(bytes: &[u8]) -> Result<Prepared<'_>, VerifyError> {
    if bytes.len() < HEADER + 64 + 32 || &bytes[..8] != PREFIX {
        return Err(VerifyError::InvalidKey);
    }
    let count = u32::from_le_bytes(bytes[HEADER - 4..HEADER].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_PUBLIC_INPUTS + 1 || bytes.len() != HEADER + count * 64 + 32 {
        return Err(VerifyError::InputCount);
    }
    let key = Prepared {
        alpha: &bytes[8..72],
        beta: &bytes[72..200],
        gamma: &bytes[200..328],
        delta: &bytes[328..456],
        coefficients: &bytes[HEADER..HEADER + count * 64],
        hash: bytes[bytes.len() - 32..].try_into().unwrap(),
    };
    if [key.alpha, key.beta, key.gamma, key.delta]
        .iter()
        .any(|p| p.iter().all(|b| *b == 0))
    {
        return Err(VerifyError::InvalidKey);
    }
    Ok(key)
}

/// Run off-chain to replace repeated contract decompression with canonical host coordinates.
pub fn prepare_key(canonical: &[u8]) -> Result<Vec<u8>, VerifyError> {
    validate_verifying_key(canonical)?;
    let key: VerifyingKey<Bn254> = decode(canonical).ok_or(VerifyError::InvalidKey)?;
    let mut bytes = Vec::with_capacity(HEADER + key.gamma_abc_g1.len() * 64 + 32);
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(&host_g1(key.alpha_g1));
    bytes.extend_from_slice(&host_g2(key.beta_g2));
    bytes.extend_from_slice(&host_g2(key.gamma_g2));
    bytes.extend_from_slice(&host_g2(key.delta_g2));
    bytes.extend_from_slice(&(key.gamma_abc_g1.len() as u32).to_le_bytes());
    for point in key.gamma_abc_g1 {
        bytes.extend_from_slice(&host_g1(point));
    }
    bytes.extend_from_slice(&Sha256::digest(canonical));
    Ok(bytes)
}

pub fn prepared_key_hash(bytes: &[u8]) -> Result<[u8; 32], VerifyError> {
    Ok(parse(bytes)?.hash)
}

fn g1_unchecked(bytes: &[u8]) -> Result<G1Affine, VerifyError> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G1Affine::identity());
    }
    let x = decode::<Fq>(&bytes[..32]).ok_or(VerifyError::InvalidKey)?;
    let y = decode::<Fq>(&bytes[32..]).ok_or(VerifyError::InvalidKey)?;
    Ok(G1Affine::new_unchecked(x, y))
}

fn g2_unchecked(bytes: &[u8]) -> Result<G2Affine, VerifyError> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G2Affine::identity());
    }
    let fields = bytes
        .chunks_exact(32)
        .map(|f| decode::<Fq>(f).ok_or(VerifyError::InvalidKey))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(G2Affine::new_unchecked(
        Fq2::new(fields[0], fields[1]),
        Fq2::new(fields[2], fields[3]),
    ))
}

fn decoded(key: &Prepared<'_>) -> Result<VerifyingKey<Bn254>, VerifyError> {
    Ok(VerifyingKey {
        alpha_g1: g1_unchecked(key.alpha)?,
        beta_g2: g2_unchecked(key.beta)?,
        gamma_g2: g2_unchecked(key.gamma)?,
        delta_g2: g2_unchecked(key.delta)?,
        gamma_abc_g1: key
            .coefficients
            .chunks_exact(64)
            .map(g1_unchecked)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Validate once before storing an immutable prepared key. On NEAR the hosts do subgroup checks.
pub fn validate_prepared_key(bytes: &[u8]) -> Result<usize, VerifyError> {
    let key = parse(bytes)?;
    let points = decoded(&key)?;
    let mut compressed = Vec::new();
    points
        .serialize_compressed(&mut compressed)
        .map_err(|_| VerifyError::InvalidKey)?;
    if <[u8; 32]>::from(Sha256::digest(&compressed)) != key.hash {
        return Err(VerifyError::InvalidKey);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        validate_verifying_key(&compressed)?;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut msm = Vec::with_capacity((key.coefficients.len() / 64 + 1) * 96);
        for point in std::iter::once(key.alpha).chain(key.coefficients.chunks_exact(64)) {
            msm.extend_from_slice(point);
            msm.extend_from_slice(&[0u8; 32]);
        }
        near_sdk::env::alt_bn128_g1_multiexp(msm);
        let mut pairing = Vec::with_capacity(576);
        for point in [key.beta, key.gamma, key.delta] {
            pairing.extend_from_slice(&[0u8; 64]);
            pairing.extend_from_slice(point);
        }
        if !near_sdk::env::alt_bn128_pairing_check(pairing) {
            return Err(VerifyError::InvalidKey);
        }
    }
    Ok(key.coefficients.len() / 64 - 1)
}

pub fn verify_prepared(
    key_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
) -> Result<bool, VerifyError> {
    let key = parse(key_bytes)?;
    if public_inputs.len() + 1 != key.coefficients.len() / 64 {
        return Err(VerifyError::InputCount);
    }
    if proof_bytes.len() != 128 {
        return Err(VerifyError::InvalidProof);
    }
    let proof: Proof<Bn254> = decode(proof_bytes).ok_or(VerifyError::InvalidProof)?;
    let inputs = public_inputs
        .iter()
        .map(|b| decode::<Fr>(b).ok_or(VerifyError::InvalidScalar))
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        validate_prepared_key(key_bytes)?;
        crate::verify_decoded(&decoded(&key)?, &proof, &inputs)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut msm = Vec::with_capacity(key.coefficients.len() / 64 * 96);
        for (point, scalar) in key
            .coefficients
            .chunks_exact(64)
            .zip(std::iter::once(Fr::from(1u64)).chain(inputs))
        {
            msm.extend_from_slice(point);
            msm.extend_from_slice(&field_bytes(scalar));
        }
        let accumulated = crate::decode_host_g1(&near_sdk::env::alt_bn128_g1_multiexp(msm))
            .ok_or(VerifyError::Verification)?;
        let mut pairing = Vec::with_capacity(768);
        pairing.extend_from_slice(&host_g1(proof.a));
        pairing.extend_from_slice(&host_g2(proof.b));
        pairing.extend_from_slice(&host_g1(-g1_unchecked(key.alpha)?));
        pairing.extend_from_slice(key.beta);
        pairing.extend_from_slice(&host_g1(-accumulated));
        pairing.extend_from_slice(key.gamma);
        pairing.extend_from_slice(&host_g1(-proof.c));
        pairing.extend_from_slice(key.delta);
        Ok(near_sdk::env::alt_bn128_pairing_check(pairing))
    }
}
