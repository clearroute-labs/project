//! Canonical bridge between Core's persistent byte fields and the pinned
//! `confidential-crypto` wire types.
//!
//! Core deliberately does not store arkworks values.  Every encrypted value
//! crossing this boundary is canonical JSON for one of the crypto crate's
//! serde wire records.  Parsing therefore performs the crypto crate's point,
//! subgroup, identity and canonical-encoding checks before a value can be
//! used in a statement or homomorphic update.  The concrete profile and
//! verifier artifacts are pinned by deployment configuration; this adapter is
//! not an independent cryptographic review claim.

use confidential_crypto::{
    Ciphertext, Commitment, FieldHex, OperationContext, PublicKey, Statement,
};

pub type WireError = ();

pub fn parse<T>(bytes: &[u8]) -> Result<T, WireError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_slice(bytes).map_err(|_| ())
}

pub fn encode<T>(value: &T) -> Result<Vec<u8>, WireError>
where
    T: serde::Serialize,
{
    serde_json::to_vec(value).map_err(|_| ())
}

pub fn parse_statement(bytes: &[u8]) -> Result<Statement, WireError> {
    parse(bytes)
}

pub fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, WireError> {
    parse(bytes)
}

pub fn parse_ciphertext(bytes: &[u8]) -> Result<Ciphertext, WireError> {
    parse(bytes)
}

pub fn parse_commitment(bytes: &[u8]) -> Result<Commitment, WireError> {
    parse(bytes)
}

pub fn statement_inputs_with_digest(
    statement: &Statement,
    context_digest: &[u8],
) -> Result<Vec<[u8; 32]>, WireError> {
    // The first public input is supplied by the proof envelope.  The pinned
    // circuit constrains that digest to the exact slot vector below, while
    // Core has already compared `statement.context()` with its authoritative
    // operation context.  This avoids evaluating the expensive host Poseidon
    // transcript merely to reconstruct a value the proof itself constrains.
    let digest: [u8; 32] = context_digest.try_into().map_err(|_| ())?;
    let slots = statement.public_slots_without_hash().map_err(|_| ())?;
    let mut inputs = Vec::with_capacity(slots.len() + 1);
    inputs.push(digest);
    for slot in slots {
        let wire = FieldHex::from(slot);
        let bytes = hex::decode(wire.0).map_err(|_| ())?;
        inputs.push(bytes.try_into().map_err(|_| ())?);
    }
    Ok(inputs)
}

// The typed context is the canonical wire transcript.  Keeping each field
// explicit makes call sites auditable and avoids accepting an opaque caller
// hash, so this fixed-ABI helper intentionally has more than seven arguments.
#[allow(clippy::too_many_arguments)]
pub fn context(
    network_id: &str,
    core_account: &str,
    asset_id: &str,
    operation_id: &str,
    vault_id: u64,
    broker_id: u64,
    loan_id: u64,
    proposal_id: u64,
    expected_versions: [u64; 8],
    authorization_epochs: [u64; 4],
    expiry: u64,
) -> OperationContext {
    let mut result =
        OperationContext::from_strings(network_id, core_account, asset_id, operation_id).with_ids(
            &vault_id.to_string(),
            &broker_id.to_string(),
            &loan_id.to_string(),
            &proposal_id.to_string(),
        );
    result.expected_versions = expected_versions;
    result.authorization_epochs = authorization_epochs;
    result.expiry = expiry;
    result
}

pub fn add_ciphertexts(left: &Ciphertext, right: &Ciphertext) -> Result<Ciphertext, WireError> {
    left.add(right).map_err(|_| ())
}

pub fn sub_ciphertexts(left: &Ciphertext, right: &Ciphertext) -> Result<Ciphertext, WireError> {
    left.sub(right).map_err(|_| ())
}

pub fn add_commitments(left: &Commitment, right: &Commitment) -> Result<Commitment, WireError> {
    left.add(right).map_err(|_| ())
}

pub fn sub_commitments(left: &Commitment, right: &Commitment) -> Result<Commitment, WireError> {
    left.sub(right).map_err(|_| ())
}

pub fn zero_ciphertext(key: &PublicKey, domain: &[u8]) -> Result<Ciphertext, WireError> {
    // The caller supplies the protocol's complete zero domain.  Core derives
    // it from the immutable network/account/asset profile and the subject's
    // key epoch; accepting a fixed profile-only tag would permit ciphertexts
    // from another subject or key epoch to be replayed as a zero assertion.
    Ciphertext::canonical_zero(key, domain).map_err(|_| ())
}

pub fn zero_commitment() -> Result<Commitment, WireError> {
    let one = confidential_crypto::ScalarHex::parse(
        "0100000000000000000000000000000000000000000000000000000000000000",
    )
    .map_err(|_| ())?
    .to_scalar()
    .map_err(|_| ())?;
    Commitment::commit_u128_with_blinding(0, one).map_err(|_| ())
}
