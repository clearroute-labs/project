//! Canonical bridge between Core's persistent byte fields and the reviewed
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
    Ciphertext, Commitment, ConversionMode, FieldHex, LoanReaderView, OperationContext, PointHex,
    PublicConversionStatement, PublicKey, ReaderView, RecoveryPair, Statement,
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

pub fn parse_recovery_pair(bytes: &[u8]) -> Result<RecoveryPair, WireError> {
    parse(bytes)
}

pub fn parse_point(bytes: &[u8]) -> Result<PointHex, WireError> {
    let value: String = parse(bytes)?;
    PointHex::parse(&value).map_err(|_| ())
}

pub fn statement_inputs(statement: &Statement) -> Result<Vec<[u8; 32]>, WireError> {
    statement.public_input_bytes().map_err(|_| ())
}

pub fn statement_context_bytes(statement: &Statement) -> Result<Vec<u8>, WireError> {
    let FieldHex(value) = statement.context_digest().map_err(|_| ())?;
    hex::decode(value).map_err(|_| ())
}

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

pub fn reader(key: PublicKey, ciphertext: Ciphertext) -> ReaderView {
    ReaderView {
        reader_key: key,
        ciphertext,
    }
}

pub fn loan_reader(key: PublicKey, ciphertext: Ciphertext) -> LoanReaderView {
    LoanReaderView {
        reader_key: key,
        ciphertext,
    }
}

pub fn public_conversion(
    context: OperationContext,
    owner_key: PublicKey,
    spending_before: Ciphertext,
    spending_after: Ciphertext,
    views: [LoanReaderView; 3],
    public_amount: u64,
    debit: bool,
    spending_version: u64,
) -> Statement {
    Statement::PublicConversion(PublicConversionStatement {
        context,
        owner_key,
        spending_before,
        spending_after,
        views,
        public_amount,
        mode: if debit {
            ConversionMode::Debit
        } else {
            ConversionMode::Credit
        },
        spending_version,
    })
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

pub fn zero_ciphertext(key: &PublicKey) -> Result<Ciphertext, WireError> {
    // Canonical zero is domain-separated by the profile rather than a caller
    // supplied replacement ciphertext.  The key itself is part of the
    // ElGamal point, so distinct registered keys cannot share a zero wire.
    Ciphertext::canonical_zero(key, b"near-confidential-lending/canonical-zero/v1").map_err(|_| ())
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
