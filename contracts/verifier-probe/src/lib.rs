//! Local integration fixture for the actual NEAR BN254 host verification path.
//!
//! The legacy `new`/`verify` entry points intentionally remain small and
//! byte-oriented so the original host benchmark remains reproducible.  The
//! typed entry points below exercise the same path used by Core: deserialize a
//! canonical [`confidential_crypto::Statement`], derive its public slots (and
//! constrained Poseidon digest), compare those slots with the envelope, and
//! finally verify the canonical proof against the immutable key installed for
//! that statement family.

use ark_bn254::Fr;
use borsh::{BorshDeserialize, BorshSerialize};
use confidential_crypto::{
    FieldHex, PROFILE_HASH, PROFILE_ID, ProofEnvelope, Statement, StatementKind, transcript_hash,
};
use near_sdk::{PanicOnDefault, near};
use serde::{Deserialize, Serialize};

const MAX_STATEMENT_KEYS: usize = 8;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct InstalledKey {
    kind: u8,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct KeyInstall {
    pub kind: String,
    pub prepared_key_hex: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct VerifierProbe {
    key: Vec<u8>,
    typed_keys: Vec<InstalledKey>,
}

#[near]
impl VerifierProbe {
    #[init]
    pub fn new(verifying_key_hex: String) -> Self {
        let key = hex::decode(verifying_key_hex).expect("invalid key encoding");
        near_verifier::validate_prepared_key(&key).expect("invalid verifying key");
        Self {
            key,
            typed_keys: Vec::new(),
        }
    }

    /// Initialize a typed probe with no installed keys.  Keys are added by
    /// `install_verifying_key` exactly once per statement family.
    #[init]
    pub fn new_typed() -> Self {
        Self {
            key: Vec::new(),
            typed_keys: Vec::new(),
        }
    }

    /// Convenience initializer for local tooling.  Installation is still
    /// checked through the same immutable per-kind path as incremental setup.
    #[init]
    pub fn new_with_keys(keys: Vec<KeyInstall>) -> Self {
        let mut probe = Self::new_typed();
        for key in keys {
            assert!(
                probe.install_key(key.kind, key.prepared_key_hex),
                "invalid or duplicate key"
            );
        }
        probe
    }

    /// Install one prepared verifying key for one fixed circuit family.
    ///
    /// The method is deliberately idempotence-resistant: once a family has a
    /// key, every later call returns `false` and leaves state untouched.  This
    /// lets deployment scripts distinguish a rejected replacement from a
    /// successful immutable install without relying on a panic message.
    pub fn install_verifying_key(&mut self, kind: String, prepared_key_hex: String) -> bool {
        self.install_key(kind, prepared_key_hex)
    }

    pub fn installed_kinds(&self) -> Vec<String> {
        self.typed_keys
            .iter()
            .filter_map(|entry| kind_from_u8(entry.kind).map(|kind| kind.as_str().to_string()))
            .collect()
    }

    pub fn verify(&self, proof_hex: String, public_inputs: Vec<String>) -> bool {
        if self.key.is_empty() {
            return false;
        }
        let Ok(proof) = hex::decode(proof_hex) else {
            return false;
        };
        let Some(inputs) = public_inputs
            .iter()
            .map(|value| hex::decode(value).ok()?.try_into().ok())
            .collect::<Option<Vec<[u8; 32]>>>()
        else {
            return false;
        };
        near_verifier::verify_prepared(&self.key, &proof, &inputs).unwrap_or(false)
    }

    /// Derive the canonical public-input vector exactly as Core does.  This
    /// endpoint is useful for integration diagnostics and does not trust a
    /// caller-provided public-input vector.
    pub fn derive_public_inputs(&self, statement_json: String) -> Option<Vec<String>> {
        let statement: Statement = serde_json::from_str(&statement_json).ok()?;
        Some(
            statement_public_inputs(&statement)?
                .into_iter()
                .map(|field| field.0)
                .collect(),
        )
    }

    /// Verify a typed statement/envelope pair with its immutable family key.
    /// All authoritative slots are derived from the typed statement; the
    /// envelope's first input is retained as the Poseidon digest because the
    /// Groth16 circuit already constrains it to those slots. This avoids
    /// recomputing the same digest in the host while preserving the binding
    /// relation enforced by the proof.
    pub fn verify_typed(&self, statement_json: String, envelope_json: String) -> bool {
        let Some(statement) = serde_json::from_str::<Statement>(&statement_json).ok() else {
            return false;
        };
        let Some(envelope) = serde_json::from_str::<ProofEnvelope>(&envelope_json).ok() else {
            return false;
        };
        if envelope.profile_id != PROFILE_ID
            || envelope.profile_hash != hex::encode(PROFILE_HASH)
            || envelope.statement_kind != statement.kind()
        {
            return false;
        }
        let Some(expected_slots) = statement_public_slots(&statement) else {
            return false;
        };
        let Some(statement_digest) = envelope.public_inputs.first() else {
            return false;
        };
        if envelope.context_digest != *statement_digest
            || envelope.public_inputs.len() != expected_slots.len() + 1
            || envelope.public_inputs[1..] != expected_slots[..]
        {
            return false;
        }
        let Some(statement_inputs) = envelope_input_bytes(&envelope) else {
            return false;
        };
        let Some(key) = self.key_for(statement.kind()) else {
            return false;
        };
        let Ok(expected_key_hash) = near_verifier::prepared_key_hash(key) else {
            return false;
        };
        if envelope.verifying_key_hash != hex::encode(expected_key_hash) {
            return false;
        }
        let Ok(proof) = envelope.proof_bytes() else {
            return false;
        };
        if !near_verifier::verify_prepared(key, &proof, &statement_inputs).unwrap_or(false) {
            return false;
        }
        // The fixed circuit has now established subgroup membership for every
        // point in this exact statement. Promote only those fields; unrelated
        // statement-cache entries remain untrusted and are never promoted.
        statement.promote_after_verified_proof().is_ok()
    }
}

/// Derive the authoritative public slots using the same typed builder exposed
/// to Core. Statement deserialization has already performed strict canonical
/// and on-curve decoding; subgroup membership is established by the verified
/// fixed-circuit cofactor relation. The bounded point cache makes subsequent
/// coordinate extraction reusable within the transaction.
fn statement_public_values(statement: &Statement) -> Option<Vec<Fr>> {
    statement.public_slots_without_hash().ok()
}

fn statement_public_slots(statement: &Statement) -> Option<Vec<FieldHex>> {
    statement_public_values(statement)
        .map(|values| values.into_iter().map(FieldHex::from).collect())
}

fn statement_public_inputs(statement: &Statement) -> Option<Vec<FieldHex>> {
    let values = statement_public_values(statement)?;
    let digest = transcript_hash(&values);
    let mut result = Vec::with_capacity(values.len() + 1);
    result.push(FieldHex::from(digest));
    result.extend(values.into_iter().map(FieldHex::from));
    Some(result)
}

impl VerifierProbe {
    fn install_key(&mut self, kind: String, prepared_key_hex: String) -> bool {
        let Some(kind) = kind_from_str(&kind) else {
            return false;
        };
        if self.typed_keys.len() >= MAX_STATEMENT_KEYS
            || self
                .typed_keys
                .iter()
                .any(|entry| entry.kind == kind.as_u8())
        {
            return false;
        }
        let Ok(bytes) = hex::decode(prepared_key_hex) else {
            return false;
        };
        let Ok(public_input_count) = near_verifier::validate_prepared_key(&bytes) else {
            return false;
        };
        if public_input_count != kind.slot_count() + 1 {
            return false;
        }
        self.typed_keys.push(InstalledKey {
            kind: kind.as_u8(),
            bytes,
        });
        true
    }

    fn key_for(&self, kind: StatementKind) -> Option<&[u8]> {
        self.typed_keys
            .iter()
            .find(|entry| entry.kind == kind.as_u8())
            .map(|entry| entry.bytes.as_slice())
    }
}

fn kind_from_str(value: &str) -> Option<StatementKind> {
    match value {
        "key-possession" => Some(StatementKind::KeyPossession),
        "public-conversion" => Some(StatementKind::PublicConversion),
        "confidential-transfer" => Some(StatementKind::ConfidentialTransfer),
        "origination" => Some(StatementKind::Origination),
        "repayment" => Some(StatementKind::Repayment),
        "reconciliation" => Some(StatementKind::Reconciliation),
        "zero-balance" => Some(StatementKind::ZeroBalance),
        "ownership" => Some(StatementKind::Ownership),
        _ => None,
    }
}

fn envelope_input_bytes(envelope: &ProofEnvelope) -> Option<Vec<[u8; 32]>> {
    envelope
        .public_inputs
        .iter()
        .map(|field| hex::decode(&field.0).ok()?.try_into().ok())
        .collect()
}

fn kind_from_u8(value: u8) -> Option<StatementKind> {
    match value {
        1 => Some(StatementKind::KeyPossession),
        2 => Some(StatementKind::PublicConversion),
        3 => Some(StatementKind::ConfidentialTransfer),
        4 => Some(StatementKind::Origination),
        5 => Some(StatementKind::Repayment),
        6 => Some(StatementKind::Reconciliation),
        7 => Some(StatementKind::ZeroBalance),
        8 => Some(StatementKind::Ownership),
        _ => None,
    }
}
