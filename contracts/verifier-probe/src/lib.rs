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
    Ciphertext, Commitment, FieldHex, PROFILE_HASH, PROFILE_ID, PointHex, ProofEnvelope,
    RecoveryPair, Statement, StatementKind, transcript_hash,
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
    /// All public inputs are derived from the typed statement; envelope inputs
    /// are accepted only when they are byte-for-byte canonical equivalents.
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
        let Some(expected_inputs) = statement_public_inputs(&statement) else {
            return false;
        };
        let Some(statement_digest) = expected_inputs.first() else {
            return false;
        };
        if envelope.context_digest != *statement_digest || envelope.public_inputs != expected_inputs
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
        near_verifier::verify_prepared(key, &proof, &statement_inputs).unwrap_or(false)
    }
}

/// Derive public inputs without re-running subgroup validation for every
/// point. `Statement` deserialization has already performed strict canonical
/// decoding and subgroup checks. `PointHex::to_affine` reuses the bounded
/// validated-point cache, so this traversal recovers coordinates without
/// weakening the wire validation policy.
fn statement_public_inputs(statement: &Statement) -> Option<Vec<FieldHex>> {
    let mut values = statement.context().canonical_fields();
    values.push(Fr::from(statement.kind().as_u8() as u64));
    match statement {
        Statement::KeyPossession(value) => {
            push_key(&mut values, &value.public_key)?;
        }
        Statement::PublicConversion(value) => {
            push_key(&mut values, &value.owner_key)?;
            push_ciphertext(&mut values, &value.spending_before)?;
            push_ciphertext(&mut values, &value.spending_after)?;
            for view in &value.views {
                push_view(&mut values, view)?;
            }
            push_u64(&mut values, value.public_amount);
            push_u64(
                &mut values,
                u64::from(matches!(
                    value.mode,
                    confidential_crypto::ConversionMode::Debit
                )),
            );
            push_u64(&mut values, value.spending_version);
        }
        Statement::ConfidentialTransfer(value) => {
            push_key(&mut values, &value.sender_key)?;
            push_key(&mut values, &value.recipient_key)?;
            push_ciphertext(&mut values, &value.sender_spending_before)?;
            push_ciphertext(&mut values, &value.sender_spending_after)?;
            for view in &value.transfer_views {
                push_view(&mut values, view)?;
            }
            for pair in &value.transfer_recovery {
                push_recovery_pair(&mut values, pair)?;
            }
            push_commitment(&mut values, &value.amount_commitment)?;
            push_u64(&mut values, value.sender_spending_version);
        }
        Statement::Origination(value) => {
            push_key(&mut values, &value.broker_key)?;
            push_key(&mut values, &value.borrower_key)?;
            push_ciphertext(&mut values, &value.broker_spending_before)?;
            push_ciphertext(&mut values, &value.broker_spending_after)?;
            for view in &value.transfer_views {
                push_view(&mut values, view)?;
            }
            for pair in &value.transfer_recovery {
                push_recovery_pair(&mut values, pair)?;
            }
            push_commitment(&mut values, &value.principal_commitment)?;
            for view in &value.owed_views {
                push_view(&mut values, view)?;
            }
            for pair in &value.owed_recovery {
                push_recovery_pair(&mut values, pair)?;
            }
            for view in &value.payment_views {
                push_view(&mut values, view)?;
            }
            for pair in &value.payment_recovery {
                push_recovery_pair(&mut values, pair)?;
            }
            push_commitment(&mut values, &value.owed_commitment)?;
            push_commitment(&mut values, &value.payment_commitment)?;
            push_u64(&mut values, value.payment_count as u64);
            push_u64(&mut values, value.max_payment_count as u64);
            push_u64(&mut values, value.broker_spending_version);
            push_u64(&mut values, value.loan_version);
        }
        Statement::Repayment(value) => {
            push_key(&mut values, &value.borrower_key)?;
            push_key(&mut values, &value.broker_key)?;
            push_ciphertext(&mut values, &value.borrower_spending_before)?;
            push_ciphertext(&mut values, &value.borrower_spending_after)?;
            for view in &value.transfer_views {
                push_view(&mut values, view)?;
            }
            for pair in &value.transfer_recovery {
                push_recovery_pair(&mut values, pair)?;
            }
            for view in &value.owed_before {
                push_view(&mut values, view)?;
            }
            for view in &value.owed_after {
                push_view(&mut values, view)?;
            }
            for (view, pair) in value
                .owed_delta
                .iter()
                .zip(value.owed_delta_recovery.iter())
            {
                push_view(&mut values, view)?;
                push_recovery_pair(&mut values, pair)?;
            }
            for view in &value.periodic_payment {
                push_view(&mut values, view)?;
            }
            for view in &value.principal_before {
                push_view(&mut values, view)?;
            }
            for view in &value.principal_after {
                push_view(&mut values, view)?;
            }
            for (view, pair) in value
                .principal_delta
                .iter()
                .zip(value.principal_delta_recovery.iter())
            {
                push_view(&mut values, view)?;
                push_recovery_pair(&mut values, pair)?;
            }
            push_commitment(&mut values, &value.principal_delta_commitment)?;
            push_u64(
                &mut values,
                u64::from(matches!(value.mode, confidential_crypto::PaymentMode::Full)),
            );
            push_u64(&mut values, value.payment_remaining_before as u64);
            push_u64(&mut values, value.payment_remaining_after as u64);
            push_u64(&mut values, value.borrower_spending_version);
            push_u64(&mut values, value.loan_version_before);
            push_u64(&mut values, value.loan_version_after);
        }
        Statement::Reconciliation(value) => {
            push_key(&mut values, &value.broker_key)?;
            push_ciphertext(&mut values, &value.cash)?;
            push_ciphertext(&mut values, &value.active_principal)?;
            push_ciphertext(&mut values, &value.impaired_principal)?;
            push_commitment(&mut values, &value.cash_commitment)?;
            push_commitment(&mut values, &value.active_principal_commitment)?;
            push_commitment(&mut values, &value.impaired_principal_commitment)?;
            push_u128(&mut values, value.debt_before);
            push_u128(&mut values, value.debt_after);
            push_u128(&mut values, value.vault_assets_before);
            push_u128(&mut values, value.vault_assets_after);
            push_u128(&mut values, value.vault_provision_before);
            push_u128(&mut values, value.vault_provision_after);
            push_u128(&mut values, value.provision_before);
            push_u128(&mut values, value.provision_after);
            push_u128(&mut values, value.realized_loss);
            push_u64(&mut values, value.book_version);
            push_u64(&mut values, value.accounting_version);
        }
        Statement::ZeroBalance(value) | Statement::Ownership(value) => {
            push_key(&mut values, &value.owner_key)?;
            push_ciphertext(&mut values, &value.ciphertext)?;
            push_u64(&mut values, value.expected_amount);
            push_u64(&mut values, value.spending_version);
        }
    }
    if values.len() != statement.kind().slot_count() {
        return None;
    }
    let digest = transcript_hash(&values);
    let mut result = Vec::with_capacity(values.len() + 1);
    result.push(FieldHex::from(digest));
    result.extend(values.into_iter().map(FieldHex::from));
    Some(result)
}

fn push_u64(values: &mut Vec<Fr>, value: u64) {
    values.push(Fr::from(value));
}

fn push_u128(values: &mut Vec<Fr>, value: u128) {
    push_u64(values, value as u64);
    push_u64(values, (value >> 64) as u64);
}

fn push_key(values: &mut Vec<Fr>, key: &confidential_crypto::PublicKey) -> Option<()> {
    push_point(values, &key.point)
}

fn push_ciphertext(values: &mut Vec<Fr>, ciphertext: &Ciphertext) -> Option<()> {
    push_point(values, &ciphertext.ephemeral)?;
    push_point(values, &ciphertext.message)
}

fn push_view(values: &mut Vec<Fr>, view: &confidential_crypto::ReaderView) -> Option<()> {
    push_key(values, &view.reader_key)?;
    push_ciphertext(values, &view.ciphertext)
}

fn push_recovery_pair(values: &mut Vec<Fr>, pair: &RecoveryPair) -> Option<()> {
    push_ciphertext(values, &pair.low_limb)?;
    push_ciphertext(values, &pair.high_limb)
}

fn push_commitment(values: &mut Vec<Fr>, commitment: &Commitment) -> Option<()> {
    push_point(values, &commitment.point)
}

fn push_point(values: &mut Vec<Fr>, point: &PointHex) -> Option<()> {
    let affine = point.to_affine().ok()?;
    values.push(affine.x);
    values.push(affine.y);
    Some(())
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
