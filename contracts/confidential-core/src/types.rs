//! Persistent protocol records and JSON-facing argument/view types.
//!
//! The contract deliberately stores private values only as opaque ciphertexts,
//! commitments, and proof-bound byte strings.  Public monetary values remain
//! `u128` in storage and are exposed as decimal `U128` values by the view layer.

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{AccountId, json_types::U128};
use serde::{Deserialize, Serialize};

pub const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024;
pub const MAX_PROOF_BYTES: usize = 256 * 1024;
pub const MAX_DELEGATES: usize = 32;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;

/// Canonical JSON representation for protocol IDs, versions and timestamps.
/// IDs and versions are accepted only as canonical decimal strings, avoiding
/// JavaScript's unsafe integer range and ambiguous `+1`/`01` spellings.
pub mod u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(serde::de::Error::custom(
                "expected canonical decimal string",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

pub mod option_u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(serde::de::Error::custom(
                        "expected canonical decimal string",
                    ));
                }
                value.parse().map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

pub mod u64_vec_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(serde::de::Error::custom(
                        "expected canonical decimal string",
                    ));
                }
                value.parse().map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct EncryptionKey {
    #[serde(with = "u64_string")]
    pub key_id: u64,
    pub public_key: Vec<u8>,
    #[serde(with = "u64_string")]
    pub registered_at: u64,
    #[serde(with = "u64_string")]
    pub authorization_epoch: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct AuthorizationKey {
    pub owner: AccountId,
    #[serde(with = "u64_string")]
    pub key_id: u64,
    pub public_key: Vec<u8>,
    #[serde(with = "u64_string")]
    pub epoch: u64,
    #[serde(with = "u64_string")]
    pub nonce: u64,
    pub revoked: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct VerifierConfig {
    pub profile_hash: Vec<u8>,
    pub manifest_hash: Vec<u8>,
    /// True once every immutable prepared verifier key has been activated.
    /// This is an operational readiness bit, not a cryptographic review or
    /// production-environment claim.
    pub ready: bool,
    pub activated: bool,
    pub key_count: u8,
}

/// A prepared Groth16 key is uploaded and validated once before activation.
/// The prepared bytes are never returned by a public view; only the canonical
/// compressed-key hash and public-input count are exposed.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct VerifierKeyRecord {
    pub statement_kind: u8,
    pub prepared_key: Vec<u8>,
    pub verifying_key_hash: Vec<u8>,
    pub public_input_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct VerifierKeyView {
    pub statement_kind: u8,
    pub verifying_key_hash: Vec<u8>,
    pub public_input_count: u32,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct AssetProfile {
    pub token_account: AccountId,
    pub decimals: u8,
    pub controller_account: AccountId,
    pub issuer_key: EncryptionKey,
    pub token_auditor_key: EncryptionKey,
    pub crypto_profile_hash: Vec<u8>,
    pub network_id: String,
    pub token_trust_policy: String,
    pub freeze_policy: String,
    pub custody_cap: u128,
}

/// JSON-facing asset profile.  Storage keeps the cap as a native `u128` for
/// checked arithmetic, while the public ABI must never emit a JSON number that
/// can be rounded by a JavaScript client.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct AssetProfileView {
    pub token_account: AccountId,
    pub decimals: u8,
    pub controller_account: AccountId,
    pub issuer_key: EncryptionKey,
    pub token_auditor_key: EncryptionKey,
    pub crypto_profile_hash: Vec<u8>,
    pub network_id: String,
    pub token_trust_policy: String,
    pub freeze_policy: String,
    pub custody_cap: U128,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum VaultKind {
    OpenEnded,
    ClosedEnded,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum VaultPhase {
    Subscription,
    Investment,
    Redemption,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct PhaseTimes {
    #[serde(with = "u64_string")]
    pub subscription_start: u64,
    #[serde(with = "u64_string")]
    pub investment_start: u64,
    #[serde(with = "u64_string")]
    pub redemption_start: u64,
    #[serde(with = "u64_string")]
    pub redemption_buffer: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct CheckpointPolicy {
    #[serde(with = "u64_string")]
    pub epoch_seconds: u64,
    pub disclosure_policy: String,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Vault {
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub owner: AccountId,
    pub asset_id: AccountId,
    pub assets_total: u128,
    pub assets_available: u128,
    pub loss_unrealized: u128,
    pub shares_total: u128,
    pub assets_maximum: u128,
    pub kind: VaultKind,
    pub phase_times: Option<PhaseTimes>,
    pub share_scale: u8,
    pub shares_transferable: bool,
    pub checkpoint_policy: CheckpointPolicy,
    pub accounting_pending: bool,
    pub pending_broker_count: u64,
    pub accounting_version: u64,
    pub risk_version: u64,
    pub reconciled_risk_version: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct KeeperGrant {
    pub delegate_account: AccountId,
    #[serde(with = "u64_string")]
    pub delegate_key_id: u64,
    pub allowed_settlement_per_operation: u128,
    pub allowed_settlement_per_window: u128,
    #[serde(with = "u64_string")]
    pub window_seconds: u64,
    #[serde(with = "u64_string")]
    pub window_started_at: u64,
    pub window_spent: u128,
    #[serde(with = "u64_string")]
    pub expires_at: u64,
    #[serde(with = "u64_string")]
    pub revocation_epoch: u64,
    #[serde(with = "u64_string")]
    pub delegate_epoch: u64,
    pub active: bool,
    pub allowed_operations: Vec<KeeperOperation>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum KeeperOperation {
    MergeInbox,
    Settle,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct KeeperGrantView {
    pub delegate_account: AccountId,
    #[serde(with = "u64_string")]
    pub delegate_key_id: u64,
    pub allowed_operations: Vec<KeeperOperation>,
    pub allowed_settlement_per_operation: U128,
    pub allowed_settlement_per_window: U128,
    #[serde(with = "u64_string")]
    pub window_seconds: u64,
    #[serde(with = "u64_string")]
    pub window_started_at: u64,
    pub window_spent: U128,
    #[serde(with = "u64_string")]
    pub expires_at: u64,
    #[serde(with = "u64_string")]
    pub revocation_epoch: u64,
    #[serde(with = "u64_string")]
    pub delegate_epoch: u64,
    pub active: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Broker {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub owner: AccountId,
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub encryption_key: EncryptionKey,
    /// Epoch for keeper/delegate authorization.  This is deliberately
    /// separate from `encryption_key.authorization_epoch`: granting or
    /// revoking a keeper must not change the canonical-zero domain of the
    /// broker's existing ciphertexts.
    #[serde(with = "u64_string")]
    pub authorization_epoch: u64,
    pub debt_total: u128,
    pub debt_maximum: u128,
    #[serde(with = "u64_string")]
    pub loan_sequence: u64,
    #[serde(with = "u64_string")]
    pub active_loan_count: u64,
    #[serde(with = "u64_string")]
    pub impaired_loan_count: u64,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    pub spending_commitment: Vec<u8>,
    pub inbox_commitment: Vec<u8>,
    #[serde(with = "u64_string")]
    pub spending_version: u64,
    pub loan_book_root: Vec<u8>,
    #[serde(with = "u64_string")]
    pub book_version: u64,
    pub active_principal_ciphertext: Vec<u8>,
    pub impaired_principal_ciphertext: Vec<u8>,
    pub active_principal_commitment: Vec<u8>,
    pub impaired_principal_commitment: Vec<u8>,
    pub impairment_provision: u128,
    pub cumulative_draws: u128,
    pub cumulative_settlements: u128,
    pub cumulative_yield: u128,
    pub cumulative_realized_losses: u128,
    #[serde(with = "u64_string")]
    pub accounting_version: u64,
    #[serde(with = "u64_string")]
    pub risk_version: u64,
    #[serde(with = "u64_string")]
    pub reconciled_risk_version: u64,
    pub accounting_pending: bool,
    #[serde(with = "u64_string")]
    pub accounting_pending_since: u64,
    #[serde(default, with = "option_u64_string")]
    pub reconciliation_checkpoint_id: Option<u64>,
    pub delegates: Vec<KeeperGrant>,
    #[serde(with = "u64_string")]
    pub last_settlement_at: u64,
    pub tombstoned: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct HolderBalance {
    pub owner: AccountId,
    pub asset_id: AccountId,
    pub encryption_key: EncryptionKey,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    #[serde(with = "u64_string")]
    pub spending_version: u64,
    #[serde(with = "u64_string")]
    pub authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub open_loan_count: u64,
    pub frozen: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum LoanStatus {
    Active,
    Paid,
    Defaulted,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Loan {
    #[serde(with = "u64_string")]
    pub loan_id: u64,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub borrower: AccountId,
    #[serde(with = "u64_string")]
    pub proposal_id: u64,
    #[serde(with = "u64_string")]
    pub start_time: u64,
    #[serde(with = "u64_string")]
    pub payment_interval: u64,
    #[serde(with = "u64_string")]
    pub grace_period: u64,
    #[serde(with = "u64_string")]
    pub previous_due: u64,
    #[serde(with = "u64_string")]
    pub next_due: u64,
    pub payment_total: u32,
    pub payment_remaining: u32,
    pub status: LoanStatus,
    pub impaired: bool,
    #[serde(with = "u64_string")]
    pub loan_version: u64,
    #[serde(with = "u64_string")]
    pub borrower_key_id: u64,
    #[serde(with = "u64_string")]
    pub broker_key_id: u64,
    #[serde(with = "u64_string")]
    pub loan_auditor_key_id: u64,
    #[serde(default)]
    pub loan_auditor_public_key: Vec<u8>,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub principal_remaining_commitment: Vec<u8>,
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    pub accounting_leaf: Vec<u8>,
    pub tombstoned: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Proposal {
    #[serde(with = "u64_string")]
    pub proposal_id: u64,
    pub borrower: AccountId,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    #[serde(with = "u64_string")]
    pub borrower_key_id: u64,
    #[serde(with = "u64_string")]
    pub broker_key_id: u64,
    #[serde(with = "u64_string")]
    pub loan_auditor_key_id: u64,
    #[serde(default)]
    pub loan_auditor_public_key: Vec<u8>,
    pub payment_count: u32,
    #[serde(with = "u64_string")]
    pub payment_interval: u64,
    #[serde(with = "u64_string")]
    pub grace_period: u64,
    #[serde(with = "u64_string")]
    pub expiry: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub principal_commitment: Vec<u8>,
    #[serde(default)]
    pub owed_commitment: Vec<u8>,
    #[serde(default)]
    pub payment_commitment: Vec<u8>,
    pub agreement_digest: Vec<u8>,
    pub broker_signature: Vec<u8>,
    pub borrower_signature: Vec<u8>,
    #[serde(with = "u64_string")]
    pub broker_authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub borrower_authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub broker_authorization_nonce: u64,
    #[serde(with = "u64_string")]
    pub borrower_authorization_nonce: u64,
    #[serde(with = "option_u64_string")]
    pub broker_authorization_key_id: Option<u64>,
    #[serde(with = "option_u64_string")]
    pub borrower_authorization_key_id: Option<u64>,
    pub broker_direct_authorized: bool,
    pub borrower_direct_authorized: bool,
    pub consumed: bool,
    pub revoked: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct PublicClaim {
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub owner: AccountId,
    pub amount: u128,
    #[serde(with = "u64_string")]
    pub created_at: u64,
    #[serde(with = "option_u64_string")]
    pub reserved_by: Option<u64>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum DepositStatus {
    Accepted,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct DepositReceipt {
    pub token_account: AccountId,
    pub sender: AccountId,
    pub deposit_id: String,
    pub amount: u128,
    pub payload_hash: Vec<u8>,
    pub status: DepositStatus,
    pub claim_id: u64,
    pub accepted_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct DepositReceiptView {
    pub token_account: AccountId,
    pub sender: AccountId,
    pub deposit_id: String,
    pub amount: U128,
    pub payload_hash: Vec<u8>,
    pub status: DepositStatus,
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    #[serde(with = "u64_string")]
    pub accepted_at: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum PayoutStatus {
    InFlight,
    ResultRecordedSuccess,
    ResultRecordedFailure,
    Succeeded,
    Failed,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct PayoutOperation {
    #[serde(with = "u64_string")]
    pub operation_id: u64,
    pub owner: AccountId,
    pub recipient: AccountId,
    pub amount: u128,
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub attempt: u32,
    pub call_hash: Vec<u8>,
    pub status: PayoutStatus,
    /// Fixed-width callback result record. `result_tag` is 0 while in flight,
    /// 1 for a confirmed token-call success and 2 for a confirmed failure.
    pub result_hash: [u8; 32],
    pub result_tag: u8,
    #[serde(with = "u64_string")]
    pub created_at: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct BookTombstone {
    #[serde(with = "u64_string")]
    pub id: u64,
    pub final_status: LoanStatus,
    #[serde(with = "u64_string")]
    pub final_version: u64,
    pub leaf: Vec<u8>,
    pub removal_evidence: Vec<u8>,
}

/// Metadata for an immutable recovery entry.  Private balance mutations carry
/// a canonical typed statement; deterministic ledger transitions (such as an
/// inbox merge or loan status action) carry an explicit metadata-only entry so
/// recovery consumers never have to infer that an event was omitted.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct RecoveryMetadata {
    pub action: String,
    #[serde(default, with = "option_u64_string")]
    pub loan_id: Option<u64>,
    pub loan_status: Option<LoanStatus>,
    pub noop: bool,
}

/// An immutable recovery entry.  The optional statement is canonical public
/// statement JSON (ciphertexts, commitments, recovery pairs and context only);
/// no plaintext witness is ever accepted or persisted.  `subject_key` and
/// `subject_sequence` identify the primary subject.  Secondary subject views
/// override those two fields while exposing the primary values as origin data.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct RecoveryRecord {
    #[serde(with = "u64_string")]
    pub event_id: u64,
    pub operation: String,
    pub subject_key: String,
    #[serde(with = "u64_string")]
    pub subject_sequence: u64,
    #[serde(with = "u64_string")]
    pub block_timestamp: u64,
    #[serde(default)]
    pub statement: Option<Vec<u8>>,
    #[serde(with = "u64_vec_string")]
    pub key_ids: Vec<u64>,
    #[serde(with = "u64_vec_string")]
    pub versions: Vec<u64>,
    pub metadata: RecoveryMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct RecoveryRecordView {
    #[serde(with = "u64_string")]
    pub event_id: u64,
    pub operation: String,
    pub subject_key: String,
    #[serde(with = "u64_string")]
    pub subject_sequence: u64,
    #[serde(with = "u64_string")]
    pub block_timestamp: u64,
    #[serde(default)]
    pub statement: Option<Vec<u8>>,
    #[serde(with = "u64_vec_string")]
    pub key_ids: Vec<u64>,
    #[serde(with = "u64_vec_string")]
    pub versions: Vec<u64>,
    /// Primary subject and sequence for this event.  For a secondary subject
    /// query, `subject_key`/`subject_sequence` refer to the requested subject.
    pub origin_subject_key: String,
    #[serde(with = "u64_string")]
    pub origin_subject_sequence: u64,
    pub metadata: RecoveryMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct RecoveryHistoryPage {
    pub records: Vec<RecoveryRecordView>,
    #[serde(with = "option_u64_string")]
    pub next_cursor: Option<u64>,
    #[serde(with = "u64_string")]
    pub end_cursor: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Checkpoint {
    #[serde(with = "u64_string")]
    pub checkpoint_id: u64,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    #[serde(with = "u64_string")]
    pub risk_version: u64,
    #[serde(with = "u64_string")]
    pub accounting_version: u64,
    #[serde(with = "u64_string")]
    pub scheduled_at: u64,
    pub consumed: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct InitArgs {
    pub token_account: AccountId,
    pub decimals: u8,
    pub controller_account: AccountId,
    #[serde(with = "u64_string")]
    pub issuer_key_id: u64,
    pub issuer_public_key: Vec<u8>,
    #[serde(with = "u64_string")]
    pub token_auditor_key_id: u64,
    pub token_auditor_public_key: Vec<u8>,
    pub crypto_profile_hash: Vec<u8>,
    pub network_id: String,
    pub token_trust_policy: String,
    pub freeze_policy: String,
    pub custody_cap: U128,
    #[serde(default)]
    pub verifier_key: Vec<u8>,
    pub verifier_manifest_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct CreateVaultArgs {
    pub assets_maximum: U128,
    pub kind: VaultKind,
    pub phase_times: Option<PhaseTimes>,
    pub share_scale: u8,
    pub shares_transferable: bool,
    pub checkpoint_policy: CheckpointPolicy,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct CreateBrokerArgs {
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    #[serde(with = "u64_string")]
    pub encryption_key_id: u64,
    pub encryption_public_key: Vec<u8>,
    pub debt_maximum: U128,
    pub proof_of_possession: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RegisterHolderArgs {
    #[serde(with = "u64_string")]
    pub key_id: u64,
    #[serde(default)]
    pub encryption_public_key: Vec<u8>,
    #[serde(default)]
    pub public_key: Vec<u8>,
    pub proof_of_possession: ProofArgs,
    #[serde(default)]
    pub zero_proofs: Vec<ProofArgs>,
    #[serde(default)]
    pub authorization_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RegisterAuthorizationKeyArgs {
    #[serde(with = "u64_string")]
    pub key_id: u64,
    pub public_key: Vec<u8>,
    /// Optional legacy field retained for wire compatibility.  Registration
    /// is authenticated by the direct predecessor account; no fake proof is
    /// accepted or required for this application authorization key.
    #[serde(default)]
    pub proof: Option<ProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct CreateProposalArgs {
    pub borrower: AccountId,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    #[serde(with = "u64_string")]
    pub borrower_key_id: u64,
    #[serde(with = "u64_string")]
    pub broker_key_id: u64,
    #[serde(with = "u64_string")]
    pub loan_auditor_key_id: u64,
    #[serde(default)]
    pub loan_auditor_public_key: Vec<u8>,
    pub payment_count: u32,
    #[serde(with = "u64_string")]
    pub payment_interval: u64,
    #[serde(with = "u64_string")]
    pub grace_period: u64,
    #[serde(with = "u64_string")]
    pub expiry: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub principal_commitment: Vec<u8>,
    #[serde(default)]
    pub owed_commitment: Vec<u8>,
    #[serde(default)]
    pub payment_commitment: Vec<u8>,
    pub agreement_digest: Vec<u8>,
    pub broker_signature: Vec<u8>,
    pub borrower_signature: Vec<u8>,
    #[serde(with = "u64_string")]
    pub broker_authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub borrower_authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub broker_authorization_nonce: u64,
    #[serde(with = "u64_string")]
    pub borrower_authorization_nonce: u64,
    #[serde(default)]
    pub broker_authorization_key_id: Option<u64>,
    #[serde(default)]
    pub borrower_authorization_key_id: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ProofArgs {
    /// Canonical `confidential_crypto::Statement` JSON bytes.  The Core
    /// reconstructs and compares this typed statement against current ledger
    /// state before deriving verifier inputs; callers cannot choose a generic
    /// context or public-input vector as proof authority.
    #[serde(default)]
    pub statement: Vec<u8>,
    pub context: Vec<u8>,
    pub proof: Vec<u8>,
    #[serde(default)]
    pub statement_kind: Option<u8>,
    #[serde(default)]
    pub public_inputs: Vec<Vec<u8>>,
    #[serde(default)]
    pub verifying_key_hash: Vec<u8>,
    #[serde(default)]
    pub profile_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct DepositMessage {
    pub version: u8,
    pub deposit_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct DepositToVaultArgs {
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub amount: U128,
    pub min_shares_out: U128,
    #[serde(with = "u64_string")]
    pub expiry: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RedeemSharesArgs {
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub shares: U128,
    pub min_assets_out: U128,
    #[serde(with = "u64_string")]
    pub expiry: u64,
    pub sole_shareholder_waiver: bool,
    #[serde(default)]
    pub burn_worthless: bool,
    #[serde(default)]
    pub broker_zero_proofs: Vec<BrokerZeroProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct BrokerZeroProofArgs {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    /// Preferred closure proof: one zero-balance statement over the
    /// homomorphic sum of spending, inbox, active-principal and
    /// impaired-principal.  The four legacy proofs remain optional
    /// compatibility fields for clients that have not migrated yet.
    #[serde(default)]
    pub combined_proof: Option<ProofArgs>,
    #[serde(default)]
    pub spending_proof: Option<ProofArgs>,
    #[serde(default)]
    pub inbox_proof: Option<ProofArgs>,
    #[serde(default)]
    pub active_principal_proof: Option<ProofArgs>,
    #[serde(default)]
    pub impaired_principal_proof: Option<ProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ShieldArgs {
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub amount: U128,
    #[serde(default)]
    pub spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct UnshieldArgs {
    pub amount: U128,
    #[serde(default)]
    pub spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub commitment: Vec<u8>,
    pub proof: ProofArgs,
    #[serde(with = "u64_string")]
    pub expected_spending_version: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct MergeArgs {
    #[serde(with = "u64_string")]
    pub expected_spending_version: u64,
    #[serde(default)]
    pub new_spending_ciphertext: Vec<u8>,
    pub proof: Option<ProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct DrawArgs {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub amount: U128,
    #[serde(default)]
    pub issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_spending_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_inbox_commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct OriginateArgs {
    #[serde(with = "u64_string")]
    pub proposal_id: u64,
    #[serde(default)]
    pub borrower_spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub borrower_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub borrower_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub loan_principal_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub loan_initial_owed_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub loan_periodic_payment_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub principal_commitment: Vec<u8>,
    #[serde(default)]
    pub owed_commitment: Vec<u8>,
    #[serde(default)]
    pub payment_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_book_root: Vec<u8>,
    #[serde(default)]
    pub accounting_leaf: Vec<u8>,
    #[serde(default)]
    pub broker_spending_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct TransferArgs {
    pub destination: AccountId,
    #[serde(with = "u64_string")]
    pub expected_spending_version: u64,
    #[serde(default)]
    pub sender_spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub sender_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub sender_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub destination_inbox_ciphertext: Vec<u8>,
    #[serde(default)]
    pub destination_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub destination_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub transfer_views: Vec<Vec<u8>>,
    #[serde(default)]
    pub commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub enum RepayMode {
    Regular,
    Full,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RepayArgs {
    #[serde(with = "u64_string")]
    pub loan_id: u64,
    pub mode: RepayMode,
    #[serde(with = "u64_string")]
    pub expected_loan_version: u64,
    #[serde(with = "u64_string")]
    pub expected_borrower_spending_version: u64,
    #[serde(default)]
    pub borrower_spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub borrower_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub borrower_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_inbox_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    #[serde(default)]
    pub broker_active_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_book_root: Vec<u8>,
    #[serde(default)]
    pub accounting_leaf: Vec<u8>,
    #[serde(default)]
    pub broker_inbox_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub transfer_views: Vec<Vec<u8>>,
    #[serde(default)]
    pub commitment: Vec<u8>,
    #[serde(default, with = "option_u64_string")]
    pub authorization_key_id: Option<u64>,
    #[serde(default, with = "u64_string")]
    pub authorization_epoch: u64,
    #[serde(default, with = "u64_string")]
    pub authorization_nonce: u64,
    #[serde(default)]
    pub authorization_signature: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub enum LoanManagementAction {
    Impair,
    Unimpair,
    Default,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ManageLoanArgs {
    #[serde(with = "u64_string")]
    pub loan_id: u64,
    pub action: LoanManagementAction,
    #[serde(with = "u64_string")]
    pub expected_loan_version: u64,
    #[serde(default)]
    pub accounting_leaf: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_book_root: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub proof: Option<ProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct SettleArgs {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub amount: U128,
    #[serde(with = "u64_string")]
    pub expected_spending_version: u64,
    #[serde(with = "u64_string")]
    pub expected_accounting_version: u64,
    #[serde(default)]
    pub broker_spending_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_issuer_ciphertext: Vec<u8>,
    #[serde(default)]
    pub broker_auditor_ciphertext: Vec<u8>,
    #[serde(default)]
    pub settlement_views: Vec<Vec<u8>>,
    #[serde(default)]
    pub broker_spending_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_inbox_commitment: Vec<u8>,
    pub reconciliation: Option<ReconcileArgs>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ReconcileArgs {
    #[serde(with = "u64_string")]
    pub checkpoint_id: u64,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    #[serde(with = "u64_string")]
    pub expected_risk_version: u64,
    #[serde(with = "u64_string")]
    pub expected_accounting_version: u64,
    pub new_broker_debt: U128,
    pub new_broker_provision: U128,
    pub loss: U128,
    pub new_vault_total: U128,
    #[serde(default)]
    pub cash_commitment: Vec<u8>,
    #[serde(default)]
    pub active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub impaired_principal_commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct GrantKeeperArgs {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub delegate_account: AccountId,
    #[serde(with = "u64_string")]
    pub delegate_key_id: u64,
    pub allowed_settlement_per_operation: U128,
    pub allowed_settlement_per_window: U128,
    #[serde(with = "u64_string")]
    pub window_seconds: u64,
    #[serde(with = "u64_string")]
    pub expires_at: u64,
    #[serde(with = "u64_string")]
    pub delegate_epoch: u64,
    pub allowed_operations: Vec<KeeperOperation>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RequestPayoutArgs {
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub recipient: AccountId,
    #[serde(with = "u64_string")]
    pub operation_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PayoutCallbackArgs {
    #[serde(with = "u64_string")]
    pub operation_id: u64,
    pub attempt: u32,
    pub result_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct VaultView {
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub owner: AccountId,
    pub asset_id: AccountId,
    pub assets_total: U128,
    pub assets_available: U128,
    pub loss_unrealized: U128,
    pub nav: U128,
    pub shares_total: U128,
    pub assets_maximum: U128,
    pub share_scale: u8,
    pub shares_transferable: bool,
    pub checkpoint_policy: CheckpointPolicy,
    pub phase_times: Option<PhaseTimes>,
    pub accounting_pending: bool,
    #[serde(with = "u64_string")]
    pub pending_broker_count: u64,
    #[serde(with = "u64_string")]
    pub accounting_version: u64,
    #[serde(with = "u64_string")]
    pub risk_version: u64,
    #[serde(with = "u64_string")]
    pub reconciled_risk_version: u64,
    pub kind: VaultKind,
    pub phase: Option<VaultPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct BrokerView {
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub owner: AccountId,
    #[serde(with = "u64_string")]
    pub vault_id: u64,
    pub debt_total: U128,
    pub debt_maximum: U128,
    #[serde(with = "u64_string")]
    pub active_loan_count: u64,
    #[serde(with = "u64_string")]
    pub impaired_loan_count: u64,
    #[serde(with = "u64_string")]
    pub spending_version: u64,
    #[serde(with = "u64_string")]
    pub book_version: u64,
    pub loan_book_root: Vec<u8>,
    #[serde(with = "u64_string")]
    pub encryption_key_id: u64,
    pub encryption_public_key: Vec<u8>,
    #[serde(with = "u64_string")]
    pub authorization_epoch: u64,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    pub spending_commitment: Vec<u8>,
    pub inbox_commitment: Vec<u8>,
    pub active_principal_ciphertext: Vec<u8>,
    pub impaired_principal_ciphertext: Vec<u8>,
    pub active_principal_commitment: Vec<u8>,
    pub impaired_principal_commitment: Vec<u8>,
    pub impairment_provision: U128,
    #[serde(with = "u64_string")]
    pub accounting_version: u64,
    #[serde(with = "u64_string")]
    pub risk_version: u64,
    #[serde(with = "u64_string")]
    pub reconciled_risk_version: u64,
    pub accounting_pending: bool,
    #[serde(with = "u64_string")]
    pub accounting_pending_since: u64,
    #[serde(default, with = "option_u64_string")]
    pub reconciliation_checkpoint_id: Option<u64>,
    pub delegates: Vec<KeeperGrantView>,
    #[serde(with = "u64_string")]
    pub last_settlement_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct HolderView {
    pub owner: AccountId,
    pub asset_id: AccountId,
    #[serde(with = "u64_string")]
    pub key_id: u64,
    pub encryption_public_key: Vec<u8>,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    #[serde(with = "u64_string")]
    pub spending_version: u64,
    #[serde(with = "u64_string")]
    pub authorization_epoch: u64,
    #[serde(with = "u64_string")]
    pub open_loan_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct FreezeStatusView {
    pub asset_frozen: bool,
    pub holder_frozen: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct LoanView {
    #[serde(with = "u64_string")]
    pub loan_id: u64,
    #[serde(with = "u64_string")]
    pub broker_id: u64,
    pub borrower: AccountId,
    #[serde(with = "u64_string")]
    pub proposal_id: u64,
    #[serde(with = "u64_string")]
    pub start_time: u64,
    #[serde(with = "u64_string")]
    pub payment_interval: u64,
    #[serde(with = "u64_string")]
    pub grace_period: u64,
    #[serde(with = "u64_string")]
    pub previous_due: u64,
    #[serde(default, with = "option_u64_string")]
    pub next_due: Option<u64>,
    pub payment_total: u32,
    pub payment_remaining: u32,
    pub status: LoanStatus,
    pub impaired: bool,
    #[serde(with = "u64_string")]
    pub loan_version: u64,
    #[serde(with = "u64_string")]
    pub borrower_key_id: u64,
    #[serde(with = "u64_string")]
    pub broker_key_id: u64,
    #[serde(with = "u64_string")]
    pub loan_auditor_key_id: u64,
    pub loan_auditor_public_key: Vec<u8>,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_commitment: Vec<u8>,
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    pub accounting_leaf: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct ClaimView {
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub owner: AccountId,
    pub amount: U128,
    #[serde(with = "u64_string")]
    pub created_at: u64,
    #[serde(default, with = "option_u64_string")]
    pub reserved_by: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PayoutView {
    #[serde(with = "u64_string")]
    pub operation_id: u64,
    pub owner: AccountId,
    pub recipient: AccountId,
    pub amount: U128,
    #[serde(with = "u64_string")]
    pub claim_id: u64,
    pub attempt: u32,
    pub call_hash: Vec<u8>,
    pub status: PayoutStatus,
    pub result_hash: [u8; 32],
    pub result_tag: u8,
    #[serde(with = "u64_string")]
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ProofContextView {
    pub operation: String,
    pub asset_account: AccountId,
    pub network_id: String,
    pub profile_hash: Vec<u8>,
    pub verifier_manifest_hash: Vec<u8>,
    #[serde(with = "u64_vec_string")]
    pub ids: Vec<u64>,
    pub account_ids: Vec<AccountId>,
    #[serde(with = "u64_vec_string")]
    pub versions: Vec<u64>,
    pub ciphertexts: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub public_values: Vec<U128>,
    pub state_digest: Vec<u8>,
    pub statement_kind: Option<u8>,
    pub statement: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub verifying_key_hash: Vec<u8>,
    /// Canonical `confidential_crypto::OperationContext` JSON.  Wallets use
    /// this exact context when constructing their typed statement.
    pub operation_context: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ProofContextArgs {
    pub operation: String,
    #[serde(default, with = "option_u64_string")]
    pub primary_id: Option<u64>,
    pub account_id: Option<AccountId>,
    pub destination: Option<AccountId>,
    #[serde(default, with = "option_u64_string")]
    pub broker_id: Option<u64>,
    #[serde(default, with = "option_u64_string")]
    pub key_id: Option<u64>,
    #[serde(default, with = "option_u64_string")]
    pub checkpoint_id: Option<u64>,
    pub action: Option<LoanManagementAction>,
    pub amount: Option<U128>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct ProtocolCounters {
    #[serde(with = "u64_string")]
    pub vault_high_water: u64,
    #[serde(with = "u64_string")]
    pub broker_high_water: u64,
    #[serde(with = "u64_string")]
    pub loan_high_water: u64,
    #[serde(with = "u64_string")]
    pub proposal_high_water: u64,
    #[serde(with = "u64_string")]
    pub claim_high_water: u64,
    #[serde(with = "u64_string")]
    pub payout_high_water: u64,
    #[serde(with = "u64_string")]
    pub checkpoint_high_water: u64,
    #[serde(with = "u64_string")]
    pub recovery_high_water: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PrepareStatementArgs {
    pub operation: String,
    #[serde(with = "u64_string")]
    pub primary_id: u64,
    /// Canonical confidential-crypto `Statement` JSON.  The contract checks
    /// that its pre-state/context matches current storage and returns the
    /// canonical statement plus verifier inputs; it never hashes an
    /// arbitrary caller output tuple as a substitute statement.
    pub statement: Vec<u8>,
    pub ciphertexts: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub public_values: Vec<U128>,
}
