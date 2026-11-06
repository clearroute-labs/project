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

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct EncryptionKey {
    pub key_id: u64,
    pub public_key: Vec<u8>,
    pub registered_at: u64,
    pub authorization_epoch: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct AuthorizationKey {
    pub owner: AccountId,
    pub key_id: u64,
    pub public_key: Vec<u8>,
    pub epoch: u64,
    pub nonce: u64,
    pub revoked: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct VerifierConfig {
    pub profile_hash: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub manifest_hash: Vec<u8>,
    pub production: bool,
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
    pub subscription_start: u64,
    pub investment_start: u64,
    pub redemption_start: u64,
    pub redemption_buffer: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct CheckpointPolicy {
    pub epoch_seconds: u64,
    pub disclosure_policy: String,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Vault {
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
    pub accounting_version: u64,
    pub risk_version: u64,
    pub reconciled_risk_version: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct KeeperGrant {
    pub delegate_account: AccountId,
    pub delegate_key_id: u64,
    pub allowed_settlement_per_operation: u128,
    pub allowed_settlement_per_window: u128,
    pub window_seconds: u64,
    pub window_started_at: u64,
    pub window_spent: u128,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub delegate_epoch: u64,
    pub active: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Broker {
    pub broker_id: u64,
    pub owner: AccountId,
    pub vault_id: u64,
    pub encryption_key: EncryptionKey,
    pub debt_total: u128,
    pub debt_maximum: u128,
    pub loan_sequence: u64,
    pub active_loan_count: u64,
    pub impaired_loan_count: u64,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    pub spending_commitment: Vec<u8>,
    pub inbox_commitment: Vec<u8>,
    pub spending_version: u64,
    pub loan_book_root: Vec<u8>,
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
    pub accounting_version: u64,
    pub risk_version: u64,
    pub reconciled_risk_version: u64,
    pub accounting_pending: bool,
    pub delegates: Vec<KeeperGrant>,
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
    pub spending_version: u64,
    pub authorization_epoch: u64,
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
    pub loan_id: u64,
    pub broker_id: u64,
    pub borrower: AccountId,
    pub proposal_id: u64,
    pub start_time: u64,
    pub payment_interval: u64,
    pub grace_period: u64,
    pub previous_due: u64,
    pub next_due: u64,
    pub payment_total: u32,
    pub payment_remaining: u32,
    pub status: LoanStatus,
    pub impaired: bool,
    pub loan_version: u64,
    pub borrower_key_id: u64,
    pub broker_key_id: u64,
    pub loan_auditor_key_id: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    pub accounting_leaf: Vec<u8>,
    pub tombstoned: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Proposal {
    pub proposal_id: u64,
    pub borrower: AccountId,
    pub broker_id: u64,
    pub vault_id: u64,
    pub borrower_key_id: u64,
    pub broker_key_id: u64,
    pub loan_auditor_key_id: u64,
    pub payment_count: u32,
    pub payment_interval: u64,
    pub grace_period: u64,
    pub expiry: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub agreement_digest: Vec<u8>,
    pub broker_signature: Vec<u8>,
    pub borrower_signature: Vec<u8>,
    pub broker_authorization_epoch: u64,
    pub borrower_authorization_epoch: u64,
    pub consumed: bool,
    pub revoked: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct PublicClaim {
    pub claim_id: u64,
    pub owner: AccountId,
    pub amount: u128,
    pub created_at: u64,
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
    pub operation_id: u64,
    pub owner: AccountId,
    pub recipient: AccountId,
    pub amount: u128,
    pub claim_id: u64,
    pub attempt: u32,
    pub call_hash: Vec<u8>,
    pub status: PayoutStatus,
    pub result_hash: Option<Vec<u8>>,
    pub result_success: Option<bool>,
    pub created_at: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct BookTombstone {
    pub id: u64,
    pub final_status: LoanStatus,
    pub final_version: u64,
    pub leaf: Vec<u8>,
    pub removal_evidence: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct Checkpoint {
    pub checkpoint_id: u64,
    pub broker_id: u64,
    pub risk_version: u64,
    pub accounting_version: u64,
    pub scheduled_at: u64,
    pub consumed: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct InitArgs {
    pub token_account: AccountId,
    pub decimals: u8,
    pub controller_account: AccountId,
    pub issuer_key_id: u64,
    pub issuer_public_key: Vec<u8>,
    pub token_auditor_key_id: u64,
    pub token_auditor_public_key: Vec<u8>,
    pub crypto_profile_hash: Vec<u8>,
    pub network_id: String,
    pub token_trust_policy: String,
    pub freeze_policy: String,
    pub custody_cap: U128,
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
    pub vault_id: u64,
    pub encryption_key_id: u64,
    pub encryption_public_key: Vec<u8>,
    pub debt_maximum: U128,
    pub proof_of_possession: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RegisterHolderArgs {
    pub key_id: u64,
    pub public_key: Vec<u8>,
    pub proof_of_possession: Vec<u8>,
    pub authorization_signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RegisterAuthorizationKeyArgs {
    pub key_id: u64,
    pub public_key: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct CreateProposalArgs {
    pub borrower: AccountId,
    pub broker_id: u64,
    pub vault_id: u64,
    pub borrower_key_id: u64,
    pub broker_key_id: u64,
    pub loan_auditor_key_id: u64,
    pub payment_count: u32,
    pub payment_interval: u64,
    pub grace_period: u64,
    pub expiry: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub agreement_digest: Vec<u8>,
    pub broker_signature: Vec<u8>,
    pub borrower_signature: Vec<u8>,
    pub broker_authorization_epoch: u64,
    pub borrower_authorization_epoch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ProofArgs {
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
#[serde(crate = "serde")]
pub struct DepositMessage {
    pub version: u8,
    pub deposit_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct DepositToVaultArgs {
    pub claim_id: u64,
    pub vault_id: u64,
    pub amount: U128,
    pub min_shares_out: U128,
    pub expiry: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RedeemSharesArgs {
    pub vault_id: u64,
    pub shares: U128,
    pub min_assets_out: U128,
    pub expiry: u64,
    pub sole_shareholder_waiver: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct ShieldArgs {
    pub claim_id: u64,
    pub amount: U128,
    pub spending_ciphertext: Vec<u8>,
    pub issuer_ciphertext: Vec<u8>,
    pub auditor_ciphertext: Vec<u8>,
    pub commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct UnshieldArgs {
    pub amount: U128,
    pub spending_ciphertext: Vec<u8>,
    pub issuer_ciphertext: Vec<u8>,
    pub auditor_ciphertext: Vec<u8>,
    pub commitment: Vec<u8>,
    pub proof: ProofArgs,
    pub expected_spending_version: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct MergeArgs {
    pub expected_spending_version: u64,
    pub new_spending_ciphertext: Vec<u8>,
    pub proof: Option<ProofArgs>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct DrawArgs {
    pub broker_id: u64,
    pub amount: U128,
    pub issuer_ciphertext: Vec<u8>,
    pub auditor_ciphertext: Vec<u8>,
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
    pub proposal_id: u64,
    pub borrower_spending_ciphertext: Vec<u8>,
    pub borrower_issuer_ciphertext: Vec<u8>,
    pub borrower_auditor_ciphertext: Vec<u8>,
    pub broker_spending_ciphertext: Vec<u8>,
    pub broker_issuer_ciphertext: Vec<u8>,
    pub broker_auditor_ciphertext: Vec<u8>,
    pub loan_principal_ciphertexts: Vec<Vec<u8>>,
    pub loan_initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub loan_periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub broker_active_principal_ciphertext: Vec<u8>,
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    pub broker_book_root: Vec<u8>,
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
    pub expected_spending_version: u64,
    pub sender_spending_ciphertext: Vec<u8>,
    pub sender_issuer_ciphertext: Vec<u8>,
    pub sender_auditor_ciphertext: Vec<u8>,
    pub destination_inbox_ciphertext: Vec<u8>,
    pub destination_issuer_ciphertext: Vec<u8>,
    pub destination_auditor_ciphertext: Vec<u8>,
    pub transfer_views: Vec<Vec<u8>>,
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
    pub loan_id: u64,
    pub mode: RepayMode,
    pub expected_loan_version: u64,
    pub expected_borrower_spending_version: u64,
    pub borrower_spending_ciphertext: Vec<u8>,
    pub borrower_issuer_ciphertext: Vec<u8>,
    pub borrower_auditor_ciphertext: Vec<u8>,
    pub broker_inbox_ciphertext: Vec<u8>,
    pub broker_issuer_ciphertext: Vec<u8>,
    pub broker_auditor_ciphertext: Vec<u8>,
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    pub broker_active_principal_ciphertext: Vec<u8>,
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    pub broker_book_root: Vec<u8>,
    pub accounting_leaf: Vec<u8>,
    #[serde(default)]
    pub broker_inbox_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_commitment: Vec<u8>,
    pub transfer_views: Vec<Vec<u8>>,
    pub commitment: Vec<u8>,
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
    pub loan_id: u64,
    pub action: LoanManagementAction,
    pub expected_loan_version: u64,
    pub accounting_leaf: Vec<u8>,
    pub broker_active_principal_ciphertext: Vec<u8>,
    pub broker_impaired_principal_ciphertext: Vec<u8>,
    pub broker_book_root: Vec<u8>,
    #[serde(default)]
    pub broker_active_principal_commitment: Vec<u8>,
    #[serde(default)]
    pub broker_impaired_principal_commitment: Vec<u8>,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct SettleArgs {
    pub broker_id: u64,
    pub amount: U128,
    pub expected_spending_version: u64,
    pub expected_accounting_version: u64,
    pub broker_spending_ciphertext: Vec<u8>,
    pub broker_issuer_ciphertext: Vec<u8>,
    pub broker_auditor_ciphertext: Vec<u8>,
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
    pub checkpoint_id: u64,
    pub broker_id: u64,
    pub expected_risk_version: u64,
    pub expected_accounting_version: u64,
    pub new_broker_debt: U128,
    pub new_broker_provision: U128,
    pub loss: U128,
    pub new_vault_total: U128,
    pub proof: ProofArgs,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct GrantKeeperArgs {
    pub broker_id: u64,
    pub delegate_account: AccountId,
    pub delegate_key_id: u64,
    pub allowed_settlement_per_operation: U128,
    pub allowed_settlement_per_window: U128,
    pub window_seconds: u64,
    pub expires_at: u64,
    pub delegate_epoch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct RequestPayoutArgs {
    pub claim_id: u64,
    pub recipient: AccountId,
    pub operation_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PayoutCallbackArgs {
    pub operation_id: u64,
    pub attempt: u32,
    pub result_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct VaultView {
    pub vault_id: u64,
    pub owner: AccountId,
    pub asset_id: AccountId,
    pub assets_total: U128,
    pub assets_available: U128,
    pub loss_unrealized: U128,
    pub nav: U128,
    pub shares_total: U128,
    pub accounting_pending: bool,
    pub accounting_version: u64,
    pub risk_version: u64,
    pub reconciled_risk_version: u64,
    pub kind: VaultKind,
    pub phase: Option<VaultPhase>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct BrokerView {
    pub broker_id: u64,
    pub owner: AccountId,
    pub vault_id: u64,
    pub debt_total: U128,
    pub debt_maximum: U128,
    pub active_loan_count: u64,
    pub impaired_loan_count: u64,
    pub spending_version: u64,
    pub book_version: u64,
    pub loan_book_root: Vec<u8>,
    pub encryption_key_id: u64,
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
    pub accounting_version: u64,
    pub risk_version: u64,
    pub reconciled_risk_version: u64,
    pub accounting_pending: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct HolderView {
    pub owner: AccountId,
    pub asset_id: AccountId,
    pub key_id: u64,
    pub spending_ciphertext: Vec<u8>,
    pub inbox_ciphertext: Vec<u8>,
    pub issuer_balance_ciphertext: Vec<u8>,
    pub auditor_balance_ciphertext: Vec<u8>,
    pub spending_version: u64,
    pub authorization_epoch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct LoanView {
    pub loan_id: u64,
    pub broker_id: u64,
    pub borrower: AccountId,
    pub proposal_id: u64,
    pub start_time: u64,
    pub payment_interval: u64,
    pub grace_period: u64,
    pub previous_due: u64,
    pub next_due: Option<u64>,
    pub payment_total: u32,
    pub payment_remaining: u32,
    pub status: LoanStatus,
    pub impaired: bool,
    pub loan_version: u64,
    pub borrower_key_id: u64,
    pub broker_key_id: u64,
    pub loan_auditor_key_id: u64,
    pub principal_ciphertexts: Vec<Vec<u8>>,
    pub initial_owed_ciphertexts: Vec<Vec<u8>>,
    pub amount_owed_ciphertexts: Vec<Vec<u8>>,
    pub periodic_payment_ciphertexts: Vec<Vec<u8>>,
    pub principal_remaining_ciphertexts: Vec<Vec<u8>>,
    pub cumulative_repaid_ciphertexts: Vec<Vec<u8>>,
    pub accounting_leaf: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct ClaimView {
    pub claim_id: u64,
    pub owner: AccountId,
    pub amount: U128,
    pub created_at: u64,
    pub reserved_by: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PayoutView {
    pub operation_id: u64,
    pub owner: AccountId,
    pub recipient: AccountId,
    pub amount: U128,
    pub claim_id: u64,
    pub attempt: u32,
    pub call_hash: Vec<u8>,
    pub status: PayoutStatus,
    pub result_hash: Option<Vec<u8>>,
    pub result_success: Option<bool>,
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
    pub ids: Vec<u64>,
    pub account_ids: Vec<AccountId>,
    pub versions: Vec<u64>,
    pub ciphertexts: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub public_values: Vec<U128>,
    pub state_digest: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
pub struct PrepareStatementArgs {
    pub operation: String,
    pub primary_id: u64,
    pub ciphertexts: Vec<Vec<u8>>,
    pub commitments: Vec<Vec<u8>>,
    pub public_values: Vec<U128>,
}
