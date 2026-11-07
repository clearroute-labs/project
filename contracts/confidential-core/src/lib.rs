#![forbid(unsafe_code)]

//! Confidential lending Core contract.
//!
//! Private values are stored only as opaque ciphertexts, commitments, and
//! proof-bound byte strings. Public monetary values remain u128 in storage and
//! are exposed as decimal U128 values. External token movement is confined to
//! the receipt and payout state machines at the end of this module.

mod crypto_adapter;
mod types;

use authenticated_book::{Book, HashFunction, NodeKey, NodeStore};
use borsh::{BorshSerialize, to_vec};
use confidential_crypto::{
    ConversionMode, KeyPossessionStatement, OperationContext, Statement, StatementKind,
};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
    PromiseOrValue, env, ext_contract, near, near_bindgen, require,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub use types::*;

const MAX_ASSET_UNITS: u128 = i64::MAX as u128;
const MAX_PAYMENT_COUNT: u32 = 10_000;
const MAX_INTERVAL_SECONDS: u64 = 365 * 24 * 60 * 60;
const MAX_ID_BYTES: usize = 128;
const PAYOUT_GAS: Gas = Gas::from_tgas(20);
const MAX_CHECKPOINT_EPOCH: u64 = 86_400;
const MIN_CHECKPOINT_EPOCH: u64 = 60;
const MAX_PREPARED_KEY_BYTES: usize = 512 * 1024;
const MAX_VERIFIER_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_EXTERNAL_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const REQUIRED_VERIFIER_KEYS: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const MAX_BROKERS_PER_VAULT: usize = 64;

const ERR_INVALID_ENCODING: &str = "INVALID_ENCODING";
const ERR_INVALID_AMOUNT: &str = "INVALID_AMOUNT";
const ERR_WRONG_ASSET: &str = "WRONG_ASSET";
const ERR_UNAUTHORIZED: &str = "UNAUTHORIZED";
const ERR_ACCOUNT_FROZEN: &str = "ACCOUNT_FROZEN";
const ERR_NOT_REGISTERED: &str = "NOT_REGISTERED";
const ERR_WRONG_PHASE: &str = "WRONG_PHASE";
const ERR_EXPIRED: &str = "EXPIRED";
const ERR_STALE_STATE: &str = "STALE_STATE";
const ERR_BAD_PROOF: &str = "BAD_PROOF";
const ERR_INSUFFICIENT_PUBLIC_FUNDS: &str = "INSUFFICIENT_PUBLIC_FUNDS";
const ERR_INSUFFICIENT_PRIVATE_FUNDS: &str = "INSUFFICIENT_PRIVATE_FUNDS";
const ERR_DEBT_LIMIT: &str = "DEBT_LIMIT";
const ERR_ACCOUNTING_PENDING: &str = "ACCOUNTING_PENDING";
const ERR_TOO_SOON: &str = "TOO_SOON";
const ERR_LOAN_CLOSED: &str = "LOAN_CLOSED";
const ERR_HAS_OBLIGATIONS: &str = "HAS_OBLIGATIONS";
const ERR_SLIPPAGE: &str = "SLIPPAGE";
const ERR_OPERATION_PENDING: &str = "OPERATION_PENDING";
const ERR_UNSUPPORTED_PROFILE: &str = "UNSUPPORTED_PROFILE";
const ERR_REPLAY: &str = "REPLAY";
const ERR_NOT_FOUND: &str = "NOT_FOUND";
const ERR_STORAGE: &str = "STORAGE";

const VERIFIER_FAMILIES: [(&str, u8); 8] = [
    ("key-possession", 1),
    ("public-conversion", 2),
    ("confidential-transfer", 3),
    ("origination", 4),
    ("repayment", 5),
    ("reconciliation", 6),
    ("zero-balance", 7),
    ("ownership", 8),
];

const EXTERNAL_ARTIFACTS: [&str; 3] = ["native.prover", "browser.glue", "browser.wasm"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierManifestDocument {
    schema: String,
    #[serde(rename = "profileHash")]
    profile_hash: String,
    #[serde(rename = "networkId")]
    network_id: String,
    #[serde(rename = "coreAccountId")]
    core_account_id: String,
    setup: String,
    artifacts: BTreeMap<String, VerifierManifestArtifact>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierManifestArtifact {
    path: String,
    sha256: String,
    bytes: u64,
}

struct ReconciliationCheck {
    new_vault_provision: u128,
}

#[derive(BorshSerialize)]
struct AgreementTerms {
    domain: Vec<u8>,
    proposal_id: u64,
    asset: AccountId,
    borrower: AccountId,
    broker_id: u64,
    vault_id: u64,
    borrower_key_id: u64,
    broker_key_id: u64,
    loan_auditor_key_id: u64,
    payment_count: u32,
    payment_interval: u64,
    grace_period: u64,
    expiry: u64,
    principal_ciphertexts: Vec<Vec<u8>>,
    initial_owed_ciphertexts: Vec<Vec<u8>>,
    periodic_payment_ciphertexts: Vec<Vec<u8>>,
    principal_commitment: Vec<u8>,
    owed_commitment: Vec<u8>,
    payment_commitment: Vec<u8>,
    broker_authorization_epoch: u64,
    borrower_authorization_epoch: u64,
    broker_authorization_nonce: u64,
    borrower_authorization_nonce: u64,
    loan_auditor_public_key: Vec<u8>,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Vaults,
    Brokers,
    Loans,
    Holders,
    Proposals,
    Claims,
    Receipts,
    Payouts,
    PayoutIndex,
    Checkpoints,
    VaultBrokers,
    Shares,
    LoanTombstones,
    BrokerTombstones,
    ProposalTombstones,
    PayoutTombstones,
    ShareTombstones,
    StorageDeposits,
    AuthorizationKeys,
    VerifierKeys,
    RecoveryRecords,
    RecoverySubjectIndex,
    RecoverySubjectCounts,
    BookNodes,
}

fn manifest_sha256(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let decoded = hex::decode(value).ok()?;
    (decoded.len() == 32).then_some(decoded)
}

fn statement_kind_for_manifest(kind: u8) -> Option<StatementKind> {
    Some(match kind {
        1 => StatementKind::KeyPossession,
        2 => StatementKind::PublicConversion,
        3 => StatementKind::ConfidentialTransfer,
        4 => StatementKind::Origination,
        5 => StatementKind::Repayment,
        6 => StatementKind::Reconciliation,
        7 => StatementKind::ZeroBalance,
        8 => StatementKind::Ownership,
        _ => return None,
    })
}

fn validate_manifest_artifact(artifact: &VerifierManifestArtifact, max_bytes: u64) -> Vec<u8> {
    require!(
        !artifact.path.is_empty() && artifact.path.len() <= MAX_VERIFIER_MANIFEST_BYTES,
        ERR_UNSUPPORTED_PROFILE
    );
    require!(
        artifact.bytes > 0 && artifact.bytes <= max_bytes,
        ERR_UNSUPPORTED_PROFILE
    );
    manifest_sha256(&artifact.sha256).unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE))
}

fn parse_verifier_manifest(args: &InitArgs) -> Vec<VerifierArtifactExpectation> {
    require!(
        !args.verifier_manifest_json.is_empty()
            && args.verifier_manifest_json.len() <= MAX_VERIFIER_MANIFEST_BYTES,
        ERR_UNSUPPORTED_PROFILE
    );
    require!(
        args.verifier_manifest_hash.len() == 32,
        ERR_UNSUPPORTED_PROFILE
    );
    let digest = Sha256::digest(args.verifier_manifest_json.as_bytes());
    require!(
        &digest[..] == args.verifier_manifest_hash.as_slice(),
        ERR_UNSUPPORTED_PROFILE
    );
    let manifest: VerifierManifestDocument =
        near_sdk::serde_json::from_str(&args.verifier_manifest_json)
            .unwrap_or_else(|_| env::panic_str(ERR_UNSUPPORTED_PROFILE));
    // Re-serialization enforces the same compact field order and escaping as
    // the deployment tooling. It also rejects duplicate object keys: a
    // duplicate cannot survive this typed parse and exact-byte comparison.
    let canonical = near_sdk::serde_json::to_string(&manifest)
        .unwrap_or_else(|_| env::panic_str(ERR_UNSUPPORTED_PROFILE));
    require!(
        canonical == args.verifier_manifest_json,
        ERR_UNSUPPORTED_PROFILE
    );
    require!(
        manifest.schema == "confidential-lending-artifacts/v1"
            && manifest.profile_hash == hex::encode(confidential_crypto::PROFILE_HASH)
            && manifest.network_id == args.network_id
            && manifest.core_account_id == env::current_account_id().as_str()
            && (manifest.setup == "development-single-party"
                || manifest.setup == "reviewed-ceremony"),
        ERR_UNSUPPORTED_PROFILE
    );
    require!(
        manifest.artifacts.len() == VERIFIER_FAMILIES.len() * 3 + EXTERNAL_ARTIFACTS.len(),
        ERR_UNSUPPORTED_PROFILE
    );

    for name in EXTERNAL_ARTIFACTS {
        let artifact = manifest
            .artifacts
            .get(name)
            .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
        validate_manifest_artifact(artifact, MAX_EXTERNAL_ARTIFACT_BYTES);
    }

    VERIFIER_FAMILIES
        .iter()
        .map(|(family, statement_kind)| {
            let vk_name = format!("{family}.vk");
            let prepared_name = format!("{family}.prepared-vk");
            let proving_name = format!("{family}.pk");
            let vk = manifest
                .artifacts
                .get(&vk_name)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            let prepared = manifest
                .artifacts
                .get(&prepared_name)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            let proving = manifest
                .artifacts
                .get(&proving_name)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            let vk_hash = validate_manifest_artifact(vk, 128 * 1024);
            let prepared_hash = validate_manifest_artifact(prepared, MAX_PREPARED_KEY_BYTES as u64);
            validate_manifest_artifact(proving, MAX_EXTERNAL_ARTIFACT_BYTES);
            let kind = statement_kind_for_manifest(*statement_kind)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            VerifierArtifactExpectation {
                statement_kind: *statement_kind,
                family: (*family).to_string(),
                verifying_key_sha256: vk_hash,
                verifying_key_bytes: vk.bytes as u32,
                prepared_key_sha256: prepared_hash,
                prepared_key_bytes: prepared.bytes as u32,
                // The context digest precedes the typed statement slots.
                public_input_count: (kind.slot_count() + 1) as u32,
            }
        })
        .collect()
}

struct NearSha256;

impl HashFunction for NearSha256 {
    fn sha256(bytes: &[u8]) -> authenticated_book::Hash {
        env::sha256_array(bytes)
    }
}

struct CoreBookStore<'a> {
    nodes: &'a mut LookupMap<Vec<u8>, [u8; 32]>,
    broker_id: u64,
}

impl NodeStore for CoreBookStore<'_> {
    fn get(&self, key: NodeKey) -> Option<authenticated_book::Hash> {
        self.nodes.get(&book_node_key(self.broker_id, key))
    }

    fn set(&mut self, key: NodeKey, value: authenticated_book::Hash) {
        self.nodes
            .insert(&book_node_key(self.broker_id, key), &value);
    }

    fn remove(&mut self, key: NodeKey) {
        self.nodes.remove(&book_node_key(self.broker_id, key));
    }
}

#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_self)]
#[allow(dead_code)]
trait CoreCallbacks {
    fn on_payout_result(&mut self, operation_id: U64, attempt: u32, result_hash: Vec<u8>) -> bool;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Core {
    pub asset: AssetProfile,
    pub verifier: VerifierConfig,
    pub owner: AccountId,
    pub asset_frozen: bool,
    pub vault_sequence: u64,
    pub broker_sequence: u64,
    pub loan_sequence: u64,
    pub proposal_sequence: u64,
    pub claim_sequence: u64,
    pub operation_sequence: u64,
    /// Monotonic enumeration of payout records.  `operation_id` is supplied
    /// by the claimant for replay protection and is deliberately not assumed
    /// to be dense; this index keeps public pagination bounded and complete.
    pub payout_sequence: u64,
    pub checkpoint_sequence: u64,
    pub vaults: UnorderedMap<u64, Vault>,
    pub brokers: UnorderedMap<u64, Broker>,
    pub loans: UnorderedMap<u64, Loan>,
    pub holders: LookupMap<AccountId, HolderBalance>,
    pub proposals: UnorderedMap<u64, Proposal>,
    pub claims: UnorderedMap<u64, PublicClaim>,
    pub receipts: LookupMap<String, DepositReceipt>,
    pub payouts: UnorderedMap<u64, PayoutOperation>,
    pub payout_index: UnorderedMap<u64, u64>,
    pub checkpoints: UnorderedMap<u64, Checkpoint>,
    pub vault_brokers: LookupMap<u64, Vec<u64>>,
    pub shares: LookupMap<Vec<u8>, u128>,
    pub loan_tombstones: LookupMap<u64, BookTombstone>,
    pub broker_tombstones: UnorderedSet<u64>,
    pub proposal_tombstones: UnorderedSet<u64>,
    pub payout_tombstones: UnorderedSet<u64>,
    pub share_tombstones: UnorderedSet<Vec<u8>>,
    pub public_claim_total: u128,
    pub payout_reserved_total: u128,
    pub confidential_outstanding: u128,
    pub custody_total: u128,
    pub storage_deposits: LookupMap<AccountId, u128>,
    pub authorization_keys: LookupMap<Vec<u8>, AuthorizationKey>,
    pub verifier_keys: LookupMap<u8, VerifierKeyRecord>,
    pub recovery_sequence: u64,
    pub recovery_records: UnorderedMap<u64, RecoveryRecord>,
    pub recovery_subject_index: LookupMap<Vec<u8>, u64>,
    pub recovery_subject_counts: LookupMap<String, u64>,
    /// Sparse authenticated-book nodes, keyed by `(broker,height,index)`.
    /// The fixed-depth book performs at most 65 bounded reads/writes per loan
    /// transition and never scans the loan collection.
    pub book_nodes: LookupMap<Vec<u8>, [u8; 32]>,
}

#[near_bindgen]
impl Core {
    /// Deploy with an immutable asset and pinned cryptographic profile.
    /// Empty verifier artifacts are rejected; no upgrade method exists.
    #[init]
    pub fn new(args: InitArgs) -> Self {
        require!(!args.network_id.is_empty(), ERR_INVALID_ENCODING);
        validate_public_key(&args.issuer_public_key);
        validate_public_key(&args.token_auditor_public_key);
        require!(
            args.crypto_profile_hash.as_slice() == confidential_crypto::PROFILE_HASH,
            ERR_UNSUPPORTED_PROFILE
        );
        // Verification keys are staged and validated with the bounded host
        // verifier below.  A legacy single-key initializer is rejected rather
        // than silently treating one circuit key as every statement kind.
        require!(args.verifier_key.is_empty(), ERR_UNSUPPORTED_PROFILE);
        require!(
            args.verifier_manifest_hash.len() == 32,
            ERR_UNSUPPORTED_PROFILE
        );
        let manifest_artifacts = parse_verifier_manifest(&args);
        require!(
            args.custody_cap.0 > 0 && args.custody_cap.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        let owner = env::predecessor_account_id();
        let now = now_seconds();
        Self {
            asset: AssetProfile {
                token_account: args.token_account,
                decimals: args.decimals,
                controller_account: args.controller_account,
                issuer_key: EncryptionKey {
                    key_id: args.issuer_key_id,
                    public_key: args.issuer_public_key,
                    registered_at: now,
                    authorization_epoch: 0,
                },
                token_auditor_key: EncryptionKey {
                    key_id: args.token_auditor_key_id,
                    public_key: args.token_auditor_public_key,
                    registered_at: now,
                    authorization_epoch: 0,
                },
                crypto_profile_hash: args.crypto_profile_hash.clone(),
                network_id: args.network_id,
                token_trust_policy: args.token_trust_policy,
                freeze_policy: args.freeze_policy,
                custody_cap: args.custody_cap.0,
            },
            verifier: VerifierConfig {
                profile_hash: args.crypto_profile_hash,
                manifest_hash: args.verifier_manifest_hash,
                manifest_artifacts,
                ready: false,
                activated: false,
                key_count: 0,
            },
            owner,
            asset_frozen: false,
            vault_sequence: 0,
            broker_sequence: 0,
            loan_sequence: 0,
            proposal_sequence: 0,
            claim_sequence: 0,
            operation_sequence: 0,
            payout_sequence: 0,
            checkpoint_sequence: 0,
            vaults: UnorderedMap::new(StorageKey::Vaults),
            brokers: UnorderedMap::new(StorageKey::Brokers),
            loans: UnorderedMap::new(StorageKey::Loans),
            holders: LookupMap::new(StorageKey::Holders),
            proposals: UnorderedMap::new(StorageKey::Proposals),
            claims: UnorderedMap::new(StorageKey::Claims),
            receipts: LookupMap::new(StorageKey::Receipts),
            payouts: UnorderedMap::new(StorageKey::Payouts),
            payout_index: UnorderedMap::new(StorageKey::PayoutIndex),
            checkpoints: UnorderedMap::new(StorageKey::Checkpoints),
            vault_brokers: LookupMap::new(StorageKey::VaultBrokers),
            shares: LookupMap::new(StorageKey::Shares),
            loan_tombstones: LookupMap::new(StorageKey::LoanTombstones),
            broker_tombstones: UnorderedSet::new(StorageKey::BrokerTombstones),
            proposal_tombstones: UnorderedSet::new(StorageKey::ProposalTombstones),
            payout_tombstones: UnorderedSet::new(StorageKey::PayoutTombstones),
            share_tombstones: UnorderedSet::new(StorageKey::ShareTombstones),
            public_claim_total: 0,
            payout_reserved_total: 0,
            confidential_outstanding: 0,
            custody_total: 0,
            storage_deposits: LookupMap::new(StorageKey::StorageDeposits),
            authorization_keys: LookupMap::new(StorageKey::AuthorizationKeys),
            verifier_keys: LookupMap::new(StorageKey::VerifierKeys),
            recovery_sequence: 0,
            recovery_records: UnorderedMap::new(StorageKey::RecoveryRecords),
            recovery_subject_index: LookupMap::new(StorageKey::RecoverySubjectIndex),
            recovery_subject_counts: LookupMap::new(StorageKey::RecoverySubjectCounts),
            book_nodes: LookupMap::new(StorageKey::BookNodes),
        }
    }

    pub fn get_asset_profile(&self) -> AssetProfileView {
        AssetProfileView {
            token_account: self.asset.token_account.clone(),
            decimals: self.asset.decimals,
            controller_account: self.asset.controller_account.clone(),
            issuer_key: self.asset.issuer_key.clone(),
            token_auditor_key: self.asset.token_auditor_key.clone(),
            crypto_profile_hash: self.asset.crypto_profile_hash.clone(),
            network_id: self.asset.network_id.clone(),
            token_trust_policy: self.asset.token_trust_policy.clone(),
            freeze_policy: self.asset.freeze_policy.clone(),
            custody_cap: U128(self.asset.custody_cap),
        }
    }

    pub fn get_verifier_config(&self) -> VerifierConfig {
        self.verifier.clone()
    }

    /// Validate and persist one immutable prepared key.  Uploading is split
    /// from activation because validating every circuit key in one deployment
    /// call exceeds NEAR's gas limit.  The key hash is derived from the
    /// canonical compressed verifying key embedded in the prepared artifact;
    /// callers cannot choose a hash that points at a different key.
    pub fn stage_verifier_key(&mut self, statement_kind: u8, prepared_key: Vec<u8>) -> Vec<u8> {
        require!(
            env::predecessor_account_id() == self.owner,
            ERR_UNAUTHORIZED
        );
        require!(!self.verifier.activated, ERR_REPLAY);
        require!(
            REQUIRED_VERIFIER_KEYS.contains(&statement_kind),
            ERR_INVALID_ENCODING
        );
        require!(
            !prepared_key.is_empty() && prepared_key.len() <= MAX_PREPARED_KEY_BYTES,
            ERR_INVALID_ENCODING
        );
        require!(
            self.verifier_keys.get(&statement_kind).is_none(),
            ERR_REPLAY
        );
        let expected = self
            .verifier
            .manifest_artifacts
            .iter()
            .find(|artifact| artifact.statement_kind == statement_kind)
            .cloned()
            .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
        require!(
            prepared_key.len() == expected.prepared_key_bytes as usize,
            ERR_UNSUPPORTED_PROFILE
        );
        require!(
            &Sha256::digest(&prepared_key)[..] == expected.prepared_key_sha256.as_slice(),
            ERR_UNSUPPORTED_PROFILE
        );
        let public_input_count = near_verifier::validate_prepared_key(&prepared_key)
            .unwrap_or_else(|_| env::panic_str(ERR_UNSUPPORTED_PROFILE));
        let hash = near_verifier::prepared_key_hash(&prepared_key)
            .unwrap_or_else(|_| env::panic_str(ERR_UNSUPPORTED_PROFILE));
        require!(
            hash.as_slice() == expected.verifying_key_sha256.as_slice(),
            ERR_UNSUPPORTED_PROFILE
        );
        require!(
            public_input_count == expected.public_input_count as usize,
            ERR_UNSUPPORTED_PROFILE
        );
        self.verifier_keys.insert(
            &statement_kind,
            &VerifierKeyRecord {
                statement_kind,
                prepared_key,
                verifying_key_hash: hash.to_vec(),
                public_input_count: public_input_count as u32,
            },
        );
        self.verifier.key_count = self
            .verifier
            .key_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.emit(
            "VerifierKeyStaged",
            json!({
                "statement_kind": statement_kind,
                "verifying_key_hash": hash.to_vec(),
                "public_input_count": public_input_count
            }),
        );
        hash.to_vec()
    }

    /// Freeze the complete pinned key set.  No financial or key-registration
    /// operation is accepted until this one-way activation succeeds.
    pub fn activate_verifier_keys(&mut self) {
        require!(
            env::predecessor_account_id() == self.owner,
            ERR_UNAUTHORIZED
        );
        require!(!self.verifier.activated, ERR_REPLAY);
        require!(
            self.verifier.manifest_artifacts.len() == REQUIRED_VERIFIER_KEYS.len()
                && self.verifier.key_count as usize == REQUIRED_VERIFIER_KEYS.len(),
            ERR_UNSUPPORTED_PROFILE
        );
        for kind in REQUIRED_VERIFIER_KEYS {
            let key = self
                .verifier_keys
                .get(&kind)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            let expected = self
                .verifier
                .manifest_artifacts
                .iter()
                .find(|artifact| artifact.statement_kind == kind)
                .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
            require!(
                key.verifying_key_hash == expected.verifying_key_sha256
                    && key.public_input_count == expected.public_input_count,
                ERR_UNSUPPORTED_PROFILE
            );
        }
        self.verifier.ready = true;
        self.verifier.activated = true;
        self.emit(
            "VerifierKeysActivated",
            json!({"key_count": self.verifier.key_count}),
        );
    }

    pub fn get_verifier_key(&self, statement_kind: u8) -> Option<VerifierKeyView> {
        self.verifier_keys
            .get(&statement_kind)
            .map(|key| VerifierKeyView {
                statement_kind: key.statement_kind,
                verifying_key_hash: key.verifying_key_hash,
                public_input_count: key.public_input_count,
            })
    }

    /// The immutable controller may apply the declared local freeze policy to
    /// one holder.  This does not rewrite ciphertexts or erase obligations.
    pub fn set_holder_frozen(&mut self, account_id: AccountId, frozen: bool) {
        require!(
            env::predecessor_account_id() == self.asset.controller_account,
            ERR_UNAUTHORIZED
        );
        let mut holder = self.holder_or_panic(&account_id);
        holder.frozen = frozen;
        self.holders.insert(&account_id, &holder);
        self.emit(
            "HolderFreezeChanged",
            json!({"account_id": account_id, "frozen": frozen}),
        );
    }

    pub fn set_asset_frozen(&mut self, frozen: bool) {
        require!(
            env::predecessor_account_id() == self.asset.controller_account,
            ERR_UNAUTHORIZED
        );
        self.asset_frozen = frozen;
        self.emit("AssetFreezeChanged", json!({"frozen": frozen}));
    }

    pub fn get_freeze_status(&self, account_id: Option<AccountId>) -> FreezeStatusView {
        FreezeStatusView {
            asset_frozen: self.asset_frozen,
            holder_frozen: account_id
                .and_then(|account| self.holders.get(&account))
                .map(|holder| holder.frozen)
                .unwrap_or(false),
        }
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> U128 {
        let account = account_id.unwrap_or_else(env::predecessor_account_id);
        require!(account == env::predecessor_account_id(), ERR_UNAUTHORIZED);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, ERR_STORAGE);
        let current = self.storage_deposits.get(&account).unwrap_or(0);
        let updated = current
            .checked_add(deposit)
            .unwrap_or_else(|| env::panic_str(ERR_STORAGE));
        self.storage_deposits.insert(&account, &updated);
        U128(updated)
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.storage_deposits.get(&account_id).unwrap_or(0))
    }

    pub fn register_holder(&mut self, args: RegisterHolderArgs) {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        require!(
            !args.public_key.is_empty() || !args.encryption_public_key.is_empty(),
            ERR_INVALID_ENCODING
        );
        if !args.public_key.is_empty() && !args.encryption_public_key.is_empty() {
            require!(
                args.public_key == args.encryption_public_key,
                ERR_INVALID_ENCODING
            );
        }
        let public_key = if args.public_key.is_empty() {
            args.encryption_public_key.clone()
        } else {
            args.public_key.clone()
        };
        validate_public_key(&public_key);
        let existing = self.holders.get(&owner);
        if let Some(existing) = existing.as_ref() {
            // A rotation must create a new immutable key identity.  Reusing
            // either component would overwrite the recovery boundary while
            // leaving historical ciphertexts attributable to the same wire
            // identity.
            require!(
                args.key_id != existing.encryption_key.key_id
                    && public_key != existing.encryption_key.public_key,
                ERR_INVALID_ENCODING
            );
        } else {
            require!(args.zero_proofs.is_empty(), ERR_INVALID_ENCODING);
        }
        require!(!args.proof_of_possession.proof.is_empty(), ERR_BAD_PROOF);
        let old_epoch = existing
            .as_ref()
            .map(|h| h.authorization_epoch)
            .unwrap_or(0);
        let existing_open_loan_count = existing.as_ref().map(|h| h.open_loan_count).unwrap_or(0);
        require!(existing_open_loan_count == 0, ERR_HAS_OBLIGATIONS);
        let key = EncryptionKey {
            key_id: args.key_id,
            public_key,
            registered_at: now_seconds(),
            authorization_epoch: old_epoch
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE)),
        };
        if let Some(existing) = existing.as_ref() {
            require!(args.zero_proofs.len() == 1, ERR_HAS_OBLIGATIONS);
            let zero_subject = owner.to_string();
            // The spending and inbox ciphertexts share the holder's current
            // public key.  Their homomorphic sum is enough: the ledger
            // invariant keeps every balance non-negative and mirrors the same
            // amount, so a proven sum of zero implies all four balances are
            // zero without asking the holder for issuer/auditor secrets.
            let combined =
                combine_ciphertexts(&existing.spending_ciphertext, &existing.inbox_ciphertext);
            let context = self.crypto_context_with_subject(
                "holder-zero-total",
                0,
                0,
                0,
                0,
                [existing.spending_version, 0, 0, 0, 0, 0, 0, 0],
                [existing.authorization_epoch, 0, 0, 0],
                0,
                &zero_subject,
            );
            self.verify_zero_balance_statement(
                &args.zero_proofs[0],
                &context,
                &existing.encryption_key.public_key,
                &combined,
                existing.spending_version,
            );
        }
        let context = self.crypto_context(
            "register-holder",
            0,
            0,
            0,
            0,
            [key.key_id, 0, 0, 0, 0, 0, 0, 0],
            [key.authorization_epoch, 0, 0, 0],
            0,
        );
        let statement = self.verify_typed_statement(
            &args.proof_of_possession,
            StatementKind::KeyPossession,
            &context,
        );
        match statement {
            Statement::KeyPossession(KeyPossessionStatement { public_key, .. }) => {
                require!(
                    crypto_adapter::parse_public_key(&key.public_key)
                        .map(|expected| expected == public_key)
                        .unwrap_or(false),
                    ERR_BAD_PROOF
                );
            }
            _ => env::panic_str(ERR_BAD_PROOF),
        }
        let key_public = key.public_key.clone();
        let key_id = key.key_id;
        let key_epoch = key.authorization_epoch;
        let recovery_start_sequence = existing
            .as_ref()
            .map(|_| {
                self.recovery_subject_counts
                    .get(&format!("holder:{owner}"))
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        let frozen = existing
            .as_ref()
            .map(|holder| holder.frozen)
            .unwrap_or(false);
        self.holders.insert(
            &owner,
            &HolderBalance {
                owner: owner.clone(),
                asset_id: self.asset.token_account.clone(),
                encryption_key: key,
                spending_ciphertext: self.canonical_zero_for(
                    &key_public,
                    &format!("holder:{owner}:spending"),
                    key_id,
                    key_epoch,
                ),
                inbox_ciphertext: self.canonical_zero_for(
                    &key_public,
                    &format!("holder:{owner}:inbox"),
                    key_id,
                    key_epoch,
                ),
                issuer_balance_ciphertext: self.canonical_zero_for(
                    &self.asset.issuer_key.public_key,
                    &format!("holder:{owner}:issuer"),
                    self.asset.issuer_key.key_id,
                    self.asset.issuer_key.authorization_epoch,
                ),
                auditor_balance_ciphertext: self.canonical_zero_for(
                    &self.asset.token_auditor_key.public_key,
                    &format!("holder:{owner}:auditor"),
                    self.asset.token_auditor_key.key_id,
                    self.asset.token_auditor_key.authorization_epoch,
                ),
                spending_version: 0,
                authorization_epoch: old_epoch
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE)),
                open_loan_count: 0,
                recovery_start_sequence,
                frozen,
            },
        );
        self.emit(
            "HolderRegistered",
            json!({"account_id": owner, "authorization_epoch": (old_epoch + 1).to_string()}),
        );
        self.charge_storage(&owner, storage_before);
    }

    pub fn register_authorization_key(&mut self, args: RegisterAuthorizationKeyArgs) {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        require!(
            !args.public_key.is_empty() && args.public_key.len() == 32,
            ERR_INVALID_ENCODING
        );
        require!(args.public_key.len() == 32, ERR_INVALID_ENCODING);
        let holder = self.holder_or_panic(&owner);
        let epoch = holder
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let key = AuthorizationKey {
            owner: owner.clone(),
            key_id: args.key_id,
            public_key: args.public_key,
            epoch,
            nonce: 0,
            revoked: false,
        };
        let mut updated_holder = holder;
        updated_holder.authorization_epoch = epoch;
        self.holders.insert(&owner, &updated_holder);
        self.authorization_keys
            .insert(&authorization_key(&owner, args.key_id), &key);
        self.emit(
            "AuthorizationKeyRegistered",
            json!({"account_id": owner, "key_id": args.key_id.to_string(), "epoch": epoch.to_string()}),
        );
        self.charge_storage(&owner, storage_before);
    }

    pub fn revoke_authorization_key(&mut self, key_id: U64) {
        let owner = env::predecessor_account_id();
        let key_id = key_id.0;
        let key_id_bytes = authorization_key(&owner, key_id);
        let mut key = self
            .authorization_keys
            .get(&key_id_bytes)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND));
        require!(key.owner == owner && !key.revoked, ERR_REPLAY);
        let mut holder = self.holder_or_panic(&owner);
        let epoch = holder
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        key.revoked = true;
        key.epoch = epoch;
        holder.authorization_epoch = epoch;
        self.authorization_keys.insert(&key_id_bytes, &key);
        self.holders.insert(&owner, &holder);
        self.emit(
            "AuthorizationKeyRevoked",
            json!({"account_id": owner, "key_id": key_id.to_string(), "epoch": epoch.to_string()}),
        );
    }

    pub fn get_authorization_key(&self, owner: AccountId, key_id: U64) -> Option<AuthorizationKey> {
        self.authorization_keys
            .get(&authorization_key(&owner, key_id.0))
    }

    pub fn create_vault(&mut self, args: CreateVaultArgs) -> U64 {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        require!(args.share_scale <= 18, ERR_INVALID_AMOUNT);
        require!(
            args.checkpoint_policy.epoch_seconds >= MIN_CHECKPOINT_EPOCH
                && args.checkpoint_policy.epoch_seconds <= MAX_CHECKPOINT_EPOCH,
            ERR_INVALID_AMOUNT
        );
        if let VaultKind::ClosedEnded = args.kind {
            let phases = args
                .phase_times
                .as_ref()
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_ENCODING));
            require!(
                phases.subscription_start <= phases.investment_start,
                ERR_INVALID_ENCODING
            );
            require!(
                phases.investment_start <= phases.redemption_start,
                ERR_INVALID_ENCODING
            );
        }
        let id = self.next_vault_id();
        let vault = Vault {
            vault_id: id,
            owner: owner.clone(),
            asset_id: self.asset.token_account.clone(),
            assets_total: 0,
            assets_available: 0,
            loss_unrealized: 0,
            shares_total: 0,
            assets_maximum: args.assets_maximum.0,
            kind: args.kind,
            phase_times: args.phase_times,
            share_scale: args.share_scale,
            shares_transferable: args.shares_transferable,
            checkpoint_policy: args.checkpoint_policy,
            accounting_pending: false,
            pending_broker_count: 0,
            accounting_version: 0,
            risk_version: 0,
            reconciled_risk_version: 0,
        };
        self.vaults.insert(&id, &vault);
        self.vault_brokers.insert(&id, &Vec::new());
        self.emit(
            "VaultCreated",
            json!({"vault_id": id.to_string(), "owner": owner, "asset_id": self.asset.token_account}),
        );
        self.charge_storage(&owner, storage_before);
        U64(id)
    }

    pub fn create_broker(&mut self, args: CreateBrokerArgs) -> U64 {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let vault = self.vault_or_panic(args.vault_id);
        require!(vault.owner == caller, ERR_UNAUTHORIZED);
        require!(!args.encryption_public_key.is_empty(), ERR_INVALID_ENCODING);
        require!(!args.proof_of_possession.proof.is_empty(), ERR_BAD_PROOF);
        validate_public_key(&args.encryption_public_key);
        let id = self.next_broker_id();
        let key = EncryptionKey {
            key_id: args.encryption_key_id,
            public_key: args.encryption_public_key,
            registered_at: now_seconds(),
            authorization_epoch: 0,
        };
        let key_public = key.public_key.clone();
        let key_id = key.key_id;
        let key_epoch = key.authorization_epoch;
        let context = self.crypto_context(
            "create-broker",
            args.vault_id,
            id,
            0,
            0,
            [key.key_id, 0, 0, 0, 0, 0, 0, 0],
            [key.authorization_epoch, 0, 0, 0],
            0,
        );
        let statement = self.verify_typed_statement(
            &args.proof_of_possession,
            StatementKind::KeyPossession,
            &context,
        );
        match statement {
            Statement::KeyPossession(KeyPossessionStatement { public_key, .. }) => {
                require!(
                    crypto_adapter::parse_public_key(&key.public_key)
                        .map(|expected| expected == public_key)
                        .unwrap_or(false),
                    ERR_BAD_PROOF
                );
            }
            _ => env::panic_str(ERR_BAD_PROOF),
        }
        let broker = Broker {
            broker_id: id,
            owner: caller.clone(),
            vault_id: args.vault_id,
            encryption_key: key,
            authorization_epoch: 0,
            debt_total: 0,
            debt_maximum: args.debt_maximum.0,
            loan_sequence: 0,
            active_loan_count: 0,
            impaired_loan_count: 0,
            spending_ciphertext: self.canonical_zero_for(
                &key_public,
                &format!("broker:{id}:spending"),
                key_id,
                key_epoch,
            ),
            inbox_ciphertext: self.canonical_zero_for(
                &key_public,
                &format!("broker:{id}:inbox"),
                key_id,
                key_epoch,
            ),
            issuer_balance_ciphertext: self.canonical_zero_for(
                &self.asset.issuer_key.public_key,
                &format!("broker:{id}:issuer"),
                self.asset.issuer_key.key_id,
                self.asset.issuer_key.authorization_epoch,
            ),
            auditor_balance_ciphertext: self.canonical_zero_for(
                &self.asset.token_auditor_key.public_key,
                &format!("broker:{id}:auditor"),
                self.asset.token_auditor_key.key_id,
                self.asset.token_auditor_key.authorization_epoch,
            ),
            spending_commitment: crypto_adapter::encode(
                &crypto_adapter::zero_commitment()
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            )
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            inbox_commitment: crypto_adapter::encode(
                &crypto_adapter::zero_commitment()
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            )
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            spending_version: 0,
            loan_book_root: Book::<NearSha256>::new(book_domain(self, id))
                .empty_root()
                .to_vec(),
            book_version: 0,
            active_principal_ciphertext: self.canonical_zero_for(
                &key_public,
                &format!("broker:{id}:active-principal"),
                key_id,
                key_epoch,
            ),
            impaired_principal_ciphertext: self.canonical_zero_for(
                &key_public,
                &format!("broker:{id}:impaired-principal"),
                key_id,
                key_epoch,
            ),
            active_principal_commitment: crypto_adapter::encode(
                &crypto_adapter::zero_commitment()
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            )
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            impaired_principal_commitment: crypto_adapter::encode(
                &crypto_adapter::zero_commitment()
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            )
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            impairment_provision: 0,
            cumulative_draws: 0,
            cumulative_settlements: 0,
            cumulative_yield: 0,
            cumulative_realized_losses: 0,
            accounting_version: 0,
            risk_version: 0,
            reconciled_risk_version: 0,
            accounting_pending: false,
            accounting_pending_since: 0,
            reconciliation_checkpoint_id: None,
            delegates: Vec::new(),
            last_settlement_at: 0,
            tombstoned: false,
        };
        self.brokers.insert(&id, &broker);
        let mut ids = self.vault_brokers.get(&args.vault_id).unwrap_or_default();
        require!(ids.len() < MAX_BROKERS_PER_VAULT, ERR_DEBT_LIMIT);
        ids.push(id);
        self.vault_brokers.insert(&args.vault_id, &ids);
        self.emit(
            "BrokerCreated",
            json!({"broker_id": id.to_string(), "vault_id": args.vault_id.to_string()}),
        );
        self.charge_storage(&caller, storage_before);
        U64(id)
    }

    pub fn create_proposal(&mut self, args: CreateProposalArgs) -> U64 {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let broker = self.broker_or_panic(args.broker_id);
        require!(broker.vault_id == args.vault_id, ERR_WRONG_ASSET);
        require!(
            caller == broker.owner || caller == args.borrower,
            ERR_UNAUTHORIZED
        );
        let borrower_holder = self.holder_or_panic(&args.borrower);
        require!(
            borrower_holder.encryption_key.key_id == args.borrower_key_id,
            ERR_STALE_STATE
        );
        require!(
            borrower_holder.authorization_epoch == args.borrower_authorization_epoch,
            ERR_STALE_STATE
        );
        require!(
            broker.encryption_key.key_id == args.broker_key_id,
            ERR_STALE_STATE
        );
        require!(
            args.payment_count > 0 && args.payment_count <= MAX_PAYMENT_COUNT,
            ERR_INVALID_AMOUNT
        );
        require!(
            args.payment_interval > 0 && args.payment_interval <= MAX_INTERVAL_SECONDS,
            ERR_INVALID_AMOUNT
        );
        require!(args.expiry > now_seconds(), ERR_EXPIRED);
        validate_ciphertext_set(&args.principal_ciphertexts, 5);
        validate_ciphertext_set(&args.initial_owed_ciphertexts, 3);
        validate_ciphertext_set(&args.periodic_payment_ciphertexts, 3);
        require!(
            !args.principal_commitment.is_empty()
                && !args.owed_commitment.is_empty()
                && !args.payment_commitment.is_empty(),
            ERR_INVALID_ENCODING
        );
        validate_commitment(&args.principal_commitment);
        validate_commitment(&args.owed_commitment);
        validate_commitment(&args.payment_commitment);
        validate_public_key(&args.loan_auditor_public_key);
        validate_authorization_nonce(
            self,
            &broker.owner,
            args.broker_authorization_key_id,
            args.broker_authorization_epoch,
            args.broker_authorization_nonce,
        );
        if args.broker_authorization_key_id.is_none() {
            require!(args.broker_authorization_epoch == 0, ERR_STALE_STATE);
        }
        validate_authorization_nonce(
            self,
            &args.borrower,
            args.borrower_authorization_key_id,
            args.borrower_authorization_epoch,
            args.borrower_authorization_nonce,
        );
        require!(
            args.grace_period <= MAX_INTERVAL_SECONDS,
            ERR_INVALID_AMOUNT
        );
        let id = self.next_proposal_id();
        let agreement_digest = hash_bytes(&AgreementTerms {
            domain: b"agreement-v1".to_vec(),
            proposal_id: id,
            asset: self.asset.token_account.clone(),
            borrower: args.borrower.clone(),
            broker_id: args.broker_id,
            vault_id: args.vault_id,
            borrower_key_id: args.borrower_key_id,
            broker_key_id: args.broker_key_id,
            loan_auditor_key_id: args.loan_auditor_key_id,
            payment_count: args.payment_count,
            payment_interval: args.payment_interval,
            grace_period: args.grace_period,
            expiry: args.expiry,
            principal_ciphertexts: args.principal_ciphertexts.clone(),
            initial_owed_ciphertexts: args.initial_owed_ciphertexts.clone(),
            periodic_payment_ciphertexts: args.periodic_payment_ciphertexts.clone(),
            principal_commitment: args.principal_commitment.clone(),
            owed_commitment: args.owed_commitment.clone(),
            payment_commitment: args.payment_commitment.clone(),
            broker_authorization_epoch: args.broker_authorization_epoch,
            borrower_authorization_epoch: args.borrower_authorization_epoch,
            broker_authorization_nonce: args.broker_authorization_nonce,
            borrower_authorization_nonce: args.borrower_authorization_nonce,
            loan_auditor_public_key: args.loan_auditor_public_key.clone(),
        });
        if !args.agreement_digest.is_empty() {
            require!(args.agreement_digest == agreement_digest, ERR_BAD_PROOF);
        }
        // A direct call authenticates only the party that sent it.  Bytes for
        // the other party may never be injected by the caller creating the
        // proposal; a relayed signature must verify against a registered
        // authorization key and the exact canonical agreement digest.
        require!(
            caller == broker.owner || args.broker_signature.is_empty(),
            ERR_UNAUTHORIZED
        );
        require!(
            caller == args.borrower || args.borrower_signature.is_empty(),
            ERR_UNAUTHORIZED
        );
        if !args.broker_signature.is_empty() {
            require!(
                verify_authorization_signature(
                    self,
                    &broker.owner,
                    args.broker_authorization_key_id,
                    args.broker_authorization_epoch,
                    args.broker_authorization_nonce,
                    &agreement_digest,
                    &args.broker_signature,
                ),
                ERR_UNAUTHORIZED
            );
        }
        if !args.borrower_signature.is_empty() {
            require!(
                verify_authorization_signature(
                    self,
                    &args.borrower,
                    args.borrower_authorization_key_id,
                    args.borrower_authorization_epoch,
                    args.borrower_authorization_nonce,
                    &agreement_digest,
                    &args.borrower_signature,
                ),
                ERR_UNAUTHORIZED
            );
        }
        let proposal = Proposal {
            proposal_id: id,
            borrower: args.borrower.clone(),
            broker_id: args.broker_id,
            vault_id: args.vault_id,
            borrower_key_id: args.borrower_key_id,
            broker_key_id: args.broker_key_id,
            loan_auditor_key_id: args.loan_auditor_key_id,
            loan_auditor_public_key: args.loan_auditor_public_key,
            payment_count: args.payment_count,
            payment_interval: args.payment_interval,
            grace_period: args.grace_period,
            expiry: args.expiry,
            principal_ciphertexts: args.principal_ciphertexts,
            initial_owed_ciphertexts: args.initial_owed_ciphertexts,
            periodic_payment_ciphertexts: args.periodic_payment_ciphertexts,
            principal_commitment: args.principal_commitment,
            owed_commitment: args.owed_commitment,
            payment_commitment: args.payment_commitment,
            agreement_digest,
            broker_signature: args.broker_signature,
            borrower_signature: args.borrower_signature,
            broker_authorization_epoch: args.broker_authorization_epoch,
            borrower_authorization_epoch: args.borrower_authorization_epoch,
            broker_authorization_nonce: args.broker_authorization_nonce,
            borrower_authorization_nonce: args.borrower_authorization_nonce,
            broker_authorization_key_id: args.broker_authorization_key_id,
            borrower_authorization_key_id: args.borrower_authorization_key_id,
            broker_direct_authorized: caller == broker.owner,
            borrower_direct_authorized: caller == args.borrower,
            consumed: false,
            revoked: false,
        };
        self.proposals.insert(&id, &proposal);
        self.emit("ProposalCreated", json!({"proposal_id": id.to_string(), "broker_id": proposal.broker_id.to_string(), "borrower": proposal.borrower}));
        self.charge_storage(&caller, storage_before);
        U64(id)
    }

    pub fn sign_proposal(&mut self, proposal_id: U64, signature: Vec<u8>) {
        let caller = env::predecessor_account_id();
        let proposal_id = proposal_id.0;
        let mut proposal = self.proposal_or_panic(proposal_id);
        let broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        require!(!proposal.consumed && !proposal.revoked, ERR_REPLAY);
        if caller == proposal.borrower {
            let holder = self.holder_or_panic(&proposal.borrower);
            require!(
                holder.authorization_epoch == proposal.borrower_authorization_epoch,
                ERR_STALE_STATE
            );
            if signature.is_empty() {
                proposal.borrower_direct_authorized = true;
            } else {
                require!(
                    verify_authorization_signature(
                        self,
                        &proposal.borrower,
                        proposal.borrower_authorization_key_id,
                        proposal.borrower_authorization_epoch,
                        proposal.borrower_authorization_nonce,
                        &proposal.agreement_digest,
                        &signature,
                    ),
                    ERR_UNAUTHORIZED
                );
                proposal.borrower_signature = signature;
            }
        } else {
            if signature.is_empty() {
                proposal.broker_direct_authorized = true;
            } else {
                require!(
                    verify_authorization_signature(
                        self,
                        &broker.owner,
                        proposal.broker_authorization_key_id,
                        proposal.broker_authorization_epoch,
                        proposal.broker_authorization_nonce,
                        &proposal.agreement_digest,
                        &signature,
                    ),
                    ERR_UNAUTHORIZED
                );
                proposal.broker_signature = signature;
            }
        }
        self.proposals.insert(&proposal_id, &proposal);
    }

    pub fn revoke_proposal(&mut self, proposal_id: U64) {
        let caller = env::predecessor_account_id();
        let proposal_id = proposal_id.0;
        let mut proposal = self.proposal_or_panic(proposal_id);
        let broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        require!(!proposal.consumed, ERR_REPLAY);
        require!(!proposal.revoked, ERR_REPLAY);
        proposal.revoked = true;
        self.proposals.insert(&proposal_id, &proposal);
        self.proposal_tombstones.insert(&proposal_id);
    }

    pub fn deposit_to_vault(&mut self, args: DepositToVaultArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        require!(now_seconds() <= args.expiry, ERR_EXPIRED);
        let mut vault = self.vault_or_panic(args.vault_id);
        self.ensure_vault_phase(&vault, false, true);
        require!(!vault.accounting_pending, ERR_ACCOUNTING_PENDING);
        let claim = self.claim_or_panic(args.claim_id);
        require!(
            claim.owner == caller && claim.reserved_by.is_none(),
            ERR_UNAUTHORIZED
        );
        require!(
            claim.amount == args.amount.0 && claim.amount > 0,
            ERR_INVALID_AMOUNT
        );
        let nav = vault
            .assets_total
            .checked_sub(vault.loss_unrealized)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        let minted = if vault.shares_total == 0 {
            require!(vault.assets_total == 0 && nav == 0, ERR_INVALID_AMOUNT);
            let scale = 10u128
                .checked_pow(u32::from(vault.share_scale))
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            args.amount
                .0
                .checked_mul(scale)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT))
        } else {
            require!(nav > 0, ERR_INVALID_AMOUNT);
            mul_div_floor(args.amount.0, vault.shares_total, nav)
        };
        require!(minted > 0, ERR_SLIPPAGE);
        require!(minted >= args.min_shares_out.0, ERR_SLIPPAGE);
        let new_total = vault
            .assets_total
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        if vault.assets_maximum != 0 {
            require!(new_total <= vault.assets_maximum, ERR_DEBT_LIMIT);
        }
        vault.assets_total = new_total;
        vault.assets_available = vault
            .assets_available
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.shares_total = vault
            .shares_total
            .checked_add(minted)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let key = share_key(args.vault_id, &caller);
        let existing = self.shares.get(&key).unwrap_or(0);
        self.shares.insert(
            &key,
            &existing
                .checked_add(minted)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT)),
        );
        self.claims.remove(&args.claim_id);
        self.public_claim_total = self
            .public_claim_total
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.vaults.insert(&args.vault_id, &vault);
        self.emit(
            "SharesMinted",
            json!({
                "vault_id": args.vault_id.to_string(),
                "owner": caller,
                "shares": minted.to_string(),
                "accounting_version": vault.accounting_version.to_string()
            }),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn redeem_shares(&mut self, args: RedeemSharesArgs) -> U64 {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        require!(now_seconds() <= args.expiry, ERR_EXPIRED);
        let mut vault = self.vault_or_panic(args.vault_id);
        self.ensure_vault_phase(&vault, true, false);
        require!(!vault.accounting_pending, ERR_ACCOUNTING_PENDING);
        require!(
            args.shares.0 > 0 && args.shares.0 <= vault.shares_total,
            ERR_INVALID_AMOUNT
        );
        let key = share_key(args.vault_id, &caller);
        let owned = self.shares.get(&key).unwrap_or(0);
        require!(owned >= args.shares.0, ERR_INSUFFICIENT_PUBLIC_FUNDS);
        let nav = vault
            .assets_total
            .checked_sub(vault.loss_unrealized)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        let assets_out = if nav == 0 {
            require!(args.burn_worthless, ERR_INVALID_AMOUNT);
            require!(args.min_assets_out.0 == 0, ERR_SLIPPAGE);
            0
        } else if args.sole_shareholder_waiver && owned == vault.shares_total {
            mul_div_floor(args.shares.0, vault.assets_total, vault.shares_total)
        } else {
            mul_div_floor(args.shares.0, nav, vault.shares_total)
        };
        // A non-worthless redemption must make economic progress.  Allowing
        // floor rounding to burn shares for zero assets strands value and
        // violates the explicit zero-result rule; only the NAV-zero
        // worthless-share path above may return zero.
        if nav > 0 {
            require!(assets_out > 0, ERR_SLIPPAGE);
        }
        require!(
            assets_out <= vault.assets_available,
            ERR_INSUFFICIENT_PUBLIC_FUNDS
        );
        require!(assets_out >= args.min_assets_out.0, ERR_SLIPPAGE);
        if args.shares.0 == vault.shares_total {
            let broker_ids = self.vault_brokers.get(&args.vault_id).unwrap_or_default();
            let mut live_broker_count = 0usize;
            for broker_id in broker_ids {
                let Some(broker) = self.brokers.get(&broker_id) else {
                    // A deleted broker has already passed its terminal zero
                    // assertion and remains represented by a tombstone.
                    require!(self.broker_tombstones.contains(&broker_id), ERR_NOT_FOUND);
                    continue;
                };
                live_broker_count = live_broker_count
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                require!(broker.debt_total == 0, ERR_HAS_OBLIGATIONS);
                require!(broker.active_loan_count == 0, ERR_HAS_OBLIGATIONS);
                require!(broker.impaired_loan_count == 0, ERR_HAS_OBLIGATIONS);
                require!(broker.impairment_provision == 0, ERR_HAS_OBLIGATIONS);
                require!(!broker.accounting_pending, ERR_ACCOUNTING_PENDING);
                require!(
                    broker.reconciliation_checkpoint_id.is_none(),
                    ERR_ACCOUNTING_PENDING
                );
                let zero_proof = args
                    .broker_zero_proofs
                    .iter()
                    .find(|proof| proof.broker_id == broker_id)
                    .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF));
                if let Some(proof) = zero_proof.combined_proof.as_ref() {
                    let combined = combine_ciphertexts(
                        &combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext),
                        &combine_ciphertexts(
                            &broker.active_principal_ciphertext,
                            &broker.impaired_principal_ciphertext,
                        ),
                    );
                    let context = self.crypto_context_with_subject(
                        "broker-zero-total",
                        broker.vault_id,
                        broker.broker_id,
                        0,
                        0,
                        [
                            broker.spending_version,
                            broker.accounting_version,
                            broker.book_version,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                        [broker.encryption_key.authorization_epoch, 0, 0, 0],
                        0,
                        "total",
                    );
                    self.verify_zero_balance_statement(
                        proof,
                        &context,
                        &broker.encryption_key.public_key,
                        &combined,
                        broker.spending_version,
                    );
                } else {
                    let spending_context = self.crypto_context_with_subject(
                        "broker-zero-spending",
                        broker.vault_id,
                        broker.broker_id,
                        0,
                        0,
                        [
                            broker.spending_version,
                            broker.accounting_version,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                        [broker.encryption_key.authorization_epoch, 0, 0, 0],
                        0,
                        "spending",
                    );
                    self.verify_zero_balance_statement(
                        zero_proof
                            .spending_proof
                            .as_ref()
                            .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                        &spending_context,
                        &broker.encryption_key.public_key,
                        &broker.spending_ciphertext,
                        broker.spending_version,
                    );
                    let inbox_context = self.crypto_context_with_subject(
                        "broker-zero-inbox",
                        broker.vault_id,
                        broker.broker_id,
                        0,
                        0,
                        [
                            broker.spending_version,
                            broker.accounting_version,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                        [broker.encryption_key.authorization_epoch, 0, 0, 0],
                        0,
                        "inbox",
                    );
                    self.verify_zero_balance_statement(
                        zero_proof
                            .inbox_proof
                            .as_ref()
                            .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                        &inbox_context,
                        &broker.encryption_key.public_key,
                        &broker.inbox_ciphertext,
                        broker.spending_version,
                    );
                    let active_context = self.crypto_context_with_subject(
                        "broker-zero-active-principal",
                        broker.vault_id,
                        broker.broker_id,
                        0,
                        0,
                        [
                            broker.spending_version,
                            broker.accounting_version,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                        [broker.encryption_key.authorization_epoch, 0, 0, 0],
                        0,
                        "active-principal",
                    );
                    let impaired_context = self.crypto_context_with_subject(
                        "broker-zero-impaired-principal",
                        broker.vault_id,
                        broker.broker_id,
                        0,
                        0,
                        [
                            broker.spending_version,
                            broker.accounting_version,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                        [broker.encryption_key.authorization_epoch, 0, 0, 0],
                        0,
                        "impaired-principal",
                    );
                    self.verify_zero_balance_statement(
                        zero_proof
                            .active_principal_proof
                            .as_ref()
                            .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                        &active_context,
                        &broker.encryption_key.public_key,
                        &broker.active_principal_ciphertext,
                        broker.spending_version,
                    );
                    self.verify_zero_balance_statement(
                        zero_proof
                            .impaired_principal_proof
                            .as_ref()
                            .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                        &impaired_context,
                        &broker.encryption_key.public_key,
                        &broker.impaired_principal_ciphertext,
                        broker.spending_version,
                    );
                }
            }
            require!(
                args.broker_zero_proofs.len() == live_broker_count,
                ERR_BAD_PROOF
            );
            require!(
                if assets_out == 0 {
                    vault.assets_total == 0
                        && vault.assets_available == 0
                        && vault.loss_unrealized == 0
                } else {
                    vault.assets_total == vault.assets_available
                },
                ERR_HAS_OBLIGATIONS
            );
            require!(
                vault.loss_unrealized == 0 && !vault.accounting_pending,
                ERR_HAS_OBLIGATIONS
            );
        }
        vault.assets_total = vault
            .assets_total
            .checked_sub(assets_out)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.assets_available = vault
            .assets_available
            .checked_sub(assets_out)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.shares_total = vault
            .shares_total
            .checked_sub(args.shares.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.shares.insert(
            &key,
            &owned
                .checked_sub(args.shares.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT)),
        );
        let claim_id = if assets_out > 0 {
            let claim_id = self.next_claim_id();
            self.claims.insert(
                &claim_id,
                &PublicClaim {
                    claim_id,
                    owner: caller.clone(),
                    amount: assets_out,
                    created_at: now_seconds(),
                    reserved_by: None,
                },
            );
            self.public_claim_total = self
                .public_claim_total
                .checked_add(assets_out)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            claim_id
        } else {
            0
        };
        self.vaults.insert(&args.vault_id, &vault);
        self.emit(
            "SharesRedeemed",
            json!({
                "vault_id": args.vault_id.to_string(),
                "owner": caller,
                "shares": args.shares.0.to_string(),
                "assets_out": assets_out.to_string(),
                "claim_id": claim_id.to_string(),
                "accounting_version": vault.accounting_version.to_string()
            }),
        );
        self.charge_storage(&caller, storage_before);
        U64(claim_id)
    }

    pub fn transfer_shares(&mut self, vault_id: U64, receiver: AccountId, shares: U128) {
        let sender = env::predecessor_account_id();
        let vault_id = vault_id.0;
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        require!(shares.0 > 0, ERR_INVALID_AMOUNT);
        require!(sender != receiver, ERR_INVALID_AMOUNT);
        let vault = self.vault_or_panic(vault_id);
        require!(vault.shares_transferable, ERR_UNAUTHORIZED);
        let from_key = share_key(vault_id, &sender);
        let to_key = share_key(vault_id, &receiver);
        let from = self.shares.get(&from_key).unwrap_or(0);
        require!(from >= shares.0, ERR_INSUFFICIENT_PUBLIC_FUNDS);
        let to = self.shares.get(&to_key).unwrap_or(0);
        self.shares.insert(
            &from_key,
            &from
                .checked_sub(shares.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT)),
        );
        self.shares.insert(
            &to_key,
            &to.checked_add(shares.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT)),
        );
        self.emit("SharesTransferred", json!({"vault_id": vault_id.to_string(), "sender": sender, "receiver": receiver, "shares": shares.0.to_string()}));
        self.charge_storage(&sender, storage_before);
    }

    pub fn get_share_balance(&self, vault_id: U64, owner: AccountId) -> U128 {
        U128(self.shares.get(&share_key(vault_id.0, &owner)).unwrap_or(0))
    }

    pub fn shield(&mut self, args: ShieldArgs) {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut holder = self.holder_or_panic(&owner);
        require!(!holder.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            args.amount.0 > 0 && args.amount.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        let claim = self.claim_or_panic(args.claim_id);
        require!(
            claim.owner == owner && claim.reserved_by.is_none(),
            ERR_UNAUTHORIZED
        );
        require!(claim.amount == args.amount.0, ERR_INVALID_AMOUNT);
        for ciphertext in [
            &args.spending_ciphertext,
            &args.issuer_ciphertext,
            &args.auditor_ciphertext,
        ] {
            if !ciphertext.is_empty() {
                validate_ciphertext(ciphertext);
            }
        }
        let context = self.crypto_context(
            "shield",
            0,
            0,
            0,
            args.claim_id,
            [holder.spending_version, args.claim_id, 0, 0, 0, 0, 0, 0],
            [holder.authorization_epoch, 0, 0, 0],
            0,
        );
        let conversion = self.verify_public_conversion_statement(
            &args.proof,
            &context,
            &holder.encryption_key.public_key,
            &holder.inbox_ciphertext,
            None,
            args.amount.0,
            false,
            holder.spending_version,
            [
                &holder.encryption_key.public_key,
                &self.asset.issuer_key.public_key,
                &self.asset.token_auditor_key.public_key,
            ],
            [
                (!args.spending_ciphertext.is_empty())
                    .then_some(args.spending_ciphertext.as_slice()),
                (!args.issuer_ciphertext.is_empty()).then_some(args.issuer_ciphertext.as_slice()),
                (!args.auditor_ciphertext.is_empty()).then_some(args.auditor_ciphertext.as_slice()),
            ],
        );
        let new_inbox = combine_ciphertexts(
            &holder.inbox_ciphertext,
            &crypto_adapter::encode(&conversion.views[0].ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
        );
        require!(
            conversion.spending_after
                == crypto_adapter::parse_ciphertext(&new_inbox)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ERR_BAD_PROOF
        );
        self.record_recovery(
            "shield",
            &args.proof.statement,
            &[format!("holder:{owner}")],
            &[
                holder.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[holder.spending_version],
        );
        holder.inbox_ciphertext = new_inbox;
        holder.issuer_balance_ciphertext = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&holder.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[1].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        holder.auditor_balance_ciphertext = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&holder.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        self.holders.insert(&owner, &holder);
        self.claims.remove(&args.claim_id);
        self.public_claim_total = self
            .public_claim_total
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.emit("Shielded", json!({"account_id": owner, "claim_id": args.claim_id.to_string(), "amount": args.amount.0.to_string(), "spending_version": holder.spending_version.to_string()}));
        self.charge_storage(&owner, storage_before);
    }

    pub fn unshield(&mut self, args: UnshieldArgs) -> U64 {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut holder = self.holder_or_panic(&owner);
        require!(!holder.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            args.amount.0 > 0 && args.amount.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        require!(
            holder.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        for ciphertext in [
            &args.spending_ciphertext,
            &args.issuer_ciphertext,
            &args.auditor_ciphertext,
        ] {
            if !ciphertext.is_empty() {
                validate_ciphertext(ciphertext);
            }
        }
        let context = self.crypto_context(
            "unshield",
            0,
            0,
            0,
            holder.spending_version,
            [holder.spending_version, 0, 0, 0, 0, 0, 0, 0],
            [holder.authorization_epoch, 0, 0, 0],
            0,
        );
        let conversion = self.verify_public_conversion_statement(
            &args.proof,
            &context,
            &holder.encryption_key.public_key,
            &holder.spending_ciphertext,
            None,
            args.amount.0,
            true,
            holder.spending_version,
            [
                &holder.encryption_key.public_key,
                &self.asset.issuer_key.public_key,
                &self.asset.token_auditor_key.public_key,
            ],
            [
                (!args.spending_ciphertext.is_empty())
                    .then_some(args.spending_ciphertext.as_slice()),
                (!args.issuer_ciphertext.is_empty()).then_some(args.issuer_ciphertext.as_slice()),
                (!args.auditor_ciphertext.is_empty()).then_some(args.auditor_ciphertext.as_slice()),
            ],
        );
        self.record_recovery(
            "unshield",
            &args.proof.statement,
            &[format!("holder:{owner}")],
            &[
                holder.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[holder.spending_version],
        );
        holder.spending_ciphertext = crypto_adapter::encode(&conversion.spending_after)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        holder.issuer_balance_ciphertext = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&holder.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[1].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        holder.auditor_balance_ciphertext = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&holder.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        self.holders.insert(&owner, &holder);
        let claim_id = self.next_claim_id();
        self.claims.insert(
            &claim_id,
            &PublicClaim {
                claim_id,
                owner: owner.clone(),
                amount: args.amount.0,
                created_at: now_seconds(),
                reserved_by: None,
            },
        );
        self.public_claim_total = self
            .public_claim_total
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INSUFFICIENT_PRIVATE_FUNDS));
        self.emit("Unshielded", json!({"account_id": owner, "amount": args.amount.0.to_string(), "claim_id": claim_id.to_string(), "spending_version": holder.spending_version.to_string()}));
        self.charge_storage(&owner, storage_before);
        U64(claim_id)
    }

    pub fn merge_inbox(&mut self, args: MergeArgs) {
        let owner = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut holder = self.holder_or_panic(&owner);
        require!(!holder.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            holder.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        // Inbox merging is a pure homomorphic move: the only accepted
        // replacement is the exact addition of the two authenticated ledger
        // ciphertexts.  It therefore needs no plaintext witness or amount
        // disclosure, and a caller cannot smuggle an arbitrary replacement
        // through the optional legacy proof field.
        let expected_spending =
            combine_ciphertexts(&holder.spending_ciphertext, &holder.inbox_ciphertext);
        if !args.new_spending_ciphertext.is_empty() {
            validate_ciphertext(&args.new_spending_ciphertext);
            require!(
                args.new_spending_ciphertext == expected_spending,
                ERR_BAD_PROOF
            );
        }
        require!(args.proof.is_none(), ERR_BAD_PROOF);
        let old_version = holder.spending_version;
        holder.spending_ciphertext = expected_spending;
        holder.inbox_ciphertext = self.canonical_zero_for(
            &holder.encryption_key.public_key,
            &format!("holder:{owner}:inbox"),
            holder.encryption_key.key_id,
            holder.encryption_key.authorization_epoch,
        );
        holder.spending_version = holder
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.holders.insert(&owner, &holder);
        self.emit(
            "InboxMerged",
            json!({"account_id": owner, "spending_version": holder.spending_version.to_string()}),
        );
        self.record_recovery_event(
            "merge-holder",
            &[format!("holder:{owner}")],
            &[holder.encryption_key.key_id],
            &[old_version, holder.spending_version],
            RecoveryMetadata {
                action: "merge-inbox".to_string(),
                loan_id: None,
                loan_status: None,
                noop: false,
            },
        );
        self.charge_storage(&owner, storage_before);
    }

    pub fn draw(&mut self, args: DrawArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut broker = self.broker_or_panic(args.broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(
            args.amount.0 > 0 && args.amount.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        let mut vault = self.vault_or_panic(broker.vault_id);
        self.ensure_vault_phase(&vault, false, false);
        require!(
            !vault.accounting_pending && !broker.accounting_pending,
            ERR_ACCOUNTING_PENDING
        );
        require!(
            vault.assets_available >= args.amount.0,
            ERR_INSUFFICIENT_PUBLIC_FUNDS
        );
        if broker.debt_maximum != 0 {
            require!(
                broker.debt_total.saturating_add(args.amount.0) <= broker.debt_maximum,
                ERR_DEBT_LIMIT
            );
        }
        for ciphertext in [
            &args.broker_ciphertext,
            &args.issuer_ciphertext,
            &args.auditor_ciphertext,
        ] {
            if !ciphertext.is_empty() {
                validate_ciphertext(ciphertext);
            }
        }
        let context = self.crypto_context(
            "draw",
            broker.vault_id,
            broker.broker_id,
            0,
            0,
            [
                broker.spending_version,
                broker.accounting_version,
                vault.accounting_version,
                0,
                0,
                0,
                broker.encryption_key.key_id,
                0,
            ],
            [broker.encryption_key.authorization_epoch, 0, 0, 0],
            0,
        );
        let conversion = self.verify_public_conversion_statement(
            &args.proof,
            &context,
            &broker.encryption_key.public_key,
            &broker.inbox_ciphertext,
            None,
            args.amount.0,
            false,
            broker.spending_version,
            [
                &broker.encryption_key.public_key,
                &self.asset.issuer_key.public_key,
                &self.asset.token_auditor_key.public_key,
            ],
            [
                (!args.broker_ciphertext.is_empty()).then_some(args.broker_ciphertext.as_slice()),
                (!args.issuer_ciphertext.is_empty()).then_some(args.issuer_ciphertext.as_slice()),
                (!args.auditor_ciphertext.is_empty()).then_some(args.auditor_ciphertext.as_slice()),
            ],
        );
        let new_inbox = combine_ciphertexts(
            &broker.inbox_ciphertext,
            &crypto_adapter::encode(&conversion.views[0].ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
        );
        require!(
            conversion.spending_after
                == crypto_adapter::parse_ciphertext(&new_inbox)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ERR_BAD_PROOF
        );
        self.record_recovery(
            "draw",
            &args.proof.statement,
            &[format!("broker:{}", broker.broker_id)],
            &[
                broker.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[broker.spending_version, broker.accounting_version],
        );
        vault.assets_available = vault
            .assets_available
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.inbox_ciphertext = new_inbox;
        broker.issuer_balance_ciphertext = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[1].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        broker.auditor_balance_ciphertext = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &conversion.views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_spending_commitment.is_empty() {
            require!(
                args.broker_spending_commitment == broker.spending_commitment,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_inbox_commitment.is_empty() {
            require!(
                args.broker_inbox_commitment == broker.inbox_commitment,
                ERR_BAD_PROOF
            );
        }
        broker.debt_total = broker
            .debt_total
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_DEBT_LIMIT));
        broker.cumulative_draws = broker
            .cumulative_draws
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&broker.vault_id, &vault);
        self.emit("BrokerDrawn", json!({"broker_id": args.broker_id.to_string(), "vault_id": broker.vault_id.to_string(), "amount": args.amount.0.to_string(), "accounting_version": broker.accounting_version.to_string()}));
        self.charge_storage(&caller, storage_before);
    }

    pub fn merge_broker_inbox(&mut self, broker_id: U64, args: MergeArgs) {
        let caller = env::predecessor_account_id();
        let broker_id = broker_id.0;
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut broker = self.broker_or_panic(broker_id);
        let keeper_index = if caller == broker.owner {
            None
        } else {
            self.keeper_index(&broker, &caller)
        };
        require!(
            caller == broker.owner || keeper_index.is_some(),
            ERR_UNAUTHORIZED
        );
        if let Some(index) = keeper_index {
            require!(
                broker.delegates[index]
                    .allowed_operations
                    .contains(&KeeperOperation::MergeInbox),
                ERR_UNAUTHORIZED
            );
        }
        require!(
            broker.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        let expected_spending =
            combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext);
        if !args.new_spending_ciphertext.is_empty() {
            validate_ciphertext(&args.new_spending_ciphertext);
            require!(
                args.new_spending_ciphertext == expected_spending,
                ERR_BAD_PROOF
            );
        }
        require!(args.proof.is_none(), ERR_BAD_PROOF);
        let old_version = broker.spending_version;
        broker.spending_ciphertext = expected_spending;
        broker.inbox_ciphertext = self.canonical_zero_for(
            &broker.encryption_key.public_key,
            &format!("broker:{broker_id}:inbox"),
            broker.encryption_key.key_id,
            broker.encryption_key.authorization_epoch,
        );
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.brokers.insert(&broker_id, &broker);
        self.emit(
            "InboxMerged",
            json!({"broker_id": broker_id.to_string(), "spending_version": broker.spending_version.to_string()}),
        );
        self.record_recovery_event(
            "merge-broker",
            &[format!("broker:{broker_id}")],
            &[broker.encryption_key.key_id],
            &[old_version, broker.spending_version],
            RecoveryMetadata {
                action: "merge-inbox".to_string(),
                loan_id: None,
                loan_status: None,
                noop: false,
            },
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn originate(&mut self, args: OriginateArgs) -> U64 {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let proposal = self.proposal_or_panic(args.proposal_id);
        let mut broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        require!(!proposal.consumed && !proposal.revoked, ERR_REPLAY);
        require!(now_seconds() <= proposal.expiry, ERR_EXPIRED);
        require!(
            now_seconds()
                .checked_add(proposal.payment_interval)
                .is_some(),
            ERR_INVALID_AMOUNT
        );
        require!(
            proposal.broker_direct_authorized
                || verify_authorization_signature(
                    self,
                    &broker.owner,
                    proposal.broker_authorization_key_id,
                    proposal.broker_authorization_epoch,
                    proposal.broker_authorization_nonce,
                    &proposal.agreement_digest,
                    &proposal.broker_signature,
                ),
            ERR_UNAUTHORIZED
        );
        require!(
            proposal.borrower_direct_authorized
                || verify_authorization_signature(
                    self,
                    &proposal.borrower,
                    proposal.borrower_authorization_key_id,
                    proposal.borrower_authorization_epoch,
                    proposal.borrower_authorization_nonce,
                    &proposal.agreement_digest,
                    &proposal.borrower_signature,
                ),
            ERR_UNAUTHORIZED
        );
        require!(
            broker.encryption_key.key_id == proposal.broker_key_id,
            ERR_STALE_STATE
        );
        let mut borrower = self.holder_or_panic(&proposal.borrower);
        require!(!borrower.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            borrower.encryption_key.key_id == proposal.borrower_key_id,
            ERR_STALE_STATE
        );
        require!(
            borrower.authorization_epoch == proposal.borrower_authorization_epoch,
            ERR_STALE_STATE
        );
        let vault = self.vault_or_panic(broker.vault_id);
        self.ensure_vault_phase(&vault, false, false);
        require!(
            !vault.accounting_pending && !broker.accounting_pending,
            ERR_ACCOUNTING_PENDING
        );
        require!(proposal.vault_id == broker.vault_id, ERR_WRONG_ASSET);
        if !args.loan_principal_ciphertexts.is_empty() {
            require!(
                args.loan_principal_ciphertexts == proposal.principal_ciphertexts,
                ERR_BAD_PROOF
            );
        }
        if !args.loan_initial_owed_ciphertexts.is_empty() {
            require!(
                args.loan_initial_owed_ciphertexts == proposal.initial_owed_ciphertexts,
                ERR_BAD_PROOF
            );
        }
        if !args.loan_periodic_payment_ciphertexts.is_empty() {
            require!(
                args.loan_periodic_payment_ciphertexts == proposal.periodic_payment_ciphertexts,
                ERR_BAD_PROOF
            );
        }
        for (provided, expected) in [
            (&args.principal_commitment, &proposal.principal_commitment),
            (&args.owed_commitment, &proposal.owed_commitment),
            (&args.payment_commitment, &proposal.payment_commitment),
        ] {
            if !provided.is_empty() {
                require!(provided == expected, ERR_BAD_PROOF);
            }
        }
        let stored_principal_ciphertexts = loan_reader_views(&proposal.principal_ciphertexts);
        // The loan sequence is part of the authenticated book key.  Compute
        // it before any proof is accepted so a proof cannot be replayed for a
        // different loan id or make the caller choose an arbitrary leaf/root.
        let expected_loan_id = self
            .loan_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let expected_leaf = derive_loan_leaf(
            expected_loan_id,
            proposal.broker_id,
            &proposal.borrower,
            proposal.proposal_id,
            &LoanStatus::Active,
            0,
            proposal.payment_count,
            &stored_principal_ciphertexts,
            &proposal.initial_owed_ciphertexts,
            &proposal.periodic_payment_ciphertexts,
            &proposal.principal_commitment,
        );
        let context = self.crypto_context_with_subject(
            "originate",
            proposal.vault_id,
            proposal.broker_id,
            expected_loan_id,
            proposal.proposal_id,
            [
                broker.spending_version,
                0,
                0,
                proposal.payment_count as u64,
                proposal.payment_interval,
                proposal.grace_period,
                proposal.broker_key_id,
                proposal.borrower_key_id,
            ],
            [
                proposal.broker_authorization_epoch,
                proposal.borrower_authorization_epoch,
                0,
                0,
            ],
            proposal.expiry,
            proposal.borrower.as_ref(),
        );
        let statement =
            self.verify_typed_statement(&args.proof, StatementKind::Origination, &context);
        let Statement::Origination(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        let broker_key = crypto_adapter::parse_public_key(&broker.encryption_key.public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let borrower_key = crypto_adapter::parse_public_key(&borrower.encryption_key.public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        require!(statement.broker_key == broker_key, ERR_BAD_PROOF);
        require!(statement.borrower_key == borrower_key, ERR_BAD_PROOF);
        require!(
            statement.broker_spending_before
                == crypto_adapter::parse_ciphertext(&broker.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.broker_spending_after
                != crypto_adapter::parse_ciphertext(&broker.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.broker_spending_version == broker.spending_version,
            ERR_BAD_PROOF
        );
        let loan_auditor_key = crypto_adapter::parse_public_key(&proposal.loan_auditor_public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let transfer_keys = [
            broker_key.clone(),
            borrower_key.clone(),
            crypto_adapter::parse_public_key(&self.asset.issuer_key.public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            crypto_adapter::parse_public_key(&self.asset.token_auditor_key.public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            loan_auditor_key.clone(),
        ];
        require!(
            statement.transfer_views.len() == transfer_keys.len(),
            ERR_BAD_PROOF
        );
        for (index, view) in statement.transfer_views.iter().enumerate() {
            require!(view.reader_key == transfer_keys[index], ERR_BAD_PROOF);
            require!(
                view.ciphertext
                    == crypto_adapter::parse_ciphertext(&proposal.principal_ciphertexts[index])
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        let expected_borrower_issuer = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&borrower.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let expected_borrower_auditor = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&borrower.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[3].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let expected_broker_issuer = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let expected_broker_auditor = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[3].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let expected_active_principal = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.active_principal_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[0].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let principal_commitment = crypto_adapter::parse_commitment(&proposal.principal_commitment)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let expected_active_commitment = crypto_adapter::add_commitments(
            &crypto_adapter::parse_commitment(&broker.active_principal_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &principal_commitment,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_active_principal_commitment.is_empty() {
            require!(
                args.broker_active_principal_commitment == expected_active_commitment,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            require!(
                args.broker_impaired_principal_commitment == broker.impaired_principal_commitment,
                ERR_BAD_PROOF
            );
        }
        let expected_loan_keys = [borrower_key, broker_key, loan_auditor_key];
        for (index, view) in statement.owed_views.iter().enumerate() {
            require!(view.reader_key == expected_loan_keys[index], ERR_BAD_PROOF);
            require!(
                view.ciphertext
                    == crypto_adapter::parse_ciphertext(&proposal.initial_owed_ciphertexts[index])
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        for (index, view) in statement.payment_views.iter().enumerate() {
            require!(view.reader_key == expected_loan_keys[index], ERR_BAD_PROOF);
            require!(
                view.ciphertext
                    == crypto_adapter::parse_ciphertext(
                        &proposal.periodic_payment_ciphertexts[index]
                    )
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        require!(
            statement.principal_commitment
                == crypto_adapter::parse_commitment(&proposal.principal_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.owed_commitment
                == crypto_adapter::parse_commitment(&proposal.owed_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.payment_commitment
                == crypto_adapter::parse_commitment(&proposal.payment_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.payment_count == proposal.payment_count,
            ERR_BAD_PROOF
        );
        require!(
            statement.max_payment_count == MAX_PAYMENT_COUNT,
            ERR_BAD_PROOF
        );
        require!(statement.loan_version == 0, ERR_BAD_PROOF);
        let broker_spending_after = crypto_adapter::encode(&statement.broker_spending_after)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let borrower_inbox_delta = crypto_adapter::encode(&statement.transfer_views[1].ciphertext)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let next_root = self.update_loan_book(
            broker.broker_id,
            expected_loan_id,
            &broker.loan_book_root,
            None,
            Some(&expected_leaf),
        );
        self.record_recovery(
            "originate",
            &args.proof.statement,
            &[
                format!("broker:{}", broker.broker_id),
                format!("holder:{}", proposal.borrower),
                format!("loan:{}", expected_loan_id),
            ],
            &[
                broker.encryption_key.key_id,
                borrower.encryption_key.key_id,
                proposal.loan_auditor_key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[broker.spending_version, borrower.spending_version],
        );
        let start = now_seconds();
        let next_due = start
            .checked_add(proposal.payment_interval)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        let loan_id = self.next_loan_id();
        require!(loan_id == expected_loan_id, ERR_STALE_STATE);
        let principal_ciphertexts = stored_principal_ciphertexts;
        let cumulative_repaid_ciphertexts = vec![
            self.canonical_zero_for(
                &borrower.encryption_key.public_key,
                &format!("loan:{expected_loan_id}:cumulative-repaid:0"),
                borrower.encryption_key.key_id,
                borrower.encryption_key.authorization_epoch,
            ),
            self.canonical_zero_for(
                &broker.encryption_key.public_key,
                &format!("loan:{expected_loan_id}:cumulative-repaid:1"),
                broker.encryption_key.key_id,
                broker.encryption_key.authorization_epoch,
            ),
            self.canonical_zero_for(
                &proposal.loan_auditor_public_key,
                &format!("loan:{expected_loan_id}:cumulative-repaid:2"),
                proposal.loan_auditor_key_id,
                0,
            ),
        ];
        let loan = Loan {
            loan_id,
            broker_id: proposal.broker_id,
            borrower: proposal.borrower.clone(),
            proposal_id: proposal.proposal_id,
            start_time: start,
            payment_interval: proposal.payment_interval,
            grace_period: proposal.grace_period,
            previous_due: 0,
            next_due,
            payment_total: proposal.payment_count,
            payment_remaining: proposal.payment_count,
            status: LoanStatus::Active,
            impaired: false,
            loan_version: 0,
            borrower_key_id: proposal.borrower_key_id,
            broker_key_id: proposal.broker_key_id,
            loan_auditor_key_id: proposal.loan_auditor_key_id,
            loan_auditor_public_key: proposal.loan_auditor_public_key.clone(),
            principal_ciphertexts: principal_ciphertexts.clone(),
            initial_owed_ciphertexts: proposal.initial_owed_ciphertexts.clone(),
            amount_owed_ciphertexts: proposal.initial_owed_ciphertexts.clone(),
            periodic_payment_ciphertexts: proposal.periodic_payment_ciphertexts.clone(),
            principal_remaining_ciphertexts: principal_ciphertexts.clone(),
            principal_remaining_commitment: proposal.principal_commitment.clone(),
            cumulative_repaid_ciphertexts,
            accounting_leaf: expected_leaf.clone(),
            tombstoned: false,
        };
        broker.spending_ciphertext = broker_spending_after;
        broker.issuer_balance_ciphertext = expected_broker_issuer;
        broker.auditor_balance_ciphertext = expected_broker_auditor;
        broker.active_principal_ciphertext = expected_active_principal;
        broker.loan_book_root = next_root;
        if !args.broker_spending_commitment.is_empty() {
            require!(
                args.broker_spending_commitment == broker.spending_commitment,
                ERR_BAD_PROOF
            );
        }
        broker.active_principal_commitment = expected_active_commitment;
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.active_loan_count = broker
            .active_loan_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.loan_sequence = broker
            .loan_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        borrower.inbox_ciphertext =
            combine_ciphertexts(&borrower.inbox_ciphertext, &borrower_inbox_delta);
        borrower.issuer_balance_ciphertext = expected_borrower_issuer;
        borrower.auditor_balance_ciphertext = expected_borrower_auditor;
        borrower.open_loan_count = borrower
            .open_loan_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let mut consumed = proposal;
        consumed.consumed = true;
        self.proposals.insert(&args.proposal_id, &consumed);
        self.proposal_tombstones.insert(&args.proposal_id);
        self.brokers.insert(&broker.broker_id, &broker);
        self.holders.insert(&borrower.owner, &borrower);
        self.loans.insert(&loan_id, &loan);
        self.emit(
            "LoanOriginated",
            json!({
                "loan_id": loan_id.to_string(),
                "proposal_id": loan.proposal_id.to_string(),
                "broker_id": loan.broker_id.to_string(),
                "borrower": loan.borrower,
                "start_time": loan.start_time.to_string(),
                "next_due": loan.next_due.to_string(),
                "payment_remaining": loan.payment_remaining.to_string(),
                "loan_version": loan.loan_version.to_string(),
                "accounting_leaf": loan.accounting_leaf,
            }),
        );
        self.charge_storage(&caller, storage_before);
        U64(loan_id)
    }

    pub fn confidential_send(&mut self, args: TransferArgs) {
        let sender = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        require!(sender != args.destination, ERR_INVALID_AMOUNT);
        let mut from = self.holder_or_panic(&sender);
        let mut to = self.holder_or_panic(&args.destination);
        require!(!from.frozen && !to.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            from.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        let context = self.crypto_context_with_subject(
            "confidential-send",
            0,
            0,
            0,
            0,
            [
                from.spending_version,
                0,
                from.encryption_key.key_id,
                to.encryption_key.key_id,
                0,
                0,
                0,
                0,
            ],
            [from.authorization_epoch, to.authorization_epoch, 0, 0],
            0,
            args.destination.as_ref(),
        );
        let statement =
            self.verify_typed_statement(&args.proof, StatementKind::ConfidentialTransfer, &context);
        let Statement::ConfidentialTransfer(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        let sender_key = crypto_adapter::parse_public_key(&from.encryption_key.public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let recipient_key = crypto_adapter::parse_public_key(&to.encryption_key.public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        require!(statement.sender_key == sender_key, ERR_BAD_PROOF);
        require!(statement.recipient_key == recipient_key, ERR_BAD_PROOF);
        require!(
            statement.sender_spending_before
                == crypto_adapter::parse_ciphertext(&from.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        if !args.sender_spending_ciphertext.is_empty() {
            require!(
                statement.sender_spending_after
                    == crypto_adapter::parse_ciphertext(&args.sender_spending_ciphertext)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        require!(
            statement.sender_spending_version == from.spending_version,
            ERR_BAD_PROOF
        );
        let readers = [
            &from.encryption_key.public_key,
            &to.encryption_key.public_key,
            &self.asset.issuer_key.public_key,
            &self.asset.token_auditor_key.public_key,
            // The fifth transfer view is deliberately pinned to the
            // destination key when no loan auditor is involved; it is not an
            // invitation to add an unregistered reader.
            &to.encryption_key.public_key,
        ];
        // The typed statement is authoritative.  Older clients may still
        // send redundant transfer-view fields, but an omitted field is
        // intentionally accepted so a recipient race cannot invalidate a
        // valid sender proof.
        if !args.transfer_views.is_empty() {
            require!(
                args.transfer_views.len() == readers.len(),
                ERR_INVALID_ENCODING
            );
        }
        for (index, view) in statement.transfer_views.iter().enumerate() {
            let expected_key = crypto_adapter::parse_public_key(readers[index])
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
            require!(view.reader_key == expected_key, ERR_BAD_PROOF);
            if !args.transfer_views.is_empty() {
                let expected_delta = crypto_adapter::parse_ciphertext(&args.transfer_views[index])
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
                require!(view.ciphertext == expected_delta, ERR_BAD_PROOF);
            }
        }
        if !args.commitment.is_empty() {
            require!(
                statement.amount_commitment
                    == crypto_adapter::parse_commitment(&args.commitment)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        self.record_recovery(
            "confidential-send",
            &args.proof.statement,
            &[
                format!("holder:{sender}"),
                format!("holder:{}", args.destination),
            ],
            &[
                from.encryption_key.key_id,
                to.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[from.spending_version, to.spending_version],
        );
        let issuer_delta = &statement.transfer_views[2].ciphertext;
        let auditor_delta = &statement.transfer_views[3].ciphertext;
        let sender_issuer = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&from.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            issuer_delta,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let sender_auditor = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&from.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            auditor_delta,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let destination_issuer = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&to.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            issuer_delta,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let destination_auditor = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_ciphertext(&to.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            auditor_delta,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        // Every post-state is derived from the authenticated typed statement
        // and the current ledger snapshot.  In particular, destination inbox
        // and mirrors are never caller replacement state; an intervening
        // credit is preserved by adding this delta to the current inbox.
        from.spending_ciphertext = crypto_adapter::encode(&statement.sender_spending_after)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        from.issuer_balance_ciphertext = sender_issuer;
        from.auditor_balance_ciphertext = sender_auditor;
        from.spending_version = from
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let inbox_delta = crypto_adapter::encode(&statement.transfer_views[1].ciphertext)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        to.inbox_ciphertext = combine_ciphertexts(&to.inbox_ciphertext, &inbox_delta);
        to.issuer_balance_ciphertext = destination_issuer;
        to.auditor_balance_ciphertext = destination_auditor;
        self.holders.insert(&sender, &from);
        self.holders.insert(&args.destination, &to);
        self.emit(
            "ConfidentialTransfer",
            json!({
                "sender": sender,
                "destination": args.destination,
                "sender_spending_version": from.spending_version.to_string(),
                "transfer_views": args.transfer_views,
                "commitment": args.commitment
            }),
        );
        self.charge_storage(&sender, storage_before);
    }

    pub fn repay(&mut self, args: RepayArgs) {
        let caller = env::predecessor_account_id();
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:start:{}", env::used_gas().as_gas()));
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut loan = self.loan_or_panic(args.loan_id);
        let relayed = caller != loan.borrower;
        if relayed {
            let authorization_message = hash_bytes(&(
                b"repay-authorization-v1".to_vec(),
                args.loan_id,
                args.mode.clone(),
                args.expected_loan_version,
                args.expected_borrower_spending_version,
                args.proof.statement.clone(),
            ));
            require!(
                verify_authorization_signature(
                    self,
                    &loan.borrower,
                    args.authorization_key_id,
                    args.authorization_epoch,
                    args.authorization_nonce,
                    &authorization_message,
                    &args.authorization_signature,
                ),
                ERR_UNAUTHORIZED
            );
        }
        require!(matches!(loan.status, LoanStatus::Active), ERR_LOAN_CLOSED);
        require!(loan.payment_remaining > 0, ERR_LOAN_CLOSED);
        require!(
            loan.loan_version == args.expected_loan_version,
            ERR_STALE_STATE
        );
        let mut borrower = self.holder_or_panic(&loan.borrower);
        require!(!borrower.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            borrower.spending_version == args.expected_borrower_spending_version,
            ERR_STALE_STATE
        );
        let broker_id = loan.broker_id;
        let mut broker = self.broker_or_panic(broker_id);
        let was_broker_accounting_pending = broker.accounting_pending;
        let context = self.crypto_context_with_subject(
            "repay",
            0,
            broker.broker_id,
            loan.loan_id,
            loan.proposal_id,
            [
                borrower.spending_version,
                loan.loan_version,
                broker.spending_version,
                broker.book_version,
                loan.payment_remaining as u64,
                loan.payment_interval,
                loan.borrower_key_id,
                loan.broker_key_id,
            ],
            [
                borrower.authorization_epoch,
                broker.encryption_key.authorization_epoch,
                0,
                0,
            ],
            0,
            borrower.owner.as_ref(),
        );
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!(
            "repay-gas:before-proof:{}",
            env::used_gas().as_gas()
        ));
        let statement =
            self.verify_typed_statement(&args.proof, StatementKind::Repayment, &context);
        let Statement::Repayment(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:verified:{}", env::used_gas().as_gas()));
        let borrower_key =
            crypto_adapter::parse_stored_public_key(&borrower.encryption_key.public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let broker_key = crypto_adapter::parse_stored_public_key(&broker.encryption_key.public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let loan_auditor_key =
            crypto_adapter::parse_stored_public_key(&loan.loan_auditor_public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        require!(statement.borrower_key == borrower_key, ERR_BAD_PROOF);
        require!(statement.broker_key == broker_key, ERR_BAD_PROOF);
        require!(
            statement.borrower_spending_before
                == crypto_adapter::parse_stored_ciphertext(&borrower.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.borrower_spending_after
                != crypto_adapter::parse_stored_ciphertext(&borrower.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.borrower_spending_version == borrower.spending_version,
            ERR_BAD_PROOF
        );
        let transfer_keys = [
            borrower_key.clone(),
            broker_key.clone(),
            crypto_adapter::parse_stored_public_key(&self.asset.issuer_key.public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            crypto_adapter::parse_stored_public_key(&self.asset.token_auditor_key.public_key)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            loan_auditor_key.clone(),
        ];
        for (index, view) in statement.transfer_views.iter().enumerate() {
            require!(view.reader_key == transfer_keys[index], ERR_BAD_PROOF);
            if !args.transfer_views.is_empty() {
                require!(
                    args.transfer_views.len() == transfer_keys.len(),
                    ERR_BAD_PROOF
                );
                require!(
                    view.ciphertext
                        == crypto_adapter::parse_ciphertext(&args.transfer_views[index])
                            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                    ERR_BAD_PROOF
                );
            }
        }
        let broker_issuer = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_stored_ciphertext(&broker.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let broker_auditor = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_stored_ciphertext(&broker.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[3].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let borrower_issuer = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_stored_ciphertext(&borrower.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let borrower_auditor = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_stored_ciphertext(&borrower.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[3].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.borrower_issuer_ciphertext.is_empty() {
            require!(
                args.borrower_issuer_ciphertext == borrower_issuer,
                ERR_BAD_PROOF
            );
        }
        if !args.borrower_auditor_ciphertext.is_empty() {
            require!(
                args.borrower_auditor_ciphertext == borrower_auditor,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_issuer_ciphertext.is_empty() {
            require!(
                args.broker_issuer_ciphertext == broker_issuer,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_auditor_ciphertext.is_empty() {
            require!(
                args.broker_auditor_ciphertext == broker_auditor,
                ERR_BAD_PROOF
            );
        }
        let borrower_spending_after = crypto_adapter::encode(&statement.borrower_spending_after)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.borrower_spending_ciphertext.is_empty() {
            require!(
                args.borrower_spending_ciphertext == borrower_spending_after,
                ERR_BAD_PROOF
            );
        }
        let broker_inbox_after = crypto_adapter::add_ciphertexts(
            &crypto_adapter::parse_stored_ciphertext(&broker.inbox_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.transfer_views[1].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_inbox_ciphertext.is_empty() {
            require!(
                args.broker_inbox_ciphertext == broker_inbox_after,
                ERR_BAD_PROOF
            );
        }
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:mirrors:{}", env::used_gas().as_gas()));
        let loan_keys = [borrower_key, broker_key, loan_auditor_key];
        for (index, loan_key) in loan_keys.iter().enumerate() {
            require!(
                statement.owed_before[index].reader_key == *loan_key
                    && statement.owed_after[index].reader_key == *loan_key
                    && statement.owed_delta[index].reader_key == *loan_key
                    && statement.periodic_payment[index].reader_key == *loan_key
                    && statement.principal_before[index].reader_key == *loan_key
                    && statement.principal_after[index].reader_key == *loan_key
                    && statement.principal_delta[index].reader_key == *loan_key,
                ERR_BAD_PROOF
            );
            require!(
                statement.owed_before[index].ciphertext
                    == crypto_adapter::parse_stored_ciphertext(
                        &loan.amount_owed_ciphertexts[index]
                    )
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
                    && statement.periodic_payment[index].ciphertext
                        == crypto_adapter::parse_stored_ciphertext(
                            &loan.periodic_payment_ciphertexts[index]
                        )
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
                    && statement.principal_before[index].ciphertext
                        == crypto_adapter::parse_stored_ciphertext(
                            &loan.principal_remaining_ciphertexts[index]
                        )
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
            if !args.amount_owed_ciphertexts.is_empty() {
                require!(
                    statement.owed_after[index].ciphertext
                        == crypto_adapter::parse_ciphertext(&args.amount_owed_ciphertexts[index])
                            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                    ERR_BAD_PROOF
                );
            }
            if !args.principal_remaining_ciphertexts.is_empty() {
                require!(
                    statement.principal_after[index].ciphertext
                        == crypto_adapter::parse_ciphertext(
                            &args.principal_remaining_ciphertexts[index],
                        )
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                    ERR_BAD_PROOF
                );
            }
        }
        require!(
            statement.mode
                == match args.mode {
                    RepayMode::Regular => confidential_crypto::PaymentMode::Regular,
                    RepayMode::Full => confidential_crypto::PaymentMode::Full,
                },
            ERR_BAD_PROOF
        );
        require!(
            statement.payment_remaining_before == loan.payment_remaining
                && statement.payment_remaining_after
                    == if matches!(args.mode, RepayMode::Full) {
                        0
                    } else {
                        loan.payment_remaining.saturating_sub(1)
                    }
                && statement.loan_version_before == loan.loan_version
                && statement.loan_version_after == loan.loan_version.saturating_add(1),
            ERR_BAD_PROOF
        );
        if !args.commitment.is_empty() {
            require!(
                statement.principal_delta_commitment
                    == crypto_adapter::parse_commitment(&args.commitment)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        let principal_delta = &statement.principal_delta[1].ciphertext;
        let expected_active = if loan.impaired {
            crypto_adapter::parse_stored_ciphertext(&broker.active_principal_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
        } else {
            crypto_adapter::sub_ciphertexts(
                &crypto_adapter::parse_stored_ciphertext(&broker.active_principal_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                principal_delta,
            )
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF))
        };
        let expected_impaired = if loan.impaired {
            crypto_adapter::sub_ciphertexts(
                &crypto_adapter::parse_stored_ciphertext(&broker.impaired_principal_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                principal_delta,
            )
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF))
        } else {
            crypto_adapter::parse_stored_ciphertext(&broker.impaired_principal_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
        };
        let expected_active_ciphertext = crypto_adapter::encode(&expected_active)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let expected_impaired_ciphertext = crypto_adapter::encode(&expected_impaired)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_active_principal_ciphertext.is_empty() {
            require!(
                args.broker_active_principal_ciphertext == expected_active_ciphertext,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_impaired_principal_ciphertext.is_empty() {
            require!(
                args.broker_impaired_principal_ciphertext == expected_impaired_ciphertext,
                ERR_BAD_PROOF
            );
        }
        let amount_owed_after = statement
            .owed_after
            .iter()
            .map(|view| crypto_adapter::encode(&view.ciphertext))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let principal_after = statement
            .principal_after
            .iter()
            .map(|view| crypto_adapter::encode(&view.ciphertext))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let cumulative_repaid_after = statement
            .owed_delta
            .iter()
            .zip(loan.cumulative_repaid_ciphertexts.iter())
            .map(|(paid, current)| {
                crypto_adapter::add_ciphertexts(
                    &crypto_adapter::parse_stored_ciphertext(current)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                    &paid.ciphertext,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF))
            })
            .collect::<Vec<_>>();
        if !args.cumulative_repaid_ciphertexts.is_empty() {
            require!(
                args.cumulative_repaid_ciphertexts == cumulative_repaid_after,
                ERR_BAD_PROOF
            );
        }
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!(
            "repay-gas:arithmetic:{}",
            env::used_gas().as_gas()
        ));
        self.record_recovery(
            "repay",
            &args.proof.statement,
            &[
                format!("holder:{}", borrower.owner),
                format!("broker:{}", broker.broker_id),
                format!("loan:{}", loan.loan_id),
            ],
            &[
                borrower.encryption_key.key_id,
                broker.encryption_key.key_id,
                loan.loan_auditor_key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[
                borrower.spending_version,
                broker.spending_version,
                loan.loan_version,
            ],
        );
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:recovery:{}", env::used_gas().as_gas()));
        let principal_delta_commitment = statement.principal_delta_commitment.clone();
        let expected_loan_commitment = crypto_adapter::sub_commitments(
            &crypto_adapter::parse_stored_commitment(&loan.principal_remaining_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &principal_delta_commitment,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let old_active_commitment =
            crypto_adapter::parse_stored_commitment(&broker.active_principal_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let old_impaired_commitment =
            crypto_adapter::parse_stored_commitment(&broker.impaired_principal_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let (expected_active_commitment, expected_impaired_commitment) = if loan.impaired {
            (
                crypto_adapter::encode(&old_active_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::sub_commitments(
                    &old_impaired_commitment,
                    &principal_delta_commitment,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            )
        } else {
            (
                crypto_adapter::sub_commitments(
                    &old_active_commitment,
                    &principal_delta_commitment,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::encode(&old_impaired_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            )
        };
        if !args.broker_active_principal_commitment.is_empty() {
            require!(
                args.broker_active_principal_commitment == expected_active_commitment,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            require!(
                args.broker_impaired_principal_commitment == expected_impaired_commitment,
                ERR_BAD_PROOF
            );
        }
        let old_loan_leaf = derive_loan_leaf(
            loan.loan_id,
            loan.broker_id,
            &loan.borrower,
            loan.proposal_id,
            &loan.status,
            loan.loan_version,
            loan.payment_remaining,
            &loan.principal_remaining_ciphertexts,
            &loan.amount_owed_ciphertexts,
            &loan.periodic_payment_ciphertexts,
            &loan.principal_remaining_commitment,
        );
        require!(loan.accounting_leaf == old_loan_leaf, ERR_BAD_PROOF);
        // Risk accounting is keyed to the pre-transition loan state.  A full
        // repayment of an impaired loan removes that loan from the broker's
        // impaired cohort, but still leaves a reconciliation event pending;
        // clearing the flag before evaluating the pending condition would
        // silently strand the old aggregate contribution.
        let was_impaired = loan.impaired;
        if matches!(args.mode, RepayMode::Regular) {
            require!(loan.payment_remaining > 1, ERR_INVALID_AMOUNT);
        }
        borrower.spending_ciphertext = borrower_spending_after;
        borrower.issuer_balance_ciphertext = borrower_issuer;
        borrower.auditor_balance_ciphertext = borrower_auditor;
        borrower.spending_version = borrower
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.inbox_ciphertext = broker_inbox_after;
        broker.issuer_balance_ciphertext = broker_issuer;
        broker.auditor_balance_ciphertext = broker_auditor;
        broker.active_principal_ciphertext = expected_active_ciphertext;
        broker.impaired_principal_ciphertext = expected_impaired_ciphertext;
        if !args.broker_inbox_commitment.is_empty() {
            require!(
                args.broker_inbox_commitment == broker.inbox_commitment,
                ERR_BAD_PROOF
            );
        }
        broker.active_principal_commitment = expected_active_commitment.clone();
        broker.impaired_principal_commitment = expected_impaired_commitment.clone();
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        loan.amount_owed_ciphertexts = amount_owed_after;
        loan.principal_remaining_ciphertexts = principal_after;
        loan.principal_remaining_commitment = expected_loan_commitment.clone();
        loan.cumulative_repaid_ciphertexts = cumulative_repaid_after;
        loan.loan_version = loan
            .loan_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        if matches!(args.mode, RepayMode::Full) {
            loan.status = LoanStatus::Paid;
            loan.payment_remaining = 0;
            loan.next_due = 0;
            loan.impaired = false;
            if was_impaired {
                broker.impaired_loan_count = broker
                    .impaired_loan_count
                    .checked_sub(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            broker.active_loan_count = broker
                .active_loan_count
                .checked_sub(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            borrower.open_loan_count = borrower
                .open_loan_count
                .checked_sub(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        } else {
            loan.payment_remaining = loan
                .payment_remaining
                .checked_sub(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            loan.previous_due = loan.next_due;
            loan.next_due = loan
                .next_due
                .checked_add(loan.payment_interval)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        }
        let expected_leaf = derive_loan_leaf(
            loan.loan_id,
            loan.broker_id,
            &loan.borrower,
            loan.proposal_id,
            &loan.status,
            loan.loan_version,
            loan.payment_remaining,
            &loan.principal_remaining_ciphertexts,
            &loan.amount_owed_ciphertexts,
            &loan.periodic_payment_ciphertexts,
            &expected_loan_commitment,
        );
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!(
            "repay-gas:before-book:{}",
            env::used_gas().as_gas()
        ));
        let expected_root = self.update_loan_book(
            broker.broker_id,
            loan.loan_id,
            &broker.loan_book_root,
            Some(&old_loan_leaf),
            Some(&expected_leaf),
        );
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:book:{}", env::used_gas().as_gas()));
        if !args.accounting_leaf.is_empty() {
            require!(args.accounting_leaf == expected_leaf, ERR_BAD_PROOF);
        }
        if !args.broker_book_root.is_empty() {
            require!(args.broker_book_root == expected_root, ERR_BAD_PROOF);
        }
        loan.accounting_leaf = expected_leaf;
        broker.loan_book_root = expected_root;
        if relayed {
            let key_id = args
                .authorization_key_id
                .unwrap_or_else(|| env::panic_str(ERR_UNAUTHORIZED));
            let mut key = self
                .authorization_keys
                .get(&authorization_key(&loan.borrower, key_id))
                .unwrap_or_else(|| env::panic_str(ERR_UNAUTHORIZED));
            key.nonce = key
                .nonce
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            self.authorization_keys
                .insert(&authorization_key(&loan.borrower, key_id), &key);
        }
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        if was_impaired || broker.impairment_provision > 0 {
            if !was_broker_accounting_pending {
                broker.accounting_pending_since = now_seconds();
            }
            broker.accounting_pending = true;
            broker.risk_version = broker
                .risk_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            let mut vault = self.vault_or_panic(broker.vault_id);
            if !was_broker_accounting_pending {
                vault.pending_broker_count = vault
                    .pending_broker_count
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            vault.accounting_pending = true;
            vault.risk_version = vault
                .risk_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            self.vaults.insert(&broker.vault_id, &vault);
        }
        self.holders.insert(&borrower.owner, &borrower);
        self.brokers.insert(&broker_id, &broker);
        self.loans.insert(&loan.loan_id, &loan);
        self.emit(
            "LoanRepaid",
            json!({
                "loan_id": loan.loan_id.to_string(),
                "broker_id": loan.broker_id.to_string(),
                "status": loan.status,
                "payment_remaining": loan.payment_remaining.to_string(),
                "loan_version": loan.loan_version.to_string(),
                "transfer_views": args.transfer_views,
                "amount_owed_ciphertexts": loan.amount_owed_ciphertexts,
            }),
        );
        #[cfg(feature = "gas-profiling")]
        env::log_str(&format!("repay-gas:stored:{}", env::used_gas().as_gas()));
        self.charge_storage(&caller, storage_before);
    }

    pub fn manage_loan(&mut self, args: ManageLoanArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        let mut loan = self.loan_or_panic(args.loan_id);
        let mut broker = self.broker_or_panic(loan.broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(
            loan.loan_version == args.expected_loan_version,
            ERR_STALE_STATE
        );
        let was_accounting_pending = broker.accounting_pending;
        let was_impaired = loan.impaired;
        require!(matches!(loan.status, LoanStatus::Active), ERR_LOAN_CLOSED);
        if !args.accounting_leaf.is_empty() {
            validate_digest32(&args.accounting_leaf);
        }
        let old_loan_leaf = derive_loan_leaf(
            loan.loan_id,
            loan.broker_id,
            &loan.borrower,
            loan.proposal_id,
            &loan.status,
            loan.loan_version,
            loan.payment_remaining,
            &loan.principal_remaining_ciphertexts,
            &loan.amount_owed_ciphertexts,
            &loan.periodic_payment_ciphertexts,
            &loan.principal_remaining_commitment,
        );
        require!(loan.accounting_leaf == old_loan_leaf, ERR_BAD_PROOF);
        match args.action {
            LoanManagementAction::Impair => {
                require!(now_seconds() > loan.next_due, ERR_TOO_SOON);
                require!(!loan.impaired, ERR_INVALID_AMOUNT);
                loan.impaired = true;
                broker.impaired_loan_count = broker
                    .impaired_loan_count
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            LoanManagementAction::Unimpair => {
                require!(loan.impaired, ERR_INVALID_AMOUNT);
                loan.impaired = false;
                broker.impaired_loan_count = broker
                    .impaired_loan_count
                    .checked_sub(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            LoanManagementAction::Default => {
                let deadline = loan
                    .next_due
                    .checked_add(loan.grace_period)
                    .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
                require!(now_seconds() > deadline, ERR_TOO_SOON);
                if loan.impaired {
                    broker.impaired_loan_count = broker
                        .impaired_loan_count
                        .checked_sub(1)
                        .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                }
                loan.impaired = false;
                loan.status = LoanStatus::Defaulted;
                loan.payment_remaining = 0;
                loan.next_due = 0;
                broker.active_loan_count = broker
                    .active_loan_count
                    .checked_sub(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
        }
        if !args.broker_active_principal_ciphertext.is_empty() {
            validate_ciphertext(&args.broker_active_principal_ciphertext);
        }
        if !args.broker_impaired_principal_ciphertext.is_empty() {
            validate_ciphertext(&args.broker_impaired_principal_ciphertext);
        }
        if !args.broker_book_root.is_empty() {
            validate_digest32(&args.broker_book_root);
        }
        let principal = crypto_adapter::parse_ciphertext(&loan.principal_remaining_ciphertexts[1])
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let active_before = crypto_adapter::parse_ciphertext(&broker.active_principal_ciphertext)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let impaired_before =
            crypto_adapter::parse_ciphertext(&broker.impaired_principal_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let (active_expected, impaired_expected) = match args.action {
            LoanManagementAction::Impair => (
                active_before.clone(),
                crypto_adapter::add_ciphertexts(&impaired_before, &principal)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
            LoanManagementAction::Unimpair => (
                active_before.clone(),
                crypto_adapter::sub_ciphertexts(&impaired_before, &principal)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
            LoanManagementAction::Default => {
                if was_impaired {
                    (
                        crypto_adapter::sub_ciphertexts(&active_before, &principal)
                            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                        crypto_adapter::sub_ciphertexts(&impaired_before, &principal)
                            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                    )
                } else {
                    (
                        crypto_adapter::sub_ciphertexts(&active_before, &principal)
                            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                        impaired_before.clone(),
                    )
                }
            }
        };
        let active_expected_ciphertext = crypto_adapter::encode(&active_expected)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let impaired_expected_ciphertext = crypto_adapter::encode(&impaired_expected)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_active_principal_ciphertext.is_empty() {
            require!(
                args.broker_active_principal_ciphertext == active_expected_ciphertext,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_impaired_principal_ciphertext.is_empty() {
            require!(
                args.broker_impaired_principal_ciphertext == impaired_expected_ciphertext,
                ERR_BAD_PROOF
            );
        }
        // Management changes only authenticated loan-book state and
        // homomorphic aggregate ciphertexts.  Direct broker-owner authority
        // is sufficient; an optional typed statement is still checked when a
        // client supplies one, but caller replacement outputs remain ignored.
        if let Some(proof) = args.proof.as_ref() {
            let cash = combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext);
            let vault = self.vault_or_panic(broker.vault_id);
            let context = self.crypto_context(
                "manage-loan",
                broker.vault_id,
                broker.broker_id,
                loan.loan_id,
                loan.proposal_id,
                [
                    broker.spending_version,
                    broker.book_version,
                    broker.accounting_version,
                    loan.loan_version,
                    broker.risk_version,
                    vault.accounting_version,
                    loan.impaired as u64,
                    matches!(args.action, LoanManagementAction::Default) as u64,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
            );
            let statement =
                self.verify_typed_statement(proof, StatementKind::Reconciliation, &context);
            let Statement::Reconciliation(statement) = statement else {
                env::panic_str(ERR_BAD_PROOF);
            };
            require!(
                statement.broker_key
                    == crypto_adapter::parse_public_key(&broker.encryption_key.public_key)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
            require!(
                statement.cash
                    == crypto_adapter::parse_ciphertext(&cash)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
            require!(
                statement.active_principal == active_expected
                    && statement.impaired_principal == impaired_expected,
                ERR_BAD_PROOF
            );
            require!(
                statement.debt_before == broker.debt_total
                    && statement.debt_after == broker.debt_total
                    && statement.vault_assets_before == vault.assets_total
                    && statement.vault_assets_after == vault.assets_total
                    && statement.vault_provision_before == vault.loss_unrealized
                    && statement.vault_provision_after == vault.loss_unrealized
                    && statement.provision_before == broker.impairment_provision
                    && statement.provision_after == broker.impairment_provision
                    && statement.realized_loss == 0
                    && statement.book_version == broker.book_version
                    && statement.accounting_version == broker.accounting_version,
                ERR_BAD_PROOF
            );
        }
        let loan_principal_commitment =
            crypto_adapter::parse_commitment(&loan.principal_remaining_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let old_active_commitment =
            crypto_adapter::parse_commitment(&broker.active_principal_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let old_impaired_commitment =
            crypto_adapter::parse_commitment(&broker.impaired_principal_commitment)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let (expected_active_commitment, expected_impaired_commitment) = match args.action {
            LoanManagementAction::Impair => (
                crypto_adapter::encode(&old_active_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::add_commitments(
                    &old_impaired_commitment,
                    &loan_principal_commitment,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
            LoanManagementAction::Unimpair => (
                crypto_adapter::encode(&old_active_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::sub_commitments(
                    &old_impaired_commitment,
                    &loan_principal_commitment,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
            LoanManagementAction::Default if was_impaired => (
                crypto_adapter::sub_commitments(&old_active_commitment, &loan_principal_commitment)
                    .and_then(|value| crypto_adapter::encode(&value))
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::sub_commitments(
                    &old_impaired_commitment,
                    &loan_principal_commitment,
                )
                .and_then(|value| crypto_adapter::encode(&value))
                .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
            LoanManagementAction::Default => (
                crypto_adapter::sub_commitments(&old_active_commitment, &loan_principal_commitment)
                    .and_then(|value| crypto_adapter::encode(&value))
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
                crypto_adapter::encode(&old_impaired_commitment)
                    .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF)),
            ),
        };
        if !args.broker_active_principal_commitment.is_empty() {
            require!(
                args.broker_active_principal_commitment == expected_active_commitment,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            require!(
                args.broker_impaired_principal_commitment == expected_impaired_commitment,
                ERR_BAD_PROOF
            );
        }
        self.record_recovery_event(
            "manage-loan",
            &[
                format!("broker:{}", broker.broker_id),
                format!("loan:{}", loan.loan_id),
            ],
            &[
                broker.encryption_key.key_id,
                loan.borrower_key_id,
                loan.broker_key_id,
                loan.loan_auditor_key_id,
            ],
            &[
                broker.book_version,
                broker.accounting_version,
                loan.loan_version,
            ],
            RecoveryMetadata {
                action: match &args.action {
                    LoanManagementAction::Impair => "impair",
                    LoanManagementAction::Unimpair => "unimpair",
                    LoanManagementAction::Default => "default",
                }
                .to_string(),
                loan_id: Some(loan.loan_id),
                loan_status: Some(loan.status.clone()),
                noop: false,
            },
        );
        let mut borrower = if matches!(&args.action, LoanManagementAction::Default) {
            Some(self.holder_or_panic(&loan.borrower))
        } else {
            None
        };
        if let Some(holder) = borrower.as_mut() {
            holder.open_loan_count = holder
                .open_loan_count
                .checked_sub(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        }
        loan.loan_version = loan
            .loan_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let expected_leaf = derive_loan_leaf(
            loan.loan_id,
            loan.broker_id,
            &loan.borrower,
            loan.proposal_id,
            &loan.status,
            loan.loan_version,
            loan.payment_remaining,
            &loan.principal_remaining_ciphertexts,
            &loan.amount_owed_ciphertexts,
            &loan.periodic_payment_ciphertexts,
            &loan.principal_remaining_commitment,
        );
        let expected_root = self.update_loan_book(
            broker.broker_id,
            loan.loan_id,
            &broker.loan_book_root,
            Some(&old_loan_leaf),
            Some(&expected_leaf),
        );
        if !args.accounting_leaf.is_empty() {
            require!(args.accounting_leaf == expected_leaf, ERR_BAD_PROOF);
        }
        if !args.broker_book_root.is_empty() {
            require!(args.broker_book_root == expected_root, ERR_BAD_PROOF);
        }
        loan.accounting_leaf = expected_leaf;
        broker.active_principal_ciphertext = active_expected_ciphertext;
        broker.impaired_principal_ciphertext = impaired_expected_ciphertext;
        broker.loan_book_root = expected_root;
        broker.active_principal_commitment = expected_active_commitment;
        broker.impaired_principal_commitment = expected_impaired_commitment;
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        if !was_accounting_pending {
            broker.accounting_pending_since = now_seconds();
        }
        broker.accounting_pending = true;
        broker.risk_version = broker
            .risk_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        let mut vault = self.vault_or_panic(broker.vault_id);
        if !was_accounting_pending {
            vault.pending_broker_count = vault
                .pending_broker_count
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        }
        vault.accounting_pending = true;
        vault.risk_version = vault
            .risk_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.loans.insert(&loan.loan_id, &loan);
        self.brokers.insert(&broker.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        if let Some(holder) = borrower {
            self.holders.insert(&holder.owner, &holder);
        }
        self.emit(
            "LoanManagement",
            json!({
                "loan_id": loan.loan_id.to_string(),
                "broker_id": loan.broker_id.to_string(),
                "action": args.action,
                "status": loan.status,
                "impaired": loan.impaired,
                "loan_version": loan.loan_version.to_string(),
                "risk_version": broker.risk_version.to_string(),
                "accounting_leaf": loan.accounting_leaf
            }),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn prepare_reconciliation(&mut self, broker_id: U64) -> U64 {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let broker_id = broker_id.0;
        let mut broker = self.broker_or_panic(broker_id);
        let vault = self.vault_or_panic(broker.vault_id);
        require!(
            broker.accounting_pending || broker.impairment_provision > 0,
            ERR_ACCOUNTING_PENDING
        );
        require!(
            broker.risk_version > broker.reconciled_risk_version || broker.impairment_provision > 0,
            ERR_ACCOUNTING_PENDING
        );
        require!(broker.reconciliation_checkpoint_id.is_none(), ERR_REPLAY);
        let scheduled_at = self.reconciliation_scheduled_at(&broker, &vault);
        let id = self.next_checkpoint_id();
        self.checkpoints.insert(
            &id,
            &Checkpoint {
                checkpoint_id: id,
                broker_id,
                risk_version: broker.risk_version,
                accounting_version: broker.accounting_version,
                scheduled_at,
                consumed: false,
            },
        );
        broker.reconciliation_checkpoint_id = Some(id);
        self.brokers.insert(&broker_id, &broker);
        self.charge_storage(&caller, storage_before);
        U64(id)
    }

    /// Validate a checkpoint against an exact broker/vault snapshot.  This is
    /// deliberately side-effect free so settlement can validate the bundled
    /// checkpoint against its virtual post-settlement state before either
    /// state transition is persisted.
    fn validate_reconciliation(
        &self,
        args: &ReconcileArgs,
        checkpoint: &Checkpoint,
        broker: &Broker,
        vault: &Vault,
        context: &OperationContext,
    ) -> ReconciliationCheck {
        require!(!checkpoint.consumed, ERR_REPLAY);
        require!(
            broker.accounting_pending || broker.impairment_provision > 0,
            ERR_ACCOUNTING_PENDING
        );
        require!(checkpoint.broker_id == args.broker_id, ERR_WRONG_ASSET);
        require!(broker.broker_id == args.broker_id, ERR_WRONG_ASSET);
        require!(
            broker.reconciliation_checkpoint_id == Some(checkpoint.checkpoint_id),
            ERR_STALE_STATE
        );
        require!(
            broker.risk_version == args.expected_risk_version,
            ERR_STALE_STATE
        );
        require!(
            broker.accounting_version == args.expected_accounting_version,
            ERR_STALE_STATE
        );
        require!(
            checkpoint.risk_version == broker.risk_version,
            ERR_STALE_STATE
        );
        require!(
            checkpoint.accounting_version <= broker.accounting_version,
            ERR_STALE_STATE
        );
        require!(now_seconds() >= checkpoint.scheduled_at, ERR_TOO_SOON);
        require!(args.loss.0 <= broker.debt_total, ERR_INVALID_AMOUNT);
        require!(
            args.new_broker_debt.0.saturating_add(args.loss.0) == broker.debt_total,
            ERR_BAD_PROOF
        );
        require!(
            args.new_vault_total.0.saturating_add(args.loss.0) == vault.assets_total,
            ERR_BAD_PROOF
        );
        require!(
            args.new_broker_provision.0 <= args.new_broker_debt.0,
            ERR_BAD_PROOF
        );
        let new_vault_provision = vault
            .loss_unrealized
            .checked_sub(broker.impairment_provision)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT))
            .checked_add(args.new_broker_provision.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        let statement =
            self.verify_typed_statement(&args.proof, StatementKind::Reconciliation, context);
        let Statement::Reconciliation(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        require!(
            statement.broker_key
                == crypto_adapter::parse_public_key(&broker.encryption_key.public_key)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        let cash = combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext);
        require!(
            statement.cash
                == crypto_adapter::parse_ciphertext(&cash)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
                && statement.active_principal
                    == crypto_adapter::parse_ciphertext(&broker.active_principal_ciphertext)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
                && statement.impaired_principal
                    == crypto_adapter::parse_ciphertext(&broker.impaired_principal_ciphertext)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.debt_before == broker.debt_total
                && statement.debt_after == args.new_broker_debt.0
                && statement.vault_assets_before == vault.assets_total
                && statement.vault_assets_after == args.new_vault_total.0
                && statement.vault_provision_before == vault.loss_unrealized
                && statement.vault_provision_after == new_vault_provision
                && statement.provision_before == broker.impairment_provision
                && statement.provision_after == args.new_broker_provision.0
                && statement.realized_loss == args.loss.0
                && statement.book_version == broker.book_version
                && statement.accounting_version == broker.accounting_version,
            ERR_BAD_PROOF
        );
        if !args.cash_commitment.is_empty() {
            require!(
                statement.cash_commitment
                    == crypto_adapter::parse_commitment(&args.cash_commitment)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        if !args.active_principal_commitment.is_empty() {
            require!(
                statement.active_principal_commitment
                    == crypto_adapter::parse_commitment(&args.active_principal_commitment)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        if !args.impaired_principal_commitment.is_empty() {
            require!(
                statement.impaired_principal_commitment
                    == crypto_adapter::parse_commitment(&args.impaired_principal_commitment)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        ReconciliationCheck {
            new_vault_provision,
        }
    }

    pub fn reconcile_credit(&mut self, args: ReconcileArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        let mut checkpoint = self
            .checkpoints
            .get(&args.checkpoint_id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND));
        let mut broker = self.broker_or_panic(args.broker_id);
        let was_accounting_pending = broker.accounting_pending;
        let mut vault = self.vault_or_panic(broker.vault_id);
        let context = self.crypto_context_with_subject(
            "reconcile-credit",
            broker.vault_id,
            broker.broker_id,
            0,
            0,
            [
                broker.risk_version,
                broker.accounting_version,
                broker.book_version,
                checkpoint.checkpoint_id,
                checkpoint.accounting_version,
                0,
                0,
                0,
            ],
            [broker.encryption_key.authorization_epoch, 0, 0, 0],
            checkpoint.scheduled_at,
            broker.owner.as_ref(),
        );
        let reconciliation =
            self.validate_reconciliation(&args, &checkpoint, &broker, &vault, &context);
        let new_vault_provision = reconciliation.new_vault_provision;
        self.record_recovery(
            "reconcile-credit",
            &args.proof.statement,
            &[format!("broker:{}", broker.broker_id)],
            &[
                broker.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[broker.risk_version, broker.accounting_version],
        );
        vault.assets_total = args.new_vault_total.0;
        vault.loss_unrealized = new_vault_provision;
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.debt_total = args.new_broker_debt.0;
        broker.impairment_provision = args.new_broker_provision.0;
        broker.cumulative_realized_losses = broker
            .cumulative_realized_losses
            .checked_add(args.loss.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.accounting_pending = false;
        broker.accounting_pending_since = 0;
        broker.reconciliation_checkpoint_id = None;
        broker.reconciled_risk_version = broker.risk_version;
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        checkpoint.consumed = true;
        if was_accounting_pending {
            vault.pending_broker_count = vault
                .pending_broker_count
                .checked_sub(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        }
        vault.accounting_pending = vault.pending_broker_count > 0;
        if !vault.accounting_pending {
            vault.reconciled_risk_version = vault.risk_version;
        }
        self.checkpoints.insert(&args.checkpoint_id, &checkpoint);
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        self.emit(
            "CreditReconciled",
            json!({
                "checkpoint_id": args.checkpoint_id.to_string(),
                "broker_id": args.broker_id.to_string(),
                "loss": args.loss.0.to_string(),
                "new_broker_debt": args.new_broker_debt.0.to_string(),
                "new_broker_provision": args.new_broker_provision.0.to_string(),
                "new_vault_total": args.new_vault_total.0.to_string(),
                "risk_version": broker.risk_version.to_string(),
                "accounting_version": broker.accounting_version.to_string()
            }),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn settle(&mut self, args: SettleArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        let mut broker = self.broker_or_panic(args.broker_id);
        let was_broker_accounting_pending = broker.accounting_pending;
        let is_owner = caller == broker.owner;
        let keeper_index = if is_owner {
            None
        } else {
            self.keeper_index(&broker, &caller)
        };
        require!(is_owner || keeper_index.is_some(), ERR_UNAUTHORIZED);
        if let Some(index) = keeper_index {
            require!(
                broker.delegates[index]
                    .allowed_operations
                    .contains(&KeeperOperation::Settle),
                ERR_UNAUTHORIZED
            );
        }
        require!(
            args.amount.0 > 0 && args.amount.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        if let Some(index) = keeper_index {
            let now = now_seconds();
            let grant = broker
                .delegates
                .get_mut(index)
                .unwrap_or_else(|| env::panic_str(ERR_UNAUTHORIZED));
            require!(grant.active && now <= grant.expires_at, ERR_EXPIRED);
            if now >= grant.window_started_at.saturating_add(grant.window_seconds) {
                grant.window_started_at = now;
                grant.window_spent = 0;
            }
            require!(
                args.amount.0 <= grant.allowed_settlement_per_operation,
                ERR_DEBT_LIMIT
            );
            require!(
                grant.window_spent.saturating_add(args.amount.0)
                    <= grant.allowed_settlement_per_window,
                ERR_DEBT_LIMIT
            );
            grant.window_spent = grant
                .window_spent
                .checked_add(args.amount.0)
                .unwrap_or_else(|| env::panic_str(ERR_DEBT_LIMIT));
        }
        require!(
            broker.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        require!(
            broker.accounting_version == args.expected_accounting_version,
            ERR_STALE_STATE
        );
        require!(
            !self.is_canonical_zero_for(
                &broker.encryption_key.public_key,
                &format!("broker:{}:spending", broker.broker_id),
                broker.encryption_key.key_id,
                broker.encryption_key.authorization_epoch,
                &broker.spending_ciphertext,
            ),
            ERR_INSUFFICIENT_PRIVATE_FUNDS
        );
        if let Some(reconciliation) = args.reconciliation.as_ref() {
            require!(reconciliation.broker_id == args.broker_id, ERR_WRONG_ASSET);
        }
        if broker.impairment_provision > 0 {
            require!(args.reconciliation.is_some(), ERR_ACCOUNTING_PENDING);
        }
        let mut vault = self.vault_or_panic(broker.vault_id);
        for ciphertext in [
            &args.broker_spending_ciphertext,
            &args.broker_issuer_ciphertext,
            &args.broker_auditor_ciphertext,
        ] {
            if !ciphertext.is_empty() {
                validate_ciphertext(ciphertext);
            }
        }
        if !args.settlement_views.is_empty() {
            require!(args.settlement_views.len() == 3, ERR_INVALID_ENCODING);
            validate_ciphertext_set(&args.settlement_views, 3);
        }
        require!(
            self.is_canonical_zero_for(
                &broker.encryption_key.public_key,
                &format!("broker:{}:inbox", broker.broker_id),
                broker.encryption_key.key_id,
                broker.encryption_key.authorization_epoch,
                &broker.inbox_ciphertext,
            ),
            ERR_BAD_PROOF
        );
        let context = self.crypto_context_with_subject(
            "settle",
            broker.vault_id,
            broker.broker_id,
            0,
            0,
            [
                broker.spending_version,
                broker.accounting_version,
                vault.accounting_version,
                args.amount.0 as u64,
                0,
                0,
                broker.encryption_key.key_id,
                0,
            ],
            [broker.encryption_key.authorization_epoch, 0, 0, 0],
            0,
            broker.owner.as_ref(),
        );
        let statement =
            self.verify_typed_statement(&args.proof, StatementKind::PublicConversion, &context);
        let Statement::PublicConversion(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        require!(
            statement.owner_key
                == crypto_adapter::parse_public_key(&broker.encryption_key.public_key)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.spending_before
                == crypto_adapter::parse_ciphertext(&broker.spending_ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
                && statement.public_amount == args.amount.0 as u64
                && statement.mode == ConversionMode::Debit
                && statement.spending_version == broker.spending_version,
            ERR_BAD_PROOF
        );
        if !args.broker_spending_ciphertext.is_empty() {
            require!(
                statement.spending_after
                    == crypto_adapter::parse_ciphertext(&args.broker_spending_ciphertext)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        let settle_keys = [
            &broker.encryption_key.public_key,
            &self.asset.issuer_key.public_key,
            &self.asset.token_auditor_key.public_key,
        ];
        let settle_views = args.settlement_views.as_slice();
        for index in 0..3 {
            require!(
                statement.views[index].reader_key
                    == crypto_adapter::parse_public_key(settle_keys[index])
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
            if !settle_views.is_empty() {
                require!(
                    statement.views[index].ciphertext
                        == crypto_adapter::parse_ciphertext(&settle_views[index])
                            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                    ERR_BAD_PROOF
                );
            }
        }
        let new_issuer = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.issuer_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.views[1].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let new_auditor = crypto_adapter::sub_ciphertexts(
            &crypto_adapter::parse_ciphertext(&broker.auditor_balance_ciphertext)
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            &statement.views[2].ciphertext,
        )
        .and_then(|value| crypto_adapter::encode(&value))
        .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.broker_issuer_ciphertext.is_empty() {
            require!(new_issuer == args.broker_issuer_ciphertext, ERR_BAD_PROOF);
        }
        if !args.broker_auditor_ciphertext.is_empty() {
            require!(new_auditor == args.broker_auditor_ciphertext, ERR_BAD_PROOF);
        }
        let statement_spending_after = crypto_adapter::encode(&statement.spending_after)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        self.record_recovery(
            "settle",
            &args.proof.statement,
            &[format!("broker:{}", broker.broker_id)],
            &[
                broker.encryption_key.key_id,
                self.asset.issuer_key.key_id,
                self.asset.token_auditor_key.key_id,
            ],
            &[broker.spending_version, broker.accounting_version],
        );
        let principal_return = args.amount.0.min(broker.debt_total);
        let realized_yield = args
            .amount
            .0
            .checked_sub(principal_return)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        require!(
            vault.assets_available.saturating_add(args.amount.0) <= self.asset.custody_cap,
            ERR_INVALID_AMOUNT
        );
        // A bundled checkpoint is evaluated against the virtual state after
        // this settlement.  It is never handed to the standalone method
        // after writes, which would permit a pre-settlement proof to be
        // replayed or make the accounting versions inconsistent.
        let bundled_reconciliation = if let Some(reconciliation) = args.reconciliation.as_ref() {
            let checkpoint = if reconciliation.checkpoint_id == 0 {
                // A scoped keeper cannot call `prepare_reconciliation`.  The
                // zero sentinel asks Core to derive and consume the next
                // checkpoint atomically with this settlement.  The client
                // binds its proof to that derived ID through the
                // `settle-reconcile` proof-context view.
                require!(broker.reconciliation_checkpoint_id.is_none(), ERR_REPLAY);
                require!(
                    broker.accounting_pending || broker.impairment_provision > 0,
                    ERR_ACCOUNTING_PENDING
                );
                let scheduled_at = self.reconciliation_scheduled_at(&broker, &vault);
                require!(now_seconds() >= scheduled_at, ERR_TOO_SOON);
                let checkpoint_id = self
                    .checkpoint_sequence
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                Checkpoint {
                    checkpoint_id,
                    broker_id: broker.broker_id,
                    risk_version: broker.risk_version,
                    accounting_version: broker.accounting_version,
                    scheduled_at,
                    consumed: false,
                }
            } else {
                require!(
                    broker.reconciliation_checkpoint_id == Some(reconciliation.checkpoint_id),
                    ERR_STALE_STATE
                );
                self.checkpoints
                    .get(&reconciliation.checkpoint_id)
                    .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
            };
            let mut post_broker = broker.clone();
            post_broker.reconciliation_checkpoint_id = Some(checkpoint.checkpoint_id);
            post_broker.spending_ciphertext = statement_spending_after.clone();
            post_broker.issuer_balance_ciphertext = new_issuer.clone();
            post_broker.auditor_balance_ciphertext = new_auditor.clone();
            post_broker.spending_version = broker
                .spending_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            post_broker.debt_total = broker
                .debt_total
                .checked_sub(principal_return)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            post_broker.cumulative_settlements = broker
                .cumulative_settlements
                .checked_add(args.amount.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            post_broker.cumulative_yield = broker
                .cumulative_yield
                .checked_add(realized_yield)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            post_broker.accounting_version = broker
                .accounting_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            let mut post_vault = vault.clone();
            post_vault.assets_available = vault
                .assets_available
                .checked_add(args.amount.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            post_vault.assets_total = vault
                .assets_total
                .checked_add(realized_yield)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            post_vault.accounting_version = vault
                .accounting_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            require!(
                reconciliation.expected_risk_version == post_broker.risk_version
                    && reconciliation.expected_accounting_version == post_broker.accounting_version,
                ERR_STALE_STATE
            );
            let context = self.crypto_context_with_subject(
                "reconcile-credit",
                post_broker.vault_id,
                post_broker.broker_id,
                0,
                0,
                [
                    post_broker.risk_version,
                    post_broker.accounting_version,
                    post_broker.book_version,
                    checkpoint.checkpoint_id,
                    checkpoint.accounting_version,
                    0,
                    0,
                    0,
                ],
                [post_broker.encryption_key.authorization_epoch, 0, 0, 0],
                checkpoint.scheduled_at,
                post_broker.owner.as_ref(),
            );
            let checked = self.validate_reconciliation(
                reconciliation,
                &checkpoint,
                &post_broker,
                &post_vault,
                &context,
            );
            Some((reconciliation.clone(), checkpoint, checked))
        } else {
            None
        };
        broker.spending_ciphertext = statement_spending_after;
        broker.issuer_balance_ciphertext = new_issuer;
        broker.auditor_balance_ciphertext = new_auditor;
        if !args.broker_spending_commitment.is_empty() {
            require!(
                args.broker_spending_commitment == broker.spending_commitment,
                ERR_BAD_PROOF
            );
        }
        if !args.broker_inbox_commitment.is_empty() {
            require!(
                args.broker_inbox_commitment == broker.inbox_commitment,
                ERR_BAD_PROOF
            );
        }
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.debt_total = broker
            .debt_total
            .checked_sub(principal_return)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.cumulative_settlements = broker
            .cumulative_settlements
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.cumulative_yield = broker
            .cumulative_yield
            .checked_add(realized_yield)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        broker.last_settlement_at = now_seconds();
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        vault.assets_available = vault
            .assets_available
            .checked_add(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.assets_total = vault
            .assets_total
            .checked_add(realized_yield)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INSUFFICIENT_PRIVATE_FUNDS));
        if broker.impairment_provision > 0 {
            if !was_broker_accounting_pending {
                broker.accounting_pending_since = now_seconds();
                vault.pending_broker_count = vault
                    .pending_broker_count
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            broker.accounting_pending = true;
            vault.accounting_pending = true;
        }
        if let Some((reconcile, mut checkpoint, checked)) = bundled_reconciliation {
            self.record_recovery(
                "reconcile-credit",
                &reconcile.proof.statement,
                &[format!("broker:{}", broker.broker_id)],
                &[
                    broker.encryption_key.key_id,
                    self.asset.issuer_key.key_id,
                    self.asset.token_auditor_key.key_id,
                ],
                &[broker.risk_version, broker.accounting_version],
            );
            // The settlement block above may have introduced the broker into
            // the pending set.  Consume exactly that one pending slot while
            // applying the post-settlement checkpoint; unrelated brokers stay
            // represented by the bounded counter.
            if !broker.accounting_pending && was_broker_accounting_pending {
                env::panic_str(ERR_STALE_STATE);
            }
            if broker.accounting_pending {
                vault.pending_broker_count = vault
                    .pending_broker_count
                    .checked_sub(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            }
            vault.assets_total = reconcile.new_vault_total.0;
            vault.loss_unrealized = checked.new_vault_provision;
            vault.accounting_version = vault
                .accounting_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            broker.debt_total = reconcile.new_broker_debt.0;
            broker.impairment_provision = reconcile.new_broker_provision.0;
            broker.cumulative_realized_losses = broker
                .cumulative_realized_losses
                .checked_add(reconcile.loss.0)
                .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
            broker.accounting_pending = false;
            broker.accounting_pending_since = 0;
            broker.reconciliation_checkpoint_id = None;
            broker.reconciled_risk_version = broker.risk_version;
            broker.accounting_version = broker
                .accounting_version
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            checkpoint.consumed = true;
            vault.accounting_pending = vault.pending_broker_count > 0;
            if !vault.accounting_pending {
                vault.reconciled_risk_version = vault.risk_version;
            }
            if reconcile.checkpoint_id == 0 {
                self.checkpoint_sequence = checkpoint.checkpoint_id;
            }
            self.checkpoints
                .insert(&checkpoint.checkpoint_id, &checkpoint);
            self.emit(
                "CreditReconciled",
                json!({
                    "checkpoint_id": checkpoint.checkpoint_id.to_string(),
                    "broker_id": reconcile.broker_id.to_string(),
                    "loss": reconcile.loss.0.to_string(),
                    "new_broker_debt": reconcile.new_broker_debt.0.to_string(),
                    "new_broker_provision": reconcile.new_broker_provision.0.to_string(),
                    "new_vault_total": reconcile.new_vault_total.0.to_string(),
                    "risk_version": broker.risk_version.to_string(),
                    "accounting_version": broker.accounting_version.to_string()
                }),
            );
        }
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        self.emit(
            "BrokerSettled",
            json!({
                "broker_id": args.broker_id.to_string(),
                "vault_id": vault.vault_id.to_string(),
                "amount": args.amount.0.to_string(),
                "principal_return": principal_return.to_string(),
                "realized_yield": realized_yield.to_string(),
                "spending_version": broker.spending_version.to_string(),
                "accounting_version": broker.accounting_version.to_string()
            }),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn grant_keeper(&mut self, args: GrantKeeperArgs) {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let mut broker = self.broker_or_panic(args.broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        let now = now_seconds();
        require!(
            args.allowed_settlement_per_operation.0 > 0,
            ERR_INVALID_AMOUNT
        );
        require!(
            args.allowed_settlement_per_window.0 >= args.allowed_settlement_per_operation.0,
            ERR_INVALID_AMOUNT
        );
        require!(
            args.window_seconds > 0
                && args.expires_at > now
                && now.checked_add(args.window_seconds).is_some(),
            ERR_INVALID_AMOUNT
        );
        require!(
            !args.allowed_operations.is_empty()
                && args.allowed_operations.len() <= 2
                && args.allowed_operations.iter().all(|operation| matches!(
                    operation,
                    KeeperOperation::MergeInbox | KeeperOperation::Settle
                )),
            ERR_INVALID_AMOUNT
        );
        require!(
            args.allowed_operations
                .iter()
                .enumerate()
                .all(|(index, operation)| {
                    args.allowed_operations[index + 1..]
                        .iter()
                        .all(|other| other != operation)
                }),
            ERR_INVALID_AMOUNT
        );
        let delegate_key = self
            .authorization_keys
            .get(&authorization_key(
                &args.delegate_account,
                args.delegate_key_id,
            ))
            .unwrap_or_else(|| env::panic_str(ERR_UNAUTHORIZED));
        require!(
            delegate_key.owner == args.delegate_account
                && !delegate_key.revoked
                && delegate_key.epoch == args.delegate_epoch,
            ERR_UNAUTHORIZED
        );
        // Delegate slots are a bounded live capability set, not an append-only
        // grant log.  Expired/revoked entries can never authorize a call and
        // must not make a broker permanently unable to renew a keeper.  A
        // replacement is done in place so there is at most one effective grant
        // for each delegate account.
        broker
            .delegates
            .retain(|grant| grant.active && now <= grant.expires_at);
        let existing_index = broker
            .delegates
            .iter()
            .position(|grant| grant.delegate_account == args.delegate_account);
        require!(
            existing_index.is_some() || broker.delegates.len() < MAX_DELEGATES,
            ERR_INVALID_AMOUNT
        );
        let epoch = broker
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.authorization_epoch = epoch;
        for grant in &mut broker.delegates {
            if grant.active {
                grant.revocation_epoch = epoch;
            }
        }
        // A live grant replacement is not a rate-limit reset.  Carry the
        // current window's spend into the replacement (and start that window
        // at `now`) so a broker owner cannot repeatedly redelegate the same
        // keeper to bypass the per-window cap.  Expired grants were pruned
        // above and therefore start with a fresh window.
        let carried_window_spent = existing_index
            .and_then(|index| broker.delegates.get(index))
            .filter(|grant| now < grant.window_started_at.saturating_add(grant.window_seconds))
            .map(|grant| grant.window_spent)
            .unwrap_or(0);
        let replacement = KeeperGrant {
            delegate_account: args.delegate_account.clone(),
            delegate_key_id: args.delegate_key_id,
            allowed_settlement_per_operation: args.allowed_settlement_per_operation.0,
            allowed_settlement_per_window: args.allowed_settlement_per_window.0,
            window_seconds: args.window_seconds,
            window_started_at: now,
            window_spent: carried_window_spent,
            expires_at: args.expires_at,
            revocation_epoch: epoch,
            delegate_epoch: args.delegate_epoch,
            active: true,
            allowed_operations: args.allowed_operations,
        };
        if let Some(index) = existing_index {
            broker.delegates[index] = replacement;
        } else {
            broker.delegates.push(replacement);
        }
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.brokers.insert(&args.broker_id, &broker);
        self.emit(
            "KeeperGranted",
            json!({
                "broker_id": args.broker_id.to_string(),
                "delegate": args.delegate_account,
                "epoch": epoch.to_string(),
                "replaced": existing_index.is_some()
            }),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn revoke_keeper(&mut self, broker_id: U64, delegate_account: AccountId) {
        let broker_id = broker_id.0;
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let mut broker = self.broker_or_panic(broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        let epoch = broker
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        broker.authorization_epoch = epoch;
        for grant in &mut broker.delegates {
            if grant.delegate_account == delegate_account {
                grant.active = false;
                grant.revocation_epoch = epoch;
            } else if grant.active {
                grant.revocation_epoch = epoch;
            }
        }
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.brokers.insert(&broker_id, &broker);
        self.emit(
            "KeeperRevoked",
            json!({"broker_id": broker_id.to_string(), "delegate": delegate_account, "epoch": epoch.to_string()}),
        );
        self.charge_storage(&caller, storage_before);
    }

    pub fn delete_loan(&mut self, loan_id: U64, evidence: Vec<u8>) {
        let loan_id = loan_id.0;
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        require!(!self.loan_tombstones.contains_key(&loan_id), ERR_REPLAY);
        let loan = self.loan_or_panic(loan_id);
        let mut broker = self.broker_or_panic(loan.broker_id);
        require!(
            caller == loan.borrower || caller == broker.owner,
            ERR_UNAUTHORIZED
        );
        require!(
            !matches!(loan.status, LoanStatus::Active),
            ERR_HAS_OBLIGATIONS
        );
        require!(!broker.accounting_pending, ERR_ACCOUNTING_PENDING);
        require!(!loan.tombstoned, ERR_REPLAY);
        let removal_evidence = if evidence.is_empty() {
            loan.accounting_leaf.clone()
        } else {
            require!(evidence == loan.accounting_leaf, ERR_BAD_PROOF);
            evidence
        };
        let tombstone_leaf = derive_tombstone_leaf(
            loan.loan_id,
            &loan.status,
            loan.loan_version,
            &loan.accounting_leaf,
        );
        let recomputed_leaf = derive_loan_leaf(
            loan.loan_id,
            loan.broker_id,
            &loan.borrower,
            loan.proposal_id,
            &loan.status,
            loan.loan_version,
            loan.payment_remaining,
            &loan.principal_remaining_ciphertexts,
            &loan.amount_owed_ciphertexts,
            &loan.periodic_payment_ciphertexts,
            &loan.principal_remaining_commitment,
        );
        require!(recomputed_leaf == loan.accounting_leaf, ERR_BAD_PROOF);
        let next_root = self.update_loan_book(
            broker.broker_id,
            loan.loan_id,
            &broker.loan_book_root,
            Some(&loan.accounting_leaf),
            Some(&tombstone_leaf),
        );
        let tombstone = BookTombstone {
            id: loan_id,
            final_status: loan.status.clone(),
            final_version: loan.loan_version,
            leaf: tombstone_leaf,
            removal_evidence,
        };
        self.loan_tombstones.insert(&loan_id, &tombstone);
        self.loans.remove(&loan_id);
        broker.loan_book_root = next_root;
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.brokers.insert(&broker.broker_id, &broker);
        self.emit("LoanDeleted", json!({"loan_id": loan_id.to_string(), "broker_id": loan.broker_id.to_string(), "final_version": loan.loan_version.to_string()}));
        self.charge_storage(&caller, storage_before);
    }

    pub fn delete_broker(&mut self, broker_id: U64, zero_proof: BrokerZeroProofArgs) {
        let broker_id = broker_id.0;
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        let broker = self.broker_or_panic(broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(broker.debt_total == 0, ERR_HAS_OBLIGATIONS);
        require!(broker.impairment_provision == 0, ERR_HAS_OBLIGATIONS);
        require!(
            broker.active_loan_count == 0 && broker.impaired_loan_count == 0,
            ERR_HAS_OBLIGATIONS
        );
        require!(zero_proof.broker_id == broker_id, ERR_BAD_PROOF);
        require!(!broker.accounting_pending, ERR_ACCOUNTING_PENDING);
        require!(
            broker.reconciliation_checkpoint_id.is_none(),
            ERR_ACCOUNTING_PENDING
        );
        if let Some(proof) = zero_proof.combined_proof.as_ref() {
            let combined = combine_ciphertexts(
                &combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext),
                &combine_ciphertexts(
                    &broker.active_principal_ciphertext,
                    &broker.impaired_principal_ciphertext,
                ),
            );
            let context = self.crypto_context_with_subject(
                "broker-zero-total",
                broker.vault_id,
                broker.broker_id,
                0,
                0,
                [
                    broker.spending_version,
                    broker.accounting_version,
                    broker.book_version,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
                "total",
            );
            self.verify_zero_balance_statement(
                proof,
                &context,
                &broker.encryption_key.public_key,
                &combined,
                broker.spending_version,
            );
        } else {
            let spending_context = self.crypto_context_with_subject(
                "broker-zero-spending",
                broker.vault_id,
                broker.broker_id,
                0,
                0,
                [
                    broker.spending_version,
                    broker.accounting_version,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
                "spending",
            );
            self.verify_zero_balance_statement(
                zero_proof
                    .spending_proof
                    .as_ref()
                    .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                &spending_context,
                &broker.encryption_key.public_key,
                &broker.spending_ciphertext,
                broker.spending_version,
            );
            let inbox_context = self.crypto_context_with_subject(
                "broker-zero-inbox",
                broker.vault_id,
                broker.broker_id,
                0,
                0,
                [
                    broker.spending_version,
                    broker.accounting_version,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
                "inbox",
            );
            self.verify_zero_balance_statement(
                zero_proof
                    .inbox_proof
                    .as_ref()
                    .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                &inbox_context,
                &broker.encryption_key.public_key,
                &broker.inbox_ciphertext,
                broker.spending_version,
            );
            let active_context = self.crypto_context_with_subject(
                "broker-zero-active-principal",
                broker.vault_id,
                broker.broker_id,
                0,
                0,
                [
                    broker.spending_version,
                    broker.accounting_version,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
                "active-principal",
            );
            self.verify_zero_balance_statement(
                zero_proof
                    .active_principal_proof
                    .as_ref()
                    .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                &active_context,
                &broker.encryption_key.public_key,
                &broker.active_principal_ciphertext,
                broker.spending_version,
            );
            let impaired_context = self.crypto_context_with_subject(
                "broker-zero-impaired-principal",
                broker.vault_id,
                broker.broker_id,
                0,
                0,
                [
                    broker.spending_version,
                    broker.accounting_version,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                [broker.encryption_key.authorization_epoch, 0, 0, 0],
                0,
                "impaired-principal",
            );
            self.verify_zero_balance_statement(
                zero_proof
                    .impaired_principal_proof
                    .as_ref()
                    .unwrap_or_else(|| env::panic_str(ERR_BAD_PROOF)),
                &impaired_context,
                &broker.encryption_key.public_key,
                &broker.impaired_principal_ciphertext,
                broker.spending_version,
            );
        }
        self.brokers.remove(&broker_id);
        self.broker_tombstones.insert(&broker_id);
        if let Some(mut broker_ids) = self.vault_brokers.get(&broker.vault_id) {
            broker_ids.retain(|id| *id != broker_id);
            self.vault_brokers.insert(&broker.vault_id, &broker_ids);
        }
        self.emit(
            "BrokerDeleted",
            json!({"broker_id": broker_id.to_string(), "vault_id": broker.vault_id.to_string()}),
        );
        self.charge_storage(&caller, storage_before);
    }

    #[payable]
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let token = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        if token != self.asset.token_account
            || self.asset_frozen
            || !self.verifier.activated
            || amount.0 == 0
            || amount.0 > self.asset.custody_cap
            || self
                .custody_total
                .checked_add(amount.0)
                .map(|total| total > self.asset.custody_cap)
                .unwrap_or(true)
        {
            return PromiseOrValue::Value(amount);
        }
        let parsed = serde_json::from_str::<DepositMessage>(&msg);
        let Ok(message) = parsed else {
            return PromiseOrValue::Value(amount);
        };
        if message.version != 1
            || message.deposit_id.is_empty()
            || message.deposit_id.len() > MAX_ID_BYTES
        {
            return PromiseOrValue::Value(amount);
        }
        let key = deposit_key(&token, &sender_id, &message.deposit_id);
        // Hash the parsed, strict message rather than the transport JSON.  The
        // Borsh tuple is canonical: equivalent JSON whitespace/key ordering
        // cannot create a second receipt for the same `(version, deposit_id)`.
        let payload_hash = hash_bytes(&(
            token.clone(),
            sender_id.clone(),
            amount.0,
            message.version,
            message.deposit_id.clone(),
        ));
        if let Some(existing) = self.receipts.get(&key) {
            if existing.payload_hash == payload_hash && existing.amount == amount.0 {
                return PromiseOrValue::Value(amount);
            }
            return PromiseOrValue::Value(amount);
        }
        let claim_id = self.next_claim_id();
        self.claims.insert(
            &claim_id,
            &PublicClaim {
                claim_id,
                owner: sender_id.clone(),
                amount: amount.0,
                created_at: now_seconds(),
                reserved_by: None,
            },
        );
        self.receipts.insert(
            &key,
            &DepositReceipt {
                token_account: token,
                sender: sender_id.clone(),
                deposit_id: message.deposit_id.clone(),
                amount: amount.0,
                payload_hash,
                status: DepositStatus::Accepted,
                claim_id,
                accepted_at: now_seconds(),
            },
        );
        self.public_claim_total = self
            .public_claim_total
            .checked_add(amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.custody_total = self
            .custody_total
            .checked_add(amount.0)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.emit("DepositReceived", json!({"sender": sender_id, "deposit_id": message.deposit_id, "claim_id": claim_id.to_string(), "amount": amount.0.to_string()}));
        self.charge_storage(&sender_id, storage_before);
        PromiseOrValue::Value(U128(0))
    }

    pub fn request_payout(&mut self, args: RequestPayoutArgs) -> Promise {
        let caller = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.ensure_verifier_active();
        self.ensure_asset_unfrozen();
        require!(args.operation_id > 0, ERR_INVALID_AMOUNT);
        require!(
            self.payouts.get(&args.operation_id).is_none()
                && !self.payout_tombstones.contains(&args.operation_id),
            ERR_REPLAY
        );
        let mut claim = self.claim_or_panic(args.claim_id);
        require!(
            claim.owner == caller && claim.reserved_by.is_none(),
            ERR_UNAUTHORIZED
        );
        require!(claim.amount > 0, ERR_INVALID_AMOUNT);
        let call_hash = hash_bytes(&(
            self.asset.token_account.clone(),
            args.recipient.clone(),
            claim.amount,
            args.operation_id,
            1u32,
        ));
        claim.reserved_by = Some(args.operation_id);
        let operation = PayoutOperation {
            operation_id: args.operation_id,
            owner: caller.clone(),
            recipient: args.recipient.clone(),
            amount: claim.amount,
            claim_id: args.claim_id,
            attempt: 1,
            call_hash: call_hash.clone(),
            status: PayoutStatus::InFlight,
            result_hash: [0; 32],
            result_tag: 0,
            created_at: now_seconds(),
        };
        self.claims.insert(&args.claim_id, &claim);
        self.payouts.insert(&args.operation_id, &operation);
        self.payout_sequence = self
            .payout_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.payout_index
            .insert(&self.payout_sequence, &args.operation_id);
        self.payout_reserved_total = self
            .payout_reserved_total
            .checked_add(claim.amount)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
        self.emit("PayoutRequested", json!({"operation_id": args.operation_id.to_string(), "claim_id": args.claim_id.to_string(), "owner": caller, "recipient": args.recipient, "amount": claim.amount.to_string()}));
        self.charge_storage(&caller, storage_before);
        ext_ft::ext(self.asset.token_account.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(PAYOUT_GAS)
            .ft_transfer(
                args.recipient,
                U128(claim.amount),
                Some(format!("core-payout:{}", args.operation_id)),
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(PAYOUT_GAS)
                    .on_payout_result(U64(args.operation_id), 1, call_hash),
            )
    }

    #[private]
    pub fn on_payout_result(
        &mut self,
        operation_id: U64,
        attempt: u32,
        result_hash: Vec<u8>,
    ) -> bool {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            ERR_UNAUTHORIZED
        );
        require!(env::promise_results_count() == 1, ERR_BAD_PROOF);
        let operation_id = operation_id.0;
        let mut operation = self.payout_or_panic(operation_id);
        require!(operation.attempt == attempt, ERR_STALE_STATE);
        require!(operation.call_hash == result_hash, ERR_STALE_STATE);
        require!(
            matches!(operation.status, PayoutStatus::InFlight),
            ERR_REPLAY
        );
        let (success, result_hash) = match env::promise_result_checked(0, 4096) {
            Ok(bytes) => (true, hash_bytes(&bytes)),
            Err(PromiseError::Failed) => (false, hash_bytes(&b"failed".to_vec())),
            // A successful token call with an oversized return value is still
            // a successful transfer.  Persist only a fixed marker and the
            // observed length; never attempt to retain an unbounded callback
            // payload or refund a claim after tokens may have left.
            Err(PromiseError::TooLong(length)) => (
                true,
                hash_bytes(&(b"success-too-long-v1".to_vec(), length as u64)),
            ),
            // Future runtime error variants remain locked rather than being
            // guessed as failures and refunded.
            Err(_) => return false,
        };
        let result_hash: [u8; 32] = result_hash
            .try_into()
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        operation.result_hash = result_hash;
        operation.result_tag = if success { 1 } else { 2 };
        operation.status = if success {
            PayoutStatus::ResultRecordedSuccess
        } else {
            PayoutStatus::ResultRecordedFailure
        };
        self.payouts.insert(&operation_id, &operation);
        self.emit(
            "PayoutResultRecorded",
            json!({"operation_id": operation_id.to_string(), "attempt": attempt.to_string(), "success": success}),
        );
        success
    }

    pub fn finalize_payout(&mut self, operation_id: U64) {
        let operation_id = operation_id.0;
        let mut operation = self.payout_or_panic(operation_id);
        if matches!(
            operation.status,
            PayoutStatus::Succeeded | PayoutStatus::Failed
        ) {
            return;
        }
        let mut claim = self.claim_or_panic(operation.claim_id);
        require!(claim.reserved_by == Some(operation_id), ERR_STALE_STATE);
        match operation.status {
            PayoutStatus::ResultRecordedSuccess => {
                self.claims.remove(&operation.claim_id);
                self.public_claim_total = self
                    .public_claim_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
                self.payout_reserved_total = self
                    .payout_reserved_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
                self.custody_total = self
                    .custody_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
                operation.status = PayoutStatus::Succeeded;
            }
            PayoutStatus::ResultRecordedFailure => {
                claim.reserved_by = None;
                self.claims.insert(&operation.claim_id, &claim);
                self.payout_reserved_total = self
                    .payout_reserved_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT));
                operation.status = PayoutStatus::Failed;
            }
            PayoutStatus::InFlight => env::panic_str(ERR_OPERATION_PENDING),
            PayoutStatus::Succeeded | PayoutStatus::Failed => return,
        }
        self.payouts.insert(&operation_id, &operation);
        // The terminal PayoutOperation itself is the permanent replay
        // tombstone.  Avoid a second grow-only set write in the permissionless
        // finalizer so callback/finalization never depends on fresh storage.
        self.emit(
            "PayoutFinalized",
            json!({"operation_id": operation_id.to_string(), "status": operation.status}),
        );
    }
}

#[near_bindgen]
impl Core {
    pub fn get_vault(&self, vault_id: U64) -> Option<VaultView> {
        self.vaults
            .get(&vault_id.0)
            .map(|vault| self.vault_view(vault))
    }

    pub fn get_broker(&self, broker_id: U64) -> Option<BrokerView> {
        self.brokers.get(&broker_id.0).map(|broker| BrokerView {
            broker_id: broker.broker_id,
            owner: broker.owner,
            vault_id: broker.vault_id,
            debt_total: U128(broker.debt_total),
            debt_maximum: U128(broker.debt_maximum),
            active_loan_count: broker.active_loan_count,
            impaired_loan_count: broker.impaired_loan_count,
            spending_version: broker.spending_version,
            book_version: broker.book_version,
            loan_book_root: broker.loan_book_root,
            encryption_key_id: broker.encryption_key.key_id,
            encryption_public_key: broker.encryption_key.public_key,
            authorization_epoch: broker.authorization_epoch,
            spending_ciphertext: broker.spending_ciphertext,
            inbox_ciphertext: broker.inbox_ciphertext,
            issuer_balance_ciphertext: broker.issuer_balance_ciphertext,
            auditor_balance_ciphertext: broker.auditor_balance_ciphertext,
            spending_commitment: broker.spending_commitment,
            inbox_commitment: broker.inbox_commitment,
            active_principal_ciphertext: broker.active_principal_ciphertext,
            impaired_principal_ciphertext: broker.impaired_principal_ciphertext,
            active_principal_commitment: broker.active_principal_commitment,
            impaired_principal_commitment: broker.impaired_principal_commitment,
            impairment_provision: U128(broker.impairment_provision),
            accounting_version: broker.accounting_version,
            risk_version: broker.risk_version,
            reconciled_risk_version: broker.reconciled_risk_version,
            accounting_pending: broker.accounting_pending,
            accounting_pending_since: broker.accounting_pending_since,
            reconciliation_checkpoint_id: broker.reconciliation_checkpoint_id,
            delegates: broker.delegates.iter().map(keeper_grant_view).collect(),
            last_settlement_at: broker.last_settlement_at,
        })
    }

    pub fn get_keeper_grants(&self, broker_id: U64) -> Option<Vec<KeeperGrantView>> {
        self.brokers
            .get(&broker_id.0)
            .map(|broker| broker.delegates.iter().map(keeper_grant_view).collect())
    }

    pub fn get_holder(&self, owner: AccountId) -> Option<HolderView> {
        self.holders.get(&owner).map(|holder| HolderView {
            owner: holder.owner,
            asset_id: holder.asset_id,
            key_id: holder.encryption_key.key_id,
            encryption_public_key: holder.encryption_key.public_key,
            spending_ciphertext: holder.spending_ciphertext,
            inbox_ciphertext: holder.inbox_ciphertext,
            issuer_balance_ciphertext: holder.issuer_balance_ciphertext,
            auditor_balance_ciphertext: holder.auditor_balance_ciphertext,
            spending_version: holder.spending_version,
            authorization_epoch: holder.authorization_epoch,
            open_loan_count: holder.open_loan_count,
            recovery_start_sequence: holder.recovery_start_sequence,
        })
    }

    pub fn get_loan(&self, loan_id: U64) -> Option<LoanView> {
        self.loans.get(&loan_id.0).map(|loan| LoanView {
            loan_id: loan.loan_id,
            broker_id: loan.broker_id,
            borrower: loan.borrower,
            proposal_id: loan.proposal_id,
            start_time: loan.start_time,
            payment_interval: loan.payment_interval,
            grace_period: loan.grace_period,
            previous_due: loan.previous_due,
            next_due: match loan.status {
                LoanStatus::Active => Some(loan.next_due),
                LoanStatus::Paid | LoanStatus::Defaulted => None,
            },
            payment_total: loan.payment_total,
            payment_remaining: loan.payment_remaining,
            status: loan.status,
            impaired: loan.impaired,
            loan_version: loan.loan_version,
            borrower_key_id: loan.borrower_key_id,
            broker_key_id: loan.broker_key_id,
            loan_auditor_key_id: loan.loan_auditor_key_id,
            loan_auditor_public_key: loan.loan_auditor_public_key,
            principal_ciphertexts: loan.principal_ciphertexts,
            initial_owed_ciphertexts: loan.initial_owed_ciphertexts,
            amount_owed_ciphertexts: loan.amount_owed_ciphertexts,
            periodic_payment_ciphertexts: loan.periodic_payment_ciphertexts,
            principal_remaining_ciphertexts: loan.principal_remaining_ciphertexts,
            principal_remaining_commitment: loan.principal_remaining_commitment,
            cumulative_repaid_ciphertexts: loan.cumulative_repaid_ciphertexts,
            accounting_leaf: loan.accounting_leaf,
        })
    }

    /// Return the current holder encryption key, optionally requiring an
    /// exact key id.  Historical keys remain attributable through immutable
    /// loan/proof records; this endpoint never accepts a caller replacement.
    pub fn get_holder_key(&self, owner: AccountId, key_id: Option<U64>) -> Option<EncryptionKey> {
        self.holders.get(&owner).and_then(|holder| {
            if key_id.is_some_and(|expected| expected.0 != holder.encryption_key.key_id) {
                None
            } else {
                Some(holder.encryption_key)
            }
        })
    }

    /// Return the current broker encryption key, optionally requiring an
    /// exact key id.
    pub fn get_broker_key(&self, broker_id: U64, key_id: Option<U64>) -> Option<EncryptionKey> {
        self.brokers.get(&broker_id.0).and_then(|broker| {
            if key_id.is_some_and(|expected| expected.0 != broker.encryption_key.key_id) {
                None
            } else {
                Some(broker.encryption_key)
            }
        })
    }

    pub fn get_proposal(&self, proposal_id: U64) -> Option<Proposal> {
        self.proposals.get(&proposal_id.0)
    }

    pub fn get_claim(&self, claim_id: U64) -> Option<ClaimView> {
        self.claims.get(&claim_id.0).map(|claim| ClaimView {
            claim_id: claim.claim_id,
            owner: claim.owner,
            amount: U128(claim.amount),
            created_at: claim.created_at,
            reserved_by: claim.reserved_by,
        })
    }

    pub fn get_payout(&self, operation_id: U64) -> Option<PayoutView> {
        self.payouts
            .get(&operation_id.0)
            .map(|operation| PayoutView {
                operation_id: operation.operation_id,
                owner: operation.owner,
                recipient: operation.recipient,
                amount: U128(operation.amount),
                claim_id: operation.claim_id,
                attempt: operation.attempt,
                call_hash: operation.call_hash,
                status: operation.status,
                result_hash: operation.result_hash,
                result_tag: operation.result_tag,
                created_at: operation.created_at,
            })
    }

    pub fn get_checkpoint(&self, checkpoint_id: U64) -> Option<Checkpoint> {
        self.checkpoints.get(&checkpoint_id.0)
    }

    pub fn get_deposit_receipt(
        &self,
        token_account: AccountId,
        sender: AccountId,
        deposit_id: String,
    ) -> Option<DepositReceiptView> {
        self.receipts
            .get(&deposit_key(&token_account, &sender, &deposit_id))
            .map(|receipt| DepositReceiptView {
                token_account: receipt.token_account,
                sender: receipt.sender,
                deposit_id: receipt.deposit_id,
                amount: U128(receipt.amount),
                payload_hash: receipt.payload_hash,
                status: receipt.status,
                claim_id: receipt.claim_id,
                accepted_at: receipt.accepted_at,
            })
    }

    /// Return one bounded page of a vault's broker membership list.  The
    /// membership vector is append-only/tombstone-preserving, so `cursor` is
    /// an element offset rather than a broker ID and deleted entries cannot
    /// cause an unbounded scan.
    pub fn get_vault_broker_ids(&self, vault_id: U64, cursor: U64, limit: u32) -> Vec<U64> {
        bounded_limit(limit);
        let brokers = self.vault_brokers.get(&vault_id.0).unwrap_or_default();
        let start = usize::try_from(cursor.0).unwrap_or(usize::MAX);
        brokers
            .into_iter()
            .skip(start)
            .take(limit as usize)
            .map(U64)
            .collect()
    }

    pub fn list_vaults(&self, cursor: U64, limit: u32) -> Vec<VaultView> {
        bounded_limit(limit);
        let cursor = cursor.0;
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|id| self.vaults.get(&id))
            })
            .map(|vault| self.vault_view(vault))
            .collect()
    }

    pub fn list_brokers(
        &self,
        cursor: U64,
        owner: Option<AccountId>,
        limit: u32,
    ) -> Vec<BrokerView> {
        bounded_limit(limit);
        let cursor = cursor.0;
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|id| self.brokers.get(&id))
            })
            .filter(|broker| {
                owner
                    .as_ref()
                    .map(|value| value == &broker.owner)
                    .unwrap_or(true)
            })
            .map(|broker| BrokerView {
                broker_id: broker.broker_id,
                owner: broker.owner,
                vault_id: broker.vault_id,
                debt_total: U128(broker.debt_total),
                debt_maximum: U128(broker.debt_maximum),
                active_loan_count: broker.active_loan_count,
                impaired_loan_count: broker.impaired_loan_count,
                spending_version: broker.spending_version,
                book_version: broker.book_version,
                loan_book_root: broker.loan_book_root,
                encryption_key_id: broker.encryption_key.key_id,
                encryption_public_key: broker.encryption_key.public_key,
                authorization_epoch: broker.authorization_epoch,
                spending_ciphertext: broker.spending_ciphertext,
                inbox_ciphertext: broker.inbox_ciphertext,
                issuer_balance_ciphertext: broker.issuer_balance_ciphertext,
                auditor_balance_ciphertext: broker.auditor_balance_ciphertext,
                spending_commitment: broker.spending_commitment,
                inbox_commitment: broker.inbox_commitment,
                active_principal_ciphertext: broker.active_principal_ciphertext,
                impaired_principal_ciphertext: broker.impaired_principal_ciphertext,
                active_principal_commitment: broker.active_principal_commitment,
                impaired_principal_commitment: broker.impaired_principal_commitment,
                impairment_provision: U128(broker.impairment_provision),
                accounting_version: broker.accounting_version,
                risk_version: broker.risk_version,
                reconciled_risk_version: broker.reconciled_risk_version,
                accounting_pending: broker.accounting_pending,
                accounting_pending_since: broker.accounting_pending_since,
                reconciliation_checkpoint_id: broker.reconciliation_checkpoint_id,
                delegates: broker.delegates.iter().map(keeper_grant_view).collect(),
                last_settlement_at: broker.last_settlement_at,
            })
            .collect()
    }

    pub fn list_loans(
        &self,
        cursor: U64,
        borrower: Option<AccountId>,
        broker_id: Option<U64>,
        limit: u32,
    ) -> Vec<LoanView> {
        bounded_limit(limit);
        let cursor = cursor.0;
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|id| self.loans.get(&id))
            })
            .filter(|loan| {
                borrower
                    .as_ref()
                    .map(|value| value == &loan.borrower)
                    .unwrap_or(true)
                    && broker_id
                        .map(|value| value.0 == loan.broker_id)
                        .unwrap_or(true)
            })
            .map(|loan| self.loan_view(loan))
            .collect()
    }

    pub fn list_claims(&self, cursor: U64, owner: Option<AccountId>, limit: u32) -> Vec<ClaimView> {
        bounded_limit(limit);
        let cursor = cursor.0;
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|id| self.claims.get(&id))
            })
            .filter(|claim| {
                owner
                    .as_ref()
                    .map(|value| value == &claim.owner)
                    .unwrap_or(true)
            })
            .map(|claim| ClaimView {
                claim_id: claim.claim_id,
                owner: claim.owner,
                amount: U128(claim.amount),
                created_at: claim.created_at,
                reserved_by: claim.reserved_by,
            })
            .collect()
    }

    pub fn list_payouts(
        &self,
        cursor: U64,
        owner: Option<AccountId>,
        limit: u32,
    ) -> Vec<PayoutView> {
        bounded_limit(limit);
        let cursor = cursor.0;
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|index| self.payout_index.get(&index))
                    .and_then(|operation_id| self.payouts.get(&operation_id))
            })
            .filter(|operation| {
                owner
                    .as_ref()
                    .map(|value| value == &operation.owner)
                    .unwrap_or(true)
            })
            .map(|operation| PayoutView {
                operation_id: operation.operation_id,
                owner: operation.owner,
                recipient: operation.recipient,
                amount: U128(operation.amount),
                claim_id: operation.claim_id,
                attempt: operation.attempt,
                call_hash: operation.call_hash,
                status: operation.status,
                result_hash: operation.result_hash,
                result_tag: operation.result_tag,
                created_at: operation.created_at,
            })
            .collect()
    }

    pub fn public_totals(&self) -> (U128, U128, U128) {
        (
            U128(self.public_claim_total),
            U128(self.payout_reserved_total),
            U128(self.confidential_outstanding),
        )
    }

    pub fn get_custody_total(&self) -> U128 {
        U128(self.custody_total)
    }

    /// High-water marks let clients continue bounded ID-range pagination after
    /// deletions or filtered gaps without treating an empty page as end of
    /// stream.
    pub fn get_counters(&self) -> ProtocolCounters {
        ProtocolCounters {
            vault_high_water: self.vault_sequence,
            broker_high_water: self.broker_sequence,
            loan_high_water: self.loan_sequence,
            proposal_high_water: self.proposal_sequence,
            claim_high_water: self.claim_sequence,
            payout_high_water: self.payout_sequence,
            checkpoint_high_water: self.checkpoint_sequence,
            recovery_high_water: self.recovery_sequence,
        }
    }

    pub fn prepare_context(
        &self,
        operation: String,
        ids: Vec<u64>,
        account_ids: Vec<AccountId>,
        versions: Vec<u64>,
        state: Vec<u8>,
    ) -> ProofContextView {
        require!(operation.len() <= MAX_ID_BYTES, ERR_INVALID_ENCODING);
        require!(
            ids.len() <= 32 && account_ids.len() <= 32 && versions.len() <= 32,
            ERR_INVALID_ENCODING
        );
        ProofContextView {
            state_digest: hash_bytes(&(
                operation.clone(),
                ids.clone(),
                account_ids.clone(),
                versions.clone(),
                state,
            )),
            operation: operation.clone(),
            asset_account: self.asset.token_account.clone(),
            network_id: self.asset.network_id.clone(),
            profile_hash: self.asset.crypto_profile_hash.clone(),
            verifier_manifest_hash: self.verifier.manifest_hash.clone(),
            ids,
            account_ids,
            versions,
            ciphertexts: Vec::new(),
            commitments: Vec::new(),
            public_values: Vec::new(),
            statement_kind: statement_kind_for_operation(&operation),
            statement: Vec::new(),
            public_inputs: Vec::new(),
            verifying_key_hash: statement_kind_for_operation(&operation)
                .and_then(|kind| self.verifier_keys.get(&kind))
                .map(|key| key.verifying_key_hash)
                .unwrap_or_default(),
            operation_context: Vec::new(),
        }
    }

    /// Build the exact operation context used by a mutating method.  Unlike
    /// the legacy `get_operation_context` labels, this endpoint accepts the
    /// affected account/operation IDs explicitly and never relies on the RPC
    /// caller's predecessor identity.
    pub fn get_proof_context(&self, args: ProofContextArgs) -> Option<ProofContextView> {
        require!(args.operation.len() <= MAX_ID_BYTES, ERR_INVALID_ENCODING);
        let operation = args.operation.as_str();
        let mut view;
        let context = match operation {
            "holder-zero-total" => {
                let owner = args.account_id?;
                let holder = self.holders.get(&owner)?;
                let combined =
                    combine_ciphertexts(&holder.spending_ciphertext, &holder.inbox_ciphertext);
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![holder.encryption_key.key_id],
                    vec![owner.clone()],
                    vec![holder.spending_version, holder.authorization_epoch],
                    to_vec(&(
                        holder.encryption_key.key_id,
                        holder.spending_version,
                        holder.authorization_epoch,
                        combined.clone(),
                    ))
                    .unwrap_or_default(),
                );
                view.ciphertexts = vec![combined, holder.encryption_key.public_key.clone()];
                self.crypto_context_with_subject(
                    "holder-zero-total",
                    0,
                    0,
                    0,
                    0,
                    [holder.spending_version, 0, 0, 0, 0, 0, 0, 0],
                    [holder.authorization_epoch, 0, 0, 0],
                    0,
                    owner.as_ref(),
                )
            }
            "register-holder" => {
                let owner = args.account_id?;
                let key_id = args.key_id.or(args.primary_id)?;
                let authorization_epoch = self
                    .holders
                    .get(&owner)
                    .map(|holder| holder.authorization_epoch.checked_add(1))
                    .unwrap_or(Some(1))?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![key_id],
                    vec![owner.clone()],
                    vec![authorization_epoch],
                    to_vec(&(owner.clone(), key_id, authorization_epoch)).unwrap_or_default(),
                );
                self.crypto_context_with_subject(
                    "register-holder",
                    0,
                    0,
                    0,
                    0,
                    [key_id, 0, 0, 0, 0, 0, 0, 0],
                    [authorization_epoch, 0, 0, 0],
                    0,
                    owner.as_ref(),
                )
            }
            "create-broker" => {
                let owner = args.account_id?;
                let vault_id = args.primary_id?;
                let broker_id = args
                    .broker_id
                    .unwrap_or(self.broker_sequence.checked_add(1)?);
                let key_id = args.key_id?;
                let vault = self.vaults.get(&vault_id)?;
                require!(vault.owner == owner, ERR_UNAUTHORIZED);
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![vault_id, broker_id],
                    vec![owner.clone()],
                    vec![key_id],
                    to_vec(&(owner.clone(), vault_id, broker_id, key_id)).unwrap_or_default(),
                );
                self.crypto_context_with_subject(
                    "create-broker",
                    vault_id,
                    broker_id,
                    0,
                    0,
                    [key_id, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0],
                    0,
                    owner.as_ref(),
                )
            }
            "shield" => {
                let owner = args.account_id?;
                let holder = self.holders.get(&owner)?;
                let claim_id = args.primary_id?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![claim_id],
                    vec![owner.clone()],
                    vec![holder.spending_version, holder.authorization_epoch],
                    to_vec(&holder).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    holder.inbox_ciphertext.clone(),
                    holder.issuer_balance_ciphertext.clone(),
                    holder.auditor_balance_ciphertext.clone(),
                    holder.encryption_key.public_key.clone(),
                ];
                self.crypto_context_with_subject(
                    "shield",
                    0,
                    0,
                    0,
                    claim_id,
                    [holder.spending_version, claim_id, 0, 0, 0, 0, 0, 0],
                    [holder.authorization_epoch, 0, 0, 0],
                    0,
                    owner.as_ref(),
                )
            }
            "unshield" => {
                let owner = args.account_id?;
                let holder = self.holders.get(&owner)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![holder.spending_version],
                    vec![owner.clone()],
                    vec![holder.spending_version, holder.authorization_epoch],
                    to_vec(&holder).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    holder.spending_ciphertext.clone(),
                    holder.issuer_balance_ciphertext.clone(),
                    holder.auditor_balance_ciphertext.clone(),
                    holder.encryption_key.public_key.clone(),
                ];
                self.crypto_context_with_subject(
                    "unshield",
                    0,
                    0,
                    0,
                    holder.spending_version,
                    [holder.spending_version, 0, 0, 0, 0, 0, 0, 0],
                    [holder.authorization_epoch, 0, 0, 0],
                    0,
                    owner.as_ref(),
                )
            }
            "confidential-send" => {
                let sender = args.account_id?;
                let destination = args.destination?;
                let from = self.holders.get(&sender)?;
                let to = self.holders.get(&destination)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![from.spending_version, to.spending_version],
                    vec![sender.clone(), destination.clone()],
                    // Recipient inbox state is intentionally not a proof
                    // precondition: the mutator adds the proven delta to the
                    // current inbox, preserving concurrent credits.
                    vec![from.spending_version, 0],
                    to_vec(&(from.clone(), to.clone())).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    from.spending_ciphertext.clone(),
                    to.inbox_ciphertext.clone(),
                    from.issuer_balance_ciphertext.clone(),
                    from.auditor_balance_ciphertext.clone(),
                    to.issuer_balance_ciphertext.clone(),
                    to.auditor_balance_ciphertext.clone(),
                ];
                self.crypto_context_with_subject(
                    "confidential-send",
                    0,
                    0,
                    0,
                    0,
                    [
                        from.spending_version,
                        0,
                        from.encryption_key.key_id,
                        to.encryption_key.key_id,
                        0,
                        0,
                        0,
                        0,
                    ],
                    [from.authorization_epoch, to.authorization_epoch, 0, 0],
                    0,
                    destination.as_ref(),
                )
            }
            "draw" => {
                let broker_id = args.broker_id.or(args.primary_id)?;
                let broker = self.brokers.get(&broker_id)?;
                let vault = self.vaults.get(&broker.vault_id)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![broker_id, broker.vault_id],
                    vec![broker.owner.clone()],
                    vec![
                        broker.spending_version,
                        broker.accounting_version,
                        vault.accounting_version,
                    ],
                    to_vec(&(broker.clone(), vault.clone())).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    broker.inbox_ciphertext.clone(),
                    broker.issuer_balance_ciphertext.clone(),
                    broker.auditor_balance_ciphertext.clone(),
                ];
                self.crypto_context_with_subject(
                    "draw",
                    broker.vault_id,
                    broker.broker_id,
                    0,
                    0,
                    [
                        broker.spending_version,
                        broker.accounting_version,
                        vault.accounting_version,
                        0,
                        0,
                        0,
                        broker.encryption_key.key_id,
                        0,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    0,
                    broker.owner.as_ref(),
                )
            }
            "originate" => {
                let proposal_id = args.primary_id?;
                let proposal = self.proposals.get(&proposal_id)?;
                let broker = self.brokers.get(&proposal.broker_id)?;
                let borrower = self.holders.get(&proposal.borrower)?;
                let loan_id = self.loan_sequence.checked_add(1)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![proposal_id, proposal.broker_id, loan_id],
                    vec![proposal.borrower.clone(), broker.owner.clone()],
                    vec![broker.spending_version, borrower.spending_version],
                    to_vec(&(proposal.clone(), broker.clone(), borrower.clone()))
                        .unwrap_or_default(),
                );
                view.ciphertexts = proposal
                    .principal_ciphertexts
                    .iter()
                    .chain(proposal.initial_owed_ciphertexts.iter())
                    .chain(proposal.periodic_payment_ciphertexts.iter())
                    .cloned()
                    .collect();
                self.crypto_context_with_subject(
                    "originate",
                    proposal.vault_id,
                    proposal.broker_id,
                    loan_id,
                    proposal.proposal_id,
                    [
                        broker.spending_version,
                        0,
                        0,
                        proposal.payment_count as u64,
                        proposal.payment_interval,
                        proposal.grace_period,
                        proposal.broker_key_id,
                        proposal.borrower_key_id,
                    ],
                    [
                        proposal.broker_authorization_epoch,
                        proposal.borrower_authorization_epoch,
                        0,
                        0,
                    ],
                    proposal.expiry,
                    proposal.borrower.as_ref(),
                )
            }
            "repay" => {
                let loan_id = args.primary_id?;
                let loan = self.loans.get(&loan_id)?;
                let broker = self.brokers.get(&loan.broker_id)?;
                let borrower = self.holders.get(&loan.borrower)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![loan_id, loan.broker_id, loan.proposal_id],
                    vec![loan.borrower.clone(), broker.owner.clone()],
                    vec![
                        borrower.spending_version,
                        loan.loan_version,
                        broker.spending_version,
                        broker.book_version,
                    ],
                    to_vec(&(loan.clone(), broker.clone(), borrower.clone())).unwrap_or_default(),
                );
                view.ciphertexts = loan
                    .amount_owed_ciphertexts
                    .iter()
                    .chain(loan.principal_remaining_ciphertexts.iter())
                    .chain(loan.periodic_payment_ciphertexts.iter())
                    .cloned()
                    .collect();
                self.crypto_context_with_subject(
                    "repay",
                    0,
                    broker.broker_id,
                    loan.loan_id,
                    loan.proposal_id,
                    [
                        borrower.spending_version,
                        loan.loan_version,
                        broker.spending_version,
                        broker.book_version,
                        loan.payment_remaining as u64,
                        loan.payment_interval,
                        loan.borrower_key_id,
                        loan.broker_key_id,
                    ],
                    [
                        borrower.authorization_epoch,
                        broker.encryption_key.authorization_epoch,
                        0,
                        0,
                    ],
                    0,
                    borrower.owner.as_ref(),
                )
            }
            "manage-loan" => {
                let loan_id = args.primary_id?;
                let action = args.action.clone()?;
                let loan = self.loans.get(&loan_id)?;
                let broker = self.brokers.get(&loan.broker_id)?;
                let vault = self.vaults.get(&broker.vault_id)?;
                let post_impaired = match action {
                    LoanManagementAction::Impair => true,
                    LoanManagementAction::Unimpair => false,
                    LoanManagementAction::Default => false,
                };
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![loan_id, broker.broker_id, broker.vault_id],
                    vec![broker.owner.clone(), loan.borrower.clone()],
                    vec![
                        broker.spending_version,
                        broker.book_version,
                        broker.accounting_version,
                        loan.loan_version,
                    ],
                    to_vec(&(loan.clone(), broker.clone(), vault.clone())).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    broker.spending_ciphertext.clone(),
                    broker.inbox_ciphertext.clone(),
                    broker.active_principal_ciphertext.clone(),
                    broker.impaired_principal_ciphertext.clone(),
                    loan.principal_remaining_ciphertexts[1].clone(),
                ];
                self.crypto_context_with_subject(
                    "manage-loan",
                    broker.vault_id,
                    broker.broker_id,
                    loan.loan_id,
                    loan.proposal_id,
                    [
                        broker.spending_version,
                        broker.book_version,
                        broker.accounting_version,
                        loan.loan_version,
                        broker.risk_version,
                        vault.accounting_version,
                        post_impaired as u64,
                        matches!(action, LoanManagementAction::Default) as u64,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    0,
                    broker.owner.as_ref(),
                )
            }
            "broker-zero-total" => {
                let broker_id = args.broker_id.or(args.primary_id)?;
                let broker = self.brokers.get(&broker_id)?;
                let combined = combine_ciphertexts(
                    &combine_ciphertexts(&broker.spending_ciphertext, &broker.inbox_ciphertext),
                    &combine_ciphertexts(
                        &broker.active_principal_ciphertext,
                        &broker.impaired_principal_ciphertext,
                    ),
                );
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![broker_id],
                    vec![broker.owner.clone()],
                    vec![
                        broker.spending_version,
                        broker.accounting_version,
                        broker.book_version,
                    ],
                    combined.clone(),
                );
                view.ciphertexts = vec![combined];
                self.crypto_context_with_subject(
                    "broker-zero-total",
                    broker.vault_id,
                    broker.broker_id,
                    0,
                    0,
                    [
                        broker.spending_version,
                        broker.accounting_version,
                        broker.book_version,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    0,
                    "total",
                )
            }
            "settle" => {
                let broker_id = args.broker_id.or(args.primary_id)?;
                let amount = args.amount?.0;
                require!(amount > 0 && amount <= u64::MAX as u128, ERR_INVALID_AMOUNT);
                let broker = self.brokers.get(&broker_id)?;
                let vault = self.vaults.get(&broker.vault_id)?;
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![broker_id, broker.vault_id],
                    vec![broker.owner.clone()],
                    vec![
                        broker.spending_version,
                        broker.accounting_version,
                        vault.accounting_version,
                    ],
                    to_vec(&(broker.clone(), vault.clone())).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    broker.spending_ciphertext.clone(),
                    broker.issuer_balance_ciphertext.clone(),
                    broker.auditor_balance_ciphertext.clone(),
                ];
                self.crypto_context_with_subject(
                    "settle",
                    broker.vault_id,
                    broker.broker_id,
                    0,
                    0,
                    [
                        broker.spending_version,
                        broker.accounting_version,
                        vault.accounting_version,
                        amount as u64,
                        0,
                        0,
                        broker.encryption_key.key_id,
                        0,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    0,
                    broker.owner.as_ref(),
                )
            }
            "settle-reconcile" => {
                // Inline reconciliation is the keeper-safe path: a scoped
                // function-call key may invoke `settle`, but cannot first
                // create a checkpoint with a separate transaction.  The
                // checkpoint ID and cadence are derived from immutable Core
                // counters/state and are therefore included in the proof
                // context without trusting caller-supplied IDs/timestamps.
                let broker_id = args.broker_id.or(args.primary_id)?;
                let amount = args.amount?.0;
                require!(amount > 0 && amount <= u64::MAX as u128, ERR_INVALID_AMOUNT);
                let broker = self.brokers.get(&broker_id)?;
                let vault = self.vaults.get(&broker.vault_id)?;
                require!(
                    broker.reconciliation_checkpoint_id.is_none()
                        && (broker.accounting_pending || broker.impairment_provision > 0),
                    ERR_ACCOUNTING_PENDING
                );
                let scheduled_at = self.reconciliation_scheduled_at(&broker, &vault);
                require!(now_seconds() >= scheduled_at, ERR_TOO_SOON);
                let checkpoint_id = self
                    .checkpoint_sequence
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                let post_accounting_version = broker
                    .accounting_version
                    .checked_add(1)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![broker_id, checkpoint_id],
                    vec![broker.owner.clone()],
                    vec![broker.risk_version, post_accounting_version],
                    to_vec(&(broker.clone(), vault.clone(), checkpoint_id, amount))
                        .unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    broker.spending_ciphertext.clone(),
                    broker.inbox_ciphertext.clone(),
                    broker.active_principal_ciphertext.clone(),
                    broker.impaired_principal_ciphertext.clone(),
                ];
                view.commitments = vec![
                    broker.spending_commitment.clone(),
                    broker.inbox_commitment.clone(),
                    broker.active_principal_commitment.clone(),
                    broker.impaired_principal_commitment.clone(),
                ];
                self.crypto_context_with_subject(
                    "reconcile-credit",
                    broker.vault_id,
                    broker.broker_id,
                    0,
                    0,
                    [
                        broker.risk_version,
                        post_accounting_version,
                        broker.book_version,
                        checkpoint_id,
                        broker.accounting_version,
                        0,
                        0,
                        0,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    scheduled_at,
                    broker.owner.as_ref(),
                )
            }
            "reconcile-credit" => {
                let broker_id = args.broker_id.or(args.primary_id)?;
                let checkpoint_id = args.checkpoint_id.or(args.primary_id)?;
                let broker = self.brokers.get(&broker_id)?;
                let checkpoint = self.checkpoints.get(&checkpoint_id)?;
                require!(
                    broker.reconciliation_checkpoint_id == Some(checkpoint_id),
                    ERR_STALE_STATE
                );
                view = self.prepare_context(
                    args.operation.clone(),
                    vec![broker_id, checkpoint_id],
                    vec![broker.owner.clone()],
                    vec![broker.risk_version, broker.accounting_version],
                    to_vec(&(broker.clone(), checkpoint.clone())).unwrap_or_default(),
                );
                view.ciphertexts = vec![
                    broker.spending_ciphertext.clone(),
                    broker.inbox_ciphertext.clone(),
                    broker.active_principal_ciphertext.clone(),
                    broker.impaired_principal_ciphertext.clone(),
                ];
                self.crypto_context_with_subject(
                    "reconcile-credit",
                    broker.vault_id,
                    broker.broker_id,
                    0,
                    0,
                    [
                        broker.risk_version,
                        broker.accounting_version,
                        broker.book_version,
                        checkpoint.checkpoint_id,
                        checkpoint.accounting_version,
                        0,
                        0,
                        0,
                    ],
                    [broker.encryption_key.authorization_epoch, 0, 0, 0],
                    checkpoint.scheduled_at,
                    broker.owner.as_ref(),
                )
            }
            _ => return None,
        };
        view.operation_context =
            serde_json::to_vec(&context).unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        view.statement_kind = statement_kind_for_operation(operation);
        view.verifying_key_hash = view
            .statement_kind
            .and_then(|kind| self.verifier_keys.get(&kind))
            .map(|key| key.verifying_key_hash)
            .unwrap_or_default();
        Some(view)
    }

    pub fn get_operation_context(&self, operation: String, id: U64) -> Option<ProofContextView> {
        let id = id.0;
        match operation.as_str() {
            "loan" => self.loans.get(&id).map(|loan| {
                self.prepare_context(
                    operation,
                    vec![id, loan.broker_id, loan.loan_version],
                    vec![loan.borrower.clone()],
                    vec![loan.loan_version],
                    to_vec(&loan).unwrap_or_default(),
                )
            }),
            "broker" => self.brokers.get(&id).map(|broker| {
                self.prepare_context(
                    operation,
                    vec![id, broker.vault_id],
                    vec![broker.owner.clone()],
                    vec![
                        broker.spending_version,
                        broker.book_version,
                        broker.accounting_version,
                    ],
                    to_vec(&broker).unwrap_or_default(),
                )
            }),
            "vault" => self.vaults.get(&id).map(|vault| {
                self.prepare_context(
                    operation,
                    vec![id],
                    vec![vault.owner.clone()],
                    vec![vault.accounting_version, vault.risk_version],
                    to_vec(&vault).unwrap_or_default(),
                )
            }),
            "proposal" => self.proposals.get(&id).map(|proposal| {
                self.prepare_context(
                    operation,
                    vec![id, proposal.broker_id, proposal.vault_id],
                    vec![proposal.borrower.clone()],
                    vec![
                        proposal.broker_authorization_epoch,
                        proposal.borrower_authorization_epoch,
                    ],
                    to_vec(&proposal).unwrap_or_default(),
                )
            }),
            _ => None,
        }
    }

    pub fn get_statement_context(&self, operation: String, id: U64) -> Option<ProofContextView> {
        let id = id.0;
        let mut context = if operation == "holder" {
            let owner = env::predecessor_account_id();
            let holder = self.holders.get(&owner)?;
            self.prepare_context(
                operation.clone(),
                vec![id],
                vec![owner],
                vec![holder.spending_version, holder.authorization_epoch],
                to_vec(&holder).unwrap_or_default(),
            )
        } else {
            self.get_operation_context(operation.clone(), U64(id))?
        };
        match operation.as_str() {
            "holder" => {
                let owner = env::predecessor_account_id();
                let holder = self.holders.get(&owner)?;
                context.account_ids = vec![owner];
                context.versions = vec![holder.spending_version, holder.authorization_epoch];
                context.ciphertexts = vec![
                    holder.spending_ciphertext,
                    holder.inbox_ciphertext,
                    holder.issuer_balance_ciphertext,
                    holder.auditor_balance_ciphertext,
                    holder.encryption_key.public_key,
                ];
            }
            "broker" => {
                let broker = self.brokers.get(&id)?;
                context.ciphertexts = vec![
                    broker.spending_ciphertext,
                    broker.inbox_ciphertext,
                    broker.issuer_balance_ciphertext,
                    broker.auditor_balance_ciphertext,
                    broker.active_principal_ciphertext,
                    broker.impaired_principal_ciphertext,
                    broker.encryption_key.public_key,
                ];
                context.commitments = vec![
                    broker.spending_commitment,
                    broker.inbox_commitment,
                    broker.active_principal_commitment,
                    broker.impaired_principal_commitment,
                ];
                context.public_values = vec![
                    U128(broker.debt_total),
                    U128(broker.debt_maximum),
                    U128(broker.impairment_provision),
                ];
            }
            "loan" => {
                let loan = self.loans.get(&id)?;
                context.ciphertexts = loan
                    .principal_ciphertexts
                    .iter()
                    .chain(loan.initial_owed_ciphertexts.iter())
                    .chain(loan.amount_owed_ciphertexts.iter())
                    .chain(loan.periodic_payment_ciphertexts.iter())
                    .chain(loan.principal_remaining_ciphertexts.iter())
                    .chain(loan.cumulative_repaid_ciphertexts.iter())
                    .cloned()
                    .collect();
                context.commitments = vec![
                    loan.principal_remaining_commitment.clone(),
                    loan.accounting_leaf.clone(),
                ];
                context.public_values = vec![
                    U128(u128::from(loan.payment_total)),
                    U128(u128::from(loan.payment_remaining)),
                    U128(u128::from(loan.payment_interval)),
                    U128(u128::from(loan.grace_period)),
                ];
            }
            "proposal" => {
                let proposal = self.proposals.get(&id)?;
                context.ciphertexts = proposal
                    .principal_ciphertexts
                    .iter()
                    .chain(proposal.initial_owed_ciphertexts.iter())
                    .chain(proposal.periodic_payment_ciphertexts.iter())
                    .cloned()
                    .collect();
                context.commitments = vec![proposal.agreement_digest.clone()];
                context.public_values = vec![
                    U128(u128::from(proposal.payment_count)),
                    U128(u128::from(proposal.payment_interval)),
                    U128(u128::from(proposal.grace_period)),
                ];
            }
            _ => {}
        }
        context.state_digest = hash_bytes(&(
            context.operation.clone(),
            context.ids.clone(),
            context.account_ids.clone(),
            context.versions.clone(),
            context.ciphertexts.clone(),
            context.commitments.clone(),
            context.public_values.clone(),
        ));
        Some(context)
    }

    /// Return one immutable proof-bound recovery entry.  The record contains
    /// only the canonical statement and public key/version metadata.
    pub fn get_recovery_record(&self, event_id: U64) -> Option<RecoveryRecordView> {
        self.recovery_records
            .get(&event_id.0)
            .map(|record| recovery_record_view(record, None))
    }

    /// List a subject's recovery history by its bounded monotonic sequence.
    /// `cursor` is the last consumed subject sequence (zero for the first
    /// page), so deleted/filtered records cannot hide later entries.
    pub fn list_recovery_history(
        &self,
        subject_key: String,
        cursor: U64,
        limit: u32,
    ) -> RecoveryHistoryPage {
        bounded_limit(limit);
        require!(subject_key.len() <= MAX_ID_BYTES, ERR_INVALID_ENCODING);
        let cursor = cursor.0;
        let end = self.recovery_subject_counts.get(&subject_key).unwrap_or(0);
        let start = cursor.saturating_add(1);
        let page_end = start
            .saturating_add(u64::from(limit))
            .saturating_sub(1)
            .min(end);
        let mut records = Vec::new();
        if start <= page_end {
            for sequence in start..=page_end {
                let key = recovery_subject_index_key(&subject_key, sequence);
                let event_id = self
                    .recovery_subject_index
                    .get(&key)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                let record = self
                    .recovery_records
                    .get(&event_id)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                records.push(recovery_record_view(record, Some((&subject_key, sequence))));
            }
        }
        RecoveryHistoryPage {
            records,
            next_cursor: (page_end < end).then_some(page_end),
            end_cursor: page_end,
        }
    }

    /// List the global immutable event stream with a bounded event-id range.
    pub fn list_recovery_records(&self, cursor: U64, limit: u32) -> RecoveryHistoryPage {
        bounded_limit(limit);
        let cursor = cursor.0;
        let end = self.recovery_sequence;
        let start = cursor.saturating_add(1);
        let page_end = start
            .saturating_add(u64::from(limit))
            .saturating_sub(1)
            .min(end);
        let mut records = Vec::new();
        if start <= page_end {
            for event_id in start..=page_end {
                let record = self
                    .recovery_records
                    .get(&event_id)
                    .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
                records.push(recovery_record_view(record, None));
            }
        }
        RecoveryHistoryPage {
            records,
            next_cursor: (page_end < end).then_some(page_end),
            end_cursor: page_end,
        }
    }
}

impl Core {
    fn next_recovery_event_id(&mut self) -> u64 {
        self.recovery_sequence = self
            .recovery_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.recovery_sequence
    }

    /// Append one canonical statement and index it under each affected
    /// subject.  Subject indexes are keyed by `(subject, sequence)` rather
    /// than a growing vector, keeping every view bounded and deterministic.
    fn record_recovery(
        &mut self,
        operation: &str,
        statement: &[u8],
        subjects: &[String],
        key_ids: &[u64],
        versions: &[u64],
    ) {
        require!(
            !statement.is_empty() && statement.len() <= MAX_PROOF_BYTES,
            ERR_BAD_PROOF
        );
        let parsed = crypto_adapter::parse_statement(statement)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        let canonical =
            crypto_adapter::encode(&parsed).unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        self.record_recovery_event_inner(
            operation,
            subjects,
            key_ids,
            versions,
            Some(canonical),
            RecoveryMetadata {
                action: "proof".to_string(),
                loan_id: None,
                loan_status: None,
                noop: false,
            },
        );
    }

    /// Record a deterministic state transition without pretending that a
    /// caller-provided proof statement authenticated it.  This is used for
    /// homomorphic inbox merges and public loan-status actions.
    fn record_recovery_event(
        &mut self,
        operation: &str,
        subjects: &[String],
        key_ids: &[u64],
        versions: &[u64],
        metadata: RecoveryMetadata,
    ) {
        self.record_recovery_event_inner(operation, subjects, key_ids, versions, None, metadata);
    }

    fn record_recovery_event_inner(
        &mut self,
        operation: &str,
        subjects: &[String],
        key_ids: &[u64],
        versions: &[u64],
        statement: Option<Vec<u8>>,
        metadata: RecoveryMetadata,
    ) {
        require!(
            !operation.is_empty() && operation.len() <= MAX_ID_BYTES,
            ERR_INVALID_ENCODING
        );
        require!(
            !subjects.is_empty() && subjects.len() <= 8,
            ERR_INVALID_ENCODING
        );
        require!(
            key_ids.len() <= 32 && versions.len() <= 32,
            ERR_INVALID_ENCODING
        );
        let event_id = self.next_recovery_event_id();
        let mut primary_sequence = 0;
        for (index, subject) in subjects.iter().enumerate() {
            require!(
                !subject.is_empty() && subject.len() <= MAX_ID_BYTES,
                ERR_INVALID_ENCODING
            );
            let sequence = self
                .recovery_subject_counts
                .get(subject)
                .unwrap_or(0)
                .checked_add(1)
                .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
            self.recovery_subject_counts.insert(subject, &sequence);
            self.recovery_subject_index
                .insert(&recovery_subject_index_key(subject, sequence), &event_id);
            if index == 0 {
                primary_sequence = sequence;
            }
        }
        self.recovery_records.insert(
            &event_id,
            &RecoveryRecord {
                event_id,
                operation: operation.to_string(),
                subject_key: subjects[0].clone(),
                subject_sequence: primary_sequence,
                block_timestamp: env::block_timestamp(),
                statement,
                key_ids: key_ids.to_vec(),
                versions: versions.to_vec(),
                metadata,
            },
        );
    }

    fn next_vault_id(&mut self) -> u64 {
        self.vault_sequence = self
            .vault_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.vault_sequence
    }

    fn next_broker_id(&mut self) -> u64 {
        self.broker_sequence = self
            .broker_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.broker_sequence
    }

    fn next_loan_id(&mut self) -> u64 {
        self.loan_sequence = self
            .loan_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.loan_sequence
    }

    fn next_proposal_id(&mut self) -> u64 {
        self.proposal_sequence = self
            .proposal_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.proposal_sequence
    }

    fn next_claim_id(&mut self) -> u64 {
        self.claim_sequence = self
            .claim_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.claim_sequence
    }

    fn next_checkpoint_id(&mut self) -> u64 {
        self.checkpoint_sequence = self
            .checkpoint_sequence
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_STALE_STATE));
        self.checkpoint_sequence
    }

    fn vault_or_panic(&self, id: u64) -> Vault {
        self.vaults
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn broker_or_panic(&self, id: u64) -> Broker {
        self.brokers
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn loan_or_panic(&self, id: u64) -> Loan {
        self.loans
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn proposal_or_panic(&self, id: u64) -> Proposal {
        self.proposals
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn claim_or_panic(&self, id: u64) -> PublicClaim {
        self.claims
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn payout_or_panic(&self, id: u64) -> PayoutOperation {
        self.payouts
            .get(&id)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_FOUND))
    }

    fn holder_or_panic(&self, account: &AccountId) -> HolderBalance {
        self.holders
            .get(account)
            .unwrap_or_else(|| env::panic_str(ERR_NOT_REGISTERED))
    }

    fn ensure_vault_phase(&self, vault: &Vault, redemption: bool, deposit: bool) {
        match (&vault.kind, &vault.phase_times) {
            (VaultKind::OpenEnded, _) => {}
            (VaultKind::ClosedEnded, Some(phases)) => {
                let now = now_seconds();
                require!(now >= phases.subscription_start, ERR_WRONG_PHASE);
                if redemption {
                    require!(
                        now < phases.investment_start || now >= phases.redemption_start,
                        ERR_WRONG_PHASE
                    );
                } else if deposit {
                    require!(now < phases.investment_start, ERR_WRONG_PHASE);
                } else {
                    require!(
                        now >= phases.investment_start && now < phases.redemption_start,
                        ERR_WRONG_PHASE
                    );
                }
            }
            _ => env::panic_str(ERR_INVALID_ENCODING),
        }
    }

    fn ensure_asset_unfrozen(&self) {
        require!(!self.asset_frozen, ERR_ACCOUNT_FROZEN);
    }

    fn ensure_verifier_active(&self) {
        require!(self.verifier.activated, ERR_UNSUPPORTED_PROFILE);
    }

    fn charge_storage(&mut self, account: &AccountId, before: u64) {
        let after = env::storage_usage();
        let additional = after.saturating_sub(before) as u128;
        if additional == 0 {
            return;
        }
        let required = additional
            .checked_mul(env::storage_byte_cost().as_yoctonear())
            .unwrap_or_else(|| env::panic_str(ERR_STORAGE));
        let available = self.storage_deposits.get(account).unwrap_or(0);
        require!(available >= required, ERR_STORAGE);
        self.storage_deposits
            .insert(account, &(available - required));
    }

    /// Return the canonical encrypted zero for one immutable subject/key
    /// epoch.  The domain is derived on-chain from deployment identity and is
    /// never accepted from a caller, so a zero ciphertext cannot be replayed
    /// across networks, assets, accounts or key rotations.
    fn canonical_zero_for(
        &self,
        public_key: &[u8],
        subject: &str,
        key_id: u64,
        authorization_epoch: u64,
    ) -> Vec<u8> {
        let key = crypto_adapter::parse_public_key(public_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let domain = to_vec(&(
            b"near-confidential-lending/canonical-zero/v2".to_vec(),
            self.asset.network_id.clone(),
            env::current_account_id(),
            self.asset.token_account.clone(),
            self.asset.crypto_profile_hash.clone(),
            subject.to_string(),
            key_id,
            authorization_epoch,
        ))
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let domain = env::sha256(&domain);
        let ciphertext = crypto_adapter::zero_ciphertext(&key, &domain)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        crypto_adapter::encode(&ciphertext).unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
    }

    fn is_canonical_zero_for(
        &self,
        public_key: &[u8],
        subject: &str,
        key_id: u64,
        authorization_epoch: u64,
        ciphertext: &[u8],
    ) -> bool {
        self.canonical_zero_for(public_key, subject, key_id, authorization_epoch) == ciphertext
    }

    /// Apply one bounded authenticated-book transition.  The sparse tree
    /// performs exactly one fixed-depth path update and checks the stored root
    /// and (when present) the exact pre-leaf before any caller-visible state is
    /// written.
    fn update_loan_book(
        &mut self,
        broker_id: u64,
        loan_id: u64,
        expected_root: &[u8],
        expected_leaf: Option<&[u8]>,
        next_leaf: Option<&[u8]>,
    ) -> Vec<u8> {
        let domain = book_domain(self, broker_id);
        let book = Book::<NearSha256>::new(domain);
        let old_root = digest32(expected_root);
        // `accounting_leaf` is the canonical payload digest stored with the
        // loan.  The authenticated book adds its own domain-separated leaf
        // envelope (including the loan ID) before touching the tree.  Keeping
        // the payload digest in the loan record lets every transition
        // deterministically recompute it without storing a second ambiguous
        // representation.
        let old_leaf = expected_leaf.map(|payload| book.leaf_hash(loan_id, &digest32(payload)));
        let next_leaf = next_leaf.map(|payload| book.leaf_hash(loan_id, &digest32(payload)));
        let mut store = CoreBookStore {
            nodes: &mut self.book_nodes,
            broker_id,
        };
        book.update(&mut store, loan_id, old_leaf, next_leaf, &old_root)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF))
            .to_vec()
    }

    fn keeper_index(&self, broker: &Broker, caller: &AccountId) -> Option<usize> {
        broker.delegates.iter().position(|grant| {
            grant.delegate_account == *caller
                && grant.active
                && now_seconds() <= grant.expires_at
                && grant.revocation_epoch == broker.authorization_epoch
                && self
                    .authorization_keys
                    .get(&authorization_key(
                        &grant.delegate_account,
                        grant.delegate_key_id,
                    ))
                    .map(|key| {
                        key.owner == grant.delegate_account
                            && !key.revoked
                            && key.epoch == grant.delegate_epoch
                    })
                    .unwrap_or(false)
        })
    }

    /// Compute the first checkpoint boundary after the risk transition that
    /// made this broker pending.  Both the permissionless checkpoint method
    /// and the inline keeper settlement path use this exact value, so a
    /// settlement cannot bypass the vault cadence by choosing a timestamp.
    fn reconciliation_scheduled_at(&self, broker: &Broker, vault: &Vault) -> u64 {
        let since = if broker.accounting_pending_since == 0 {
            // A zero value is only possible for state created before this
            // field existed or a synthetic unit-test context.  Use the
            // current block as a conservative migration fallback.
            now_seconds()
        } else {
            broker.accounting_pending_since
        };
        let epoch = vault.checkpoint_policy.epoch_seconds;
        ((since / epoch)
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT)))
        .checked_mul(epoch)
        .unwrap_or_else(|| env::panic_str(ERR_INVALID_AMOUNT))
    }

    /// Build the exact operation context used by the crypto profile.  The
    /// operation identifier is deterministic from the method and affected
    /// public IDs; expected versions make a proof one-shot even when a caller
    /// retries the same payload.
    // These explicit fields mirror the protocol transcript and are kept
    // separate to make every binding visible at each call site.
    #[allow(clippy::too_many_arguments)]
    fn crypto_context(
        &self,
        domain: &str,
        vault_id: u64,
        broker_id: u64,
        loan_id: u64,
        proposal_id: u64,
        expected_versions: [u64; 8],
        authorization_epochs: [u64; 4],
        expiry: u64,
    ) -> OperationContext {
        self.crypto_context_with_subject(
            domain,
            vault_id,
            broker_id,
            loan_id,
            proposal_id,
            expected_versions,
            authorization_epochs,
            expiry,
            env::predecessor_account_id().as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn crypto_context_with_subject(
        &self,
        domain: &str,
        vault_id: u64,
        broker_id: u64,
        loan_id: u64,
        proposal_id: u64,
        expected_versions: [u64; 8],
        authorization_epochs: [u64; 4],
        expiry: u64,
        subject: &str,
    ) -> OperationContext {
        let operation_id = format!(
            "{domain}:{vault_id}:{broker_id}:{loan_id}:{proposal_id}:{}",
            subject,
        );
        crypto_adapter::context(
            &self.asset.network_id,
            env::current_account_id().as_ref(),
            self.asset.token_account.as_ref(),
            &operation_id,
            vault_id,
            broker_id,
            loan_id,
            proposal_id,
            expected_versions,
            authorization_epochs,
            expiry,
        )
    }

    /// Verify a typed statement.  `args.public_inputs`, `args.context` and
    /// `args.statement_kind` are consistency fields only; authoritative public
    /// inputs come from the parsed statement itself and are passed directly to
    /// the immutable prepared verifier key selected by `Statement::kind()`.
    fn verify_typed_statement(
        &self,
        args: &ProofArgs,
        expected_kind: StatementKind,
        expected_context: &OperationContext,
    ) -> Statement {
        require!(
            self.verifier.activated && self.verifier.ready,
            ERR_UNSUPPORTED_PROFILE
        );
        require!(!args.statement.is_empty(), ERR_BAD_PROOF);
        let statement = crypto_adapter::parse_statement(&args.statement)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        require!(statement.kind() == expected_kind, ERR_BAD_PROOF);
        if let Some(kind) = args.statement_kind {
            require!(kind == expected_kind.as_u8(), ERR_BAD_PROOF);
        }
        if !args.profile_hash.is_empty() {
            require!(
                args.profile_hash == self.asset.crypto_profile_hash,
                ERR_UNSUPPORTED_PROFILE
            );
        }
        require!(statement.context() == expected_context, ERR_BAD_PROOF);
        // The proof envelope carries the transcript digest.  The typed
        // statement supplies every remaining slot, and the pinned circuit
        // constrains the digest to that slot vector.  Core intentionally does
        // not recompute host Poseidon here.
        require!(args.context.len() == 32, ERR_BAD_PROOF);
        let inputs = crypto_adapter::statement_inputs_with_digest(&statement, &args.context)
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        if !args.public_inputs.is_empty() {
            require!(
                args.public_inputs.len() == inputs.len()
                    && args
                        .public_inputs
                        .iter()
                        .zip(inputs.iter())
                        .all(|(provided, expected)| provided.as_slice() == expected),
                ERR_BAD_PROOF
            );
        }
        let key = self
            .verifier_keys
            .get(&expected_kind.as_u8())
            .unwrap_or_else(|| env::panic_str(ERR_UNSUPPORTED_PROFILE));
        require!(
            args.verifying_key_hash == key.verifying_key_hash,
            ERR_UNSUPPORTED_PROFILE
        );
        require!(
            key.public_input_count as usize == inputs.len(),
            ERR_UNSUPPORTED_PROFILE
        );
        require!(
            !args.proof.is_empty() && args.proof.len() <= MAX_PROOF_BYTES,
            ERR_BAD_PROOF
        );
        let accepted = near_verifier::verify_prepared(&key.prepared_key, &args.proof, &inputs)
            .unwrap_or(false);
        require!(accepted, ERR_BAD_PROOF);
        statement
            .promote_after_verified_proof()
            .unwrap_or_else(|_| env::panic_str(ERR_BAD_PROOF));
        statement
    }

    // Conversion verification has three fixed reader keys and three fixed
    // output views; collapsing them into untyped slices would weaken the
    // statement-to-ledger binding.
    #[allow(clippy::too_many_arguments)]
    fn verify_public_conversion_statement(
        &self,
        args: &ProofArgs,
        context: &OperationContext,
        owner_key: &[u8],
        before: &[u8],
        after: Option<&[u8]>,
        amount: u128,
        debit: bool,
        spending_version: u64,
        reader_keys: [&[u8]; 3],
        output_views: [Option<&[u8]>; 3],
    ) -> confidential_crypto::PublicConversionStatement {
        require!(amount <= u64::MAX as u128, ERR_INVALID_AMOUNT);
        let statement = self.verify_typed_statement(args, StatementKind::PublicConversion, context);
        let Statement::PublicConversion(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        let owner = crypto_adapter::parse_public_key(owner_key)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        let before = crypto_adapter::parse_ciphertext(before)
            .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        require!(statement.owner_key == owner, ERR_BAD_PROOF);
        require!(statement.spending_before == before, ERR_BAD_PROOF);
        if let Some(after) = after {
            require!(
                statement.spending_after
                    == crypto_adapter::parse_ciphertext(after)
                        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
                ERR_BAD_PROOF
            );
        }
        require!(statement.public_amount == amount as u64, ERR_BAD_PROOF);
        require!(
            statement.mode
                == if debit {
                    ConversionMode::Debit
                } else {
                    ConversionMode::Credit
                },
            ERR_BAD_PROOF
        );
        require!(
            statement.spending_version == spending_version,
            ERR_BAD_PROOF
        );
        require!(statement.views.len() == reader_keys.len(), ERR_BAD_PROOF);
        for (index, view) in statement.views.iter().enumerate() {
            let expected_key = crypto_adapter::parse_public_key(reader_keys[index])
                .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
            require!(view.reader_key == expected_key, ERR_BAD_PROOF);
            if let Some(output) = output_views[index] {
                let expected_ciphertext = crypto_adapter::parse_ciphertext(output)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
                require!(view.ciphertext == expected_ciphertext, ERR_BAD_PROOF);
            }
        }
        statement
    }

    fn verify_zero_balance_statement(
        &self,
        args: &ProofArgs,
        context: &OperationContext,
        owner_key: &[u8],
        ciphertext: &[u8],
        spending_version: u64,
    ) {
        let statement = self.verify_typed_statement(args, StatementKind::ZeroBalance, context);
        let Statement::ZeroBalance(statement) = statement else {
            env::panic_str(ERR_BAD_PROOF);
        };
        require!(
            statement.owner_key
                == crypto_adapter::parse_public_key(owner_key)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(
            statement.ciphertext
                == crypto_adapter::parse_ciphertext(ciphertext)
                    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING)),
            ERR_BAD_PROOF
        );
        require!(statement.expected_amount == 0, ERR_BAD_PROOF);
        require!(
            statement.spending_version == spending_version,
            ERR_BAD_PROOF
        );
    }

    fn vault_view(&self, vault: Vault) -> VaultView {
        let nav = vault.assets_total.saturating_sub(vault.loss_unrealized);
        VaultView {
            vault_id: vault.vault_id,
            owner: vault.owner,
            asset_id: vault.asset_id,
            assets_total: U128(vault.assets_total),
            assets_available: U128(vault.assets_available),
            loss_unrealized: U128(vault.loss_unrealized),
            nav: U128(nav),
            shares_total: U128(vault.shares_total),
            assets_maximum: U128(vault.assets_maximum),
            share_scale: vault.share_scale,
            shares_transferable: vault.shares_transferable,
            checkpoint_policy: vault.checkpoint_policy,
            phase_times: vault.phase_times.clone(),
            accounting_pending: vault.accounting_pending,
            pending_broker_count: vault.pending_broker_count,
            accounting_version: vault.accounting_version,
            risk_version: vault.risk_version,
            reconciled_risk_version: vault.reconciled_risk_version,
            kind: vault.kind.clone(),
            phase: match (&vault.kind, &vault.phase_times) {
                (VaultKind::OpenEnded, _) => None,
                (VaultKind::ClosedEnded, Some(times)) => {
                    let now = now_seconds();
                    Some(if now < times.investment_start {
                        VaultPhase::Subscription
                    } else if now < times.redemption_start {
                        VaultPhase::Investment
                    } else {
                        VaultPhase::Redemption
                    })
                }
                _ => None,
            },
        }
    }

    fn loan_view(&self, loan: Loan) -> LoanView {
        LoanView {
            loan_id: loan.loan_id,
            broker_id: loan.broker_id,
            borrower: loan.borrower,
            proposal_id: loan.proposal_id,
            start_time: loan.start_time,
            payment_interval: loan.payment_interval,
            grace_period: loan.grace_period,
            previous_due: loan.previous_due,
            next_due: match loan.status {
                LoanStatus::Active => Some(loan.next_due),
                LoanStatus::Paid | LoanStatus::Defaulted => None,
            },
            payment_total: loan.payment_total,
            payment_remaining: loan.payment_remaining,
            status: loan.status,
            impaired: loan.impaired,
            loan_version: loan.loan_version,
            borrower_key_id: loan.borrower_key_id,
            broker_key_id: loan.broker_key_id,
            loan_auditor_key_id: loan.loan_auditor_key_id,
            loan_auditor_public_key: loan.loan_auditor_public_key,
            principal_ciphertexts: loan.principal_ciphertexts,
            initial_owed_ciphertexts: loan.initial_owed_ciphertexts,
            amount_owed_ciphertexts: loan.amount_owed_ciphertexts,
            periodic_payment_ciphertexts: loan.periodic_payment_ciphertexts,
            principal_remaining_ciphertexts: loan.principal_remaining_ciphertexts,
            principal_remaining_commitment: loan.principal_remaining_commitment,
            cumulative_repaid_ciphertexts: loan.cumulative_repaid_ciphertexts,
            accounting_leaf: loan.accounting_leaf,
        }
    }

    fn emit(&self, event_type: &str, payload: serde_json::Value) {
        let event = json!({
            "standard": "near-confidential-lending",
            "version": "1.0.0",
            "event": event_type,
            "core": env::current_account_id(),
            "asset": self.asset.token_account,
            "data": payload,
        });
        let encoded =
            serde_json::to_string(&event).unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
        require!(encoded.len() <= MAX_EVENT_BYTES, ERR_INVALID_ENCODING);
        env::log_str(&format!("EVENT_JSON:{encoded}"));
    }
}

fn now_seconds() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

fn validate_ciphertext(bytes: &[u8]) {
    require!(
        !bytes.is_empty() && bytes.len() <= MAX_CIPHERTEXT_BYTES,
        ERR_INVALID_ENCODING
    );
}

fn validate_digest32(bytes: &[u8]) {
    require!(bytes.len() == 32, ERR_INVALID_ENCODING);
}

fn digest32(bytes: &[u8]) -> [u8; 32] {
    require!(bytes.len() == 32, ERR_INVALID_ENCODING);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    digest
}

fn validate_public_key(bytes: &[u8]) {
    require!(bytes.len() <= MAX_CIPHERTEXT_BYTES, ERR_INVALID_ENCODING);
    crypto_adapter::parse_public_key(bytes)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
}

fn validate_commitment(bytes: &[u8]) {
    require!(bytes.len() <= MAX_CIPHERTEXT_BYTES, ERR_INVALID_ENCODING);
    crypto_adapter::parse_commitment(bytes)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
}

fn validate_ciphertext_set(values: &[Vec<u8>], minimum: usize) {
    require!(values.len() >= minimum, ERR_INVALID_ENCODING);
    for value in values {
        validate_ciphertext(value);
    }
}

fn bounded_limit(limit: u32) {
    require!(limit > 0 && limit <= 50, ERR_INVALID_AMOUNT);
}

/// Combine an authenticated encrypted delta with the current ciphertext.
///
/// The deployed build replaces this wire-level adapter with the
/// confidential-crypto Baby-Jubjub point addition implementation. The Core
/// never treats the delta as a replacement balance: the proof binds the exact
/// current ciphertext and this function is the only inbox-credit path.
fn combine_ciphertexts(current: &[u8], delta: &[u8]) -> Vec<u8> {
    let current = crypto_adapter::parse_ciphertext(current)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
    let delta = crypto_adapter::parse_ciphertext(delta)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
    let combined = crypto_adapter::add_ciphertexts(&current, &delta)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
    crypto_adapter::encode(&combined).unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING))
}

fn share_key(vault_id: u64, owner: &AccountId) -> Vec<u8> {
    hash_bytes(&(vault_id, owner))
}

fn authorization_key(owner: &AccountId, key_id: u64) -> Vec<u8> {
    hash_bytes(&(b"authorization-key-v1".to_vec(), owner, key_id))
}

fn verify_authorization_signature(
    core: &Core,
    owner: &AccountId,
    key_id: Option<u64>,
    epoch: u64,
    nonce: u64,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Some(key_id) = key_id else { return false };
    let Some(key) = core
        .authorization_keys
        .get(&authorization_key(owner, key_id))
    else {
        return false;
    };
    if key.owner != *owner || key.revoked || key.epoch != epoch || key.nonce != nonce {
        return false;
    }
    if key.public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&key.public_key);
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(signature);
    env::ed25519_verify(&signature_bytes, message, &public_key)
}

fn validate_authorization_nonce(
    core: &Core,
    owner: &AccountId,
    key_id: Option<u64>,
    epoch: u64,
    nonce: u64,
) {
    if let Some(key_id) = key_id {
        let key = core
            .authorization_keys
            .get(&authorization_key(owner, key_id))
            .unwrap_or_else(|| env::panic_str(ERR_UNAUTHORIZED));
        require!(
            key.owner == *owner && !key.revoked && key.epoch == epoch && key.nonce == nonce,
            ERR_UNAUTHORIZED
        );
    } else {
        require!(nonce == 0, ERR_UNAUTHORIZED);
    }
}

fn statement_kind_for_operation(operation: &str) -> Option<u8> {
    match operation {
        "register-holder" | "create-broker" => Some(1),
        "shield" | "unshield" | "merge-holder" | "merge-broker" | "draw" | "settle" => Some(2),
        "confidential-send" => Some(3),
        "originate" => Some(4),
        "repay" => Some(5),
        "reconcile-credit" | "settle-reconcile" | "manage-loan" => Some(6),
        "holder-zero-total" | "broker-zero" | "broker-zero-total" | "loan-zero" => Some(7),
        "holder" => Some(8),
        _ => None,
    }
}

fn deposit_key(token: &AccountId, sender: &AccountId, deposit_id: &str) -> String {
    format!("{token}:{sender}:{deposit_id}")
}

fn hash_bytes<T: BorshSerialize>(value: &T) -> Vec<u8> {
    let encoded = to_vec(value).unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
    Sha256::digest(encoded).to_vec()
}

fn recovery_subject_index_key(subject: &str, sequence: u64) -> Vec<u8> {
    hash_bytes(&(
        b"recovery-subject-v1".to_vec(),
        subject.to_string(),
        sequence,
    ))
}

fn book_node_key(broker_id: u64, key: NodeKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(17);
    bytes.extend_from_slice(b"book-node-v1");
    bytes.extend_from_slice(&broker_id.to_le_bytes());
    bytes.push(key.height);
    bytes.extend_from_slice(&key.index.to_le_bytes());
    bytes
}

fn book_domain(core: &Core, broker_id: u64) -> [u8; 32] {
    let bytes = to_vec(&(
        b"near-confidential-lending/book-domain/v1".to_vec(),
        core.asset.network_id.clone(),
        env::current_account_id(),
        core.asset.token_account.clone(),
        core.asset.crypto_profile_hash.clone(),
        broker_id,
    ))
    .unwrap_or_else(|_| env::panic_str(ERR_INVALID_ENCODING));
    env::sha256_array(&bytes)
}

fn recovery_record_view(
    record: RecoveryRecord,
    requested_subject: Option<(&str, u64)>,
) -> RecoveryRecordView {
    let (subject_key, subject_sequence) = requested_subject
        .map(|(subject, sequence)| (subject.to_string(), sequence))
        .unwrap_or_else(|| (record.subject_key.clone(), record.subject_sequence));
    RecoveryRecordView {
        event_id: record.event_id,
        operation: record.operation,
        subject_key,
        subject_sequence,
        block_timestamp: record.block_timestamp,
        statement: record.statement,
        key_ids: record.key_ids,
        versions: record.versions,
        origin_subject_key: record.subject_key,
        origin_subject_sequence: record.subject_sequence,
        metadata: record.metadata,
    }
}

fn keeper_grant_view(grant: &KeeperGrant) -> KeeperGrantView {
    KeeperGrantView {
        delegate_account: grant.delegate_account.clone(),
        delegate_key_id: grant.delegate_key_id,
        allowed_operations: grant.allowed_operations.clone(),
        allowed_settlement_per_operation: U128(grant.allowed_settlement_per_operation),
        allowed_settlement_per_window: U128(grant.allowed_settlement_per_window),
        window_seconds: grant.window_seconds,
        window_started_at: grant.window_started_at,
        window_spent: U128(grant.window_spent),
        expires_at: grant.expires_at,
        revocation_epoch: grant.revocation_epoch,
        delegate_epoch: grant.delegate_epoch,
        active: grant.active,
    }
}

// The authenticated leaf includes the complete canonical loan record.  The
// explicit arguments document the exact hash preimage and are deliberately
// not replaced by a caller-provided digest.
#[allow(clippy::too_many_arguments)]
fn derive_loan_leaf(
    loan_id: u64,
    broker_id: u64,
    borrower: &AccountId,
    proposal_id: u64,
    status: &LoanStatus,
    loan_version: u64,
    payment_remaining: u32,
    principal: &[Vec<u8>],
    owed: &[Vec<u8>],
    periodic: &[Vec<u8>],
    principal_commitment: &[u8],
) -> Vec<u8> {
    hash_bytes(&(
        b"loan-leaf-v1".to_vec(),
        loan_id,
        broker_id,
        borrower,
        proposal_id,
        status,
        loan_version,
        payment_remaining,
        principal,
        owed,
        periodic,
        principal_commitment,
    ))
}

fn loan_reader_views(transfer_views: &[Vec<u8>]) -> Vec<Vec<u8>> {
    require!(transfer_views.len() == 5, ERR_INVALID_ENCODING);
    // Origination transfer views are [broker, borrower, issuer, token
    // auditor, loan auditor].  Loan P/O/Q/R records deliberately retain only
    // the three loan readers [borrower, broker, loan auditor].
    vec![
        transfer_views[1].clone(),
        transfer_views[0].clone(),
        transfer_views[4].clone(),
    ]
}

fn derive_tombstone_leaf(
    loan_id: u64,
    status: &LoanStatus,
    final_version: u64,
    final_leaf: &[u8],
) -> Vec<u8> {
    hash_bytes(&(
        b"loan-tombstone-v1".to_vec(),
        loan_id,
        status,
        final_version,
        final_leaf,
    ))
}

fn mul_div_floor(left: u128, right: u128, denominator: u128) -> u128 {
    lending_math::mul_div_floor(left, right, denominator)
        .unwrap_or_else(|_| env::panic_str(ERR_INVALID_AMOUNT))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(deprecated)]
    use near_sdk::test_utils::{VMContextBuilder, testing_env_with_promise_results};
    use near_sdk::{NearToken, PromiseResult, testing_env};
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn test_public_key(seed: u64) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let scalar = confidential_crypto::ScalarHex::parse(&hex::encode(bytes)).unwrap();
        let secret = confidential_crypto::SecretKey::from_wire(&scalar).unwrap();
        serde_json::to_vec(&secret.public_key()).unwrap()
    }

    fn test_manifest() -> (String, Vec<u8>) {
        let mut artifacts = BTreeMap::new();
        for (family, statement_kind) in VERIFIER_FAMILIES {
            let vk_hash = format!("{statement_kind:02x}").repeat(32);
            let prepared_hash = format!("{:02x}", statement_kind + 16).repeat(32);
            let proving_hash = format!("{:02x}", statement_kind + 32).repeat(32);
            artifacts.insert(
                format!("{family}.pk"),
                json!({
                    "path": format!("{family}.pk"),
                    "sha256": proving_hash,
                    "bytes": 3
                }),
            );
            artifacts.insert(
                format!("{family}.vk"),
                json!({
                    "path": format!("{family}.vk"),
                    "sha256": vk_hash,
                    "bytes": 1
                }),
            );
            artifacts.insert(
                format!("{family}.prepared-vk"),
                json!({
                    "path": format!("{family}.prepared-vk"),
                    "sha256": prepared_hash,
                    "bytes": 2
                }),
            );
        }
        for (name, bytes) in [
            ("native.prover", 4),
            ("browser.glue", 5),
            ("browser.wasm", 6),
        ] {
            artifacts.insert(
                name.to_string(),
                json!({
                    "path": name,
                    "sha256": format!("{:02x}", bytes).repeat(32),
                    "bytes": bytes
                }),
            );
        }
        let manifest = json!({
            "schema": "confidential-lending-artifacts/v1",
            "profileHash": hex::encode(confidential_crypto::PROFILE_HASH),
            "networkId": "local",
            "coreAccountId": env::current_account_id().to_string(),
            "setup": "development-single-party",
            "artifacts": artifacts
        });
        let bytes = serde_json::to_string(&manifest).unwrap();
        let hash = Sha256::digest(bytes.as_bytes()).to_vec();
        (bytes, hash)
    }

    fn test_init_args(manifest_json: String, manifest_hash: Vec<u8>) -> InitArgs {
        InitArgs {
            token_account: account("token.testnet"),
            decimals: 6,
            controller_account: account("issuer.testnet"),
            issuer_key_id: 1,
            issuer_public_key: test_public_key(3),
            token_auditor_key_id: 2,
            token_auditor_public_key: test_public_key(5),
            crypto_profile_hash: confidential_crypto::PROFILE_HASH.to_vec(),
            network_id: "local".to_string(),
            token_trust_policy: "local-test".to_string(),
            freeze_policy: "none".to_string(),
            custody_cap: U128(MAX_ASSET_UNITS),
            verifier_key: Vec::new(),
            verifier_manifest_hash: manifest_hash,
            verifier_manifest_json: manifest_json,
        }
    }

    fn init() -> Core {
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("owner.testnet"))
                .build()
        );
        let (manifest_json, manifest_hash) = test_manifest();
        let mut core = Core::new(test_init_args(manifest_json, manifest_hash));
        // Tests exercise accounting/custody transitions without running the
        // staged eight-key deployment ceremony.  This mutation is confined to
        // the unit-test fixture; production state can only reach activation
        // through stage_verifier_key + activate_verifier_keys.
        core.verifier.ready = true;
        core.verifier.activated = true;
        for name in [
            "owner.testnet",
            "alice.testnet",
            "bob.testnet",
            "lender.testnet",
            "sender.testnet",
            "recipient.testnet",
        ] {
            core.storage_deposits.insert(&account(name), &u128::MAX);
        }
        core
    }

    fn minimal_broker(owner: AccountId, broker_id: u64, vault_id: u64) -> Broker {
        Broker {
            broker_id,
            owner,
            vault_id,
            encryption_key: EncryptionKey {
                key_id: 11,
                public_key: Vec::new(),
                registered_at: 0,
                authorization_epoch: 0,
            },
            authorization_epoch: 0,
            debt_total: 0,
            debt_maximum: 0,
            loan_sequence: 0,
            active_loan_count: 0,
            impaired_loan_count: 0,
            spending_ciphertext: Vec::new(),
            inbox_ciphertext: Vec::new(),
            issuer_balance_ciphertext: Vec::new(),
            auditor_balance_ciphertext: Vec::new(),
            spending_commitment: Vec::new(),
            inbox_commitment: Vec::new(),
            spending_version: 0,
            loan_book_root: Vec::new(),
            book_version: 0,
            active_principal_ciphertext: Vec::new(),
            impaired_principal_ciphertext: Vec::new(),
            active_principal_commitment: Vec::new(),
            impaired_principal_commitment: Vec::new(),
            impairment_provision: 0,
            cumulative_draws: 0,
            cumulative_settlements: 0,
            cumulative_yield: 0,
            cumulative_realized_losses: 0,
            accounting_version: 0,
            risk_version: 0,
            reconciled_risk_version: 0,
            accounting_pending: false,
            accounting_pending_since: 0,
            reconciliation_checkpoint_id: None,
            delegates: Vec::new(),
            last_settlement_at: 0,
            tombstoned: false,
        }
    }

    fn minimal_holder(core: &Core, owner: AccountId, key_id: u64) -> HolderBalance {
        HolderBalance {
            owner,
            asset_id: core.asset.token_account.clone(),
            encryption_key: EncryptionKey {
                key_id,
                public_key: Vec::new(),
                registered_at: 0,
                authorization_epoch: 0,
            },
            spending_ciphertext: Vec::new(),
            inbox_ciphertext: Vec::new(),
            issuer_balance_ciphertext: Vec::new(),
            auditor_balance_ciphertext: Vec::new(),
            spending_version: 0,
            authorization_epoch: 0,
            open_loan_count: 0,
            recovery_start_sequence: 0,
            frozen: false,
        }
    }

    fn minimal_proposal(
        borrower: AccountId,
        broker_id: u64,
        vault_id: u64,
        expiry: u64,
    ) -> Proposal {
        Proposal {
            proposal_id: 1,
            borrower,
            broker_id,
            vault_id,
            borrower_key_id: 22,
            broker_key_id: 11,
            loan_auditor_key_id: 3,
            loan_auditor_public_key: Vec::new(),
            payment_count: 1,
            payment_interval: 1,
            grace_period: 0,
            expiry,
            principal_ciphertexts: Vec::new(),
            initial_owed_ciphertexts: Vec::new(),
            periodic_payment_ciphertexts: Vec::new(),
            principal_commitment: Vec::new(),
            owed_commitment: Vec::new(),
            payment_commitment: Vec::new(),
            agreement_digest: Vec::new(),
            broker_signature: Vec::new(),
            borrower_signature: Vec::new(),
            broker_authorization_epoch: 0,
            borrower_authorization_epoch: 0,
            broker_authorization_nonce: 0,
            borrower_authorization_nonce: 0,
            broker_authorization_key_id: None,
            borrower_authorization_key_id: None,
            broker_direct_authorized: true,
            borrower_direct_authorized: true,
            consumed: false,
            revoked: false,
        }
    }

    fn empty_originate_args(proposal_id: u64) -> OriginateArgs {
        OriginateArgs {
            proposal_id,
            borrower_spending_ciphertext: Vec::new(),
            borrower_issuer_ciphertext: Vec::new(),
            borrower_auditor_ciphertext: Vec::new(),
            broker_spending_ciphertext: Vec::new(),
            broker_issuer_ciphertext: Vec::new(),
            broker_auditor_ciphertext: Vec::new(),
            loan_principal_ciphertexts: Vec::new(),
            loan_initial_owed_ciphertexts: Vec::new(),
            loan_periodic_payment_ciphertexts: Vec::new(),
            principal_commitment: Vec::new(),
            owed_commitment: Vec::new(),
            payment_commitment: Vec::new(),
            broker_active_principal_ciphertext: Vec::new(),
            broker_impaired_principal_ciphertext: Vec::new(),
            broker_book_root: Vec::new(),
            accounting_leaf: Vec::new(),
            broker_spending_commitment: Vec::new(),
            broker_active_principal_commitment: Vec::new(),
            broker_impaired_principal_commitment: Vec::new(),
            proof: ProofArgs {
                statement: Vec::new(),
                context: Vec::new(),
                proof: Vec::new(),
                statement_kind: None,
                public_inputs: Vec::new(),
                verifying_key_hash: Vec::new(),
                profile_hash: Vec::new(),
            },
        }
    }

    fn create_claim(core: &mut Core, claim_id: u64, owner: &AccountId, amount: u128) {
        core.claims.insert(
            &claim_id,
            &PublicClaim {
                claim_id,
                owner: owner.clone(),
                amount,
                created_at: 0,
                reserved_by: None,
            },
        );
        core.public_claim_total = core.public_claim_total.checked_add(amount).unwrap();
        core.custody_total = core.custody_total.checked_add(amount).unwrap();
    }

    fn closed_vault_args() -> CreateVaultArgs {
        CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::ClosedEnded,
            phase_times: Some(PhaseTimes {
                subscription_start: 100,
                investment_start: 200,
                redemption_start: 300,
                redemption_buffer: 0,
            }),
            share_scale: 0,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        }
    }

    #[test]
    fn init_rejects_invalid_manifest_identity_and_missing_family() {
        let _guard = test_guard();
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("owner.testnet"))
                .build()
        );
        let (manifest_json, _) = test_manifest();
        let mut value: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
        value["artifacts"]
            .as_object_mut()
            .unwrap()
            .remove("ownership.vk");
        let missing_json = serde_json::to_string(&value).unwrap();
        let missing_hash = Sha256::digest(missing_json.as_bytes()).to_vec();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Core::new(test_init_args(missing_json, missing_hash));
            }))
            .is_err()
        );

        let mismatched_json =
            manifest_json.replace("\"networkId\":\"local\"", "\"networkId\":\"other\"");
        let mismatched_hash = Sha256::digest(mismatched_json.as_bytes()).to_vec();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Core::new(test_init_args(mismatched_json, mismatched_hash));
            }))
            .is_err()
        );

        let (valid_json, _) = test_manifest();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Core::new(test_init_args(valid_json, vec![0; 32]));
            }))
            .is_err()
        );

        let (canonical_json, _) = test_manifest();
        let duplicate_json = canonical_json.replace(
            "\"schema\":\"confidential-lending-artifacts/v1\",",
            "\"schema\":\"confidential-lending-artifacts/v1\",\"schema\":\"confidential-lending-artifacts/v1\",",
        );
        let duplicate_hash = Sha256::digest(duplicate_json.as_bytes()).to_vec();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Core::new(test_init_args(duplicate_json, duplicate_hash));
            }))
            .is_err()
        );
    }

    #[test]
    fn staging_rejects_bytes_not_pinned_by_manifest() {
        let _guard = test_guard();
        let mut core = init();
        core.verifier.activated = false;
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("owner.testnet"))
                .build()
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.stage_verifier_key(1, vec![0; 2]);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn staging_accepts_real_prepared_key_with_complete_input_count() {
        let _guard = test_guard();
        let mut core = init();
        core.verifier.activated = false;
        core.verifier.ready = false;
        core.verifier.key_count = 0;

        let mut rng = StdRng::seed_from_u64(7);
        let artifacts = confidential_crypto::setup(StatementKind::KeyPossession, &mut rng)
            .expect("key-possession fixture");
        let artifact = artifacts
            .get(StatementKind::KeyPossession)
            .expect("key-possession artifact");
        let verifying_key = artifact.verifying_key_bytes().expect("canonical vk");
        let prepared_key = near_verifier::prepare_key(&verifying_key).expect("prepared vk");
        let expected = core
            .verifier
            .manifest_artifacts
            .iter_mut()
            .find(|entry| entry.statement_kind == 1)
            .expect("key-possession expectation");
        expected.verifying_key_sha256 = Sha256::digest(&verifying_key).to_vec();
        expected.verifying_key_bytes = verifying_key.len() as u32;
        expected.prepared_key_sha256 = Sha256::digest(&prepared_key).to_vec();
        expected.prepared_key_bytes = prepared_key.len() as u32;
        expected.public_input_count = (StatementKind::KeyPossession.slot_count() + 1) as u32;

        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("owner.testnet"))
                .build()
        );
        let hash = core.stage_verifier_key(1, prepared_key);
        assert_eq!(hash, Sha256::digest(&verifying_key).to_vec());
        assert_eq!(
            core.get_verifier_key(1).unwrap().public_input_count as usize,
            StatementKind::KeyPossession.slot_count() + 1
        );
    }

    #[test]
    fn registration_requires_activated_verifier_set() {
        let _guard = test_guard();
        let mut core = init();
        core.verifier.ready = false;
        core.verifier.activated = false;
        let owner = account("alice.testnet");
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .build()
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.register_holder(RegisterHolderArgs {
                key_id: 22,
                public_key: test_public_key(22),
                encryption_public_key: Vec::new(),
                proof_of_possession: ProofArgs {
                    statement: Vec::new(),
                    context: vec![0; 32],
                    proof: vec![1],
                    statement_kind: Some(1),
                    public_inputs: Vec::new(),
                    verifying_key_hash: vec![0; 32],
                    profile_hash: confidential_crypto::PROFILE_HASH.to_vec(),
                },
                zero_proofs: Vec::new(),
                authorization_signature: Vec::new(),
            });
        }));
        assert!(result.is_err());
        assert!(core.holders.get(&owner).is_none());
    }

    #[test]
    fn wide_share_product_and_rounding() {
        assert_eq!(mul_div_floor(u128::MAX, 2, 2), u128::MAX);
        assert_eq!(mul_div_floor(10, 3, 4), 7);
        assert_eq!(mul_div_floor(1, 1, 2), 0);
    }

    #[test]
    fn first_deposit_uses_share_scale_and_public_claim() {
        let _guard = test_guard();
        let mut core = init();
        let vault_id = core.create_vault(CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::OpenEnded,
            phase_times: None,
            share_scale: 6,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        });
        let owner = account("lender.testnet");
        core.claims.insert(
            &7,
            &PublicClaim {
                claim_id: 7,
                owner: owner.clone(),
                amount: 1_000_000,
                created_at: 0,
                reserved_by: None,
            },
        );
        core.public_claim_total = 1_000_000;
        core.custody_total = 1_000_000;
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .block_timestamp(1)
                .build()
        );
        core.deposit_to_vault(DepositToVaultArgs {
            claim_id: 7,
            vault_id: vault_id.0,
            amount: U128(1_000_000),
            min_shares_out: U128(1_000_000),
            expiry: 100,
        });
        assert_eq!(
            core.get_share_balance(vault_id, owner),
            U128(1_000_000_000_000)
        );
        assert_eq!(core.get_claim(U64(7)), None);
        assert_eq!(
            core.get_vault(vault_id).unwrap().assets_total,
            U128(1_000_000)
        );
    }

    #[test]
    fn closed_ended_vault_enforces_subscription_investment_redemption_boundaries() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner)
                .block_timestamp(0)
                .build()
        );
        let vault_id = core.create_vault(closed_vault_args());
        let lender = account("lender.testnet");
        create_claim(&mut core, 31, &lender, 100);

        // Before subscription starts, even a public claim cannot enter the
        // vault.  The claim remains available after the rejected call.
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(lender.clone())
                .block_timestamp(50_000_000_000)
                .build()
        );
        let before_subscription = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.deposit_to_vault(DepositToVaultArgs {
                claim_id: 31,
                vault_id: vault_id.0,
                amount: U128(100),
                min_shares_out: U128(100),
                expiry: 1_000,
            });
        }));
        assert!(before_subscription.is_err());
        assert!(core.get_claim(U64(31)).is_some());

        // Subscription permits both deposits and redemptions.
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(lender.clone())
                .block_timestamp(150_000_000_000)
                .build()
        );
        core.deposit_to_vault(DepositToVaultArgs {
            claim_id: 31,
            vault_id: vault_id.0,
            amount: U128(100),
            min_shares_out: U128(100),
            expiry: 1_000,
        });
        assert_eq!(core.get_share_balance(vault_id, lender.clone()), U128(100));
        let subscription_redeem = core.redeem_shares(RedeemSharesArgs {
            vault_id: vault_id.0,
            shares: U128(10),
            min_assets_out: U128(10),
            expiry: 1_000,
            sole_shareholder_waiver: false,
            burn_worthless: false,
            broker_zero_proofs: Vec::new(),
        });
        assert!(core.get_claim(subscription_redeem).is_some());

        // The investment phase is the only closed-ended phase for new
        // origination/draw paths; deposits and redemptions are rejected.
        create_claim(&mut core, 32, &lender, 1);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(lender.clone())
                .block_timestamp(250_000_000_000)
                .build()
        );
        let investment_deposit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.deposit_to_vault(DepositToVaultArgs {
                claim_id: 32,
                vault_id: vault_id.0,
                amount: U128(1),
                min_shares_out: U128(1),
                expiry: 1_000,
            });
        }));
        assert!(investment_deposit.is_err());
        let investment_redeem = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(1),
                min_assets_out: U128(1),
                expiry: 1_000,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(investment_redeem.is_err());

        // Redemption reopens withdrawals while continuing to reject deposits.
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(lender)
                .block_timestamp(350_000_000_000)
                .build()
        );
        let redemption = core.redeem_shares(RedeemSharesArgs {
            vault_id: vault_id.0,
            shares: U128(1),
            min_assets_out: U128(1),
            expiry: 1_000,
            sole_shareholder_waiver: false,
            burn_worthless: false,
            broker_zero_proofs: Vec::new(),
        });
        assert_eq!(core.get_claim(redemption).unwrap().amount, U128(1));
    }

    #[test]
    fn share_mint_and_redeem_guards_reject_rounding_slippage_and_illiquidity() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner)
                .build()
        );
        let vault_id = core.create_vault(CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::OpenEnded,
            phase_times: None,
            share_scale: 0,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        });
        let lender = account("lender.testnet");
        create_claim(&mut core, 41, &lender, 100);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(lender.clone())
                .block_timestamp(1_000_000_000)
                .build()
        );
        core.deposit_to_vault(DepositToVaultArgs {
            claim_id: 41,
            vault_id: vault_id.0,
            amount: U128(100),
            min_shares_out: U128(100),
            expiry: 100,
        });

        // Slippage is checked before consuming the claim.
        create_claim(&mut core, 42, &lender, 1);
        let mint_slippage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.deposit_to_vault(DepositToVaultArgs {
                claim_id: 42,
                vault_id: vault_id.0,
                amount: U128(1),
                min_shares_out: U128(2),
                expiry: 100,
            });
        }));
        assert!(mint_slippage.is_err());
        assert!(core.get_claim(U64(42)).is_some());

        // A positive NAV can still round a tiny deposit to zero shares.
        let mut vault = core.vaults.get(&vault_id.0).unwrap();
        vault.shares_total = 1;
        vault.assets_total = 100;
        vault.assets_available = 100;
        core.vaults.insert(&vault_id.0, &vault);
        core.shares.insert(&share_key(vault_id.0, &lender), &1);
        create_claim(&mut core, 43, &lender, 1);
        let zero_mint = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.deposit_to_vault(DepositToVaultArgs {
                claim_id: 43,
                vault_id: vault_id.0,
                amount: U128(1),
                min_shares_out: U128(0),
                expiry: 100,
            });
        }));
        assert!(zero_mint.is_err());
        assert!(core.get_claim(U64(43)).is_some());

        // Redemption slippage and liquidity failures likewise leave shares
        // untouched and never create a claim.
        let redeem_slippage = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(1),
                min_assets_out: U128(101),
                expiry: 100,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(redeem_slippage.is_err());
        assert_eq!(core.get_share_balance(vault_id, lender.clone()), U128(1));
        let mut vault = core.vaults.get(&vault_id.0).unwrap();
        vault.assets_available = 0;
        core.vaults.insert(&vault_id.0, &vault);
        let insufficient = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(1),
                min_assets_out: U128(0),
                expiry: 100,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(insufficient.is_err());

        // A positive NAV cannot be consumed by a zero-result partial burn.
        vault.assets_total = 1;
        vault.assets_available = 1;
        vault.shares_total = 3;
        core.vaults.insert(&vault_id.0, &vault);
        core.shares.insert(&share_key(vault_id.0, &lender), &1);
        let other = account("bob.testnet");
        core.shares.insert(&share_key(vault_id.0, &other), &2);
        let zero_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(1),
                min_assets_out: U128(0),
                expiry: 100,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(zero_result.is_err());
        assert_eq!(core.get_share_balance(vault_id, lender), U128(1));

        // Pending accounting blocks both NAV-priced directions.
        vault.accounting_pending = true;
        vault.assets_available = 1;
        core.vaults.insert(&vault_id.0, &vault);
        let pending = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(1),
                min_assets_out: U128(0),
                expiry: 100,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(pending.is_err());
    }

    #[test]
    fn final_redemption_releases_rounding_dust_and_sole_waiver_is_explicit() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner)
                .build()
        );
        let vault_id = core.create_vault(CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::OpenEnded,
            phase_times: None,
            share_scale: 0,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        });
        let first = account("lender.testnet");
        let second = account("bob.testnet");
        let mut vault = core.vaults.get(&vault_id.0).unwrap();
        vault.assets_total = 5;
        vault.assets_available = 5;
        vault.shares_total = 3;
        core.vaults.insert(&vault_id.0, &vault);
        core.shares.insert(&share_key(vault_id.0, &first), &1);
        core.shares.insert(&share_key(vault_id.0, &second), &2);

        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(first)
                .block_timestamp(1_000_000_000)
                .build()
        );
        let first_claim = core.redeem_shares(RedeemSharesArgs {
            vault_id: vault_id.0,
            shares: U128(1),
            min_assets_out: U128(1),
            expiry: 100,
            sole_shareholder_waiver: false,
            burn_worthless: false,
            broker_zero_proofs: Vec::new(),
        });
        assert_eq!(core.get_claim(first_claim).unwrap().amount, U128(1));

        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(second)
                .block_timestamp(1_000_000_000)
                .build()
        );
        let final_claim = core.redeem_shares(RedeemSharesArgs {
            vault_id: vault_id.0,
            shares: U128(2),
            min_assets_out: U128(4),
            expiry: 100,
            sole_shareholder_waiver: false,
            burn_worthless: false,
            broker_zero_proofs: Vec::new(),
        });
        assert_eq!(core.get_claim(final_claim).unwrap().amount, U128(4));
        let closed = core.get_vault(vault_id).unwrap();
        assert_eq!(closed.shares_total, U128(0));
        assert_eq!(closed.assets_total, U128(0));
        assert_eq!(closed.assets_available, U128(0));

        // With unrealized loss, only the explicit sole-owner waiver can use
        // gross T rather than NAV.  It is still a normal partial redemption.
        let waiver_vault = core.create_vault(CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::OpenEnded,
            phase_times: None,
            share_scale: 0,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        });
        let waiver_owner = account("lender.testnet");
        let mut waiver_state = core.vaults.get(&waiver_vault.0).unwrap();
        waiver_state.assets_total = 100;
        waiver_state.assets_available = 100;
        waiver_state.loss_unrealized = 20;
        waiver_state.shares_total = 100;
        core.vaults.insert(&waiver_vault.0, &waiver_state);
        core.shares
            .insert(&share_key(waiver_vault.0, &waiver_owner), &100);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(waiver_owner)
                .block_timestamp(1_000_000_000)
                .build()
        );
        let waiver_claim = core.redeem_shares(RedeemSharesArgs {
            vault_id: waiver_vault.0,
            shares: U128(10),
            min_assets_out: U128(10),
            expiry: 100,
            sole_shareholder_waiver: true,
            burn_worthless: false,
            broker_zero_proofs: Vec::new(),
        });
        assert_eq!(core.get_claim(waiver_claim).unwrap().amount, U128(10));
    }

    #[test]
    fn deposit_receipt_is_sender_scoped_and_idempotent() {
        let _guard = test_guard();
        let mut core = init();
        let sender = account("sender.testnet");
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("token.testnet"))
                .block_timestamp(1)
                .build()
        );
        let first = core.ft_on_transfer(
            sender.clone(),
            U128(25),
            r#"{"version":1,"deposit_id":"d1"}"#.into(),
        );
        assert!(matches!(first, PromiseOrValue::Value(U128(0))));
        let duplicate = core.ft_on_transfer(
            sender,
            U128(25),
            r#"{"deposit_id":"d1","version":1}"#.into(),
        );
        assert!(matches!(duplicate, PromiseOrValue::Value(U128(25))));
        let unknown = core.ft_on_transfer(
            account("sender.testnet"),
            U128(25),
            r#"{"version":1,"deposit_id":"d2","extra":true}"#.into(),
        );
        assert!(matches!(unknown, PromiseOrValue::Value(U128(25))));
        assert_eq!(core.public_claim_total, 25);
    }

    #[test]
    fn payout_requires_runtime_result_before_finalize() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("lender.testnet");
        core.claims.insert(
            &9,
            &PublicClaim {
                claim_id: 9,
                owner: owner.clone(),
                amount: 10,
                created_at: 0,
                reserved_by: None,
            },
        );
        core.public_claim_total = 10;
        core.custody_total = 10;
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        let _promise = core.request_payout(RequestPayoutArgs {
            claim_id: 9,
            recipient: account("recipient.testnet"),
            operation_id: 42,
        });
        assert!(matches!(
            core.get_payout(U64(42)).unwrap().status,
            PayoutStatus::InFlight
        ));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.finalize_payout(U64(42))
        }));
        assert!(result.is_err());
        assert_eq!(core.get_claim(U64(9)).unwrap().reserved_by, Some(42));
    }

    #[test]
    fn authorization_epoch_and_nonce_reject_stale_relays() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("alice.testnet");
        core.authorization_keys.insert(
            &authorization_key(&owner, 7),
            &AuthorizationKey {
                owner: owner.clone(),
                key_id: 7,
                public_key: vec![9; 32],
                epoch: 3,
                nonce: 2,
                revoked: false,
            },
        );
        validate_authorization_nonce(&core, &owner, Some(7), 3, 2);
        assert!(!verify_authorization_signature(
            &core,
            &owner,
            Some(7),
            3,
            1,
            b"repay",
            &[0; 64],
        ));
        let stale = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_authorization_nonce(&core, &owner, Some(7), 3, 1)
        }));
        assert!(stale.is_err());
        let revoked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_authorization_nonce(&core, &owner, Some(8), 3, 2)
        }));
        assert!(revoked.is_err());
    }

    #[test]
    fn signed_broker_proposal_uses_registered_application_epoch() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        let borrower = account("alice.testnet");
        let public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155".to_string()
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        core.authorization_keys.insert(
            &authorization_key(&owner, 7),
            &AuthorizationKey {
                owner: owner.clone(),
                key_id: 7,
                public_key,
                epoch: 3,
                nonce: 2,
                revoked: false,
            },
        );
        core.brokers.insert(
            &7,
            &Broker {
                broker_id: 7,
                owner: owner.clone(),
                vault_id: 1,
                encryption_key: EncryptionKey {
                    key_id: 11,
                    public_key: Vec::new(),
                    registered_at: 0,
                    authorization_epoch: 0,
                },
                authorization_epoch: 0,
                debt_total: 0,
                debt_maximum: 0,
                loan_sequence: 0,
                active_loan_count: 0,
                impaired_loan_count: 0,
                spending_ciphertext: Vec::new(),
                inbox_ciphertext: Vec::new(),
                issuer_balance_ciphertext: Vec::new(),
                auditor_balance_ciphertext: Vec::new(),
                spending_commitment: Vec::new(),
                inbox_commitment: Vec::new(),
                spending_version: 0,
                loan_book_root: Vec::new(),
                book_version: 0,
                active_principal_ciphertext: Vec::new(),
                impaired_principal_ciphertext: Vec::new(),
                active_principal_commitment: Vec::new(),
                impaired_principal_commitment: Vec::new(),
                impairment_provision: 0,
                cumulative_draws: 0,
                cumulative_settlements: 0,
                cumulative_yield: 0,
                cumulative_realized_losses: 0,
                accounting_version: 0,
                risk_version: 0,
                reconciled_risk_version: 0,
                accounting_pending: false,
                accounting_pending_since: 0,
                reconciliation_checkpoint_id: None,
                delegates: Vec::new(),
                last_settlement_at: 0,
                tombstoned: false,
            },
        );
        core.proposals.insert(
            &1,
            &Proposal {
                proposal_id: 1,
                borrower,
                broker_id: 7,
                vault_id: 1,
                borrower_key_id: 2,
                broker_key_id: 11,
                loan_auditor_key_id: 3,
                loan_auditor_public_key: Vec::new(),
                payment_count: 1,
                payment_interval: 1,
                grace_period: 0,
                expiry: u64::MAX,
                principal_ciphertexts: Vec::new(),
                initial_owed_ciphertexts: Vec::new(),
                periodic_payment_ciphertexts: Vec::new(),
                principal_commitment: Vec::new(),
                owed_commitment: Vec::new(),
                payment_commitment: Vec::new(),
                agreement_digest: Vec::new(),
                broker_signature: Vec::new(),
                borrower_signature: Vec::new(),
                broker_authorization_epoch: 3,
                borrower_authorization_epoch: 1,
                broker_authorization_nonce: 2,
                borrower_authorization_nonce: 0,
                broker_authorization_key_id: Some(7),
                borrower_authorization_key_id: None,
                broker_direct_authorized: false,
                borrower_direct_authorized: true,
                consumed: false,
                revoked: false,
            },
        );
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner)
                .build()
        );
        core.sign_proposal(U64(1), signature.clone());
        assert_eq!(core.proposals.get(&1).unwrap().broker_signature, signature);
    }

    #[test]
    fn proposal_dates_and_authorization_boundaries_are_terminal() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        let borrower = account("alice.testnet");
        let broker_id = 7;
        core.brokers
            .insert(&broker_id, &minimal_broker(owner.clone(), broker_id, 1));
        core.holders
            .insert(&borrower, &minimal_holder(&core, borrower.clone(), 22));

        let make_args = |payment_interval: u64, expiry: u64| CreateProposalArgs {
            borrower: borrower.clone(),
            broker_id,
            vault_id: 1,
            borrower_key_id: 22,
            broker_key_id: 11,
            loan_auditor_key_id: 3,
            loan_auditor_public_key: Vec::new(),
            payment_count: 1,
            payment_interval,
            grace_period: 0,
            expiry,
            principal_ciphertexts: Vec::new(),
            initial_owed_ciphertexts: Vec::new(),
            periodic_payment_ciphertexts: Vec::new(),
            principal_commitment: Vec::new(),
            owed_commitment: Vec::new(),
            payment_commitment: Vec::new(),
            agreement_digest: Vec::new(),
            broker_signature: Vec::new(),
            borrower_signature: Vec::new(),
            broker_authorization_epoch: 0,
            borrower_authorization_epoch: 0,
            broker_authorization_nonce: 0,
            borrower_authorization_nonce: 0,
            broker_authorization_key_id: None,
            borrower_authorization_key_id: None,
        };

        // A non-party cannot submit even a malformed proposal.  Date and
        // interval checks then reject overflow-equivalent wire values before
        // any ciphertext/commitment parsing.
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("mallory.testnet"))
                .build()
        );
        let unauthorized_create = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.create_proposal(make_args(1, u64::MAX));
        }));
        assert!(unauthorized_create.is_err());
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .build()
        );
        let interval_overflow = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.create_proposal(make_args(u64::MAX, u64::MAX));
        }));
        assert!(interval_overflow.is_err());
        let expired_create = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.create_proposal(make_args(1, 0));
        }));
        assert!(expired_create.is_err());

        // Cancellation is owner/borrower-only, permanent, and blocks the
        // subsequent origination entrypoint before proof processing.
        core.proposals.insert(
            &1,
            &minimal_proposal(borrower.clone(), broker_id, 1, u64::MAX),
        );
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("mallory.testnet"))
                .build()
        );
        let unauthorized_revoke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.revoke_proposal(U64(1));
        }));
        assert!(unauthorized_revoke.is_err());
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .build()
        );
        core.revoke_proposal(U64(1));
        assert!(core.proposals.get(&1).unwrap().revoked);
        let duplicate_revoke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.revoke_proposal(U64(1));
        }));
        assert!(duplicate_revoke.is_err());
        let canceled_origination = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.originate(empty_originate_args(1));
        }));
        assert!(canceled_origination.is_err());

        // Expiry is checked before holder/proof material, and an unrelated
        // caller cannot use a valid broker's proposal.
        core.proposals
            .insert(&2, &minimal_proposal(borrower.clone(), broker_id, 1, 0));
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .block_timestamp(1_000_000_000)
                .build()
        );
        let expired_origination = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.originate(empty_originate_args(2));
        }));
        assert!(expired_origination.is_err());

        let mut overflowing_date = minimal_proposal(borrower.clone(), broker_id, 1, u64::MAX);
        overflowing_date.payment_interval = u64::MAX;
        core.proposals.insert(&4, &overflowing_date);
        let date_overflow = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.originate(empty_originate_args(4));
        }));
        assert!(date_overflow.is_err());

        core.proposals
            .insert(&3, &minimal_proposal(borrower, broker_id, 1, u64::MAX));
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("mallory.testnet"))
                .build()
        );
        let unauthorized_origination =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                core.originate(empty_originate_args(3));
            }));
        assert!(unauthorized_origination.is_err());
    }

    #[test]
    fn zero_nav_redemption_requires_explicit_worthless_burn() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("lender.testnet");
        let vault_id = core.create_vault(CreateVaultArgs {
            assets_maximum: U128(0),
            kind: VaultKind::OpenEnded,
            phase_times: None,
            share_scale: 6,
            shares_transferable: true,
            checkpoint_policy: CheckpointPolicy {
                epoch_seconds: 60,
                disclosure_policy: "aggregate".into(),
            },
        });
        let mut vault = core.vaults.get(&vault_id.0).unwrap();
        vault.shares_total = 10;
        core.vaults.insert(&vault_id.0, &vault);
        core.shares.insert(&share_key(vault_id.0, &owner), &10);
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .block_timestamp(1_000_000_000)
                .build()
        );
        let no_burn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.redeem_shares(RedeemSharesArgs {
                vault_id: vault_id.0,
                shares: U128(10),
                min_assets_out: U128(0),
                expiry: 100,
                sole_shareholder_waiver: false,
                burn_worthless: false,
                broker_zero_proofs: Vec::new(),
            });
        }));
        assert!(no_burn.is_err());
        let claim_id = core.redeem_shares(RedeemSharesArgs {
            vault_id: vault_id.0,
            shares: U128(10),
            min_assets_out: U128(0),
            expiry: 100,
            sole_shareholder_waiver: false,
            burn_worthless: true,
            broker_zero_proofs: Vec::new(),
        });
        assert_eq!(claim_id, U64(0));
        assert_eq!(core.get_share_balance(vault_id, owner), U128(0));
    }

    #[test]
    fn holder_rotation_requires_fresh_key_and_exposes_recovery_boundary() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("alice.testnet");
        let old_public_key = test_public_key(17);
        core.holders.insert(
            &owner,
            &HolderBalance {
                owner: owner.clone(),
                asset_id: core.asset.token_account.clone(),
                encryption_key: EncryptionKey {
                    key_id: 41,
                    public_key: old_public_key.clone(),
                    registered_at: 1,
                    authorization_epoch: 3,
                },
                spending_ciphertext: Vec::new(),
                inbox_ciphertext: Vec::new(),
                issuer_balance_ciphertext: Vec::new(),
                auditor_balance_ciphertext: Vec::new(),
                spending_version: 7,
                authorization_epoch: 3,
                open_loan_count: 0,
                recovery_start_sequence: 11,
                frozen: true,
            },
        );
        core.recovery_subject_counts
            .insert(&format!("holder:{owner}"), &19);

        let view = core.get_holder(owner.clone()).expect("holder view");
        assert_eq!(view.recovery_start_sequence, 11);

        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .build()
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            core.register_holder(RegisterHolderArgs {
                key_id: 41,
                encryption_public_key: old_public_key.clone(),
                public_key: Vec::new(),
                proof_of_possession: ProofArgs {
                    statement: Vec::new(),
                    context: Vec::new(),
                    proof: Vec::new(),
                    statement_kind: None,
                    public_inputs: Vec::new(),
                    verifying_key_hash: Vec::new(),
                    profile_hash: Vec::new(),
                },
                zero_proofs: Vec::new(),
                authorization_signature: Vec::new(),
            });
        }));
        assert!(result.is_err());

        let unchanged = core.holders.get(&owner).expect("holder remains");
        assert_eq!(unchanged.encryption_key.key_id, 41);
        assert!(unchanged.frozen);
        assert_eq!(unchanged.recovery_start_sequence, 11);
    }

    #[test]
    fn keeper_grants_replace_and_prune_bounded_live_slots() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("owner.testnet");
        let delegate_a = account("keeper-a.testnet");
        let delegate_b = account("keeper-b.testnet");
        let delegate_c = account("keeper-c.testnet");
        for (delegate, key_id) in [
            (delegate_a.clone(), 1_u64),
            (delegate_b.clone(), 2_u64),
            (delegate_c.clone(), 3_u64),
        ] {
            core.authorization_keys.insert(
                &authorization_key(&delegate, key_id),
                &AuthorizationKey {
                    owner: delegate,
                    key_id,
                    public_key: Vec::new(),
                    epoch: 1,
                    nonce: 0,
                    revoked: false,
                },
            );
        }
        core.brokers.insert(
            &7,
            &Broker {
                broker_id: 7,
                owner: owner.clone(),
                vault_id: 1,
                encryption_key: EncryptionKey {
                    key_id: 1,
                    public_key: Vec::new(),
                    registered_at: 0,
                    authorization_epoch: 0,
                },
                authorization_epoch: 0,
                debt_total: 0,
                debt_maximum: 0,
                loan_sequence: 0,
                active_loan_count: 0,
                impaired_loan_count: 0,
                spending_ciphertext: Vec::new(),
                inbox_ciphertext: Vec::new(),
                issuer_balance_ciphertext: Vec::new(),
                auditor_balance_ciphertext: Vec::new(),
                spending_commitment: Vec::new(),
                inbox_commitment: Vec::new(),
                spending_version: 0,
                loan_book_root: Vec::new(),
                book_version: 0,
                active_principal_ciphertext: Vec::new(),
                impaired_principal_ciphertext: Vec::new(),
                active_principal_commitment: Vec::new(),
                impaired_principal_commitment: Vec::new(),
                impairment_provision: 0,
                cumulative_draws: 0,
                cumulative_settlements: 0,
                cumulative_yield: 0,
                cumulative_realized_losses: 0,
                accounting_version: 0,
                risk_version: 0,
                reconciled_risk_version: 0,
                accounting_pending: false,
                accounting_pending_since: 0,
                reconciliation_checkpoint_id: None,
                delegates: Vec::new(),
                last_settlement_at: 0,
                tombstoned: false,
            },
        );
        let grant =
            |delegate_account: AccountId, delegate_key_id: u64, expires_at: u64| GrantKeeperArgs {
                broker_id: 7,
                delegate_account,
                delegate_key_id,
                allowed_settlement_per_operation: U128(10),
                allowed_settlement_per_window: U128(100),
                window_seconds: 60,
                expires_at,
                delegate_epoch: 1,
                allowed_operations: vec![KeeperOperation::Settle],
            };

        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .block_timestamp(1_000_000_000)
                .build()
        );
        core.grant_keeper(grant(delegate_a.clone(), 1, 6));
        core.grant_keeper(grant(delegate_a.clone(), 1, 15));
        assert_eq!(core.brokers.get(&7).unwrap().delegates.len(), 1);
        assert_eq!(core.brokers.get(&7).unwrap().delegates[0].expires_at, 15);

        core.grant_keeper(grant(delegate_b, 2, 6));
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner)
                .block_timestamp(20_000_000_000)
                .build()
        );
        core.grant_keeper(grant(delegate_c, 3, 100));
        let broker = core.brokers.get(&7).unwrap();
        assert_eq!(broker.delegates.len(), 1);
        assert_eq!(broker.delegates[0].delegate_key_id, 3);
        assert_eq!(broker.authorization_epoch, 4);
    }

    #[allow(deprecated)]
    #[test]
    fn payout_success_is_terminal_and_permissionless_finalize_is_idempotent() {
        let _guard = test_guard();
        let mut core = init();
        let owner = account("lender.testnet");
        core.claims.insert(
            &9,
            &PublicClaim {
                claim_id: 9,
                owner: owner.clone(),
                amount: 10,
                created_at: 0,
                reserved_by: None,
            },
        );
        core.public_claim_total = 10;
        core.custody_total = 10;
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .attached_deposit(NearToken::from_yoctonear(1))
                .build()
        );
        let _promise = core.request_payout(RequestPayoutArgs {
            claim_id: 9,
            recipient: account("recipient.testnet"),
            operation_id: 42,
        });
        let call_hash = core.payouts.get(&42).unwrap().call_hash;
        testing_env_with_promise_results(
            VMContextBuilder::new()
                .current_account_id(account("test.testnet"))
                .predecessor_account_id(account("test.testnet"))
                .build(),
            PromiseResult::Successful(Vec::new()),
        );
        assert!(core.on_payout_result(U64(42), 1, call_hash));
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("finalizer.testnet"))
                .build()
        );
        core.finalize_payout(U64(42));
        core.finalize_payout(U64(42));
        assert_eq!(core.get_claim(U64(9)), None);
        assert!(matches!(
            core.get_payout(U64(42)).unwrap().status,
            PayoutStatus::Succeeded
        ));
    }
}
