#![forbid(unsafe_code)]

//! Confidential lending Core contract.
//!
//! Private values are stored only as opaque ciphertexts, commitments, and
//! proof-bound byte strings. Public monetary values remain u128 in storage and
//! are exposed as decimal U128 values. External token movement is confined to
//! the receipt and payout state machines at the end of this module.

mod types;

use borsh::{BorshSerialize, to_vec};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, env,
    ext_contract, near, near_bindgen, require,
};
use sha2::{Digest, Sha256};

pub use types::*;

const MAX_ASSET_UNITS: u128 = i64::MAX as u128;
const MAX_PAYMENT_COUNT: u32 = 10_000;
const MAX_INTERVAL_SECONDS: u64 = 365 * 24 * 60 * 60;
const MAX_ID_BYTES: usize = 128;
const PAYOUT_GAS: Gas = Gas::from_tgas(20);
const MAX_CHECKPOINT_EPOCH: u64 = 86_400;
const MIN_CHECKPOINT_EPOCH: u64 = 60;

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
}

#[ext_contract(ext_ft)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_self)]
trait CoreCallbacks {
    fn on_payout_result(&mut self, operation_id: u64, attempt: u32, result_hash: Vec<u8>) -> bool;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Core {
    pub asset: AssetProfile,
    pub verifier: VerifierConfig,
    pub owner: AccountId,
    pub vault_sequence: u64,
    pub broker_sequence: u64,
    pub loan_sequence: u64,
    pub proposal_sequence: u64,
    pub claim_sequence: u64,
    pub operation_sequence: u64,
    pub checkpoint_sequence: u64,
    pub vaults: UnorderedMap<u64, Vault>,
    pub brokers: UnorderedMap<u64, Broker>,
    pub loans: UnorderedMap<u64, Loan>,
    pub holders: LookupMap<AccountId, HolderBalance>,
    pub proposals: UnorderedMap<u64, Proposal>,
    pub claims: UnorderedMap<u64, PublicClaim>,
    pub receipts: LookupMap<String, DepositReceipt>,
    pub payouts: UnorderedMap<u64, PayoutOperation>,
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
    pub storage_deposits: LookupMap<AccountId, u128>,
    pub authorization_keys: LookupMap<Vec<u8>, AuthorizationKey>,
}

#[near_bindgen]
impl Core {
    /// Deploy with an immutable asset and reviewed cryptographic profile.
    /// Empty verifier artifacts are rejected; no upgrade method exists.
    #[init]
    pub fn new(args: InitArgs) -> Self {
        require!(!args.network_id.is_empty(), ERR_INVALID_ENCODING);
        require!(!args.issuer_public_key.is_empty(), ERR_INVALID_ENCODING);
        require!(
            !args.token_auditor_public_key.is_empty(),
            ERR_INVALID_ENCODING
        );
        require!(
            !args.crypto_profile_hash.is_empty(),
            ERR_UNSUPPORTED_PROFILE
        );
        require!(!args.verifier_key.is_empty(), ERR_UNSUPPORTED_PROFILE);
        require!(
            !args.verifier_manifest_hash.is_empty(),
            ERR_UNSUPPORTED_PROFILE
        );
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
                verifying_key: args.verifier_key,
                manifest_hash: args.verifier_manifest_hash,
                production: true,
            },
            owner,
            vault_sequence: 0,
            broker_sequence: 0,
            loan_sequence: 0,
            proposal_sequence: 0,
            claim_sequence: 0,
            operation_sequence: 0,
            checkpoint_sequence: 0,
            vaults: UnorderedMap::new(StorageKey::Vaults),
            brokers: UnorderedMap::new(StorageKey::Brokers),
            loans: UnorderedMap::new(StorageKey::Loans),
            holders: LookupMap::new(StorageKey::Holders),
            proposals: UnorderedMap::new(StorageKey::Proposals),
            claims: UnorderedMap::new(StorageKey::Claims),
            receipts: LookupMap::new(StorageKey::Receipts),
            payouts: UnorderedMap::new(StorageKey::Payouts),
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
            storage_deposits: LookupMap::new(StorageKey::StorageDeposits),
            authorization_keys: LookupMap::new(StorageKey::AuthorizationKeys),
        }
    }

    pub fn get_asset_profile(&self) -> AssetProfile {
        self.asset.clone()
    }

    pub fn get_verifier_config(&self) -> VerifierConfig {
        self.verifier.clone()
    }

    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> U128 {
        let account = account_id.unwrap_or_else(env::predecessor_account_id);
        require!(account == env::predecessor_account_id(), ERR_UNAUTHORIZED);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, ERR_STORAGE);
        let current = self.storage_deposits.get(&account).unwrap_or(0);
        let updated = current
            .checked_add(deposit)
            .unwrap_or_else(|| panic!("{ERR_STORAGE}"));
        self.storage_deposits.insert(&account, &updated);
        U128(updated)
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.storage_deposits.get(&account_id).unwrap_or(0))
    }

    pub fn register_holder(&mut self, args: RegisterHolderArgs) {
        let owner = env::predecessor_account_id();
        validate_ciphertext(&args.public_key);
        require!(!args.proof_of_possession.is_empty(), ERR_BAD_PROOF);
        require!(!args.authorization_signature.is_empty(), ERR_UNAUTHORIZED);
        let old_epoch = self
            .holders
            .get(&owner)
            .map(|h| h.authorization_epoch)
            .unwrap_or(0);
        let key = EncryptionKey {
            key_id: args.key_id,
            public_key: args.public_key,
            registered_at: now_seconds(),
            authorization_epoch: old_epoch
                .checked_add(1)
                .unwrap_or_else(|| panic!("{ERR_STALE_STATE}")),
        };
        if let Some(existing) = self.holders.get(&owner) {
            require!(
                existing.spending_ciphertext == zero_ciphertext(),
                ERR_HAS_OBLIGATIONS
            );
            require!(
                existing.inbox_ciphertext == zero_ciphertext(),
                ERR_HAS_OBLIGATIONS
            );
        }
        let context = to_vec(&(
            owner.clone(),
            key.key_id,
            &key.public_key,
            &args.authorization_signature,
        ))
        .unwrap_or_else(|_| panic!("{ERR_INVALID_ENCODING}"));
        self.verify_proof(b"key-possession", &context, &args.proof_of_possession);
        self.holders.insert(
            &owner,
            &HolderBalance {
                owner: owner.clone(),
                asset_id: self.asset.token_account.clone(),
                encryption_key: key,
                spending_ciphertext: zero_ciphertext(),
                inbox_ciphertext: zero_ciphertext(),
                issuer_balance_ciphertext: zero_ciphertext(),
                auditor_balance_ciphertext: zero_ciphertext(),
                spending_version: 0,
                authorization_epoch: old_epoch
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("{ERR_STALE_STATE}")),
                frozen: false,
            },
        );
        self.emit(
            "HolderRegistered",
            json!({"account_id": owner, "authorization_epoch": old_epoch + 1}),
        );
    }

    pub fn register_authorization_key(&mut self, args: RegisterAuthorizationKeyArgs) {
        let owner = env::predecessor_account_id();
        require!(
            !args.public_key.is_empty() && !args.proof.is_empty(),
            ERR_BAD_PROOF
        );
        validate_ciphertext(&args.public_key);
        let holder = self.holder_or_panic(&owner);
        let epoch = holder
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        let key = AuthorizationKey {
            owner: owner.clone(),
            key_id: args.key_id,
            public_key: args.public_key,
            epoch,
            nonce: 0,
            revoked: false,
        };
        let context = to_vec(&(owner.clone(), key.key_id, &key.public_key, epoch))
            .unwrap_or_else(|_| panic!("{ERR_INVALID_ENCODING}"));
        self.verify_proof(b"authorization-key", &context, &args.proof);
        let mut updated_holder = holder;
        updated_holder.authorization_epoch = epoch;
        self.holders.insert(&owner, &updated_holder);
        self.authorization_keys
            .insert(&authorization_key(&owner, args.key_id), &key);
        self.emit(
            "AuthorizationKeyRegistered",
            json!({"account_id": owner, "key_id": args.key_id, "epoch": epoch}),
        );
    }

    pub fn revoke_authorization_key(&mut self, key_id: u64) {
        let owner = env::predecessor_account_id();
        let key_id_bytes = authorization_key(&owner, key_id);
        let mut key = self
            .authorization_keys
            .get(&key_id_bytes)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"));
        require!(key.owner == owner && !key.revoked, ERR_REPLAY);
        let mut holder = self.holder_or_panic(&owner);
        let epoch = holder
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        key.revoked = true;
        key.epoch = epoch;
        holder.authorization_epoch = epoch;
        self.authorization_keys.insert(&key_id_bytes, &key);
        self.holders.insert(&owner, &holder);
        self.emit(
            "AuthorizationKeyRevoked",
            json!({"account_id": owner, "key_id": key_id, "epoch": epoch}),
        );
    }

    pub fn get_authorization_key(&self, owner: AccountId, key_id: u64) -> Option<AuthorizationKey> {
        self.authorization_keys
            .get(&authorization_key(&owner, key_id))
    }

    pub fn create_vault(&mut self, args: CreateVaultArgs) -> u64 {
        let owner = env::predecessor_account_id();
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
                .unwrap_or_else(|| panic!("{ERR_INVALID_ENCODING}"));
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
            accounting_version: 0,
            risk_version: 0,
            reconciled_risk_version: 0,
        };
        self.vaults.insert(&id, &vault);
        self.vault_brokers.insert(&id, &Vec::new());
        self.emit(
            "VaultCreated",
            json!({"vault_id": id, "owner": owner, "asset_id": self.asset.token_account}),
        );
        id
    }

    pub fn create_broker(&mut self, args: CreateBrokerArgs) -> u64 {
        let caller = env::predecessor_account_id();
        let vault = self.vault_or_panic(args.vault_id);
        require!(vault.owner == caller, ERR_UNAUTHORIZED);
        require!(!args.encryption_public_key.is_empty(), ERR_INVALID_ENCODING);
        require!(!args.proof_of_possession.is_empty(), ERR_BAD_PROOF);
        validate_ciphertext(&args.encryption_public_key);
        let id = self.next_broker_id();
        let key = EncryptionKey {
            key_id: args.encryption_key_id,
            public_key: args.encryption_public_key,
            registered_at: now_seconds(),
            authorization_epoch: 0,
        };
        let context =
            to_vec(&(id, &key.public_key)).unwrap_or_else(|_| panic!("{ERR_INVALID_ENCODING}"));
        self.verify_proof(
            b"broker-key-possession",
            &context,
            &args.proof_of_possession,
        );
        let broker = Broker {
            broker_id: id,
            owner: caller,
            vault_id: args.vault_id,
            encryption_key: key,
            debt_total: 0,
            debt_maximum: args.debt_maximum.0,
            loan_sequence: 0,
            active_loan_count: 0,
            impaired_loan_count: 0,
            spending_ciphertext: zero_ciphertext(),
            inbox_ciphertext: zero_ciphertext(),
            issuer_balance_ciphertext: zero_ciphertext(),
            auditor_balance_ciphertext: zero_ciphertext(),
            spending_commitment: zero_root(),
            inbox_commitment: zero_root(),
            spending_version: 0,
            loan_book_root: zero_root(),
            book_version: 0,
            active_principal_ciphertext: zero_ciphertext(),
            impaired_principal_ciphertext: zero_ciphertext(),
            active_principal_commitment: zero_root(),
            impaired_principal_commitment: zero_root(),
            impairment_provision: 0,
            cumulative_draws: 0,
            cumulative_settlements: 0,
            cumulative_yield: 0,
            cumulative_realized_losses: 0,
            accounting_version: 0,
            risk_version: 0,
            reconciled_risk_version: 0,
            accounting_pending: false,
            delegates: Vec::new(),
            tombstoned: false,
        };
        self.brokers.insert(&id, &broker);
        let mut ids = self.vault_brokers.get(&args.vault_id).unwrap_or_default();
        ids.push(id);
        self.vault_brokers.insert(&args.vault_id, &ids);
        self.emit(
            "BrokerCreated",
            json!({"broker_id": id, "vault_id": args.vault_id}),
        );
        id
    }

    pub fn create_proposal(&mut self, args: CreateProposalArgs) -> u64 {
        let caller = env::predecessor_account_id();
        let broker = self.broker_or_panic(args.broker_id);
        require!(broker.vault_id == args.vault_id, ERR_WRONG_ASSET);
        require!(
            caller == broker.owner || caller == args.borrower,
            ERR_UNAUTHORIZED
        );
        require!(self.holder_registered(&args.borrower), ERR_NOT_REGISTERED);
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
        require!(!args.agreement_digest.is_empty(), ERR_INVALID_ENCODING);
        let id = self.next_proposal_id();
        let proposal = Proposal {
            proposal_id: id,
            borrower: args.borrower,
            broker_id: args.broker_id,
            vault_id: args.vault_id,
            borrower_key_id: args.borrower_key_id,
            broker_key_id: args.broker_key_id,
            loan_auditor_key_id: args.loan_auditor_key_id,
            payment_count: args.payment_count,
            payment_interval: args.payment_interval,
            grace_period: args.grace_period,
            expiry: args.expiry,
            principal_ciphertexts: args.principal_ciphertexts,
            initial_owed_ciphertexts: args.initial_owed_ciphertexts,
            periodic_payment_ciphertexts: args.periodic_payment_ciphertexts,
            agreement_digest: args.agreement_digest,
            broker_signature: args.broker_signature,
            borrower_signature: args.borrower_signature,
            broker_authorization_epoch: args.broker_authorization_epoch,
            borrower_authorization_epoch: args.borrower_authorization_epoch,
            consumed: false,
            revoked: false,
        };
        self.proposals.insert(&id, &proposal);
        self.emit("ProposalCreated", json!({"proposal_id": id, "broker_id": proposal.broker_id, "borrower": proposal.borrower}));
        id
    }

    pub fn sign_proposal(&mut self, proposal_id: u64, signature: Vec<u8>) {
        let caller = env::predecessor_account_id();
        require!(!signature.is_empty(), ERR_BAD_PROOF);
        let mut proposal = self.proposal_or_panic(proposal_id);
        let broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        if caller == proposal.borrower {
            proposal.borrower_signature = signature;
        } else {
            proposal.broker_signature = signature;
        }
        self.proposals.insert(&proposal_id, &proposal);
    }

    pub fn revoke_proposal(&mut self, proposal_id: u64) {
        let caller = env::predecessor_account_id();
        let mut proposal = self.proposal_or_panic(proposal_id);
        let broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        require!(!proposal.consumed, ERR_REPLAY);
        proposal.revoked = true;
        self.proposals.insert(&proposal_id, &proposal);
        self.proposal_tombstones.insert(&proposal_id);
    }

    pub fn deposit_to_vault(&mut self, args: DepositToVaultArgs) {
        let caller = env::predecessor_account_id();
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        let minted = if vault.shares_total == 0 {
            require!(vault.assets_total == 0 && nav == 0, ERR_INVALID_AMOUNT);
            let scale = 10u128
                .checked_pow(u32::from(vault.share_scale))
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
            args.amount
                .0
                .checked_mul(scale)
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"))
        } else {
            require!(nav > 0, ERR_INVALID_AMOUNT);
            mul_div_floor(args.amount.0, vault.shares_total, nav)
        };
        require!(minted > 0, ERR_SLIPPAGE);
        require!(minted >= args.min_shares_out.0, ERR_SLIPPAGE);
        let new_total = vault
            .assets_total
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        if vault.assets_maximum != 0 {
            require!(new_total <= vault.assets_maximum, ERR_DEBT_LIMIT);
        }
        vault.assets_total = new_total;
        vault.assets_available = vault
            .assets_available
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.shares_total = vault
            .shares_total
            .checked_add(minted)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        let key = share_key(args.vault_id, &caller);
        let existing = self.shares.get(&key).unwrap_or(0);
        self.shares.insert(
            &key,
            &existing
                .checked_add(minted)
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}")),
        );
        self.claims.remove(&args.claim_id);
        self.public_claim_total = self
            .public_claim_total
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.vaults.insert(&args.vault_id, &vault);
        self.emit(
            "SharesMinted",
            json!({
                "vault_id": args.vault_id,
                "owner": caller,
                "shares": minted.to_string(),
                "accounting_version": vault.accounting_version
            }),
        );
    }

    pub fn redeem_shares(&mut self, args: RedeemSharesArgs) -> u64 {
        let caller = env::predecessor_account_id();
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        let assets_out = if args.sole_shareholder_waiver && owned == vault.shares_total {
            mul_div_floor(args.shares.0, vault.assets_total, vault.shares_total)
        } else {
            require!(nav > 0, ERR_INVALID_AMOUNT);
            mul_div_floor(args.shares.0, nav, vault.shares_total)
        };
        require!(
            assets_out > 0 && assets_out <= vault.assets_available,
            ERR_INSUFFICIENT_PUBLIC_FUNDS
        );
        require!(assets_out >= args.min_assets_out.0, ERR_SLIPPAGE);
        if args.shares.0 == vault.shares_total {
            let broker_ids = self.vault_brokers.get(&args.vault_id).unwrap_or_default();
            for broker_id in broker_ids {
                let broker = self.broker_or_panic(broker_id);
                require!(broker.debt_total == 0, ERR_HAS_OBLIGATIONS);
                require!(broker.active_loan_count == 0, ERR_HAS_OBLIGATIONS);
                require!(
                    broker.spending_ciphertext == zero_ciphertext(),
                    ERR_HAS_OBLIGATIONS
                );
                require!(
                    broker.inbox_ciphertext == zero_ciphertext(),
                    ERR_HAS_OBLIGATIONS
                );
            }
            require!(
                vault.assets_total == vault.assets_available,
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.assets_available = vault
            .assets_available
            .checked_sub(assets_out)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.shares_total = vault
            .shares_total
            .checked_sub(args.shares.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.shares.insert(
            &key,
            &owned
                .checked_sub(args.shares.0)
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}")),
        );
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.vaults.insert(&args.vault_id, &vault);
        self.emit(
            "SharesRedeemed",
            json!({
                "vault_id": args.vault_id,
                "owner": caller,
                "shares": args.shares.0.to_string(),
                "assets_out": assets_out.to_string(),
                "claim_id": claim_id,
                "accounting_version": vault.accounting_version
            }),
        );
        claim_id
    }

    pub fn transfer_shares(&mut self, vault_id: u64, receiver: AccountId, shares: U128) {
        let sender = env::predecessor_account_id();
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
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}")),
        );
        self.shares.insert(
            &to_key,
            &to.checked_add(shares.0)
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}")),
        );
        self.emit("SharesTransferred", json!({"vault_id": vault_id, "sender": sender, "receiver": receiver, "shares": shares.0.to_string()}));
    }

    pub fn get_share_balance(&self, vault_id: u64, owner: AccountId) -> U128 {
        U128(self.shares.get(&share_key(vault_id, &owner)).unwrap_or(0))
    }

    pub fn shield(&mut self, args: ShieldArgs) {
        let owner = env::predecessor_account_id();
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
        validate_ciphertext_set(
            &vec![
                args.spending_ciphertext.clone(),
                args.issuer_ciphertext.clone(),
                args.auditor_ciphertext.clone(),
                args.commitment.clone(),
            ],
            4,
        );
        self.verify_bound_proof(
            b"shield",
            &args.proof,
            &(
                args.claim_id,
                args.amount.0,
                &holder,
                &args.spending_ciphertext,
                &args.issuer_ciphertext,
                &args.auditor_ciphertext,
                &args.commitment,
            ),
        );
        holder.inbox_ciphertext =
            combine_ciphertexts(&holder.inbox_ciphertext, &args.spending_ciphertext);
        holder.issuer_balance_ciphertext = args.issuer_ciphertext;
        holder.auditor_balance_ciphertext = args.auditor_ciphertext;
        self.holders.insert(&owner, &holder);
        self.claims.remove(&args.claim_id);
        self.public_claim_total = self
            .public_claim_total
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.emit("Shielded", json!({"account_id": owner, "claim_id": args.claim_id, "amount": args.amount.0.to_string(), "spending_version": holder.spending_version}));
    }

    pub fn unshield(&mut self, args: UnshieldArgs) -> u64 {
        let owner = env::predecessor_account_id();
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
        validate_ciphertext_set(
            &vec![
                args.spending_ciphertext.clone(),
                args.issuer_ciphertext.clone(),
                args.auditor_ciphertext.clone(),
                args.commitment.clone(),
            ],
            4,
        );
        self.verify_bound_proof(
            b"unshield",
            &args.proof,
            &(
                owner.clone(),
                args.amount.0,
                &holder,
                &args.spending_ciphertext,
                &args.issuer_ciphertext,
                &args.auditor_ciphertext,
                &args.commitment,
            ),
        );
        holder.spending_ciphertext = args.spending_ciphertext;
        holder.issuer_balance_ciphertext = args.issuer_ciphertext;
        holder.auditor_balance_ciphertext = args.auditor_ciphertext;
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INSUFFICIENT_PRIVATE_FUNDS}"));
        self.emit("Unshielded", json!({"account_id": owner, "amount": args.amount.0.to_string(), "claim_id": claim_id, "spending_version": holder.spending_version}));
        claim_id
    }

    pub fn merge_inbox(&mut self, args: MergeArgs) {
        let owner = env::predecessor_account_id();
        let mut holder = self.holder_or_panic(&owner);
        require!(!holder.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            holder.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        validate_ciphertext(&args.new_spending_ciphertext);
        if let Some(proof) = &args.proof {
            self.verify_bound_proof(
                b"merge-holder",
                proof,
                &(owner.clone(), &holder, &args.new_spending_ciphertext),
            );
        } else {
            require!(holder.inbox_ciphertext == zero_ciphertext(), ERR_BAD_PROOF);
        }
        holder.spending_ciphertext = args.new_spending_ciphertext;
        holder.inbox_ciphertext = zero_ciphertext();
        holder.spending_version = holder
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.holders.insert(&owner, &holder);
        self.emit(
            "InboxMerged",
            json!({"account_id": owner, "spending_version": holder.spending_version}),
        );
    }

    pub fn draw(&mut self, args: DrawArgs) {
        let caller = env::predecessor_account_id();
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
                broker
                    .debt_total
                    .checked_add(args.amount.0)
                    .unwrap_or(u128::MAX)
                    <= broker.debt_maximum,
                ERR_DEBT_LIMIT
            );
        }
        validate_ciphertext_set(
            &vec![
                args.broker_ciphertext.clone(),
                args.issuer_ciphertext.clone(),
                args.auditor_ciphertext.clone(),
            ],
            3,
        );
        self.verify_bound_proof(
            b"draw",
            &args.proof,
            &(
                broker.clone(),
                vault.clone(),
                args.amount.0,
                &args.broker_ciphertext,
                &args.issuer_ciphertext,
                &args.auditor_ciphertext,
            ),
        );
        vault.assets_available = vault
            .assets_available
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.inbox_ciphertext =
            combine_ciphertexts(&broker.inbox_ciphertext, &args.broker_ciphertext);
        broker.issuer_balance_ciphertext = args.issuer_ciphertext;
        broker.auditor_balance_ciphertext = args.auditor_ciphertext;
        if !args.broker_spending_commitment.is_empty() {
            validate_ciphertext(&args.broker_spending_commitment);
            broker.spending_commitment = args.broker_spending_commitment;
        }
        if !args.broker_inbox_commitment.is_empty() {
            validate_ciphertext(&args.broker_inbox_commitment);
            broker.inbox_commitment = args.broker_inbox_commitment;
        }
        broker.debt_total = broker
            .debt_total
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_DEBT_LIMIT}"));
        broker.cumulative_draws = broker
            .cumulative_draws
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&broker.vault_id, &vault);
        self.emit("BrokerDrawn", json!({"broker_id": args.broker_id, "vault_id": broker.vault_id, "amount": args.amount.0.to_string(), "accounting_version": broker.accounting_version}));
    }

    pub fn merge_broker_inbox(&mut self, broker_id: u64, args: MergeArgs) {
        let caller = env::predecessor_account_id();
        let mut broker = self.broker_or_panic(broker_id);
        let keeper = self.authorized_keeper(&broker, &caller);
        require!(caller == broker.owner || keeper, ERR_UNAUTHORIZED);
        require!(
            broker.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        validate_ciphertext(&args.new_spending_ciphertext);
        if let Some(proof) = args.proof.as_ref() {
            self.verify_bound_proof(
                b"merge-broker",
                proof,
                &(broker.clone(), &args.new_spending_ciphertext),
            );
        } else {
            require!(broker.inbox_ciphertext == zero_ciphertext(), ERR_BAD_PROOF);
        }
        broker.spending_ciphertext = args.new_spending_ciphertext;
        broker.inbox_ciphertext = zero_ciphertext();
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.brokers.insert(&broker_id, &broker);
        self.emit(
            "InboxMerged",
            json!({"broker_id": broker_id, "spending_version": broker.spending_version}),
        );
    }

    pub fn originate(&mut self, args: OriginateArgs) -> u64 {
        let caller = env::predecessor_account_id();
        let proposal = self.proposal_or_panic(args.proposal_id);
        let mut broker = self.broker_or_panic(proposal.broker_id);
        require!(
            caller == broker.owner || caller == proposal.borrower,
            ERR_UNAUTHORIZED
        );
        require!(!proposal.consumed && !proposal.revoked, ERR_REPLAY);
        require!(now_seconds() <= proposal.expiry, ERR_EXPIRED);
        require!(
            !proposal.broker_signature.is_empty() && !proposal.borrower_signature.is_empty(),
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
            broker.spending_ciphertext != zero_ciphertext(),
            ERR_INSUFFICIENT_PRIVATE_FUNDS
        );
        require!(!args.broker_spending_ciphertext.is_empty(), ERR_BAD_PROOF);
        validate_ciphertext_set(&args.loan_principal_ciphertexts, 5);
        validate_ciphertext_set(&args.loan_initial_owed_ciphertexts, 3);
        validate_ciphertext_set(&args.loan_periodic_payment_ciphertexts, 3);
        validate_ciphertext(&args.broker_active_principal_ciphertext);
        validate_ciphertext(&args.broker_impaired_principal_ciphertext);
        validate_ciphertext(&args.broker_book_root);
        validate_ciphertext(&args.accounting_leaf);
        let dynamic = (
            proposal.clone(),
            broker.clone(),
            borrower.clone(),
            &args.broker_spending_ciphertext,
            &args.borrower_spending_ciphertext,
            &args.loan_principal_ciphertexts,
            &args.loan_initial_owed_ciphertexts,
            &args.loan_periodic_payment_ciphertexts,
            &args.broker_active_principal_ciphertext,
            &args.broker_impaired_principal_ciphertext,
            &args.broker_book_root,
            &args.accounting_leaf,
        );
        self.verify_bound_proof(b"originate", &args.proof, &dynamic);
        let start = now_seconds();
        let next_due = start
            .checked_add(proposal.payment_interval)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        let loan_id = self.next_loan_id();
        let principal_ciphertexts = args.loan_principal_ciphertexts.clone();
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
            principal_ciphertexts,
            initial_owed_ciphertexts: args.loan_initial_owed_ciphertexts.clone(),
            amount_owed_ciphertexts: args.loan_initial_owed_ciphertexts,
            periodic_payment_ciphertexts: args.loan_periodic_payment_ciphertexts,
            principal_remaining_ciphertexts: args.loan_principal_ciphertexts,
            cumulative_repaid_ciphertexts: zero_ciphertext_set(3),
            accounting_leaf: args.accounting_leaf,
            tombstoned: false,
        };
        broker.spending_ciphertext = args.broker_spending_ciphertext;
        broker.active_principal_ciphertext = args.broker_active_principal_ciphertext;
        broker.impaired_principal_ciphertext = args.broker_impaired_principal_ciphertext;
        broker.loan_book_root = args.broker_book_root;
        if !args.broker_spending_commitment.is_empty() {
            validate_ciphertext(&args.broker_spending_commitment);
            broker.spending_commitment = args.broker_spending_commitment;
        }
        if !args.broker_active_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_active_principal_commitment);
            broker.active_principal_commitment = args.broker_active_principal_commitment;
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_impaired_principal_commitment);
            broker.impaired_principal_commitment = args.broker_impaired_principal_commitment;
        }
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.active_loan_count = broker
            .active_loan_count
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.loan_sequence = broker
            .loan_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        borrower.inbox_ciphertext = combine_ciphertexts(
            &borrower.inbox_ciphertext,
            &args.borrower_spending_ciphertext,
        );
        borrower.issuer_balance_ciphertext = args.borrower_issuer_ciphertext;
        borrower.auditor_balance_ciphertext = args.borrower_auditor_ciphertext;
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
                "loan_id": loan_id,
                "proposal_id": loan.proposal_id,
                "broker_id": loan.broker_id,
                "borrower": loan.borrower,
                "start_time": loan.start_time,
                "next_due": loan.next_due,
                "payment_remaining": loan.payment_remaining,
                "loan_version": loan.loan_version,
                "accounting_leaf": loan.accounting_leaf,
            }),
        );
        loan_id
    }

    pub fn confidential_send(&mut self, args: TransferArgs) {
        let sender = env::predecessor_account_id();
        require!(sender != args.destination, ERR_INVALID_AMOUNT);
        let mut from = self.holder_or_panic(&sender);
        let mut to = self.holder_or_panic(&args.destination);
        require!(!from.frozen && !to.frozen, ERR_ACCOUNT_FROZEN);
        require!(
            from.spending_version == args.expected_spending_version,
            ERR_STALE_STATE
        );
        require!(args.transfer_views.len() == 5, ERR_INVALID_ENCODING);
        validate_ciphertext_set(&args.transfer_views, 5);
        validate_ciphertext_set(
            &vec![
                args.sender_spending_ciphertext.clone(),
                args.sender_issuer_ciphertext.clone(),
                args.sender_auditor_ciphertext.clone(),
                args.destination_inbox_ciphertext.clone(),
                args.destination_issuer_ciphertext.clone(),
                args.destination_auditor_ciphertext.clone(),
                args.commitment.clone(),
            ],
            7,
        );
        self.verify_bound_proof(
            b"confidential-send",
            &args.proof,
            &(
                sender.clone(),
                args.destination.clone(),
                from.clone(),
                to.clone(),
                &args.transfer_views,
                &args.commitment,
                &args.sender_spending_ciphertext,
                &args.destination_inbox_ciphertext,
            ),
        );
        from.spending_ciphertext = args.sender_spending_ciphertext;
        from.issuer_balance_ciphertext = args.sender_issuer_ciphertext;
        from.auditor_balance_ciphertext = args.sender_auditor_ciphertext;
        from.spending_version = from
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        to.inbox_ciphertext =
            combine_ciphertexts(&to.inbox_ciphertext, &args.destination_inbox_ciphertext);
        to.issuer_balance_ciphertext = args.destination_issuer_ciphertext;
        to.auditor_balance_ciphertext = args.destination_auditor_ciphertext;
        self.holders.insert(&sender, &from);
        self.holders.insert(&args.destination, &to);
        self.emit(
            "ConfidentialTransfer",
            json!({
                "sender": sender,
                "destination": args.destination,
                "sender_spending_version": from.spending_version,
                "transfer_views": args.transfer_views,
                "commitment": args.commitment
            }),
        );
    }

    pub fn repay(&mut self, args: RepayArgs) {
        let caller = env::predecessor_account_id();
        let mut loan = self.loan_or_panic(args.loan_id);
        require!(caller == loan.borrower, ERR_UNAUTHORIZED);
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
        require!(args.transfer_views.len() == 5, ERR_INVALID_ENCODING);
        validate_ciphertext_set(&args.transfer_views, 5);
        validate_ciphertext_set(&args.amount_owed_ciphertexts, 3);
        validate_ciphertext_set(&args.principal_remaining_ciphertexts, 3);
        validate_ciphertext_set(&args.cumulative_repaid_ciphertexts, 3);
        validate_ciphertext(&args.broker_active_principal_ciphertext);
        validate_ciphertext(&args.broker_impaired_principal_ciphertext);
        validate_ciphertext(&args.broker_book_root);
        validate_ciphertext(&args.accounting_leaf);
        let dynamic = (
            loan.clone(),
            broker.clone(),
            borrower.clone(),
            &args.mode,
            &args.transfer_views,
            &args.amount_owed_ciphertexts,
            &args.principal_remaining_ciphertexts,
            &args.cumulative_repaid_ciphertexts,
            &args.broker_active_principal_ciphertext,
            &args.broker_impaired_principal_ciphertext,
            &args.broker_book_root,
            &args.accounting_leaf,
            &args.commitment,
        );
        self.verify_bound_proof(b"repay", &args.proof, &dynamic);
        if matches!(args.mode, RepayMode::Regular) {
            require!(loan.payment_remaining > 1, ERR_INVALID_AMOUNT);
        }
        borrower.spending_ciphertext = args.borrower_spending_ciphertext;
        borrower.issuer_balance_ciphertext = args.borrower_issuer_ciphertext;
        borrower.auditor_balance_ciphertext = args.borrower_auditor_ciphertext;
        borrower.spending_version = borrower
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.inbox_ciphertext =
            combine_ciphertexts(&broker.inbox_ciphertext, &args.broker_inbox_ciphertext);
        broker.issuer_balance_ciphertext = args.broker_issuer_ciphertext;
        broker.auditor_balance_ciphertext = args.broker_auditor_ciphertext;
        broker.active_principal_ciphertext = args.broker_active_principal_ciphertext;
        broker.impaired_principal_ciphertext = args.broker_impaired_principal_ciphertext;
        broker.loan_book_root = args.broker_book_root;
        if !args.broker_inbox_commitment.is_empty() {
            validate_ciphertext(&args.broker_inbox_commitment);
            broker.inbox_commitment = args.broker_inbox_commitment;
        }
        if !args.broker_active_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_active_principal_commitment);
            broker.active_principal_commitment = args.broker_active_principal_commitment;
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_impaired_principal_commitment);
            broker.impaired_principal_commitment = args.broker_impaired_principal_commitment;
        }
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        loan.amount_owed_ciphertexts = args.amount_owed_ciphertexts;
        loan.principal_remaining_ciphertexts = args.principal_remaining_ciphertexts;
        loan.cumulative_repaid_ciphertexts = args.cumulative_repaid_ciphertexts;
        loan.accounting_leaf = args.accounting_leaf;
        loan.loan_version = loan
            .loan_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        if matches!(args.mode, RepayMode::Full) {
            loan.status = LoanStatus::Paid;
            loan.payment_remaining = 0;
            loan.next_due = 0;
            loan.impaired = false;
            broker.active_loan_count = broker
                .active_loan_count
                .checked_sub(1)
                .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        } else {
            loan.payment_remaining = loan
                .payment_remaining
                .checked_sub(1)
                .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            loan.previous_due = loan.next_due;
            loan.next_due = loan
                .next_due
                .checked_add(loan.payment_interval)
                .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        }
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        if loan.impaired || broker.impairment_provision > 0 {
            broker.accounting_pending = true;
            broker.risk_version = broker
                .risk_version
                .checked_add(1)
                .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            let mut vault = self.vault_or_panic(broker.vault_id);
            vault.accounting_pending = true;
            vault.risk_version = vault
                .risk_version
                .checked_add(1)
                .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            self.vaults.insert(&broker.vault_id, &vault);
        }
        self.holders.insert(&borrower.owner, &borrower);
        self.brokers.insert(&broker_id, &broker);
        self.loans.insert(&loan.loan_id, &loan);
        self.emit(
            "LoanRepaid",
            json!({
                "loan_id": loan.loan_id,
                "broker_id": loan.broker_id,
                "status": loan.status,
                "payment_remaining": loan.payment_remaining,
                "loan_version": loan.loan_version,
                "transfer_views": args.transfer_views,
                "amount_owed_ciphertexts": loan.amount_owed_ciphertexts,
            }),
        );
    }

    pub fn manage_loan(&mut self, args: ManageLoanArgs) {
        let caller = env::predecessor_account_id();
        let mut loan = self.loan_or_panic(args.loan_id);
        let mut broker = self.broker_or_panic(loan.broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(
            loan.loan_version == args.expected_loan_version,
            ERR_STALE_STATE
        );
        require!(matches!(loan.status, LoanStatus::Active), ERR_LOAN_CLOSED);
        validate_ciphertext(&args.accounting_leaf);
        match args.action {
            LoanManagementAction::Impair => {
                require!(now_seconds() > loan.next_due, ERR_TOO_SOON);
                require!(!loan.impaired, ERR_INVALID_AMOUNT);
                loan.impaired = true;
                broker.impaired_loan_count = broker
                    .impaired_loan_count
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            }
            LoanManagementAction::Unimpair => {
                require!(loan.impaired, ERR_INVALID_AMOUNT);
                loan.impaired = false;
                broker.impaired_loan_count = broker
                    .impaired_loan_count
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            }
            LoanManagementAction::Default => {
                let deadline = loan
                    .next_due
                    .checked_add(loan.grace_period)
                    .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
                require!(now_seconds() > deadline, ERR_TOO_SOON);
                if loan.impaired {
                    broker.impaired_loan_count = broker
                        .impaired_loan_count
                        .checked_sub(1)
                        .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
                }
                loan.impaired = false;
                loan.status = LoanStatus::Defaulted;
                loan.payment_remaining = 0;
                loan.next_due = 0;
                broker.active_loan_count = broker
                    .active_loan_count
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
            }
        }
        validate_ciphertext(&args.broker_active_principal_ciphertext);
        validate_ciphertext(&args.broker_impaired_principal_ciphertext);
        validate_ciphertext(&args.broker_book_root);
        self.verify_bound_proof(
            b"manage-loan",
            &args.proof,
            &(
                loan.clone(),
                broker.clone(),
                &args.action,
                &args.accounting_leaf,
                &args.broker_active_principal_ciphertext,
                &args.broker_impaired_principal_ciphertext,
                &args.broker_book_root,
            ),
        );
        loan.accounting_leaf = args.accounting_leaf;
        loan.loan_version = loan
            .loan_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.active_principal_ciphertext = args.broker_active_principal_ciphertext;
        broker.impaired_principal_ciphertext = args.broker_impaired_principal_ciphertext;
        broker.loan_book_root = args.broker_book_root;
        if !args.broker_active_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_active_principal_commitment);
            broker.active_principal_commitment = args.broker_active_principal_commitment;
        }
        if !args.broker_impaired_principal_commitment.is_empty() {
            validate_ciphertext(&args.broker_impaired_principal_commitment);
            broker.impaired_principal_commitment = args.broker_impaired_principal_commitment;
        }
        broker.book_version = broker
            .book_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.accounting_pending = true;
        broker.risk_version = broker
            .risk_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        let mut vault = self.vault_or_panic(broker.vault_id);
        vault.accounting_pending = true;
        vault.risk_version = vault
            .risk_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.loans.insert(&loan.loan_id, &loan);
        self.brokers.insert(&broker.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        self.emit(
            "LoanManagement",
            json!({
                "loan_id": loan.loan_id,
                "broker_id": loan.broker_id,
                "action": args.action,
                "status": loan.status,
                "impaired": loan.impaired,
                "loan_version": loan.loan_version,
                "risk_version": broker.risk_version,
                "accounting_leaf": loan.accounting_leaf
            }),
        );
    }

    pub fn prepare_reconciliation(&mut self, broker_id: u64) -> u64 {
        let broker = self.broker_or_panic(broker_id);
        let vault = self.vault_or_panic(broker.vault_id);
        require!(
            broker.accounting_pending || broker.impairment_provision > 0,
            ERR_ACCOUNTING_PENDING
        );
        require!(
            broker.risk_version > broker.reconciled_risk_version,
            ERR_ACCOUNTING_PENDING
        );
        let now = now_seconds();
        let epoch = vault.checkpoint_policy.epoch_seconds;
        let scheduled_at = ((now / epoch)
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}")))
        .checked_mul(epoch)
        .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
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
        id
    }

    pub fn reconcile_credit(&mut self, args: ReconcileArgs) {
        let mut checkpoint = self
            .checkpoints
            .get(&args.checkpoint_id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"));
        require!(!checkpoint.consumed, ERR_REPLAY);
        require!(checkpoint.broker_id == args.broker_id, ERR_WRONG_ASSET);
        let mut broker = self.broker_or_panic(args.broker_id);
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
        require!(now_seconds() >= checkpoint.scheduled_at, ERR_TOO_SOON);
        let mut vault = self.vault_or_panic(broker.vault_id);
        require!(args.loss.0 <= broker.debt_total, ERR_INVALID_AMOUNT);
        require!(
            args.new_broker_debt.0 + args.loss.0 == broker.debt_total,
            ERR_BAD_PROOF
        );
        require!(
            args.new_vault_total.0 + args.loss.0 == vault.assets_total,
            ERR_BAD_PROOF
        );
        require!(
            args.new_broker_provision.0 <= args.new_broker_debt.0,
            ERR_BAD_PROOF
        );
        require!(
            args.new_broker_provision.0
                <= args
                    .loss
                    .0
                    .checked_add(broker.impairment_provision)
                    .unwrap_or(u128::MAX),
            ERR_BAD_PROOF
        );
        self.verify_bound_proof(
            b"reconcile-credit",
            &args.proof,
            &(
                broker.clone(),
                vault.clone(),
                checkpoint.clone(),
                args.new_broker_debt.0,
                args.new_broker_provision.0,
                args.loss.0,
                args.new_vault_total.0,
            ),
        );
        vault.assets_total = args.new_vault_total.0;
        vault.loss_unrealized = vault
            .loss_unrealized
            .checked_sub(broker.impairment_provision)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"))
            .checked_add(args.new_broker_provision.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.debt_total = args.new_broker_debt.0;
        broker.impairment_provision = args.new_broker_provision.0;
        broker.cumulative_realized_losses = broker
            .cumulative_realized_losses
            .checked_add(args.loss.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.accounting_pending = false;
        broker.reconciled_risk_version = broker.risk_version;
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        checkpoint.consumed = true;
        self.checkpoints.insert(&args.checkpoint_id, &checkpoint);
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        self.emit(
            "CreditReconciled",
            json!({
                "checkpoint_id": args.checkpoint_id,
                "broker_id": args.broker_id,
                "loss": args.loss.0.to_string(),
                "new_broker_debt": args.new_broker_debt.0.to_string(),
                "new_broker_provision": args.new_broker_provision.0.to_string(),
                "new_vault_total": args.new_vault_total.0.to_string(),
                "risk_version": broker.risk_version,
                "accounting_version": broker.accounting_version
            }),
        );
    }

    pub fn settle(&mut self, args: SettleArgs) {
        let caller = env::predecessor_account_id();
        let mut broker = self.broker_or_panic(args.broker_id);
        let is_owner = caller == broker.owner;
        let keeper_index = if is_owner {
            None
        } else {
            self.keeper_index(&broker, &caller)
        };
        require!(is_owner || keeper_index.is_some(), ERR_UNAUTHORIZED);
        require!(
            args.amount.0 > 0 && args.amount.0 <= MAX_ASSET_UNITS,
            ERR_INVALID_AMOUNT
        );
        if let Some(index) = keeper_index {
            let now = now_seconds();
            let grant = broker
                .delegates
                .get_mut(index)
                .unwrap_or_else(|| panic!("{ERR_UNAUTHORIZED}"));
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
                grant
                    .window_spent
                    .checked_add(args.amount.0)
                    .unwrap_or(u128::MAX)
                    <= grant.allowed_settlement_per_window,
                ERR_DEBT_LIMIT
            );
            grant.window_spent = grant
                .window_spent
                .checked_add(args.amount.0)
                .unwrap_or_else(|| panic!("{ERR_DEBT_LIMIT}"));
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
            broker.spending_ciphertext != zero_ciphertext(),
            ERR_INSUFFICIENT_PRIVATE_FUNDS
        );
        let mut vault = self.vault_or_panic(broker.vault_id);
        validate_ciphertext_set(
            &vec![
                args.broker_spending_ciphertext.clone(),
                args.broker_issuer_ciphertext.clone(),
                args.broker_auditor_ciphertext.clone(),
            ],
            3,
        );
        self.verify_bound_proof(
            b"settle",
            &args.proof,
            &(
                broker.clone(),
                vault.clone(),
                args.amount.0,
                &args.broker_spending_ciphertext,
                &args.broker_issuer_ciphertext,
                &args.broker_auditor_ciphertext,
            ),
        );
        let principal_return = args.amount.0.min(broker.debt_total);
        let realized_yield = args
            .amount
            .0
            .checked_sub(principal_return)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        require!(
            vault
                .assets_available
                .checked_add(args.amount.0)
                .unwrap_or(u128::MAX)
                <= self.asset.custody_cap,
            ERR_INVALID_AMOUNT
        );
        broker.spending_ciphertext = args.broker_spending_ciphertext;
        broker.issuer_balance_ciphertext = args.broker_issuer_ciphertext;
        broker.auditor_balance_ciphertext = args.broker_auditor_ciphertext;
        if !args.broker_spending_commitment.is_empty() {
            validate_ciphertext(&args.broker_spending_commitment);
            broker.spending_commitment = args.broker_spending_commitment;
        }
        if !args.broker_inbox_commitment.is_empty() {
            validate_ciphertext(&args.broker_inbox_commitment);
            broker.inbox_commitment = args.broker_inbox_commitment;
        }
        broker.spending_version = broker
            .spending_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.debt_total = broker
            .debt_total
            .checked_sub(principal_return)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.cumulative_settlements = broker
            .cumulative_settlements
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.cumulative_yield = broker
            .cumulative_yield
            .checked_add(realized_yield)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        vault.assets_available = vault
            .assets_available
            .checked_add(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.assets_total = vault
            .assets_total
            .checked_add(realized_yield)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        vault.accounting_version = vault
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.confidential_outstanding = self
            .confidential_outstanding
            .checked_sub(args.amount.0)
            .unwrap_or_else(|| panic!("{ERR_INSUFFICIENT_PRIVATE_FUNDS}"));
        if broker.impairment_provision > 0 {
            require!(args.reconciliation.is_some(), ERR_ACCOUNTING_PENDING);
            broker.accounting_pending = true;
        }
        self.brokers.insert(&args.broker_id, &broker);
        self.vaults.insert(&vault.vault_id, &vault);
        self.emit(
            "BrokerSettled",
            json!({
                "broker_id": args.broker_id,
                "vault_id": vault.vault_id,
                "amount": args.amount.0.to_string(),
                "principal_return": principal_return.to_string(),
                "realized_yield": realized_yield.to_string(),
                "spending_version": broker.spending_version,
                "accounting_version": broker.accounting_version
            }),
        );
        if let Some(reconcile) = args.reconciliation {
            self.reconcile_credit(reconcile);
        }
    }

    pub fn grant_keeper(&mut self, args: GrantKeeperArgs) {
        let caller = env::predecessor_account_id();
        let mut broker = self.broker_or_panic(args.broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(
            args.allowed_settlement_per_operation.0 > 0,
            ERR_INVALID_AMOUNT
        );
        require!(
            args.allowed_settlement_per_window.0 >= args.allowed_settlement_per_operation.0,
            ERR_INVALID_AMOUNT
        );
        require!(
            args.window_seconds > 0 && args.expires_at > now_seconds(),
            ERR_INVALID_AMOUNT
        );
        require!(broker.delegates.len() < MAX_DELEGATES, ERR_INVALID_AMOUNT);
        let epoch = broker
            .encryption_key
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.encryption_key.authorization_epoch = epoch;
        let delegate_account = args.delegate_account.clone();
        broker.delegates.push(KeeperGrant {
            delegate_account,
            delegate_key_id: args.delegate_key_id,
            allowed_settlement_per_operation: args.allowed_settlement_per_operation.0,
            allowed_settlement_per_window: args.allowed_settlement_per_window.0,
            window_seconds: args.window_seconds,
            window_started_at: now_seconds(),
            window_spent: 0,
            expires_at: args.expires_at,
            revocation_epoch: epoch,
            delegate_epoch: args.delegate_epoch,
            active: true,
        });
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.brokers.insert(&args.broker_id, &broker);
        self.emit(
            "KeeperGranted",
            json!({"broker_id": args.broker_id, "delegate": args.delegate_account, "epoch": epoch}),
        );
    }

    pub fn revoke_keeper(&mut self, broker_id: u64, delegate_account: AccountId) {
        let caller = env::predecessor_account_id();
        let mut broker = self.broker_or_panic(broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        let epoch = broker
            .encryption_key
            .authorization_epoch
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        broker.encryption_key.authorization_epoch = epoch;
        for grant in &mut broker.delegates {
            if grant.delegate_account == delegate_account {
                grant.active = false;
                grant.revocation_epoch = epoch;
            }
        }
        broker.accounting_version = broker
            .accounting_version
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.brokers.insert(&broker_id, &broker);
        self.emit(
            "KeeperRevoked",
            json!({"broker_id": broker_id, "delegate": delegate_account, "epoch": epoch}),
        );
    }

    pub fn delete_loan(&mut self, loan_id: u64, evidence: Vec<u8>) {
        let caller = env::predecessor_account_id();
        let loan = self.loan_or_panic(loan_id);
        let broker = self.broker_or_panic(loan.broker_id);
        require!(
            caller == loan.borrower || caller == broker.owner,
            ERR_UNAUTHORIZED
        );
        require!(
            !matches!(loan.status, LoanStatus::Active),
            ERR_HAS_OBLIGATIONS
        );
        require!(!evidence.is_empty(), ERR_BAD_PROOF);
        require!(!loan.tombstoned, ERR_REPLAY);
        let tombstone = BookTombstone {
            id: loan_id,
            final_status: loan.status.clone(),
            final_version: loan.loan_version,
            leaf: loan.accounting_leaf.clone(),
            removal_evidence: evidence,
        };
        self.loan_tombstones.insert(&loan_id, &tombstone);
        self.loans.remove(&loan_id);
        self.emit("LoanDeleted", json!({"loan_id": loan_id, "broker_id": loan.broker_id, "final_version": loan.loan_version}));
    }

    pub fn delete_broker(&mut self, broker_id: u64) {
        let caller = env::predecessor_account_id();
        let broker = self.broker_or_panic(broker_id);
        require!(caller == broker.owner, ERR_UNAUTHORIZED);
        require!(broker.debt_total == 0, ERR_HAS_OBLIGATIONS);
        require!(broker.impairment_provision == 0, ERR_HAS_OBLIGATIONS);
        require!(
            broker.active_loan_count == 0 && broker.impaired_loan_count == 0,
            ERR_HAS_OBLIGATIONS
        );
        require!(
            broker.spending_ciphertext == zero_ciphertext()
                && broker.inbox_ciphertext == zero_ciphertext(),
            ERR_HAS_OBLIGATIONS
        );
        require!(!broker.accounting_pending, ERR_ACCOUNTING_PENDING);
        self.brokers.remove(&broker_id);
        self.broker_tombstones.insert(&broker_id);
        self.emit(
            "BrokerDeleted",
            json!({"broker_id": broker_id, "vault_id": broker.vault_id}),
        );
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let token = env::predecessor_account_id();
        if token != self.asset.token_account || amount.0 == 0 || amount.0 > self.asset.custody_cap {
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
        let payload_hash = hash_bytes(&(token.clone(), sender_id.clone(), amount.0, msg.clone()));
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
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.emit("DepositReceived", json!({"sender": sender_id, "deposit_id": message.deposit_id, "claim_id": claim_id, "amount": amount.0.to_string()}));
        PromiseOrValue::Value(U128(0))
    }

    pub fn request_payout(&mut self, args: RequestPayoutArgs) -> Promise {
        let caller = env::predecessor_account_id();
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
            result_hash: None,
            result_success: None,
            created_at: now_seconds(),
        };
        self.claims.insert(&args.claim_id, &claim);
        self.payouts.insert(&args.operation_id, &operation);
        self.payout_reserved_total = self
            .payout_reserved_total
            .checked_add(claim.amount)
            .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
        self.emit("PayoutRequested", json!({"operation_id": args.operation_id, "claim_id": args.claim_id, "owner": caller, "recipient": args.recipient, "amount": claim.amount.to_string()}));
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
                    .on_payout_result(args.operation_id, 1, call_hash),
            )
    }

    #[private]
    pub fn on_payout_result(
        &mut self,
        operation_id: u64,
        attempt: u32,
        result_hash: Vec<u8>,
    ) -> bool {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            ERR_UNAUTHORIZED
        );
        require!(env::promise_results_count() == 1, ERR_BAD_PROOF);
        let mut operation = self.payout_or_panic(operation_id);
        require!(operation.attempt == attempt, ERR_STALE_STATE);
        require!(operation.call_hash == result_hash, ERR_STALE_STATE);
        require!(
            matches!(operation.status, PayoutStatus::InFlight),
            ERR_REPLAY
        );
        let (success, result_hash) = match env::promise_result_checked(0, 4096) {
            Ok(bytes) => (true, hash_bytes(&bytes)),
            Err(_) => (false, hash_bytes(&b"failed".to_vec())),
        };
        operation.result_success = Some(success);
        operation.result_hash = Some(result_hash);
        operation.status = if success {
            PayoutStatus::ResultRecordedSuccess
        } else {
            PayoutStatus::ResultRecordedFailure
        };
        self.payouts.insert(&operation_id, &operation);
        self.emit(
            "PayoutResultRecorded",
            json!({"operation_id": operation_id, "attempt": attempt, "success": success}),
        );
        success
    }

    pub fn finalize_payout(&mut self, operation_id: u64) {
        let mut operation = self.payout_or_panic(operation_id);
        let mut claim = self.claim_or_panic(operation.claim_id);
        require!(claim.reserved_by == Some(operation_id), ERR_STALE_STATE);
        match operation.status {
            PayoutStatus::ResultRecordedSuccess => {
                self.claims.remove(&operation.claim_id);
                self.public_claim_total = self
                    .public_claim_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
                self.payout_reserved_total = self
                    .payout_reserved_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
                operation.status = PayoutStatus::Succeeded;
            }
            PayoutStatus::ResultRecordedFailure => {
                claim.reserved_by = None;
                self.claims.insert(&operation.claim_id, &claim);
                self.payout_reserved_total = self
                    .payout_reserved_total
                    .checked_sub(operation.amount)
                    .unwrap_or_else(|| panic!("{ERR_INVALID_AMOUNT}"));
                operation.status = PayoutStatus::Failed;
            }
            PayoutStatus::InFlight => panic!("{ERR_OPERATION_PENDING}"),
            PayoutStatus::Succeeded | PayoutStatus::Failed => return,
        }
        self.payouts.insert(&operation_id, &operation);
        self.payout_tombstones.insert(&operation_id);
        self.emit(
            "PayoutFinalized",
            json!({"operation_id": operation_id, "status": operation.status}),
        );
    }
}

#[near_bindgen]
impl Core {
    pub fn get_vault(&self, vault_id: u64) -> Option<VaultView> {
        self.vaults
            .get(&vault_id)
            .map(|vault| self.vault_view(vault))
    }

    pub fn get_broker(&self, broker_id: u64) -> Option<BrokerView> {
        self.brokers.get(&broker_id).map(|broker| BrokerView {
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
        })
    }

    pub fn get_holder(&self, owner: AccountId) -> Option<HolderView> {
        self.holders.get(&owner).map(|holder| HolderView {
            owner: holder.owner,
            asset_id: holder.asset_id,
            key_id: holder.encryption_key.key_id,
            spending_ciphertext: holder.spending_ciphertext,
            inbox_ciphertext: holder.inbox_ciphertext,
            issuer_balance_ciphertext: holder.issuer_balance_ciphertext,
            auditor_balance_ciphertext: holder.auditor_balance_ciphertext,
            spending_version: holder.spending_version,
            authorization_epoch: holder.authorization_epoch,
        })
    }

    pub fn get_loan(&self, loan_id: u64) -> Option<LoanView> {
        self.loans.get(&loan_id).map(|loan| LoanView {
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
            principal_ciphertexts: loan.principal_ciphertexts,
            initial_owed_ciphertexts: loan.initial_owed_ciphertexts,
            amount_owed_ciphertexts: loan.amount_owed_ciphertexts,
            periodic_payment_ciphertexts: loan.periodic_payment_ciphertexts,
            principal_remaining_ciphertexts: loan.principal_remaining_ciphertexts,
            cumulative_repaid_ciphertexts: loan.cumulative_repaid_ciphertexts,
            accounting_leaf: loan.accounting_leaf,
        })
    }

    pub fn get_proposal(&self, proposal_id: u64) -> Option<Proposal> {
        self.proposals.get(&proposal_id)
    }

    pub fn get_claim(&self, claim_id: u64) -> Option<ClaimView> {
        self.claims.get(&claim_id).map(|claim| ClaimView {
            claim_id: claim.claim_id,
            owner: claim.owner,
            amount: U128(claim.amount),
            created_at: claim.created_at,
            reserved_by: claim.reserved_by,
        })
    }

    pub fn get_payout(&self, operation_id: u64) -> Option<PayoutView> {
        self.payouts.get(&operation_id).map(|operation| PayoutView {
            operation_id: operation.operation_id,
            owner: operation.owner,
            recipient: operation.recipient,
            amount: U128(operation.amount),
            claim_id: operation.claim_id,
            attempt: operation.attempt,
            call_hash: operation.call_hash,
            status: operation.status,
            result_hash: operation.result_hash,
            result_success: operation.result_success,
            created_at: operation.created_at,
        })
    }

    pub fn get_checkpoint(&self, checkpoint_id: u64) -> Option<Checkpoint> {
        self.checkpoints.get(&checkpoint_id)
    }

    pub fn get_deposit_receipt(
        &self,
        token_account: AccountId,
        sender: AccountId,
        deposit_id: String,
    ) -> Option<DepositReceipt> {
        self.receipts
            .get(&deposit_key(&token_account, &sender, &deposit_id))
    }

    pub fn get_vault_broker_ids(&self, vault_id: u64) -> Vec<u64> {
        self.vault_brokers.get(&vault_id).unwrap_or_default()
    }

    pub fn list_vaults(&self, cursor: u64, limit: u32) -> Vec<VaultView> {
        bounded_limit(limit);
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
        cursor: u64,
        owner: Option<AccountId>,
        limit: u32,
    ) -> Vec<BrokerView> {
        bounded_limit(limit);
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
            })
            .collect()
    }

    pub fn list_loans(
        &self,
        cursor: u64,
        borrower: Option<AccountId>,
        broker_id: Option<u64>,
        limit: u32,
    ) -> Vec<LoanView> {
        bounded_limit(limit);
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
                        .map(|value| value == loan.broker_id)
                        .unwrap_or(true)
            })
            .map(|loan| self.loan_view(loan))
            .collect()
    }

    pub fn list_claims(&self, cursor: u64, owner: Option<AccountId>, limit: u32) -> Vec<ClaimView> {
        bounded_limit(limit);
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
        cursor: u64,
        owner: Option<AccountId>,
        limit: u32,
    ) -> Vec<PayoutView> {
        bounded_limit(limit);
        (1..=u64::from(limit))
            .filter_map(|offset| {
                cursor
                    .checked_add(offset)
                    .and_then(|id| self.payouts.get(&id))
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
                result_success: operation.result_success,
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
            operation,
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
        }
    }

    pub fn get_operation_context(&self, operation: String, id: u64) -> Option<ProofContextView> {
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

    pub fn get_statement_context(&self, operation: String, id: u64) -> Option<ProofContextView> {
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
            self.get_operation_context(operation.clone(), id)?
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
                context.commitments = vec![loan.accounting_leaf.clone()];
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

    pub fn prepare_statement(&self, args: PrepareStatementArgs) -> Option<ProofContextView> {
        require!(args.operation.len() <= MAX_ID_BYTES, ERR_INVALID_ENCODING);
        require!(
            args.ciphertexts.len() <= 64
                && args.commitments.len() <= 32
                && args.public_values.len() <= 32,
            ERR_INVALID_ENCODING
        );
        for ciphertext in &args.ciphertexts {
            validate_ciphertext(ciphertext);
        }
        for commitment in &args.commitments {
            validate_ciphertext(commitment);
        }
        let mut context = self.get_statement_context(args.operation.clone(), args.primary_id)?;
        context.ciphertexts.extend(args.ciphertexts);
        context.commitments.extend(args.commitments);
        context.public_values.extend(args.public_values);
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
}

impl Core {
    fn next_vault_id(&mut self) -> u64 {
        self.vault_sequence = self
            .vault_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.vault_sequence
    }

    fn next_broker_id(&mut self) -> u64 {
        self.broker_sequence = self
            .broker_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.broker_sequence
    }

    fn next_loan_id(&mut self) -> u64 {
        self.loan_sequence = self
            .loan_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.loan_sequence
    }

    fn next_proposal_id(&mut self) -> u64 {
        self.proposal_sequence = self
            .proposal_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.proposal_sequence
    }

    fn next_claim_id(&mut self) -> u64 {
        self.claim_sequence = self
            .claim_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.claim_sequence
    }

    fn next_checkpoint_id(&mut self) -> u64 {
        self.checkpoint_sequence = self
            .checkpoint_sequence
            .checked_add(1)
            .unwrap_or_else(|| panic!("{ERR_STALE_STATE}"));
        self.checkpoint_sequence
    }

    fn vault_or_panic(&self, id: u64) -> Vault {
        self.vaults
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn broker_or_panic(&self, id: u64) -> Broker {
        self.brokers
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn loan_or_panic(&self, id: u64) -> Loan {
        self.loans
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn proposal_or_panic(&self, id: u64) -> Proposal {
        self.proposals
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn claim_or_panic(&self, id: u64) -> PublicClaim {
        self.claims
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn payout_or_panic(&self, id: u64) -> PayoutOperation {
        self.payouts
            .get(&id)
            .unwrap_or_else(|| panic!("{ERR_NOT_FOUND}"))
    }

    fn holder_or_panic(&self, account: &AccountId) -> HolderBalance {
        self.holders
            .get(account)
            .unwrap_or_else(|| panic!("{ERR_NOT_REGISTERED}"))
    }

    fn holder_registered(&self, account: &AccountId) -> bool {
        self.holders.get(account).is_some()
    }

    fn ensure_vault_phase(&self, vault: &Vault, redemption: bool, deposit: bool) {
        match (&vault.kind, &vault.phase_times) {
            (VaultKind::OpenEnded, _) => {}
            (VaultKind::ClosedEnded, Some(phases)) => {
                let now = now_seconds();
                if redemption {
                    require!(now >= phases.redemption_start, ERR_WRONG_PHASE);
                } else if deposit {
                    require!(now < phases.investment_start, ERR_WRONG_PHASE);
                } else {
                    require!(
                        now >= phases.investment_start && now < phases.redemption_start,
                        ERR_WRONG_PHASE
                    );
                }
            }
            _ => panic!("{ERR_INVALID_ENCODING}"),
        }
    }

    fn keeper_index(&self, broker: &Broker, caller: &AccountId) -> Option<usize> {
        broker.delegates.iter().position(|grant| {
            grant.delegate_account == *caller
                && grant.active
                && now_seconds() <= grant.expires_at
                && grant.revocation_epoch == broker.encryption_key.authorization_epoch
        })
    }

    fn authorized_keeper(&self, broker: &Broker, caller: &AccountId) -> bool {
        self.keeper_index(broker, caller).is_some()
    }

    fn verify_bound_proof<T: BorshSerialize>(&self, domain: &[u8], args: &ProofArgs, dynamic: &T) {
        if !args.profile_hash.is_empty() {
            require!(
                args.profile_hash == self.asset.crypto_profile_hash,
                ERR_UNSUPPORTED_PROFILE
            );
        }
        let expected = hash_bytes(&(
            domain,
            &self.asset.crypto_profile_hash,
            &self.verifier.manifest_hash,
            dynamic,
        ));
        require!(args.context == expected, ERR_BAD_PROOF);
        self.verify_proof(domain, &expected, &args.proof);
    }

    /// Verify a reviewed profile proof through the immutable verifier boundary.
    ///
    /// The wire envelope is domain/profile-bound context followed by the
    /// verifier's pairing input. The crypto worker replaces this thin host
    /// boundary with its per-kind arkworks/NEAR BN254 adapter; no method accepts
    /// an empty proof or a caller-selected success flag.
    fn verify_proof(&self, domain: &[u8], context: &[u8], proof: &[u8]) {
        require!(
            self.verifier.production && !self.verifier.verifying_key.is_empty(),
            ERR_UNSUPPORTED_PROFILE
        );
        require!(!domain.is_empty() && !context.is_empty(), ERR_BAD_PROOF);
        require!(
            proof.len() > 32 && proof.len() <= MAX_PROOF_BYTES,
            ERR_BAD_PROOF
        );
        let expected = hash_bytes(&(
            domain,
            context,
            &self.asset.crypto_profile_hash,
            &self.verifier.manifest_hash,
        ));
        require!(proof[..32] == expected[..32], ERR_BAD_PROOF);
        let pairing = &proof[32..];
        require!(
            pairing.len() >= 192 && pairing.len() % 192 == 0,
            ERR_BAD_PROOF
        );
        require!(env::alt_bn128_pairing_check(pairing), ERR_BAD_PROOF);
    }

    fn vault_view(&self, vault: Vault) -> VaultView {
        let nav = vault
            .assets_total
            .checked_sub(vault.loss_unrealized)
            .unwrap_or(0);
        VaultView {
            vault_id: vault.vault_id,
            owner: vault.owner,
            asset_id: vault.asset_id,
            assets_total: U128(vault.assets_total),
            assets_available: U128(vault.assets_available),
            loss_unrealized: U128(vault.loss_unrealized),
            nav: U128(nav),
            shares_total: U128(vault.shares_total),
            accounting_pending: vault.accounting_pending,
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
            principal_ciphertexts: loan.principal_ciphertexts,
            initial_owed_ciphertexts: loan.initial_owed_ciphertexts,
            amount_owed_ciphertexts: loan.amount_owed_ciphertexts,
            periodic_payment_ciphertexts: loan.periodic_payment_ciphertexts,
            principal_remaining_ciphertexts: loan.principal_remaining_ciphertexts,
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
            serde_json::to_string(&event).unwrap_or_else(|_| panic!("{ERR_INVALID_ENCODING}"));
        require!(encoded.len() <= MAX_EVENT_BYTES, ERR_INVALID_ENCODING);
        env::log_str(&encoded);
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

fn validate_ciphertext_set(values: &[Vec<u8>], minimum: usize) {
    require!(values.len() >= minimum, ERR_INVALID_ENCODING);
    for value in values {
        validate_ciphertext(value);
    }
}

fn bounded_limit(limit: u32) {
    require!(limit > 0 && limit <= 50, ERR_INVALID_AMOUNT);
}

fn zero_ciphertext() -> Vec<u8> {
    vec![0u8; 32]
}

fn zero_ciphertext_set(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|_| zero_ciphertext()).collect()
}

fn zero_root() -> Vec<u8> {
    vec![0u8; 32]
}

/// Combine an authenticated encrypted delta with the current ciphertext.
///
/// The deployed build replaces this wire-level adapter with the
/// confidential-crypto Baby-Jubjub point addition implementation. The Core
/// never treats the delta as a replacement balance: the proof binds the exact
/// current ciphertext and this function is the only inbox-credit path.
fn combine_ciphertexts(current: &[u8], delta: &[u8]) -> Vec<u8> {
    // The crypto worker supplies Baby-Jubjub point addition at this boundary.
    // Never replace an encrypted balance with a digest of ciphertext bytes.
    validate_ciphertext(current);
    validate_ciphertext(delta);
    if current == zero_ciphertext().as_slice() {
        return delta.to_vec();
    }
    if delta == zero_ciphertext().as_slice() {
        return current.to_vec();
    }
    panic!("{ERR_UNSUPPORTED_PROFILE}")
}

fn share_key(vault_id: u64, owner: &AccountId) -> Vec<u8> {
    hash_bytes(&(vault_id, owner))
}

fn authorization_key(owner: &AccountId, key_id: u64) -> Vec<u8> {
    hash_bytes(&(b"authorization-key-v1".to_vec(), owner, key_id))
}

fn deposit_key(token: &AccountId, sender: &AccountId, deposit_id: &str) -> String {
    format!("{token}:{sender}:{deposit_id}")
}

fn hash_bytes<T: BorshSerialize>(value: &T) -> Vec<u8> {
    let encoded = to_vec(value).unwrap_or_else(|_| panic!("{ERR_INVALID_ENCODING}"));
    Sha256::digest(encoded).to_vec()
}

fn mul_u128(left: u128, right: u128) -> [u64; 4] {
    let a = [left as u64, (left >> 64) as u64];
    let b = [right as u64, (right >> 64) as u64];
    let mut out = [0u64; 4];
    for i in 0..2 {
        let mut carry = 0u128;
        for j in 0..2 {
            let index = i + j;
            let value = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[index]) + carry;
            out[index] = value as u64;
            carry = value >> 64;
        }
        let mut index = i + 2;
        while carry != 0 && index < 4 {
            let value = u128::from(out[index]) + carry;
            out[index] = value as u64;
            carry = value >> 64;
            index += 1;
        }
    }
    out
}

fn div_u256_u128(numerator: [u64; 4], denominator: u128) -> (u128, u128) {
    require!(denominator > 0, ERR_INVALID_AMOUNT);
    let mut quotient = [0u64; 4];
    let mut remainder = 0u128;
    for limb_index in (0..4).rev() {
        for bit_index in (0..64).rev() {
            let bit = (numerator[limb_index] >> bit_index) & 1;
            let high = remainder >> 127;
            let shifted = remainder.wrapping_shl(1).wrapping_add(u128::from(bit));
            if high != 0 || shifted >= denominator {
                remainder = shifted.wrapping_sub(denominator);
                quotient[limb_index] |= 1u64 << bit_index;
            } else {
                remainder = shifted;
            }
        }
    }
    require!(quotient[2] == 0 && quotient[3] == 0, ERR_INVALID_AMOUNT);
    (
        (u128::from(quotient[1]) << 64) | u128::from(quotient[0]),
        remainder,
    )
}

fn mul_div_floor(left: u128, right: u128, denominator: u128) -> u128 {
    let (quotient, _) = div_u256_u128(mul_u128(left, right), denominator);
    quotient
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{NearToken, testing_env};

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn init() -> Core {
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(account("owner.testnet"))
                .build()
        );
        Core::new(InitArgs {
            token_account: account("token.testnet"),
            decimals: 6,
            controller_account: account("issuer.testnet"),
            issuer_key_id: 1,
            issuer_public_key: vec![1; 32],
            token_auditor_key_id: 2,
            token_auditor_public_key: vec![2; 32],
            crypto_profile_hash: vec![3; 32],
            network_id: "local".to_string(),
            token_trust_policy: "local-test".to_string(),
            freeze_policy: "none".to_string(),
            custody_cap: U128(MAX_ASSET_UNITS),
            verifier_key: vec![4; 32],
            verifier_manifest_hash: vec![5; 32],
        })
    }

    #[test]
    fn wide_share_product_and_rounding() {
        assert_eq!(mul_div_floor(u128::MAX, 2, 2), u128::MAX);
        assert_eq!(mul_div_floor(10, 3, 4), 7);
        assert_eq!(mul_div_floor(1, 1, 2), 0);
    }

    #[test]
    fn first_deposit_uses_share_scale_and_public_claim() {
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
        testing_env!(
            VMContextBuilder::new()
                .predecessor_account_id(owner.clone())
                .block_timestamp(1)
                .build()
        );
        core.deposit_to_vault(DepositToVaultArgs {
            claim_id: 7,
            vault_id,
            amount: U128(1_000_000),
            min_shares_out: U128(1_000_000),
            expiry: 100,
        });
        assert_eq!(
            core.get_share_balance(vault_id, owner),
            U128(1_000_000_000_000)
        );
        assert_eq!(core.get_claim(7), None);
        assert_eq!(
            core.get_vault(vault_id).unwrap().assets_total,
            U128(1_000_000)
        );
    }

    #[test]
    fn deposit_receipt_is_sender_scoped_and_idempotent() {
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
            r#"{"version":1,"deposit_id":"d1"}"#.into(),
        );
        assert!(matches!(duplicate, PromiseOrValue::Value(U128(25))));
        assert_eq!(core.public_claim_total, 25);
    }

    #[test]
    fn payout_requires_runtime_result_before_finalize() {
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
            core.get_payout(42).unwrap().status,
            PayoutStatus::InFlight
        ));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.finalize_payout(42)));
        assert!(result.is_err());
        assert_eq!(core.get_claim(9).unwrap().reserved_by, Some(42));
    }
}
