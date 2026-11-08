#![forbid(unsafe_code)]

//! Test token for Core integration tests and the public testnet deployment.
//! It supports storage registration, transfer-call refunds, and test funding.

use borsh::BorshSerialize;
use near_sdk::collections::LookupMap;
use near_sdk::json_types::U128;
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue, env,
    ext_contract, near, near_bindgen, require,
};

const GAS_TRANSFER_CALL: Gas = Gas::from_tgas(25);
const ERR_UNAUTHORIZED: &str = "UNAUTHORIZED";
const ERR_NOT_REGISTERED: &str = "NOT_REGISTERED";
const ERR_INSUFFICIENT: &str = "INSUFFICIENT_BALANCE";
const ERR_AMOUNT: &str = "INVALID_AMOUNT";
const ERR_FROZEN: &str = "ACCOUNT_FROZEN";
const ERR_FAUCET_NETWORK: &str = "FAUCET_TESTNET_ONLY";
const ERR_FAUCET_REPLAY: &str = "FAUCET_ALREADY_CLAIMED";
const ERR_FAUCET_STORAGE: &str = "FAUCET_STORAGE_REQUIRED";
const ERR_STORAGE_DEPOSIT: &str = "INSUFFICIENT_STORAGE_DEPOSIT";
const FAUCET_CLAIM_AMOUNT: u128 = 1_000_000_000;
const FAUCET_CLAIM_KEY_PREFIX: &[u8] = b"faucet_claimed:v1:";
// 0.01 NEAR leaves a conservative reserve for the three registration maps;
// storage_deposit also measures the exact first-write delta before accepting
// the transaction, so this is a lower bound rather than a guessed charge.
const MIN_STORAGE_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;

#[derive(near_sdk::serde::Serialize, near_sdk::serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct FungibleTokenMetadata {
    pub spec: String,
    pub name: String,
    pub symbol: String,
    pub icon: Option<String>,
    pub reference: Option<String>,
    pub reference_hash: Option<String>,
    pub decimals: u8,
}

#[derive(near_sdk::serde::Serialize, near_sdk::serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct StorageBalance {
    pub total: U128,
    pub available: U128,
}

#[derive(near_sdk::serde::Serialize, near_sdk::serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct StorageBalanceBounds {
    pub min: U128,
    pub max: Option<U128>,
}

#[derive(BorshSerialize, borsh::BorshDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    Normal,
    Fail,
    OversizedSuccess,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Accounts,
    Registered,
    Storage,
    Frozen,
}

#[ext_contract(ext_receiver)]
#[allow(dead_code)]
trait FungibleTokenReceiver {
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128>;
}

#[ext_contract(ext_self)]
#[allow(dead_code)]
trait TokenCallbacks {
    fn resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128;
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TestToken {
    pub owner_id: AccountId,
    pub total_supply: u128,
    pub accounts: LookupMap<AccountId, u128>,
    pub registered: LookupMap<AccountId, bool>,
    pub storage: LookupMap<AccountId, u128>,
    pub frozen: LookupMap<AccountId, bool>,
    pub transfer_mode: TransferMode,
}

#[near_bindgen]
impl TestToken {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner_id,
            total_supply: 0,
            accounts: LookupMap::new(StorageKey::Accounts),
            registered: LookupMap::new(StorageKey::Registered),
            storage: LookupMap::new(StorageKey::Storage),
            frozen: LookupMap::new(StorageKey::Frozen),
            transfer_mode: TransferMode::Normal,
        }
    }

    #[payable]
    pub fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        let account = account_id.unwrap_or_else(env::predecessor_account_id);
        let deposit = env::attached_deposit().as_yoctonear();
        require!(deposit > 0, ERR_NOT_REGISTERED);
        let _registration_only = registration_only.unwrap_or(false);
        let was_registered = self.registered.get(&account).unwrap_or(false);
        let storage_before = env::storage_usage();
        let current = self.storage.get(&account).unwrap_or(0);
        self.storage.insert(
            &account,
            &current
                .checked_add(deposit)
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}")),
        );
        self.registered.insert(&account, &true);
        if self.accounts.get(&account).is_none() {
            self.accounts.insert(&account, &0);
        }
        if !was_registered {
            let storage_delta = env::storage_usage().saturating_sub(storage_before) as u128;
            let measured_cost = storage_delta
                .checked_mul(env::storage_byte_cost().as_yoctonear())
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
            require!(
                deposit >= measured_cost.max(MIN_STORAGE_DEPOSIT),
                ERR_STORAGE_DEPOSIT
            );
        }
        self.storage_balance(&account)
    }

    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<U128>) -> StorageBalance {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let account = env::predecessor_account_id();
        let current = self.storage.get(&account).unwrap_or(0);
        require!(self.registered.get(&account).unwrap_or(false), ERR_NOT_REGISTERED);
        let available = current.saturating_sub(MIN_STORAGE_DEPOSIT);
        let requested = amount.map(|value| value.0).unwrap_or(available);
        require!(requested <= available, ERR_INSUFFICIENT);
        self.storage.insert(&account, &(current - requested));
        if requested > 0 {
            let _ = Promise::new(account.clone()).transfer(NearToken::from_yoctonear(requested));
        }
        self.storage_balance(&account)
    }

    #[payable]
    pub fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let account = env::predecessor_account_id();
        let balance = self.accounts.get(&account).unwrap_or(0);
        require!(force.unwrap_or(false) || balance == 0, ERR_INSUFFICIENT);
        if balance > 0 {
            self.total_supply = self
                .total_supply
                .checked_sub(balance)
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
        }
        self.registered.remove(&account);
        self.accounts.remove(&account);
        self.storage.remove(&account);
        self.frozen.remove(&account);
        true
    }

    pub fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        StorageBalanceBounds {
            min: U128(MIN_STORAGE_DEPOSIT),
            max: None,
        }
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.registered
            .get(&account_id)
            .filter(|registered| *registered)
            .map(|_| self.storage_balance(&account_id))
    }

    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_supply)
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.accounts.get(&account_id).unwrap_or(0))
    }

    /// NEP-148 metadata for the public test token used by the testnet demo.
    /// The token intentionally has no external icon or reference document.
    pub fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: "ft-1.0.0".to_string(),
            name: "ClearRoute Test Token".to_string(),
            symbol: "TEST".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 6,
        }
    }

    /// Return whether `account_id` has already consumed the one-time faucet
    /// grant. This is a view-only helper for wallet UIs; it does not reveal
    /// any owner credential or allow a claim on behalf of another account.
    pub fn faucet_has_claimed(&self, account_id: AccountId) -> bool {
        env::storage_has_key(&faucet_claim_key(&account_id))
    }

    pub fn faucet_claim_amount(&self) -> U128 {
        U128(FAUCET_CLAIM_AMOUNT)
    }

    /// Minimum storage balance for the versioned claim marker. The actual
    /// transaction checks the exact runtime delta, so callers should attach
    /// at least this amount in `storage_deposit` (one NEAR is ample).
    pub fn faucet_claim_storage_cost(&self, account_id: AccountId) -> U128 {
        let key = faucet_claim_key(&account_id);
        U128((key.len() as u128 + 1) * env::storage_byte_cost().as_yoctonear())
    }

    #[payable]
    pub fn ft_transfer(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    ) -> Vec<u8> {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let sender = env::predecessor_account_id();
        let _ = memo;
        require!(self.transfer_mode != TransferMode::Fail, ERR_UNAUTHORIZED);
        self.transfer(&sender, &receiver_id, amount.0);
        if self.transfer_mode == TransferMode::OversizedSuccess {
            vec![0u8; 8192]
        } else {
            Vec::new()
        }
    }

    #[payable]
    pub fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> Promise {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let sender = env::predecessor_account_id();
        let _ = memo;
        require!(self.transfer_mode != TransferMode::Fail, ERR_UNAUTHORIZED);
        self.transfer(&sender, &receiver_id, amount.0);
        ext_receiver::ext(receiver_id.clone())
            .with_static_gas(GAS_TRANSFER_CALL)
            .ft_on_transfer(sender.clone(), amount, msg)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(GAS_TRANSFER_CALL)
                    .resolve_transfer(sender, receiver_id, amount),
            )
            .into()
    }

    #[private]
    pub fn resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            ERR_UNAUTHORIZED
        );
        require!(env::promise_results_count() == 1, ERR_UNAUTHORIZED);
        let unused = match env::promise_result_checked(0, 4096) {
            Ok(bytes) => near_sdk::serde_json::from_slice::<U128>(&bytes)
                .map(|v| v.0)
                .unwrap_or(amount.0),
            Err(_) => amount.0,
        }
        .min(amount.0);
        if unused > 0 {
            let receiver_balance = self.accounts.get(&receiver_id).unwrap_or(0);
            let refund = unused.min(receiver_balance);
            self.accounts
                .insert(&receiver_id, &receiver_balance.saturating_sub(refund));
            let sender_balance = self.accounts.get(&sender_id).unwrap_or(0);
            self.accounts
                .insert(&sender_id, &sender_balance.saturating_add(refund));
        }
        U128(unused)
    }

    pub fn mint(&mut self, receiver_id: AccountId, amount: U128) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            ERR_UNAUTHORIZED
        );
        require!(amount.0 > 0, ERR_AMOUNT);
        require!(
            self.registered.get(&receiver_id).unwrap_or(false),
            ERR_NOT_REGISTERED
        );
        let balance = self.accounts.get(&receiver_id).unwrap_or(0);
        self.accounts.insert(
            &receiver_id,
            &balance
                .checked_add(amount.0)
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}")),
        );
        self.total_supply = self
            .total_supply
            .checked_add(amount.0)
            .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
    }

    /// Grant one fixed test-token balance to a registered Testnet account.
    ///
    /// This is deliberately self-service: no server-held signer or owner
    /// credential is involved. The caller must register storage first and
    /// must have enough registered storage balance to pay for the one-time
    /// claim marker. A raw versioned key is used so this can be added to an
    /// already initialized token without changing its serialized state.
    pub fn faucet_claim(&mut self) {
        require!(
            env::current_account_id().to_string().ends_with(".testnet"),
            ERR_FAUCET_NETWORK
        );
        let caller = env::predecessor_account_id();
        require!(
            self.registered.get(&caller).unwrap_or(false),
            ERR_NOT_REGISTERED
        );

        let claim_key = faucet_claim_key(&caller);
        require!(!env::storage_has_key(&claim_key), ERR_FAUCET_REPLAY);

        let storage_before = env::storage_usage();
        let balance = self.accounts.get(&caller).unwrap_or(0);
        self.accounts.insert(
            &caller,
            &balance
                .checked_add(FAUCET_CLAIM_AMOUNT)
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}")),
        );
        self.total_supply = self
            .total_supply
            .checked_add(FAUCET_CLAIM_AMOUNT)
            .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
        env::storage_write(&claim_key, &[1]);
        let storage_delta = env::storage_usage().saturating_sub(storage_before) as u128;
        let storage_cost = storage_delta
            .checked_mul(env::storage_byte_cost().as_yoctonear())
            .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
        let available = self.storage.get(&caller).unwrap_or(0);
        require!(available >= storage_cost, ERR_FAUCET_STORAGE);
        self.storage.insert(&caller, &(available - storage_cost));
    }

    pub fn burn(&mut self, owner_id: AccountId, amount: U128) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            ERR_UNAUTHORIZED
        );
        let balance = self.accounts.get(&owner_id).unwrap_or(0);
        require!(balance >= amount.0 && amount.0 > 0, ERR_INSUFFICIENT);
        self.accounts.insert(&owner_id, &(balance - amount.0));
        self.total_supply = self
            .total_supply
            .checked_sub(amount.0)
            .unwrap_or_else(|| panic!("{ERR_AMOUNT}"));
    }

    /// Local-test controls. They are owner-only and intentionally absent from
    /// the Core contract; sandbox tests use them to exercise failed and
    /// oversized-success payout receipts and token-side freezes.
    pub fn set_transfer_mode(&mut self, mode: u8) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            ERR_UNAUTHORIZED
        );
        self.transfer_mode = match mode {
            0 => TransferMode::Normal,
            1 => TransferMode::Fail,
            2 => TransferMode::OversizedSuccess,
            _ => panic!("{ERR_AMOUNT}"),
        };
    }

    pub fn set_frozen(&mut self, account_id: AccountId, frozen: bool) {
        require!(
            env::predecessor_account_id() == self.owner_id,
            ERR_UNAUTHORIZED
        );
        self.frozen.insert(&account_id, &frozen);
    }
}

impl TestToken {
    fn storage_balance(&self, account_id: &AccountId) -> StorageBalance {
        let total = self.storage.get(account_id).unwrap_or(0);
        StorageBalance {
            total: U128(total),
            available: U128(total.saturating_sub(MIN_STORAGE_DEPOSIT)),
        }
    }

    fn transfer(&mut self, sender: &AccountId, receiver: &AccountId, amount: u128) {
        require!(amount > 0, ERR_AMOUNT);
        require!(!self.frozen.get(sender).unwrap_or(false), ERR_FROZEN);
        require!(!self.frozen.get(receiver).unwrap_or(false), ERR_FROZEN);
        require!(
            self.registered.get(receiver).unwrap_or(false),
            ERR_NOT_REGISTERED
        );
        let sender_balance = self.accounts.get(sender).unwrap_or(0);
        require!(sender_balance >= amount, ERR_INSUFFICIENT);
        self.accounts.insert(sender, &(sender_balance - amount));
        let receiver_balance = self.accounts.get(receiver).unwrap_or(0);
        self.accounts.insert(
            receiver,
            &receiver_balance
                .checked_add(amount)
                .unwrap_or_else(|| panic!("{ERR_AMOUNT}")),
        );
    }
}

fn faucet_claim_key(account_id: &AccountId) -> Vec<u8> {
    let account = account_id.to_string();
    let mut key = Vec::with_capacity(FAUCET_CLAIM_KEY_PREFIX.len() + account.len());
    key.extend_from_slice(FAUCET_CLAIM_KEY_PREFIX);
    key.extend_from_slice(account.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{NearToken, testing_env};

    fn account(value: &str) -> AccountId {
        value.parse().expect("valid account id")
    }

    fn context(current: &str, predecessor: &str, deposit: NearToken) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(account(current))
                .predecessor_account_id(account(predecessor))
                .attached_deposit(deposit)
                .build()
        );
    }

    #[test]
    fn faucet_claim_requires_registration_and_mints_fixed_amount() {
        let mut token = TestToken::new(account("owner.testnet"));
        context("token.testnet", "alice.testnet", NearToken::from_near(1));
        token.storage_deposit(None, None);
        context("token.testnet", "alice.testnet", NearToken::from_yoctonear(0));
        token.faucet_claim();

        assert_eq!(token.ft_balance_of(account("alice.testnet")).0, FAUCET_CLAIM_AMOUNT);
        assert_eq!(token.ft_total_supply().0, FAUCET_CLAIM_AMOUNT);
        assert!(token.faucet_has_claimed(account("alice.testnet")));
        assert_eq!(token.faucet_claim_amount().0, FAUCET_CLAIM_AMOUNT);
    }

    #[test]
    #[should_panic(expected = "INSUFFICIENT_STORAGE_DEPOSIT")]
    fn storage_registration_rejects_a_nominal_one_yocto_deposit() {
        let mut token = TestToken::new(account("owner.testnet"));
        context("token.testnet", "alice.testnet", NearToken::from_yoctonear(1));
        token.storage_deposit(None, None);
    }

    #[test]
    #[should_panic(expected = "FAUCET_ALREADY_CLAIMED")]
    fn faucet_claim_is_one_time_per_account() {
        let mut token = TestToken::new(account("owner.testnet"));
        context("token.testnet", "alice.testnet", NearToken::from_near(1));
        token.storage_deposit(None, None);
        context("token.testnet", "alice.testnet", NearToken::from_yoctonear(0));
        token.faucet_claim();
        token.faucet_claim();
    }

    #[test]
    #[should_panic(expected = "FAUCET_TESTNET_ONLY")]
    fn faucet_claim_rejects_non_testnet_contract_deployment() {
        let mut token = TestToken::new(account("owner.testnet"));
        context("token.near", "alice.near", NearToken::from_near(1));
        token.storage_deposit(None, None);
        context("token.near", "alice.near", NearToken::from_yoctonear(0));
        token.faucet_claim();
    }

    #[test]
    fn metadata_is_nep148_compatible() {
        let token = TestToken::new(account("owner.testnet"));
        let metadata = token.ft_metadata();
        assert_eq!(metadata.spec, "ft-1.0.0");
        assert_eq!(metadata.symbol, "TEST");
        assert_eq!(metadata.decimals, 6);
    }

    #[test]
    fn storage_withdraw_defaults_to_available_and_retains_registration_reserve() {
        context("token.testnet", "alice.testnet", NearToken::from_near(1));
        let mut token = TestToken::new(account("owner.testnet"));
        token.storage_deposit(None, None);
        context("token.testnet", "alice.testnet", NearToken::from_yoctonear(1));
        let balance = token.storage_withdraw(None);
        assert_eq!(balance.total.0, MIN_STORAGE_DEPOSIT);
        assert_eq!(balance.available.0, 0);
        assert!(token.storage_balance_of(account("alice.testnet")).is_some());
        assert_eq!(near_sdk::test_utils::get_created_receipts().len(), 1);
    }

    #[test]
    fn implicit_wallet_can_claim_with_the_ui_registration_deposit() {
        let implicit = "a".repeat(64);
        context("token.testnet", &implicit, NearToken::from_yoctonear(MIN_STORAGE_DEPOSIT));
        let mut token = TestToken::new(account("owner.testnet"));
        token.storage_deposit(None, Some(true));
        context("token.testnet", &implicit, NearToken::from_yoctonear(0));
        token.faucet_claim();
        assert_eq!(token.ft_balance_of(account(&implicit)).0, FAUCET_CLAIM_AMOUNT);
        context("token.testnet", &implicit, NearToken::from_yoctonear(1));
        assert_eq!(token.storage_withdraw(None).available.0, 0);
    }
}
