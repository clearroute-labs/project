#![forbid(unsafe_code)]

//! Small, reviewable NEP-141 token for local Core integration tests.
//! It supports storage registration, transfer-call refunds, and owner minting.

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
        let requested = amount.map(|value| value.0).unwrap_or(current);
        require!(requested <= current, ERR_INSUFFICIENT);
        self.storage.insert(&account, &(current - requested));
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
            min: U128(1),
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
            available: U128(total),
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
