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

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Accounts,
    Registered,
}

#[ext_contract(ext_receiver)]
trait FungibleTokenReceiver {
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128>;
}

#[ext_contract(ext_self)]
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
        }
    }

    #[payable]
    pub fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        _registration_only: Option<bool>,
    ) -> U128 {
        let account = account_id.unwrap_or_else(env::predecessor_account_id);
        require!(account == env::predecessor_account_id(), ERR_UNAUTHORIZED);
        require!(
            env::attached_deposit() > NearToken::from_yoctonear(0),
            ERR_NOT_REGISTERED
        );
        self.registered.insert(&account, &true);
        if self.accounts.get(&account).is_none() {
            self.accounts.insert(&account, &0);
        }
        U128(1)
    }

    #[payable]
    pub fn storage_withdraw(&mut self, _amount: Option<U128>) -> U128 {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        U128(0)
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
        self.registered.remove(&account);
        self.accounts.remove(&account);
        true
    }

    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_supply)
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.accounts.get(&account_id).unwrap_or(0))
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, _memo: Option<String>) {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let sender = env::predecessor_account_id();
        self.transfer(&sender, &receiver_id, amount.0);
    }

    #[payable]
    pub fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        _memo: Option<String>,
        msg: String,
    ) -> Promise {
        require!(
            env::attached_deposit() == NearToken::from_yoctonear(1),
            ERR_UNAUTHORIZED
        );
        let sender = env::predecessor_account_id();
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
}

impl TestToken {
    fn transfer(&mut self, sender: &AccountId, receiver: &AccountId, amount: u128) {
        require!(amount > 0, ERR_AMOUNT);
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
