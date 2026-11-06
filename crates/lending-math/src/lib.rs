//! Integer accounting shared by the contract and off-chain witness builders.
//! Authority, phase, expiry, frozen accounts and proof validity are checked by callers.
#![forbid(unsafe_code)]

pub const MAX_ASSET_UNITS: u128 = (1u128 << 63) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAmount,
    InvalidState,
    Overflow,
    ZeroNav,
    Dust,
    InsufficientShares,
    InsufficientLiquidity,
    Slippage,
    HasObligations,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vault {
    pub total: u128,
    pub available: u128,
    pub provision: u128,
    pub shares: u128,
}

impl Vault {
    pub fn validate(self) -> Result<Self, Error> {
        if self.total > MAX_ASSET_UNITS
            || self.available > self.total
            || self.provision > self.total
        {
            return Err(Error::InvalidState);
        }
        Ok(self)
    }

    pub fn nav(self) -> Result<u128, Error> {
        self.validate()?;
        self.total
            .checked_sub(self.provision)
            .ok_or(Error::InvalidState)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareChange {
    pub vault: Vault,
    pub assets: u128,
    pub shares: u128,
}

/// Whether all broker cash, debts, active loans and pending work have been cleared.
/// The Core derives this flag from authenticated state and verified zero assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalRedemption {
    pub obligations_cleared: bool,
}

pub fn mint(vault: Vault, assets: u128, scale: u8, min_shares: u128) -> Result<ShareChange, Error> {
    positive_amount(assets)?;
    let nav = vault.nav()?;
    let shares = if vault.shares == 0 {
        if vault.total != 0 {
            return Err(Error::InvalidState);
        }
        if scale > 18 {
            return Err(Error::InvalidAmount);
        }
        assets
            .checked_mul(10u128.pow(u32::from(scale)))
            .ok_or(Error::Overflow)?
    } else {
        if nav == 0 {
            return Err(Error::ZeroNav);
        }
        mul_div_floor(assets, vault.shares, nav)?
    };
    if shares == 0 {
        return Err(Error::Dust);
    }
    if shares < min_shares {
        return Err(Error::Slippage);
    }
    let next = Vault {
        total: vault.total.checked_add(assets).ok_or(Error::Overflow)?,
        available: vault.available.checked_add(assets).ok_or(Error::Overflow)?,
        shares: vault.shares.checked_add(shares).ok_or(Error::Overflow)?,
        ..vault
    }
    .validate()?;
    Ok(ShareChange {
        vault: next,
        assets,
        shares,
    })
}

pub fn redeem_shares(
    vault: Vault,
    owned: u128,
    shares: u128,
    min_assets: u128,
    waive_provision: bool,
    final_state: FinalRedemption,
) -> Result<ShareChange, Error> {
    let nav = redemption_nav(vault, owned, waive_provision)?;
    if shares == 0 || shares > owned {
        return Err(Error::InsufficientShares);
    }
    let assets = mul_div_floor(shares, nav, vault.shares)?;
    finish_redemption(vault, shares, assets, min_assets, final_state)
}

pub fn redeem_amount(
    vault: Vault,
    owned: u128,
    assets: u128,
    max_shares: u128,
    waive_provision: bool,
    final_state: FinalRedemption,
) -> Result<ShareChange, Error> {
    positive_amount(assets)?;
    let nav = redemption_nav(vault, owned, waive_provision)?;
    let shares = mul_div_ceil(assets, vault.shares, nav)?;
    if shares == 0 || shares > owned {
        return Err(Error::InsufficientShares);
    }
    if shares > max_shares {
        return Err(Error::Slippage);
    }
    finish_redemption(vault, shares, assets, assets, final_state)
}

fn redemption_nav(vault: Vault, owned: u128, waive: bool) -> Result<u128, Error> {
    let nav = vault.nav()?;
    if owned > vault.shares || vault.shares == 0 {
        return Err(Error::InsufficientShares);
    }
    if waive && owned != vault.shares {
        return Err(Error::InvalidState);
    }
    let priced_nav = if waive { vault.total } else { nav };
    if priced_nav == 0 {
        return Err(Error::ZeroNav);
    }
    Ok(priced_nav)
}

fn finish_redemption(
    vault: Vault,
    shares: u128,
    mut assets: u128,
    min_assets: u128,
    final_state: FinalRedemption,
) -> Result<ShareChange, Error> {
    if shares == vault.shares {
        if !final_state.obligations_cleared
            || vault.provision != 0
            || vault.total != vault.available
        {
            return Err(Error::HasObligations);
        }
        assets = vault.total;
    }
    if assets == 0 {
        return Err(Error::Dust);
    }
    if assets > vault.available {
        return Err(Error::InsufficientLiquidity);
    }
    if assets < min_assets {
        return Err(Error::Slippage);
    }
    let next = Vault {
        total: vault.total.checked_sub(assets).ok_or(Error::InvalidState)?,
        available: vault.available - assets,
        shares: vault.shares - shares,
        ..vault
    }
    .validate()?;
    Ok(ShareChange {
        vault: next,
        assets,
        shares,
    })
}

pub fn burn_worthless(
    vault: Vault,
    owned: u128,
    shares: u128,
    final_state: FinalRedemption,
) -> Result<Vault, Error> {
    if vault.nav()? != 0 {
        return Err(Error::InvalidState);
    }
    if shares == 0 || shares > owned || owned > vault.shares {
        return Err(Error::InsufficientShares);
    }
    if shares == vault.shares
        && (!final_state.obligations_cleared
            || vault.total != 0
            || vault.available != 0
            || vault.provision != 0)
    {
        return Err(Error::HasObligations);
    }
    Ok(Vault {
        shares: vault.shares - shares,
        ..vault
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub vault: Vault,
    pub debt: u128,
    pub principal_return: u128,
    pub yield_received: u128,
}

/// When the broker has a provision, the caller must reconcile the resulting state atomically.
pub fn settle(vault: Vault, debt: u128, amount: u128) -> Result<Settlement, Error> {
    vault.validate()?;
    positive_amount(amount)?;
    amount_bound(debt)?;
    if debt > vault.total - vault.available {
        return Err(Error::InvalidState);
    }
    let principal_return = amount.min(debt);
    let yield_received = amount - principal_return;
    let next = Vault {
        total: vault
            .total
            .checked_add(yield_received)
            .ok_or(Error::Overflow)?,
        available: vault.available.checked_add(amount).ok_or(Error::Overflow)?,
        ..vault
    }
    .validate()?;
    Ok(Settlement {
        vault: next,
        debt: debt - principal_return,
        principal_return,
        yield_received,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfidentialBook {
    pub cash: u128,
    /// Includes healthy and impaired active principal (H + I).
    pub active_principal: u128,
    pub impaired_principal: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reconciliation {
    pub vault: Vault,
    pub debt: u128,
    pub broker_provision: u128,
    pub realized_loss: u128,
}

pub fn reconcile(
    vault: Vault,
    debt: u128,
    old_broker_provision: u128,
    book: ConfidentialBook,
) -> Result<Reconciliation, Error> {
    vault.validate()?;
    amount_bound(debt)?;
    amount_bound(book.cash)?;
    if old_broker_provision > vault.provision
        || book.impaired_principal > book.active_principal
        || debt > vault.total - vault.available
    {
        return Err(Error::InvalidState);
    }
    let backing = book
        .cash
        .checked_add(book.active_principal)
        .ok_or(Error::Overflow)?;
    let healthy_backing = backing - book.impaired_principal;
    let realized_loss = debt.saturating_sub(backing);
    let new_debt = debt - realized_loss;
    let broker_provision = new_debt.saturating_sub(healthy_backing);
    let next = Vault {
        total: vault
            .total
            .checked_sub(realized_loss)
            .ok_or(Error::InvalidState)?,
        provision: (vault.provision - old_broker_provision)
            .checked_add(broker_provision)
            .ok_or(Error::Overflow)?,
        ..vault
    }
    .validate()?;
    Ok(Reconciliation {
        vault: next,
        debt: new_debt,
        broker_provision,
        realized_loss,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub principal_paid: u128,
    pub finance_charge_paid: u128,
    pub remaining_principal: u128,
    pub remaining_owed: u128,
}

pub fn allocate_payment(owed: u128, principal: u128, payment: u128) -> Result<Allocation, Error> {
    amount_bound(owed)?;
    amount_bound(principal)?;
    positive_amount(payment)?;
    if principal > owed || payment > owed {
        return Err(Error::InvalidAmount);
    }
    let principal_paid = payment.min(principal);
    Ok(Allocation {
        principal_paid,
        finance_charge_paid: payment - principal_paid,
        remaining_principal: principal - principal_paid,
        remaining_owed: owed - payment,
    })
}

pub fn validate_schedule(
    start: u64,
    interval: u64,
    count: u32,
    grace: u64,
) -> Result<(u64, u64), Error> {
    if interval == 0 || count == 0 {
        return Err(Error::InvalidAmount);
    }
    let first = start.checked_add(interval).ok_or(Error::Overflow)?;
    let final_due = interval
        .checked_mul(u64::from(count))
        .and_then(|term| start.checked_add(term))
        .ok_or(Error::Overflow)?;
    final_due.checked_add(grace).ok_or(Error::Overflow)?;
    Ok((first, final_due))
}

fn positive_amount(amount: u128) -> Result<(), Error> {
    if amount == 0 {
        return Err(Error::InvalidAmount);
    }
    amount_bound(amount)
}

fn amount_bound(amount: u128) -> Result<(), Error> {
    if amount > MAX_ASSET_UNITS {
        return Err(Error::InvalidAmount);
    }
    Ok(())
}

pub fn mul_div_floor(a: u128, b: u128, denominator: u128) -> Result<u128, Error> {
    mul_div(a, b, denominator).map(|(quotient, _)| quotient)
}

pub fn mul_div_ceil(a: u128, b: u128, denominator: u128) -> Result<u128, Error> {
    let (quotient, remainder) = mul_div(a, b, denominator)?;
    quotient
        .checked_add(u128::from(remainder != 0))
        .ok_or(Error::Overflow)
}

fn mul_div(a: u128, b: u128, denominator: u128) -> Result<(u128, u128), Error> {
    if denominator == 0 {
        return Err(Error::InvalidAmount);
    }
    let left = [a as u64, (a >> 64) as u64];
    let right = [b as u64, (b >> 64) as u64];
    let mut product = [0u64; 4];
    for (i, a) in left.iter().enumerate() {
        let mut carry = 0u128;
        for (j, b) in right.iter().enumerate() {
            let value = u128::from(*a) * u128::from(*b) + u128::from(product[i + j]) + carry;
            product[i + j] = value as u64;
            carry = value >> 64;
        }
        product[i + 2] = carry as u64;
    }
    let mut quotient = [0u64; 4];
    let mut remainder = 0u128;
    for index in (0..256).rev() {
        let bit = (product[index / 64] >> (index % 64)) & 1;
        let high = remainder >> 127;
        let shifted = (remainder << 1) | u128::from(bit);
        if high != 0 || shifted >= denominator {
            remainder = shifted.wrapping_sub(denominator);
            quotient[index / 64] |= 1u64 << (index % 64);
        } else {
            remainder = shifted;
        }
    }
    if quotient[2] != 0 || quotient[3] != 0 {
        return Err(Error::Overflow);
    }
    Ok((
        u128::from(quotient[0]) | (u128::from(quotient[1]) << 64),
        remainder,
    ))
}

#[cfg(test)]
mod tests;
