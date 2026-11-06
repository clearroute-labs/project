use super::*;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng, rngs::StdRng};

const CLEAR: FinalRedemption = FinalRedemption {
    obligations_cleared: true,
};
const OBLIGATIONS: FinalRedemption = FinalRedemption {
    obligations_cleared: false,
};

fn drawn(debt: u128) -> Vault {
    Vault {
        total: debt,
        available: 0,
        provision: 0,
        shares: debt,
    }
}
fn book(cash: u128, active_principal: u128, impaired_principal: u128) -> ConfidentialBook {
    ConfidentialBook {
        cash,
        active_principal,
        impaired_principal,
    }
}

#[test]
fn wide_products_match_independent_big_integer_oracle() {
    let mut rng = StdRng::seed_from_u64(0x6163636f756e7469);
    for index in 0..10_000 {
        let (a, b, d) = if index == 0 {
            (u128::MAX, u128::MAX, u128::MAX)
        } else {
            (
                rng.r#gen::<u128>(),
                rng.r#gen::<u128>(),
                rng.r#gen::<u128>().max(1),
            )
        };
        let product = BigUint::from(a) * BigUint::from(b);
        let floor = &product / d;
        let ceil = (&product + BigUint::from(d - 1)) / d;
        for (actual, expected) in [
            (mul_div_floor(a, b, d), floor),
            (mul_div_ceil(a, b, d), ceil),
        ] {
            match u128::try_from(expected) {
                Ok(value) => assert_eq!(actual, Ok(value)),
                Err(_) => assert_eq!(actual, Err(Error::Overflow)),
            }
        }
    }
    assert_eq!(mul_div_floor(1, 1, 0), Err(Error::InvalidAmount));
}

#[test]
fn share_prices_round_against_the_actor_and_preserve_final_dust() {
    let first = mint(Vault::default(), 3, 2, 300).unwrap();
    assert_eq!(first.shares, 300);
    let vault = Vault {
        total: 100,
        available: 100,
        provision: 0,
        shares: 3,
    };
    assert_eq!(
        redeem_shares(vault, 3, 1, 33, false, CLEAR).unwrap().assets,
        33
    );
    assert_eq!(
        redeem_amount(vault, 3, 34, 2, false, CLEAR).unwrap().shares,
        2
    );
    assert_eq!(
        redeem_amount(vault, 3, 99, 3, false, CLEAR).unwrap().assets,
        100
    );
    assert_eq!(
        redeem_shares(vault, 3, 3, 100, false, OBLIGATIONS),
        Err(Error::HasObligations)
    );
    assert_eq!(
        redeem_amount(vault, 3, 34, 1, false, CLEAR),
        Err(Error::Slippage)
    );
    assert_eq!(
        mint(Vault { shares: 1, ..vault }, 1, 0, 0),
        Err(Error::Dust)
    );
}

#[test]
fn sole_shareholder_waiver_does_not_create_liquidity_or_clear_obligations() {
    let vault = Vault {
        total: 100,
        available: 50,
        provision: 50,
        shares: 100,
    };
    assert_eq!(
        redeem_shares(vault, 100, 50, 0, false, OBLIGATIONS)
            .unwrap()
            .assets,
        25
    );
    assert_eq!(
        redeem_shares(vault, 100, 50, 0, true, OBLIGATIONS)
            .unwrap()
            .assets,
        50
    );
    assert_eq!(
        redeem_shares(vault, 99, 50, 0, true, OBLIGATIONS),
        Err(Error::InvalidState)
    );
    assert_eq!(
        redeem_shares(vault, 100, 60, 0, true, OBLIGATIONS),
        Err(Error::InsufficientLiquidity)
    );
    assert_eq!(
        redeem_shares(vault, 100, 100, 0, true, OBLIGATIONS),
        Err(Error::HasObligations)
    );
}

#[test]
fn worthless_final_shares_require_every_obligation_cleared() {
    let vault = Vault {
        total: 100,
        available: 0,
        provision: 100,
        shares: 100,
    };
    assert_eq!(
        burn_worthless(vault, 100, 40, OBLIGATIONS).unwrap().shares,
        60
    );
    assert_eq!(
        burn_worthless(vault, 100, 100, CLEAR),
        Err(Error::HasObligations)
    );
    let empty = Vault {
        total: 0,
        available: 0,
        provision: 0,
        shares: 100,
    };
    assert_eq!(burn_worthless(empty, 100, 100, CLEAR).unwrap().shares, 0);
    assert_eq!(
        redeem_shares(empty, 100, 1, 0, false, CLEAR),
        Err(Error::ZeroNav)
    );
}

#[test]
fn spec_23_1_and_23_2_principal_first_and_yield_only_at_settlement() {
    assert_eq!(
        allocate_payment(1100, 1000, 1100).unwrap(),
        Allocation {
            principal_paid: 1000,
            finance_charge_paid: 100,
            remaining_principal: 0,
            remaining_owed: 0
        }
    );
    let regular = allocate_payment(1100, 1000, 275).unwrap();
    assert_eq!(
        (
            regular.remaining_owed,
            regular.remaining_principal,
            regular.finance_charge_paid
        ),
        (825, 725, 0)
    );
    let vault = Vault {
        total: 1000,
        available: 400,
        provision: 0,
        shares: 1000,
    };
    let result = settle(vault, 600, 660).unwrap();
    assert_eq!(
        (
            result.vault.total,
            result.vault.available,
            result.debt,
            result.yield_received
        ),
        (1060, 1060, 0, 60)
    );
}

#[test]
fn spec_23_3_profit_offsets_default_in_both_orders() {
    let checkpoint = reconcile(drawn(200), 200, 0, book(150, 0, 0)).unwrap();
    assert_eq!(checkpoint.realized_loss, 50);
    let first = settle(checkpoint.vault, checkpoint.debt, 150).unwrap();
    let second_settle = settle(drawn(200), 200, 150).unwrap();
    let second = reconcile(second_settle.vault, second_settle.debt, 0, book(0, 0, 0)).unwrap();
    assert_eq!((first.vault, first.debt), (second.vault, second.debt));
    assert_eq!(second.realized_loss, 50);
}

#[test]
fn spec_23_4_recycled_income_is_not_an_extra_draw() {
    let before = reconcile(drawn(100), 100, 0, book(0, 150, 0)).unwrap();
    assert_eq!(before.realized_loss, 0);
    let after = reconcile(before.vault, before.debt, 0, book(0, 0, 0)).unwrap();
    assert_eq!(after.realized_loss, 100);
}

#[test]
fn spec_23_5_impairment_to_default_preserves_nav() {
    let impaired = reconcile(drawn(200), 200, 0, book(150, 100, 100)).unwrap();
    assert_eq!(
        (
            impaired.realized_loss,
            impaired.broker_provision,
            impaired.vault.nav().unwrap()
        ),
        (0, 50, 150)
    );
    let defaulted = reconcile(
        impaired.vault,
        impaired.debt,
        impaired.broker_provision,
        book(150, 0, 0),
    )
    .unwrap();
    assert_eq!(
        (
            defaulted.realized_loss,
            defaulted.broker_provision,
            defaulted.vault.nav().unwrap()
        ),
        (50, 0, 150)
    );
    let unimpair = reconcile(
        impaired.vault,
        impaired.debt,
        impaired.broker_provision,
        book(150, 100, 0),
    )
    .unwrap();
    assert_eq!(unimpair.vault.nav().unwrap(), 200);
}

#[test]
fn settlement_with_a_provision_reconciles_after_debt_decreases() {
    let impaired = reconcile(drawn(200), 200, 0, book(150, 100, 100)).unwrap();
    let settled = settle(impaired.vault, impaired.debt, 150).unwrap();
    let checkpoint = reconcile(
        settled.vault,
        settled.debt,
        impaired.broker_provision,
        book(0, 100, 100),
    )
    .unwrap();
    assert_eq!(
        (
            checkpoint.debt,
            checkpoint.broker_provision,
            checkpoint.vault.nav().unwrap()
        ),
        (50, 50, 150)
    );
}

#[test]
fn spec_23_6_and_23_8_old_income_and_defaults_cannot_be_reused() {
    let yielded = settle(drawn(100), 100, 150).unwrap();
    let redrawn = Vault {
        available: yielded.vault.available - 100,
        ..yielded.vault
    };
    let loss = reconcile(redrawn, 100, 0, book(0, 0, 0)).unwrap();
    assert_eq!(loss.realized_loss, 100);
    let redrawn_again = Vault {
        available: loss.vault.available - 50,
        ..loss.vault
    };
    let no_loss = reconcile(redrawn_again, 50, 0, book(50, 0, 0)).unwrap();
    assert_eq!(no_loss.realized_loss, 0);
}

#[test]
fn reconciliation_replaces_one_brokers_provision_without_erasing_others() {
    let vault = Vault {
        total: 400,
        available: 0,
        provision: 80,
        shares: 400,
    };
    let result = reconcile(vault, 200, 50, book(150, 0, 0)).unwrap();
    assert_eq!(
        (
            result.vault.total,
            result.vault.provision,
            result.vault.nav().unwrap()
        ),
        (350, 30, 320)
    );
}

#[test]
fn bounds_reject_overflow_and_invalid_interpretations() {
    assert_eq!(
        reconcile(drawn(1), 1, 0, book(1, u128::MAX, 0)),
        Err(Error::Overflow)
    );
    assert_eq!(
        reconcile(drawn(1), 1, 0, book(0, 1, 2)),
        Err(Error::InvalidState)
    );
    assert_eq!(
        mint(
            Vault {
                total: MAX_ASSET_UNITS,
                available: MAX_ASSET_UNITS,
                provision: 0,
                shares: 1
            },
            1,
            0,
            0
        ),
        Err(Error::Dust)
    );
    assert_eq!(
        validate_schedule(u64::MAX - 1, 1, 1, 1),
        Err(Error::Overflow)
    );
    assert_eq!(validate_schedule(100, 60, 4, 5), Ok((160, 340)));
    assert_eq!(allocate_payment(10, 11, 1), Err(Error::InvalidAmount));
}
