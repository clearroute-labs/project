use ark_bn254::Fr;
use serde::{Deserialize, Serialize};

use crate::CryptoError;
use crate::commitment::Commitment;
use crate::context::{OperationContext, PublicSlots, SlotBuilder};
use crate::elgamal::{Ciphertext, PublicKey};
use crate::encoding::{FieldHex, ScalarHex};

pub const TRANSFER_VIEW_COUNT: usize = 5;
pub const LOAN_READER_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum StatementKind {
    KeyPossession = 1,
    PublicConversion = 2,
    ConfidentialTransfer = 3,
    Origination = 4,
    Repayment = 5,
    Reconciliation = 6,
    ZeroBalance = 7,
    Ownership = 8,
}

impl StatementKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyPossession => "key-possession",
            Self::PublicConversion => "public-conversion",
            Self::ConfidentialTransfer => "confidential-transfer",
            Self::Origination => "origination",
            Self::Repayment => "repayment",
            Self::Reconciliation => "reconciliation",
            Self::ZeroBalance => "zero-balance",
            Self::Ownership => "ownership",
        }
    }

    /// Number of public field slots for this fixed circuit family. Slots are
    /// fixed per statement kind (and bounded by `CONTEXT_SLOTS`), rather than
    /// padded to the global maximum, so the verifier does not pay for unused
    /// public-input constraints.
    pub const fn slot_count(self) -> usize {
        const PREFIX: usize = 46; // context fields plus statement kind
        match self {
            Self::KeyPossession => PREFIX + 2,
            Self::PublicConversion => PREFIX + 2 + 8 + 3 * 6 + 1 + 2,
            Self::ConfidentialTransfer => PREFIX + 4 + 8 + TRANSFER_VIEW_COUNT * 14 + 2 + 1,
            Self::Origination => {
                PREFIX
                    + 4
                    + 8
                    + TRANSFER_VIEW_COUNT * 14
                    + 2
                    + LOAN_READER_COUNT * 14
                    + LOAN_READER_COUNT * 14
                    + 2
                    + 2
                    + 4
            }
            Self::Repayment => {
                PREFIX
                    + 4
                    + 8
                    + TRANSFER_VIEW_COUNT * 14
                    + LOAN_READER_COUNT * 6
                    + LOAN_READER_COUNT * 6
                    + LOAN_READER_COUNT * 14
                    + LOAN_READER_COUNT * 6
                    + LOAN_READER_COUNT * 6
                    + LOAN_READER_COUNT * 6
                    + LOAN_READER_COUNT * 14
                    + 2
                    + 6
            }
            Self::Reconciliation => PREFIX + 2 + 3 * 4 + 3 * 2 + 9 * 2 + 2,
            Self::ZeroBalance | Self::Ownership => PREFIX + 2 + 4 + 2,
        }
    }
}

impl std::fmt::Display for StatementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One encrypted amount view, including the exact reader key it is encrypted
/// to.  The circuit checks that all views in a statement open to the same
/// amount; a caller cannot swap a ciphertext under another reader's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderView {
    pub reader_key: PublicKey,
    pub ciphertext: Ciphertext,
}

/// Two authenticated ElGamal limb ciphertexts for a 63-bit amount. The pair
/// is carried in the exact statement and constrained to
/// `(amount & 0xffff_ffff, amount >> 32)` by the lending circuit. It is not a
/// caller-supplied recovery hint: a malformed pair makes the proof invalid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPair {
    pub low_limb: Ciphertext,
    pub high_limb: Ciphertext,
}

pub type TransferView = ReaderView;
pub type LoanReaderView = ReaderView;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentMode {
    Regular,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversionMode {
    Credit,
    Debit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPossessionStatement {
    pub context: OperationContext,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct KeyPossessionWitness {
    pub secret_key: crate::SecretKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicConversionStatement {
    pub context: OperationContext,
    pub owner_key: PublicKey,
    pub spending_before: Ciphertext,
    pub spending_after: Ciphertext,
    pub views: [LoanReaderView; LOAN_READER_COUNT],
    #[serde(with = "crate::encoding::decimal_u64")]
    pub public_amount: u64,
    pub mode: ConversionMode,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub spending_version: u64,
}

#[derive(Clone, Debug)]
pub struct PublicConversionWitness {
    pub owner_secret: crate::SecretKey,
    pub private_balance: u64,
    pub delta_randomness: ScalarHex,
    pub randomness: [ScalarHex; LOAN_READER_COUNT],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTransferStatement {
    pub context: OperationContext,
    pub sender_key: PublicKey,
    pub recipient_key: PublicKey,
    pub sender_spending_before: Ciphertext,
    pub sender_spending_after: Ciphertext,
    pub transfer_views: [TransferView; TRANSFER_VIEW_COUNT],
    pub transfer_recovery: [RecoveryPair; TRANSFER_VIEW_COUNT],
    pub amount_commitment: Commitment,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub sender_spending_version: u64,
}

#[derive(Clone, Debug)]
pub struct ConfidentialTransferWitness {
    pub sender_secret: crate::SecretKey,
    pub sender_balance: u64,
    pub amount: u64,
    pub sender_delta_randomness: ScalarHex,
    pub transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
    pub transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
    pub commitment_blinding: ScalarHex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginationStatement {
    pub context: OperationContext,
    pub broker_key: PublicKey,
    pub borrower_key: PublicKey,
    pub broker_spending_before: Ciphertext,
    pub broker_spending_after: Ciphertext,
    pub transfer_views: [TransferView; TRANSFER_VIEW_COUNT],
    pub transfer_recovery: [RecoveryPair; TRANSFER_VIEW_COUNT],
    pub principal_commitment: Commitment,
    pub owed_views: [LoanReaderView; LOAN_READER_COUNT],
    pub owed_recovery: [RecoveryPair; LOAN_READER_COUNT],
    pub payment_views: [LoanReaderView; LOAN_READER_COUNT],
    pub payment_recovery: [RecoveryPair; LOAN_READER_COUNT],
    pub owed_commitment: Commitment,
    pub payment_commitment: Commitment,
    pub payment_count: u32,
    pub max_payment_count: u32,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub broker_spending_version: u64,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub loan_version: u64,
}

#[derive(Clone, Debug)]
pub struct OriginationWitness {
    pub broker_secret: crate::SecretKey,
    pub broker_balance: u64,
    pub principal: u64,
    pub initial_owed: u64,
    pub periodic_payment: u64,
    pub transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
    pub transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
    pub broker_delta_randomness: ScalarHex,
    pub principal_blinding: ScalarHex,
    pub owed_randomness: [ScalarHex; LOAN_READER_COUNT],
    pub owed_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
    pub payment_randomness: [ScalarHex; LOAN_READER_COUNT],
    pub payment_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
    pub owed_blinding: ScalarHex,
    pub payment_blinding: ScalarHex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepaymentStatement {
    pub context: OperationContext,
    pub borrower_key: PublicKey,
    pub broker_key: PublicKey,
    pub borrower_spending_before: Ciphertext,
    pub borrower_spending_after: Ciphertext,
    pub transfer_views: [TransferView; TRANSFER_VIEW_COUNT],
    pub transfer_recovery: [RecoveryPair; TRANSFER_VIEW_COUNT],
    pub owed_before: [LoanReaderView; LOAN_READER_COUNT],
    pub owed_after: [LoanReaderView; LOAN_READER_COUNT],
    pub owed_delta: [LoanReaderView; LOAN_READER_COUNT],
    pub owed_delta_recovery: [RecoveryPair; LOAN_READER_COUNT],
    pub periodic_payment: [LoanReaderView; LOAN_READER_COUNT],
    pub principal_before: [LoanReaderView; LOAN_READER_COUNT],
    pub principal_after: [LoanReaderView; LOAN_READER_COUNT],
    pub principal_delta: [LoanReaderView; LOAN_READER_COUNT],
    pub principal_delta_recovery: [RecoveryPair; LOAN_READER_COUNT],
    pub principal_delta_commitment: Commitment,
    pub mode: PaymentMode,
    pub payment_remaining_before: u32,
    pub payment_remaining_after: u32,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub borrower_spending_version: u64,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub loan_version_before: u64,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub loan_version_after: u64,
}

#[derive(Clone, Debug)]
pub struct RepaymentWitness {
    pub borrower_secret: crate::SecretKey,
    pub borrower_balance: u64,
    pub payment: u64,
    pub owed_before: u64,
    pub periodic_payment: u64,
    pub principal_before: u64,
    pub principal_paid: u64,
    pub transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
    pub transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
    pub borrower_delta_randomness: ScalarHex,
    pub owed_delta_randomness: [ScalarHex; LOAN_READER_COUNT],
    pub owed_delta_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
    pub principal_delta_randomness: [ScalarHex; LOAN_READER_COUNT],
    pub principal_delta_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
    pub principal_paid_blinding: ScalarHex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationStatement {
    pub context: OperationContext,
    pub broker_key: PublicKey,
    pub cash: Ciphertext,
    pub active_principal: Ciphertext,
    pub impaired_principal: Ciphertext,
    pub cash_commitment: Commitment,
    pub active_principal_commitment: Commitment,
    pub impaired_principal_commitment: Commitment,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub debt_before: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub debt_after: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub vault_assets_before: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub vault_assets_after: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub vault_provision_before: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub vault_provision_after: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub provision_before: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub provision_after: u128,
    #[serde(with = "crate::encoding::decimal_u128")]
    pub realized_loss: u128,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub book_version: u64,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub accounting_version: u64,
}

#[derive(Clone, Debug)]
pub struct ReconciliationWitness {
    pub broker_secret: crate::SecretKey,
    pub cash: u128,
    pub active_principal: u128,
    pub impaired_principal: u128,
    pub cash_blinding: ScalarHex,
    pub active_principal_blinding: ScalarHex,
    pub impaired_principal_blinding: ScalarHex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceAssertionStatement {
    pub context: OperationContext,
    pub owner_key: PublicKey,
    pub ciphertext: Ciphertext,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub expected_amount: u64,
    #[serde(with = "crate::encoding::decimal_u64")]
    pub spending_version: u64,
}

#[derive(Clone, Debug)]
pub struct BalanceAssertionWitness {
    pub secret_key: crate::SecretKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// One bounded statement is processed per proof; preserve the direct typed API without heap indirection.
#[allow(clippy::large_enum_variant)]
pub enum Statement {
    KeyPossession(KeyPossessionStatement),
    PublicConversion(PublicConversionStatement),
    ConfidentialTransfer(ConfidentialTransferStatement),
    Origination(OriginationStatement),
    Repayment(RepaymentStatement),
    Reconciliation(ReconciliationStatement),
    ZeroBalance(BalanceAssertionStatement),
    Ownership(BalanceAssertionStatement),
}

impl Statement {
    pub fn kind(&self) -> StatementKind {
        match self {
            Self::KeyPossession(_) => StatementKind::KeyPossession,
            Self::PublicConversion(_) => StatementKind::PublicConversion,
            Self::ConfidentialTransfer(_) => StatementKind::ConfidentialTransfer,
            Self::Origination(_) => StatementKind::Origination,
            Self::Repayment(_) => StatementKind::Repayment,
            Self::Reconciliation(_) => StatementKind::Reconciliation,
            Self::ZeroBalance(_) => StatementKind::ZeroBalance,
            Self::Ownership(_) => StatementKind::Ownership,
        }
    }

    pub fn context(&self) -> &OperationContext {
        match self {
            Self::KeyPossession(s) => &s.context,
            Self::PublicConversion(s) => &s.context,
            Self::ConfidentialTransfer(s) => &s.context,
            Self::Origination(s) => &s.context,
            Self::Repayment(s) => &s.context,
            Self::Reconciliation(s) => &s.context,
            Self::ZeroBalance(s) | Self::Ownership(s) => &s.context,
        }
    }

    pub fn public_slots(&self) -> Result<PublicSlots, CryptoError> {
        let mut b = SlotBuilder::new(self.context(), self.kind())?;
        match self {
            Self::KeyPossession(s) => {
                b.push_public_key(&s.public_key)?;
            }
            Self::PublicConversion(s) => {
                b.push_public_key(&s.owner_key)?;
                b.push_ciphertext(&s.spending_before)?;
                b.push_ciphertext(&s.spending_after)?;
                for view in &s.views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                b.push_u64(s.public_amount);
                b.push_u64(matches!(s.mode, ConversionMode::Debit) as u64);
                b.push_u64(s.spending_version);
            }
            Self::ConfidentialTransfer(s) => {
                b.push_public_key(&s.sender_key)?;
                b.push_public_key(&s.recipient_key)?;
                b.push_ciphertext(&s.sender_spending_before)?;
                b.push_ciphertext(&s.sender_spending_after)?;
                for view in &s.transfer_views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for pair in &s.transfer_recovery {
                    b.push_recovery_pair(pair)?;
                }
                b.push_commitment(&s.amount_commitment)?;
                b.push_u64(s.sender_spending_version);
            }
            Self::Origination(s) => {
                b.push_public_key(&s.broker_key)?;
                b.push_public_key(&s.borrower_key)?;
                b.push_ciphertext(&s.broker_spending_before)?;
                b.push_ciphertext(&s.broker_spending_after)?;
                for view in &s.transfer_views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for pair in &s.transfer_recovery {
                    b.push_recovery_pair(pair)?;
                }
                b.push_commitment(&s.principal_commitment)?;
                for view in &s.owed_views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for pair in &s.owed_recovery {
                    b.push_recovery_pair(pair)?;
                }
                for view in &s.payment_views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for pair in &s.payment_recovery {
                    b.push_recovery_pair(pair)?;
                }
                b.push_commitment(&s.owed_commitment)?;
                b.push_commitment(&s.payment_commitment)?;
                b.push_u64(s.payment_count as u64);
                b.push_u64(s.max_payment_count as u64);
                b.push_u64(s.broker_spending_version);
                b.push_u64(s.loan_version);
            }
            Self::Repayment(s) => {
                b.push_public_key(&s.borrower_key)?;
                b.push_public_key(&s.broker_key)?;
                b.push_ciphertext(&s.borrower_spending_before)?;
                b.push_ciphertext(&s.borrower_spending_after)?;
                for view in &s.transfer_views {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for pair in &s.transfer_recovery {
                    b.push_recovery_pair(pair)?;
                }
                for view in &s.owed_before {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for view in &s.owed_after {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for (view, pair) in s.owed_delta.iter().zip(s.owed_delta_recovery.iter()) {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                    b.push_recovery_pair(pair)?;
                }
                for view in &s.periodic_payment {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for view in &s.principal_before {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for view in &s.principal_after {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                }
                for (view, pair) in s
                    .principal_delta
                    .iter()
                    .zip(s.principal_delta_recovery.iter())
                {
                    b.push_public_key(&view.reader_key)?;
                    b.push_ciphertext(&view.ciphertext)?;
                    b.push_recovery_pair(pair)?;
                }
                b.push_commitment(&s.principal_delta_commitment)?;
                b.push_u64(matches!(s.mode, PaymentMode::Full) as u64);
                b.push_u64(s.payment_remaining_before as u64);
                b.push_u64(s.payment_remaining_after as u64);
                b.push_u64(s.borrower_spending_version);
                b.push_u64(s.loan_version_before);
                b.push_u64(s.loan_version_after);
            }
            Self::Reconciliation(s) => {
                b.push_public_key(&s.broker_key)?;
                b.push_ciphertext(&s.cash)?;
                b.push_ciphertext(&s.active_principal)?;
                b.push_ciphertext(&s.impaired_principal)?;
                b.push_commitment(&s.cash_commitment)?;
                b.push_commitment(&s.active_principal_commitment)?;
                b.push_commitment(&s.impaired_principal_commitment)?;
                b.push_bytes(&s.debt_before.to_le_bytes());
                b.push_bytes(&s.debt_after.to_le_bytes());
                b.push_bytes(&s.vault_assets_before.to_le_bytes());
                b.push_bytes(&s.vault_assets_after.to_le_bytes());
                b.push_bytes(&s.vault_provision_before.to_le_bytes());
                b.push_bytes(&s.vault_provision_after.to_le_bytes());
                b.push_bytes(&s.provision_before.to_le_bytes());
                b.push_bytes(&s.provision_after.to_le_bytes());
                b.push_bytes(&s.realized_loss.to_le_bytes());
                b.push_u64(s.book_version);
                b.push_u64(s.accounting_version);
            }
            Self::ZeroBalance(s) | Self::Ownership(s) => {
                b.push_public_key(&s.owner_key)?;
                b.push_ciphertext(&s.ciphertext)?;
                b.push_u64(s.expected_amount);
                b.push_u64(s.spending_version);
            }
        }
        let slots = b.finish()?;
        if slots.values.len() != self.kind().slot_count() {
            return Err(CryptoError::ProfileMismatch);
        }
        Ok(slots)
    }

    pub fn context_digest(&self) -> Result<FieldHex, CryptoError> {
        Ok(self.public_slots()?.digest_wire())
    }

    pub fn public_inputs(&self) -> Result<Vec<Fr>, CryptoError> {
        Ok(self.public_slots()?.public_inputs())
    }

    pub fn public_input_wires(&self) -> Result<Vec<FieldHex>, CryptoError> {
        Ok(self
            .public_inputs()?
            .into_iter()
            .map(FieldHex::from)
            .collect())
    }

    pub fn public_input_bytes(&self) -> Result<Vec<[u8; 32]>, CryptoError> {
        self.public_input_wires()?
            .into_iter()
            .map(|wire| {
                let bytes = hex::decode(wire.0).map_err(|_| CryptoError::InvalidProofEncoding)?;
                bytes
                    .try_into()
                    .map_err(|_| CryptoError::InvalidProofEncoding)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_slot_counts_fit_profile_capacity() {
        let expected = [
            (StatementKind::KeyPossession, 48),
            (StatementKind::PublicConversion, 77),
            (StatementKind::ConfidentialTransfer, 131),
            (StatementKind::Origination, 222),
            (StatementKind::Repayment, 310),
            (StatementKind::Reconciliation, 86),
            (StatementKind::ZeroBalance, 54),
            (StatementKind::Ownership, 54),
        ];
        for (kind, count) in expected {
            assert_eq!(kind.slot_count(), count);
            assert!(count <= crate::CONTEXT_SLOTS);
        }
    }
}
