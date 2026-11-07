//! Cryptographic profile for the confidential lending protocol.
//!
//! The public API intentionally keeps wire values separate from arkworks
//! values.  Callers must pass canonical hex encodings at protocol boundaries;
//! malformed, non-canonical, identity, or non-subgroup points are rejected.

#![forbid(unsafe_code)]

mod commitment;
mod context;
mod elgamal;
mod encoding;
mod error;
mod hash_to_curve;
mod statement;

pub mod proof;
pub mod recovery;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use commitment::Commitment;
pub use context::{OperationContext, transcript_hash};
pub use elgamal::{Ciphertext, PublicKey, SecretKey};
pub use encoding::{FieldHex, PointHex, ScalarHex};
pub use error::CryptoError;
pub use proof::{
    ArtifactSet, ProofEnvelope, ProvingArtifacts, SetupMode, Witness, WitnessWire, prove, setup,
    verify, verify_with_vk_bytes,
};
pub use recovery::{RecoveryMetadata, RecoveryRecord, RecoverySignature, recover_pair};
pub use statement::{
    BalanceAssertionStatement, BalanceAssertionWitness, ConfidentialTransferStatement,
    ConfidentialTransferWitness, ConversionMode, KeyPossessionStatement,
    KeyPossessionStatement as KeyStatement, KeyPossessionWitness, LoanReaderView,
    OriginationStatement, OriginationWitness, PaymentMode, PublicConversionStatement,
    PublicConversionWitness, ReaderView, ReconciliationStatement, ReconciliationWitness,
    RecoveryPair, RepaymentStatement, RepaymentWitness, Statement, StatementKind, TransferView,
};

pub const PROFILE_ID: &str = "near-confidential-lending-bn254-edwards-groth16-v3";
pub const PROFILE_VERSION: u32 = 3;
pub const MAX_AMOUNT: u64 = (1u64 << 63) - 1;
/// Fixed slot capacity. Repayment carries five transfer recovery pairs plus
/// recovery pairs for each owed/principal delta; origination carries principal
/// and term pairs. The cap leaves no caller-selected circuit shape while
/// retaining room for future context fields without truncation.
pub const CONTEXT_SLOTS: usize = 320;
/// Canonical suite description. Artifact/VK/WASM hashes are deployment
/// artifacts and are intentionally not part of this immutable suite hash.
pub const PROFILE_MANIFEST: &str = "near-confidential-lending-bn254-edwards-groth16-v3\nversion=3\ncurve=ark-ed-on-bn254;subgroup=prime-order;encoding=compressed-32-byte-lower-hex\nelgamal=C=(rG,mG+rPK);pedersen=mG+rH;H=NEAR-CONFIDENTIAL-LENDING/PEDERSEN-H/v1:sha256-try-and-increment:cofactor8\nproof=arkworks-groth16-bn254;proof-compressed=canonical;field-input=canonical-le32\nposeidon=width3;rate2;capacity1;alpha5;full8;partial57;grain-skip0\ntranscript=domain-field+slot-count+all-fixed-kind-slots;poseidon-field-output\npoint-membership=statement-on-curve-plus-private-cofactor-preimage-[8]Q=P;generic-points=strict-prime-subgroup\nmax-amount=9223372036854775807;slot-capacity=320\ntransfer-views=5;loan-reader-views=3\nrecovery=proof-bound-two-encrypted-u32-limbs;authenticated-records-hints-only\nsetup=development-single-party-rejected-funded-release\n";
pub const PROFILE_HASH: [u8; 32] = [
    0xba, 0xc6, 0x8a, 0x9f, 0xba, 0xef, 0xea, 0x12, 0x28, 0x27, 0x9a, 0x36, 0x65, 0xbe, 0xeb, 0x9f,
    0x08, 0x2a, 0x52, 0x0b, 0x98, 0x86, 0xb9, 0x4c, 0x2d, 0x97, 0x13, 0x42, 0x81, 0x22, 0xb8, 0xdb,
];

pub fn profile_id() -> &'static str {
    PROFILE_ID
}

pub fn profile_hash_hex() -> String {
    hex::encode(PROFILE_HASH)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{PROFILE_HASH, PROFILE_MANIFEST};

    #[test]
    fn profile_hash_matches_published_manifest() {
        let digest: [u8; 32] = Sha256::digest(PROFILE_MANIFEST.as_bytes()).into();
        assert_eq!(digest, PROFILE_HASH);
    }
}
