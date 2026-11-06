use thiserror::Error;

/// Errors deliberately avoid including secret values or witness material.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("non-canonical wire encoding")]
    NonCanonicalEncoding,
    #[error("malformed elliptic-curve point")]
    MalformedPoint,
    #[error("identity point is not allowed here")]
    IdentityPoint,
    #[error("malformed scalar")]
    MalformedScalar,
    #[error("zero scalar is not allowed")]
    ZeroScalar,
    #[error("amount is outside the declared range")]
    AmountOutOfRange,
    #[error("invalid ciphertext relation")]
    InvalidCiphertext,
    #[error("invalid commitment relation")]
    InvalidCommitment,
    #[error("invalid key relation")]
    InvalidKey,
    #[error("proof relation is unsatisfied")]
    Unsatisfied,
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("proof profile or statement kind mismatch")]
    ProfileMismatch,
    #[error("context digest mismatch")]
    ContextMismatch,
    #[error("statement has too many canonical fields")]
    StatementTooLarge,
    #[error("invalid integer relation")]
    InvalidIntegerRelation,
    #[error("discrete-log recovery requires an authenticated recovery record")]
    RecoveryRequired,
    #[error("recovery record is not authenticated")]
    InvalidRecoveryAuthentication,
    #[error("recovery record does not match ciphertext")]
    RecoveryMismatch,
    #[error("recovery record amount is outside the declared range")]
    RecoveryOutOfRange,
    #[error("discrete-log recovery failed")]
    DiscreteLogFailed,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("invalid proof key material")]
    InvalidKeyMaterial,
    #[error("invalid proof encoding")]
    InvalidProofEncoding,
    #[error("proof system error: {0}")]
    ProofSystem(String),
    #[error("invalid operation context")]
    InvalidContext,
}
