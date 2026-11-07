use ark_std::io::Cursor;
use std::collections::BTreeMap;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bn254::{EdwardsConfig, constraints::FqVar};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_r1cs_std::{
    alloc::AllocationMode, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget,
    fields::fp::FpVar, groups::CurveVar, groups::curves::twisted_edwards::AffineVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;
use crate::context::{poseidon_config, transcript_hash};
use crate::elgamal::{Ciphertext, PublicKey};
use crate::encoding::{FieldHex, ScalarHex};
use crate::hash_to_curve::{encryption_base, pedersen_base};
use crate::statement::*;
use crate::{CONTEXT_SLOTS, CryptoError, MAX_AMOUNT, PROFILE_HASH, PROFILE_ID};

const DATA_START: usize = 46; // OperationContext::canonical_fields() + kind.
const MAX_PROOF_BYTES: usize = 256;

/// Development setup is deliberately distinct from an imported release key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetupMode {
    DevelopmentSingleParty,
    ImportedArtifact,
}

#[derive(Clone)]
pub struct ProvingArtifacts {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
    pub mode: SetupMode,
    pub artifact_hash: [u8; 32],
}

impl ProvingArtifacts {
    /// Serialize the proving key in arkworks' canonical compressed format.
    /// Release artifact distribution should hash and pin these bytes together
    /// with the matching verifying key before importing them.
    pub fn proving_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        canonical_bytes(&self.proving_key)
    }

    /// Serialize the verifying key in the exact compressed format consumed by
    /// the native and NEAR host verifiers.
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serialize_verifying_key(&self.verifying_key)
    }

    pub fn verifying_key_hash_hex(&self) -> String {
        hex::encode(self.artifact_hash)
    }

    /// Import a complete artifact pair. The key pair is checked before it can
    /// be used for proving, preventing a caller from mixing a proving key with
    /// an unrelated verifier key.
    pub fn from_bytes(
        proving_key_bytes: &[u8],
        verifying_key_bytes: &[u8],
        mode: SetupMode,
    ) -> Result<Self, CryptoError> {
        let proving_key: ProvingKey<Bn254> = deserialize_canonical(proving_key_bytes)?;
        let verifying_key = deserialize_verifying_key(verifying_key_bytes)?;
        if hash_vk(&proving_key.vk)? != hash_vk(&verifying_key)? {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        let artifact_hash = hash_vk(&verifying_key)?;
        Ok(Self {
            proving_key,
            verifying_key,
            mode,
            artifact_hash,
        })
    }

    pub fn from_proving_key_bytes(
        proving_key_bytes: &[u8],
        mode: SetupMode,
    ) -> Result<Self, CryptoError> {
        let proving_key: ProvingKey<Bn254> = deserialize_canonical(proving_key_bytes)?;
        let verifying_key = proving_key.vk.clone();
        let artifact_hash = hash_vk(&verifying_key)?;
        Ok(Self {
            proving_key,
            verifying_key,
            mode,
            artifact_hash,
        })
    }
}

#[derive(Clone, Default)]
pub struct ArtifactSet {
    pub profile_id: String,
    pub profile_hash: [u8; 32],
    pub artifacts: BTreeMap<StatementKind, ProvingArtifacts>,
}

impl ArtifactSet {
    pub fn empty() -> Self {
        Self {
            profile_id: PROFILE_ID.to_string(),
            profile_hash: PROFILE_HASH,
            artifacts: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        kind: StatementKind,
        artifacts: ProvingArtifacts,
    ) -> Result<(), CryptoError> {
        if artifacts.artifact_hash == [0; 32] {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        self.artifacts.insert(kind, artifacts);
        Ok(())
    }

    pub fn get(&self, kind: StatementKind) -> Result<&ProvingArtifacts, CryptoError> {
        if self.profile_id != PROFILE_ID || self.profile_hash != PROFILE_HASH {
            return Err(CryptoError::ProfileMismatch);
        }
        self.artifacts
            .get(&kind)
            .ok_or(CryptoError::InvalidKeyMaterial)
    }

    pub fn setup_kind<R: RngCore + CryptoRng>(
        kind: StatementKind,
        rng: &mut R,
    ) -> Result<(Self, SetupMode), CryptoError> {
        let circuit = LendingCircuit::blank(kind);
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
            .map_err(|e| CryptoError::ProofSystem(e.to_string()))?;
        let vk = pk.vk.clone();
        let artifact_hash = hash_vk(&vk)?;
        let mut set = Self::empty();
        set.insert(
            kind,
            ProvingArtifacts {
                proving_key: pk,
                verifying_key: vk,
                mode: SetupMode::DevelopmentSingleParty,
                artifact_hash,
            },
        )?;
        Ok((set, SetupMode::DevelopmentSingleParty))
    }

    pub fn setup_all<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut set = Self::empty();
        for kind in [
            StatementKind::KeyPossession,
            StatementKind::PublicConversion,
            StatementKind::ConfidentialTransfer,
            StatementKind::Origination,
            StatementKind::Repayment,
            StatementKind::Reconciliation,
            StatementKind::ZeroBalance,
            StatementKind::Ownership,
        ] {
            let one = Self::setup_kind(kind, rng)?.0;
            let artifact = one.artifacts.into_values().next().unwrap();
            set.insert(kind, artifact)?;
        }
        Ok(set)
    }

    pub fn is_development_only(&self) -> bool {
        self.artifacts
            .values()
            .any(|a| a.mode == SetupMode::DevelopmentSingleParty)
    }
}

/// The wire proof envelope includes the exact public input vector so a NEAR
/// adapter can pass it directly to the BN254 pairing host.  The vector is
/// independently recomputed from the typed statement during verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub profile_id: String,
    pub profile_hash: String,
    pub statement_kind: StatementKind,
    pub context_digest: FieldHex,
    pub public_inputs: Vec<FieldHex>,
    pub proof: String,
    pub verifying_key_hash: String,
}

impl ProofEnvelope {
    pub fn proof_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        decode_lower_hex(&self.proof, MAX_PROOF_BYTES)
    }

    pub fn public_input_fields(&self) -> Result<Vec<Fr>, CryptoError> {
        self.public_inputs
            .iter()
            .map(|field| FieldHex::parse(&field.0)?.to_field())
            .collect()
    }

    /// Return public inputs as canonical little-endian 32-byte BN254 field
    /// encodings for the NEAR verifier adapter.
    pub fn public_input_bytes(&self) -> Result<Vec<[u8; 32]>, CryptoError> {
        if self.public_inputs.len() < 2 || self.public_inputs.len() > CONTEXT_SLOTS + 1 {
            return Err(CryptoError::InvalidProofEncoding);
        }
        self.public_inputs
            .iter()
            .map(|field| {
                let canonical =
                    FieldHex::parse(&field.0).map_err(|_| CryptoError::InvalidProofEncoding)?;
                hex::decode(canonical.0)
                    .map_err(|_| CryptoError::InvalidProofEncoding)?
                    .try_into()
                    .map_err(|_| CryptoError::InvalidProofEncoding)
            })
            .collect()
    }

    pub fn context_digest_bytes(&self) -> Result<[u8; 32], CryptoError> {
        let canonical = FieldHex::parse(&self.context_digest.0)
            .map_err(|_| CryptoError::InvalidProofEncoding)?;
        hex::decode(canonical.0)
            .map_err(|_| CryptoError::InvalidProofEncoding)?
            .try_into()
            .map_err(|_| CryptoError::InvalidProofEncoding)
    }
}

/// Private witness enum.  It is not serializable by default; applications can
/// explicitly persist encrypted wallet witnesses if their custody policy calls
/// for it.
#[derive(Clone, Debug)]
pub enum Witness {
    KeyPossession(KeyPossessionWitness),
    PublicConversion(PublicConversionWitness),
    ConfidentialTransfer(ConfidentialTransferWitness),
    Origination(OriginationWitness),
    Repayment(RepaymentWitness),
    Reconciliation(ReconciliationWitness),
    Balance(BalanceAssertionWitness),
}

/// JSON-safe witness envelope used by the native CLI and browser bindings.
/// Secrets are represented only by the explicit canonical scalar wire field;
/// they are never included in `Debug` output or error strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WitnessWire {
    KeyPossession {
        secret_key: ScalarHex,
    },
    PublicConversion {
        owner_secret: ScalarHex,
        #[serde(with = "crate::encoding::decimal_u64")]
        private_balance: u64,
        delta_randomness: ScalarHex,
        randomness: [ScalarHex; LOAN_READER_COUNT],
    },
    ConfidentialTransfer {
        sender_secret: ScalarHex,
        #[serde(with = "crate::encoding::decimal_u64")]
        sender_balance: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        amount: u64,
        sender_delta_randomness: ScalarHex,
        transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
        transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
        commitment_blinding: ScalarHex,
    },
    Origination {
        broker_secret: ScalarHex,
        #[serde(with = "crate::encoding::decimal_u64")]
        broker_balance: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        principal: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        initial_owed: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        periodic_payment: u64,
        transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
        transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
        broker_delta_randomness: ScalarHex,
        principal_blinding: ScalarHex,
        owed_randomness: [ScalarHex; LOAN_READER_COUNT],
        owed_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
        payment_randomness: [ScalarHex; LOAN_READER_COUNT],
        payment_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
        owed_blinding: ScalarHex,
        payment_blinding: ScalarHex,
    },
    Repayment {
        borrower_secret: ScalarHex,
        #[serde(with = "crate::encoding::decimal_u64")]
        borrower_balance: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        payment: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        owed_before: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        periodic_payment: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        principal_before: u64,
        #[serde(with = "crate::encoding::decimal_u64")]
        principal_paid: u64,
        transfer_randomness: [ScalarHex; TRANSFER_VIEW_COUNT],
        transfer_recovery_randomness: [[ScalarHex; 2]; TRANSFER_VIEW_COUNT],
        borrower_delta_randomness: ScalarHex,
        owed_delta_randomness: [ScalarHex; LOAN_READER_COUNT],
        owed_delta_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
        principal_delta_randomness: [ScalarHex; LOAN_READER_COUNT],
        principal_delta_recovery_randomness: [[ScalarHex; 2]; LOAN_READER_COUNT],
        principal_paid_blinding: ScalarHex,
    },
    Reconciliation {
        broker_secret: ScalarHex,
        #[serde(with = "crate::encoding::decimal_u128")]
        cash: u128,
        #[serde(with = "crate::encoding::decimal_u128")]
        active_principal: u128,
        #[serde(with = "crate::encoding::decimal_u128")]
        impaired_principal: u128,
        cash_blinding: ScalarHex,
        active_principal_blinding: ScalarHex,
        impaired_principal_blinding: ScalarHex,
    },
    Balance {
        secret_key: ScalarHex,
    },
}

impl WitnessWire {
    pub fn into_witness(self) -> Result<Witness, CryptoError> {
        let secret = |wire: ScalarHex| crate::SecretKey::from_wire(&wire);
        Ok(match self {
            Self::KeyPossession { secret_key } => Witness::KeyPossession(KeyPossessionWitness {
                secret_key: secret(secret_key)?,
            }),
            Self::PublicConversion {
                owner_secret,
                private_balance,
                delta_randomness,
                randomness,
            } => Witness::PublicConversion(PublicConversionWitness {
                owner_secret: secret(owner_secret)?,
                private_balance,
                delta_randomness,
                randomness,
            }),
            Self::ConfidentialTransfer {
                sender_secret,
                sender_balance,
                amount,
                sender_delta_randomness,
                transfer_randomness,
                transfer_recovery_randomness,
                commitment_blinding,
            } => Witness::ConfidentialTransfer(ConfidentialTransferWitness {
                sender_secret: secret(sender_secret)?,
                sender_balance,
                amount,
                sender_delta_randomness,
                transfer_randomness,
                transfer_recovery_randomness,
                commitment_blinding,
            }),
            Self::Origination {
                broker_secret,
                broker_balance,
                principal,
                initial_owed,
                periodic_payment,
                transfer_randomness,
                transfer_recovery_randomness,
                broker_delta_randomness,
                principal_blinding,
                owed_randomness,
                owed_recovery_randomness,
                payment_randomness,
                payment_recovery_randomness,
                owed_blinding,
                payment_blinding,
            } => Witness::Origination(OriginationWitness {
                broker_secret: secret(broker_secret)?,
                broker_balance,
                principal,
                initial_owed,
                periodic_payment,
                transfer_randomness,
                transfer_recovery_randomness,
                broker_delta_randomness,
                principal_blinding,
                owed_randomness,
                owed_recovery_randomness,
                payment_randomness,
                payment_recovery_randomness,
                owed_blinding,
                payment_blinding,
            }),
            Self::Repayment {
                borrower_secret,
                borrower_balance,
                payment,
                owed_before,
                periodic_payment,
                principal_before,
                principal_paid,
                transfer_randomness,
                transfer_recovery_randomness,
                borrower_delta_randomness,
                owed_delta_randomness,
                owed_delta_recovery_randomness,
                principal_delta_randomness,
                principal_delta_recovery_randomness,
                principal_paid_blinding,
            } => Witness::Repayment(RepaymentWitness {
                borrower_secret: secret(borrower_secret)?,
                borrower_balance,
                payment,
                owed_before,
                periodic_payment,
                principal_before,
                principal_paid,
                transfer_randomness,
                transfer_recovery_randomness,
                borrower_delta_randomness,
                owed_delta_randomness,
                owed_delta_recovery_randomness,
                principal_delta_randomness,
                principal_delta_recovery_randomness,
                principal_paid_blinding,
            }),
            Self::Reconciliation {
                broker_secret,
                cash,
                active_principal,
                impaired_principal,
                cash_blinding,
                active_principal_blinding,
                impaired_principal_blinding,
            } => Witness::Reconciliation(ReconciliationWitness {
                broker_secret: secret(broker_secret)?,
                cash,
                active_principal,
                impaired_principal,
                cash_blinding,
                active_principal_blinding,
                impaired_principal_blinding,
            }),
            Self::Balance { secret_key } => Witness::Balance(BalanceAssertionWitness {
                secret_key: secret(secret_key)?,
            }),
        })
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    kind: StatementKind,
    rng: &mut R,
) -> Result<ArtifactSet, CryptoError> {
    Ok(ArtifactSet::setup_kind(kind, rng)?.0)
}

pub fn prove<R: RngCore + CryptoRng>(
    statement: &Statement,
    witness: &Witness,
    artifacts: &ArtifactSet,
    rng: &mut R,
) -> Result<ProofEnvelope, CryptoError> {
    if statement.kind() != witness_kind_for_statement(witness, statement.kind()) {
        return Err(CryptoError::ProfileMismatch);
    }
    let slots = statement.public_slots()?;
    validate_host_relation(statement, witness)?;
    let artifact = artifacts.get(statement.kind())?;
    let circuit =
        LendingCircuit::from_statement(statement.kind(), slots.values.clone(), witness.clone())?;
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &artifact.proving_key, rng)
            .map_err(|e| CryptoError::ProofSystem(e.to_string()))?;
    let mut proof_bytes = Vec::new();
    proof
        .serialize_with_mode(&mut proof_bytes, Compress::Yes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let public_inputs = slots
        .public_inputs()
        .into_iter()
        .map(FieldHex::from)
        .collect::<Vec<_>>();
    Ok(ProofEnvelope {
        profile_id: PROFILE_ID.to_string(),
        profile_hash: hex::encode(PROFILE_HASH),
        statement_kind: statement.kind(),
        context_digest: slots.digest_wire(),
        public_inputs,
        proof: hex::encode(proof_bytes),
        verifying_key_hash: hex::encode(artifact.artifact_hash),
    })
}

pub fn verify(
    statement: &Statement,
    envelope: &ProofEnvelope,
    artifacts: &ArtifactSet,
) -> Result<(), CryptoError> {
    if envelope.profile_id != PROFILE_ID
        || envelope.profile_hash != hex::encode(PROFILE_HASH)
        || envelope.statement_kind != statement.kind()
    {
        return Err(CryptoError::ProfileMismatch);
    }
    let slots = statement.public_slots()?;
    if envelope.context_digest != slots.digest_wire() {
        return Err(CryptoError::ContextMismatch);
    }
    let expected_inputs = slots
        .public_inputs()
        .into_iter()
        .map(FieldHex::from)
        .collect::<Vec<_>>();
    if envelope.public_inputs != expected_inputs {
        return Err(CryptoError::ContextMismatch);
    }
    let artifact = artifacts.get(statement.kind())?;
    verify_with_verifying_key_and_slots(envelope, &artifact.verifying_key, &slots)
}

/// Verify an envelope with a canonical compressed verifying key. This is the
/// native counterpart of the NEAR adapter: the contract can pass the same VK,
/// proof bytes, and `ProofEnvelope::public_input_bytes()` to its host verifier.
pub fn verify_with_vk_bytes(
    statement: &Statement,
    envelope: &ProofEnvelope,
    verifying_key_bytes: &[u8],
) -> Result<(), CryptoError> {
    let verifying_key = deserialize_verifying_key(verifying_key_bytes)?;
    let slots = statement.public_slots()?;
    verify_with_verifying_key_and_slots(envelope, &verifying_key, &slots)
}

fn verify_with_verifying_key_and_slots(
    envelope: &ProofEnvelope,
    verifying_key: &VerifyingKey<Bn254>,
    slots: &crate::context::PublicSlots,
) -> Result<(), CryptoError> {
    let artifact_hash = hash_vk(verifying_key)?;
    if envelope.verifying_key_hash != hex::encode(artifact_hash) {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let proof_bytes = envelope.proof_bytes()?;
    let mut cursor = Cursor::new(proof_bytes.as_slice());
    let proof = Proof::<Bn254>::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::Yes)
        .map_err(|_| CryptoError::InvalidProofEncoding)?;
    if cursor.position() != proof_bytes.len() as u64 {
        return Err(CryptoError::InvalidProofEncoding);
    }
    let pvk = prepare_verifying_key(verifying_key);
    let inputs = slots.public_inputs();
    let accepted = Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs)
        .map_err(|e| CryptoError::ProofSystem(e.to_string()))?;
    if accepted {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

fn witness_kind(witness: &Witness) -> StatementKind {
    match witness {
        Witness::KeyPossession(_) => StatementKind::KeyPossession,
        Witness::PublicConversion(_) => StatementKind::PublicConversion,
        Witness::ConfidentialTransfer(_) => StatementKind::ConfidentialTransfer,
        Witness::Origination(_) => StatementKind::Origination,
        Witness::Repayment(_) => StatementKind::Repayment,
        Witness::Reconciliation(_) => StatementKind::Reconciliation,
        Witness::Balance(_) => StatementKind::ZeroBalance,
    }
}

fn witness_kind_for_statement(witness: &Witness, kind: StatementKind) -> StatementKind {
    match (witness, kind) {
        (Witness::Balance(_), StatementKind::ZeroBalance | StatementKind::Ownership) => kind,
        _ => witness_kind(witness),
    }
}

fn hash_vk(vk: &VerifyingKey<Bn254>) -> Result<[u8; 32], CryptoError> {
    let bytes = serialize_verifying_key(vk)?;
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(bytes).into())
}

pub fn serialize_verifying_key(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, CryptoError> {
    canonical_bytes(vk)
}

fn canonical_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    value
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(bytes)
}

fn deserialize_canonical<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, CryptoError> {
    let mut cursor = Cursor::new(bytes);
    let value = T::deserialize_with_mode(&mut cursor, Compress::Yes, Validate::Yes)
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(value)
}

fn deserialize_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, CryptoError> {
    // Keep this limit aligned with the contract's artifact upload bound.
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    deserialize_canonical(bytes)
}

fn decode_lower_hex(value: &str, max_bytes: usize) -> Result<Vec<u8>, CryptoError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() / 2 > max_bytes
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(CryptoError::InvalidProofEncoding);
    }
    hex::decode(value).map_err(|_| CryptoError::InvalidProofEncoding)
}

type PointVar = AffineVar<EdwardsConfig, FqVar>;

#[derive(Clone)]
struct LendingCircuit {
    kind: StatementKind,
    slots: Vec<Fr>,
    witness: Witness,
}

impl LendingCircuit {
    fn blank(kind: StatementKind) -> Self {
        let base = encryption_base().into_affine();
        let mut slots = vec![Fr::from(0u64); kind.slot_count()];
        // Setup synthesizes arithmetic using valid public points.  This avoids
        // exceptional affine denominators while preserving the exact circuit
        // shape used by real statements.
        for pair in slots.chunks_exact_mut(2) {
            pair[0] = base.x;
            pair[1] = base.y;
        }
        let zero = ScalarHex::from(ark_ed_on_bn254::Fr::zero());
        let secret = crate::SecretKey::from_scalar(ark_ed_on_bn254::Fr::from(1u64)).unwrap();
        let key = KeyPossessionWitness {
            secret_key: secret.clone(),
        };
        let witness = match kind {
            StatementKind::KeyPossession => Witness::KeyPossession(key),
            StatementKind::PublicConversion => Witness::PublicConversion(PublicConversionWitness {
                owner_secret: secret.clone(),
                private_balance: 0,
                delta_randomness: zero.clone(),
                randomness: std::array::from_fn(|_| zero.clone()),
            }),
            StatementKind::ConfidentialTransfer => {
                Witness::ConfidentialTransfer(ConfidentialTransferWitness {
                    sender_secret: secret.clone(),
                    sender_balance: 0,
                    amount: 0,
                    sender_delta_randomness: zero.clone(),
                    transfer_randomness: std::array::from_fn(|_| zero.clone()),
                    transfer_recovery_randomness: std::array::from_fn(|_| {
                        std::array::from_fn(|_| zero.clone())
                    }),
                    commitment_blinding: zero.clone(),
                })
            }
            StatementKind::Origination => Witness::Origination(OriginationWitness {
                broker_secret: secret.clone(),
                broker_balance: 0,
                principal: 0,
                initial_owed: 0,
                periodic_payment: 0,
                transfer_randomness: std::array::from_fn(|_| zero.clone()),
                transfer_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                broker_delta_randomness: zero.clone(),
                principal_blinding: zero.clone(),
                owed_randomness: std::array::from_fn(|_| zero.clone()),
                owed_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                payment_randomness: std::array::from_fn(|_| zero.clone()),
                payment_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                owed_blinding: zero.clone(),
                payment_blinding: zero.clone(),
            }),
            StatementKind::Repayment => Witness::Repayment(RepaymentWitness {
                borrower_secret: secret.clone(),
                borrower_balance: 0,
                payment: 0,
                owed_before: 0,
                periodic_payment: 0,
                principal_before: 0,
                principal_paid: 0,
                transfer_randomness: std::array::from_fn(|_| zero.clone()),
                transfer_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                borrower_delta_randomness: zero.clone(),
                owed_delta_randomness: std::array::from_fn(|_| zero.clone()),
                owed_delta_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                principal_delta_randomness: std::array::from_fn(|_| zero.clone()),
                principal_delta_recovery_randomness: std::array::from_fn(|_| {
                    std::array::from_fn(|_| zero.clone())
                }),
                principal_paid_blinding: zero.clone(),
            }),
            StatementKind::Reconciliation => Witness::Reconciliation(ReconciliationWitness {
                broker_secret: secret.clone(),
                cash: 0,
                active_principal: 0,
                impaired_principal: 0,
                cash_blinding: zero.clone(),
                active_principal_blinding: zero.clone(),
                impaired_principal_blinding: zero.clone(),
            }),
            StatementKind::ZeroBalance | StatementKind::Ownership => {
                Witness::Balance(BalanceAssertionWitness { secret_key: secret })
            }
        };
        Self {
            kind,
            slots,
            witness,
        }
    }

    fn from_statement(
        kind: StatementKind,
        slots: Vec<Fr>,
        witness: Witness,
    ) -> Result<Self, CryptoError> {
        if slots.len() != kind.slot_count() || slots.len() > CONTEXT_SLOTS {
            return Err(CryptoError::StatementTooLarge);
        }
        Ok(Self {
            kind,
            slots,
            witness,
        })
    }
}

impl ConstraintSynthesizer<Fr> for LendingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let digest = FpVar::<Fr>::new_input(ark_relations::ns!(cs, "transcript_digest"), || {
            Ok(self.transcript())
        })?;
        let slots = (0..self.slots.len())
            .map(|i| FpVar::<Fr>::new_input(ark_relations::ns!(cs, "slot"), || Ok(self.slots[i])))
            .collect::<Result<Vec<_>, _>>()?;
        // Poseidon is evaluated inside the circuit with the same pinned
        // arkworks configuration used by `context::transcript_hash`. This is
        // the binding constraint for every canonical slot; no private shadow
        // or caller-selected digest is accepted.
        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), poseidon_config());
        let mut transcript_inputs = Vec::with_capacity(self.slots.len() + 2);
        transcript_inputs.push(FpVar::constant(Fr::from_le_bytes_mod_order(
            b"NEAR-CONFIDENTIAL-LENDING/TRANSCRIPT/POSEIDON/v1",
        )));
        transcript_inputs.push(FpVar::constant(Fr::from(self.slots.len() as u64)));
        transcript_inputs.extend(slots.iter().cloned());
        sponge.absorb(&transcript_inputs)?;
        let computed_digest = sponge.squeeze_field_elements(1)?[0].clone();
        computed_digest.enforce_equal(&digest)?;
        let mut cursor = SlotCursor::new();
        match (self.kind, self.witness) {
            (StatementKind::KeyPossession, Witness::KeyPossession(w)) => {
                let pk = cursor.key(&slots)?;
                let sk = scalar_witness(&cs, ed_to_circuit(w.secret_key.scalar()))?;
                enforce_key_possession(&pk, sk)?;
            }
            (StatementKind::PublicConversion, Witness::PublicConversion(w)) => {
                let owner_key = cursor.key(&slots)?;
                let spending_before = cursor.cipher(&slots)?;
                let spending_after = cursor.cipher(&slots)?;
                let views = (0..LOAN_READER_COUNT)
                    .map(|_| cursor.view(&slots))
                    .collect::<Result<Vec<_>, _>>()?;
                let amount = cursor.u64(&slots);
                let mode = cursor.u64(&slots);
                let _version = cursor.u64(&slots);
                enforce_range(&amount, 63)?;
                enforce_nonzero(&amount, 63)?;
                enforce_range(&mode, 1)?;
                let owner_secret = scalar_witness(&cs, ed_to_circuit(w.owner_secret.scalar()))?;
                enforce_key_possession(&owner_key, owner_secret.clone())?;
                let private_balance = amount_witness(&cs, w.private_balance)?;
                enforce_decrypt(
                    &owner_key,
                    &spending_before,
                    &owner_secret,
                    &private_balance,
                    63,
                )?;
                let mode_bit = mode.to_bits_le()?[0].clone();
                enforce_le(&amount, &private_balance, 63)?
                    .conditional_enforce_equal(&Boolean::TRUE, &mode_bit)?;
                let credit_total = private_balance.clone() + amount.clone();
                enforce_le(&credit_total, &FpVar::constant(Fr::from(MAX_AMOUNT)), 63)?
                    .conditional_enforce_equal(&Boolean::TRUE, &(!&mode_bit))?;
                let delta = scalar_witness_hex(&cs, &w.delta_randomness)?;
                let base = PointVar::constant(encryption_base());
                let delta_point = point_scalar_mul(&base, &delta, 254)?;
                let amount_point = point_scalar_mul(&base, &amount, 63)?;
                let key_delta = point_scalar_mul(&owner_key, &delta, 254)?;
                let credit_mode = !&mode_bit;
                // Credit (shield/draw) adds the public amount; debit
                // (unshield/settlement) subtracts it after the solvency check.
                (spending_before.0.clone() + delta_point.clone())
                    .conditional_enforce_equal(&spending_after.0, &credit_mode)?;
                (spending_before.1.clone() + amount_point.clone() + key_delta.clone())
                    .conditional_enforce_equal(&spending_after.1, &credit_mode)?;
                (spending_after.0.clone() + delta_point)
                    .conditional_enforce_equal(&spending_before.0, &mode_bit)?;
                (spending_after.1.clone() + amount_point + key_delta)
                    .conditional_enforce_equal(&spending_before.1, &mode_bit)?;
                for (view, randomness) in views.iter().zip(w.randomness.iter()) {
                    enforce_encryption(
                        &view.0,
                        &view.1,
                        &amount,
                        &scalar_witness_hex(&cs, randomness)?,
                        63,
                    )?;
                }
            }
            (StatementKind::ConfidentialTransfer, Witness::ConfidentialTransfer(w)) => {
                synth_transfer(&cs, &slots, &mut cursor, w)?;
            }
            (StatementKind::Origination, Witness::Origination(w)) => {
                synth_origination(&cs, &slots, &mut cursor, w)?;
            }
            (StatementKind::Repayment, Witness::Repayment(w)) => {
                synth_repayment(&cs, &slots, &mut cursor, w)?;
            }
            (StatementKind::Reconciliation, Witness::Reconciliation(w)) => {
                synth_reconciliation(&cs, &slots, &mut cursor, w)?;
            }
            (StatementKind::ZeroBalance, Witness::Balance(w))
            | (StatementKind::Ownership, Witness::Balance(w)) => {
                let pk = cursor.key(&slots)?;
                let ciphertext = cursor.cipher(&slots)?;
                let amount = cursor.u64(&slots);
                let sk = scalar_witness(&cs, ed_to_circuit(w.secret_key.scalar()))?;
                enforce_key_possession(&pk, sk.clone())?;
                enforce_decrypt(&pk, &ciphertext, &sk, &amount, 63)?;
                if self.kind == StatementKind::ZeroBalance {
                    amount.enforce_equal(&FpVar::zero())?;
                }
            }
            _ => return Err(SynthesisError::Unsatisfiable),
        }
        Ok(())
    }
}

impl LendingCircuit {
    fn transcript(&self) -> Fr {
        // The digest public input is also supplied by the host.  Its witness
        // value is recomputed here only to make setup deterministic; the
        // equality to the in-circuit sponge is what matters for proving.
        transcript_hash(&self.slots)
    }
}

type RecoveryPairVar = ((PointVar, PointVar), (PointVar, PointVar));

#[derive(Clone)]
struct SlotCursor {
    pos: usize,
}

impl SlotCursor {
    fn new() -> Self {
        Self { pos: DATA_START }
    }

    fn next(&mut self) -> usize {
        let pos = self.pos;
        self.pos += 1;
        pos
    }

    fn field(&mut self, slots: &[FpVar<Fr>]) -> FpVar<Fr> {
        slots[self.next()].clone()
    }

    fn u64(&mut self, slots: &[FpVar<Fr>]) -> FpVar<Fr> {
        self.field(slots)
    }

    fn u128(&mut self, slots: &[FpVar<Fr>]) -> FpVar<Fr> {
        let low = self.field(slots);
        let high = self.field(slots);
        let two_64 = Fr::from(2u64).pow([64]);
        &low + &(high * two_64)
    }

    fn point(&mut self, slots: &[FpVar<Fr>]) -> Result<PointVar, SynthesisError> {
        let x = self.field(slots);
        let y = self.field(slots);
        let point = PointVar::new(x, y);
        enforce_on_curve(&point)?;
        // Allocate a private cofactor preimage and constrain [8]Q = P. This
        // proves prime-subgroup membership inside Groth16 while letting the
        // contract parser avoid repeating the expensive full-[r] check for
        // every distinct ciphertext coordinate.
        let mut preimage = PointVar::new_variable_omit_on_curve_check(
            point.x.cs(),
            || {
                Ok(ark_ed_on_bn254::EdwardsProjective::from(
                    point.value()?.into_affine().mul_by_cofactor_inv(),
                ))
            },
            AllocationMode::Witness,
        )?;
        enforce_on_curve(&preimage)?;
        for _ in 0..3 {
            preimage.double_in_place()?;
        }
        preimage.enforce_equal(&point)?;
        Ok(point)
    }

    fn key(&mut self, slots: &[FpVar<Fr>]) -> Result<PointVar, SynthesisError> {
        self.point(slots)
    }

    fn cipher(&mut self, slots: &[FpVar<Fr>]) -> Result<(PointVar, PointVar), SynthesisError> {
        Ok((self.point(slots)?, self.point(slots)?))
    }

    fn recovery(&mut self, slots: &[FpVar<Fr>]) -> Result<RecoveryPairVar, SynthesisError> {
        Ok((self.cipher(slots)?, self.cipher(slots)?))
    }

    fn commit(&mut self, slots: &[FpVar<Fr>]) -> Result<PointVar, SynthesisError> {
        self.point(slots)
    }

    fn view(
        &mut self,
        slots: &[FpVar<Fr>],
    ) -> Result<(PointVar, (PointVar, PointVar)), SynthesisError> {
        Ok((self.key(slots)?, self.cipher(slots)?))
    }
}

fn enforce_on_curve(point: &PointVar) -> Result<(), SynthesisError> {
    let x2 = point.x.square()?;
    let y2 = point.y.square()?;
    let lhs = x2.clone() + y2.clone();
    let rhs = FpVar::constant(Fr::ONE) + x2 * y2 * EdwardsConfig::COEFF_D;
    lhs.enforce_equal(&rhs)
}

fn scalar_witness(cs: &ConstraintSystemRef<Fr>, scalar: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    let value = FpVar::new_witness(ark_relations::ns!(cs, "scalar"), || Ok(scalar))?;
    enforce_range(&value, 254)?;
    Ok(value)
}

fn scalar_witness_hex(
    cs: &ConstraintSystemRef<Fr>,
    scalar: &ScalarHex,
) -> Result<FpVar<Fr>, SynthesisError> {
    let value = scalar
        .to_scalar()
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    scalar_witness(cs, ed_to_circuit(value))
}

fn ed_to_circuit(value: ark_ed_on_bn254::Fr) -> Fr {
    Fr::from_le_bytes_mod_order(&value.into_bigint().to_bytes_le())
}

fn amount_witness(cs: &ConstraintSystemRef<Fr>, amount: u64) -> Result<FpVar<Fr>, SynthesisError> {
    let value = FpVar::new_witness(ark_relations::ns!(cs, "amount"), || Ok(Fr::from(amount)))?;
    enforce_range(&value, 63)?;
    Ok(value)
}

fn u128_witness(cs: &ConstraintSystemRef<Fr>, amount: u128) -> Result<FpVar<Fr>, SynthesisError> {
    let value = FpVar::new_witness(ark_relations::ns!(cs, "u128"), || {
        Ok(Fr::from_le_bytes_mod_order(&amount.to_le_bytes()))
    })?;
    enforce_range(&value, 128)?;
    Ok(value)
}

fn enforce_range(value: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let value_bits = value.to_bits_le()?;
    if value_bits.len() > bits {
        for bit in &value_bits[bits..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
    }
    Ok(())
}

fn point_scalar_mul(
    base: &PointVar,
    scalar: &FpVar<Fr>,
    bits: usize,
) -> Result<PointVar, SynthesisError> {
    let scalar_bits = scalar.to_bits_le()?;
    base.scalar_mul_le(scalar_bits.iter().take(bits))
        .map_err(|_| SynthesisError::Unsatisfiable)
}

fn enforce_key_possession(pk: &PointVar, secret: FpVar<Fr>) -> Result<(), SynthesisError> {
    enforce_range(&secret, 254)?;
    let base = PointVar::constant(encryption_base());
    let expected = point_scalar_mul(&base, &secret, 254)?;
    expected.enforce_equal(pk)
}

fn enforce_encryption(
    pk: &PointVar,
    ciphertext: &(PointVar, PointVar),
    amount: &FpVar<Fr>,
    randomness: &FpVar<Fr>,
    amount_bits: usize,
) -> Result<(), SynthesisError> {
    enforce_range(amount, amount_bits)?;
    enforce_range(randomness, 254)?;
    let base = PointVar::constant(encryption_base());
    let ephemeral = point_scalar_mul(&base, randomness, 254)?;
    ephemeral.enforce_equal(&ciphertext.0)?;
    let amount_point = point_scalar_mul(&base, amount, amount_bits)?;
    let random_point = point_scalar_mul(pk, randomness, 254)?;
    let message = amount_point + random_point;
    message.enforce_equal(&ciphertext.1)
}

fn amount_limb(
    amount: &FpVar<Fr>,
    start: usize,
    width: usize,
) -> Result<FpVar<Fr>, SynthesisError> {
    let bits = amount.to_bits_le()?;
    let mut result = FpVar::zero();
    for offset in 0..width {
        let bit = bits
            .get(start + offset)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let selected = bit.select(&FpVar::constant(Fr::ONE), &FpVar::zero())?;
        result += selected * Fr::from(1u64 << offset);
    }
    Ok(result)
}

fn enforce_recovery_pair(
    key: &PointVar,
    pair: &((PointVar, PointVar), (PointVar, PointVar)),
    amount: &FpVar<Fr>,
    low_randomness: &FpVar<Fr>,
    high_randomness: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let low = amount_limb(amount, 0, 32)?;
    let high = amount_limb(amount, 32, 32)?;
    enforce_encryption(key, &pair.0, &low, low_randomness, 32)?;
    enforce_encryption(key, &pair.1, &high, high_randomness, 32)
}

fn enforce_decrypt(
    _pk: &PointVar,
    ciphertext: &(PointVar, PointVar),
    secret: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    amount_bits: usize,
) -> Result<(), SynthesisError> {
    let base = PointVar::constant(encryption_base());
    let shared = point_scalar_mul(&ciphertext.0, secret, 254)?;
    let recovered = ciphertext.1.clone() - shared;
    let expected = point_scalar_mul(&base, amount, amount_bits)?;
    recovered.enforce_equal(&expected)
}

fn enforce_ciphertext_delta(
    before: &(PointVar, PointVar),
    after: &(PointVar, PointVar),
    delta: &(PointVar, PointVar),
) -> Result<(), SynthesisError> {
    (after.0.clone() + delta.0.clone()).enforce_equal(&before.0)?;
    (after.1.clone() + delta.1.clone()).enforce_equal(&before.1)
}

fn enforce_commitment(
    commitment: &PointVar,
    amount: &FpVar<Fr>,
    blind: &FpVar<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    enforce_range(amount, bits)?;
    enforce_range(blind, 254)?;
    enforce_nonzero(blind, 254)?;
    let base = PointVar::constant(encryption_base());
    let h = PointVar::constant(pedersen_base());
    let expected = point_scalar_mul(&base, amount, bits)? + point_scalar_mul(&h, blind, 254)?;
    expected.enforce_equal(commitment)
}

fn enforce_transfer_delta(
    before: &(PointVar, PointVar),
    after: &(PointVar, PointVar),
    key: &PointVar,
    amount: &FpVar<Fr>,
    delta: &FpVar<Fr>,
    credit: bool,
) -> Result<(), SynthesisError> {
    let base = PointVar::constant(encryption_base());
    let delta_point = point_scalar_mul(&base, delta, 254)?;
    let amount_point = point_scalar_mul(&base, amount, 63)?;
    let key_delta = point_scalar_mul(key, delta, 254)?;
    if credit {
        (before.0.clone() + delta_point.clone()).enforce_equal(&after.0)?;
        (before.1.clone() + amount_point + key_delta).enforce_equal(&after.1)
    } else {
        (after.0.clone() + delta_point.clone()).enforce_equal(&before.0)?;
        (after.1.clone() + amount_point + key_delta).enforce_equal(&before.1)
    }
}

fn synth_transfer(
    cs: &ConstraintSystemRef<Fr>,
    slots: &[FpVar<Fr>],
    cursor: &mut SlotCursor,
    witness: ConfidentialTransferWitness,
) -> Result<(), SynthesisError> {
    let sender_key = cursor.key(slots)?;
    let recipient_key = cursor.key(slots)?;
    let sender_before = cursor.cipher(slots)?;
    let sender_after = cursor.cipher(slots)?;
    let mut views = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        views.push(cursor.view(slots)?);
    }
    let mut recovery = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        recovery.push(cursor.recovery(slots)?);
    }
    let commitment = cursor.commit(slots)?;
    let _sender_version = cursor.u64(slots);
    let sender_secret = scalar_witness(cs, ed_to_circuit(witness.sender_secret.scalar()))?;
    enforce_key_possession(&sender_key, sender_secret.clone())?;
    let sender_balance = amount_witness(cs, witness.sender_balance)?;
    enforce_decrypt(
        &sender_key,
        &sender_before,
        &sender_secret,
        &sender_balance,
        63,
    )?;
    let amount = amount_witness(cs, witness.amount)?;
    enforce_nonzero(&amount, 63)?;
    enforce_le(&amount, &sender_balance, 63)?.enforce_equal(&Boolean::TRUE)?;
    let sender_delta = scalar_witness_hex(cs, &witness.sender_delta_randomness)?;
    enforce_transfer_delta(
        &sender_before,
        &sender_after,
        &sender_key,
        &amount,
        &sender_delta,
        false,
    )?;
    // Reader slot one is the destination key.  The destination inbox is
    // intentionally absent: Core homomorphically credits its current inbox.
    views[1].0.enforce_equal(&recipient_key)?;
    for (view, randomness) in views.iter().zip(witness.transfer_randomness.iter()) {
        let randomness = scalar_witness_hex(cs, randomness)?;
        enforce_encryption(&view.0, &view.1, &amount, &randomness, 63)?;
    }
    for ((view, pair), randomness) in views
        .iter()
        .zip(recovery.iter())
        .zip(witness.transfer_recovery_randomness.iter())
    {
        let low_randomness = scalar_witness_hex(cs, &randomness[0])?;
        let high_randomness = scalar_witness_hex(cs, &randomness[1])?;
        enforce_recovery_pair(&view.0, pair, &amount, &low_randomness, &high_randomness)?;
    }
    let blind = scalar_witness_hex(cs, &witness.commitment_blinding)?;
    enforce_commitment(&commitment, &amount, &blind, 63)
}

fn synth_origination(
    cs: &ConstraintSystemRef<Fr>,
    slots: &[FpVar<Fr>],
    cursor: &mut SlotCursor,
    witness: OriginationWitness,
) -> Result<(), SynthesisError> {
    let broker_key = cursor.key(slots)?;
    let borrower_key = cursor.key(slots)?;
    let broker_before = cursor.cipher(slots)?;
    let broker_after = cursor.cipher(slots)?;
    let mut transfer_views = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        transfer_views.push(cursor.view(slots)?);
    }
    let mut transfer_recovery = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        transfer_recovery.push(cursor.recovery(slots)?);
    }
    let principal_commitment = cursor.commit(slots)?;
    let mut owed_views = Vec::with_capacity(LOAN_READER_COUNT);
    let mut payment_views = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        owed_views.push(cursor.view(slots)?);
    }
    let mut owed_recovery = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        owed_recovery.push(cursor.recovery(slots)?);
    }
    for _ in 0..LOAN_READER_COUNT {
        payment_views.push(cursor.view(slots)?);
    }
    let mut payment_recovery = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        payment_recovery.push(cursor.recovery(slots)?);
    }
    let owed_commitment = cursor.commit(slots)?;
    let payment_commitment = cursor.commit(slots)?;
    let payment_count = cursor.u64(slots);
    let max_payment_count = cursor.u64(slots);
    let _broker_version = cursor.u64(slots);
    let _loan_version = cursor.u64(slots);
    let principal = amount_witness(cs, witness.principal)?;
    let broker_secret = scalar_witness(cs, ed_to_circuit(witness.broker_secret.scalar()))?;
    enforce_key_possession(&broker_key, broker_secret.clone())?;
    let broker_balance = amount_witness(cs, witness.broker_balance)?;
    enforce_decrypt(
        &broker_key,
        &broker_before,
        &broker_secret,
        &broker_balance,
        63,
    )?;
    enforce_le(&principal, &broker_balance, 63)?.enforce_equal(&Boolean::TRUE)?;
    let owed = amount_witness(cs, witness.initial_owed)?;
    let periodic = amount_witness(cs, witness.periodic_payment)?;
    enforce_nonzero(&principal, 63)?;
    enforce_nonzero(&owed, 63)?;
    enforce_nonzero(&periodic, 63)?;
    enforce_le(&principal, &owed, 63)?.enforce_equal(&Boolean::TRUE)?;
    enforce_le(&periodic, &owed, 63)?.enforce_equal(&Boolean::TRUE)?;
    enforce_range(&payment_count, 32)?;
    enforce_range(&max_payment_count, 32)?;
    enforce_nonzero(&payment_count, 32)?;
    enforce_le(&payment_count, &max_payment_count, 32)?.enforce_equal(&Boolean::TRUE)?;
    let total = &payment_count * &periodic;
    enforce_ge(&total, &owed, 126)?.enforce_equal(&Boolean::TRUE)?;
    let broker_delta = scalar_witness_hex(cs, &witness.broker_delta_randomness)?;
    enforce_transfer_delta(
        &broker_before,
        &broker_after,
        &broker_key,
        &principal,
        &broker_delta,
        false,
    )?;
    transfer_views[1].0.enforce_equal(&borrower_key)?;
    for (view, randomness) in transfer_views
        .iter()
        .zip(witness.transfer_randomness.iter())
    {
        enforce_encryption(
            &view.0,
            &view.1,
            &principal,
            &scalar_witness_hex(cs, randomness)?,
            63,
        )?;
    }
    for ((view, pair), randomness) in transfer_views
        .iter()
        .zip(transfer_recovery.iter())
        .zip(witness.transfer_recovery_randomness.iter())
    {
        enforce_recovery_pair(
            &view.0,
            pair,
            &principal,
            &scalar_witness_hex(cs, &randomness[0])?,
            &scalar_witness_hex(cs, &randomness[1])?,
        )?;
    }
    let principal_blinding = scalar_witness_hex(cs, &witness.principal_blinding)?;
    enforce_commitment(&principal_commitment, &principal, &principal_blinding, 63)?;
    for (view, randomness) in owed_views.iter().zip(witness.owed_randomness.iter()) {
        enforce_encryption(
            &view.0,
            &view.1,
            &owed,
            &scalar_witness_hex(cs, randomness)?,
            63,
        )?;
    }
    for ((view, pair), randomness) in owed_views
        .iter()
        .zip(owed_recovery.iter())
        .zip(witness.owed_recovery_randomness.iter())
    {
        enforce_recovery_pair(
            &view.0,
            pair,
            &owed,
            &scalar_witness_hex(cs, &randomness[0])?,
            &scalar_witness_hex(cs, &randomness[1])?,
        )?;
    }
    for (view, randomness) in payment_views.iter().zip(witness.payment_randomness.iter()) {
        enforce_encryption(
            &view.0,
            &view.1,
            &periodic,
            &scalar_witness_hex(cs, randomness)?,
            63,
        )?;
    }
    for ((view, pair), randomness) in payment_views
        .iter()
        .zip(payment_recovery.iter())
        .zip(witness.payment_recovery_randomness.iter())
    {
        enforce_recovery_pair(
            &view.0,
            pair,
            &periodic,
            &scalar_witness_hex(cs, &randomness[0])?,
            &scalar_witness_hex(cs, &randomness[1])?,
        )?;
    }
    let owed_blinding = scalar_witness_hex(cs, &witness.owed_blinding)?;
    let payment_blinding = scalar_witness_hex(cs, &witness.payment_blinding)?;
    enforce_commitment(&owed_commitment, &owed, &owed_blinding, 63)?;
    enforce_commitment(&payment_commitment, &periodic, &payment_blinding, 63)
}

fn synth_repayment(
    cs: &ConstraintSystemRef<Fr>,
    slots: &[FpVar<Fr>],
    cursor: &mut SlotCursor,
    witness: RepaymentWitness,
) -> Result<(), SynthesisError> {
    let borrower_key = cursor.key(slots)?;
    let broker_key = cursor.key(slots)?;
    let borrower_before = cursor.cipher(slots)?;
    let borrower_after = cursor.cipher(slots)?;
    let mut transfer_views = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        transfer_views.push(cursor.view(slots)?);
    }
    let mut transfer_recovery = Vec::with_capacity(TRANSFER_VIEW_COUNT);
    for _ in 0..TRANSFER_VIEW_COUNT {
        transfer_recovery.push(cursor.recovery(slots)?);
    }
    let mut owed_before = Vec::with_capacity(LOAN_READER_COUNT);
    let mut owed_after = Vec::with_capacity(LOAN_READER_COUNT);
    let mut owed_delta = Vec::with_capacity(LOAN_READER_COUNT);
    let mut periodic_views = Vec::with_capacity(LOAN_READER_COUNT);
    let mut principal_before = Vec::with_capacity(LOAN_READER_COUNT);
    let mut principal_after = Vec::with_capacity(LOAN_READER_COUNT);
    let mut principal_delta = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        owed_before.push(cursor.view(slots)?);
    }
    for _ in 0..LOAN_READER_COUNT {
        owed_after.push(cursor.view(slots)?);
    }
    let mut owed_delta_recovery = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        owed_delta.push(cursor.view(slots)?);
        owed_delta_recovery.push(cursor.recovery(slots)?);
    }
    for _ in 0..LOAN_READER_COUNT {
        periodic_views.push(cursor.view(slots)?);
    }
    for _ in 0..LOAN_READER_COUNT {
        principal_before.push(cursor.view(slots)?);
    }
    for _ in 0..LOAN_READER_COUNT {
        principal_after.push(cursor.view(slots)?);
    }
    let mut principal_delta_recovery = Vec::with_capacity(LOAN_READER_COUNT);
    for _ in 0..LOAN_READER_COUNT {
        principal_delta.push(cursor.view(slots)?);
        principal_delta_recovery.push(cursor.recovery(slots)?);
    }
    let principal_commitment = cursor.commit(slots)?;
    let mode = cursor.u64(slots);
    let remaining_before = cursor.u64(slots);
    let remaining_after = cursor.u64(slots);
    let _borrower_spending_version = cursor.u64(slots);
    let loan_version_before = cursor.u64(slots);
    let loan_version_after = cursor.u64(slots);
    enforce_range(&mode, 1)?;
    enforce_range(&remaining_before, 32)?;
    enforce_range(&remaining_after, 32)?;
    enforce_range(&loan_version_before, 64)?;
    enforce_range(&loan_version_after, 64)?;
    let payment = amount_witness(cs, witness.payment)?;
    let owed = amount_witness(cs, witness.owed_before)?;
    let periodic = amount_witness(cs, witness.periodic_payment)?;
    let principal = amount_witness(cs, witness.principal_before)?;
    let principal_paid = amount_witness(cs, witness.principal_paid)?;
    let borrower_secret = scalar_witness(cs, ed_to_circuit(witness.borrower_secret.scalar()))?;
    enforce_key_possession(&borrower_key, borrower_secret.clone())?;
    let borrower_balance = amount_witness(cs, witness.borrower_balance)?;
    enforce_decrypt(
        &borrower_key,
        &borrower_before,
        &borrower_secret,
        &borrower_balance,
        63,
    )?;
    enforce_le(&payment, &borrower_balance, 63)?.enforce_equal(&Boolean::TRUE)?;
    enforce_nonzero(&payment, 63)?;
    enforce_nonzero(&owed, 63)?;
    enforce_nonzero(&periodic, 63)?;
    enforce_le(&payment, &owed, 63)?.enforce_equal(&Boolean::TRUE)?;
    enforce_le(&principal_paid, &payment, 63)?.enforce_equal(&Boolean::TRUE)?;
    enforce_le(&principal_paid, &principal, 63)?.enforce_equal(&Boolean::TRUE)?;
    let mode_bit = mode.to_bits_le()?[0].clone();
    let owed_eq = payment.is_eq(&owed)?;
    owed_eq.conditional_enforce_equal(&Boolean::TRUE, &mode_bit)?;
    let regular = !&mode_bit;
    let payment_ge_q = enforce_le(&periodic, &payment, 63)?;
    payment_ge_q.conditional_enforce_equal(&Boolean::TRUE, &regular)?;
    let payment_lt_owed = enforce_lt(&payment, &owed, 63)?;
    payment_lt_owed.conditional_enforce_equal(&Boolean::TRUE, &regular)?;
    let rem_gt_one = enforce_ge_const(&remaining_before, 2, 32)?;
    rem_gt_one.conditional_enforce_equal(&Boolean::TRUE, &regular)?;
    remaining_after
        .is_eq(&FpVar::zero())?
        .conditional_enforce_equal(&Boolean::TRUE, &mode_bit)?;
    remaining_after
        .is_eq(&(remaining_before.clone() - Fr::ONE))?
        .conditional_enforce_equal(&Boolean::TRUE, &regular)?;
    owed.is_eq(&payment)?
        .conditional_enforce_equal(&Boolean::TRUE, &mode_bit)?;
    let new_owed = owed.clone() - payment.clone();
    enforce_range(&new_owed, 63)?;
    let version_expected = loan_version_before.clone() + Fr::ONE;
    version_expected.enforce_equal(&loan_version_after)?;
    let branch = Boolean::new_witness(ark_relations::ns!(cs, "principal_min_branch"), || {
        Ok(witness.payment <= witness.principal_before)
    })?;
    let x_le_r = enforce_le(&payment, &principal, 63)?;
    x_le_r.conditional_enforce_equal(&Boolean::TRUE, &branch)?;
    enforce_lt(&principal, &payment, 63)?.conditional_enforce_equal(&Boolean::TRUE, &(!&branch))?;
    let selected = branch.select(&payment, &principal)?;
    selected.enforce_equal(&principal_paid)?;
    let principal_after_value = principal.clone() - principal_paid.clone();
    enforce_range(&principal_after_value, 63)?;
    let base_delta = scalar_witness_hex(cs, &witness.borrower_delta_randomness)?;
    enforce_transfer_delta(
        &borrower_before,
        &borrower_after,
        &borrower_key,
        &payment,
        &base_delta,
        false,
    )?;
    transfer_views[1].0.enforce_equal(&broker_key)?;
    for (view, randomness) in transfer_views
        .iter()
        .zip(witness.transfer_randomness.iter())
    {
        enforce_encryption(
            &view.0,
            &view.1,
            &payment,
            &scalar_witness_hex(cs, randomness)?,
            63,
        )?;
    }
    for ((view, pair), randomness) in transfer_views
        .iter()
        .zip(transfer_recovery.iter())
        .zip(witness.transfer_recovery_randomness.iter())
    {
        enforce_recovery_pair(
            &view.0,
            pair,
            &payment,
            &scalar_witness_hex(cs, &randomness[0])?,
            &scalar_witness_hex(cs, &randomness[1])?,
        )?;
    }
    for i in 0..LOAN_READER_COUNT {
        let owed_delta_r = scalar_witness_hex(cs, &witness.owed_delta_randomness[i])?;
        let principal_delta_r = scalar_witness_hex(cs, &witness.principal_delta_randomness[i])?;
        enforce_ciphertext_delta(&owed_before[i].1, &owed_after[i].1, &owed_delta[i].1)?;
        enforce_encryption(
            &owed_delta[i].0,
            &owed_delta[i].1,
            &payment,
            &owed_delta_r,
            63,
        )?;
        enforce_recovery_pair(
            &owed_delta[i].0,
            &owed_delta_recovery[i],
            &payment,
            &scalar_witness_hex(cs, &witness.owed_delta_recovery_randomness[i][0])?,
            &scalar_witness_hex(cs, &witness.owed_delta_recovery_randomness[i][1])?,
        )?;
        enforce_ciphertext_delta(
            &principal_before[i].1,
            &principal_after[i].1,
            &principal_delta[i].1,
        )?;
        enforce_encryption(
            &principal_delta[i].0,
            &principal_delta[i].1,
            &principal_paid,
            &principal_delta_r,
            63,
        )?;
        enforce_recovery_pair(
            &principal_delta[i].0,
            &principal_delta_recovery[i],
            &principal_paid,
            &scalar_witness_hex(cs, &witness.principal_delta_recovery_randomness[i][0])?,
            &scalar_witness_hex(cs, &witness.principal_delta_recovery_randomness[i][1])?,
        )?;
    }
    // Reader index zero is fixed to the borrower key.  Its pre-state values
    // are opened with the borrower secret; the remaining reader ciphertexts
    // are carried by the inductive homomorphic delta relation above.
    owed_before[0].0.enforce_equal(&borrower_key)?;
    periodic_views[0].0.enforce_equal(&borrower_key)?;
    principal_before[0].0.enforce_equal(&borrower_key)?;
    enforce_decrypt(
        &borrower_key,
        &owed_before[0].1,
        &borrower_secret,
        &owed,
        63,
    )?;
    enforce_decrypt(
        &borrower_key,
        &periodic_views[0].1,
        &borrower_secret,
        &periodic,
        63,
    )?;
    enforce_decrypt(
        &borrower_key,
        &principal_before[0].1,
        &borrower_secret,
        &principal,
        63,
    )?;
    let paid_blind = scalar_witness_hex(cs, &witness.principal_paid_blinding)?;
    enforce_commitment(&principal_commitment, &principal_paid, &paid_blind, 63)
}

fn synth_reconciliation(
    cs: &ConstraintSystemRef<Fr>,
    slots: &[FpVar<Fr>],
    cursor: &mut SlotCursor,
    witness: ReconciliationWitness,
) -> Result<(), SynthesisError> {
    let broker_key = cursor.key(slots)?;
    let cash_cipher = cursor.cipher(slots)?;
    let active_cipher = cursor.cipher(slots)?;
    let impaired_cipher = cursor.cipher(slots)?;
    let cash_commitment = cursor.commit(slots)?;
    let active_commitment = cursor.commit(slots)?;
    let impaired_commitment = cursor.commit(slots)?;
    let debt_before = cursor.u128(slots);
    let debt_after = cursor.u128(slots);
    let vault_before = cursor.u128(slots);
    let vault_after = cursor.u128(slots);
    let vault_provision_before = cursor.u128(slots);
    let vault_provision_after = cursor.u128(slots);
    let provision_before = cursor.u128(slots);
    let provision_after = cursor.u128(slots);
    let loss = cursor.u128(slots);
    let _book_version = cursor.u64(slots);
    let _accounting_version = cursor.u64(slots);
    for value in [
        &debt_before,
        &debt_after,
        &vault_before,
        &vault_after,
        &vault_provision_before,
        &vault_provision_after,
        &provision_before,
        &provision_after,
        &loss,
    ] {
        enforce_range(value, 128)?;
    }
    let cash = u128_witness(cs, witness.cash)?;
    let active = u128_witness(cs, witness.active_principal)?;
    let impaired = u128_witness(cs, witness.impaired_principal)?;
    let broker_secret = scalar_witness(cs, ed_to_circuit(witness.broker_secret.scalar()))?;
    enforce_key_possession(&broker_key, broker_secret.clone())?;
    enforce_decrypt(&broker_key, &cash_cipher, &broker_secret, &cash, 128)?;
    enforce_decrypt(&broker_key, &active_cipher, &broker_secret, &active, 128)?;
    enforce_decrypt(
        &broker_key,
        &impaired_cipher,
        &broker_secret,
        &impaired,
        128,
    )?;
    let cash_blind = scalar_witness_hex(cs, &witness.cash_blinding)?;
    let active_blind = scalar_witness_hex(cs, &witness.active_principal_blinding)?;
    let impaired_blind = scalar_witness_hex(cs, &witness.impaired_principal_blinding)?;
    enforce_commitment(&cash_commitment, &cash, &cash_blind, 128)?;
    enforce_commitment(&active_commitment, &active, &active_blind, 128)?;
    enforce_commitment(&impaired_commitment, &impaired, &impaired_blind, 128)?;
    let impaired_le_active = enforce_le(&impaired, &active, 128)?;
    impaired_le_active.enforce_equal(&Boolean::TRUE)?;
    let sum = cash.clone() + active.clone();
    enforce_range(&sum, 128)?;
    let cash_active = cash.clone() + active.clone() - impaired.clone();
    enforce_range(&cash_active, 128)?;
    // L=max(D-(C+H+I),0), with a private branch bit and bounded operands.
    let sum_value = witness
        .cash
        .checked_add(witness.active_principal)
        .ok_or(SynthesisError::Unsatisfiable)?;
    let loss_branch = Boolean::new_witness(ark_relations::ns!(cs, "loss_branch"), || {
        let debt_before_value = field_to_u128(debt_before.value()?)?;
        Ok(debt_before_value > sum_value)
    })?;
    // Derive branch values from the public relation; the host rejects overflow
    // and the circuit enforces the selected equation and both range bounds.
    let d_gt_sum = enforce_lt(&sum, &debt_before, 128)?;
    let sum_ge_d = enforce_ge(&sum, &debt_before, 128)?;
    let loss_is_zero = loss.is_eq(&FpVar::zero())?;
    d_gt_sum.conditional_enforce_equal(&Boolean::TRUE, &loss_branch)?;
    sum_ge_d.conditional_enforce_equal(&Boolean::TRUE, &(!&loss_branch))?;
    loss_is_zero.conditional_enforce_equal(&Boolean::TRUE, &(!&loss_branch))?;
    loss.is_eq(&(&debt_before - &sum))?
        .conditional_enforce_equal(&Boolean::TRUE, &loss_branch)?;
    let expected_debt_after = debt_before.clone() - loss.clone();
    expected_debt_after.enforce_equal(&debt_after)?;
    let cash_active_value = witness
        .cash
        .checked_add(witness.active_principal)
        .and_then(|v| v.checked_sub(witness.impaired_principal))
        .ok_or(SynthesisError::Unsatisfiable)?;
    let provision_branch =
        Boolean::new_witness(ark_relations::ns!(cs, "provision_branch"), || {
            let debt_after_value = field_to_u128(debt_after.value()?)?;
            Ok(debt_after_value > cash_active_value)
        })?;
    let debt_after_gt_ca = enforce_lt(&cash_active, &debt_after, 128)?;
    let ca_ge_debt_after = enforce_ge(&cash_active, &debt_after, 128)?;
    debt_after_gt_ca.conditional_enforce_equal(&Boolean::TRUE, &provision_branch)?;
    ca_ge_debt_after.conditional_enforce_equal(&Boolean::TRUE, &(!&provision_branch))?;
    provision_after
        .is_eq(&(&debt_after - &cash_active))?
        .conditional_enforce_equal(&Boolean::TRUE, &provision_branch)?;
    provision_after
        .is_eq(&FpVar::zero())?
        .conditional_enforce_equal(&Boolean::TRUE, &(!&provision_branch))?;
    let u_bound = enforce_le(&provision_after, &impaired, 128)?;
    u_bound.enforce_equal(&Boolean::TRUE)?;
    let expected_vault_after = vault_before.clone() - loss.clone();
    expected_vault_after.enforce_equal(&vault_after)?;
    // The public provision update is U_new = U_old - old broker provision +
    // new broker provision.  Its range is checked above; underflow is rejected
    // by the host relation and by the 128-bit witness range in the circuit.
    let old_vault_provision = vault_provision_before.clone();
    let expected_vault_provision =
        old_vault_provision - provision_before.clone() + provision_after.clone();
    expected_vault_provision.enforce_equal(&vault_provision_after)
}

fn enforce_nonzero(value: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let value_bits = value.to_bits_le()?;
    let bounded = &value_bits[..value_bits.len().min(bits)];
    Boolean::kary_or(bounded)?.enforce_equal(&Boolean::TRUE)
}

fn enforce_le(a: &FpVar<Fr>, b: &FpVar<Fr>, bits: usize) -> Result<Boolean<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;
    let mut borrow = Boolean::FALSE;
    for i in 0..bits {
        let ai = a_bits.get(i).cloned().unwrap_or(Boolean::FALSE);
        let bi = b_bits.get(i).cloned().unwrap_or(Boolean::FALSE);
        let term1 = (!&bi) & &ai;
        let term2 = &borrow & !(&bi ^ &ai);
        borrow = term1 | term2;
    }
    Ok(!borrow)
}

fn enforce_ge(a: &FpVar<Fr>, b: &FpVar<Fr>, bits: usize) -> Result<Boolean<Fr>, SynthesisError> {
    enforce_le(b, a, bits)
}

fn enforce_lt(a: &FpVar<Fr>, b: &FpVar<Fr>, bits: usize) -> Result<Boolean<Fr>, SynthesisError> {
    let le = enforce_le(a, b, bits)?;
    let eq = a.is_eq(b)?;
    Ok(le & !eq)
}

fn enforce_ge_const(
    value: &FpVar<Fr>,
    constant: u64,
    bits: usize,
) -> Result<Boolean<Fr>, SynthesisError> {
    let c = FpVar::constant(Fr::from(constant));
    enforce_ge(value, &c, bits)
}

fn field_to_u128(value: Fr) -> Result<u128, SynthesisError> {
    let limbs = value.into_bigint().0;
    if limbs[2] != 0 || limbs[3] != 0 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok((limbs[0] as u128) | ((limbs[1] as u128) << 64))
}

fn validate_host_relation(statement: &Statement, witness: &Witness) -> Result<(), CryptoError> {
    statement.context().validate()?;
    match (statement, witness) {
        (Statement::KeyPossession(s), Witness::KeyPossession(w)) => {
            if !s.public_key.verify_possession(&w.secret_key) {
                return Err(CryptoError::InvalidKey);
            }
        }
        (Statement::PublicConversion(s), Witness::PublicConversion(w)) => {
            check_public_conversion(s, w)?;
        }
        (Statement::ConfidentialTransfer(s), Witness::ConfidentialTransfer(w)) => {
            check_transfer(s, w)?;
        }
        (Statement::Origination(s), Witness::Origination(w)) => {
            check_origination(s, w)?;
        }
        (Statement::Repayment(s), Witness::Repayment(w)) => {
            check_repayment(s, w)?;
        }
        (Statement::Reconciliation(s), Witness::Reconciliation(w)) => {
            check_reconciliation(s, w)?;
        }
        (Statement::ZeroBalance(s), Witness::Balance(w)) => {
            if s.expected_amount != 0 {
                return Err(CryptoError::InvalidIntegerRelation);
            }
            check_balance_assertion(s, w)?;
        }
        (Statement::Ownership(s), Witness::Balance(w)) => {
            if s.expected_amount == 0 {
                return Err(CryptoError::InvalidIntegerRelation);
            }
            check_balance_assertion(s, w)?;
        }
        _ => return Err(CryptoError::ProfileMismatch),
    }
    Ok(())
}

fn check_amount(amount: u64) -> Result<(), CryptoError> {
    if amount > MAX_AMOUNT {
        Err(CryptoError::AmountOutOfRange)
    } else {
        Ok(())
    }
}

fn check_public_conversion(
    s: &PublicConversionStatement,
    w: &PublicConversionWitness,
) -> Result<(), CryptoError> {
    check_amount(s.public_amount)?;
    if s.public_amount == 0 || !s.owner_key.verify_possession(&w.owner_secret) {
        return Err(if s.public_amount == 0 {
            CryptoError::AmountOutOfRange
        } else {
            CryptoError::InvalidKey
        });
    }
    check_decrypt(&s.spending_before, &w.owner_secret, w.private_balance)?;
    if matches!(s.mode, ConversionMode::Debit) && s.public_amount > w.private_balance {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    if matches!(s.mode, ConversionMode::Credit)
        && w.private_balance
            .checked_add(s.public_amount)
            .filter(|v| *v <= MAX_AMOUNT)
            .is_none()
    {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    check_delta(
        &s.spending_before,
        &s.spending_after,
        &s.owner_key,
        s.public_amount,
        &w.delta_randomness,
        matches!(s.mode, ConversionMode::Debit),
    )?;
    for (view, randomness) in s.views.iter().zip(w.randomness.iter()) {
        check_encryption(
            &view.reader_key,
            &view.ciphertext,
            s.public_amount,
            randomness,
        )?;
    }
    Ok(())
}

fn witness_scalar(value: &ScalarHex) -> Result<ark_ed_on_bn254::Fr, CryptoError> {
    value.to_scalar()
}

fn check_encryption(
    key: &PublicKey,
    ciphertext: &Ciphertext,
    amount: u64,
    randomness: &ScalarHex,
) -> Result<(), CryptoError> {
    let randomness = witness_scalar(randomness)?;
    if randomness.is_zero() {
        return Err(CryptoError::ZeroScalar);
    }
    let expected = Ciphertext::encrypt_with_randomness(key, amount, randomness)?;
    if expected != *ciphertext {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

fn check_recovery_pair(
    key: &PublicKey,
    pair: &RecoveryPair,
    amount: u64,
    randomness: &[ScalarHex; 2],
) -> Result<(), CryptoError> {
    check_amount(amount)?;
    check_encryption(
        key,
        &pair.low_limb,
        amount & u32::MAX as u64,
        &randomness[0],
    )?;
    check_encryption(key, &pair.high_limb, amount >> 32, &randomness[1])
}

fn check_decrypt(
    ciphertext: &Ciphertext,
    secret: &crate::SecretKey,
    amount: u64,
) -> Result<(), CryptoError> {
    check_amount(amount)?;
    let recovered = ciphertext.decrypt_point(secret)?;
    let expected = encryption_base() * ark_ed_on_bn254::Fr::from(amount);
    if recovered != expected {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

fn check_decrypt_u128(
    ciphertext: &Ciphertext,
    secret: &crate::SecretKey,
    amount: u128,
) -> Result<(), CryptoError> {
    let recovered = ciphertext.decrypt_point(secret)?;
    let expected =
        encryption_base() * ark_ed_on_bn254::Fr::from_le_bytes_mod_order(&amount.to_le_bytes());
    if recovered != expected {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

fn check_commitment_u64(
    commitment: &Commitment,
    amount: u64,
    blinding: &ScalarHex,
) -> Result<(), CryptoError> {
    if !commitment.verify(amount, witness_scalar(blinding)?)? {
        return Err(CryptoError::InvalidCommitment);
    }
    Ok(())
}

fn check_commitment_u128(
    commitment: &Commitment,
    amount: u128,
    blinding: &ScalarHex,
) -> Result<(), CryptoError> {
    if Commitment::commit_u128_with_blinding(amount, witness_scalar(blinding)?)? != *commitment {
        return Err(CryptoError::InvalidCommitment);
    }
    Ok(())
}

fn check_delta(
    before: &Ciphertext,
    after: &Ciphertext,
    key: &PublicKey,
    amount: u64,
    randomness: &ScalarHex,
    debit: bool,
) -> Result<(), CryptoError> {
    let d = witness_scalar(randomness)?;
    let (be, bm) = before.to_points()?;
    let (ae, am) = after.to_points()?;
    let base = encryption_base();
    let key_point = key.to_point()?;
    let delta_e = base * d;
    let delta_m = base * ark_ed_on_bn254::Fr::from(amount) + key_point * d;
    if debit {
        if ae + delta_e != be || am + delta_m != bm {
            return Err(CryptoError::InvalidCiphertext);
        }
    } else if be + delta_e != ae || bm + delta_m != am {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

fn check_ciphertext_delta(
    before: &Ciphertext,
    after: &Ciphertext,
    delta: &Ciphertext,
) -> Result<(), CryptoError> {
    let (be, bm) = before.to_points()?;
    let (ae, am) = after.to_points()?;
    let (de, dm) = delta.to_points()?;
    if ae + de != be || am + dm != bm {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

fn check_transfer(
    s: &ConfidentialTransferStatement,
    w: &ConfidentialTransferWitness,
) -> Result<(), CryptoError> {
    check_amount(w.amount)?;
    if w.amount == 0 {
        return Err(CryptoError::AmountOutOfRange);
    }
    if !s.sender_key.verify_possession(&w.sender_secret) {
        return Err(CryptoError::InvalidKey);
    }
    check_decrypt(
        &s.sender_spending_before,
        &w.sender_secret,
        w.sender_balance,
    )?;
    if w.amount > w.sender_balance {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    check_delta(
        &s.sender_spending_before,
        &s.sender_spending_after,
        &s.sender_key,
        w.amount,
        &w.sender_delta_randomness,
        true,
    )?;
    if s.transfer_views[1].reader_key != s.recipient_key {
        return Err(CryptoError::InvalidKey);
    }
    for (view, randomness) in s.transfer_views.iter().zip(w.transfer_randomness.iter()) {
        check_encryption(&view.reader_key, &view.ciphertext, w.amount, randomness)?;
    }
    for ((view, pair), randomness) in s
        .transfer_views
        .iter()
        .zip(s.transfer_recovery.iter())
        .zip(w.transfer_recovery_randomness.iter())
    {
        check_recovery_pair(&view.reader_key, pair, w.amount, randomness)?;
    }
    check_commitment_u64(&s.amount_commitment, w.amount, &w.commitment_blinding)
}

fn check_origination(s: &OriginationStatement, w: &OriginationWitness) -> Result<(), CryptoError> {
    check_amount(w.principal)?;
    check_amount(w.initial_owed)?;
    check_amount(w.periodic_payment)?;
    if w.principal == 0
        || w.initial_owed == 0
        || w.periodic_payment == 0
        || w.principal > w.initial_owed
        || w.periodic_payment > w.initial_owed
    {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    if s.payment_count == 0 || s.payment_count > s.max_payment_count || s.max_payment_count == 0 {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    let total = (s.payment_count as u128)
        .checked_mul(w.periodic_payment as u128)
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    if total < w.initial_owed as u128 {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    if !s.broker_key.verify_possession(&w.broker_secret) {
        return Err(CryptoError::InvalidKey);
    }
    check_decrypt(
        &s.broker_spending_before,
        &w.broker_secret,
        w.broker_balance,
    )?;
    if w.principal > w.broker_balance {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    check_delta(
        &s.broker_spending_before,
        &s.broker_spending_after,
        &s.broker_key,
        w.principal,
        &w.broker_delta_randomness,
        true,
    )?;
    if s.transfer_views[1].reader_key != s.borrower_key {
        return Err(CryptoError::InvalidKey);
    }
    for (view, randomness) in s.transfer_views.iter().zip(w.transfer_randomness.iter()) {
        check_encryption(&view.reader_key, &view.ciphertext, w.principal, randomness)?;
    }
    for ((view, pair), randomness) in s
        .transfer_views
        .iter()
        .zip(s.transfer_recovery.iter())
        .zip(w.transfer_recovery_randomness.iter())
    {
        check_recovery_pair(&view.reader_key, pair, w.principal, randomness)?;
    }
    check_commitment_u64(&s.principal_commitment, w.principal, &w.principal_blinding)?;
    for (view, randomness) in s.owed_views.iter().zip(w.owed_randomness.iter()) {
        check_encryption(
            &view.reader_key,
            &view.ciphertext,
            w.initial_owed,
            randomness,
        )?;
    }
    for ((view, pair), randomness) in s
        .owed_views
        .iter()
        .zip(s.owed_recovery.iter())
        .zip(w.owed_recovery_randomness.iter())
    {
        check_recovery_pair(&view.reader_key, pair, w.initial_owed, randomness)?;
    }
    for (view, randomness) in s.payment_views.iter().zip(w.payment_randomness.iter()) {
        check_encryption(
            &view.reader_key,
            &view.ciphertext,
            w.periodic_payment,
            randomness,
        )?;
    }
    for ((view, pair), randomness) in s
        .payment_views
        .iter()
        .zip(s.payment_recovery.iter())
        .zip(w.payment_recovery_randomness.iter())
    {
        check_recovery_pair(&view.reader_key, pair, w.periodic_payment, randomness)?;
    }
    check_commitment_u64(&s.owed_commitment, w.initial_owed, &w.owed_blinding)?;
    check_commitment_u64(
        &s.payment_commitment,
        w.periodic_payment,
        &w.payment_blinding,
    )
}

fn check_repayment(s: &RepaymentStatement, w: &RepaymentWitness) -> Result<(), CryptoError> {
    for amount in [
        w.payment,
        w.owed_before,
        w.periodic_payment,
        w.principal_before,
        w.principal_paid,
    ] {
        check_amount(amount)?;
    }
    if w.payment == 0
        || w.owed_before == 0
        || w.periodic_payment == 0
        || w.payment > w.owed_before
        || w.principal_paid > w.payment
        || w.principal_paid > w.principal_before
    {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    if !s.borrower_key.verify_possession(&w.borrower_secret) {
        return Err(CryptoError::InvalidKey);
    }
    check_decrypt(
        &s.borrower_spending_before,
        &w.borrower_secret,
        w.borrower_balance,
    )?;
    if w.payment > w.borrower_balance {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    match s.mode {
        PaymentMode::Regular => {
            if s.payment_remaining_before <= 1
                || s.payment_remaining_after != s.payment_remaining_before - 1
                || w.payment < w.periodic_payment
                || w.payment >= w.owed_before
            {
                return Err(CryptoError::InvalidIntegerRelation);
            }
        }
        PaymentMode::Full => {
            if w.payment != w.owed_before || s.payment_remaining_after != 0 {
                return Err(CryptoError::InvalidIntegerRelation);
            }
        }
    }
    if s.loan_version_after
        != s.loan_version_before
            .checked_add(1)
            .ok_or(CryptoError::InvalidIntegerRelation)?
    {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    let expected_principal = w.payment.min(w.principal_before);
    if w.principal_paid != expected_principal {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    check_delta(
        &s.borrower_spending_before,
        &s.borrower_spending_after,
        &s.borrower_key,
        w.payment,
        &w.borrower_delta_randomness,
        true,
    )?;
    for (view, randomness) in s.transfer_views.iter().zip(w.transfer_randomness.iter()) {
        check_encryption(&view.reader_key, &view.ciphertext, w.payment, randomness)?;
    }
    for ((view, pair), randomness) in s
        .transfer_views
        .iter()
        .zip(s.transfer_recovery.iter())
        .zip(w.transfer_recovery_randomness.iter())
    {
        check_recovery_pair(&view.reader_key, pair, w.payment, randomness)?;
    }
    for i in 0..LOAN_READER_COUNT {
        check_ciphertext_delta(
            &s.owed_before[i].ciphertext,
            &s.owed_after[i].ciphertext,
            &s.owed_delta[i].ciphertext,
        )?;
        check_encryption(
            &s.owed_delta[i].reader_key,
            &s.owed_delta[i].ciphertext,
            w.payment,
            &w.owed_delta_randomness[i],
        )?;
        check_recovery_pair(
            &s.owed_delta[i].reader_key,
            &s.owed_delta_recovery[i],
            w.payment,
            &w.owed_delta_recovery_randomness[i],
        )?;
        check_ciphertext_delta(
            &s.principal_before[i].ciphertext,
            &s.principal_after[i].ciphertext,
            &s.principal_delta[i].ciphertext,
        )?;
        check_encryption(
            &s.principal_delta[i].reader_key,
            &s.principal_delta[i].ciphertext,
            w.principal_paid,
            &w.principal_delta_randomness[i],
        )?;
        check_recovery_pair(
            &s.principal_delta[i].reader_key,
            &s.principal_delta_recovery[i],
            w.principal_paid,
            &w.principal_delta_recovery_randomness[i],
        )?;
    }
    if s.owed_before[0].reader_key != s.borrower_key
        || s.periodic_payment[0].reader_key != s.borrower_key
        || s.principal_before[0].reader_key != s.borrower_key
    {
        return Err(CryptoError::InvalidKey);
    }
    check_decrypt(
        &s.owed_before[0].ciphertext,
        &w.borrower_secret,
        w.owed_before,
    )?;
    check_decrypt(
        &s.periodic_payment[0].ciphertext,
        &w.borrower_secret,
        w.periodic_payment,
    )?;
    check_decrypt(
        &s.principal_before[0].ciphertext,
        &w.borrower_secret,
        w.principal_before,
    )?;
    check_commitment_u64(
        &s.principal_delta_commitment,
        w.principal_paid,
        &w.principal_paid_blinding,
    )
}

fn check_reconciliation(
    s: &ReconciliationStatement,
    w: &ReconciliationWitness,
) -> Result<(), CryptoError> {
    let sum = w
        .cash
        .checked_add(w.active_principal)
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    let cash_active = w
        .cash
        .checked_add(w.active_principal)
        .and_then(|v| v.checked_sub(w.impaired_principal))
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    let loss = s.debt_before.saturating_sub(sum);
    let debt_after = s
        .debt_before
        .checked_sub(loss)
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    let provision = debt_after.saturating_sub(cash_active);
    let vault_after = s
        .vault_assets_before
        .checked_sub(loss)
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    let vault_provision_after = s
        .vault_provision_before
        .checked_sub(s.provision_before)
        .and_then(|v| v.checked_add(provision))
        .ok_or(CryptoError::InvalidIntegerRelation)?;
    if loss != s.realized_loss
        || debt_after != s.debt_after
        || provision != s.provision_after
        || vault_after != s.vault_assets_after
        || vault_provision_after != s.vault_provision_after
        || provision > w.impaired_principal
        || provision > debt_after
    {
        return Err(CryptoError::InvalidIntegerRelation);
    }
    if !s.broker_key.verify_possession(&w.broker_secret) {
        return Err(CryptoError::InvalidKey);
    }
    check_decrypt_u128(&s.cash, &w.broker_secret, w.cash)?;
    check_decrypt_u128(&s.active_principal, &w.broker_secret, w.active_principal)?;
    check_decrypt_u128(
        &s.impaired_principal,
        &w.broker_secret,
        w.impaired_principal,
    )?;
    check_commitment_u128(&s.cash_commitment, w.cash, &w.cash_blinding)?;
    check_commitment_u128(
        &s.active_principal_commitment,
        w.active_principal,
        &w.active_principal_blinding,
    )?;
    check_commitment_u128(
        &s.impaired_principal_commitment,
        w.impaired_principal,
        &w.impaired_principal_blinding,
    )
}

fn check_balance_assertion(
    s: &BalanceAssertionStatement,
    w: &BalanceAssertionWitness,
) -> Result<(), CryptoError> {
    if !s.owner_key.verify_possession(&w.secret_key) {
        return Err(CryptoError::InvalidKey);
    }
    check_amount(s.expected_amount)?;
    check_decrypt(&s.ciphertext, &w.secret_key, s.expected_amount)
}

#[cfg(test)]
mod smoke_tests {
    use super::*;
    use ark_ed_on_bn254::Fr as EdFr;
    use ark_relations::r1cs::ConstraintSystem;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    #[test]
    fn key_possession_proof_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let secret = crate::SecretKey::from_scalar(EdFr::from(9u64)).unwrap();
        let context = crate::OperationContext {
            operation_id: [7u8; 32],
            ..Default::default()
        };
        let statement = Statement::KeyPossession(KeyPossessionStatement {
            context,
            public_key: secret.public_key(),
        });
        let artifacts = setup(StatementKind::KeyPossession, &mut rng).unwrap();
        let witness = Witness::KeyPossession(KeyPossessionWitness { secret_key: secret });
        let envelope = prove(&statement, &witness, &artifacts, &mut rng).unwrap();
        verify(&statement, &envelope, &artifacts).unwrap();

        // Every context field is part of the Poseidon input inside the
        // circuit. Mutating any one after proof generation must fail even
        // though the witness and statement kind are unchanged.
        for field in 0..8 {
            let mut changed = statement.clone();
            if let Statement::KeyPossession(ref mut s) = changed {
                let target = match field {
                    0 => &mut s.context.network_id,
                    1 => &mut s.context.core_account,
                    2 => &mut s.context.asset_id,
                    3 => &mut s.context.operation_id,
                    4 => &mut s.context.vault_id,
                    5 => &mut s.context.broker_id,
                    6 => &mut s.context.loan_id,
                    _ => &mut s.context.proposal_id,
                };
                target[0] ^= 1;
            }
            assert!(verify(&changed, &envelope, &artifacts).is_err());
        }
        for change in 0..3 {
            let mut changed = statement.clone();
            if let Statement::KeyPossession(ref mut s) = changed {
                match change {
                    0 => s.context.expected_versions[0] += 1,
                    1 => s.context.authorization_epochs[0] += 1,
                    _ => s.context.expiry += 1,
                }
            }
            assert!(verify(&changed, &envelope, &artifacts).is_err());
        }
    }

    fn conversion_fixture(mode: ConversionMode, balance: u64, amount: u64) -> (Statement, Witness) {
        let owner = crate::SecretKey::from_scalar(EdFr::from(31u64)).unwrap();
        let readers = [
            owner.public_key(),
            crate::SecretKey::from_scalar(EdFr::from(37u64))
                .unwrap()
                .public_key(),
            crate::SecretKey::from_scalar(EdFr::from(41u64))
                .unwrap()
                .public_key(),
        ];
        let before_randomness = EdFr::from(101u64);
        let after_randomness = EdFr::from(103u64);
        let (spending_before, spending_after, delta_randomness) = match mode {
            ConversionMode::Credit => (
                Ciphertext::encrypt_with_randomness(
                    &owner.public_key(),
                    balance,
                    before_randomness,
                )
                .unwrap(),
                Ciphertext::encrypt_with_randomness(
                    &owner.public_key(),
                    balance + amount,
                    after_randomness,
                )
                .unwrap(),
                after_randomness - before_randomness,
            ),
            ConversionMode::Debit => (
                Ciphertext::encrypt_with_randomness(
                    &owner.public_key(),
                    balance,
                    before_randomness,
                )
                .unwrap(),
                Ciphertext::encrypt_with_randomness(
                    &owner.public_key(),
                    balance.saturating_sub(amount),
                    after_randomness,
                )
                .unwrap(),
                before_randomness - after_randomness,
            ),
        };
        let views = readers.map(|reader_key| {
            let ciphertext =
                Ciphertext::encrypt_with_randomness(&reader_key, amount, EdFr::from(107u64))
                    .unwrap();
            ReaderView {
                reader_key,
                ciphertext,
            }
        });
        let context = crate::OperationContext {
            operation_id: [6u8; 32],
            ..Default::default()
        };
        let statement = Statement::PublicConversion(PublicConversionStatement {
            context,
            owner_key: owner.public_key(),
            spending_before,
            spending_after,
            views,
            public_amount: amount,
            mode,
            spending_version: 1,
        });
        let witness = Witness::PublicConversion(PublicConversionWitness {
            owner_secret: owner,
            private_balance: balance,
            delta_randomness: ScalarHex::from(delta_randomness),
            randomness: std::array::from_fn(|_| ScalarHex::from(EdFr::from(107u64))),
        });
        (statement, witness)
    }

    #[test]
    fn conversion_credit_zero_balance_is_satisfied_and_debit_solvent_check_is_gated() {
        let (credit, credit_witness) = conversion_fixture(ConversionMode::Credit, 0, 25);
        let slots = credit.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(credit.kind(), slots.values, credit_witness).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "{:?}",
            cs.which_is_unsatisfied()
        );

        let (debit, debit_witness) = conversion_fixture(ConversionMode::Debit, 0, 25);
        let slots = debit.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(debit.kind(), slots.values, debit_witness).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn transfer_proof_constrains_owner_balance_and_context() {
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let sender = crate::SecretKey::from_scalar(EdFr::from(11u64)).unwrap();
        let recipient = crate::SecretKey::from_scalar(EdFr::from(13u64)).unwrap();
        let readers = [
            sender.public_key(),
            recipient.public_key(),
            crate::SecretKey::from_scalar(EdFr::from(17u64))
                .unwrap()
                .public_key(),
            crate::SecretKey::from_scalar(EdFr::from(19u64))
                .unwrap()
                .public_key(),
            crate::SecretKey::from_scalar(EdFr::from(23u64))
                .unwrap()
                .public_key(),
        ];
        let sender_before_r = EdFr::from(101u64);
        let sender_after_r = EdFr::from(103u64);
        let amount = 25;
        let sender_before =
            Ciphertext::encrypt_with_randomness(&sender.public_key(), 100, sender_before_r)
                .unwrap();
        let sender_after =
            Ciphertext::encrypt_with_randomness(&sender.public_key(), 75, sender_after_r).unwrap();
        let (commitment, blind) = crate::Commitment::commit(amount, &mut rng).unwrap();
        let transfer_views = readers.clone().map(|reader_key| {
            let (ciphertext, randomness) =
                Ciphertext::encrypt(&reader_key, amount, &mut rng).unwrap();
            (
                ReaderView {
                    reader_key,
                    ciphertext,
                },
                ScalarHex::from(randomness),
            )
        });
        let transfer_recovery = readers.clone().map(|reader_key| {
            let (low_limb, low_randomness) =
                Ciphertext::encrypt(&reader_key, amount & u32::MAX as u64, &mut rng).unwrap();
            let (high_limb, high_randomness) =
                Ciphertext::encrypt(&reader_key, amount >> 32, &mut rng).unwrap();
            (
                RecoveryPair {
                    low_limb,
                    high_limb,
                },
                [
                    ScalarHex::from(low_randomness),
                    ScalarHex::from(high_randomness),
                ],
            )
        });
        let context = crate::OperationContext {
            operation_id: [8u8; 32],
            ..Default::default()
        };
        let statement = Statement::ConfidentialTransfer(ConfidentialTransferStatement {
            context,
            sender_key: sender.public_key(),
            recipient_key: recipient.public_key(),
            sender_spending_before: sender_before,
            sender_spending_after: sender_after,
            transfer_views: transfer_views.clone().map(|x| x.0),
            transfer_recovery: transfer_recovery.clone().map(|x| x.0),
            amount_commitment: commitment,
            sender_spending_version: 1,
        });
        let witness = Witness::ConfidentialTransfer(ConfidentialTransferWitness {
            sender_secret: sender.clone(),
            sender_balance: 100,
            amount,
            sender_delta_randomness: ScalarHex::from(sender_before_r - sender_after_r),
            transfer_randomness: transfer_views.map(|x| x.1),
            transfer_recovery_randomness: transfer_recovery.map(|x| x.1),
            commitment_blinding: ScalarHex::from(blind),
        });
        let artifacts = setup(StatementKind::ConfidentialTransfer, &mut rng).unwrap();
        let envelope = prove(&statement, &witness, &artifacts, &mut rng).unwrap();
        verify(&statement, &envelope, &artifacts).unwrap();
        let mut changed = statement.clone();
        if let Statement::ConfidentialTransfer(ref mut s) = changed {
            s.sender_spending_version += 1;
        }
        assert!(verify(&changed, &envelope, &artifacts).is_err());
    }

    fn reconciliation_fixture() -> (Statement, Witness) {
        let broker = crate::SecretKey::from_scalar(EdFr::from(41u64)).unwrap();
        let cash = 110u128;
        let active = 50u128;
        let impaired = 10u128;
        let cash_cipher = Ciphertext::encrypt_u128_with_randomness(
            &broker.public_key(),
            cash,
            EdFr::from(101u64),
        )
        .unwrap();
        let active_cipher = Ciphertext::encrypt_u128_with_randomness(
            &broker.public_key(),
            active,
            EdFr::from(103u64),
        )
        .unwrap();
        let impaired_cipher = Ciphertext::encrypt_u128_with_randomness(
            &broker.public_key(),
            impaired,
            EdFr::from(107u64),
        )
        .unwrap();
        let cash_blind = EdFr::from(11u64);
        let active_blind = EdFr::from(13u64);
        let impaired_blind = EdFr::from(17u64);
        let cash_commitment = Commitment::commit_u128_with_blinding(cash, cash_blind).unwrap();
        let active_commitment =
            Commitment::commit_u128_with_blinding(active, active_blind).unwrap();
        let impaired_commitment =
            Commitment::commit_u128_with_blinding(impaired, impaired_blind).unwrap();
        let context = crate::OperationContext {
            operation_id: [44u8; 32],
            ..Default::default()
        };
        let statement = Statement::Reconciliation(ReconciliationStatement {
            context,
            broker_key: broker.public_key(),
            cash: cash_cipher,
            active_principal: active_cipher,
            impaired_principal: impaired_cipher,
            cash_commitment,
            active_principal_commitment: active_commitment,
            impaired_principal_commitment: impaired_commitment,
            debt_before: 150,
            debt_after: 150,
            vault_assets_before: 1_000,
            vault_assets_after: 1_000,
            vault_provision_before: 20,
            vault_provision_after: 20,
            provision_before: 0,
            provision_after: 0,
            realized_loss: 0,
            book_version: 3,
            accounting_version: 4,
        });
        let witness = Witness::Reconciliation(ReconciliationWitness {
            broker_secret: broker,
            cash,
            active_principal: active,
            impaired_principal: impaired,
            cash_blinding: ScalarHex::from(cash_blind),
            active_principal_blinding: ScalarHex::from(active_blind),
            impaired_principal_blinding: ScalarHex::from(impaired_blind),
        });
        (statement, witness)
    }

    fn reader_views<const N: usize>(
        keys: [crate::PublicKey; N],
        amount: u64,
        seed: u64,
    ) -> ([ReaderView; N], [ScalarHex; N]) {
        let values: Vec<_> = keys
            .into_iter()
            .map(|key| {
                let randomness = EdFr::from(seed + 1);
                let ciphertext =
                    Ciphertext::encrypt_with_randomness(&key, amount, randomness).unwrap();
                (
                    ReaderView {
                        reader_key: key,
                        ciphertext,
                    },
                    ScalarHex::from(randomness),
                )
            })
            .collect();
        let views = values
            .iter()
            .map(|(view, _)| view.clone())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let randomness = values
            .into_iter()
            .map(|(_, randomness)| randomness)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        (views, randomness)
    }

    fn recovery_pairs<const N: usize>(
        keys: [crate::PublicKey; N],
        amount: u64,
        seed: u64,
    ) -> ([RecoveryPair; N], [[ScalarHex; 2]; N]) {
        let values: Vec<_> = keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                let low_randomness = EdFr::from(seed + index as u64 * 3 + 1);
                let high_randomness = EdFr::from(seed + index as u64 * 3 + 2);
                let low_limb = Ciphertext::encrypt_with_randomness(
                    &key,
                    amount & u32::MAX as u64,
                    low_randomness,
                )
                .unwrap();
                let high_limb =
                    Ciphertext::encrypt_with_randomness(&key, amount >> 32, high_randomness)
                        .unwrap();
                (
                    RecoveryPair {
                        low_limb,
                        high_limb,
                    },
                    [
                        ScalarHex::from(low_randomness),
                        ScalarHex::from(high_randomness),
                    ],
                )
            })
            .collect();
        let pairs = values
            .iter()
            .map(|(pair, _)| pair.clone())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let randomness = values
            .into_iter()
            .map(|(_, randomness)| randomness)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        (pairs, randomness)
    }

    fn repayment_full_fixture() -> (Statement, Witness) {
        let borrower = crate::SecretKey::from_scalar(EdFr::from(51u64)).unwrap();
        let broker = crate::SecretKey::from_scalar(EdFr::from(53u64)).unwrap();
        let reader_two = crate::SecretKey::from_scalar(EdFr::from(59u64)).unwrap();
        let transfer_keys = [
            borrower.public_key(),
            broker.public_key(),
            reader_two.public_key(),
            crate::SecretKey::from_scalar(EdFr::from(61u64))
                .unwrap()
                .public_key(),
            crate::SecretKey::from_scalar(EdFr::from(67u64))
                .unwrap()
                .public_key(),
        ];
        let term_keys = [
            borrower.public_key(),
            broker.public_key(),
            reader_two.public_key(),
        ];
        let payment = 100u64;
        let owed = 100u64;
        let periodic = 25u64;
        let principal = 60u64;
        let borrower_before_randomness = EdFr::from(71u64);
        let borrower_after_randomness = EdFr::from(73u64);
        let borrower_before = Ciphertext::encrypt_with_randomness(
            &borrower.public_key(),
            200,
            borrower_before_randomness,
        )
        .unwrap();
        let borrower_after = Ciphertext::encrypt_with_randomness(
            &borrower.public_key(),
            100,
            borrower_after_randomness,
        )
        .unwrap();
        let (transfer_views, transfer_randomness) =
            reader_views(transfer_keys.clone(), payment, 79);
        let (transfer_recovery, transfer_recovery_randomness) =
            recovery_pairs(transfer_keys, payment, 89);
        let (owed_before, _) = reader_views(term_keys.clone(), owed, 201);
        let (owed_after, _) = reader_views(term_keys.clone(), 0, 101);
        let (owed_delta, owed_delta_randomness) = reader_views(term_keys.clone(), payment, 99);
        let (owed_delta_recovery, owed_delta_recovery_randomness) =
            recovery_pairs(term_keys.clone(), payment, 137);
        let (periodic_views, _) = reader_views(term_keys.clone(), periodic, 149);
        let (principal_before, _) = reader_views(term_keys.clone(), principal, 263);
        let (principal_after, _) = reader_views(term_keys.clone(), 0, 163);
        let (principal_delta, principal_delta_randomness) =
            reader_views(term_keys.clone(), principal, 99);
        let (principal_delta_recovery, principal_delta_recovery_randomness) =
            recovery_pairs(term_keys, principal, 191);
        let principal_paid_blinding = EdFr::from(197u64);
        let principal_delta_commitment =
            Commitment::commit_with_blinding(principal, principal_paid_blinding).unwrap();
        let context = crate::OperationContext {
            operation_id: [55u8; 32],
            ..Default::default()
        };
        let statement = Statement::Repayment(RepaymentStatement {
            context,
            borrower_key: borrower.public_key(),
            broker_key: broker.public_key(),
            borrower_spending_before: borrower_before,
            borrower_spending_after: borrower_after,
            transfer_views,
            transfer_recovery,
            owed_before,
            owed_after,
            owed_delta,
            owed_delta_recovery,
            periodic_payment: periodic_views,
            principal_before,
            principal_after,
            principal_delta,
            principal_delta_recovery,
            principal_delta_commitment,
            mode: PaymentMode::Full,
            payment_remaining_before: 1,
            payment_remaining_after: 0,
            borrower_spending_version: 7,
            loan_version_before: 8,
            loan_version_after: 9,
        });
        let witness = Witness::Repayment(RepaymentWitness {
            borrower_secret: borrower,
            borrower_balance: 200,
            payment,
            owed_before: owed,
            periodic_payment: periodic,
            principal_before: principal,
            principal_paid: principal,
            transfer_randomness,
            transfer_recovery_randomness,
            borrower_delta_randomness: ScalarHex::from(
                borrower_before_randomness - borrower_after_randomness,
            ),
            owed_delta_randomness,
            owed_delta_recovery_randomness,
            principal_delta_randomness,
            principal_delta_recovery_randomness,
            principal_paid_blinding: ScalarHex::from(principal_paid_blinding),
        });
        (statement, witness)
    }

    #[test]
    fn reconciliation_no_loss_and_zero_impairment_proof_are_satisfied_directly() {
        let (statement, witness) = reconciliation_fixture();
        let slots = statement.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(statement.kind(), slots.values, witness).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "{:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn reconciliation_wrong_public_outputs_fail_direct_r1cs() {
        let (mut statement, witness) = reconciliation_fixture();
        if let Statement::Reconciliation(ref mut s) = statement {
            s.provision_after = 1;
        }
        let slots = statement.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(statement.kind(), slots.values, witness).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn full_repayment_boundary_and_min_principal_split_are_directly_constrained() {
        let (statement, witness) = repayment_full_fixture();
        validate_host_relation(&statement, &witness).unwrap();
        let slots = statement.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(statement.kind(), slots.values, witness).unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "{:?}",
            cs.which_is_unsatisfied()
        );

        let (mut invalid_statement, witness) = repayment_full_fixture();
        if let Statement::Repayment(ref mut s) = invalid_statement {
            s.payment_remaining_after = 1;
        }
        let slots = invalid_statement.public_slots().unwrap();
        let circuit =
            LendingCircuit::from_statement(invalid_statement.kind(), slots.values, witness)
                .unwrap();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
