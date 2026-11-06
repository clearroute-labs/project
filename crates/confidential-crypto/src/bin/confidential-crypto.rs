use confidential_crypto::{
    ArtifactSet, CONTEXT_SLOTS, Ciphertext, Commitment, FieldHex, MAX_AMOUNT, PROFILE_VERSION,
    ProofEnvelope, ProvingArtifacts, PublicKey, ReaderView, RecoveryMetadata, RecoveryPair,
    RecoveryRecord, SecretKey, SetupMode, Statement, WitnessWire, profile_hash_hex, profile_id,
    prove, setup, verify_with_vk_bytes,
};
use rand::rngs::OsRng;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::env;
use std::fs;
use std::io::{Read, Write};

fn usage() -> ! {
    eprintln!(
        "usage:\n  confidential-crypto inspect-profile\n  confidential-crypto keygen [seed-hex-32]\n  confidential-crypto dev setup <statement-kind> <artifact-prefix>\n  confidential-crypto prove <statement.json> <witness.json> <proving-key.bin>\n  confidential-crypto verify <statement.json> <proof.json> <verifying-key.bin>"
    );
    std::process::exit(2)
}

fn kind(value: &str) -> Result<confidential_crypto::StatementKind, String> {
    match value {
        "key-possession" => Ok(confidential_crypto::StatementKind::KeyPossession),
        "public-conversion" => Ok(confidential_crypto::StatementKind::PublicConversion),
        "confidential-transfer" => Ok(confidential_crypto::StatementKind::ConfidentialTransfer),
        "origination" => Ok(confidential_crypto::StatementKind::Origination),
        "repayment" => Ok(confidential_crypto::StatementKind::Repayment),
        "reconciliation" => Ok(confidential_crypto::StatementKind::Reconciliation),
        "zero-balance" => Ok(confidential_crypto::StatementKind::ZeroBalance),
        "ownership" => Ok(confidential_crypto::StatementKind::Ownership),
        _ => Err(format!("unknown statement kind: {value}")),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|_| format!("cannot read input: {path}"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("invalid JSON input: {path}"))
}

fn inspect_profile() -> Result<(), String> {
    println!(
        "{}",
        serde_json::json!({
            "profile_id": profile_id(),
            "profile_version": PROFILE_VERSION,
            "profile_hash": profile_hash_hex(),
            "curve": "ark-ed-on-bn254 prime-order Edwards subgroup",
            "proof_system": "arkworks Groth16 BN254, compressed canonical proof/VK",
            "max_amount": MAX_AMOUNT.to_string(),
            "max_public_slots": CONTEXT_SLOTS,
            "transcript": "arkworks Poseidon width=3 rate=2 capacity=1 alpha=5 full_rounds=8 partial_rounds=57 grain_skip=0",
            "recovery": "proof-bound encrypted 32-bit limbs; authenticated records are hints only",
            "development_setup": "single-party; not accepted for funded release",
        })
    );
    Ok(())
}

fn keygen(seed: Option<&str>) -> Result<(), String> {
    let secret = if let Some(seed) = seed {
        let bytes = hex::decode(seed).map_err(|_| "seed must be lowercase hex".to_string())?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "seed must be 32 bytes".to_string())?;
        let mut rng = ChaCha20Rng::from_seed(seed);
        SecretKey::generate(&mut rng)
    } else {
        SecretKey::generate(&mut OsRng)
    };
    // This command is an explicit wallet-backup operation. No secret is ever
    // included in diagnostics or an error path.
    println!(
        "{}",
        serde_json::json!({
            "secret_key": secret.to_wire().0,
            "public_key": secret.public_key(),
        })
    );
    Ok(())
}

fn dev_setup(kind_name: &str, prefix: &str) -> Result<(), String> {
    let statement_kind = kind(kind_name)?;
    let mut rng = OsRng;
    let artifacts = setup(statement_kind, &mut rng).map_err(|e| e.to_string())?;
    let artifact = artifacts.get(statement_kind).map_err(|e| e.to_string())?;
    write_new_artifact(
        &format!("{prefix}.pk"),
        &artifact.proving_key_bytes().map_err(|e| e.to_string())?,
    )?;
    write_new_artifact(
        &format!("{prefix}.vk"),
        &artifact.verifying_key_bytes().map_err(|e| e.to_string())?,
    )?;
    println!(
        "{}",
        serde_json::json!({
            "statement_kind": statement_kind.as_str(),
            "mode": "development_single_party",
            "proving_key": format!("{prefix}.pk"),
            "verifying_key": format!("{prefix}.vk"),
            "verifying_key_hash": artifact.verifying_key_hash_hex(),
            "warning": "development setup is rejected for funded release",
        })
    );
    Ok(())
}

fn write_new_artifact(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| format!("refusing to overwrite artifact: {path}"))?;
    file.write_all(bytes)
        .map_err(|_| format!("cannot write artifact: {path}"))
}

fn prove_file(
    statement_path: &str,
    witness_path: &str,
    proving_key_path: &str,
) -> Result<(), String> {
    let statement: Statement = read_json(statement_path)?;
    let witness_wire: WitnessWire = read_json(witness_path)?;
    let witness = witness_wire.into_witness().map_err(|e| e.to_string())?;
    let proving_key =
        fs::read(proving_key_path).map_err(|_| "cannot read proving key".to_string())?;
    let artifact =
        ProvingArtifacts::from_proving_key_bytes(&proving_key, SetupMode::ImportedArtifact)
            .map_err(|e| e.to_string())?;
    let mut artifacts = ArtifactSet::empty();
    artifacts
        .insert(statement.kind(), artifact)
        .map_err(|e| e.to_string())?;
    let mut rng = OsRng;
    let envelope = prove(&statement, &witness, &artifacts, &mut rng).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&envelope).map_err(|_| "cannot encode proof".to_string())?
    );
    Ok(())
}

fn verify_file(
    statement_path: &str,
    envelope_path: &str,
    verifying_key_path: &str,
) -> Result<(), String> {
    let statement: Statement = read_json(statement_path)?;
    let envelope: confidential_crypto::ProofEnvelope = read_json(envelope_path)?;
    let verifying_key =
        fs::read(verifying_key_path).map_err(|_| "cannot read verifying key".to_string())?;
    verify_with_vk_bytes(&statement, &envelope, &verifying_key).map_err(|e| e.to_string())?;
    println!("{{\"valid\":true}}\n");
    Ok(())
}

fn parse_secret_wire(value: &str) -> Result<SecretKey, String> {
    let wire = confidential_crypto::ScalarHex::parse(value).map_err(|e| e.to_string())?;
    SecretKey::from_wire(&wire).map_err(|e| e.to_string())
}

fn required_text<'a>(
    value: &'a serde_json::Value,
    name: &str,
    method: &str,
) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{method} requires {name}"))
}

fn required_amount(value: &serde_json::Value, name: &str, method: &str) -> Result<u64, String> {
    let text = required_text(value, name, method)?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("{name} must be a canonical decimal string"));
    }
    text.parse().map_err(|_| format!("{name} is out of range"))
}

fn required_amount_u128(
    value: &serde_json::Value,
    name: &str,
    method: &str,
) -> Result<u128, String> {
    let text = required_text(value, name, method)?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("{name} must be a canonical decimal string"));
    }
    text.parse().map_err(|_| format!("{name} is out of range"))
}

fn encrypt_views(params: &serde_json::Value, method: &str) -> Result<String, String> {
    let keys: Vec<PublicKey> = serde_json::from_value(
        params
            .get("public_keys")
            .cloned()
            .ok_or_else(|| format!("{method} requires public_keys"))?,
    )
    .map_err(|_| "invalid public_keys".to_string())?;
    if keys.is_empty() || keys.len() > 5 {
        return Err("encrypt_views requires one through five keys".to_string());
    }
    let amount = required_amount(params, "amount", method)?;
    let seed = hex::decode(required_text(params, "seed_hex", method)?)
        .map_err(|_| "seed must be hex".to_string())?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "seed must be 32 bytes".to_string())?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut views = Vec::with_capacity(keys.len());
    let mut recovery = Vec::with_capacity(keys.len());
    let mut randomness = Vec::with_capacity(keys.len());
    let mut recovery_randomness = Vec::with_capacity(keys.len());
    for key in keys {
        let (ciphertext, r) =
            Ciphertext::encrypt(&key, amount, &mut rng).map_err(|e| e.to_string())?;
        let (low_limb, low_r) = Ciphertext::encrypt(&key, amount & u32::MAX as u64, &mut rng)
            .map_err(|e| e.to_string())?;
        let (high_limb, high_r) =
            Ciphertext::encrypt(&key, amount >> 32, &mut rng).map_err(|e| e.to_string())?;
        views.push(ReaderView {
            reader_key: key,
            ciphertext,
        });
        recovery.push(RecoveryPair {
            low_limb,
            high_limb,
        });
        randomness.push(confidential_crypto::ScalarHex::from(r));
        recovery_randomness.push([
            confidential_crypto::ScalarHex::from(low_r),
            confidential_crypto::ScalarHex::from(high_r),
        ]);
    }
    serde_json::to_string(&serde_json::json!({
        "views": views,
        "recovery": recovery,
        "randomness": randomness,
        "recovery_randomness": recovery_randomness,
    }))
    .map_err(|_| "cannot encode encrypted views".to_string())
}

fn execute_request(request_json: &str, artifact_bytes: &[u8]) -> Result<String, String> {
    let request: serde_json::Value =
        serde_json::from_str(request_json).map_err(|_| "invalid request JSON".to_string())?;
    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "request method is required".to_string())?;
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    match method {
        "keygen" => {
            let seed = hex::decode(required_text(&params, "seed_hex", method)?)
                .map_err(|_| "seed must be hex".to_string())?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| "seed must be 32 bytes".to_string())?;
            let mut rng = ChaCha20Rng::from_seed(seed);
            let secret = SecretKey::generate(&mut rng);
            serde_json::to_string(&serde_json::json!({
                "secret_key": secret.to_wire().0,
                "public_key": secret.public_key(),
            }))
            .map_err(|_| "cannot encode key".to_string())
        }
        "public_key_from_secret" => {
            let secret = parse_secret_wire(required_text(&params, "secret_key", method)?)?;
            serde_json::to_string(&secret.public_key())
                .map_err(|_| "cannot encode public key".to_string())
        }
        "encrypt_amount" => {
            let public_key = required_text(&params, "public_key", method)?;
            let key: PublicKey = serde_json::from_str(public_key)
                .or_else(|_| PublicKey::parse(public_key))
                .map_err(|e| e.to_string())?;
            let randomness = confidential_crypto::ScalarHex::parse(required_text(
                &params,
                "randomness",
                method,
            )?)
            .map_err(|e| e.to_string())?
            .to_scalar()
            .map_err(|e| e.to_string())?;
            let amount = required_amount(&params, "amount", method)?;
            serde_json::to_string(
                &Ciphertext::encrypt_with_randomness(&key, amount, randomness)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "cannot encode ciphertext".to_string())
        }
        "decrypt_bounded" => {
            let secret = parse_secret_wire(required_text(&params, "secret_key", method)?)?;
            let ciphertext: Ciphertext =
                serde_json::from_str(required_text(&params, "ciphertext", method)?)
                    .map_err(|_| "invalid ciphertext JSON".to_string())?;
            let max_amount = required_amount(&params, "max_amount", method)?;
            Ok(serde_json::to_string(
                &ciphertext
                    .decrypt_bounded(&secret, max_amount)
                    .map_err(|e| e.to_string())?
                    .to_string(),
            )
            .map_err(|_| "cannot encode amount".to_string())?)
        }
        "verify_plaintext_u128" => {
            let secret = parse_secret_wire(required_text(&params, "secret_key", method)?)?;
            let ciphertext: Ciphertext =
                serde_json::from_str(required_text(&params, "ciphertext", method)?)
                    .map_err(|_| "invalid ciphertext JSON".to_string())?;
            let amount = required_amount_u128(&params, "amount", method)?;
            serde_json::to_string(
                &ciphertext
                    .verify_plaintext_u128(&secret, amount)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "cannot encode verification result".to_string())
        }
        "create_recovery_record" => {
            let amount = required_amount(&params, "amount", method)?;
            let recipient_key: PublicKey = serde_json::from_value(
                params
                    .get("recipient_key")
                    .cloned()
                    .ok_or_else(|| "create_recovery_record requires recipient_key".to_string())?,
            )
            .map_err(|_| "invalid recipient_key".to_string())?;
            let metadata: RecoveryMetadata = serde_json::from_value(
                params
                    .get("metadata")
                    .cloned()
                    .ok_or_else(|| "create_recovery_record requires metadata".to_string())?,
            )
            .map_err(|_| "invalid recovery metadata".to_string())?;
            let main_ciphertext: Ciphertext =
                serde_json::from_value(params.get("main_ciphertext").cloned().ok_or_else(
                    || "create_recovery_record requires main_ciphertext".to_string(),
                )?)
                .map_err(|_| "invalid main_ciphertext".to_string())?;
            let signer = parse_secret_wire(required_text(&params, "signer_secret", method)?)?;
            let seed = hex::decode(required_text(&params, "seed_hex", method)?)
                .map_err(|_| "seed must be hex".to_string())?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| "seed must be 32 bytes".to_string())?;
            let mut rng = ChaCha20Rng::from_seed(seed);
            let record = RecoveryRecord::create(
                amount,
                &recipient_key,
                metadata,
                &main_ciphertext,
                &signer,
                &mut rng,
            )
            .map_err(|e| e.to_string())?;
            serde_json::to_string(&record).map_err(|_| "cannot encode recovery record".to_string())
        }
        "decrypt_recovery_record" => {
            let record: RecoveryRecord = serde_json::from_value(
                params
                    .get("record")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_record requires record".to_string())?,
            )
            .map_err(|_| "invalid recovery record".to_string())?;
            let secret = parse_secret_wire(required_text(&params, "secret_key", method)?)?;
            let expected_key: PublicKey = serde_json::from_value(
                params
                    .get("expected_recipient_key")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_record requires key".to_string())?,
            )
            .map_err(|_| "invalid expected_recipient_key".to_string())?;
            let main_ciphertext: Ciphertext = serde_json::from_value(
                params
                    .get("main_ciphertext")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_record requires ciphertext".to_string())?,
            )
            .map_err(|_| "invalid main_ciphertext".to_string())?;
            let metadata: RecoveryMetadata = serde_json::from_value(
                params
                    .get("metadata")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_record requires metadata".to_string())?,
            )
            .map_err(|_| "invalid recovery metadata".to_string())?;
            serde_json::to_string(
                &record
                    .recover(&secret, &expected_key, &main_ciphertext, &metadata)
                    .map_err(|e| e.to_string())?
                    .to_string(),
            )
            .map_err(|_| "cannot encode amount".to_string())
        }
        "decrypt_recovery_pair" => {
            let secret = parse_secret_wire(required_text(&params, "secret_key", method)?)?;
            let expected_key: PublicKey = serde_json::from_value(
                params
                    .get("expected_key")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_pair requires expected_key".to_string())?,
            )
            .map_err(|_| "invalid expected_key".to_string())?;
            let pair: RecoveryPair = serde_json::from_value(
                params
                    .get("pair")
                    .cloned()
                    .ok_or_else(|| "decrypt_recovery_pair requires pair".to_string())?,
            )
            .map_err(|_| "invalid recovery pair".to_string())?;
            Ok(serde_json::to_string(
                &confidential_crypto::recover_pair(&pair, &secret, &expected_key)
                    .map_err(|e| e.to_string())?
                    .to_string(),
            )
            .map_err(|_| "cannot encode amount".to_string())?)
        }
        "canonical_statement" => {
            let statement: Statement =
                serde_json::from_str(required_text(&params, "statement", method)?)
                    .map_err(|_| "invalid statement JSON".to_string())?;
            let slots = statement.public_slots().map_err(|e| e.to_string())?;
            serde_json::to_string(&serde_json::json!({
                "statement_kind": statement.kind().as_str(),
                "context_digest": slots.digest_wire(),
                "public_inputs": slots.public_inputs().into_iter().map(FieldHex::from).collect::<Vec<_>>(),
            }))
            .map_err(|_| "cannot encode statement".to_string())
        }
        "encrypt_views" => encrypt_views(&params, method),
        "prove" => {
            let statement: Statement =
                serde_json::from_str(required_text(&params, "statement", method)?)
                    .map_err(|_| "invalid statement JSON".to_string())?;
            let witness_wire: WitnessWire =
                serde_json::from_str(required_text(&params, "witness", method)?)
                    .map_err(|_| "invalid witness JSON".to_string())?;
            let witness = witness_wire.into_witness().map_err(|e| e.to_string())?;
            let artifact = ProvingArtifacts::from_proving_key_bytes(
                artifact_bytes,
                SetupMode::ImportedArtifact,
            )
            .map_err(|e| e.to_string())?;
            let mut artifacts = ArtifactSet::empty();
            artifacts
                .insert(statement.kind(), artifact)
                .map_err(|e| e.to_string())?;
            let mut rng = OsRng;
            serde_json::to_string(
                &prove(&statement, &witness, &artifacts, &mut rng).map_err(|e| e.to_string())?,
            )
            .map_err(|_| "cannot encode proof".to_string())
        }
        "verify" => {
            let statement: Statement =
                serde_json::from_str(required_text(&params, "statement", method)?)
                    .map_err(|_| "invalid statement JSON".to_string())?;
            let envelope: ProofEnvelope =
                serde_json::from_str(required_text(&params, "envelope", method)?)
                    .map_err(|_| "invalid envelope JSON".to_string())?;
            verify_with_vk_bytes(&statement, &envelope, artifact_bytes)
                .map_err(|e| e.to_string())?;
            Ok("true".to_string())
        }
        "ciphertext_add" | "ciphertext_sub" => {
            let left: Ciphertext = serde_json::from_str(required_text(&params, "left", method)?)
                .map_err(|_| "invalid left ciphertext".to_string())?;
            let right: Ciphertext = serde_json::from_str(required_text(&params, "right", method)?)
                .map_err(|_| "invalid right ciphertext".to_string())?;
            let result = if method == "ciphertext_add" {
                left.add(&right)
            } else {
                left.sub(&right)
            }
            .map_err(|e| e.to_string())?;
            serde_json::to_string(&result).map_err(|_| "cannot encode ciphertext".to_string())
        }
        "commitment_create" => {
            let amount = required_amount_u128(&params, "amount", method)?;
            let blind =
                confidential_crypto::ScalarHex::parse(required_text(&params, "blinding", method)?)
                    .map_err(|e| e.to_string())?
                    .to_scalar()
                    .map_err(|e| e.to_string())?;
            serde_json::to_string(
                &Commitment::commit_u128_with_blinding(amount, blind).map_err(|e| e.to_string())?,
            )
            .map_err(|_| "cannot encode commitment".to_string())
        }
        _ => Err("unknown crypto method".to_string()),
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("inspect-profile") => inspect_profile(),
        Some("keygen") => keygen(args.next().as_deref()),
        Some("dev") if args.next().as_deref() == Some("setup") => {
            let kind_name = args
                .next()
                .ok_or_else(|| "missing statement kind".to_string())?;
            let prefix = args
                .next()
                .ok_or_else(|| "missing artifact prefix".to_string())?;
            dev_setup(&kind_name, &prefix)
        }
        Some("prove") => prove_file(
            &args
                .next()
                .ok_or_else(|| "missing statement path".to_string())?,
            &args
                .next()
                .ok_or_else(|| "missing witness path".to_string())?,
            &args
                .next()
                .ok_or_else(|| "missing proving key path".to_string())?,
        ),
        Some("verify") => verify_file(
            &args
                .next()
                .ok_or_else(|| "missing statement path".to_string())?,
            &args
                .next()
                .ok_or_else(|| "missing proof path".to_string())?,
            &args
                .next()
                .ok_or_else(|| "missing verifying key path".to_string())?,
        ),
        Some("execute") => {
            let mut artifact_path = None;
            while let Some(arg) = args.next() {
                if arg == "--artifact" {
                    artifact_path = Some(
                        args.next()
                            .ok_or_else(|| "missing artifact path".to_string())?,
                    );
                } else {
                    return Err("unknown execute argument".to_string());
                }
            }
            let artifact = artifact_path
                .map(|path| fs::read(path).map_err(|_| "cannot read artifact".to_string()))
                .transpose()?
                .unwrap_or_default();
            let mut request = String::new();
            std::io::stdin()
                .read_to_string(&mut request)
                .map_err(|_| "cannot read request".to_string())?;
            println!("{}", execute_request(&request, &artifact)?);
            Ok(())
        }
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("crypto command failed: {error}");
        std::process::exit(1);
    }
}
