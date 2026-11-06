//! Convert a canonical arkworks BN254 verification key into the validated NEAR format.
use std::{fs, io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err("usage: prepare_key <canonical-vk.bin> <prepared-vk.bin>".into());
    }
    let input = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let details = fs::metadata(&input)?;
    if !details.is_file() || details.len() > 128 * 1024 {
        return Err("verification key exceeds file bound".into());
    }
    let prepared = near_verifier::prepare_key(&fs::read(input)?)?;
    let inputs = near_verifier::validate_prepared_key(&prepared)?;
    let key_hash = near_verifier::prepared_key_hash(&prepared)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&prepared)?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::json!({ "public_inputs": inputs, "canonical_key_sha256": hex::encode(key_hash), "prepared_bytes": prepared.len() })
    );
    Ok(())
}
