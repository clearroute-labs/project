//! Local integration fixture for the actual NEAR BN254 host verification path.

use near_sdk::{PanicOnDefault, near};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct VerifierProbe {
    key: Vec<u8>,
}

#[near]
impl VerifierProbe {
    #[init]
    pub fn new(verifying_key_hex: String) -> Self {
        let key = hex::decode(verifying_key_hex).expect("invalid key encoding");
        near_verifier::validate_prepared_key(&key).expect("invalid verifying key");
        Self { key }
    }

    pub fn verify(&self, proof_hex: String, public_inputs: Vec<String>) -> bool {
        let Ok(proof) = hex::decode(proof_hex) else {
            return false;
        };
        let Some(inputs) = public_inputs
            .iter()
            .map(|value| hex::decode(value).ok()?.try_into().ok())
            .collect::<Option<Vec<[u8; 32]>>>()
        else {
            return false;
        };
        near_verifier::verify_prepared(&self.key, &proof, &inputs).unwrap_or(false)
    }
}
