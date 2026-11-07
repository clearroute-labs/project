//! Generates only a public, development-only proof/VK fixture for runtime tests.
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;

#[derive(Clone)]
struct Product {
    context_inputs: u64,
}

impl ConstraintSynthesizer<Fr> for Product {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(Fr::from(6u64)))?;
        let b = cs.new_witness_variable(|| Ok(Fr::from(7u64)))?;
        let product = cs.new_input_variable(|| Ok(Fr::from(42u64)))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + product)?;
        for value in 0u64..self.context_inputs {
            let context = cs.new_input_variable(|| Ok(Fr::from(value)))?;
            let square = cs.new_witness_variable(|| Ok(Fr::from(value * value)))?;
            cs.enforce_constraint(lc!() + context, lc!() + context, lc!() + square)?;
        }
        Ok(())
    }
}

fn encoded(value: &impl CanonicalSerialize) -> String {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialize public fixture");
    hex::encode(bytes)
}

fn main() {
    let context_inputs = std::env::args()
        .nth(1)
        .map(|value| value.parse::<u64>().expect("context input count"))
        .unwrap_or(192);
    assert!(
        context_inputs < 2048,
        "fixture exceeds verifier input bound"
    );
    let circuit = Product { context_inputs };
    let mut rng = rand::thread_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
        .expect("fixture setup");
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng)
        .expect("fixture proof");
    println!(
        "{}",
        serde_json::json!({
            "development_only": true,
            "verifying_key_hex": hex::encode(near_verifier::prepare_key(&hex::decode(encoded(&pk.vk)).unwrap()).unwrap()),
            "proof_hex": encoded(&proof),
            "public_inputs": std::iter::once(42u64).chain(0u64..context_inputs).map(|value| encoded(&Fr::from(value))).collect::<Vec<_>>(),
            "wrong_inputs": std::iter::once(43u64).chain(0u64..context_inputs).map(|value| encoded(&Fr::from(value))).collect::<Vec<_>>()
        })
    );
}
