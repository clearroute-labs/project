//! Generates only a public, development-only proof/VK fixture for runtime tests.
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;

#[derive(Clone)]
struct Product;

impl ConstraintSynthesizer<Fr> for Product {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(Fr::from(6u64)))?;
        let b = cs.new_witness_variable(|| Ok(Fr::from(7u64)))?;
        let product = cs.new_input_variable(|| Ok(Fr::from(42u64)))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + product)?;
        for value in 1u64..=192 {
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
    let mut rng = rand::thread_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(Product, &mut rng)
        .expect("fixture setup");
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(Product, &pk, &mut rng)
        .expect("fixture proof");
    println!(
        "{}",
        serde_json::json!({
            "development_only": true,
            "verifying_key_hex": hex::encode(near_verifier::prepare_key(&hex::decode(encoded(&pk.vk)).unwrap()).unwrap()),
            "proof_hex": encoded(&proof),
            "public_inputs": std::iter::once(42u64).chain(1u64..=192).map(|value| encoded(&Fr::from(value))).collect::<Vec<_>>(),
            "wrong_inputs": std::iter::once(43u64).chain(1u64..=192).map(|value| encoded(&Fr::from(value))).collect::<Vec<_>>()
        })
    );
}
