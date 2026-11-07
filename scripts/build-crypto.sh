#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --profile prover -p confidential-crypto --bin confidential-crypto
cargo build --locked --release -p near-verifier --example prepare_key --example verifier_fixture
cargo build --locked --profile prover -p confidential-crypto --lib --features browser --target wasm32-unknown-unknown
mkdir -p .artifacts/browser
binding_cli=".local/wasm-bindgen/bin/wasm-bindgen"
if [[ ! -x "$binding_cli" ]]; then
  binding_cli="$(command -v wasm-bindgen || true)"
fi
if [[ -z "$binding_cli" ]]; then
  printf '%s\n' 'Install the pinned CLI: cargo install wasm-bindgen-cli --version 0.2.130 --locked --root .local/wasm-bindgen' >&2
  exit 1
fi
"$binding_cli" target/wasm32-unknown-unknown/prover/confidential_crypto.wasm --target web --out-dir .artifacts/browser
