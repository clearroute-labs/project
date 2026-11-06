#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --profile prover -p confidential-crypto --features wasm --target wasm32-unknown-unknown
mkdir -p .artifacts/browser
wasm-bindgen target/wasm32-unknown-unknown/prover/confidential_crypto.wasm --target web --out-dir .artifacts/browser
