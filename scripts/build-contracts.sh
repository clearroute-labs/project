#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .artifacts/contracts
# NEAR SDK 5.30 selects its runtime host functions with this target cfg.
# Keep it scoped to contract builds: the browser prover uses the same WASM target.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS:+${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS} }--cfg near"
for package in confidential-core test-token verifier-probe; do
  cargo build --locked --release --target wasm32-unknown-unknown -p "$package"
  artifact="${package//-/_}"
  cp "target/wasm32-unknown-unknown/release/${artifact}.wasm" ".artifacts/contracts/${artifact}.wasm"
done
node scripts/check-contract-hosts.mjs
