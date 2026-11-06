#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .artifacts/contracts
for package in confidential-core test-token verifier-probe; do
  cargo build --locked --release --target wasm32-unknown-unknown -p "$package"
  artifact="${package//-/_}"
  cp "target/wasm32-unknown-unknown/release/${artifact}.wasm" ".artifacts/contracts/${artifact}.wasm"
done
