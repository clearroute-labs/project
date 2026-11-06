# Implementation integration review

This is an internal engineering checklist, not an independent security audit.

## Components

- Main workspace: transport/client, BN254 NEAR host verifier/probe, integration tests, build/release tooling, keeper integration.
- Crypto worker branch `implement/crypto`, isolated `.worktrees/crypto`.
- Core worker branch `implement/core`, isolated `.worktrees/core`.
- Web worker branch `implement/web`, isolated `.worktrees/web`.

## Findings to verify before completion

- [ ] Transfer/origination/repayment circuits prove key knowledge and a bounded sufficient sender balance. A ciphertext delta alone does not prevent negative private balances.
- [ ] Borrower repayment decrypts stored O/Q/R with borrower secret; it never requires original broker encryption randomness or secrets for other readers.
- [ ] Broker reconciliation decrypts C/active-principal/impaired-principal with broker secret, not unknown accumulated randomness.
- [ ] Aggregate `active_principal` is H + I: book value is C + active_principal; healthy backing is C + active_principal - impaired_principal. Do not count I twice.
- [ ] Circuit u128 high limb coefficient is 2^64, not 1^64; every limb/comparison is range checked and field wrap cannot satisfy conservation.
- [ ] Repayment public-slot cursor order matches the statement exactly, including spending/loan versions.
- [ ] R1CS conditional equalities use the condition argument correctly; valid full repayments and exact D = book reconciliation must be satisfiable. Negative tests bypass the honest prover's prechecks.
- [ ] Recipient credits apply proven deltas to current inbox; proofs do not depend on an earlier recipient inbox/version.
- [ ] Public conversion binds all holder/issuer/auditor copies; O/Q terms have only the three loan readers.
- [ ] Recovery supports the full 63-bit amount domain and cannot be disabled by an adversarial unverified hint. Ledger history contains the necessary encrypted recovery data.
- [ ] Transcript binding uses established primitives, not a newly invented x^5 sponge treated as a secure hash.
- [ ] Core constructs typed statements from authoritative state and selects immutable per-kind verifier keys. Caller-chosen post states are not accepted without proved relations.
- [ ] JSON-facing u64 IDs/versions are safe across Rust and TypeScript.
- [ ] Web has actual wallet, RPC and browser-prover adapters; disconnected fallbacks do not substitute for integrations.
- [ ] Keeper durably journals transaction hashes before broadcast and never retries an unknown outcome as a new spend.
- [ ] Real NEAR sandbox validates host verifier encodings, rejection paths and gas limits.

## Evidence so far

- `near-verifier` native tests passed with real Groth16 proofs, altered public input rejection and canonical scalar/proof checks.
- `verifier-probe` built for wasm32 with NEAR SDK 5.30.1 / Rust 1.95.0.
- Client typecheck and 10 unit tests passed for exact amounts, artifact hash/size validation, finalized RPC reads, pending outcomes and receipt-event filtering.
- Official current NEAR sandbox release 2.14.0 selected. Its archive is installed via `scripts/install-sandbox.mjs`, with bounded parallel ranges and official S3 ETag validation. The old near-workspaces dependency's auto-downloader is disabled; runtime uses an explicit local binary path.
