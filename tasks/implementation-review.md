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
- [ ] First impairment can increase U with zero realized loss and zero prior U; reconciliation must not apply the false bound `new_U <= loss + old_U`.
- [ ] Vault pending-accounting state clears only when every required broker checkpoint is current, without unbounded scans.
- [ ] Positive-U settlement reconciles the same broker against its post-settlement state, including when its risk version was already reconciled.
- [ ] Zero-balance closure uses verified plaintext-zero evidence, not equality with a canonical ciphertext; worthless-share burn and final dust rules are implemented.
- [ ] Every persistent record is charged to an authorized storage payer; global custody cap includes all claims, vault cash, private balances and in-flight payouts.
- [ ] An oversized successful payout return never becomes a failure/refund; duplicate finalization is idempotent even after the claim was consumed.
- [ ] Deleted brokers do not break vault enumeration/final redemption. Terminal loan deletion relies on authenticated removal evidence.
- [ ] Standard events include the `EVENT_JSON:` prefix and decimal-string wide integers.
- [ ] Recovery correctness is enforced in proofs: a sender's signature over an incorrect recovery hint is not sufficient.
- [ ] Public conversion gates sufficient-funds checks on Debit and overflow checks on Credit; first credit from zero must succeed. Direct circuit regression now passes.
- [ ] Persisted loan P/R and cumulative repayments use borrower/broker/loan-auditor order, while transfer amounts use five readers.
- [ ] Aggregate commitments update from the proved principal commitment/deltas and are never arbitrary caller replacements.
- [ ] Runtime manifest hash pins executable browser glue/WASM and proving artifacts separately from the immutable cryptographic suite hash.
- [ ] Callback/finalization storage is preallocated before an external payout; permissionless finalization needs no fresh caller storage budget.
- [x] Real NEAR sandbox validates host verifier encodings and rejection paths for a 193-input fixture. Full lending circuit gas remains to be checked.

## Evidence so far

- `near-verifier` native tests passed with real Groth16 proofs, altered public input rejection and canonical scalar/proof checks.
- `verifier-probe` built for wasm32 with NEAR SDK 5.30.1 / Rust 1.95.0.
- Client typecheck and 10 unit tests passed for exact amounts, artifact hash/size validation, finalized RPC reads, pending outcomes and receipt-event filtering.
- Official current NEAR sandbox release 2.14.0 selected. Its archive is installed via `scripts/install-sandbox.mjs`, with bounded parallel ranges and official S3 ETag validation. The old near-workspaces dependency's auto-downloader is disabled; runtime uses an explicit local binary path.
- Real sandbox verification passed for valid/modified/malformed proofs. For 193 public inputs, raw VK decompression cost 241,940,723,110,140 gas; prepared host-coordinate keys reduced verification to 112,353,750,400,779 gas. Prepared-key initialization cost 100,271,579,054,001 gas. Core therefore needs staged immutable per-kind key installation before activation; full circuits may have more inputs and must be measured.
- Keeper engine/signer: seven tests passed for durable-before-broadcast journaling, lost RPC responses, restart, concurrent processes, identical-byte rebroadcast, restricted function-call keys, signature validation and finalized outcomes. Contract-aware planning remains to be integrated.
- Expanded synthetic host fixture with 321 public inputs passed on NEAR 2.14.0: verification 157,088,779,560,055 gas; one prepared key initialization 147,926,033,555,545 gas. This measures the host adapter, not complete lending contract calls.
- `lending-math`: 12 tests passed; full-width multiplication/division checked on 10,000 cases against BigUint. Covers principal allocation, both settlement/default orderings, recycled income, impairment/default NAV continuity, multi-broker provision replacement, share rounding, sole-owner waiver, worthless-share burns and schedule overflow. Clippy passed with warnings denied.
- Browser proof transport: three tests passed for initialization gating, message matching, worker termination/cancellation and exclusion of exception text that may contain witnesses. Actual WASM operation integration remains pending.
