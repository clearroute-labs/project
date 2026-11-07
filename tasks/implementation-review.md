# Implementation integration review

This is an internal engineering checklist, not an independent security audit.

## Components

- Main workspace: transport/client, BN254 NEAR host verifier/probe, integration tests, build/release tooling, keeper integration.
- Crypto worker branch `implement/crypto`, isolated `.worktrees/crypto`.
- Core worker branch `implement/core`, isolated `.worktrees/core`.
- Web worker branch `implement/web`, isolated `.worktrees/web`.

## Findings to verify before completion

- [x] Transfer/origination/repayment circuits prove key knowledge and a bounded sufficient sender balance. A ciphertext delta alone does not prevent negative private balances.
- [x] Borrower repayment decrypts stored O/Q/R with borrower secret; it never requires original broker encryption randomness or secrets for other readers.
- [x] Broker reconciliation decrypts C/active-principal/impaired-principal with broker secret, not unknown accumulated randomness.
- [x] Aggregate `active_principal` is H + I: book value is C + active_principal; healthy backing is C + active_principal - impaired_principal. Do not count I twice.
- [x] Circuit u128 high limb coefficient is 2^64, not 1^64; every limb/comparison is range checked and field wrap cannot satisfy conservation.
- [x] Repayment public-slot cursor order matches the statement exactly, including spending/loan versions.
- [x] R1CS conditional equalities use the condition argument correctly; valid full repayments and exact D = book reconciliation must be satisfiable. Negative tests bypass the honest prover's prechecks.
- [x] Recipient credits apply proven deltas to current inbox; proofs do not depend on an earlier recipient inbox/version.
- [x] Public conversion binds all holder/issuer/auditor copies; O/Q terms have only the three loan readers.
- [x] Recovery supports the full 63-bit amount domain and cannot be disabled by an adversarial unverified hint. Ledger history contains the necessary encrypted recovery data.
- [x] Transcript binding uses established primitives, not a newly invented x^5 sponge treated as a secure hash.
- [x] Core constructs typed statements from authoritative state and selects immutable per-kind verifier keys. Caller-chosen post states are not accepted without proved relations.
- [x] JSON-facing u64 IDs/versions are safe across Rust and TypeScript.
- [x] Web has actual wallet, RPC and browser-prover adapters; disconnected fallbacks do not substitute for integrations.
- [x] Keeper durably journals transaction hashes before broadcast and never retries an unknown outcome as a new spend.
- [x] First impairment can increase U with zero realized loss and zero prior U; reconciliation must not apply the false bound `new_U <= loss + old_U`.
- [x] Vault pending-accounting state clears only when every required broker checkpoint is current, without unbounded scans.
- [x] Positive-U settlement reconciles the same broker against its post-settlement state, including when its risk version was already reconciled.
- [x] Zero-balance closure uses verified plaintext-zero evidence, not equality with a canonical ciphertext; worthless-share burn and final dust rules are implemented.
- [x] Every persistent record is charged to an authorized storage payer; global custody cap includes all claims, vault cash, private balances and in-flight payouts.
- [x] An oversized successful payout return never becomes a failure/refund; duplicate finalization is idempotent even after the claim was consumed.
- [x] Deleted brokers do not break vault enumeration/final redemption. Terminal loan deletion relies on authenticated removal evidence.
- [x] Standard events include the `EVENT_JSON:` prefix and decimal-string wide integers.
- [x] Recovery correctness is enforced in proofs: a sender's signature over an incorrect recovery hint is not sufficient.
- [x] Public conversion gates sufficient-funds checks on Debit and overflow checks on Credit; first credit from zero must succeed. Direct circuit regression now passes.
- [x] Persisted loan P/R and cumulative repayments use borrower/broker/loan-auditor order, while transfer amounts use five readers.
- [x] Aggregate commitments update from the proved principal commitment/deltas and are never arbitrary caller replacements.
- [x] Runtime manifest hash pins executable browser glue/WASM and proving artifacts separately from the immutable cryptographic suite hash.
- [x] Callback/finalization storage is preallocated before an external payout; permissionless finalization needs no fresh caller storage budget.
- [x] Real NEAR sandbox validates host verifier encodings and rejection paths for a 193-input fixture. Final v4 host and complete lending gas have also been measured; see implementation.md.

## Evidence so far

### Final conformance pass

The following concrete gaps were found during implementation. Checked items have been resolved and exercised; remaining items block final acceptance:

- [x] Require exact proposal reader counts and validate every persisted ciphertext; no trailing unvalidated vectors.
- [x] Implement amount-specified redemption with ceiling rounding and a maximum-share guard.
- [x] Enforce full loan maturity, grace period and redemption buffer for closed-ended vaults.
- [x] Increment origination accounting versions and bind the complete loan leaf and current book root.
- [x] Charge proposal signatures and revocation tombstones to an authorized storage payer.
- [x] Expose the immutable authorization policy and required public accounting counters.
- [x] Emit proof-authoritative ciphertexts or durable recovery references for compact calls.
- [x] Bound proof/proposal parsing and final-redemption proof batches; keep sequential broker closure executable.
- [x] Keep wide IDs canonical across every current and compatibility API.
- [x] Enforce encryption/recovery randomness, ownership ranges and u128 limbs inside the circuits; regenerate the profile and all keys.
- [x] Recover token-auditor balances from finalized history using only authorized auditor keys.
- [x] Review agreement plaintext against finalized proposal fields using bounded recovery data.
- [x] Merge inboxes before proof construction when required spending exceeds the available spending balance.
- [x] Exercise connected browser operations, backup restore and authorized audit against the deployed contract.
- [x] Keep every SDK and dashboard list page within Core's 50-record bound, including filtered lists and broker enumeration; test beyond the first page.
- [x] Expose real storage funding in the UI and charge the initial storage-budget record to its creator.
- [x] Retain terminal loan snapshots for authorized historical audit, and consume deletion history records without breaking broker recovery.
- [x] Supersede stale prepared checkpoints without blocking reconciliation or keeper settlement; retain permanent checkpoint IDs and the original pending cadence.
- [x] Constrain randomness below the Edwards subgroup order inside R1CS, and reject conversion credit overflow without truncating its carry bit.
- [x] Charge verifier installation to the deployer's prepaid storage budget before activation.
- [x] Require terminal loan archival and proposal resolution before broker closure; preserve stable vault membership tombstones.
- [x] Complete exact-operation relayed origination and enforce the declared account-freeze policy across public and private financial paths.
- [x] Bind registered authorization signatures to deployment, owner, key ID, epoch, nonce and the exact operation digest; reject reuse through another registration of the same public key.
- [x] Permit application authorization keys without a holder balance, preserving monotonic epochs across registration and revocation.
- [x] Include the exact dispatched method and message in each immutable outgoing payout call hash.
- [x] Strip non-executable contract symbols and enforce the deployment RPC size budget; rerun real deployment against the resulting artifact.
- [x] Exercise unknown payout results without refunding or releasing their reservations, and emit all affected authoritative financial versions.

The persisted-state decoder optimization is restricted to Core's authenticated fixed financial slots. The read-only provenance audit confirmed those slots originate in validated keys, successful proof statements or trusted group arithmetic. Proposal vectors now require exact reader counts and validation before persistence.

Latest artifact hashes, test results, gas, transaction sizes and storage measurements are recorded in [implementation.md](implementation.md). Earlier fixture and pre-hardening measurements are superseded for final acceptance.

Final browser checks identified additional integration issues: native NEAR storage amounts were parsed under the private asset cap, and final redemption still expected proofs for closed broker tombstones. Both are corrected and covered by focused tests, including pinned closure reads. Background refresh now preserves mounted forms and transaction feedback when a finalized snapshot exists. Proposal expiry is checked before and after proving, and the client's default 300 Tgas budget covers the complete measured origination and repayment calls. The connected scenario passes through lender payout, archived audit and restoration of an earlier borrower backup; public evidence is recorded in .artifacts/product-validation.json.
