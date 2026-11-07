# Complete protocol implementation

The user authorized implementation of the whole SPEC.md on 2026-11-06. This supersedes the earlier research-only scope. Preserve its economics, confidentiality, audit roles and all five approved improvements. No public deployment, funded release or claims of an independent security audit are authorized or implied.

## Plan

- [x] Establish a pinned Rust/TypeScript workspace and exact protocol/cryptographic interfaces.
- [x] Implement real confidential encryption, recoverable wallet data, proof circuits, setup/proving and verification.
- [ ] Implement the NEAR Core: assets, holder registration, custody, vaults, shares and authorization.
- [ ] Implement broker balances, jointly authorized origination, confidential transfers/payments, management and aggregate accounting.
- [ ] Implement idempotent token ingress, reserved payouts, result recording and finalization.
- [ ] Implement the wallet/application, SDK, auditor access and scoped settlement keeper.
- [ ] Integrate real proofs and callbacks through complete lending/default/withdrawal scenarios.
- [ ] Run adversarial arithmetic, authorization, privacy, replay, callback, build and UI checks; resolve failures.
- [ ] Document reproducible local operation, deployment artifacts, verification evidence and release gates.

## Execution

Use isolated git worktrees for independent writing workers. Shared interfaces are established by the main thread before integration. No production proof bypasses, plaintext confidential contract state or fabricated successful transactions. Development-only setup material must be unmistakably labeled and excluded from funded releases. Cryptographic implementation is subject to the independent-review requirement in SPEC.md.

## Review

Pending implementation and verification.

Verified components so far (not full protocol acceptance):

- Pinned Rust/TypeScript workspace, client transport, artifact validation and reproducible sandbox installation.
- Real Groth16 host verification in NEAR sandbox; prepared-key optimization measured against a 193-input fixture.
- Exact lending/share arithmetic: 12 tests, including all financial worked examples and 10,000 full-width integer cases against an independent BigUint oracle.
- Durable keeper journal and restricted signer: seven crash/retry/identity/finality tests.
- Core, cryptographic circuits and the application are integrated on main. Focused worker branches are completing authenticated-book, minimal wallet ABI, browser execution and target-runtime verification findings.

Integration update:

- Client: 12 tests passed, including one-block finalized snapshots and a deployment manifest pin covering every executable artifact.
- Wallet: 11 tests passed for private key import/export, cancellation, native process isolation, encrypted backups, and incomplete/tampered recovery history. Actual native client validation passed all eight proof families, including both conversion modes and regular/full repayments. Public statements, envelopes and timings are in `.artifacts/integration-v2/client-operations.json` and `client-validation.json`.
- Development setup resumes without regenerating keys, validates all resumed artifacts, and refuses changed binaries/deployment identity. Its restart/tampering test passed.
- Cryptographic worker crate: 11 tests passed, including real key-possession and confidential-transfer proofs; direct circuit checks cover conversion solvency, full repayment and reconciliation. Full client, browser and contract execution remain pending.
- Contract review is resolving typed statement/state binding, three-reader loan terms, authenticated book updates, durable recovery history, and callback storage allocation.
- Native crypto and WASM browser artifacts build; strict crypto Clippy passes. Core/test-token/probe WASM builds pass. Workspace TypeScript checks and 56 tests pass (12 client, 11 wallet, 10 keeper, 21 web, two tooling).
- Actual sandbox custody integration exposed the missing payable annotation on Core storage deposits. The fix is applied and the token callback/recovery test is being rerun; successful deployment alone is not custody acceptance.

2026-11-07 integration evidence:

- Real NEAR custody test passed: canonical duplicate deposits, forged callback rejection, failed payout restoration, oversized successful return, permissionless/idempotent finalization, and IDs above JavaScript's safe integer range.
- All eight proof families passed in Chromium using the pinned WASM worker; both repayment modes and modified-context rejection were exercised. Largest measured operation in the first browser build was regular repayment at 129,271 ms. Native and browser validation now share one fixture implementation.
- The integrated workspace has 69 passing TypeScript tests (12 client, 15 wallet, 12 keeper, 28 web, two tooling). Strict package typechecking exposed additional optional-property issues in the new web-facing wallet adapter; these are being corrected.
- The real lending scenario passes registration, vault deposit, broker draw/merge, borrower shielding/merge, proposal creation and borrower consent. Origination still exceeds 300 Tgas in the initial contract build; full lifecycle acceptance remains open.
- Fixed the contract build's missing `--cfg near`, which made the pinned NEAR SDK select local panic/hash implementations. Builds now assert required NEAR host imports. Release optimization targets execution cost (`opt-level = 3`).
- Added real multi-broker impairment/default/redemption and restricted-keeper restart/limits/revocation scenarios. Their acceptance awaits the remaining contract/verifier integration fixes.

Current v3 verification:

- Replaced repeated host subgroup checks with in-circuit cofactor-preimage constraints for every typed statement point. Generic point decoding stays strict; successful proof verification promotes only that statement's points. The cryptographic profile changed and all eight development key sets were regenerated in `.artifacts/integration-v3`.
- Core now binds staged keys to the complete canonical deployment manifest, validates its identity, and permits no proof state transition before activation. Actual deployment caught and resolved the transcript-digest input-count offset.
- Holder rotation proves the old total balance is zero, preserves freezes, and records an immutable recovery-history boundary. Broker settlement can atomically derive and consume a reconciliation checkpoint, including through restricted keeper keys.
- Application screens now expose shield/unshield, share transfers, loan/broker closure, auditor recovery, and proof-backed final redemption. Chromium renders desktop/mobile; live UI operation and mobile workspace selection remain under verification.
- Fresh native/browser proofs and complete lending, loss, and keeper scenarios are running. Earlier v2 results do not establish v3 acceptance.

Latest verified results:

- The v3 native and Chromium runs both passed all eight proof families, including both conversion and repayment modes. Chromium's largest measured proof took 131,158 ms; its WASM linear-memory high-water allocation was 988,020,736 bytes. This is allocated WASM memory, not a measured whole-process peak.
- All eight v3 families verify through the actual NEAR host verifier. The largest measured typed verification call was full repayment at about 242 Tgas; complete Core execution has a separate gas budget and remains under test.
- Core: 18 unit tests and strict Clippy pass. Shared crates: 13 arithmetic tests, two authenticated-book tests and two host-verifier tests pass.
- A real restricted keeper now passes merge, per-operation/window settlement limits, journal restart and execution-time revocation against the v3 sandbox. Sandbox time advances now wait for finalized state before timestamp-dependent assertions.
- Compacted proof transport removes duplicated public-input vectors; Core derives them from the typed statement and authoritative state. No proof relation or verifier key changed.
- Reusing subgroup membership of authenticated persisted financial points brings complete regular and full Core repayments below the execution limit: both reached successful storage updates at approximately 274 Tgas. Origination succeeds at approximately 288 Tgas in the same v3 build. The complete economic scenarios continue beyond these transitions; these measurements do not yet establish final-profile acceptance.
- A second conformance review identified missing amount-based redemption, closed-vault maturity checks, complete book-root/leaf binding and signature storage charges. Those fixes are in progress, alongside real auditor recovery and browser agreement/inbox workflows. The next cryptographic profile moves all randomness/range checks into R1CS and removes duplicated reader-key inputs; its artifacts and proofs must be regenerated and revalidated.
- The full v3 lending scenario now passes (554 seconds): jointly authorized origination, private transfer, regular/full repayment, concurrent inbox credit, replay rejection, yield settlement, partial/final lender withdrawal through actual token receipts, terminal loan/broker closure, and zero-balance holder rotation preserving issuer freeze. Separate keyrings containing only the issuer or token-auditor key recover authoritative mirrors, including after rotation. Evidence is `.artifacts/lifecycle-benchmark.json` and `.artifacts/lending-v3.log`; the recorded Core WASM hash is `cc442c688aefc4a0b94dd84b5bf22c633ac783435c57182328c71988c981f241`. This run predates the amount-specified redemption and final v4 contract changes.
- Expanded actual custody checks pass (111 seconds), including mismatched deposit-ID refund and result finalization under an asset freeze while new payout dispatch is rejected. The integrated TypeScript suite has 83 passing tests and the production browser build passes.
