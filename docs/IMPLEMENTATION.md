# Implementation architecture

[SPEC.md](../SPEC.md) defines the protocol. The implementation co-locates private balances, loan transitions and the authenticated credit book in one NEAR Core contract. External NEP-141 deposits and payouts use explicit custody states because cross-contract receipts are asynchronous.

## Financial state

Core owns the immutable asset profile, public claims, vault shares, restricted broker balances, holder inbox/spending balances and encrypted loan records. Draws increase public broker debt. Private origination and repayment update encrypted balances and the loan book atomically. Settlement returns public liquidity, repays aggregate debt first and recognizes only excess yield.

Principal allocation, impairment and default update authenticated aggregates. Reconciliation proves the current loss and provision against those aggregates, their versions and prior public accounting. Pending reconciliation blocks risk creation and share pricing. Permanent proposal, loan, checkpoint and broker tombstones preserve replay protection and stable vault membership; terminal loan snapshots remain available for authorized historical audit.

Public quantities use exact integer arithmetic. Asset custody is capped at 2^63 - 1, while shares and cumulative counters use checked u128 values. Share products use full-width arithmetic. The UI distinguishes these limits from native NEAR storage deposits, which use u128 yoctoNEAR.

## Proof and encoding boundary

The concrete profile uses arkworks Groth16 over BN254, additive ElGamal and Pedersen commitments in the prime-order Edwards subgroup. Eight fixed proof families cover key possession, conversion, transfer, origination, repayment, reconciliation, zero state and balance ownership. [CRYPTO_PROFILE.md](CRYPTO_PROFILE.md) defines their relations and canonical encodings.

Core constructs statements from authoritative financial state and selects the immutable verification key by operation kind. Successful verification authenticates only the submitted statement's points. Persisted financial points can then be reused without repeating expensive subgroup checks. Provers cannot select their own verification relation or bypass a failed proof.

The crypto JSON layer represents canonical points and scalars as hex. Core ElGamal-key and ciphertext BLOB arguments contain structured, canonical JSON bytes represented as byte arrays; a raw point is not interchangeable with that BLOB. SDK adapters perform this conversion and reject private witness fields. Wide JSON integers remain decimal strings throughout the wallet, RPC and UI.

Verification keys are staged with prepaid deployer storage, checked against the pinned manifest and activated once. NEAR host pairing functions perform verification. Contract builds remove non-executable symbol metadata and check both required host imports and the deployment request size budget.

## Authorization and custody

Direct account calls and registered exact-operation signatures are separate from proof validity. Application keys can exist without a confidential holder balance. Signed envelopes bind the deployment, asset, owner, key ID, monotonic epoch, nonce and operation digest; see [AUTHORIZATION.md](AUTHORIZATION.md).

Incoming token callbacks authenticate the configured asset and create one idempotent public claim. Outgoing payouts reserve their claim and storage before dispatch. Their immutable call hash includes the exact method, recipient, amount and memo. Authenticated callback results are recorded before permissionless finalization; unknown results retain their reservations. Freezes block the specified financial sources and destinations while preserving safe accounting and payout-result recovery.

## Client operation

The wallet recovers balances and loan terms from finalized encrypted history using only the selected reader's keys. Proof preparation uses a finalized snapshot, merges an inbox when required and rebuilds on an explicitly stale state. Private material remains in a browser worker or the native prover process; encrypted backups provide recovery across sessions.

Proof-bearing calls receive the 300 Tgas transaction budget by default. The complete measured origination consumed 289.89 Tgas; measuring the verifier alone understates the budget required for authorization, storage and accounting. Callers may supply a smaller budget for operations such as storage funding.

The web application supplies lender, broker, borrower and auditor workspaces with real wallet, RPC and browser-prover adapters. A separate keeper has only delegated broker visibility and on-chain merge/settlement limits. Its journal persists signed transaction bytes before broadcast; unknown outcomes are never retried as a new spend.

Action feedback retains the public hash and signer for unresolved transactions and offers an explicit read-only status check. The active action stays locked while preparing, awaiting signing or pending. Resolution requires a matching transaction identity and FINAL execution status; an RPC failure or optimistic success cannot unlock it. Known contract errors are mapped to safe messages without exposing arbitrary receipt payloads.

## Deployment boundary

Generated local artifacts use a development single-party setup. Funded deployments require the independent review, setup evidence, target-runtime measurements and published trust policy specified in SPEC section 22.2. Immutable application verification keys do not remove a NEAR account's full-access upgrade authority; that account policy must be separately enforced and disclosed.

See [README.md](../README.md) for reproducible builds and tests, and [LOCAL_DEMO.md](LOCAL_DEMO.md) for the connected product flow.
