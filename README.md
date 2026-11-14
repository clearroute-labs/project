# clear — confidential lending on NEAR

An implementation of [SPEC.md](SPEC.md): public single-asset vaults fund broker-underwritten loans whose amounts, repayments and balances remain encrypted. The Core contract enforces confidential transfers and credit accounting with Groth16 proofs. Borrowers, brokers and designated auditors decrypt only their authorized views.

The credit model has no on-chain collateral or first-loss cover. Brokers underwrite borrowers off-chain. Fixed finance charges are agreed at origination; there are no late fees or time-based interest accrual. Public settlement repays vault debt before recognizing yield. Impairment and default reconciliation prevent lenders from redeeming against stale accounting.

## Run the app

The product defaults to NEAR testnet and uses NEAR Connect for wallet access. Install dependencies with `pnpm install --frozen-lockfile --ignore-scripts`, prepare the pinned public artifacts using [testnet setup](docs/TESTNET.md), and run `pnpm dev --host localhost --port 5175`. See [wallet setup](docs/WALLETS.md) and [web configuration](web/README.md).

Confidential keys can be saved encrypted in this browser and unlocked with a compatible passkey. Keep the encrypted recovery file for a new browser or lost browser data.

## Protocol development and sandbox verification

Use Node 24.11 or newer, the pinned pnpm version in `package.json`, and Rust through rustup. `rust-toolchain.toml` pins the compiler and WASM target.

```sh
pnpm install --frozen-lockfile --ignore-scripts
cargo install wasm-bindgen-cli --version 0.2.130 --locked --root .local/wasm-bindgen
pnpm install:sandbox
pnpm build:crypto
pnpm build:contracts
pnpm setup:development
pnpm demo
```

Development setup generates proving and verification keys for all eight proof families and pins every executable artifact in a deployment manifest. It resumes interrupted setup without changing completed keys. If source binaries change, choose a fresh output directory with `pnpm setup:development --output .artifacts/development-v2`; pass the same directory to `pnpm demo .artifacts/development-v2`.

The launcher starts an isolated NEAR sandbox, deploys the Core and a test token, stages the real verification keys, creates funded test accounts and opens the test-only wallet fixture at `http://127.0.0.1:5174/tests/browser/sandbox.html`. It serves only manifest-listed public cryptographic artifacts. Local account credentials are saved with owner-only permissions under `.local/demo/credentials/`. Import the chosen account in that test fixture to act as lender, broker or borrower. The sandbox stops when the launcher exits; its test assets have no monetary value.

`.local/demo/public.json` contains public deployment details and the loan auditor public key. The encrypted auditor wallet and its locally generated passphrase are separate owner-only files in the same directory. All generated keys, backups, artifacts and local chain files are excluded from Git.

Follow [the local product walkthrough](docs/LOCAL_DEMO.md) to create a vault, fund and repay a confidential loan, settle yield, withdraw and audit the terminal record.

Public deployments use NEAR Connect to select an ecosystem wallet. Optional Privy configuration adds email and Google login through an embedded NEAR wallet in the same selector. See [wallet setup](docs/WALLETS.md) for the public IDs, hosting requirements, account funding and verification steps.

## Components

| Location | Responsibility |
| --- | --- |
| `contracts/confidential-core` | Custody, public claims, vault shares, encrypted balances, loan state, accounting, authorization and immutable verifier keys |
| `crates/confidential-crypto` | Additive ElGamal, commitments, authenticated recovery data, proof circuits, native prover and browser WASM |
| `crates/near-verifier` | Groth16 encoding and prepared-key verification through NEAR BN254 host functions |
| `crates/lending-math` | Checked financial arithmetic and full-width share multiplication/division |
| `crates/authenticated-book` | Bounded authenticated loan-book updates and membership evidence |
| `packages/client` | Exact amount handling, finalized RPC, transaction outcomes and artifact pins |
| `packages/wallet` | Local key custody, encrypted backup, history recovery and concrete proof preparation |
| `web` | Lender, broker, borrower, auditor and operations screens |
| `services/keeper` | Restricted settlement signing, grant/cadence planning and durable transaction journal |

See [the cryptographic profile](docs/CRYPTO_PROFILE.md) and [the Core ABI](docs/CONTRACT_API.md) for wire formats. The wallet's `LedgerWallet` prepares `{ method, args }` calls from a single finalized block; secret witnesses never enter those arguments. Incoming token callbacks create idempotent public claims. Outgoing transfers reserve a claim before calling the token and require an authenticated result before finalization.

[Registered operation authorization](docs/AUTHORIZATION.md) describes exact-operation signatures for relayers and the portable client helpers.

## Verification

```sh
pnpm typecheck
pnpm test
cargo test -p lending-math -p authenticated-book -p near-verifier
cargo test -p confidential-crypto
cargo test -p confidential-core --features unit-testing
pnpm validate:crypto .artifacts/development
CRYPTO_ARTIFACT_DIR=.artifacts/development pnpm test:e2e
```

`validate:crypto` generates and verifies real native proofs for every family, checks changed-context rejection and writes public vectors and timing evidence. Sandbox tests use the pinned official NEAR runtime and real token receipts. The test token's failure modes are confined to `contracts/test-token`; it is not a production asset implementation.

For actual browser/WASM proof validation, install Chromium with `pnpm exec playwright install chromium`, keep `pnpm --dir web dev --host 127.0.0.1 --port 5174 --strictPort` running in another terminal, then run `CRYPTO_ARTIFACT_DIR=.artifacts/development pnpm validate:browser`. The harness verifies the original pinned artifact bytes and writes timings and allocated WASM memory to `.artifacts/browser-validation.json`. `VALIDATION_ORIGIN` selects another local Vite origin. The full suite generates large proofs and requires a desktop browser with sufficient memory.

The v4 profile passes native, Chromium/WASM and NEAR host verification for all eight proof families. Complete sandbox scenarios pass for lending, credit losses, token custody and the restricted keeper. The connected browser scenario also passes: agreement exchange, confidential funding/spending, both repayment modes, settlement, lender payout, archival, authorized audit and encrypted-backup restoration. Run `pnpm validate:product` against a fresh local demo to repeat it.

Complete origination measured 289.89 Tgas; repayment measured up to 268.77 Tgas. The client supplies 300 Tgas by default for these calls. Large browser proofs took about three minutes and allocated about 1.72 GB of WASM linear memory, in addition to browser/artifact memory. See [the verification record](tasks/implementation.md) for artifact hashes, measurements and test coverage.

## Keeper operation

The keeper uses a dedicated NEAR delegate account with a function-call access key restricted to this Core's `merge_broker_inbox` and `settle` methods. The broker owner grants on-chain limits and explicitly provisions only the required broker decryption keys. A function-call key does not provide private witnesses. Using the broker owner account is rejected because owner authority would bypass grant limits.

The service reads its pinned manifest, an encrypted keeper-only wallet backup, an owner-only NEAR credential file and a JSON configuration. The backup passphrase is piped through standard input, never placed in arguments or environment variables. A signed transaction is durably journaled before broadcast. An unknown outcome stays pending; explicit rebroadcast sends the identical signed bytes.

```sh
pnpm --filter @confidential-lending/keeper start run path/to/keeper.json < path/to/passphrase-file
pnpm --filter @confidential-lending/keeper start once path/to/keeper.json < path/to/passphrase-file
pnpm --filter @confidential-lending/keeper start rebroadcast path/to/keeper.json < path/to/passphrase-file
```

Start with `services/keeper/config.example.json`, replacing its RPC URL, manifest pin, broker IDs and paths with the deployment's values. The configuration fields are defined in `services/keeper/src/config.ts`. Paths resolve relative to the configuration file. Amount limits and broker IDs are decimal strings. Keep the journal when restarting a service or replacing credentials; deleting a pending journal is not recovery.

## Deployment trust and release gates

Development artifacts use a single-party setup and are labeled accordingly. No independent circuit review or production ceremony is implied. A funded release requires the evidence in SPEC section 22.2. `pnpm check:release path/to/release.json` checks artifact integrity, deployment pins, proof-family coverage, measurements and required evidence fields; it does not authenticate an auditor's work.

The Core has no application-level arbitrary-balance reset or verifier replacement after activation. A NEAR account's remaining full-access keys can still replace its deployed code; the actual account upgrade policy must therefore be disclosed and enforced at deployment. The configured token/controller can freeze transfers according to its published policy. Issuer, token-auditor and loan-auditor keys have distinct scopes. Provisioning a broker decryption key to a keeper gives that service the corresponding private visibility.

The sandbox launcher and tests do not deploy to public networks. `pnpm deploy:testnet` explicitly deploys the testnet contracts; see [TESTNET.md](docs/TESTNET.md) for the active deployment, public artifact packaging and test-token funding.
