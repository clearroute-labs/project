# clear — confidential lending on NEAR

Clear is a confidential lending prototype on NEAR. Lenders fund public vaults, brokers arrange loans, and borrowers manage encrypted loan amounts and balances. Cryptographic proofs let the contract verify operations, while designated auditors can decrypt the views they are authorized to inspect.

**[Try the testnet app](https://clear-near.vercel.app)** · **[Protocol specification](SPEC.md)** · **[Local demo walkthrough](docs/LOCAL_DEMO.md)**

Clear implements [SPEC.md](SPEC.md), which defines the credit model, privacy boundaries, accounting rules and release requirements. The sections below introduce the product; the specification remains the reference for protocol behavior.

## Why Clear?

On-chain credit needs verifiable accounting, but publishing every loan amount exposes sensitive financial information. Clear separates public vault accounting from encrypted loan data. Lenders can inspect the vault's public position without automatically gaining access to each borrower's private loan terms.

## How it works

1. **A lender deposits into a vault** and receives shares representing their position in its public accounting.
2. **A broker evaluates the borrower off-chain** and proposes an encrypted loan agreement. Both parties must authorize the same agreement before funding.
3. **The borrower receives funds and repays privately.** Proofs check the confidential operations against the contract's rules.
4. **The broker settles funds back into the vault.** Settlement repays vault debt before recognizing yield; lenders can redeem shares under the vault's accounting and withdrawal rules.
5. **An authorized loan auditor can inspect the loan.** Audit access is scoped to the encrypted views designated for that auditor.

For a successful-loan example, see [SPEC section 23.2](SPEC.md#232-successful-loan-and-yield). For the corresponding product screens, follow the [local walkthrough](docs/LOCAL_DEMO.md).

## What is public, and what is private?

| Data | Visibility |
| --- | --- |
| Loan principal, amount owed, periodic payment and individual repayment amounts | Encrypted; readable through authorized views |
| Confidential wallet and broker balances | Encrypted; readable through authorized views |
| Vault totals, shares, broker debt, draws and settlements | Public |
| Account identities, loan relationships, payment schedules, status and transaction timing | Public |
| Public deposits, redemptions and external payouts | Public, including their amounts |

Amount confidentiality does not provide anonymity. Public entry/exit amounts can correlate with private activity, and an aggregate containing only one loan can reveal that loan's amount. See [SPEC section 4](SPEC.md#4-roles-and-public-visibility) for the complete visibility model.

## Try it

Open **[clear-near.vercel.app](https://clear-near.vercel.app)** on a desktop browser and connect a NEAR testnet wallet. In **Get test funds**, register token storage and claim TEST tokens; testnet NEAR is also required for gas and storage. Before private operations, open **Wallet & security**, add a Core storage budget, generate confidential keys, save the encrypted recovery file and register the key on-chain. Switch between the lender, broker, borrower and auditor workspaces to explore their roles.

Confidential keys can also be saved encrypted in this browser and unlocked with a compatible passkey. Keep the recovery file for a new browser or lost browser data. See [wallet setup](docs/WALLETS.md) for wallet options and optional email/Google login configuration.

**Current status: testnet prototype.** Test assets have no monetary value. Development proving keys use a single-party setup; this is not an independently reviewed or production-ready release. Large browser proofs can take about three minutes and allocate about 1.72 GB of WASM memory, in addition to other browser memory. The full lending lifecycle has been verified against real contracts in local sandbox; this does not claim a complete loan lifecycle on public testnet.

There is no on-chain borrower collateral or first-loss cover. Brokers assess creditworthiness off-chain; proofs verify protocol rules, not a borrower's ability to repay. Lenders bear credit and liquidity risk and can lose capital. Fixed finance charges are agreed at origination, with no late fees or time-based interest accrual. Impairment and default reconciliation prevent redemption against stale accounting.

## Run locally

For a local testnet client, install dependencies with `pnpm install --frozen-lockfile --ignore-scripts`, prepare the deployment's matching pinned artifacts using [testnet setup](docs/TESTNET.md), and run `pnpm dev --host localhost --port 5175`. A local checkout and the hosted app may target different deployments: the public proving bundle must match the selected Core account and manifest pin. See [web configuration](web/README.md).

To run the complete flow with fresh local test accounts, use the sandbox setup below.

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
