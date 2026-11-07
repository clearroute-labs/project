# Testnet application

The app defaults to this live deployment:

| Setting | Value |
| --- | --- |
| Network | NEAR testnet |
| Core | `clearroute-core-312a0a7a.testnet` |
| Test asset | `clearroute-token-312a0a7a.testnet` |
| Asset | TEST, 6 decimals |
| Crypto profile | `a4827cac06c9581120a6b10555397b499568b6ae89fc3d363816167648c80b3d` |
| Manifest pin | `b2a94cc9d734cc7df5b1f060a7191dc36b62b8748df106b41a98b003f34ab41b` |

Core has all eight verifier families activated. Testnet assets have no monetary value. This deployment uses the existing development proving keys and retains operator-controlled NEAR account access keys; it is not a production ceremony or immutable-code release.

## Start and use the app

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm dev --host localhost --port 5175 --strictPort
```

Open `http://localhost:5175`. The public proving artifacts must already be prepared as described below. No sandbox account credentials are accepted by this application.

1. Connect a testnet wallet through NEAR Connect. Optional Privy login requires the public app/client IDs described in [WALLETS.md](WALLETS.md).
2. Obtain gas and storage funds from the [NEAR testnet faucet](https://docs.near.org/getting-started/faucet).
3. In **Get test funds**, register token storage with 0.01 testnet NEAR, then claim 1,000 TEST. Each account may claim once.
4. In **Wallet & security**, add a Core storage budget before registering protocol records. Generate confidential keys, export and confirm an encrypted recovery file, then register the key on-chain.
5. Choose **Save with passkey** for everyday access in this browser. On a later visit, connect the same NEAR account and choose **Unlock with passkey**. The recovery file is still needed if the browser data is lost or on a different device.
6. Use the broker workspace to create a vault and broker; use the lender workspace to fund public claims and deposit into a vault. Borrower/broker loan agreement and repayment actions use the same real Core protocol as the integration suite.

## Public artifacts

The app serves only a verified allowlist of public proving files at `/crypto/`. Private deployment credentials and auditor keys stay in owner-only files under `.local/testnet/`. The 300+ MB proving bundle is excluded from Git.

Given the deployment operator's matching public bundle:

```sh
pnpm prepare:testnet-web .local/testnet/public.json .artifacts/testnet
pnpm dev --host localhost --port 5175 --strictPort
```

Preparation checks the deployment identity, manifest pin and each artifact hash, then stages public files into `web/public/crypto/` and writes the public frontend defaults. It never copies the private deployment directory. Do not generate new proving keys for an already activated Core: its immutable verifier configuration will reject them.

For website hosting, run `pnpm --dir web build` after preparation and host the complete `web/dist/` directory over HTTPS, including `/crypto/`. Large file limits must accommodate the largest proving key (about 129 MB). This workspace serves the bundle on localhost; no separate permanent public artifact host has been provisioned.

## Deployment operator

```sh
pnpm build:contracts
pnpm deploy:testnet
pnpm prepare:testnet-web
```

The deployment command creates/funds testnet accounts, verifies/copies the selected public proving artifacts, deploys Core and the test token, registers Core to receive the token, stages verifier keys and validates the resulting on-chain profile. It persists account credentials before requesting account creation, retains transaction hashes as it progresses, and checks existing Core pins and issuer/auditor keys before resuming. A different token binary requires the explicit `TESTNET_ALLOW_TOKEN_UPGRADE=true` option; a different Core binary is refused.

For a new deployment, first build the crypto binaries and run `pnpm setup:development` as described in the root README, or set `CRYPTO_ARTIFACT_SOURCE` to an existing complete development bundle. Subsequent runs reuse `.artifacts/testnet` by default. `TESTNET_LOCAL_DIR`, `TESTNET_ARTIFACT_DIR`, `CONTRACT_ARTIFACT_DIR` and `NEAR_TESTNET_RPC_URL` select operator paths and the HTTPS RPC. `--owner`, `--core` and `--token` select existing accounts with matching credential files; without those options, missing credentials are generated. Helper funding remains subject to testnet faucet availability.

Exact deployed WASM binaries are retained under `.artifacts/testnet/contracts` and reused by default. Keep these bytes: a rebuild from another checkout can produce a different binary. For an intentional token upgrade, point `CONTRACT_ARTIFACT_DIR` at a directory containing the archived Core binary and the reviewed new token binary, and explicitly enable the token-upgrade option.

Keep `.local/testnet/` and the matching `.artifacts/testnet/` bundle for subsequent verification and operator actions. Never put the account key files, issuer/auditor secrets or unencrypted wallet material in Git or web hosting.

The test asset is a development contract with an explicit owner and test controls, not a production stablecoin. Core's credit model and lender accounting do not change for this deployment.

## Verified live operations

The deployment smoke check finalized these transactions and checked their resulting state:

| Operation | Testnet transaction |
| --- | --- |
| Register Core to receive TEST | `9YWyMkaHiGMmhhMdJz3gieaeEBQkL2rhbKnD91WeBBRg` |
| Claim 1,000 TEST | `8Day3iK1SbEvCYP5WhrZUWpSJ7AL4rZeuJstitNzJGd7` |
| Reject a repeated faucet claim | `4dHihfjYFk582Pq9rbA3Ghkb9ArZ1i6iZD9vwY6rdxSA` |
| Register holder encryption key with a real proof | `AKyTTyrcorhZ9MHWRMVz5QDMLSLsrNbULG2aFo8jjiMe` |
| Deposit 100 TEST into Core; accepted claim `1` | `4MXRFxWmoFPDsn2LfjFibYxgNpadCGeJ4kVBZfNz4PTm` |

Browser verification covers the finalized AssetProfile, faucet views, manifest-pinned WASM, the real NEAR Connect wallet picker and WebAuthn PRF enrollment/reload/unlock. Passkeys were exercised with Chromium's virtual authenticator; physical Touch ID/Face ID was not exercised. Full lending scenarios remain covered by the real-contract sandbox suite; this testnet smoke does not claim a complete public-testnet loan lifecycle.
