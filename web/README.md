# clear web application

This directory contains the React/Vite wallet application for the NEAR confidential lending protocol.

## Run locally

```sh
cp .env.example .env.local
pnpm install
pnpm --filter confidential-lending-web dev
```

The app defaults to the deployed Core/token and manifest pins in `src/config/testnet.json`; prepare its public artifacts as described in [testnet setup](../docs/TESTNET.md). It connects through NEAR Connect, including ecosystem wallets and optional Privy social login. A wallet can connect before deployment configuration is complete; lending requires the deployed Core/token and pinned crypto manifest. See [wallet setup](../docs/WALLETS.md). The product never imports account credential files or installs a sandbox signer.

Sandbox signing is isolated in `tests/support/sandboxWallet.ts` and the development-only `/tests/browser/sandbox.html` fixture. The local validation launcher opens that fixture explicitly; it is not a Vite production build entry.

## Routes

`/` is the public landing page. `Open app` opens `/app`; workspace navigation uses hashes such as `/app#/borrower/agreements`. Existing root hash links redirect to `/app` while retaining their destination. `/wallet/privy` remains the social-wallet callback route. Configure static hosting to serve `index.html` for `/app` and `/wallet/privy`. Wallet and cryptographic services initialize only when the app is opened.

## Visual conventions and checks

The desert identity uses warm ivory, charcoal, copper accents, the angular clear wordmark and locally served Archivo Variable. IBM Plex Mono remains reserved for identifiers. Licensed fonts live in `public/fonts`; responsive WebP dunes weigh approximately 64 KiB (desktop) and 16 KiB (mobile). No remote font, design CDN or illustrative account balance is loaded by the product.

The landing loads the wallet application only after entry. Its terrain-following canvas grain is capped at 30 fps and DPR 1.5, pauses offscreen/in hidden tabs, and respects reduced motion. Keep animation out of data views. The workspace follows the approved composition: a dark desktop sidebar with role selector, editorial route headings, a dunes/privacy aside, a modal mobile menu, stacked mobile records and task drawers. Disconnected users can navigate every workspace; each route renders its own context and connection prompt without invented balances. Only account reads and operations require the wallet. Overview URLs include the role so refresh and browser history preserve it. Drawers retain entries while closed on the same route; navigation, account changes and session locking discard them. Failed reads hide and disable stale data while preserving mounted forms for a successful retry. Never persist plaintext drafts or private review data to storage.

Financial forms require a local review before their existing validation/proof/wallet handler runs. File contents, passwords, key material and textareas are hidden in that review. Pending-transaction locks remain in the action layer. Claims are explained as public receipts; checkpoints as accounting snapshots. Public boundary amounts must never be presented as confidential.

From repository root, with the development server running:

```sh
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-navigation.mjs
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-design.mjs
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-disconnected-routes.mjs
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-interactions.mjs
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-accessibility.mjs
UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-dev-boundaries.mjs
```

Use `UI_BROWSER_CHANNEL=chrome` for installed Chrome. Design checks cover populated/empty/loading/error states at 1440, 768, 390 and 320 px. Interaction checks cover retained entries, focus wrapping, Escape and review cancellation. axe checks WCAG 2.2 AA rules on public pages, workspaces and open task dialogs; this is not an accessibility certification or a substitute for assistive-technology testing. Synthetic fixtures never verify payments.

For a repeatable local performance sample, build, serve `pnpm --dir web preview --host 127.0.0.1 --port 4176`, then run `PERF_BASE_URL=http://127.0.0.1:4176 node web/tests/browser/test-performance.mjs`. It records LCP, layout shifts, resource bytes and animation long tasks under 4× CPU slowdown and a simulated 1.6 Mbps / 150 ms connection in `.local/performance.json`. Local measurements are not field data. The optional Privy popup bundle remains large and does not load on the landing.

The development port defaults to 5174 and advances if occupied. There is no lint script; run the documented build, typecheck and existing tests before committing.

## Account metrics and realized yield

Overview metrics are scoped to the connected account and role. The lender value is the integer pro-rata share of net vault assets, after provisions; it is unavailable when accounting or share balances are incomplete. Available claims exclude reserved/paid receipts. Unresolved payouts include recorded results awaiting finalization. Broker metrics include only owned broker accounts and their loan book; borrower metrics include only agreements where the account is the borrower. Audit metrics describe the current explicitly decrypted result, never inferred reader authorization.

`cumulative_yield` and `cumulative_realized_losses` are public broker counters. Realized yield is settlement surplus after principal repayment (SPEC.md §12.2), not the finance charge promised at origination. Broker performance covers currently owned active account records. Lender performance aggregates complete counters for the vaults where the account currently holds shares, with membership and broker reads pinned to one finalized block when supported. Optional yield reads run in batches of eight; failure cannot block account loading or become an invented zero.

A deleted broker's tombstone has no historical yield counters, so a vault with incomplete history displays unavailable performance. Gross yield and realized losses are shown separately; net realized result excludes unrealized provisions. These lifetime vault totals are not the shareholder's personal profit. Personal P&L and APY need deposit, withdrawal and share-transfer history and are not inferred from current ownership or share price. No private amounts are automatically decrypted for metrics.

Run `UI_BASE_URL=http://localhost:5174 node web/tests/browser/test-workspace-metrics.mjs` to check displayed values while changing roles. Unit tests cover multi-role wallets, exact large-number arithmetic, stale accounting, incomplete history and negative realized results.

## Integration boundary

`src/lib/types.ts` is the browser-facing contract between the UI, the NEAR client and the crypto worker:

- `ProtocolClient` reads finalized public/ciphertext state and submits typed Core actions. `src/lib/nearClient.ts` maps every action to the documented Core ABI through `@confidential-lending/client`'s HTTPS JSON-RPC and final-outcome transport.
- `WalletAdapter` owns NEAR Connect session state and forwards exact reviewed actions to the selected wallet. Optional Privy login uses an origin-isolated executor page.
- `CryptoProvider` owns browser-local key material, WASM artifact/profile validation, key-registration/PoP preparation, proof preparation (including merge, draw, broker-only origination, repayment, settlement and reconciliation), direct loan-management preparation, and explicit decryption. Witnesses and decrypted values must not be sent to RPC or telemetry.

`src/lib/nearClient.ts` maps those typed operations to the Core method names from `SPEC.md`. `src/lib/workerCrypto.ts` is the fail-closed worker transport for the reviewed WASM module; a module is accepted only when its profile and artifact hashes match the deployment manifest. Root integration may inject a reviewed crypto provider before mounting the app.

Deployment values are read from `VITE_NETWORK_ID`, `VITE_CORE_ACCOUNT_ID`, `VITE_TOKEN_ACCOUNT_ID`, `VITE_RPC_URL`, `VITE_ALLOW_INSECURE_LOCALHOST`, `VITE_CRYPTO_PROFILE_HASH`, `VITE_CRYPTO_ARTIFACT_HASH`, `VITE_CRYPTO_MANIFEST_URL`, `VITE_CRYPTO_ARTIFACT_BASE_URL`, `VITE_FUNDED_DEPLOYMENT`, `VITE_ASSET_DECIMALS`, `VITE_ASSET_SYMBOL` and `VITE_TESTNET_FAUCET`. Supplying a custom contract/profile override disables bundled contract/profile defaults; supply the complete custom deployment together. RPC URLs must not contain credentials; production RPC must use HTTPS. The localhost HTTP opt-in is accepted only by the test fixture; the product always requires HTTPS RPC.

The browser crypto bridge must implement the `CryptoProvider` interface in
`src/lib/types.ts`. Every `PreparedProof` carries canonical Statement JSON,
hex `context`, `proof`, public inputs and profile/artifact hashes. Its `operationArgs` uses
the Core ABI snake_case names for ciphertexts, commitments, roots, versions
and reconciliation outputs only; the RPC mapper converts those documented
byte fields to `Vec<u8>` and rejects unknown/private keys. Proposal creation
also supplies five principal views, three owed views, three payment views,
their three commitments, and the auditor public key. Broker origination
uses `prepareBrokerOrigination`; borrowers only decrypt/review and call
`authorizeAgreement`. Holder and broker key registration proofs are nested
Core `ProofArgs` envelopes, not fabricated signature strings.

`packages/wallet/src/core.ts` contains the reusable finalized-read/proof-context
`CoreWallet` boundary used by the worker and native keeper. Its constructor is
`new CoreWallet(rpc, configuration, crypto, keys, proofs, recovery?)`; the
important methods are `read`, `getProofContext`, `listRecoveryHistory` and
`prove`. The browser worker then composes that boundary with the concrete
`LedgerWallet` from `@confidential-lending/wallet` for registration, merge,
draw, transfer, origination, repayment, settlement and recovery.

`CryptoProvider.prepareAgreement` is the broker-side draft boundary. It
receives base-unit decimal strings and registered reader public keys, keeps
amount randomness and recovery witnesses in the browser worker, and returns
only the encrypted agreement envelope, ciphertext views, commitments and
public recovery pairs. The UI will not publish a proposal until this worker
step succeeds; an encrypted wallet backup is the explicit recovery path for a
draft kept across sessions.

## Privacy and money rules

Amounts are parsed and formatted as decimal strings with `BigInt` base units. Private terms and balances are represented by ciphertexts/commitments until the user deliberately decrypts them. Wallet backup encryption is provided by the shared `@confidential-lending/wallet` PBKDF2-SHA-256/AES-256-GCM implementation and is downloaded as an encrypted file; no secret is put into `localStorage`. The UI requires an explicit saved-backup confirmation before registering a newly generated holder/broker key or receiving/decrypting a loan proposal, and scopes that confirmation to the connected account and deployment.

All action controls report `pending`, `failed`, and `unknown` states separately. An unknown payout result remains locked; the UI never treats a timeout as a refund or success.

## Passkey unlock

`DeviceKeyVault` uses WebAuthn PRF with required user verification to derive a wrapping key. It encrypts wallet material under a random AES-GCM data key and stores only the encrypted envelope, wrapped key and public credential metadata in IndexedDB. Account, deployment and origin are bound to the envelope. Unlock requires the original passkey and this browser’s stored envelope. Actual PRF output is checked during enrollment and unlock; unsupported authenticators leave file recovery available.

`DeviceKeySession` automatically updates the encrypted copy while unlocked, invalidates recovery-file confirmation when private material changes, and clears worker keys when locked or the NEAR account changes. A recovery file confirmed for the saved snapshot restores that confirmation on unlock. Restoring a file over a locked browser copy requires an explicit authenticated update; an older copy is never silently imported over loaded keys. Concurrent tabs use revision-checked storage updates.

Use HTTPS or `http://localhost` for WebAuthn. Apple/Google passkey sync does not sync the app’s IndexedDB data. Browser storage may be deleted or evicted; keep the encrypted recovery file. Removing the browser copy does not delete the passkey from the OS password manager.
