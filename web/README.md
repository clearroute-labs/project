# Private Ledger web application

This directory contains the React/Vite wallet application for the NEAR confidential lending protocol.

## Run locally

```sh
cp .env.example .env.local
npm install --cache /tmp/near-lending-npm
npm run dev
```

With a complete deployment configuration, the app creates a real Wallet Selector session (MyNearWallet and Meteor) and a finalized JSON-RPC `ProtocolClient`. Without the required Core/token/profile values it starts in an intentionally disconnected, empty state. It does not invent balances, claims, proof results or transaction success.

## Integration boundary

`src/lib/types.ts` is the browser-facing contract between the UI, the NEAR client and the crypto worker:

- `ProtocolClient` reads finalized public/ciphertext state and submits typed Core actions. `src/lib/nearClient.ts` maps every action to the documented Core ABI through `@confidential-lending/client`'s HTTPS JSON-RPC and final-outcome transport.
- `WalletAdapter` owns NEAR wallet-selector/session connection state. The default `NearWalletSelectorSession` uses supported MyNearWallet and Meteor modules and returns only actual connection state; no account is embedded in the app.
- `CryptoProvider` owns browser-local key material, WASM artifact/profile validation, key-registration/PoP preparation, proof preparation (including merge, draw, broker-only origination, repayment, management, settlement and reconciliation) and explicit decryption. Witnesses and decrypted values must not be sent to RPC or telemetry.

`src/lib/nearClient.ts` maps those typed operations to the Core method names from `SPEC.md`. `src/lib/workerCrypto.ts` is the fail-closed worker transport for the reviewed WASM module; a module is accepted only when its profile and artifact hashes match the deployment manifest. Root integration may inject a reviewed crypto provider before mounting the app.

Deployment values are read from `VITE_NETWORK_ID`, `VITE_CORE_ACCOUNT_ID`, `VITE_TOKEN_ACCOUNT_ID`, `VITE_RPC_URL`, `VITE_ALLOW_INSECURE_LOCALHOST`, `VITE_CRYPTO_PROFILE_HASH`, `VITE_CRYPTO_ARTIFACT_HASH`, `VITE_ASSET_DECIMALS` and `VITE_ASSET_SYMBOL`. RPC URLs must not contain credentials; production RPC must use HTTPS. The localhost HTTP opt-in is only for an explicitly local sandbox.

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
