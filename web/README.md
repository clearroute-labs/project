# Private Ledger web application

This directory contains the React/Vite wallet application for the NEAR confidential lending protocol.

## Run locally

```sh
cp .env.example .env.local
npm install --cache /tmp/near-lending-npm
npm run dev
```

The app starts in an intentionally disconnected, empty state when no real adapters are installed. It does not invent balances, claims, proof results or transaction success.

## Integration boundary

`src/lib/types.ts` is the browser-facing contract between the UI, the NEAR client and the crypto worker:

- `ProtocolClient` reads finalized public/ciphertext state and submits typed Core actions.
- `WalletAdapter` owns NEAR wallet-selector/session connection state. It must use a supported wallet and return only actual connection state.
- `CryptoProvider` owns browser-local key material, WASM artifact/profile validation, proof preparation (including merge, draw, origination, repayment, management, settlement and reconciliation) and explicit decryption. Witnesses and decrypted values must not be sent to RPC or telemetry.

`src/lib/nearClient.ts` maps those typed operations to the Core method names from `SPEC.md`. The root SDK can supply the `NearContractTransport` backed by `@confidential-lending/client` and a wallet-selector session. `src/lib/workerCrypto.ts` is the fail-closed worker transport for the reviewed WASM module; a module is accepted only when its profile and artifact hashes match the deployment manifest.

Deployment values are read from `VITE_NETWORK_ID`, `VITE_CORE_ACCOUNT_ID`, `VITE_TOKEN_ACCOUNT_ID`, `VITE_RPC_URL` and `VITE_CRYPTO_PROFILE_HASH`. RPC URLs must not contain credentials; production RPC must use HTTPS.

## Privacy and money rules

Amounts are parsed and formatted as decimal strings with `BigInt` base units. Private terms and balances are represented by ciphertexts/commitments until the user deliberately decrypts them. Local wallet exports use PBKDF2-SHA-256 and AES-256-GCM and are downloaded as encrypted files; no secret is put into `localStorage`.

All action controls report `pending`, `failed`, and `unknown` states separately. An unknown payout result remains locked; the UI never treats a timeout as a refund or success.
