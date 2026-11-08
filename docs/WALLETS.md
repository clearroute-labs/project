# Wallet connections

Private Ledger uses `@hot-labs/near-connect` on NEAR mainnet and testnet. The selector loads the NEAR Connect ecosystem registry and filters wallets for the deployment network and transaction signing. The application does not replace that registry with a private wallet list. The local sandbox continues to use the existing in-memory credential-file signer.

## Enable email and social login

1. Configure the public network deployment in `web/.env.local` using `web/.env.example`. Set the Core and token accounts, RPC, cryptographic artifact pins and asset decimals as usual.
2. Create a Privy application in the [Privy dashboard](https://dashboard.privy.io/). Enable email and Google login, and allow your development and deployment origins in the app settings. An app client is optional for this web integration; it overrides settings for a particular environment. Privy’s default Google OAuth credentials can be used for development.
3. Set `VITE_PRIVY_APP_ID` to the public App ID. Leave `VITE_PRIVY_APP_CLIENT_ID` empty unless using an explicit app client. Both installed Privy SDKs support an omitted Client ID; see [Privy’s React setup](https://docs.privy.io/basics/react/setup). No app secret belongs in a `VITE_` variable or this repository.
4. Rebuild with `pnpm --dir web build`. Serve over HTTPS (localhost HTTP is supported for development). The host must serve the SPA's `index.html` at `/wallet/privy`, while serving built `/assets/*` files normally. Keep the popup's opener available; a restrictive `Cross-Origin-Opener-Policy: same-origin` can break OAuth popup flows. Use a hosting policy compatible with Privy's popup guidance, such as `same-origin-allow-popups`, and allow the required Privy resources if you set a CSP.
5. Choose **Connect wallet → Email or social login**. The popup opens the app's signing page, offers Privy's email/Google login and creates a NEAR wallet on request. Every connection and transaction requires explicit approval.

Without an App ID, ecosystem wallet connections remain available and the social login entry is omitted. Social login is intentionally unavailable on the local sandbox. The build bundles the executor from the lockfile-pinned `@peerfolio/privy-near-connect@0.0.8` package and serves it locally. Upgrading that package requires rerunning the handshake tests.

The login screen uses React Auth and a JS Core signing client with the same IDs, origin and default LocalStorage session, as described in the [plugin's authentication setup](https://github.com/beneviolabs/privy-near-connect). Custom authentication domains or HttpOnly-cookie integrations require their own live integration check. The React Auth/core versions are aligned; the plugin's `viem` dependency is pinned to React Auth's version so TypeScript resolves a single JS Core peer instance. The Solana packages in `web/package.json` satisfy React Auth's optional peers with mutually compatible versions; this does not enable Solana wallets in this app.

## Accounts and confidential keys

A new Privy NEAR wallet has a 64-character implicit account address. Wallet creation does not fund that account. Fund it with native NEAR on the configured network before submitting transactions; a mainnet balance does not pay testnet fees. Storage deposits and attached NEAR deposits remain visible in the approval screen, including the exact amount and gas limit. Private Ledger's large proof calls retain their 300 Tgas budget.

Privy authenticates the user and holds the NEAR signing key. It does not store the lending protocol's decryption keys or replace their encrypted backup. Continue through **Wallet & security**, save the encrypted backup before key registration, and restore it when using a different browser. Changing accounts clears the active confidential wallet context and invalidates old dashboard reads.

Disconnect in **Wallet & security** to choose another ecosystem wallet. NEAR Connect disconnect removes its wallet association; the Privy login session can remain active. In the next social-login popup, **Use another login** signs out of Privy so another identity can be selected.

The signing page accepts requests only from the application's origin, on the configured network, for the configured Core/token contracts. It supports account connection and contract function calls, without function-call access key installation, arbitrary messages or other account actions. The selected NEAR wallet is bound again at approval and the request must remain identical. It does not load a confidential wallet or receive decryption material.

## Verification

Run `pnpm typecheck`, `pnpm test` and `pnpm build`. The wallet tests cover connection cancellation/retry, account changes, restore, exact gas/deposit forwarding, wrong signer/network rejection and unknown outcomes. Privy tests exercise the actual pinned executor's delayed-login/repeated-handshake behavior and the app's request validation and approval UI with mocked authentication; those mocks do not demonstrate a successful OAuth login.

With Chromium installed and an unconfigured local Vite demo running, `node web/tests/browser/test-near-connect.mjs` checks the actual ecosystem registry, selector cancellation/retry, locally served Privy executor and unconfigured popup route. `UI_BASE_URL` selects the demo URL. It does not authenticate or submit transactions. The usual `web/tests/browser/test-ui.mjs` harness covers desktop/mobile layouts and sandbox credentials.

With a configured App ID and Vite running, `node web/tests/browser/test-privy-oauth.mjs` exercises the installed Privy SDKs and NEAR Connect with synthetic OAuth/session responses. It checks the Google callback, PKCE/state validation, reload, explicit connection approval, the main app's account update, rejected exchanges and retry. Only public application configuration is fetched live; it does not authenticate a Google account or sign transactions. `UI_BASE_URL` defaults to `http://localhost:5175`.

The signing page completes Google redirects through the core SDK before mounting React Auth. React Auth otherwise treats this page's same-origin opener as the initiator of an OAuth popup and forwards the callback to the main app, which did not initiate Privy's login. The SDK validates the saved state and PKCE verifier; callback parameters are removed only after a successful exchange. The authenticated session is then restored by React Auth, while the existing core client handles NEAR signing.

With a real App ID and a testnet deployment, verify email and Google login, create/fund an implicit account, approve a storage deposit, reject a transaction, reconnect after reload, switch identities, and restore the corresponding encrypted confidential backup. Live email/OAuth login and a transaction signed by a real Privy wallet remain unverified; the automated callback tests use synthetic users and tokens.

NEAR Connect provides remote ecosystem wallet executors through its registry. They remain an upstream runtime dependency, as in NEAR Connect's normal integration. The app-specific Privy executor is served from this build. Native wallets may redirect or return an unresolved submission; the app does not automatically submit a second transaction when the outcome is unknown.
