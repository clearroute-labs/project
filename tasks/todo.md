# Confidential lending on NEAR

## Current task: stop the app and open the UI pull request

- [x] Stop this app’s development server and verify it is no longer listening.
- [x] Review the existing PR state and isolate the UI changes on a new branch.
- [x] Commit, push, open a PR against main and verify the remote head.

### Plan

The earlier testnet/passkey PR is merged. Preserve it and open a separate PR for the completed design refresh, minimalist pages, landing route and compact navigation. Reuse the completed web, build and browser verification; check the final diff and branch against current main.

### Pre-publication review

Stopped the app server and confirmed port 5175 has no listener. PR #2 is merged at 1850277; current main is 1fb4654 with the same tracked tree. Created `feat/minimal-app-design` from current main, preserving only the completed UI changes. The final diff passes whitespace checks; the recorded production build passed. Existing completed verification covers 137 web unit tests, type checking, all workspace routes at desktop/390/320 widths, navigation/accessibility interactions and four mocked OAuth outcomes. No real authentication or financial transactions were performed.

### Publication result

Opened [PR #3 — Refresh the UI and add a public landing page](https://github.com/clearroute-labs/project/pull/3) from `feat/minimal-app-design` to `main`. GitHub reports the PR open, ready for review and mergeable, with implementation commit `cefaf4b` matching the pushed branch. No CI checks were reported at publication; the local verification above passed. The application development server is stopped.

## Current task: public landing and compact app navigation

- [x] Add a public landing page at `/` with Open app linking to `/app`; preserve wallet callback and existing app links.
- [x] Center disconnected wallet access, move workspace selection into the top bar, and make navigation collapse to accessible icons.
- [x] Verify landing/app navigation, hover/focus/touch sidebar behavior, wallet flows and desktop/mobile layouts.

### Plan

Keep the sparse visual direction. Root owns routing, shared logo/icons, shell and checks. The landing-page worker owns only the new page and scoped stylesheet in an isolated worktree. Desktop navigation expands on hover or keyboard focus; touch gets an explicit menu control. Public entry must not initialize wallet/crypto until the app opens.

### Landing and navigation review

Added a sparse public landing page at `/` with logo-only branding and Open app at the top right. `/app` lazily initializes the application; disconnected routes show only a centered wallet action. Workspace selection now sits immediately left of the wallet/account control. The icon sidebar expands on hover or keyboard focus, uses a touch disclosure with Escape/outside dismissal, and returns focus to content after navigation. Existing root hash links retain their destination; the Privy callback remains `/wallet/privy`.

Verification: all 137 web tests, TypeScript, production build, disconnected checks, all connected workspace routes at 1440/390/320 pixels, and all four mocked OAuth scenarios pass. New browser checks cover landing-to-app/back/forward navigation, legacy links, button centering, workspace/control placement, desktop hover collapse, keyboard focus and touch disclosure/dismissal. Screenshots are in `.local/navigation-review`. Another project occupies IPv6 localhost:5175; this app remains on IPv4 at http://127.0.0.1:5175 with the workspace at /app. No real wallet authentication or transactions performed.

## Current task: simplify the interface

- [x] Remove decorative strips, repeated labels and promotional copy from the shell and welcome screen.
- [x] Simplify workspaces and security copy; keep actionable guidance, real state and financial/recovery safeguards.
- [x] Verify all routes on desktop/mobile, update affected checks and document the result.

### Plan

Use concise page titles and action labels. Remove repeated privacy explanations and technical overviews from dashboards, keep essential information next to the relevant decision, and collapse optional configuration details. Preserve the presentation palette. Root owns shared components/styles and workspaces; the security-page worker owns only its file in an isolated worktree.

### Minimal-interface review

Removed the welcome principle strip, footer caption, orbit illustration, sidebar tagline, numbered navigation, section eyebrows, repeated privacy banners and static borrower inbox/backup metrics. Replaced slogan headings with direct titles, reduced heading size and shortened form guidance. Dashboards now start with real balances/activity; test funds remain available in Wallet & security. Collapsed vault disclosure and deployment diagnostics, retained recovery requirements, financial risks, pending-payout guidance, errors and all action handlers.

Verification: 137 web tests, TypeScript and production build pass. All workspace routes, populated/empty/error/loading states, keyboard navigation and overflow checks pass at 1440, 390 and 320 pixels. Disconnected welcome/security checks and optional configuration expansion pass. Reviewed desktop and mobile screenshots in `.local/minimal-review`. App remains running at http://localhost:5175.

## Current task: apply the technical-direction presentation design system

- [x] Inspect the reference presentation and translate its recurring visual rules into app design tokens.
- [x] Restyle the shared shell, components, data views, forms and wallet screens, preserving behavior.
- [x] Verify representative workspaces and states on desktop/mobile; run applicable checks and document results.

### Design and verification plan

Use the local presentation at `/Users/thomashussenet/Documents/commons/code/xrpl-commons-technical-direction/dist/index.html` as the visual source of truth. Extract its palette, fonts, surfaces, geometry and hierarchy; adapt them to an interactive lending product with readable forms, accessible states and responsive navigation. Keep Private Ledger branding and existing functionality. Root owns implementation; two read-only reviews cover reference extraction and UI verification coverage. Validate actual rendered screens with existing browser fixtures and testnet reads, without signing or changing live financial state.

### Design review

Applied the presentation’s Arial typography, paper/ink/olive palette, lime/lavender/blue surfaces, 22px cards, thin rules, tracked labels and geometric orbit motif across the app. Updated navigation, forms, tables, balance/security panels, wallet picker, social sign-in page, tab icon and browser theme color. Added responsive wrapping, visible keyboard focus and reduced-motion handling. Private Ledger branding and lending behavior are preserved.

Verification: 137 web tests, TypeScript checking, production build and diff checks pass. The test-only injected-adapter fixture covers every workspace route with populated/empty data at 1440, 390 and 320 pixels, plus loading/error states, keyboard navigation, focus indicators and horizontal-overflow checks. Reviewed rendered welcome, dashboard, form, security, balance and wallet screens; checked pastel-text contrast and reduced-motion rendering. Existing disconnected browser checks and all four mocked OAuth scenarios pass. Synthetic fixtures cannot sign or submit mutations and are not production build entries. No real authentication or financial transaction was performed. Screenshots are in `.local/design-review`; the app is running at http://localhost:5175.

## Current task: Google login does not update the wallet

- [x] Reproduce the callback state and inspect SDK/session and popup lifecycle independently.
- [x] Fix the authentication-to-wallet transition while preserving request approval and account binding.
- [x] Add regression coverage, verify browser behavior, and publish the fix.

### Review

Root cause: the installed React Auth SDK classifies a Google redirect inside any same-origin popup as a child OAuth flow and forwards it to the opener. Our opener is the main app, which does not own the Privy login, so the signing page returned to unauthenticated state. The signing page now completes the callback through the core SDK before mounting React Auth, preserving SDK state/PKCE validation and exchanging the code once. Successful callbacks clear only their OAuth parameters; failures offer a fresh login. The existing request/account approval checks remain in force, and handshake effects now use a fresh abort controller on replay.

Verification: all 137 web tests, web typecheck and the production build pass. Chromium exercises the actual installed SDKs and NEAR Connect with synthetic authentication responses: existing-wallet login, first-time wallet setup, reload without a repeated code exchange, explicit approval and the main app account update, rejected exchange/retry and rejection of mismatched state before exchange. Public Privy app configuration is fetched live. No real Google authentication, wallet creation or transaction signing was performed. The development server was restarted and serves the fix at http://localhost:5175.


## Current task: allow Privy App ID without a Client ID

- [x] Check current Privy documentation and both installed SDK interfaces.
- [x] Make the Client ID optional and correct setup instructions.
- [x] Verify App-ID-only authentication setup and preserve explicit client overrides.


### Review

Privy React Auth and JS Core both accept an omitted Client ID. The app now enables social login with only the App ID, validates optional client overrides, and uses the same identity in both SDKs. Updated the setup docs and ignored the user’s local `web/.env` without changing its contents. All 28 focused configuration/signing-page tests and web typecheck pass. After restarting Vite, Chromium confirmed the real App-ID-only configuration lists the social wallet and opens a signing page ready for login; no authentication or transaction was submitted.

## Current task: testnet app and easier key recovery

- [x] Make the product connect to testnet by default, remove sandbox credential controls/signing from the production app, and keep financial sandbox verification in test fixtures.
- [x] Update launch instructions and browser tests, then run the testnet app at the existing local URL.
- [x] Deploy testnet Core/token contracts and serve the corresponding pinned public cryptographic artifacts; wire the product to the real deployment.
- [x] Add passkey-backed same-browser unlock for confidential keys, retaining the encrypted recovery-file requirement and a fallback for unsupported authenticators.
- [x] Publish the verified follow-up in [PR #2](https://github.com/clearroute-labs/project/pull/2), since PR #1 was already merged.

### Review

Implemented the real testnet default, self-service TEST faucet, and WebAuthn PRF-encrypted same-browser key storage with recovery files retained. Core `clearroute-core-312a0a7a.testnet` has eight activated verifier families; token `clearroute-token-312a0a7a.testnet` accepts wallet storage registration and a one-time 1,000 TEST claim. Live checks finalized the faucet claim/replay rejection, a real holder-key proof, and a 100 TEST deposit creating public claim `1`. Exact transaction hashes and operator instructions are in [TESTNET.md](../docs/TESTNET.md). Private operator files remain ignored and owner-only; only manifest-allowlisted public artifacts are staged into the web app.

Verification: 183 TypeScript tests, strict workspace typecheck, seven token Rust tests, contract WASM build/host checks, production web build, and the real-token custody regression pass. Chromium verifies PRF enrollment/encrypted autosave/reload/unlock, the app's recovery-file restore/save/lock/reconnect flow, desktop/mobile layout, live finalized testnet reads, pinned WASM and six ecosystem wallet choices. Vite denies access to private deployment directories. Testnet deployment and resumption are checked against the immutable Core configuration and exact archived WASM.

The app is running at http://localhost:5175. Public artifacts are served from this app; no permanent external artifact host was requested or provisioned. Cross-device encrypted backup hosting is outside this change. Physical Touch ID/Face ID and real Privy social login remain untested; Privy requires a public App ID; a Client ID is optional. Development proving keys and operator account access remain explicitly documented testnet limitations.

## Current task: NEAR Connect and configurable Privy support

User requested a feature branch and PR, then selected NEAR Connect to support Privy alongside ecosystem wallets. No Privy application exists yet; implement configurable support and explicitly document that live social login requires public deployment IDs.

- [x] Inspect current connector and Privy SDK APIs and define the session/signing boundary.
- [x] Replace Wallet Selector with NEAR Connect, preserving sandbox mode and private-key session boundaries.
- [x] Add optional configured Privy wallet registration and its login/signing page.
- [x] Verify wallet switching, rejected/unknown outcomes, signing parameters, configuration and browser flows.
- [x] Document setup and verification, commit/push the feature branch, and open a PR.

### Review

Implemented on `feat/near-connect-privy` in [PR #1](https://github.com/clearroute-labs/project/pull/1). NEAR Connect retains its ecosystem registry and registers an optional app-hosted Privy executor. Login uses pinned React Auth/JS Core versions, creates a NEAR wallet only on request, and reviews a network/account/contract-bound request before signing. The local sandbox signer and encrypted-backup requirement remain in place. Account switching invalidates stale security reads; disconnect/reconnect and late popup cleanup preserve the newer session.

Verification: strict workspace typecheck, 151 TypeScript tests, production build and peer-dependency checks; Chromium desktop/mobile checks with real sandbox credentials; real NEAR Connect selector with seven testnet wallet entries, cancellation/retry, local executor and unconfigured signing-page popup; production signing-page bundle loaded in Chromium. Mocked authentication tests and the real pinned executor test cover approval and delayed-login handshakes. Live email/Google login and Privy-signed testnet transactions remain unverified because no Privy application IDs were supplied. Setup is documented in [WALLETS.md](../docs/WALLETS.md).

## Current task: implement the whole specification

The user authorized full implementation after approving `SPEC.md`. Earlier research-only and specification-only scope statements below are historical, not current restrictions. The active implementation checklist and verification results are in [implementation.md](implementation.md); unresolved review findings are in [implementation-review.md](implementation-review.md).

- [x] Establish the implementation workspace and dispatch isolated contract, cryptography and web work.
- [x] Validate the NEAR host proof verifier and implement tested accounting/client/keeper foundations.
- [x] Integrate complete proof relations with authoritative contract state and verify their positive/negative cases in native, browser and NEAR runtimes.
- [x] Complete the application, recovery and keeper flows using the actual artifacts and contract.
- [x] Verify complete scenarios, resolve review findings, and document reproducible operation.

### Implementation review

Completed against the final v4 artifacts: all proof families pass native/browser/NEAR verification, four financial sandbox scenarios pass, and the full browser flow passes through repayment, lender payout, archived audit and backup restoration. Final workspace checks pass 117 TypeScript tests, strict typechecking and the production build. [implementation.md](implementation.md) records exact artifacts, runtime measurements and evidence. Development setup remains subject to the specification's independent review and production setup gates before a funded release.

## Historical feasibility review

- [x] Establish available project and hackathon context.
- [x] Verify NEAR privacy, token, proof verification, and confidential execution capabilities against primary sources.
- [x] Map the supplied XRPL proposal to a NEAR architecture and identify privacy and lending risks.
- [x] Assess a finished product's track fit, differentiation, demonstration, and technical feasibility without imposing team or time constraints.
- [x] Review claims and record conclusions with sources.

## Scope

Research and architecture assessment only. No contract implementation or deployment is requested. The workspace initially contains no project files. The user confirmed https://nearhackathon.com and explicitly prioritizes a finished product, track fit, and technical feasibility; team size and build time must not constrain the recommendation.

## Review

### Verified findings

- NEAR's current SDK exposes `alt_bn128_pairing_check`, a native pairing primitive suitable for ZK verification. This supports the feasibility of a NEAR-native proof-verifying contract; it does not establish the gas or proving performance of a full lending circuit.
- The event's Privacy & Private AI track explicitly includes private finance. Unstoppable DeFi includes lending and vaults with cross-chain settlement; track examples are examples, not a requirement to bolt AI onto every project.
- NEAR cross-contract calls are asynchronous and do not roll back earlier receipts automatically. Keep confidential debt and value updates in the same contract execution where possible; handle public token deposits/withdrawals through explicit pending states and callbacks.
- Confidential Intents provides confidential execution through a permissioned private shard. Its public 1Click integration is evidence of swap support, not proof that arbitrary custom lending contracts can be deployed to that shard.
- NEAR AI Cloud can support private underwriting, but the selected model must have the appropriate TEE privacy tier and attestation verification. This does not itself hide token transfers or prove creditworthiness.
- The standalone Shade Agent Framework is deprecated according to current NEAR docs.
- Gloam's own hackathon page says its private payment pools are not deployed on NEAR itself. Do not describe it as a native NEAR confidential lending primitive.
- Independent ecosystem research found no documented facility that atomically ties a Gloam or Confidential Intents private payment to arbitrary NEAR lending state. Optional TEE execution/custody does not remove the need for that binding.
- NEP-141 exposes ordinary account balances and transfer amounts; NEAR RPC exposes contract state. Private amounts must be represented cryptographically inside the application, not stored as plaintext behind a restricted view method.
- Independent ZK research confirmed NEAR pairing primitives and historical ZeroPool verifier precedent. The old example depends on obsolete feature branches, so it is a reference rather than a production dependency. Select a current proof system/curve after security review and actual performance measurements.

### Proposed architecture under review

Public pooled stablecoin vault; restricted shielded broker allocation; committed loan state; ZK-verified origination and repayments tied to the actual private asset movement; encrypted terms for borrower, underwriter, and designated auditor; aggregate settlement. Cross-chain funding and private document analysis are additional integrations, not substitutes for private loan accounting.

### Product requirements

Preserve the supplied XRPL confidential proposal's credit model, lender protection, and visibility, with ordinary lending behaviour checked against the local rippled reference. Do not independently add collateral or stronger privacy/protection requirements. Distinguish amount confidentiality from identity or timing anonymity. Public deposits/withdrawals and small pools can leak information by correlation. Do not claim a proof guarantees future repayment or that a TEE signature proves economic truth.

### Sources reviewed

- https://docs.rs/near-sdk/latest/near_sdk/env/fn.alt_bn128_pairing_check.html
- https://github.com/near/NEPs/blob/master/neps/nep-0141.md
- https://docs.near.org/api-reference/post-experimental_view_state
- https://github.com/near/NEPs/blob/master/neps/nep-0488.md
- https://github.com/zeropoolnetwork/near-groth16-verifier
- https://nearhackathon.com/
- https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/03-privacy.md
- https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/01-defi.md
- https://docs.near.org/smart-contracts/anatomy/crosscontract
- https://www.near.org/blog/how-confidential-intents-works
- https://www.near.org/blog/announcing-general-availability-of-confidential-intents
- https://docs.near-intents.org/integration/distribution-channels/1click-api/about-1click-api
- https://docs.near-intents.org/integration/distribution-channels/1click-api/quickstart/confidential-swaps
- https://docs.near-intents.org/integration/distribution-channels/1click-api/quickstart/signed-intent-execution
- https://docs.near.ai/cloud/models
- https://docs.near.ai/cloud/verification
- https://docs.near.org/ai/shade-agents/getting-started/introduction
- https://www.gloam.trade/blog/build-with-gloam-at-the-near-hackathon

### Verification limits

This is source-based feasibility research. No contract, circuit, browser prover, or integration has been implemented or benchmarked in this task.

### Recommendation

Proceed with a NEAR-native confidential business-credit product. Primary track: Privacy & Private AI. Additional fit: Unstoppable DeFi with substantive Intents funding/settlement, and Real-World Money with an actual business working-capital flow. Use ZK-enforced shielded value movement and loan accounting as the core; optional attested private document analysis can support underwriting. No technical basis was found for requiring a NEAR protocol amendment.

### Final review

Both delegated read-only research tasks were checked against their requested scope: primary-source evidence, actual capabilities versus assumptions, and unresolved dependencies. The final assessment separates verified building blocks from proposed architecture. Shielded notes are the recommended architecture, not a claim that encrypted-balance designs are impossible. Feasibility is established at architecture level; production readiness, performance, and security have not been demonstrated.

## XRPL behaviour alignment

The user has chosen the same credit model, lender protection, and public visibility as the supplied XRPL confidential lending draft. This is the product baseline, not an open product decision.

- [x] Locate and identify the local normal-lending reference.
- [x] Inspect broker/borrower authorization, agreement, repayment, default, and lifecycle behaviour.
- [x] Inspect vault shares, cash-basis accounting, liquidity restrictions, and normal first-loss cover.
- [x] Compare public ledger fields with the confidential draft's explicit overrides.
- [x] Record the NEAR behaviour baseline and any genuine gaps in the supplied draft.

### Reference

The suggested `../project_goXRPL/rippled` path does not exist. The neighbouring repository's AGENTS.md designates `../project_goXRPL/rippled-worktrees/v3.4.1-oracle` as the local read-only reference. Its checkout is clean at commit `d147fccf54a500fce586522f28d6044c37fd8d29` (tag 3.4.1).

### Review

Completed source-based review of the clean pinned rippled reference, relevant test assertions, and the user-supplied confidential draft. Both delegated results were checked; the lifecycle result was re-dispatched to obtain precise references and correct an ambiguous deletion claim. Research only: no code was changed, no tests were executed, and no confidential lending implementation is present in the inspected reference.

### Chosen behaviour baseline

- Use broker-underwritten lending with a mutually signed agreement. On-ledger collateral and automated liquidation are not additional requirements.
- Apply the supplied confidential draft's zero management fee, cover rates and cover balance. Do not add first-loss insurance that the draft expressly excludes.
- Keep principal, current amount owed and periodic payment encrypted; an agreed initial amount owed may exceed principal. Do not introduce late fees or accruing interest.
- Keep the normal public lifecycle counters: LoanSet initializes PaymentRemaining from PaymentTotal, LoanDelete rejects PaymentRemaining > 0, and LoanManage rejects PaymentRemaining == 0. Zero transparent monetary placeholders do not bypass those checks. Default is broker-authorized and closes the loan after the due date plus grace period; with fixCleanup3_4_0 the deadline comparison is exclusive.
- Keep the broker's restricted lending balance, inbox/spending distinction, explicit merge, and explicit public draw/settlement semantics. Preserve the stated broker liveness dependency.
- Draw increases public broker DebtTotal. Private origination and repayment do not change public vault accounting or DebtTotal. Settlement reduces aggregate DebtTotal first and recognizes only the excess as vault yield.
- Keep the loan's existence, borrower account, broker account, vault association, start date, payment interval, grace period, due dates, remaining payment count and lifecycle flags public. Ciphertexts and proofs are public data; their underlying amounts are confidential.
- Keep public vault shares, lender deposits/withdrawals, available/total assets, broker debt cap/debt total, and draw/settle amounts.
- Loan terms are readable by the borrower, broker and designated loan auditor. Separately preserve token-issuer and token-auditor visibility into encrypted transfer amounts and their balance mirrors. These roles must not be collapsed into a promise that only borrower and broker can read all financial data.

### Credit, lender protection and lifecycle evidence

All paths below are relative to the pinned rippled reference:

- `src/libxrpl/tx/transactors/lending/LoanSet.cpp:85` requires the counterparty signature outside the inner-batch path; `:155` verifies the counterparty; `:664` creates the Loan and `:691` sets PaymentRemaining from PaymentTotal. The loan schema has no on-ledger borrower collateral field.
- `src/libxrpl/tx/transactors/lending/LoanManage.cpp:100` rejects management of closed loans; `:106` checks due date plus grace; `:124` restricts management to the broker owner; `:263` marks default and `:266` closes the payment schedule.
- `src/libxrpl/tx/transactors/lending/LoanDelete.cpp:50` prevents deleting active loans; `:63` authorizes the borrower or broker owner. `:112` clears residual debt after deleting the last ordinary loan, but the confidential draft explicitly disables that clearing.
- `src/libxrpl/tx/transactors/lending/LoanBrokerDelete.cpp:76` rejects deletion when aggregate debt rounds to a nonzero asset amount.
- `src/libxrpl/tx/transactors/vault/VaultCreate.cpp:251` initializes vault accounting; `:286` participates in the cash-basis version selection. `include/xrpl/protocol/Protocol.h:320` defines the accounting versions.
- `src/libxrpl/ledger/helpers/VaultHelpers.cpp:133` and `:150` use AssetsTotal minus LossUnrealized for share conversions, with the sole-shareholder exception defined there.
- `src/libxrpl/tx/transactors/vault/VaultWithdraw.cpp:495` rejects insufficient available liquidity. `src/libxrpl/tx/invariants/VaultInvariant.cpp:597` bounds available/total assets and unrealized loss.
- `src/libxrpl/ledger/helpers/LendingHelpers.cpp:222` defines cash-basis origination, default exposure and payment deltas. `src/test/app/lending/LoanCashBasis_test.cpp:134`, `:400`, and `:919` assert origination, repayment and default accounting.

### Confidential-default accounting limitation

Ordinary cash-basis default exposure is `PrincipalOutstanding` (`LendingHelpers.cpp:236`). `LoanManage.cpp:148`, `:196`, and `:248` use it to write down vault AssetsTotal and broker DebtTotal; impairment uses the same exposure for public LossUnrealized (`LoanManage.cpp:302`).

The supplied confidential draft sets PrincipalOutstanding to zero and makes DebtTotal an aggregate draw/settlement obligation. Literally applying the inherited default code therefore marks the loan defaulted and closes its schedule, while the public accounting deltas are zero. This does not forgive the broker's aggregate drawn debt. LoanDelete's explicit confidential override also prevents forgiveness on final deletion.

There is no specified replacement mechanism for recognizing an unrecoverable aggregate broker shortfall. Immediate ordinary per-loan write-down would disclose the hidden exposure through public accounting changes. Record that as a limitation of the supplied draft, not as evidence that ordinary XRPL loss recognition or first-loss protection is retained. The chosen baseline preserves the draft's explicit economics; no new insurance, collateral, loss-forgiveness transaction or private identity layer is added.

### Visibility evidence

`include/xrpl/protocol/detail/ledger_entries.macro:492` defines public Vault fields, `:522` defines LoanBroker fields, and `:546` defines Loan metadata. `src/libxrpl/tx/transactors/token/ConfidentialMPTSend.cpp:130` binds public sender/destination/version to the proof; `:147` binds issuer ciphertexts; `:345` and `:361` update issuer and auditor mirrors. The supplied confidential draft specifies which monetary fields become encrypted and requires both token-level and loan-level auditor roles.

### Behaviour checks for the eventual implementation

These are acceptance criteria, not executed tests:

1. Origination requires the broker and borrower to authorize the same terms.
2. Public draws cannot exceed vault liquidity, the configured broker debt ceiling, or the permitted vault phase.
3. Broker confidential funds can only fund authorized loans or settle to the vault.
4. A valid private repayment reduces confidential borrower debt and credits broker funds without changing public vault totals or DebtTotal.
5. Invalid amounts, stale proofs and replayed repayments fail without changing balances or debt.
6. Full payment proves equality to the amount owed and closes the loan; a regular final scheduled payment is rejected as specified by the draft.
7. Active loans cannot be deleted merely because their transparent monetary placeholder fields are zero.
8. Default follows the specified broker authorization and due-date/grace rule; confidential state must not be interpreted as a zero-value transparent loan.
9. Deleting the last confidential loan never forgives the broker's aggregate drawn debt.
10. Settlement returns public liquidity, reduces DebtTotal first and recognizes excess as yield.
11. Confidential brokers reject cover deposits and confidential loans reject ordinary LoanPay.
12. Public records contain the selected XRPL metadata, while encrypted values are available only through the specified holder, issuer and auditor keys.

## Flow improvement assessment

The user asked which parts of the flow could be improved, then approved the five recommendations and requested a specification. The specification must distinguish the inherited baseline from the approved extensions.

- [x] Check repayment and closure consistency against the supplied confidential draft.
- [x] Separate correctness gaps from UX/operational improvements and deliberate protocol extensions.
- [x] Record prioritized recommendations and their privacy/trust tradeoffs.

### Proposed improvements

1. Complete default and impairment accounting. A possible extension is ZK-verified aggregate loss recognition, tied to eligible defaulted loans and previously accounted amounts. It requires a precise definition of unrecovered principal and repayment allocation; aggregate broker DebtTotal must not be erased by an arbitrary broker assertion. This is a protocol extension to the incomplete draft, not an existing capability. A publicly recognized aggregate loss reveals the individual amount when only one loan contributes, so aggregation is not a guarantee of privacy. The timing and disclosure policy need to be part of that extension.
2. Make payoff closure consistent. Section 15.3 permits a regular payment X equal to O; section 15.6 only decrements PaymentRemaining. For O=1000, Q=250, PaymentRemaining=4, regular X=1000 satisfies the supplied bounds but leaves O=0 and PaymentRemaining=3. Recommend regular proofs enforce X < O, and full proofs enforce X = O and close. On full payment, also subtract the proven payment from all owed ciphertexts and increment ConfidentialLoanVersion, rather than leaving the previous encrypted debt in a closed record. Closure was already public, so these changes do not disclose a new amount.
3. Automate inbox handling within the user's intended action. Preserve separate inbox/spending state for proof stability. Merge only when necessary, wait for confirmed resulting state, generate the proof against its current version, and handle stale proofs explicitly. Do not claim a multi-receipt workflow is atomic or allow arbitrary third-party merges that can invalidate proofs.
4. Operate a broker-controlled settlement keeper at a predictable cadence, with spending constrained to the vault, observable failures and retries. This preserves broker authorization while improving day-to-day liveness. It cannot eliminate key-loss/operator-outage risk, and proof generation still requires the appropriate private witness. NEAR function-call keys alone do not provide encrypted-balance decryption or proof witnesses. Aggregation can reduce direct timing correlation but does not guarantee privacy for small pools.
5. Co-locate confidential balance changes and loan accounting in one contract execution; model external token ingress/egress as explicit pending/confirmed/failed operations with recovery. Authenticate callbacks and make retries idempotent. This is needed because NEAR cross-contract calls execute independently without automatic global rollback.

### Review of recommendations

The repayment edge case was checked directly against the supplied proof bounds and state changes with a concrete numerical example; no contract test was run. Default-accounting findings reuse the pinned rippled source review above. NEAR execution constraints were rechecked against https://docs.near.org/smart-contracts/anatomy/crosscontract and https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks. The user has now accepted these improvements for the specification; no protocol code has been implemented.

## Protocol specification

- [x] Define complete state, roles, visibility, amounts, authorization and invariants.
- [x] Resolve repayment allocation, aggregate loss recognition and public NAV consistency.
- [x] Specify NEAR custody, asynchronous operations, proof binding and keeper permissions.
- [x] Write the repository specification with lifecycle/API tables and worked examples.
- [x] Review the draft for accounting, privacy and execution errors; resolve findings.
- [x] Validate examples and document review results.

### Scope

Create `SPEC.md` as the repository's implementation-facing protocol specification. Preserve the agreed XRPL model and explicitly incorporate all five approved improvements. Do not implement, deploy or publish a service.

### Specification review

Created `SPEC.md`, version 0.1, with 24 sections covering roles and public visibility, a Core architecture diagram, financial state and invariants, loan/vault transitions, aggregate loss accounting, proof requirements, keeper authority, asynchronous custody, API/events, release verification and eight worked examples.

Three independent read-only reviews covered economic accounting, cryptographic semantics and NEAR execution. All results were checked against their requested scope. Resolved findings include exact pre-state binding, mandatory book/accounting versions, principal allocation and range checks, authenticated aggregate updates, recovery-hint context, idempotent deposit receipts, durable payout-result recording and permissionless finalization. Final economic review confirmed the C/H/I formulas, NAV consistency, impairment replacement and settlement-order examples; its full-payment risk-queue ambiguity was already corrected, and its settlement-phase wording was clarified.

Two suggested changes were intentionally rejected after checking the chosen model: issuer/token auditors receive transfer/balance views, not automatic access to future loan O/Q terms; an unresolved external payout does not freeze unrelated vault pricing because redemption already removed its value from T/A and the payout is separately reserved. These choices are explicit in the specification.

### Validation performed

- Executed an integer accounting model over 20,000 generated transitions (100 sequences of 200, seed 68123), including draws, origination, repayments, impairment, default and settlement. Checked T - A = D, nonnegative values, provision bounds and unchanged-book checkpoint idempotence after each reconciliation.
- Checked concrete settlement-before/after-default orders, income recycled into later loans, impairment becoming realized loss, and the regular/full payment boundary. The equations matched the worked examples. This validates the arithmetic model, not an implementation or cryptographic proof system.
- Checked all 24 top-level sections and subsection references, Markdown table column counts, code-fence balance and absence of unfilled TODO/TBD markers. No structural issues remained.
- Rechecked ordinary impairment and default timing against the pinned local LoanManage implementation; confidential economics and visibility retain the supplied draft's explicit overrides.

### Release limitations

This task delivered the protocol specification only. No contracts, circuits or wallet were implemented, audited or benchmarked. A concrete immutable CryptoProfile, artifact hashes, runtime gas/proving/recovery measurements and independent security review remain mandatory before a funded release. The document explicitly retains broker-witness liveness, aggregate disclosure for small cohorts, underlying-token trust and unresolved payout-result risks; it does not claim these have been eliminated.
