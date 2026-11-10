# clear contributor guide

clear is a NEAR testnet confidential-lending prototype. SPEC.md defines the financial and privacy contract. Public vault accounting and encrypted loan amounts must remain distinct in product copy.

Use Node 24.11+ and the pnpm version pinned in package.json. Install with `pnpm install --frozen-lockfile --ignore-scripts`. The web development command is `pnpm --dir web dev`. Build with `pnpm build`, typecheck with `pnpm typecheck`, and run existing tests with `pnpm test`. There is currently no lint script. On-chain browser and proof tests require staged cryptographic artifacts; follow README.md and docs/TESTNET.md.

Work in isolated feature worktrees. Preserve wallet, proof, accounting, authorization and pending-transaction behavior when changing presentation. Never log or transmit private keys, witnesses or decrypted values. Use synthetic data in design previews and label it as illustrative.

Do not claim guaranteed returns, full anonymity or legal certification. Account relationships, transaction timing and public vault accounting remain visible. Proofs do not establish creditworthiness.

Generated repository context belongs in .Codex/rules/. Local design exploration is ignored by Git. The implemented visual conventions and frontend checks are documented in web/README.md.
