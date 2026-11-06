# Implementation contract

SPEC.md is the authority. The implementation uses a Rust workspace with a `confidential-crypto` crate, a `confidential-core` NEAR contract, a local developer token for integration tests, and a TypeScript web application. Internal transfers are co-located in Core.

## Cryptographic profile

Use arkworks 0.5 Groth16 over BN254 and the prime-order subgroup of ark-ed-on-bn254 for additive ElGamal and Pedersen commitments. This is a concrete implementation profile requiring independent review; using established primitives does not certify custom lending circuits. All scalar/point inputs are canonical, checked and subgroup-validated. Nonzero encryption keys are required. Proof public inputs bind a canonical operation context digest, every relevant pre-state and all outputs. NEAR verification uses its BN254 host functions; native tests use arkworks. Never enable an unconditional verifier in a deployable build.

Proof families cover key possession, public conversion, confidential transfer, origination, repayment, reconciliation and zero/balance assertions. They enforce bounded integer relations and matching ciphertexts/commitments for their authorized readers. Loan management moves already-authenticated encrypted principal aggregates homomorphically. Repayments prove a principal-paid delta so the borrower need not decrypt the broker's other loans. Circuits must be fixed by kind, not generated from attacker-chosen constraints.

Wire values use hex-encoded canonical bytes; monetary JSON values are decimal strings. The crypto crate owns these wire types and publishes JSON serialization and canonical statement/transcript helpers. Proving material must be imported and hashed in a deployment manifest. A local single-party setup is development-only and must not be advertised as suitable for a funded deployment.

## Components and ownership

- Crypto worker: `crates/confidential-crypto/**`, `docs/CRYPTO_PROFILE.md`; proof statements, actual cryptography, native/WASM proving APIs, artifact tools and cryptographic tests.
- Core worker: `contracts/confidential-core/**`, `contracts/test-token/**`, `docs/CONTRACT_API.md`; all on-chain financial transitions, authority, storage/callback handling, native and sandbox tests.
- Web worker: `web/**`; real RPC-backed UI, wallet connection, user roles and action orchestration. Browser private data stays local; no server receives decrypted amounts or secret witnesses.
- Main thread: root workspace/configuration, cross-component integration, SDK/services, end-to-end verification, operational docs and release checks.

Workers use isolated worktrees, commit their scoped work and do not revert other contributors' edits. Changes to the shared crypto interface must be announced before dependent code is adjusted. All components expose explicit pending/failure states and never simulate success in the live UI.

## Release boundaries

Local implementation and testing are authorized. Public deployment, funded release, multi-party setup contributions and independent security auditing are separate real-world actions. The code must expose and enforce the deployment profile, immutable verifier configuration and authority assumptions; generated development artifacts are labeled and excluded from release manifests.
