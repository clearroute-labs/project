# Confidential lending cryptographic profile

This document is the wire and circuit profile implemented by
`crates/confidential-crypto`. It is a protocol profile, not an audit report.
The implementation has not been independently audited and the development
setup command is not suitable for a funded release.

## Suite identity

The suite identifier is
`near-confidential-lending-bn254-edwards-groth16-v3` and the profile version
is `3`. `profile_hash()` returns the SHA-256 digest of the following exact
UTF-8 manifest, including the final newline:

```text
near-confidential-lending-bn254-edwards-groth16-v3
version=3
curve=ark-ed-on-bn254;subgroup=prime-order;encoding=compressed-32-byte-lower-hex
elgamal=C=(rG,mG+rPK);pedersen=mG+rH;H=NEAR-CONFIDENTIAL-LENDING/PEDERSEN-H/v1:sha256-try-and-increment:cofactor8
proof=arkworks-groth16-bn254;proof-compressed=canonical;field-input=canonical-le32
poseidon=width3;rate2;capacity1;alpha5;full8;partial57;grain-skip0
transcript=domain-field+slot-count+all-fixed-kind-slots;poseidon-field-output
point-membership=statement-on-curve-plus-private-cofactor-preimage-[8]Q=P;generic-points=strict-prime-subgroup
max-amount=9223372036854775807;slot-capacity=320
transfer-views=5;loan-reader-views=3
recovery=proof-bound-two-encrypted-u32-limbs;authenticated-records-hints-only
setup=development-single-party-rejected-funded-release
```

The current suite hash is
`bac68a9fbaefea1228279a3665beeb9f082a520b9886b94c2d9713428122b8db`.
This is intentionally separate from a deployment artifact-manifest hash. A
deployment manifest must hash each proving key, verifying key, WASM binary and
native binary; those artifact hashes are not included in the immutable suite
manifest, which avoids a circular hash involving the WASM export itself.

## Groups, encodings, and arithmetic

Amounts use additive ElGamal on the prime-order subgroup represented by
`ark-ed-on-bn254`. The generator is the arkworks encryption base. A ciphertext
is exactly `(rG, mG+rPK)`. A fresh encryption requires a non-zero scalar `r`;
homomorphic `add` and `sub` may produce the identity point, including the
valid result `C-C`. Persisted zero balances should use
`Ciphertext::canonical_zero(public_key, domain)` with a domain containing the
deployment, account, and asset identifiers. `Ciphertext::zero()` is the
algebraic identity and is intended for intermediate cancellation only.

The hiding commitment is `mG+rH`. `H` is derived by SHA-256
try-and-increment on the Edwards curve using the domain
`NEAR-CONFIDENTIAL-LENDING/PEDERSEN-H/v1`, then cofactor-cleared into the
prime-order subgroup. No known-discrete-log or audit claim is made beyond this
specified derivation; an independent review is required before funded use.

Points, Edwards scalars, and BN254 public-input fields are serialized as
exactly 32 bytes, lower-case hexadecimal. Decoding rejects wrong lengths,
upper-case or non-hex characters, non-canonical encodings, off-curve points,
and zero keys/secrets where a key is required. Generic point APIs reject
non-subgroup points. Statement parsing additionally checks canonical encoding
and the curve equation; the fixed Groth16 circuit proves prime-subgroup
membership by allocating a private Q and constraining `[8]Q = P`. This moves
the expensive subgroup relation into the proof without accepting an
unvalidated point as a generic key or ciphertext. Statement-only
canonical/on-curve cache entries are kept separate from the strict
validated-point cache and are never returned by generic decoding. Cache hits
still apply the key/non-identity policy, and both caches are bounded per
thread and are not protocol state.
After the exact statement's Groth16 proof verifies, the verifier may call
`Statement::promote_after_verified_proof()` to promote only that statement's
point fields into the strict cache before homomorphic state updates. No
thread-local cache-wide promotion is permitted.

Core may additionally enable the opt-in `validated-storage` crate feature for
immutable ciphertexts, commitments, and keys loaded from authenticated
persisted state whose subgroup membership was already established when the
record was accepted. `validated_storage::parse_key`,
`parse_ciphertext`, and `parse_commitment` still require canonical lower-hex
and on-curve encodings, reject invalid key identities, and promote only the
exact points they parsed. The returned `Stored*` types are the only API for
this fast path. This feature is disabled by default and must never be enabled
for untrusted request or statement bytes; generic `PublicKey::parse`,
`Ciphertext::parse`, and `Commitment::parse` retain strict subgroup checks.
Groth16 proof and verifying-key bytes use arkworks canonical compressed
serialization. Public BN254 inputs passed to a host verifier are canonical
little-endian 32-byte field encodings.

Individual private amounts are bounded by `MAX_AMOUNT = 2^63 - 1`; protocol
versions/counters retain their declared u64 or u32 widths. Aggregate
reconciliation amounts and commitments use checked `u128` witnesses and
decimal-string wire values.

## Transcript and fixed circuits

Every statement has a fixed circuit family; a caller cannot choose an
arbitrary constraint shape. The canonical slot vector starts with the eight
32-byte identifiers (four field elements each), eight expected versions, four
authorization epochs, the expiry, and the numeric statement kind. Statement
fields then follow the order in `Statement::public_slots()`.

The transcript input is the field domain
`NEAR-CONFIDENTIAL-LENDING/TRANSCRIPT/POSEIDON/v1`, the field-encoded slot
count, and every canonical slot. It is absorbed by the pinned arkworks
Poseidon configuration: width 3, rate 2, capacity 1, exponent 5, 8 full
rounds, 57 partial rounds, Grain-generated round constants/MDS, and skip 0.
The same configuration is evaluated natively and by
`PoseidonSpongeVar` inside Groth16. The digest is a public input and the
in-circuit sponge output is constrained equal to it, so changing any context,
state, output, point, flag, or version invalidates the proof. A private
“shadow” copy is not used.

As a cross-implementation vector, the circomlib reference permutation for
`[0, 1]` (its state-0 output) is
`12583541437132735734108669866114103169564651237895298778035846191048104863326`.
The arkworks sponge exposes the first rate element (state index 1), which is
the constrained output used here and is
`9807604810977681540537942462159990591554827872659661794094614452930421286825`.

The fixed public slot counts are:

| Family | Slots (before the public digest) |
| --- | ---: |
| key possession | 48 |
| public conversion | 77 |
| confidential transfer | 131 |
| origination | 222 |
| repayment | 310 |
| reconciliation | 86 |
| zero balance / ownership | 54 |

The global capacity is 320 slots. The public digest is an additional verifier
input, so the largest Groth16 input vector currently has 311 field elements.
The contract adapter must use the exact vector supplied by the typed statement;
it must not pad, reorder, or replace fields.

Public conversion has two explicit modes. `Credit` proves a public amount is
added to the owner’s private spending ciphertext; `Debit` proves possession,
decrypts the private pre-balance, proves sufficient funds, and subtracts the
public amount. Both modes bind three matching reader ciphertexts and the
spending version.

Transfers bind five matching reader views, a positive amount commitment,
sender secret-key possession, sender pre-balance decryption, a bounded
sufficient-funds relation, and the sender spending version. Origination binds
the broker’s sufficient balance, five transfer views, three-reader initial O
and Q terms, commitments, payment counters, and broker/loan versions.

Repayment binds the borrower’s pre/post spending ciphertexts, five transfer
views, the borrower-decryptable three-reader O/Q/R state, homomorphic owed and
principal deltas, delta commitments, regular/full bounds, principal-first
`min(X,R)` allocation, payment counters, and all spending/loan versions. The
borrower need not know another reader’s ElGamal randomness. Core applies the
validated delta homomorphically to each stored reader view.

Reconciliation decrypts broker cash, active principal, and impaired principal
with the broker key and checks checked-u128 accounting relations. Here active
principal is `H + I`, so broker book cash coverage is `C + active - impaired`;
the loss and new provision relations are the checked forms of
`L=max(D-(C+H+I),0)` and `newU=max(D-L-(C+H),0)`.

## Recovery records

Full-range recovery is mandatory and does not rely on scanning a `2^63` range
or a wallet-local cache. Each recoverable amount event includes two
proof-bound ElGamal ciphertexts for the low and high 32-bit limbs. The circuit
constrains these pairs to the exact amount and reader key. Each limb is
recovered with a `2^16` baby-step/giant-step table and recombined with checked
u64 arithmetic. `recover_pair` and the WASM/native `decrypt_recovery_pair`
method accept only these exact pairs.

`RecoveryRecord` is an authenticated, encrypted wallet hint for the main
ciphertext. It carries the profile, operation/context digest, account/asset
identifiers, recipient key, ciphertext digest/version, and a signature. It is
never state authority: Core must persist proof-bound pairs or authenticated
transition history, and a malformed/missing hint cannot authorize a balance
or alter accounting.

## Setup and artifacts

`setup`/`dev setup` generate ordinary arkworks Groth16 parameters with random
single-party toxic waste for local development. Their mode is explicitly
`DevelopmentSingleParty` and must be rejected by a funded deployment. Imported
proving/verifying keys are canonical-deserialized, matched by SHA-256 of the
compressed verifying key, and pinned by the deployment artifact manifest.

## Native and browser transport

The native binary supports:

```text
confidential-crypto inspect-profile
confidential-crypto keygen [seed-hex-32]
confidential-crypto dev setup <statement-kind> <artifact-prefix>
confidential-crypto prove <statement.json> <witness.json> <proving-key.bin>
confidential-crypto verify <statement.json> <proof.json> <verifying-key.bin>
confidential-crypto execute [--artifact <proving-key-or-vk-file>]
```

`execute` reads one JSON request from stdin and emits one JSON result. The
browser feature exports `profile_hash()` and
`execute(request_json, artifact_bytes)`. The transport methods are
`keygen`, `public_key_from_secret`, `encrypt_amount`, `encrypt_views`,
`create_recovery_record`, `decrypt_bounded`, `verify_plaintext_u128`,
`decrypt_recovery_pair`, `decrypt_recovery_record`, `canonical_statement`,
`prove`, `verify`, `ciphertext_add`, `ciphertext_sub`, and
`commitment_create`.
The browser caller supplies a WebCrypto-generated 32-byte seed for encryption
and proving randomness; no predictable browser fallback is provided. Secret
keys are not `Debug`/`Serialize` types, and errors never include witness or
plaintext values.

All JSON monetary values and versions are quoted canonical decimal strings
(no leading zeroes; JSON numbers are rejected). Keys, points, ciphertexts,
commitments, proofs, fields, and randomness are canonical lower-case hex wire
strings/objects. `decrypt_bounded` and `decrypt_recovery_pair` return quoted
decimal strings so values above JavaScript’s 53-bit safe integer range are not
rounded.

The exact Rust structs (`Statement`, `WitnessWire`, `ProofEnvelope`,
`RecoveryPair`, `PublicKey`, `Ciphertext`, and `Commitment`) are the stable
typed API. Core must construct statements from finalized stored pre-state and
compare the canonical public slots before calling its native or host verifier.
