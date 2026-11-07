# Registered operation authorization

Direct calls use the authenticated NEAR predecessor. Application authorization
keys are separate Ed25519 keys registered by their account through
`register_authorization_key`. They are not ElGamal encryption keys or NEAR
function-call keys, and do not require a confidential holder balance.
Registering or revoking a key advances its account's epoch and updates an
existing holder's authorization epoch, so prepare affected proofs after that
change is final.

For relayed origination or repayment, prepare and inspect the complete operation
first. Read the registered key's current epoch and nonce from finalized state.
The client exports `originationOperationMessage`, `repaymentOperationMessage`
and `registeredAuthorizationMessage`; the latter returns the 32 bytes to sign
with Ed25519. Add `authorization_key_id`, `authorization_epoch`,
`authorization_nonce` and the 64 signature bytes to the call's `args` object.
The relayer pays its transaction fee and Core storage charge.

The outer message is SHA-256 of this Borsh tuple:

```text
Vec<u8> "registered-authorization-v1"
String network_id
AccountId Core
AccountId asset
AccountId owner
u64 key_id
u64 epoch
u64 nonce
Vec<u8> operation_message
```

Strings and byte vectors use a little-endian u32 length followed by their
bytes. Account IDs use their UTF-8 string encoding. Integers are little-endian;
JSON-facing integers remain canonical decimal strings. `operation_message` is
a 32-byte SHA-256 digest. Sign these returned bytes directly, without a wallet
message prefix, JSON encoding, or another hash.

Origination's operation digest binds its domain tag, proposal ID, stored
agreement digest, current broker spending version and exact proof statement
bytes. Repayment's digest binds its domain tag, loan ID, mode, expected loan
and borrower spending versions, and exact proof statement bytes. The statement
already binds the cryptographic profile, deployment, participants, encrypted
effects and authoritative pre-state. See [the Core ABI](CONTRACT_API.md) for the
precise operation tuples.

The proof statement byte vector must be copied from the prepared call. Parsing
and reserializing its JSON can change the bytes that were signed. Regenerating
a proof against changed state requires a fresh exact-operation authorization.

The contract consumes the accepted nonce only with the successful financial
transition. A rejected operation leaves it available. A revoked key, stale
epoch or consumed nonce fails. Changing the key ID or epoch cannot reuse the
signature, including when two registrations use the same public key. Proposal
consent is still required independently from the relayer's authority to submit
funding.

Registered-key proposal consent uses the same outer envelope, with the
finalized proposal's `agreement_digest` as its operation message. Its owner,
key ID, epoch and nonce must match that party's fields in the proposal.
Borrowers still decrypt and verify the agreement before consenting. A direct
party call can authorize the proposal without an application-key signature.

Keep the original signed transaction when its result is unknown. An RPC timeout
is not evidence of failure and does not authorize a second spend.
