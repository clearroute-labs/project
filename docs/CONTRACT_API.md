# Confidential Core contract API

This document describes the ABI implemented by
'contracts/confidential-core'. It is the shared contract between the browser,
prover, keeper, indexer, and the Core contract. It intentionally describes
private values as ciphertexts, commitments, or proof bytes; no private amount
is accepted as a plaintext argument or returned by a view.

## Deployment

'new(InitArgs)' is the only deployment initializer. The configured NEP-141
token account, decimals, controller, network ID, asset encryption keys,
'crypto_profile_hash', authorization policy (`permissionless-v1`), verifier manifest hash, and canonical manifest JSON are
immutable. `InitArgs.verifier_manifest_json` must be the compact canonical JSON
whose fields are, in order, `schema`, `profileHash`, `networkId`,
`coreAccountId`, `setup`, and an alphabetically ordered `artifacts` object.
Each artifact entry has exactly `path`, `sha256`, and `bytes`; the complete
object contains 27 entries: `<family>.pk`, `<family>.vk`, and
`<family>.prepared-vk` for all eight families (`key-possession`,
`public-conversion`, `confidential-transfer`, `origination`, `repayment`,
`reconciliation`, `zero-balance`, and `ownership`), plus `native.prover`,
`browser.glue`, and `browser.wasm`. Core validates every artifact commitment,
hashes the exact JSON bytes, and requires that digest to equal
`verifier_manifest_hash`. It persists the verifier hash/length and profile
public-input expectations; the proving/executable entries remain pinned by the
immutable manifest hash. Duplicate, missing, unknown, non-canonical, or
deployment-mismatched entries are rejected. Verifier keys are uploaded one
statement kind at a time with `stage_verifier_key`; a staged prepared key must
match its manifest byte length and SHA-256, embed the manifest's canonical
`.vk` hash, and expose the family's expected public-input count. Keys become
immutable only after the owner calls `activate_verifier_keys`; all eight exact
pinned kinds must be present before any financial method is enabled. The
legacy single-key initializer is rejected. There is no unrestricted upgrade,
verifier replacement, debt reset, or payout redirection method.

`authorization_policy` is fixed to `permissionless-v1` and `freeze_policy` is
fixed to `controller-freeze-v1`; these are enforced capability identifiers,
not descriptive metadata. The controller's `set_holder_frozen` method also
records freezes for accounts that do not yet have a holder record, and charges
the controller's storage budget for each new map entry. Registered holders
mirror that state in `HolderView.frozen`. Asset/account freezes reject new
deposits, share/debt/private-balance movement, and payout dispatch. Callback
result recording, payout finalization, loan management, and reconciliation
remain available so a freeze cannot strand claims or accounting progress.
`get_freeze_status(account_id?)` is the authoritative view for the global
asset freeze and the selected account freeze.

All public amounts are JSON decimal strings ('U128'). IDs, timestamps, and
versions are serialized as canonical decimal strings (no JSON numbers, leading
zeroes, or '+' prefix). Scalar ID/cursor arguments use near-sdk 'U64' and have
the same string wire form. A browser should carry them as strings to avoid
JavaScript precision loss. The JSON-facing `AssetProfile` is returned as a
view with `authorization_policy`, `confidential_outstanding: U128`, and
`custody_cap: U128`; the native storage record is not exposed.

## Public lifecycle methods

| Method | Input | Authority | Result |
| --- | --- | --- | --- |
| 'storage_deposit' | optional self account | account | Records NEAR storage budget |
| 'register_holder' | key ID, public key, possession proof; one aggregate zero proof when rotating | holder | Registers an encryption/authorization epoch |
| 'register_authorization_key' / 'revoke_authorization_key' | application key, or key ID | direct account | Advances public auth epoch and revokes a key without touching encrypted balances |
| 'create_vault' | asset phase/share/checkpoint policy | caller | Vault ID |
| 'create_broker' | vault, broker key, debt cap, PoP | vault owner | Broker ID |
| 'create_proposal' | parties, schedule, encrypted P/O/Q, agreement digest/signatures | broker owner or borrower | Proposal ID |
| 'sign_proposal' | proposal ID, signature | proposal party | Updates that party's signature |
| 'revoke_proposal' | proposal ID | proposal party | Permanent proposal tombstone |
| 'deposit_to_vault' | claim ID, vault, amount, slippage, expiry | claim owner | Burns claim and mints shares |
| 'redeem_shares' | vault, shares, slippage, expiry, sole-shareholder flag | share owner | Burns shares and returns a PublicClaim ID |
| 'redeem_amount' | vault, `assets_out`, `max_shares_in`, expiry, sole-shareholder flag | share owner | Computes ceil shares with checked 256-bit arithmetic and burns them for exactly the requested amount |
| 'transfer_shares' | vault, receiver, shares | share owner | Transfers public shares if enabled |
| 'shield' | claim, public amount, typed proof | claim owner | Moves claim to holder inbox |
| 'unshield' | amount, expected spending version, typed proof | holder | Creates a PublicClaim |
| 'merge_inbox' | expected version, exact homomorphic spending+inbox ciphertext | holder | Moves inbox to spending and increments version |
| 'draw' | broker, public amount, typed proof | broker owner | Reduces vault liquidity and increases broker debt |
| 'originate' | proposal and typed proof | party or relayer | Creates an Active loan atomically |
| 'confidential_send' | receiver, expected sender version, typed proof | sender holder | Credits receiver inbox without changing receiver spending version |
| 'repay' | loan/mode, expected loan/spending versions, typed proof; optional relayed auth key/epoch/nonce/signature | borrower or registered relayer | Regular or full confidential payment |
| 'manage_loan' | loan, 'Impair'/'Unimpair'/'Default', expected version | broker owner | Changes public risk state; queues accounting |
| 'prepare_reconciliation' | broker ID | anyone | Returns the current snapshot checkpoint or replaces a stale one |
| 'reconcile_credit' | checkpoint, bounded public outputs, proof | anyone with valid proof | Applies aggregate loss/provision once |
| 'merge_broker_inbox' | broker, expected version, exact homomorphic spending+inbox ciphertext | owner or settlement keeper | Broker-only inbox merge |
| 'settle' | broker, public amount, expected versions, post states/proof, optional reconciliation | owner or scoped keeper | Returns broker funds to associated vault |
| 'grant_keeper' / 'revoke_keeper' | broker scope/limits/expiry or delegate | broker owner | Changes settlement/merge grant epoch |
| 'delete_loan' | closed loan ID and evidence | borrower or broker owner | Removes active entry; retains full terminal loan archive and leaf tombstone |
| 'delete_broker' | broker ID | broker owner | Removes only an entirely closed broker |

`originate` keeps the existing direct-party ABI: a broker owner or borrower
may omit the optional `authorization_key_id`, `authorization_epoch`,
`authorization_nonce`, and `authorization_signature` fields. A non-party
relayer must provide all four fields. The signature is Ed25519 over the
SHA-256 of the canonical Borsh envelope
`("registered-authorization-v1", network_id, core_account_id, asset_account,
signer_account_id, key_id, epoch, nonce, operation_message)`. Here
`operation_message` is a `Vec<u8>` containing the SHA-256/Borsh hash of
`("originate-authorization-v1", proposal_id, agreement_digest,
broker_spending_version, proof.statement)`. The envelope is checked against
either party's currently registered authorization key, exact epoch, and exact
nonce, so changing any lookup argument invalidates the signature.
The accepted nonce is incremented atomically after the proof and all ledger
bindings succeed; wrong epoch, revoked key, stale nonce, or replay is rejected.
The broker's encryption-key epoch is not an application authorization epoch.
Relayed `repay` uses the same outer envelope with its operation-specific
payload hash; direct borrower repayment keeps the zero/default authorization
fields.

`BrokerView.live_loan_count` counts every active-book loan, including loans
whose public status is terminal but which have not yet been deleted. Its
`pending_proposal_count` counts every unconsumed, unrevoked proposal, including
expired proposals until a party revokes them. `delete_broker` requires both
counters (and all public/private obligations) to be zero, so terminal records
cannot orphan a broker. `vault_brokers` is append-only and preserves closed
broker IDs as tombstones. A vault lifetime is capped at
`MAX_BROKERS_PER_VAULT = 64`, including deleted entries; page the list with
`get_vault_broker_ids` and resolve a closed ID with `get_broker_tombstone`.

`storage_deposit` charges the measured first `StorageDeposits` map entry from
the attached NEAR before returning the remaining budget; a top-up of an
existing entry is credited in full. Every mutating method charges any further
persistent bytes to the caller's recorded budget and rolls back atomically when
that budget is insufficient. `stage_verifier_key` is payable but its attached
NEAR is not silently treated as a key budget: the owner must pre-fund the
owner's Core storage balance, and the measured prepared-key bytes are charged
to that balance before the call commits.

`register_holder` is a key rotation when the account already has a holder
record.  The rotation request must use a fresh `key_id` and public key and
must carry exactly one `ZeroBalance` proof whose context operation is
`holder-zero-total`.  Its ciphertext is the homomorphic sum of the previous
key's spending and inbox balances, and its context binds the previous
`spending_version` and `authorization_epoch`.  Issuer and auditor private
keys are not required.  First registration carries no zero proof.  The
resulting `HolderView.recovery_start_sequence` is the holder history count at
the rotation boundary; clients replay recovery records from that sequence
with the new key while retaining earlier records for audit.  Rotation
preserves the holder's freeze state.

'Regular' repayment requires the proof to establish 'Q <= X < O' and more
than one installment remaining. 'Full' repayment requires 'X = O', clears all
owed ciphertexts and principal remaining, sets 'Paid', and sets
'payment_remaining'/'next_due' to zero. The encrypted principal allocation and
aggregate 'C/H/I' updates are part of the same proof; the caller cannot submit
a public repayment amount. `BrokerView.active_principal_*` is the homomorphic
H+I aggregate (healthy plus impaired), while `impaired_principal_*` is I;
repayment always reduces active and additionally reduces impaired when the
loan is impaired.

'manage_loan(Default)' requires 'now > next_due + grace' (exclusive deadline).
Default is terminal. Impairment is allowed only after the next due date, and
accounting remains pending until the current authenticated book is reconciled.

`delete_broker` and final redemption accept a preferred `combined_proof` in
`BrokerZeroProofArgs`. It proves a zero balance for the homomorphic sum of the
broker spending, inbox, active-principal and impaired-principal ciphertexts,
reducing closure verification to one bounded ZeroBalance proof. The four
per-field proof members remain optional compatibility fields; callers must
provide either the combined proof or all four legacy proofs. Final redemption
rejects a vault with more than four still-live brokers before any zero-proof
verification; close brokers sequentially first so the per-call proof path
remains within the contract gas budget.

`merge_broker_inbox` accepts `broker_id` plus `{ expected_spending_version,
new_spending_ciphertext }`; the new ciphertext must equal the homomorphic sum
of the stored spending and inbox values, and no plaintext or caller-selected
replacement is accepted. `settle` accepts `SettleArgs` with the public
`amount`, expected spending/accounting versions, a typed public-conversion
proof, and an optional bundled `ReconcileArgs`. The three broker post-state
ciphertexts, commitments, settlement views, and aggregate/book outputs are
derived from the verified statement and current storage; legacy fields are
optional consistency checks only. A keeper may submit this only within its
immutable per-operation/per-window grant. Grants explicitly list
`MergeInbox` and/or `Settle`, bind a registered delegate authorization key and
epoch, and are visible through `delegates` and `get_keeper_grants`; the broker
view also exposes `authorization_epoch` and `last_settlement_at`.
For a positive-U settlement, a scoped keeper may not call
`prepare_reconciliation`. Instead it requests
`get_proof_context({ operation: "settle-reconcile", broker_id, amount })` after
the broker's checkpoint cadence boundary, proves the virtual post-settlement
aggregate, and submits the same `settle` call with
`reconciliation.checkpoint_id: "0"`. Core derives the next checkpoint ID,
binds it into the reconciliation statement context, and consumes the checkpoint
atomically with settlement. A nonzero checkpoint ID is reserved for a
permissionless checkpoint created by `prepare_reconciliation`; only the
broker's current `reconciliation_checkpoint_id` is accepted.
`ReconcileArgs` contains the checkpoint and broker IDs, expected risk/accounting
versions, public `new_broker_debt`, `new_broker_provision`, `loss`, and
`new_vault_total`, plus the reconciliation proof. Those public outputs are
checked against the authenticated encrypted aggregate by the verifier; they
are not accepted as an operator-selected write. `manage_loan` similarly derives
principal aggregates and the authenticated sparse-book leaf from stored state;
its optional proof is an additional typed consistency check, not a replacement
for broker-owner authorization.

Keeper grants are a bounded live capability set (at most 32 entries). Granting
the same delegate account replaces its existing entry in place, while expired
or revoked entries are pruned before a new slot is allocated. Core advances the
broker authorization epoch and rebinds every surviving active grant on each
grant/revoke operation, so a pre-revocation proof cannot be replayed; grant
events retain the replacement and epoch audit trail. A live replacement carries
the current window's spent amount forward, so redelegation cannot reset the
per-window settlement cap.

## External NEP-141 boundary

The configured token alone may call:

    ft_on_transfer(sender_id, amount, '{"version":1,"deposit_id":"..."}')

The message is strict JSON containing only `version` and `deposit_id`; Core
parses it and hashes the canonical Borsh tuple
`(token, sender, amount, version, deposit_id)` for replay identity. Whitespace,
JSON key order, or unknown fields cannot create an alternate receipt.
The first '(token,sender,deposit_id)' receipt creates exactly one
'PublicClaim' and returns '0'. A duplicate with the same payload returns the
whole amount with no second credit. A mismatched reuse, unsupported message,
wrong token, cap violation, or invalid amount returns the whole incoming
amount and changes no state. Direct 'ft_transfer' donations never create
claims.

'request_payout' fixes the owner, recipient, amount, operation ID, token method,
and one dispatch attempt, rejects a frozen owner or recipient, moves the claim
to a reservation, and dispatches
'ft_transfer' with exactly one yoctoNEAR. The private callback
'on_payout_result' accepts only the Core predecessor and one runtime
'PromiseResult'; it records success/failure and makes no external call.
'finalize_payout' is permissionless and idempotent: success consumes the
reservation, failure restores the exact original claim, and an unresolved
'InFlight' operation remains locked. A runtime 'PromiseError::TooLong' is
treated as successful token transfer and records a fixed hash of the outcome
marker/observed length; only 'PromiseError::Failed' restores the claim. There
is no timeout refund or resend.

## Read APIs

'get_asset_profile', 'get_verifier_config', 'get_verifier_key', 'get_vault', 'get_broker',
'get_broker_tombstone',
'get_holder', 'get_holder_key', 'get_broker_key', 'get_loan', 'get_archived_loan',
'get_loan_tombstone', 'get_proposal', 'get_claim', 'get_payout',
'get_checkpoint', 'get_deposit_receipt', 'get_vault_broker_ids(vault_id, cursor, limit)',
'get_share_balance', 'list_vaults', 'list_brokers', 'list_loans',
'list_claims', 'list_payouts', 'get_counters', and 'public_totals' expose public
records and authorized encrypted views. 'get_counters' returns high-water
marks so range pagination can continue across deleted/filtered IDs. The
'list_recovery_history' and 'list_recovery_records' pages return immutable
proof-bound statement records with 'next_cursor'/'end_cursor'. Deterministic
merge/status transitions carry metadata without a private statement, while
proof-bearing mutations carry canonical statements. The pages never scan an
unbounded collection. 'get_freeze_status(account_id?)' reports asset and
holder freeze state separately and does not grant an override. 'get_keeper_grants'
returns bounded delegate views with U128 limits, operation scopes, delegate and
revocation epochs, expiry and window counters; broker views include the same
grants, the broker authorization epoch, accounting-pending timestamp,
current reconciliation checkpoint ID, and last settlement timestamp.
'prepare_context' and 'get_operation_context' return the
immutable asset/profile/network identity, current IDs and versions, and a
canonical state digest for prover statement construction. 'get_statement_context'
also returns bounded authoritative ciphertexts, commitments, and public schedule
values needed to build the typed statement. 'get_proof_context(ProofContextArgs)'
is the executable client endpoint: it takes explicit affected account,
destination, primary ID, broker/checkpoint, action, and public amount and
returns canonical 'OperationContext' bytes plus current ciphertexts, keys,
commitments, versions, and the prepared-key hash. It never uses the RPC
predecessor as an implicit party. This context is authoritative: the wallet
constructs its typed `confidential_crypto::Statement` locally from these
state-bound values and submits it with the mutation proof; there is no generic
caller-selected statement-preparation endpoint. A wallet must
refresh these views after a merge or any stale-state error.

`get_proof_context` operation `settle-reconcile` returns the post-settlement
accounting version and the derived checkpoint ID. It is the only context a
keeper needs for the bundled path; no keeper authority is granted for
`prepare_reconciliation` or arbitrary reconciliation. A checkpoint prepared
for a prior risk version is retired as a permanent consumed tombstone when a
new checkpoint is prepared or successfully bundled; the replacement ID is
derived from the checkpoint high-water counter. Repeated preparation for the
same risk snapshot is idempotent. If a broker has positive provision but no
new `accounting_pending` risk boundary, the inline context is immediately
eligible rather than inventing a future cadence.

Mutation events include a decimal-string `recovery_event_id` whenever the
transition appends a recovery record. Settlement additionally exposes
`reconciliation_recovery_event_id` when it consumes a bundled checkpoint;
these IDs resolve to the immutable bounded history pages rather than to
caller-supplied ciphertext mirrors.

Proposal `broker_authorization_epoch`/`broker_authorization_nonce` refer to
the broker owner's registered application authorization key, when one is
provided; they never refer to the broker encryption key epoch. A direct
broker-owner proposal uses no application key and pins those fields to zero.
The encryption key ID remains separately pinned in the proposal ciphertext
terms. Signed broker and borrower agreements are verified over the exact
stored agreement digest and current registered key epoch/nonce; a typed proof
cannot substitute for either party authorization.

For wallet registration flows, `get_proof_context` uses operation
`register-holder` with `{ account_id, key_id }` and `create-broker` with
`{ account_id, primary_id: vault_id, broker_id, key_id }`; these contexts pin
the next authorization epoch or globally allocated broker ID. Financial
mutations intentionally accept only their IDs, expected versions, public
boundary amount where applicable, and `proof`; all mirrors, aggregate
commitments, sparse-book roots/leaves and recipient inbox updates are derived
from the authoritative current state. Incoming confidential credits are added
to the destination's current inbox, so a concurrent recipient credit does not
invalidate a sender proof.

Loan records contain five ciphertext views for transfer amounts and exactly
three ciphertext views for stored P/O/Q/R terms in the fixed order
'[borrower, broker, loan auditor]'. Aggregate principal commitments are
homomorphically updated from verified proof deltas; caller-supplied replacement
commitments are rejected. Events contain IDs, versions,
ciphertext references, and public lifecycle/accounting outputs; they never
contain decrypted witnesses or private plaintext amounts.

For credit-mode shield/draw proofs, Core authenticates the public amount,
reader keys, and encrypted delta but does not require the statement's
`spending_before` to equal the current recipient inbox. It homomorphically adds
the proof-bound delta to the current inbox, so an unrelated incoming credit
does not invalidate a prepared proof. Debit-mode unshield proofs remain bound
to the exact current spending ciphertext and version.

## Proof context

Every proof argument contains a typed statement:

    { "statement": "<canonical Statement JSON>",
      "verifying_key_hash": "<immutable prepared-key hash>",
      "proof": "<profile proof bytes>",
      "context": "<32-byte transcript digest>",
      "public_inputs": "<optional consistency inputs>" }

The method selects the statement kind and recomputes the expected context from
the operation domain, immutable profile/manifest hashes, exact current
pre-state, affected IDs/keys/epochs, expected versions, and method-specific
post ciphertexts. The required context digest is the first proof public input;
the pinned circuit constrains it to the exact typed-statement slot vector, so
Core does not spend gas recomputing the host Poseidon transcript. An optional
public-input vector is only a consistency check; all remaining authoritative
inputs come from the parsed typed statement and are verified against the
immutable prepared key for that kind. Proof validity never grants
authorization: direct predecessor/keeper/party checks and proposal
epochs/nonces are also enforced.

### Canonical zeros and loan-book roots

Every newly-created or reset ciphertext zero is encrypted with a domain that
includes the immutable network ID, Core account, configured asset account,
profile hash, subject label, encryption key ID and key authorization epoch.
The fixed domain prevents a zero ciphertext from one deployment, account or
rotation from being replayed as another subject's state. Holder key rotation
therefore requires one typed zero-balance proof over the homomorphic sum of
the existing spending and inbox ciphertexts under the old holder key; the
ledger's non-negative mirror invariant implies the issuer/auditor mirrors are
zero as well, so their private keys are not required. Byte equality with a
legacy fixed zero is not accepted.

Each broker has a domain-separated sparse Merkle loan book with depth 64 over
loan IDs. Origination, repayment, impairment/unimpairment/default and deletion
update exactly one authenticated path after checking the stored root and
expected leaf. Closed-loan leaves become tombstones in Core storage, and the
complete terminal `Loan` snapshot remains available through
`get_archived_loan`; the root is never accepted from a caller.
`get_loan_tombstone` exposes the terminal-record leaf, sparse-book tombstone
leaf, final status/version, and the active-leaf removal evidence. Each leaf commits schedule dates,
payment counts, impairment/status/version, key IDs and auditor key, agreement
digest, all P/O/Q/R ciphertexts, cumulative repayment ciphertexts, and all
principal/owed/payment commitments. Tombstone leaves additionally commit the
terminal record marker. This keeps membership and omission checks bounded even
when a broker has many historical loans. Reconciliation contexts include the
authoritative current book-root digest in their operation subject without
adding a circuit input.

`get_archived_loan(loan_id)` returns the complete terminal `LoanView` after
deletion, with `tombstoned: true`; it never makes the record visible to
`get_loan`/`list_loans` and cannot be passed to a financial transition.
`get_loan_tombstone(loan_id)` returns `{id, final_status, final_version,
terminal_leaf, leaf, removal_evidence}`. `terminal_leaf` is the digest of the
archived record, `leaf` is the depth-64 book tombstone digest, and
`removal_evidence` is the pre-deletion active leaf.

The canonical `loan-leaf-v2` digest is defined by
`contracts/confidential-core/src/lib.rs::derive_loan_leaf`: domain-separated
`identity-core` (loan/broker/borrower/proposal/schedule/status/impairment/
version), `identity-keys` (key IDs, auditor key, agreement digest),
`ciphertexts` (principal, initial owed, amount owed, periodic payment,
principal remaining, cumulative repaid), and `commitments` (principal, owed,
payment, principal remaining), followed by the tombstoned marker. The sparse
book wraps that terminal digest with `loan-tombstone-v1`, loan ID, final status,
and final version. Clients must consume these chain-provided digests rather
than reimplementing an alternate leaf schema.

## Stable error categories

'INVALID_ENCODING', 'INVALID_AMOUNT', 'WRONG_ASSET', 'UNAUTHORIZED',
'ACCOUNT_FROZEN', 'NOT_REGISTERED', 'WRONG_PHASE', 'EXPIRED', 'STALE_STATE',
'BAD_PROOF', 'INSUFFICIENT_PUBLIC_FUNDS', 'INSUFFICIENT_PRIVATE_FUNDS',
'DEBT_LIMIT', 'ACCOUNTING_PENDING', 'TOO_SOON', 'LOAN_CLOSED',
'HAS_OBLIGATIONS', 'SLIPPAGE', 'OPERATION_PENDING', and
'UNSUPPORTED_PROFILE' are used as panic payloads. Private predicate details are
never included in an error.

## Events

Events use the 'near-confidential-lending' standard and include schema/core/
asset metadata. Implemented lifecycle events include 'VaultCreated',
'BrokerCreated', 'ProposalCreated', 'HolderRegistered', 'SharesMinted',
'SharesRedeemed', 'Shielded', 'Unshielded', 'InboxMerged', 'BrokerDrawn',
'LoanOriginated', 'ConfidentialTransfer', 'LoanRepaid', 'LoanManagement',
'CreditReconciled', 'BrokerSettled', 'DepositReceived', 'PayoutRequested',
'PayoutResultRecorded', 'PayoutFinalized', keeper grant/revoke, and deletion
tombstones. Financial events include every affected borrower/broker spending
version, broker book/accounting/risk version, vault accounting/risk version,
and recovery-event reference as applicable; all IDs and versions are decimal
strings. Transfer events expose the authoritative proof-bound reader views and
commitment rather than empty legacy caller fields. They never contain
plaintext witnesses.
