# Confidential Core contract API

This document describes the ABI implemented by
'contracts/confidential-core'. It is the shared contract between the browser,
prover, keeper, indexer, and the Core contract. It intentionally describes
private values as ciphertexts, commitments, or proof bytes; no private amount
is accepted as a plaintext argument or returned by a view.

## Deployment

'new(InitArgs)' is the only deployment initializer. The configured NEP-141
token account, decimals, controller, network ID, asset encryption keys,
'crypto_profile_hash', and verifier manifest hash are immutable. Verifier keys
are uploaded one statement kind at a time with 'stage_verifier_key' and become
immutable only after the owner calls 'activate_verifier_keys'; all required
statement kinds must be present before any financial method is enabled. The
legacy single-key initializer is rejected. There is no unrestricted upgrade,
verifier replacement, debt reset, or payout redirection method.

All public amounts are JSON decimal strings ('U128'). IDs, timestamps, and
versions are serialized as canonical decimal strings (no JSON numbers, leading
zeroes, or '+' prefix). Scalar ID/cursor arguments use near-sdk 'U64' and have
the same string wire form. A browser should carry them as strings to avoid
JavaScript precision loss.

## Public lifecycle methods

| Method | Input | Authority | Result |
| --- | --- | --- | --- |
| 'storage_deposit' | optional self account | account | Records NEAR storage budget |
| 'register_holder' | key ID, public key, possession proof | holder | Registers an encryption/authorization epoch |
| 'register_authorization_key' / 'revoke_authorization_key' | application key and proof, or key ID | account | Advances public auth epoch and revokes a key without touching encrypted balances |
| 'create_vault' | asset phase/share/checkpoint policy | caller | Vault ID |
| 'create_broker' | vault, broker key, debt cap, PoP | vault owner | Broker ID |
| 'create_proposal' | parties, schedule, encrypted P/O/Q, agreement digest/signatures | broker owner or borrower | Proposal ID |
| 'sign_proposal' | proposal ID, signature | proposal party | Updates that party's signature |
| 'revoke_proposal' | proposal ID | proposal party | Permanent proposal tombstone |
| 'deposit_to_vault' | claim ID, vault, amount, slippage, expiry | claim owner | Burns claim and mints shares |
| 'redeem_shares' | vault, shares, slippage, expiry, sole-shareholder flag | share owner | Burns shares and returns a PublicClaim ID |
| 'transfer_shares' | vault, receiver, shares | share owner | Transfers public shares if enabled |
| 'shield' | claim, public amount, ciphertexts, commitment, proof | claim owner | Moves claim to holder inbox |
| 'unshield' | amount, post-spending ciphertexts, proof, expected version | holder | Creates a PublicClaim |
| 'merge_inbox' | expected version, exact homomorphic spending+inbox ciphertext | holder | Moves inbox to spending and increments version |
| 'draw' | broker, public amount, broker/audit ciphertexts, proof | broker owner | Reduces vault liquidity and increases broker debt |
| 'originate' | proposal, all post-ciphertexts/roots, proof | party or relayer | Creates an Active loan atomically |
| 'confidential_send' | receiver, expected sender version, five transfer views, post states, proof | sender holder | Credits receiver inbox without changing receiver spending version |
| 'repay' | loan/mode, expected loan/spending versions, five views, post states, proof | borrower | Regular or full confidential payment |
| 'manage_loan' | loan, 'Impair'/'Unimpair'/'Default', expected version, aggregate post states, proof | broker owner | Changes public risk state; queues accounting |
| 'prepare_reconciliation' | broker ID | anyone | Creates the next scheduled checkpoint |
| 'reconcile_credit' | checkpoint, bounded public outputs, proof | anyone with valid proof | Applies aggregate loss/provision once |
| 'merge_broker_inbox' | broker, expected version, exact homomorphic spending+inbox ciphertext | owner or settlement keeper | Broker-only inbox merge |
| 'settle' | broker, public amount, expected versions, post states/proof, optional reconciliation | owner or scoped keeper | Returns broker funds to associated vault |
| 'grant_keeper' / 'revoke_keeper' | broker scope/limits/expiry or delegate | broker owner | Changes settlement/merge grant epoch |
| 'delete_loan' | closed loan ID and evidence | borrower or broker owner | Removes display entry; retains leaf tombstone |
| 'delete_broker' | broker ID | broker owner | Removes only an entirely closed broker |

'Regular' repayment requires the proof to establish 'Q <= X < O' and more
than one installment remaining. 'Full' repayment requires 'X = O', clears all
owed ciphertexts and principal remaining, sets 'Paid', and sets
'payment_remaining'/'next_due' to zero. The encrypted principal allocation and
aggregate 'C/H/I' updates are part of the same proof; the caller cannot submit
a public repayment amount.

'manage_loan(Default)' requires 'now > next_due + grace' (exclusive deadline).
Default is terminal. Impairment is allowed only after the next due date, and
accounting remains pending until the current authenticated book is reconciled.

`merge_broker_inbox` accepts `broker_id` plus `{ expected_spending_version,
new_spending_ciphertext }`; the new ciphertext must equal the homomorphic sum
of the stored spending and inbox values, and no plaintext or caller-selected
replacement is accepted. `settle` accepts
`SettleArgs` with the public `amount`, expected spending/accounting versions,
the three broker post-state ciphertexts, optional spending/inbox commitments,
an optional `ReconcileArgs`, and the settlement proof. A keeper may submit this
only within its immutable per-operation/per-window limits. `ReconcileArgs`
contains the checkpoint and broker IDs, expected risk/accounting versions,
public `new_broker_debt`, `new_broker_provision`, `loss`, and
`new_vault_total`, plus the reconciliation proof. Those public outputs are
checked against the authenticated encrypted aggregate by the verifier; they
are not accepted as an operator-selected write.

## External NEP-141 boundary

The configured token alone may call:

    ft_on_transfer(sender_id, amount, '{"version":1,"deposit_id":"..."}')

The first '(token,sender,deposit_id)' receipt creates exactly one
'PublicClaim' and returns '0'. A duplicate with the same payload returns the
whole amount with no second credit. A mismatched reuse, unsupported message,
wrong token, cap violation, or invalid amount returns the whole incoming
amount and changes no state. Direct 'ft_transfer' donations never create
claims.

'request_payout' fixes the owner, recipient, amount, operation ID, token method,
and one dispatch attempt, moves the claim to a reservation, and dispatches
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
'get_holder', 'get_holder_key', 'get_broker_key', 'get_loan', 'get_proposal', 'get_claim', 'get_payout',
'get_checkpoint', 'get_deposit_receipt', 'get_vault_broker_ids',
'get_share_balance', 'list_vaults', 'list_brokers', 'list_loans',
'list_claims', 'list_payouts', 'get_counters', and 'public_totals' expose public
records and authorized encrypted views. 'get_counters' returns high-water
marks so range pagination can continue across deleted/filtered IDs. The
'list_recovery_history' and 'list_recovery_records' pages return immutable
proof-bound statement records with 'next_cursor'/'end_cursor'. Deterministic
merge/status transitions carry metadata without a private statement, while
proof-bearing mutations carry canonical statements. The pages never scan an
unbounded collection. 'prepare_context' and 'get_operation_context' return the
immutable asset/profile/network identity, current IDs and versions, and a
canonical state digest for prover statement construction. 'get_statement_context'
also returns bounded authoritative ciphertexts, commitments, and public schedule
values needed to build the typed statement. 'get_proof_context(ProofContextArgs)'
is the executable client endpoint: it takes explicit affected account,
destination, primary ID, broker/checkpoint, action, and public amount and
returns canonical 'OperationContext' bytes plus current ciphertexts, keys,
commitments, versions, and the prepared-key hash. It never uses the RPC
predecessor as an implicit party. 'prepare_statement' accepts a canonical
typed 'confidential_crypto::Statement' JSON value, validates its kind and
authoritative context, derives public inputs from that statement, and returns
the same statement/context for local proving. It does not hash arbitrary
caller-selected outputs. A wallet must
refresh these views after a merge or any stale-state error.

Loan records contain five ciphertext views for transfer amounts and exactly
three ciphertext views for stored P/O/Q/R terms in the fixed order
'[borrower, broker, loan auditor]'. Aggregate principal commitments are
homomorphically updated from verified proof deltas; caller-supplied replacement
commitments are rejected. Events contain IDs, versions,
ciphertext references, and public lifecycle/accounting outputs; they never
contain decrypted witnesses or private plaintext amounts.

## Proof context

Every proof argument contains a typed statement:

    { "statement": "<canonical Statement JSON>",
      "verifying_key_hash": "<immutable prepared-key hash>",
      "proof": "<profile proof bytes>",
      "context": "<optional consistency bytes>",
      "public_inputs": "<optional consistency inputs>" }

The method selects the statement kind and recomputes the expected context from
the operation domain, immutable profile/manifest hashes, exact current
pre-state, affected IDs/keys/epochs, expected versions, and method-specific
post ciphertexts. A statement kind, public-input vector, or context hash
supplied by a caller is only a consistency check; authoritative public inputs
come from the parsed typed statement itself and are verified against the
immutable prepared key for that kind. Proof validity never grants
authorization: direct predecessor/keeper/party checks and proposal
epochs/nonces are also enforced.

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
tombstones.
