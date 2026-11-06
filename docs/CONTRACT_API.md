# Confidential Core contract API

This document describes the ABI implemented by
'contracts/confidential-core'. It is the shared contract between the browser,
prover, keeper, indexer, and the Core contract. It intentionally describes
private values as ciphertexts, commitments, or proof bytes; no private amount
is accepted as a plaintext argument or returned by a view.

## Deployment

'new(InitArgs)' is the only deployment initializer. The configured NEP-141
token account, decimals, controller, network ID, asset encryption keys,
'crypto_profile_hash', verifier key, and verifier manifest hash are immutable.
The initializer rejects empty profile/artifact values and caps
'custody_cap' at '2^63 - 1'. There is no unrestricted upgrade, verifier
replacement, debt reset, or payout redirection method.

All public amounts are JSON decimal strings ('U128'). IDs and versions are
currently monotonic 'u64' values and are unique within a Core. A browser should
carry them as strings to avoid JavaScript precision loss.

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
| 'merge_inbox' | expected version, post-spending ciphertext, optional proof | holder | Moves inbox to spending and increments version |
| 'draw' | broker, public amount, broker/audit ciphertexts, proof | broker owner | Reduces vault liquidity and increases broker debt |
| 'originate' | proposal, all post-ciphertexts/roots, proof | party or relayer | Creates an Active loan atomically |
| 'confidential_send' | receiver, expected sender version, five transfer views, post states, proof | sender holder | Credits receiver inbox without changing receiver spending version |
| 'repay' | loan/mode, expected loan/spending versions, five views, post states, proof | borrower | Regular or full confidential payment |
| 'manage_loan' | loan, 'Impair'/'Unimpair'/'Default', expected version, aggregate post states, proof | broker owner | Changes public risk state; queues accounting |
| 'prepare_reconciliation' | broker ID | anyone | Creates the next scheduled checkpoint |
| 'reconcile_credit' | checkpoint, bounded public outputs, proof | anyone with valid proof | Applies aggregate loss/provision once |
| 'merge_broker_inbox' | broker, expected version, post spending ciphertext, proof | owner or settlement keeper | Broker-only inbox merge |
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
'InFlight' operation remains locked. There is no timeout refund or resend.

## Read APIs

'get_asset_profile', 'get_verifier_config', 'get_vault', 'get_broker',
'get_holder', 'get_loan', 'get_proposal', 'get_claim', 'get_payout',
'get_checkpoint', 'get_deposit_receipt', 'get_vault_broker_ids',
'get_share_balance', 'list_vaults', 'list_brokers', 'list_loans',
'list_claims', 'list_payouts', and 'public_totals' expose public records and authorized
encrypted views. 'prepare_context' and 'get_operation_context' return the
immutable asset/profile/network identity, current IDs and versions, and a
canonical state digest for prover statement construction. 'get_statement_context'
also returns bounded authoritative ciphertexts, commitments, and public schedule
values needed to build the typed statement. 'prepare_statement' accepts only
encrypted post-state values/commitments and public fields, merges them with
authoritative current storage, and returns the canonical context used by the
mutating method. A wallet must
refresh these views after a merge or any stale-state error.

Loan records contain five ciphertext views for transfer amounts and three
ciphertext views for stored P/O/Q terms. Events contain IDs, versions,
ciphertext references, and public lifecycle/accounting outputs; they never
contain decrypted witnesses or private plaintext amounts.

## Proof context

Every proof argument is:

    { "context": "<canonical digest bytes>", "proof": "<profile proof bytes>" }

The contract recomputes the context from the operation domain, immutable
profile/manifest hashes, exact current pre-state, affected IDs/keys/epochs,
expected versions, and all caller-supplied post ciphertexts/roots. A context
that does not match current storage fails before mutation. The verifier
boundary is intentionally closed until deployment links immutable per-
statement prepared verification keys and the native/WASM `near-verifier`
adapter. Once activated, that adapter constructs the authoritative public-input
vector and calls the prepared key; a context hash, caller-selected key, or
pairing envelope alone is never sufficient. Proof validity never grants
authorization: direct predecessor/keeper/party checks and proposal epochs are
also enforced.

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
