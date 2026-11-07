import type {
  ActionReceipt,
  AppAdapters,
  AssetProfile,
  AuthorizationKeyRegistration,
  AuditCiphertextBundle,
  BrokerSummary,
  DashboardSnapshot,
  DeploymentConfig,
  HolderKeyView,
  BrokerKeyView,
  KeeperGrant,
  KeyRegistration,
  LoanManagementPreparation,
  PrivateAccountView,
  PreparedProof,
  ProposalSummary,
  ProtocolClient,
  WalletAdapter,
} from './types'
import { ProtocolError } from './types'
import { ContractClient, NearRpc, type WalletAdapter as RpcWalletAdapter } from '@confidential-lending/client'

/**
 * Minimal bridge expected from the real NEAR SDK. The root client package
 * supplies finality-aware JSON-RPC reads and wallet-signed calls; this adapter
 * only maps typed product actions to the Core API and never manufactures data.
 */
export interface NearContractTransport {
  view<T>(method: string, args?: Record<string, unknown>, signal?: AbortSignal): Promise<T>
  call(method: string, args: Record<string, unknown>, options?: { deposit?: string; gas?: string; receiverId?: string; signal?: AbortSignal }): Promise<NearCallResult | undefined>
}

export interface NearCallResult {
  transactionHash?: string
  operationId?: string
  returnValue?: string
  finalized: boolean
  status: 'succeeded' | 'failed' | 'unknown' | 'pending'
}

export interface NearWalletSession {
  readonly status: WalletAdapter['status']
  readonly accountId?: string
  readonly networkId?: string
  readonly error?: string
  connect(): Promise<void>
  disconnect(): Promise<void>
  subscribe(listener: () => void): () => void
  signAndSendTransaction(params: { receiverId: string; actions: Array<{ type: 'FunctionCall'; params: { methodName: string; args: Record<string, unknown>; gas: string; deposit: string } }> }): Promise<{ transaction: { hash: string; signer_id: string } } | void>
}

function proofArgs(proof: PreparedProof): Record<string, unknown> {
  const operationArgs = { ...(proof.operationArgs || {}) }
  // Operation arguments are produced by the browser crypto provider and are
  // intentionally limited to ciphertexts, commitments, roots and public
  // counters. Never let a provider-supplied duplicate proof/context shadow
  // the canonical proof envelope below.
  delete operationArgs.proof
  delete operationArgs.context
  delete operationArgs.statement
  delete operationArgs.statement_kind
  delete operationArgs.statement_digest
  delete operationArgs.artifact_hash
  delete operationArgs.public_inputs
  delete operationArgs.verifying_key_hash
  delete operationArgs.profile_hash
  for (const key of Object.keys(operationArgs)) {
    if (/^(?:amount|plaintext|cleartext|witness|secret|private(?:_|$)|decrypted)/i.test(key)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Private proof arguments may contain only ciphertexts, commitments, roots and public versions.' })
    if (!CORE_OPERATION_KEYS.has(key)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Unsupported proof argument ${key}.` })
  }
  const verifyingKeyHash = proof.verifyingKeyHash || (typeof proof.operationArgs?.verifying_key_hash === 'string' ? proof.operationArgs.verifying_key_hash : undefined)
  return {
    ...Object.fromEntries(Object.entries(operationArgs).map(([key, value]) => [key, encodeCoreOperationValue(key, value)])),
    proof: {
      statement: utf8Bytes(proof.statement),
      context: namedHexToBytes(proof.context, 'proof context'),
      proof: namedHexToBytes(proof.proof, 'proof bytes'),
      ...(proof.statementKind === undefined ? {} : { statement_kind: proof.statementKind }),
      // Core derives public-input slots from the canonical statement/profile;
      // do not resend the envelope copy in signed call arguments.
      public_inputs: [],
      verifying_key_hash: verifyingKeyHash ? namedHexToBytes(verifyingKeyHash, 'verifying-key hash') : [],
      profile_hash: namedHexToBytes(proof.profileHash, 'profile hash'),
    },
  }
}

function utf8Bytes(value: string): number[] {
  if (!value.trim()) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'A canonical crypto Statement is required for every proof.' })
  return [...new TextEncoder().encode(value)]
}

function bytesToHex(value: unknown): string {
  if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
    return value.map((item) => (item as number).toString(16).padStart(2, '0')).join('')
  }
  if (typeof value === 'string') return value
  throw new TypeError('Core returned an invalid byte encoding')
}

function hexToBytes(value: string): number[] {
  const normalized = value.trim().replace(/^0x/, '')
  if (!normalized || normalized.length % 2 !== 0 || !/^[a-f\d]+$/i.test(normalized)) throw new TypeError('Expected canonical hex bytes')
  const bytes: number[] = []
  for (let index = 0; index < normalized.length; index += 2) bytes.push(Number.parseInt(normalized.slice(index, index + 2), 16))
  return bytes
}

function namedHexToBytes(value: string, field: string): number[] {
  try {
    return hexToBytes(value)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Expected canonical hex bytes'
    throw new TypeError(`${message} for ${field}`)
  }
}

function optionalHexToBytes(value: string): number[] {
  return value.trim() ? hexToBytes(value) : []
}

function mergeArgs(proof: PreparedProof, expectedSpendingVersion: string): Record<string, unknown> {
  const value = proof.operationArgs?.new_spending_ciphertext
  if (typeof value !== 'string' || !value.trim()) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Inbox merge requires the homomorphic new spending ciphertext.' })
  return { expected_spending_version: expectedSpendingVersion, new_spending_ciphertext: hexToBytes(value), proof: null }
}

const CORE_OPERATION_KEYS = new Set([
  'new_spending_ciphertext', 'issuer_ciphertext', 'auditor_ciphertext', 'broker_ciphertext', 'broker_spending_commitment', 'broker_inbox_commitment',
  'borrower_spending_ciphertext', 'borrower_issuer_ciphertext', 'borrower_auditor_ciphertext', 'broker_spending_ciphertext', 'broker_issuer_ciphertext', 'broker_auditor_ciphertext',
  'loan_principal_ciphertexts', 'loan_initial_owed_ciphertexts', 'loan_periodic_payment_ciphertexts', 'principal_commitment', 'owed_commitment', 'payment_commitment', 'broker_active_principal_ciphertext', 'broker_impaired_principal_ciphertext', 'broker_book_root', 'accounting_leaf', 'broker_active_principal_commitment', 'broker_impaired_principal_commitment',
  'sender_spending_ciphertext', 'sender_issuer_ciphertext', 'sender_auditor_ciphertext', 'destination_inbox_ciphertext', 'destination_issuer_ciphertext', 'destination_auditor_ciphertext', 'transfer_views', 'commitment',
  'broker_inbox_ciphertext', 'amount_owed_ciphertexts', 'principal_remaining_ciphertexts', 'cumulative_repaid_ciphertexts', 'broker_inbox_commitment', 'zero_proof',
  'settlement_views', 'expected_spending_version', 'expected_loan_version', 'expected_borrower_spending_version', 'expected_book_version', 'expected_accounting_version', 'checkpoint_id', 'broker_id', 'loan_id', 'proposal_id', 'expected_risk_version', 'new_broker_debt', 'new_broker_provision', 'loss', 'new_vault_total', 'reconciliation',
])
const CORE_BYTE_KEYS = new Set([
  'new_spending_ciphertext', 'issuer_ciphertext', 'auditor_ciphertext', 'broker_ciphertext', 'broker_spending_commitment', 'broker_inbox_commitment',
  'borrower_spending_ciphertext', 'borrower_issuer_ciphertext', 'borrower_auditor_ciphertext', 'broker_spending_ciphertext', 'broker_issuer_ciphertext', 'broker_auditor_ciphertext',
  'loan_principal_ciphertexts', 'loan_initial_owed_ciphertexts', 'loan_periodic_payment_ciphertexts', 'principal_commitment', 'owed_commitment', 'payment_commitment', 'broker_active_principal_ciphertext', 'broker_impaired_principal_ciphertext', 'broker_book_root', 'accounting_leaf', 'broker_active_principal_commitment', 'broker_impaired_principal_commitment',
  'sender_spending_ciphertext', 'sender_issuer_ciphertext', 'sender_auditor_ciphertext', 'destination_inbox_ciphertext', 'destination_issuer_ciphertext', 'destination_auditor_ciphertext', 'transfer_views', 'commitment', 'settlement_views',
  'broker_inbox_ciphertext', 'amount_owed_ciphertexts', 'principal_remaining_ciphertexts', 'cumulative_repaid_ciphertexts', 'broker_inbox_commitment',
])
const CORE_PROOF_BYTE_KEYS = new Set(['context', 'proof', 'public_inputs', 'verifying_key_hash', 'profile_hash'])
const RECONCILIATION_KEYS = new Set(['checkpoint_id', 'broker_id', 'expected_risk_version', 'expected_accounting_version', 'new_broker_debt', 'new_broker_provision', 'loss', 'new_vault_total', 'cash_commitment', 'active_principal_commitment', 'impaired_principal_commitment', 'proof'])
const RECONCILIATION_BYTE_KEYS = new Set(['cash_commitment', 'active_principal_commitment', 'impaired_principal_commitment'])

function encodeProofEnvelope(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Nested reconciliation proofs must use the Core ProofArgs shape.' })
  const candidate = value as Record<string, unknown>
  const unknown = Object.keys(candidate).filter((key) => !['statement', 'context', 'proof', 'statement_kind', 'public_inputs', 'verifying_key_hash', 'profile_hash'].includes(key))
  if (unknown.length) throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Unsupported nested proof field ${unknown[0]}.` })
  if (typeof candidate.statement !== 'string' || !candidate.statement.trim()) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Nested reconciliation proofs require a canonical crypto Statement.' })
  if (typeof candidate.context !== 'string' || typeof candidate.proof !== 'string') throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Nested reconciliation proofs require canonical context and proof bytes.' })
  const publicInputs = candidate.public_inputs === undefined ? [] : candidate.public_inputs
  if (!Array.isArray(publicInputs) || publicInputs.some((item) => typeof item !== 'string')) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Nested proof public inputs must be canonical hex strings.' })
  return {
    statement: utf8Bytes(candidate.statement),
    context: hexToBytes(candidate.context),
    proof: hexToBytes(candidate.proof),
    ...(candidate.statement_kind === undefined ? {} : { statement_kind: candidate.statement_kind }),
    // Nested envelopes follow the same Core-derived public-input rule.
    public_inputs: [],
    verifying_key_hash: candidate.verifying_key_hash === undefined ? [] : hexToBytes(String(candidate.verifying_key_hash)),
    profile_hash: candidate.profile_hash === undefined ? [] : hexToBytes(String(candidate.profile_hash)),
  }
}

function encodeReconciliation(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Reconciliation must be a Core ReconcileArgs object.' })
  const candidate = value as Record<string, unknown>
  for (const key of Object.keys(candidate)) if (!RECONCILIATION_KEYS.has(key)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Unsupported reconciliation field ${key}.` })
  if (!candidate.proof) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Reconciliation proof is required.' })
  return {
    ...Object.fromEntries(Object.entries(candidate).filter(([key]) => key !== 'proof').map(([key, childValue]) => [key, RECONCILIATION_BYTE_KEYS.has(key) ? optionalHexToBytes(String(childValue)) : childValue])),
    proof: encodeProofEnvelope(candidate.proof),
  }
}

function encodeBrokerZeroProof(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Broker closure requires a Core zero-proof object.' })
  const candidate = value as Record<string, unknown>
  const allowed = new Set(['broker_id', 'combined_proof', 'spending_proof', 'inbox_proof', 'active_principal_proof', 'impaired_principal_proof'])
  for (const key of Object.keys(candidate)) if (!allowed.has(key)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Unsupported broker closure field ${key}.` })
  if (typeof candidate.broker_id !== 'string' && typeof candidate.broker_id !== 'number') throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Broker closure requires a broker ID.' })
  const result: Record<string, unknown> = { broker_id: decimal(candidate.broker_id) }
  for (const key of ['combined_proof', 'spending_proof', 'inbox_proof', 'active_principal_proof', 'impaired_principal_proof']) {
    if (candidate[key] !== undefined && candidate[key] !== null) result[key] = encodeProofEnvelope(candidate[key])
  }
  const legacyProofs = ['spending_proof', 'inbox_proof', 'active_principal_proof', 'impaired_principal_proof']
  if (!result.combined_proof && !legacyProofs.every((key) => result[key] !== undefined)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Broker closure requires a combined proof or all four legacy zero proofs.' })
  return result
}

function encodeCoreOperationValue(key: string, value: unknown): unknown {
  if (value === undefined || value === null) return value
  if (CORE_BYTE_KEYS.has(key) || CORE_PROOF_BYTE_KEYS.has(key)) {
    if (typeof value === 'string') return hexToBytes(value)
    if (Array.isArray(value)) return value.map((item) => typeof item === 'string' ? hexToBytes(item) : item)
    return value
  }
  if (key === 'reconciliation') return encodeReconciliation(value)
  if (key === 'zero_proof') return encodeBrokerZeroProof(value)
  return value
}

function decimal(value: unknown): string {
  if (typeof value === 'string' && /^\d+$/.test(value)) return value
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value)
  throw new TypeError('Core returned a non-canonical decimal value')
}

function optionalDecimal(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined
  return decimal(value)
}

/** Core's U64 JSON adapter accepts canonical decimal strings for every ID. */
function wireId(value: string): string {
  if (!/^\d+$/.test(value)) throw new TypeError('Core IDs must be canonical decimal strings')
  if (value.length > 1 && value.startsWith('0')) throw new TypeError('Core IDs must be canonical decimal strings')
  return value
}

type TokenAuditReaderRole = 'issuer' | 'token_auditor'
type TokenAuditSubject = { kind: 'holder' | 'broker'; id: string }

/**
 * Token-auditor recovery is scoped to one registered subject.  Core has no
 * unbounded token-audit listing endpoint, so the UI carries an explicit
 * `holder:<account>` or `broker:<decimal-id>` subject selector.  Keeping the
 * discriminator in the value prevents an account ID from being confused with
 * a broker ID and keeps all Core IDs canonical at the RPC boundary.
 */
function parseTokenAuditSubject(value: string): TokenAuditSubject {
  const separator = value.indexOf(':')
  if (separator <= 0 || separator === value.length - 1) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Choose a holder account or broker ID for token audit.' })
  const kind = value.slice(0, separator)
  const id = value.slice(separator + 1)
  if (kind === 'holder') {
    if (id.length > 128 || /[\u0000-\u001f\u007f]/.test(id)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'The holder account identifier is invalid.' })
    return { kind, id }
  }
  if (kind === 'broker') return { kind, id: wireId(id) }
  throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Token audit subjects must be a holder account or broker ID.' })
}

function safeNumber(value: unknown, label: string): number {
  const result = decimal(value)
  const number = Number(result)
  if (!Number.isSafeInteger(number)) throw new TypeError(`Core returned an unsafe ${label}`)
  return number
}

function decodeMethodReturn(encoded: string | undefined): string | undefined {
  if (!encoded) return undefined
  try {
    const bytes = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0))
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    const value = JSON.parse(text) as unknown
    if (typeof value === 'string' && /^\d+$/.test(value)) return value
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value)
    return undefined
  } catch {
    return undefined
  }
}

type RawAssetProfile = { token_account: string; decimals: number; controller_account: string; issuer_key: { key_id: string | number; public_key: unknown }; token_auditor_key: { key_id: string | number; public_key: unknown }; crypto_profile_hash: unknown; token_trust_policy: string; authorization_policy?: string; freeze_policy?: string; custody_cap?: string | number; confidential_outstanding?: string | number }
type RawHolder = { owner: string; asset_id: string; key_id: string | number; authorization_epoch?: string | number; public_key?: unknown; encryption_public_key?: unknown; encryption_key?: { public_key?: unknown }; spending_ciphertext: unknown; inbox_ciphertext: unknown; issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown; spending_commitment?: unknown; inbox_commitment?: unknown; spending_version: string | number }
type RawBroker = { broker_id: string | number; owner: string; vault_id: string | number; debt_total: unknown; debt_maximum: unknown; spending_version: string | number; book_version: string | number; loan_book_root?: unknown; encryption_key_id: string | number; authorization_epoch?: string | number; encryption_public_key?: unknown; spending_ciphertext: unknown; inbox_ciphertext: unknown; issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown; spending_commitment?: unknown; inbox_commitment?: unknown; active_principal_ciphertext?: unknown; impaired_principal_ciphertext?: unknown; active_principal_commitment?: unknown; impaired_principal_commitment?: unknown; impairment_provision?: unknown; accounting_pending: boolean; accounting_version: string | number; risk_version?: string | number; delegates?: RawKeeper[] }
type RawVault = { vault_id: string | number; owner: string; asset_id: string; assets_total: unknown; assets_available: unknown; shares_total: unknown; share_scale?: number; checkpoint_policy?: { epoch_seconds?: string | number; disclosure_policy?: string }; accounting_pending: boolean; accounting_version: string | number; phase?: string | null; kind?: string }
type RawLoan = { loan_id: string | number; broker_id: string | number; borrower: string; proposal_id: string | number; payment_interval: string | number; grace_period: string | number; next_due?: string | number | null; payment_total: number; payment_remaining: number; status: string; impaired?: boolean; loan_version: string | number; borrower_key_id?: string | number; broker_key_id?: string | number; loan_auditor_key_id?: string | number; loan_auditor_public_key?: unknown; principal_ciphertexts?: unknown[]; initial_owed_ciphertexts?: unknown[]; amount_owed_ciphertexts?: unknown[]; periodic_payment_ciphertexts?: unknown[]; principal_remaining_ciphertexts?: unknown[]; cumulative_repaid_ciphertexts?: unknown[]; accounting_leaf?: unknown }
type RawProposal = { proposal_id: string | number; borrower: string; broker_id: string | number; vault_id: string | number; borrower_key_id?: string | number; broker_key_id?: string | number; expiry: string | number; agreement_digest: unknown; principal_ciphertexts?: unknown[]; initial_owed_ciphertexts?: unknown[]; periodic_payment_ciphertexts?: unknown[]; principal_commitment?: unknown; owed_commitment?: unknown; payment_commitment?: unknown; loan_auditor_public_key?: unknown; consumed: boolean; revoked: boolean; broker_signature?: unknown; borrower_signature?: unknown; broker_authorization_epoch?: string | number; borrower_authorization_epoch?: string | number; broker_authorization_key_id?: string | number | null; borrower_authorization_key_id?: string | number | null; broker_direct_authorized?: boolean; borrower_direct_authorized?: boolean; loan_auditor_key_id: string | number }
type RawCounters = {
  vault_high_water: string | number
  broker_high_water: string | number
  loan_high_water: string | number
  proposal_high_water: string | number
  claim_high_water: string | number
  payout_high_water: string | number
}
type RawClaim = { claim_id: string | number; owner: string; amount: unknown; reserved_by?: string | number | null }
type RawPayout = { operation_id: string | number; owner: string; recipient: string; amount: unknown; claim_id: string | number; attempt: number; status: string; created_at: string | number }
type RawKeeper = { delegate_account: string; delegate_key_id: string | number; allowed_operations?: string[]; allowed_settlement_per_operation: unknown; allowed_settlement_per_window: unknown; expires_at: string | number; revocation_epoch: string | number; active: boolean }

function mapKeeperScope(values: string[] | undefined): KeeperGrant['scope'] {
  const result: KeeperGrant['scope'] = []
  for (const value of values || []) {
    if (value === 'MergeInbox' && !result.includes('merge')) result.push('merge')
    if (value === 'Settle' && !result.includes('settle')) result.push('settle')
  }
  return result
}

const CORE_VIEW_PAGE_LIMIT = 50
type PageArgs = Record<string, unknown>

function counter(value: unknown, label: string): bigint {
  try {
    return BigInt(decimal(value))
  } catch {
    throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Core returned an invalid ${label}.` })
  }
}

/**
 * Core list views page over an ID cursor, not over returned rows. A filtered
 * page may be empty while later IDs still exist, so `page.length < limit` is
 * not an end marker. The high-water counters are the authoritative bound.
 */
async function readHighWaterPages<T>(transport: NearContractTransport, method: string, highWaterValue: unknown, args: PageArgs, label: string): Promise<T[]> {
  const highWater = counter(highWaterValue, `${label} high-water mark`)
  const values: T[] = []
  for (let cursor = 0n; cursor < highWater; cursor += BigInt(CORE_VIEW_PAGE_LIMIT)) {
    const page = await transport.view<unknown[]>(method, { ...args, cursor: cursor.toString(), limit: CORE_VIEW_PAGE_LIMIT })
    if (!Array.isArray(page)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: `Core returned an invalid ${label} page.` })
    values.push(...page as T[])
  }
  return values
}

async function readCounters(transport: NearContractTransport): Promise<RawCounters> {
  return transport.view<RawCounters>('get_counters')
}

async function readDashboardProposals(transport: NearContractTransport, accountId: string, brokerIds: string[], counters?: RawCounters): Promise<RawProposal[]> {
  const brokerIdSet = new Set(brokerIds)
  // Core deliberately has no proposal list view. Enumerate the authoritative
  // ID range from its high-water counter; a missing ID is a normal tombstone,
  // while transport/RPC errors must reach the caller rather than becoming an
  // apparently empty financial state.
  const bounds = counters || await readCounters(transport)
  const highWater = counter(bounds.proposal_high_water, 'proposal high-water mark')
  const records: RawProposal[] = []
  for (let first = 1n; first <= highWater; first += BigInt(CORE_VIEW_PAGE_LIMIT)) {
    const count = Number((highWater - first + 1n) < BigInt(CORE_VIEW_PAGE_LIMIT) ? highWater - first + 1n : BigInt(CORE_VIEW_PAGE_LIMIT))
    const page = await Promise.all(Array.from({ length: count }, (_, index) => {
      const proposalId = (first + BigInt(index)).toString()
      return transport.view<RawProposal | null>('get_proposal', { proposal_id: proposalId })
    }))
    records.push(...page.flatMap((proposal) => proposal && (proposal.borrower === accountId || brokerIdSet.has(decimal(proposal.broker_id))) ? [proposal] : []))
  }
  return records
}

function mapAsset(raw: RawAssetProfile): AssetProfile {
  return { tokenAccount: raw.token_account, decimals: raw.decimals, controllerAccount: raw.controller_account, issuerKeyId: decimal(raw.issuer_key.key_id), issuerPublicKey: bytesToHex(raw.issuer_key.public_key), tokenAuditorKeyId: decimal(raw.token_auditor_key.key_id), tokenAuditorPublicKey: bytesToHex(raw.token_auditor_key.public_key), cryptoProfileHash: bytesToHex(raw.crypto_profile_hash), tokenTrustPolicy: raw.token_trust_policy, ...(raw.authorization_policy === undefined ? {} : { authorizationPolicy: raw.authorization_policy }), ...(raw.freeze_policy === undefined ? {} : { freezePolicy: raw.freeze_policy }), ...(raw.custody_cap === undefined ? {} : { custodyCap: decimal(raw.custody_cap) }), ...(raw.confidential_outstanding === undefined ? {} : { confidentialOutstanding: decimal(raw.confidential_outstanding) }) }
}

function mapHolder(raw: RawHolder): PrivateAccountView {
  return { accountId: raw.owner, assetAccount: raw.asset_id, encryptionKeyId: decimal(raw.key_id), balanceCiphertext: bytesToHex(raw.spending_ciphertext), balanceCommitment: bytesToHex(raw.spending_commitment || ''), inboxCiphertext: bytesToHex(raw.inbox_ciphertext), inboxCommitment: bytesToHex(raw.inbox_commitment || ''), issuerBalanceCiphertext: raw.issuer_balance_ciphertext === undefined ? undefined : bytesToHex(raw.issuer_balance_ciphertext), auditorBalanceCiphertext: raw.auditor_balance_ciphertext === undefined ? undefined : bytesToHex(raw.auditor_balance_ciphertext), spendingVersion: decimal(raw.spending_version), registered: true }
}

function mapBroker(raw: RawBroker, assetAccount: string): BrokerSummary {
  return { brokerId: decimal(raw.broker_id), ownerId: raw.owner, vaultId: decimal(raw.vault_id), debtTotal: decimal(raw.debt_total), debtCeiling: decimal(raw.debt_maximum), spendingVersion: decimal(raw.spending_version), bookVersion: decimal(raw.book_version), privateBalanceKeyId: decimal(raw.encryption_key_id), checkpointStatus: raw.accounting_pending ? 'pending' : 'current', keeperCount: raw.delegates?.filter((delegate) => delegate.active).length || 0, spendingCiphertext: bytesToHex(raw.spending_ciphertext), inboxCiphertext: bytesToHex(raw.inbox_ciphertext), issuerBalanceCiphertext: raw.issuer_balance_ciphertext === undefined ? undefined : bytesToHex(raw.issuer_balance_ciphertext), auditorBalanceCiphertext: raw.auditor_balance_ciphertext === undefined ? undefined : bytesToHex(raw.auditor_balance_ciphertext), spendingCommitment: raw.spending_commitment === undefined ? undefined : bytesToHex(raw.spending_commitment), inboxCommitment: raw.inbox_commitment === undefined ? undefined : bytesToHex(raw.inbox_commitment), activePrincipalCiphertext: raw.active_principal_ciphertext === undefined ? undefined : bytesToHex(raw.active_principal_ciphertext), impairedPrincipalCiphertext: raw.impaired_principal_ciphertext === undefined ? undefined : bytesToHex(raw.impaired_principal_ciphertext), activePrincipalCommitment: raw.active_principal_commitment === undefined ? undefined : bytesToHex(raw.active_principal_commitment), impairedPrincipalCommitment: raw.impaired_principal_commitment === undefined ? undefined : bytesToHex(raw.impaired_principal_commitment), loanBookRoot: raw.loan_book_root === undefined ? undefined : bytesToHex(raw.loan_book_root), impairmentProvision: raw.impairment_provision === undefined ? undefined : decimal(raw.impairment_provision), accountingVersion: decimal(raw.accounting_version), riskVersion: raw.risk_version === undefined ? undefined : decimal(raw.risk_version) }
}

function mapVault(raw: RawVault, shares?: string): import('./types').VaultSummary {
  const phase = raw.kind === 'ClosedEnded' && raw.phase === null
    ? 'closed'
    : raw.phase === 'Subscription'
      ? 'subscription'
      : raw.phase === 'Investment'
        ? 'investment'
        : raw.phase === 'Redemption'
          ? 'redemption'
          : 'open'
  return { vaultId: decimal(raw.vault_id), ownerId: raw.owner, assetAccount: raw.asset_id, phase, decimals: 0, assetsTotal: decimal(raw.assets_total), assetsAvailable: decimal(raw.assets_available), sharesSupply: decimal(raw.shares_total), yourShares: shares, shareScale: raw.share_scale, ...(raw.checkpoint_policy?.epoch_seconds === undefined ? {} : { checkpointEpochSeconds: decimal(raw.checkpoint_policy.epoch_seconds) }), ...(raw.checkpoint_policy?.disclosure_policy === undefined ? {} : { checkpointDisclosurePolicy: raw.checkpoint_policy.disclosure_policy }), accountingVersion: decimal(raw.accounting_version), checkpointStatus: raw.accounting_pending ? 'pending' : 'current' }
}

function mapLoan(raw: RawLoan): import('./types').LoanSummary {
  const status = raw.status.toLowerCase()
  const mappedStatus = raw.impaired && status === 'active' ? 'impaired' : status === 'active' || status === 'defaulted' || status === 'paid' || status === 'deleted' ? status : 'active'
  return { loanId: decimal(raw.loan_id), proposalId: decimal(raw.proposal_id), brokerId: decimal(raw.broker_id), borrowerId: raw.borrower, vaultId: '', auditorKeyId: raw.loan_auditor_key_id === undefined ? '' : decimal(raw.loan_auditor_key_id), auditorPublicKey: raw.loan_auditor_public_key === undefined ? undefined : bytesToHex(raw.loan_auditor_public_key), status: mappedStatus, paymentRemaining: raw.payment_remaining, paymentCount: raw.payment_total, paymentIntervalSeconds: safeNumber(raw.payment_interval, 'payment interval'), gracePeriodSeconds: safeNumber(raw.grace_period, 'grace period'), nextPaymentDue: raw.next_due === null || raw.next_due === undefined ? 0 : safeNumber(raw.next_due, 'next due date'), stateVersion: decimal(raw.loan_version), termsDigest: '', principalCiphertextDigest: bytesToHex(raw.principal_ciphertexts?.[0] || ''), owedCiphertextDigest: bytesToHex(raw.amount_owed_ciphertexts?.[0] || ''), principalCiphertexts: raw.principal_ciphertexts?.map(bytesToHex), initialOwedCiphertexts: raw.initial_owed_ciphertexts?.map(bytesToHex), amountOwedCiphertexts: raw.amount_owed_ciphertexts?.map(bytesToHex), periodicPaymentCiphertexts: raw.periodic_payment_ciphertexts?.map(bytesToHex), principalRemainingCiphertexts: raw.principal_remaining_ciphertexts?.map(bytesToHex), cumulativeRepaidCiphertexts: raw.cumulative_repaid_ciphertexts?.map(bytesToHex), accountingLeaf: raw.accounting_leaf === undefined ? undefined : bytesToHex(raw.accounting_leaf), borrowerKeyId: raw.borrower_key_id === undefined ? undefined : decimal(raw.borrower_key_id), brokerKeyId: raw.broker_key_id === undefined ? undefined : decimal(raw.broker_key_id) }
}

function mapProposal(raw: RawProposal): ProposalSummary {
  const borrowerSigned = Boolean(raw.borrower_signature && bytesToHex(raw.borrower_signature).length)
  const brokerSigned = Boolean(raw.broker_signature && bytesToHex(raw.broker_signature).length)
  const borrowerAuthorized = raw.borrower_direct_authorized ?? borrowerSigned
  const brokerAuthorized = raw.broker_direct_authorized ?? brokerSigned
  const expiresAt = safeNumber(raw.expiry, 'proposal expiry')
  const status = raw.revoked ? 'revoked' : raw.consumed ? 'consumed' : expiresAt <= Math.floor(Date.now() / 1000) ? 'expired' : borrowerAuthorized && brokerAuthorized ? 'broker_authorized' : borrowerAuthorized ? 'borrower_authorized' : 'pending'
  return {
    proposalId: decimal(raw.proposal_id),
    brokerId: decimal(raw.broker_id),
    borrowerId: raw.borrower,
    vaultId: decimal(raw.vault_id),
    expiresAt,
    status,
    termsDigest: bytesToHex(raw.agreement_digest),
    encryptedAgreement: '',
    encryptionKeyId: decimal(raw.loan_auditor_key_id),
    encryptedPrincipal: (raw.principal_ciphertexts || []).map(bytesToHex),
    encryptedOwed: (raw.initial_owed_ciphertexts || []).map(bytesToHex),
    encryptedPayment: (raw.periodic_payment_ciphertexts || []).map(bytesToHex),
    principalCommitment: raw.principal_commitment === undefined ? undefined : bytesToHex(raw.principal_commitment),
    owedCommitment: raw.owed_commitment === undefined ? undefined : bytesToHex(raw.owed_commitment),
    paymentCommitment: raw.payment_commitment === undefined ? undefined : bytesToHex(raw.payment_commitment),
    loanAuditorPublicKey: raw.loan_auditor_public_key === undefined ? undefined : bytesToHex(raw.loan_auditor_public_key),
    brokerSignature: raw.broker_signature ? bytesToHex(raw.broker_signature) : '',
    borrowerSignature: raw.borrower_signature ? bytesToHex(raw.borrower_signature) : '',
    borrowerKeyId: raw.borrower_key_id === undefined ? undefined : decimal(raw.borrower_key_id),
    brokerKeyId: raw.broker_key_id === undefined ? undefined : decimal(raw.broker_key_id),
    brokerAuthorizationEpoch: raw.broker_authorization_epoch === undefined ? undefined : decimal(raw.broker_authorization_epoch),
    borrowerAuthorizationEpoch: raw.borrower_authorization_epoch === undefined ? undefined : decimal(raw.borrower_authorization_epoch),
    brokerAuthorizationKeyId: raw.broker_authorization_key_id === undefined || raw.broker_authorization_key_id === null ? undefined : decimal(raw.broker_authorization_key_id),
    borrowerAuthorizationKeyId: raw.borrower_authorization_key_id === undefined || raw.borrower_authorization_key_id === null ? undefined : decimal(raw.borrower_authorization_key_id),
    brokerDirectAuthorized: raw.broker_direct_authorized,
    borrowerDirectAuthorized: raw.borrower_direct_authorized,
  }
}

export function createWalletAdapter(session: NearWalletSession): WalletAdapter {
  return session
}

export class NearProtocolClient implements ProtocolClient {
  readonly config: DeploymentConfig
  private readonly transport: NearContractTransport

  constructor(transport: NearContractTransport, config: DeploymentConfig) {
    this.transport = transport
    this.config = config
  }

  async getAssetProfile(): Promise<AssetProfile> {
    return mapAsset(await this.transport.view<RawAssetProfile>('get_asset_profile'))
  }

  async storageBalanceOf(accountId: string): Promise<string> {
    return decimal(await this.transport.view<unknown>('storage_balance_of', { account_id: accountId }))
  }

  storageDeposit(input: { accountId: string; deposit: string }): Promise<ActionReceipt> {
    if (!/^[1-9]\d*$/.test(input.deposit)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Storage deposit must be a positive yoctoNEAR amount.' })
    return this.callWithOptions('storage_deposit', { account_id: input.accountId }, { deposit: input.deposit, gas: '30000000000000' })
  }

  async getDashboard(accountId: string): Promise<DashboardSnapshot> {
    const [asset, counters] = await Promise.all([this.getAssetProfile(), readCounters(this.transport)])
    const [rawVaults, rawBrokers, rawClaims, rawPayouts] = await Promise.all([
      readHighWaterPages<RawVault>(this.transport, 'list_vaults', counters.vault_high_water, {}, 'vault'),
      readHighWaterPages<RawBroker>(this.transport, 'list_brokers', counters.broker_high_water, { owner: accountId }, 'broker'),
      readHighWaterPages<RawClaim>(this.transport, 'list_claims', counters.claim_high_water, { owner: accountId }, 'claim'),
      readHighWaterPages<RawPayout>(this.transport, 'list_payouts', counters.payout_high_water, { owner: accountId }, 'payout'),
    ])
    const brokers = rawBrokers.map((broker) => mapBroker(broker, asset.tokenAccount))
    const loanReads = [
      readHighWaterPages<RawLoan>(this.transport, 'list_loans', counters.loan_high_water, { borrower: accountId, broker_id: null }, 'loan'),
      ...brokers.map((broker) => readHighWaterPages<RawLoan>(this.transport, 'list_loans', counters.loan_high_water, { borrower: null, broker_id: wireId(broker.brokerId) }, 'loan')),
    ]
    const rawLoans = (await Promise.all(loanReads)).flat()
    const uniqueLoans = [...new Map(rawLoans.map((loan) => [decimal(loan.loan_id), loan])).values()]
    const proposals = await readDashboardProposals(this.transport, accountId, brokers.map((broker) => broker.brokerId), counters)
    const uniqueProposals = [...new Map(proposals.map((proposal) => [decimal(proposal.proposal_id), proposal])).values()]
    const vaults = await Promise.all(rawVaults.map(async (vault) => {
      let shares: string | undefined
      try { shares = decimal(await this.transport.view<unknown>('get_share_balance', { vault_id: wireId(decimal(vault.vault_id)), owner: accountId })) } catch { shares = undefined }
      return { ...mapVault(vault, shares), decimals: asset.decimals }
    }))
    return {
      fetchedAt: Date.now(),
      asset,
      vaults,
      brokers,
      loans: uniqueLoans.map((loan) => {
        const mapped = mapLoan(loan)
        mapped.vaultId = brokers.find((broker) => broker.brokerId === mapped.brokerId)?.vaultId || ''
        return mapped
      }),
      proposals: uniqueProposals.map(mapProposal),
      claims: rawClaims.map((claim) => ({ claimId: decimal(claim.claim_id), ownerId: claim.owner, amount: decimal(claim.amount), assetAccount: asset.tokenAccount, status: claim.reserved_by === null || claim.reserved_by === undefined ? 'available' : 'reserved', payoutOperationId: optionalDecimal(claim.reserved_by) })),
      payouts: rawPayouts.map((payout) => ({ operationId: decimal(payout.operation_id), claimId: decimal(payout.claim_id), amount: decimal(payout.amount), recipientId: payout.recipient, status: payout.status === 'Succeeded' ? 'succeeded' : payout.status === 'Failed' || payout.status === 'ResultRecordedFailure' ? 'failed' : payout.status === 'InFlight' ? 'in_flight' : payout.status === 'ResultRecordedSuccess' ? 'result_recorded' : 'unknown', attempt: payout.attempt, lastUpdatedAt: safeNumber(payout.created_at, 'payout timestamp') })),
      keeperGrants: rawBrokers.flatMap((broker) => (broker.delegates || []).map((delegate) => ({ delegateId: delegate.delegate_account, brokerId: decimal(broker.broker_id), scope: mapKeeperScope(delegate.allowed_operations), maxAmount: decimal(delegate.allowed_settlement_per_operation), expiresAt: safeNumber(delegate.expires_at, 'keeper expiry'), epoch: decimal(delegate.revocation_epoch), revoked: !delegate.active }))),
      publicNotice: uniqueProposals.length || rawBrokers.some((broker) => broker.delegates?.length) ? undefined : 'This deployment returned no optional proposal/keeper index entries. Core get_proposal/get_broker reads remain available by ID; the UI never invents records.',
    }
  }

  async getPrivateAccount(accountId: string): Promise<PrivateAccountView> {
    const holder = await this.transport.view<RawHolder | null>('get_holder', { owner: accountId })
    if (!holder) throw new ProtocolError({ category: 'NOT_REGISTERED', message: 'This account has no registered confidential holder key.' })
    return mapHolder(holder)
  }

  async getHolderEncryptionKey(accountId: string): Promise<HolderKeyView> {
    try {
      const holder = await this.transport.view<{ key_id: string | number; public_key: unknown } | null>('get_holder_key', { owner: accountId, key_id: null })
      if (holder) return { accountId, encryptionKeyId: decimal(holder.key_id), publicKey: bytesToHex(holder.public_key) }
    } catch {
      // Older Core deployments may not expose get_holder_key. Fall through to
      // the holder's registered public record instead of accepting a key from
      // the caller.
    }
    try {
      const holder = await this.transport.view<RawHolder | null>('get_holder', { owner: accountId })
      const publicKey = holder?.public_key ?? holder?.encryption_public_key ?? holder?.encryption_key?.public_key
      if (holder && publicKey !== undefined) return { accountId: holder.owner, encryptionKeyId: decimal(holder.key_id), publicKey: bytesToHex(publicKey) }
    } catch {
      // Preserve the explicit unsupported-profile result below; no key is
      // ever inferred from a ciphertext or authorization key.
    }
    throw new ProtocolError({ category: 'UNSUPPORTED_PROFILE', message: 'This Core deployment does not expose registered holder encryption public keys for recipient lookup.' })
  }

  async getBrokerEncryptionKey(brokerId: string): Promise<BrokerKeyView> {
    try {
      const key = await this.transport.view<{ key_id: string | number; public_key: unknown } | null>('get_broker_key', { broker_id: wireId(brokerId), key_id: null })
      if (key) return { brokerId, encryptionKeyId: decimal(key.key_id), publicKey: bytesToHex(key.public_key) }
    } catch {
      // Fall through to the broker's registered public view for older Core deployments.
    }
    const broker = await this.transport.view<RawBroker | null>('get_broker', { broker_id: wireId(brokerId) })
    const publicKey = broker?.encryption_public_key
    if (broker && publicKey !== undefined) return { brokerId, encryptionKeyId: decimal(broker.encryption_key_id), publicKey: bytesToHex(publicKey) }
    throw new ProtocolError({ category: 'UNSUPPORTED_PROFILE', message: 'This Core deployment does not expose the broker encryption public key.' })
  }

  async getVaultBrokerIds(vaultId: string): Promise<string[]> {
    // This endpoint pages an append-only membership vector by element offset,
    // not by broker ID. Empty/tombstoned entries therefore only terminate the
    // scan when the returned page is shorter than Core's bounded page size.
    const values: unknown[] = []
    for (let cursor = 0n; ; cursor += BigInt(CORE_VIEW_PAGE_LIMIT)) {
      const page = await this.transport.view<unknown[]>('get_vault_broker_ids', { vault_id: wireId(vaultId), cursor: cursor.toString(), limit: CORE_VIEW_PAGE_LIMIT })
      if (!Array.isArray(page)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Core returned an invalid vault broker membership page.' })
      values.push(...page)
      if (page.length < CORE_VIEW_PAGE_LIMIT) break
    }
    return values.map((value) => decimal(value))
  }

  async getBrokerPrivateAccount(brokerId: string): Promise<PrivateAccountView> {
    const broker = await this.transport.view<RawBroker | null>('get_broker', { broker_id: wireId(brokerId) })
    if (!broker) throw new ProtocolError({ category: 'NOT_REGISTERED', message: 'This broker account is no longer available.' })
    return { accountId: broker.owner, assetAccount: this.config.tokenAccountId, encryptionKeyId: decimal(broker.encryption_key_id), balanceCiphertext: bytesToHex(broker.spending_ciphertext), balanceCommitment: bytesToHex(broker.spending_commitment || ''), inboxCiphertext: bytesToHex(broker.inbox_ciphertext), inboxCommitment: bytesToHex(broker.inbox_commitment || ''), issuerBalanceCiphertext: broker.issuer_balance_ciphertext === undefined ? undefined : bytesToHex(broker.issuer_balance_ciphertext), auditorBalanceCiphertext: broker.auditor_balance_ciphertext === undefined ? undefined : bytesToHex(broker.auditor_balance_ciphertext), spendingVersion: decimal(broker.spending_version), registered: true }
  }

  async getProposal(proposalId: string): Promise<ProposalSummary> {
    const proposal = await this.transport.view<RawProposal | null>('get_proposal', { proposal_id: wireId(proposalId) })
    if (!proposal) throw new ProtocolError({ category: 'EXPIRED', message: 'The requested proposal is not available.' })
    return mapProposal(proposal)
  }

  async getAuditBundle(input: { scope: 'loan' | 'token'; subjectId: string; readerRole?: TokenAuditReaderRole }): Promise<AuditCiphertextBundle> {
    if (input.scope === 'token') {
      const subject = parseTokenAuditSubject(input.subjectId)
      const asset = await this.getAssetProfile()
      const readerRole: TokenAuditReaderRole = input.readerRole ?? 'token_auditor'
      const record = subject.kind === 'holder'
        ? await this.transport.view<RawHolder | null>('get_holder', { owner: subject.id })
        : await this.transport.view<RawBroker | null>('get_broker', { broker_id: subject.id })
      if (!record) throw new ProtocolError({ category: 'NOT_REGISTERED', message: `The selected ${subject.kind === 'holder' ? 'holder account' : 'broker'} is not registered.` })
      const readerKeyId = readerRole === 'issuer' ? asset.issuerKeyId : asset.tokenAuditorKeyId
      const spendingVersion = decimal(record.spending_version)
      return {
        scope: 'token',
        subjectId: subject.id,
        subjectKind: subject.kind,
        readerRole,
        auditorKeyId: readerKeyId,
        cryptoProfileHash: this.config.cryptoProfileHash,
        // Mirror ciphertexts are recovered from the finalized history by the
        // browser wallet. Do not copy them into a generic audit bundle or
        // expose a second, unverified decryption path in the UI.
        ciphertexts: {},
        commitments: {},
        versions: { spending: spendingVersion },
        fetchedAt: Date.now(),
      }
    }
    let loan = await this.transport.view<RawLoan | null>('get_loan', { loan_id: wireId(input.subjectId) })
    if (!loan) {
      // Closed loans leave the active index but retain an immutable archived
      // record for the designated auditor. A deployment predating that view
      // simply reports the normal closed-scope error.
      try { loan = await this.transport.view<RawLoan | null>('get_archived_loan', { loan_id: wireId(input.subjectId) }) } catch { loan = null }
    }
    if (!loan) throw new ProtocolError({ category: 'LOAN_CLOSED', message: 'The requested loan is not available.' })
    const ciphertexts: Record<string, string> = {}
    for (const [name, values] of [['principal', loan.principal_ciphertexts], ['initialOwed', loan.initial_owed_ciphertexts], ['amountOwed', loan.amount_owed_ciphertexts], ['periodicPayment', loan.periodic_payment_ciphertexts], ['principalRemaining', loan.principal_remaining_ciphertexts], ['cumulativeRepaid', loan.cumulative_repaid_ciphertexts]] as const) (values || []).forEach((value, index) => { ciphertexts[`${name}_${index}`] = bytesToHex(value) })
    if (ciphertexts.principal_0) ciphertexts.principal = ciphertexts.principal_0
    if (ciphertexts.amountOwed_0) ciphertexts.amountOwed = ciphertexts.amountOwed_0
    return { scope: 'loan', subjectId: input.subjectId, auditorKeyId: loan.loan_auditor_key_id === undefined ? '' : decimal(loan.loan_auditor_key_id), auditorPublicKey: loan.loan_auditor_public_key === undefined ? undefined : bytesToHex(loan.loan_auditor_public_key), cryptoProfileHash: this.config.cryptoProfileHash, ciphertexts, commitments: {}, versions: { loan: decimal(loan.loan_version) }, fetchedAt: Date.now() }
  }

  private async callWithOptions(method: string, args: Record<string, unknown>, options?: { deposit?: string; gas?: string; receiverId?: string }): Promise<ActionReceipt> {
    const result = await this.transport.call(method, args, options)
    if (!result) return { operationId: `${method}:${Date.now()}`, status: 'pending', finalized: false }
    return {
      operationId: result.operationId || `${method}:${result.transactionHash || Date.now()}`,
      transactionHash: result.transactionHash,
      returnValue: result.returnValue,
      status: result.status,
      finalized: result.finalized,
    }
  }

  private call(method: string, args: Record<string, unknown>): Promise<ActionReceipt> {
    return this.callWithOptions(method, args)
  }

  /**
   * Core methods taking one typed argument struct use the explicit `args`
   * envelope in their NEAR JSON ABI. Keep that wire detail in one place so a
   * public action cannot accidentally serialize a flat object that the
   * contract rejects before entering its business logic.
   */
  private callStruct(method: string, args: Record<string, unknown>): Promise<ActionReceipt> {
    return this.call(method, { args })
  }

  registerHolder(input: KeyRegistration): Promise<ActionReceipt> {
    return this.callStruct('register_holder', { key_id: input.encryptionKeyId, encryption_public_key: namedHexToBytes(input.encryptionPublicKey, 'holder encryption public key'), public_key: namedHexToBytes(input.authorizationPublicKey, 'holder authorization public key'), proof_of_possession: proofArgs(input.possessionProof).proof, authorization_signature: input.authorizationSignature.trim() ? namedHexToBytes(input.authorizationSignature, 'holder authorization signature') : [] })
  }

  registerAuthorizationKey(input: AuthorizationKeyRegistration): Promise<ActionReceipt> {
    return this.callStruct('register_authorization_key', { key_id: input.keyId, public_key: hexToBytes(input.publicKey) })
  }

  revokeAuthorizationKey(input: { keyId: string }): Promise<ActionReceipt> {
    return this.call('revoke_authorization_key', { key_id: input.keyId })
  }

  createVault(input: { assetAccount: string; assetsMaximum: string; kind: 'open_ended' | 'closed_ended'; phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }; shareScale: number; sharesTransferable: boolean; checkpointPolicy: { epochSeconds: number; disclosurePolicy: string } }): Promise<ActionReceipt> {
    return this.callStruct('create_vault', { assets_maximum: input.assetsMaximum, kind: input.kind === 'open_ended' ? 'OpenEnded' : 'ClosedEnded', phase_times: input.phaseTimes ? { subscription_start: decimal(input.phaseTimes.subscriptionStart), investment_start: decimal(input.phaseTimes.investmentStart), redemption_start: decimal(input.phaseTimes.redemptionStart), redemption_buffer: decimal(input.phaseTimes.redemptionBuffer) } : null, share_scale: input.shareScale, shares_transferable: input.sharesTransferable, checkpoint_policy: { epoch_seconds: decimal(input.checkpointPolicy.epochSeconds), disclosure_policy: input.checkpointPolicy.disclosurePolicy } })
  }

  createBroker(input: { vaultId: string; brokerEncryptionKeyId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('create_broker', { vault_id: input.vaultId, encryption_key_id: input.brokerEncryptionKeyId, encryption_public_key: hexToBytes(input.brokerEncryptionKey), debt_maximum: input.brokerDebtCeiling, proof_of_possession: proofArgs(input.possessionProof).proof })
  }

  depositExternal(input: { amount: string; depositId: string }): Promise<ActionReceipt> {
    return this.callWithOptions('ft_transfer_call', { receiver_id: this.config.coreAccountId, amount: input.amount, msg: JSON.stringify({ version: 1, deposit_id: input.depositId }) }, { receiverId: this.config.tokenAccountId, gas: '100000000000000', deposit: '1' })
  }

  depositToVault(input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.callStruct('deposit_to_vault', { claim_id: input.claimId, vault_id: input.vaultId, amount: input.amount, min_shares_out: input.minShares, expiry: decimal(input.expiresAt) })
  }

  redeemShares(input: { vaultId: string; shares: string; minAmount: string; expiresAt: number; soleShareholderWaiver?: boolean; burnWorthless?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt> {
    const args: Record<string, unknown> = { vault_id: input.vaultId, shares: input.shares, min_assets_out: input.minAmount, expiry: decimal(input.expiresAt), sole_shareholder_waiver: input.soleShareholderWaiver === true, burn_worthless: input.burnWorthless === true }
    if (input.brokerZeroProofs !== undefined) args.broker_zero_proofs = input.brokerZeroProofs.map((proof) => {
      const mapped = proofArgs(proof).zero_proof
      if (!mapped || typeof mapped !== 'object' || Array.isArray(mapped)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Broker redemption requires a typed zero-proof envelope.' })
      return mapped
    })
    return this.callStruct('redeem_shares', args)
  }

  redeemAmount(input: { vaultId: string; assetsOut: string; maxSharesIn: string; expiresAt: number; soleShareholderWaiver?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt> {
    const args: Record<string, unknown> = { vault_id: input.vaultId, assets_out: input.assetsOut, max_shares_in: input.maxSharesIn, expiry: decimal(input.expiresAt), sole_shareholder_waiver: input.soleShareholderWaiver === true }
    if (input.brokerZeroProofs !== undefined) args.broker_zero_proofs = input.brokerZeroProofs.map((proof) => {
      const mapped = proofArgs(proof).zero_proof
      if (!mapped || typeof mapped !== 'object' || Array.isArray(mapped)) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Broker redemption requires a typed zero-proof envelope.' })
      return mapped
    })
    return this.callStruct('redeem_amount', args)
  }

  transferShares(input: { vaultId: string; receiverId: string; shares: string }): Promise<ActionReceipt> {
    return this.call('transfer_shares', { vault_id: input.vaultId, receiver: input.receiverId, shares: input.shares })
  }

  requestPayout(input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt> {
    return this.callStruct('request_payout', { claim_id: input.claimId, operation_id: input.operationId, recipient: input.recipientId })
  }

  shield(input: { claimId: string; amount: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('shield', { claim_id: input.claimId, amount: input.amount, ...proofArgs(input.proof) })
  }

  unshield(input: { amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('unshield', { amount: input.amount, expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  deleteLoan(input: { loanId: string }): Promise<ActionReceipt> {
    return this.call('delete_loan', { loan_id: input.loanId, evidence: [] })
  }

  deleteBroker(input: { brokerId: string; proof: PreparedProof }): Promise<ActionReceipt> {
    const mapped = proofArgs(input.proof)
    return this.call('delete_broker', { broker_id: input.brokerId, zero_proof: mapped.zero_proof })
  }

  mergeInbox(input: { accountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('merge_inbox', mergeArgs(input.proof, input.expectedSpendingVersion))
  }

  mergeBrokerInbox(input: { brokerId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('merge_broker_inbox', { broker_id: input.brokerId, args: mergeArgs(input.proof, input.expectedSpendingVersion) })
  }

  draw(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('draw', { broker_id: input.brokerId, amount: input.amount, ...proofArgs(input.proof) })
  }

  async createProposal(input: { brokerId: string; borrowerId: string; vaultId: string; borrowerKeyId: string; brokerKeyId: string; borrowerAuthorizationKeyId?: string; brokerAuthorizationKeyId?: string; auditorKeyId: string; auditorPublicKey: string; paymentCount: number; paymentIntervalSeconds: number; gracePeriodSeconds: number; encryptedPrincipal: string[]; encryptedOwed: string[]; encryptedPayment: string[]; principalCommitment: string; owedCommitment: string; paymentCommitment: string; encryptedAgreement: string; termsDigest: string; brokerSignature: string; borrowerSignature: string; brokerAuthorizationEpoch?: string; borrowerAuthorizationEpoch?: string; brokerAuthorizationNonce?: string; borrowerAuthorizationNonce?: string; expiresAt: number }): Promise<ActionReceipt> {
    // A broker without an application authorization key uses direct owner
    // authorization, whose epoch is defined as zero. The broker's encryption
    // key epoch must never be substituted for this value.
    let brokerEpoch = input.brokerAuthorizationKeyId ? input.brokerAuthorizationEpoch : '0'
    let borrowerEpoch = input.borrowerAuthorizationEpoch
    if (!borrowerEpoch) {
      const borrower = await this.transport.view<RawHolder | null>('get_holder', { owner: input.borrowerId })
      if (!borrower || borrower.authorization_epoch === undefined) throw new ProtocolError({ category: 'STALE_STATE', message: 'The borrower authorization epoch could not be read from finalized Core state.' })
      borrowerEpoch = decimal(borrower.authorization_epoch)
    }
    if (input.brokerAuthorizationKeyId && !brokerEpoch) {
      const broker = await this.transport.view<RawBroker | null>('get_broker', { broker_id: wireId(input.brokerId) })
      if (!broker || broker.authorization_epoch === undefined) throw new ProtocolError({ category: 'STALE_STATE', message: 'The broker authorization epoch could not be read from finalized Core state.' })
      brokerEpoch = decimal(broker.authorization_epoch)
    }
    return this.callStruct('create_proposal', { borrower: input.borrowerId, broker_id: input.brokerId, vault_id: input.vaultId, borrower_key_id: input.borrowerKeyId, broker_key_id: input.brokerKeyId, ...(input.brokerAuthorizationKeyId ? { broker_authorization_key_id: input.brokerAuthorizationKeyId } : {}), ...(input.borrowerAuthorizationKeyId ? { borrower_authorization_key_id: input.borrowerAuthorizationKeyId } : {}), loan_auditor_key_id: input.auditorKeyId, loan_auditor_public_key: hexToBytes(input.auditorPublicKey), payment_count: input.paymentCount, payment_interval: decimal(input.paymentIntervalSeconds), grace_period: decimal(input.gracePeriodSeconds), expiry: decimal(input.expiresAt), principal_ciphertexts: input.encryptedPrincipal.map(hexToBytes), initial_owed_ciphertexts: input.encryptedOwed.map(hexToBytes), periodic_payment_ciphertexts: input.encryptedPayment.map(hexToBytes), principal_commitment: hexToBytes(input.principalCommitment), owed_commitment: hexToBytes(input.owedCommitment), payment_commitment: hexToBytes(input.paymentCommitment), agreement_digest: input.termsDigest.trim() ? hexToBytes(input.termsDigest) : [], broker_signature: optionalHexToBytes(input.brokerSignature), borrower_signature: optionalHexToBytes(input.borrowerSignature), broker_authorization_epoch: brokerEpoch, borrower_authorization_epoch: borrowerEpoch, broker_authorization_nonce: input.brokerAuthorizationNonce || '0', borrower_authorization_nonce: input.borrowerAuthorizationNonce || '0' })
  }

  authorizeProposal(input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt> {
    return this.call('sign_proposal', { proposal_id: input.proposalId, signature: optionalHexToBytes(input.authorizationSignature) })
  }

  revokeProposal(input: { proposalId: string }): Promise<ActionReceipt> {
    return this.call('revoke_proposal', { proposal_id: input.proposalId })
  }

  originate(input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('originate', { proposal_id: input.proposalId, ...proofArgs(input.proof) })
  }

  confidentialSend(input: { senderAccountId: string; destinationAccountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('confidential_send', { destination: input.destinationAccountId, expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  repay(input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; expectedBorrowerSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('repay', { loan_id: input.loanId, mode: input.mode === 'regular' ? 'Regular' : 'Full', expected_loan_version: input.expectedLoanVersion, expected_borrower_spending_version: input.expectedBorrowerSpendingVersion, ...proofArgs(input.proof) })
  }

  manageLoan(input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; preparation?: LoanManagementPreparation; proof?: PreparedProof }): Promise<ActionReceipt> {
    const preparation = input.preparation
    if (preparation && (preparation.loanId !== input.loanId || preparation.operation !== input.operation || preparation.expectedLoanVersion !== input.expectedLoanVersion)) throw new ProtocolError({ category: 'STALE_STATE', message: 'Loan management preparation does not match the submitted loan version.' })
    const args: Record<string, unknown> = { loan_id: input.loanId, action: input.operation === 'impair' ? 'Impair' : input.operation === 'unimpair' ? 'Unimpair' : 'Default', expected_loan_version: input.expectedLoanVersion }
    if (input.proof) Object.assign(args, proofArgs(input.proof))
    return this.callStruct('manage_loan', args)
  }

  settle(input: { brokerId: string; amount: string; expectedSpendingVersion: string; expectedAccountingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('settle', { broker_id: input.brokerId, amount: input.amount, expected_spending_version: input.expectedSpendingVersion, expected_accounting_version: input.expectedAccountingVersion, ...proofArgs(input.proof) })
  }

  reconcileCredit(input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.callStruct('reconcile_credit', { broker_id: input.brokerId, ...proofArgs(input.proof) })
  }

  prepareReconciliation(input: { brokerId: string }): Promise<ActionReceipt> {
    return this.call('prepare_reconciliation', { broker_id: input.brokerId })
  }

  grantKeeper(input: { brokerId: string; delegateId: string; delegateKeyId: string; scope: KeeperGrant['scope']; maxAmountPerOperation: string; maxAmountPerWindow: string; windowSeconds: number; delegateEpoch: string; expiresAt: number }): Promise<ActionReceipt> {
    if (!input.scope.length || input.scope.some((scope) => scope !== 'merge' && scope !== 'settle')) throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Core keeper grants support only merge and settle operations.' })
    return this.callStruct('grant_keeper', {
      broker_id: input.brokerId,
      delegate_account: input.delegateId,
      delegate_key_id: input.delegateKeyId,
      allowed_settlement_per_operation: input.maxAmountPerOperation,
      allowed_settlement_per_window: input.maxAmountPerWindow,
      window_seconds: decimal(input.windowSeconds),
      expires_at: decimal(input.expiresAt),
      delegate_epoch: input.delegateEpoch,
      allowed_operations: input.scope.map((scope) => scope === 'merge' ? 'MergeInbox' : 'Settle'),
    })
  }

  revokeKeeper(input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt> {
    return this.call('revoke_keeper', { broker_id: input.brokerId, delegate_account: input.delegateId })
  }
}

export function createAppAdapters(protocol: ProtocolClient, wallet: WalletAdapter, crypto: AppAdapters['crypto']): AppAdapters {
  return { protocol, wallet, crypto }
}

export interface RpcProtocolBundle {
  protocol: ProtocolClient
  wallet: WalletAdapter
}

/** Build the production RPC/client pair used by createBrowserAdapters. */
export function createRpcProtocolClient(config: DeploymentConfig, session: NearWalletSession): RpcProtocolBundle {
  // Browsers require `fetch` to be invoked with the global object as its
  // receiver. NearRpc stores the supplied transport and invokes it later;
  // bind it here so the real browser transport is not rejected as an
  // "Illegal invocation" and misreported as a generic RPC-unavailable error.
  const rpc = new NearRpc(config.rpcUrl, { allowInsecureLocalhost: config.allowInsecureLocalhost, fetch: globalThis.fetch.bind(globalThis) })
  const signer: RpcWalletAdapter = {
    get accountId() {
      if (!session.accountId) throw new Error('Connect a NEAR wallet before signing.')
      return session.accountId
    },
    signAndSendTransaction: (transaction) => session.signAndSendTransaction(transaction),
  }
  const contract = new ContractClient(rpc, {
    networkId: config.networkId,
    coreAccountId: config.coreAccountId,
    tokenAccountId: config.tokenAccountId,
    rpcUrl: config.rpcUrl,
    profileHash: config.cryptoProfileHash,
    assetDecimals: config.assetDecimals,
    assetSymbol: config.assetSymbol,
  })
  const transport: NearContractTransport = {
    view: (method, args, signal) => contract.view(method, args as never, signal),
    call: async (method, args, options) => {
      const outcome = await contract.call(signer, method, args as never, options)
      if (!outcome) return { status: 'pending', finalized: false }
      return { transactionHash: outcome.transaction.hash, operationId: outcome.transaction.hash, returnValue: decodeMethodReturn('SuccessValue' in outcome.status ? outcome.status.SuccessValue : undefined), status: 'succeeded', finalized: true }
    },
  }
  return { protocol: new NearProtocolClient(transport, config), wallet: createWalletAdapter(session) }
}
