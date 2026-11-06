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
  KeeperGrant,
  KeyRegistration,
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
      context: hexToBytes(proof.context),
      proof: hexToBytes(proof.proof),
      ...(proof.statementKind === undefined ? {} : { statement_kind: proof.statementKind }),
      public_inputs: proof.publicInputs.map(hexToBytes),
      verifying_key_hash: verifyingKeyHash ? hexToBytes(verifyingKeyHash) : [],
      profile_hash: hexToBytes(proof.profileHash),
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

function optionalHexToBytes(value: string): number[] {
  return value.trim() ? hexToBytes(value) : []
}

const CORE_OPERATION_KEYS = new Set([
  'new_spending_ciphertext', 'issuer_ciphertext', 'auditor_ciphertext', 'broker_ciphertext', 'broker_spending_commitment', 'broker_inbox_commitment',
  'borrower_spending_ciphertext', 'borrower_issuer_ciphertext', 'borrower_auditor_ciphertext', 'broker_spending_ciphertext', 'broker_issuer_ciphertext', 'broker_auditor_ciphertext',
  'loan_principal_ciphertexts', 'loan_initial_owed_ciphertexts', 'loan_periodic_payment_ciphertexts', 'principal_commitment', 'owed_commitment', 'payment_commitment', 'broker_active_principal_ciphertext', 'broker_impaired_principal_ciphertext', 'broker_book_root', 'accounting_leaf', 'broker_active_principal_commitment', 'broker_impaired_principal_commitment',
  'sender_spending_ciphertext', 'sender_issuer_ciphertext', 'sender_auditor_ciphertext', 'destination_inbox_ciphertext', 'destination_issuer_ciphertext', 'destination_auditor_ciphertext', 'transfer_views', 'commitment',
  'broker_inbox_ciphertext', 'amount_owed_ciphertexts', 'principal_remaining_ciphertexts', 'cumulative_repaid_ciphertexts', 'broker_inbox_commitment',
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
    public_inputs: publicInputs.map((item) => hexToBytes(item)),
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

function encodeCoreOperationValue(key: string, value: unknown): unknown {
  if (value === undefined || value === null) return value
  if (CORE_BYTE_KEYS.has(key) || CORE_PROOF_BYTE_KEYS.has(key)) {
    if (typeof value === 'string') return hexToBytes(value)
    if (Array.isArray(value)) return value.map((item) => typeof item === 'string' ? hexToBytes(item) : item)
    return value
  }
  if (key === 'reconciliation') return encodeReconciliation(value)
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

/**
 * Current Core pagination/lookup methods use plain u64 parameters while the
 * response and mutating argument ABI use decimal strings. Keep small IDs
 * compatible with that deployed view ABI, and preserve a string if a future
 * string-aware view is asked to address an ID beyond JavaScript's safe range.
 */
function wireId(value: string): number | string {
  if (!/^\d+$/.test(value)) throw new TypeError('Core IDs must be canonical decimal strings')
  const integer = BigInt(value)
  return integer <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(integer) : value
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

type RawAssetProfile = { token_account: string; decimals: number; controller_account: string; issuer_key: { key_id: string | number; public_key: unknown }; token_auditor_key: { key_id: string | number; public_key: unknown }; crypto_profile_hash: unknown; token_trust_policy: string }
type RawHolder = { owner: string; asset_id: string; key_id: string | number; public_key?: unknown; encryption_public_key?: unknown; encryption_key?: { public_key?: unknown }; spending_ciphertext: unknown; inbox_ciphertext: unknown; issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown; spending_commitment?: unknown; inbox_commitment?: unknown; spending_version: string | number }
type RawBroker = { broker_id: string | number; owner: string; vault_id: string | number; debt_total: unknown; debt_maximum: unknown; spending_version: string | number; book_version: string | number; loan_book_root?: unknown; encryption_key_id: string | number; spending_ciphertext: unknown; inbox_ciphertext: unknown; issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown; spending_commitment?: unknown; inbox_commitment?: unknown; active_principal_ciphertext?: unknown; impaired_principal_ciphertext?: unknown; active_principal_commitment?: unknown; impaired_principal_commitment?: unknown; impairment_provision?: unknown; accounting_pending: boolean; accounting_version: string | number; risk_version?: string | number; delegates?: RawKeeper[] }
type RawVault = { vault_id: string | number; owner: string; asset_id: string; assets_total: unknown; assets_available: unknown; shares_total: unknown; share_scale?: number; accounting_pending: boolean; accounting_version: string | number; phase?: string | null; kind?: string }
type RawLoan = { loan_id: string | number; broker_id: string | number; borrower: string; proposal_id: string | number; payment_interval: string | number; grace_period: string | number; next_due?: string | number | null; payment_total: number; payment_remaining: number; status: string; impaired?: boolean; loan_version: string | number; borrower_key_id?: string | number; broker_key_id?: string | number; loan_auditor_key_id?: string | number; loan_auditor_public_key?: unknown; principal_ciphertexts?: unknown[]; initial_owed_ciphertexts?: unknown[]; amount_owed_ciphertexts?: unknown[]; periodic_payment_ciphertexts?: unknown[]; principal_remaining_ciphertexts?: unknown[]; cumulative_repaid_ciphertexts?: unknown[]; accounting_leaf?: unknown }
type RawProposal = { proposal_id: string | number; borrower: string; broker_id: string | number; vault_id: string | number; borrower_key_id?: string | number; broker_key_id?: string | number; expiry: string | number; agreement_digest: unknown; principal_ciphertexts?: unknown[]; initial_owed_ciphertexts?: unknown[]; periodic_payment_ciphertexts?: unknown[]; principal_commitment?: unknown; owed_commitment?: unknown; payment_commitment?: unknown; loan_auditor_public_key?: unknown; consumed: boolean; revoked: boolean; broker_signature?: unknown; borrower_signature?: unknown; broker_authorization_epoch?: string | number; borrower_authorization_epoch?: string | number; broker_authorization_key_id?: string | number | null; borrower_authorization_key_id?: string | number | null; broker_direct_authorized?: boolean; borrower_direct_authorized?: boolean; loan_auditor_key_id: string | number }
type RawClaim = { claim_id: string | number; owner: string; amount: unknown; reserved_by?: string | number | null }
type RawPayout = { operation_id: string | number; owner: string; recipient: string; amount: unknown; claim_id: string | number; attempt: number; status: string; created_at: string | number }
type RawKeeper = { delegate_account: string; delegate_key_id: string | number; allowed_settlement_per_operation: unknown; allowed_settlement_per_window: unknown; expires_at: string | number; revocation_epoch: string | number; active: boolean; scope?: string[] }

function mapAsset(raw: RawAssetProfile): AssetProfile {
  return { tokenAccount: raw.token_account, decimals: raw.decimals, controllerAccount: raw.controller_account, issuerKeyId: decimal(raw.issuer_key.key_id), issuerPublicKey: bytesToHex(raw.issuer_key.public_key), tokenAuditorKeyId: decimal(raw.token_auditor_key.key_id), tokenAuditorPublicKey: bytesToHex(raw.token_auditor_key.public_key), cryptoProfileHash: bytesToHex(raw.crypto_profile_hash), tokenTrustPolicy: raw.token_trust_policy }
}

function mapHolder(raw: RawHolder): PrivateAccountView {
  return { accountId: raw.owner, assetAccount: raw.asset_id, encryptionKeyId: decimal(raw.key_id), balanceCiphertext: bytesToHex(raw.spending_ciphertext), balanceCommitment: bytesToHex(raw.spending_commitment || ''), inboxCiphertext: bytesToHex(raw.inbox_ciphertext), inboxCommitment: bytesToHex(raw.inbox_commitment || ''), issuerBalanceCiphertext: raw.issuer_balance_ciphertext === undefined ? undefined : bytesToHex(raw.issuer_balance_ciphertext), auditorBalanceCiphertext: raw.auditor_balance_ciphertext === undefined ? undefined : bytesToHex(raw.auditor_balance_ciphertext), spendingVersion: decimal(raw.spending_version), registered: true }
}

function mapBroker(raw: RawBroker, assetAccount: string): BrokerSummary {
  return { brokerId: decimal(raw.broker_id), ownerId: raw.owner, vaultId: decimal(raw.vault_id), debtTotal: decimal(raw.debt_total), debtCeiling: decimal(raw.debt_maximum), spendingVersion: decimal(raw.spending_version), bookVersion: decimal(raw.book_version), privateBalanceKeyId: decimal(raw.encryption_key_id), checkpointStatus: raw.accounting_pending ? 'pending' : 'current', keeperCount: raw.delegates?.filter((delegate) => delegate.active).length || 0, spendingCiphertext: bytesToHex(raw.spending_ciphertext), inboxCiphertext: bytesToHex(raw.inbox_ciphertext), issuerBalanceCiphertext: raw.issuer_balance_ciphertext === undefined ? undefined : bytesToHex(raw.issuer_balance_ciphertext), auditorBalanceCiphertext: raw.auditor_balance_ciphertext === undefined ? undefined : bytesToHex(raw.auditor_balance_ciphertext), spendingCommitment: raw.spending_commitment === undefined ? undefined : bytesToHex(raw.spending_commitment), inboxCommitment: raw.inbox_commitment === undefined ? undefined : bytesToHex(raw.inbox_commitment), activePrincipalCiphertext: raw.active_principal_ciphertext === undefined ? undefined : bytesToHex(raw.active_principal_ciphertext), impairedPrincipalCiphertext: raw.impaired_principal_ciphertext === undefined ? undefined : bytesToHex(raw.impaired_principal_ciphertext), activePrincipalCommitment: raw.active_principal_commitment === undefined ? undefined : bytesToHex(raw.active_principal_commitment), impairedPrincipalCommitment: raw.impaired_principal_commitment === undefined ? undefined : bytesToHex(raw.impaired_principal_commitment), loanBookRoot: raw.loan_book_root === undefined ? undefined : bytesToHex(raw.loan_book_root), impairmentProvision: raw.impairment_provision === undefined ? undefined : decimal(raw.impairment_provision), accountingVersion: decimal(raw.accounting_version), riskVersion: raw.risk_version === undefined ? undefined : decimal(raw.risk_version) }
}

function mapVault(raw: RawVault, shares?: string): import('./types').VaultSummary {
  return { vaultId: decimal(raw.vault_id), ownerId: raw.owner, assetAccount: raw.asset_id, phase: raw.phase === 'Redemption' ? 'settlement_only' : raw.phase === 'Investment' ? 'draw_locked' : raw.kind === 'ClosedEnded' && raw.phase === null ? 'closed' : 'open', decimals: 0, assetsTotal: decimal(raw.assets_total), assetsAvailable: decimal(raw.assets_available), sharesSupply: decimal(raw.shares_total), yourShares: shares, shareScale: raw.share_scale, accountingVersion: decimal(raw.accounting_version), checkpointStatus: raw.accounting_pending ? 'pending' : 'current' }
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

  async getDashboard(accountId: string): Promise<DashboardSnapshot> {
    const asset = await this.getAssetProfile()
    const [rawVaults, rawBrokers, rawClaims, rawPayouts] = await Promise.all([
      this.transport.view<RawVault[]>('list_vaults', { cursor: 0, limit: 100 }),
      this.transport.view<RawBroker[]>('list_brokers', { cursor: 0, owner: accountId, limit: 100 }),
      this.transport.view<RawClaim[]>('list_claims', { cursor: 0, owner: accountId, limit: 100 }),
      this.transport.view<RawPayout[]>('list_payouts', { cursor: 0, owner: accountId, limit: 100 }),
    ])
    const brokers = rawBrokers.map((broker) => mapBroker(broker, asset.tokenAccount))
    const loanReads = [
      this.transport.view<RawLoan[]>('list_loans', { cursor: 0, borrower: accountId, broker_id: null, limit: 100 }),
      ...brokers.map((broker) => this.transport.view<RawLoan[]>('list_loans', { cursor: 0, borrower: null, broker_id: wireId(broker.brokerId), limit: 100 })),
    ]
    const rawLoans = (await Promise.all(loanReads)).flat()
    const uniqueLoans = [...new Map(rawLoans.map((loan) => [decimal(loan.loan_id), loan])).values()]
    const proposalReads = [
      this.transport.view<RawProposal[]>('list_proposals', { cursor: 0, borrower: accountId, broker_id: null, limit: 100 }).catch(() => [] as RawProposal[]),
      ...brokers.map((broker) => this.transport.view<RawProposal[]>('list_proposals', { cursor: 0, borrower: null, broker_id: wireId(broker.brokerId), limit: 100 }).catch(() => [] as RawProposal[])),
    ]
    const proposals = (await Promise.all(proposalReads)).flat()
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
      loans: uniqueLoans.map(mapLoan),
      proposals: uniqueProposals.map(mapProposal),
      claims: rawClaims.map((claim) => ({ claimId: decimal(claim.claim_id), ownerId: claim.owner, amount: decimal(claim.amount), assetAccount: asset.tokenAccount, status: claim.reserved_by === null || claim.reserved_by === undefined ? 'available' : 'reserved', payoutOperationId: optionalDecimal(claim.reserved_by) })),
      payouts: rawPayouts.map((payout) => ({ operationId: decimal(payout.operation_id), claimId: decimal(payout.claim_id), amount: decimal(payout.amount), recipientId: payout.recipient, status: payout.status === 'Succeeded' ? 'succeeded' : payout.status === 'Failed' || payout.status === 'ResultRecordedFailure' ? 'failed' : payout.status === 'InFlight' ? 'in_flight' : payout.status === 'ResultRecordedSuccess' ? 'result_recorded' : 'unknown', attempt: payout.attempt, lastUpdatedAt: safeNumber(payout.created_at, 'payout timestamp') })),
      keeperGrants: rawBrokers.flatMap((broker) => (broker.delegates || []).map((delegate) => ({ delegateId: delegate.delegate_account, brokerId: decimal(broker.broker_id), scope: (delegate.scope || ['merge', 'settle']) as KeeperGrant['scope'], maxAmount: decimal(delegate.allowed_settlement_per_operation), expiresAt: safeNumber(delegate.expires_at, 'keeper expiry'), epoch: decimal(delegate.revocation_epoch), revoked: !delegate.active }))),
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
      const holder = await this.transport.view<{ owner: string; key_id: string | number; public_key: unknown }>('get_holder_encryption_key', { owner: accountId })
      return { accountId: holder.owner, encryptionKeyId: String(holder.key_id), publicKey: bytesToHex(holder.public_key) }
    } catch {
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

  async getAuditBundle(input: { scope: 'loan' | 'token'; subjectId: string }): Promise<AuditCiphertextBundle> {
    if (input.scope !== 'loan') throw new ProtocolError({ category: 'UNSUPPORTED_PROFILE', message: 'Token-auditor ciphertext views require the configured audit service; Core exposes no token audit listing view.' })
    const loan = await this.transport.view<RawLoan | null>('get_loan', { loan_id: wireId(input.subjectId) })
    if (!loan) throw new ProtocolError({ category: 'LOAN_CLOSED', message: 'The requested loan is not available.' })
    const ciphertexts: Record<string, string> = {}
    for (const [name, values] of [['principal', loan.principal_ciphertexts], ['initialOwed', loan.initial_owed_ciphertexts], ['amountOwed', loan.amount_owed_ciphertexts], ['periodicPayment', loan.periodic_payment_ciphertexts], ['principalRemaining', loan.principal_remaining_ciphertexts], ['cumulativeRepaid', loan.cumulative_repaid_ciphertexts]] as const) (values || []).forEach((value, index) => { ciphertexts[`${name}_${index}`] = bytesToHex(value) })
    if (ciphertexts.principal_0) ciphertexts.principal = ciphertexts.principal_0
    if (ciphertexts.amountOwed_0) ciphertexts.amountOwed = ciphertexts.amountOwed_0
    return { scope: 'loan', subjectId: input.subjectId, auditorKeyId: loan.loan_auditor_key_id === undefined ? '' : decimal(loan.loan_auditor_key_id), cryptoProfileHash: this.config.cryptoProfileHash, ciphertexts, commitments: {}, versions: { loan: decimal(loan.loan_version) }, fetchedAt: Date.now() }
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

  registerHolder(input: KeyRegistration): Promise<ActionReceipt> {
    return this.call('register_holder', { key_id: input.encryptionKeyId, public_key: hexToBytes(input.encryptionPublicKey), proof_of_possession: proofArgs(input.possessionProof).proof, authorization_signature: hexToBytes(input.authorizationSignature) })
  }

  registerAuthorizationKey(input: AuthorizationKeyRegistration): Promise<ActionReceipt> {
    return this.call('register_authorization_key', { key_id: input.keyId, public_key: hexToBytes(input.publicKey), proof: proofArgs(input.proof).proof })
  }

  revokeAuthorizationKey(input: { keyId: string }): Promise<ActionReceipt> {
    return this.call('revoke_authorization_key', { key_id: input.keyId })
  }

  createVault(input: { assetAccount: string; assetsMaximum: string; kind: 'open_ended' | 'closed_ended'; phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }; shareScale: number; sharesTransferable: boolean; checkpointPolicy: { epochSeconds: number; disclosurePolicy: string } }): Promise<ActionReceipt> {
    return this.call('create_vault', { assets_maximum: input.assetsMaximum, kind: input.kind === 'open_ended' ? 'OpenEnded' : 'ClosedEnded', phase_times: input.phaseTimes ? { subscription_start: decimal(input.phaseTimes.subscriptionStart), investment_start: decimal(input.phaseTimes.investmentStart), redemption_start: decimal(input.phaseTimes.redemptionStart), redemption_buffer: decimal(input.phaseTimes.redemptionBuffer) } : null, share_scale: input.shareScale, shares_transferable: input.sharesTransferable, checkpoint_policy: { epoch_seconds: decimal(input.checkpointPolicy.epochSeconds), disclosure_policy: input.checkpointPolicy.disclosurePolicy } })
  }

  createBroker(input: { vaultId: string; brokerEncryptionKeyId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('create_broker', { vault_id: input.vaultId, encryption_key_id: input.brokerEncryptionKeyId, encryption_public_key: hexToBytes(input.brokerEncryptionKey), debt_maximum: input.brokerDebtCeiling, proof_of_possession: proofArgs(input.possessionProof).proof })
  }

  depositExternal(input: { amount: string; depositId: string }): Promise<ActionReceipt> {
    return this.callWithOptions('ft_transfer_call', { receiver_id: this.config.coreAccountId, amount: input.amount, msg: JSON.stringify({ version: 1, deposit_id: input.depositId }) }, { receiverId: this.config.tokenAccountId, gas: '100000000000000', deposit: '1' })
  }

  depositToVault(input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('deposit_to_vault', { claim_id: input.claimId, vault_id: input.vaultId, amount: input.amount, min_shares_out: input.minShares, expiry: decimal(input.expiresAt) })
  }

  redeemShares(input: { vaultId: string; shares: string; minAmount: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('redeem_shares', { vault_id: input.vaultId, shares: input.shares, min_assets_out: input.minAmount, expiry: decimal(input.expiresAt), sole_shareholder_waiver: false })
  }

  requestPayout(input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt> {
    return this.call('request_payout', { claim_id: input.claimId, operation_id: input.operationId, recipient: input.recipientId })
  }

  mergeInbox(input: { accountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('merge_inbox', { expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  mergeBrokerInbox(input: { brokerId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('merge_broker_inbox', { broker_id: input.brokerId, args: { expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) } })
  }

  draw(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('draw', { broker_id: input.brokerId, amount: input.amount, ...proofArgs(input.proof) })
  }

  createProposal(input: { brokerId: string; borrowerId: string; vaultId: string; borrowerKeyId: string; brokerKeyId: string; borrowerAuthorizationKeyId?: string; brokerAuthorizationKeyId?: string; auditorKeyId: string; auditorPublicKey: string; paymentCount: number; paymentIntervalSeconds: number; gracePeriodSeconds: number; encryptedPrincipal: string[]; encryptedOwed: string[]; encryptedPayment: string[]; principalCommitment: string; owedCommitment: string; paymentCommitment: string; encryptedAgreement: string; termsDigest: string; brokerSignature: string; borrowerSignature: string; brokerAuthorizationEpoch: string; borrowerAuthorizationEpoch: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('create_proposal', { borrower: input.borrowerId, broker_id: input.brokerId, vault_id: input.vaultId, borrower_key_id: input.borrowerKeyId, broker_key_id: input.brokerKeyId, ...(input.brokerAuthorizationKeyId ? { broker_authorization_key_id: input.brokerAuthorizationKeyId } : {}), ...(input.borrowerAuthorizationKeyId ? { borrower_authorization_key_id: input.borrowerAuthorizationKeyId } : {}), loan_auditor_key_id: input.auditorKeyId, loan_auditor_public_key: hexToBytes(input.auditorPublicKey), payment_count: input.paymentCount, payment_interval: decimal(input.paymentIntervalSeconds), grace_period: decimal(input.gracePeriodSeconds), expiry: decimal(input.expiresAt), principal_ciphertexts: input.encryptedPrincipal.map(hexToBytes), initial_owed_ciphertexts: input.encryptedOwed.map(hexToBytes), periodic_payment_ciphertexts: input.encryptedPayment.map(hexToBytes), principal_commitment: hexToBytes(input.principalCommitment), owed_commitment: hexToBytes(input.owedCommitment), payment_commitment: hexToBytes(input.paymentCommitment), agreement_digest: input.termsDigest.trim() ? hexToBytes(input.termsDigest) : [], broker_signature: optionalHexToBytes(input.brokerSignature), borrower_signature: optionalHexToBytes(input.borrowerSignature), broker_authorization_epoch: input.brokerAuthorizationEpoch, borrower_authorization_epoch: input.borrowerAuthorizationEpoch })
  }

  authorizeProposal(input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt> {
    return this.call('sign_proposal', { proposal_id: input.proposalId, signature: hexToBytes(input.authorizationSignature) })
  }

  revokeProposal(input: { proposalId: string }): Promise<ActionReceipt> {
    return this.call('revoke_proposal', { proposal_id: input.proposalId })
  }

  originate(input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('originate', { proposal_id: input.proposalId, ...proofArgs(input.proof) })
  }

  confidentialSend(input: { senderAccountId: string; destinationAccountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('confidential_send', { destination: input.destinationAccountId, expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  repay(input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; expectedBorrowerSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('repay', { loan_id: input.loanId, mode: input.mode === 'regular' ? 'Regular' : 'Full', expected_loan_version: input.expectedLoanVersion, expected_borrower_spending_version: input.expectedBorrowerSpendingVersion, ...proofArgs(input.proof) })
  }

  manageLoan(input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('manage_loan', { loan_id: input.loanId, action: input.operation === 'impair' ? 'Impair' : input.operation === 'unimpair' ? 'Unimpair' : 'Default', expected_loan_version: input.expectedLoanVersion, ...proofArgs(input.proof) })
  }

  settle(input: { brokerId: string; amount: string; expectedSpendingVersion: string; expectedAccountingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('settle', { broker_id: input.brokerId, amount: input.amount, expected_spending_version: input.expectedSpendingVersion, expected_accounting_version: input.expectedAccountingVersion, ...proofArgs(input.proof) })
  }

  reconcileCredit(input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('reconcile_credit', { broker_id: input.brokerId, ...proofArgs(input.proof) })
  }

  prepareReconciliation(input: { brokerId: string }): Promise<ActionReceipt> {
    return this.call('prepare_reconciliation', { broker_id: input.brokerId })
  }

  grantKeeper(input: { brokerId: string; delegateId: string; delegateKeyId: string; scope: KeeperGrant['scope']; maxAmountPerOperation: string; maxAmountPerWindow: string; windowSeconds: number; delegateEpoch: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('grant_keeper', {
      broker_id: input.brokerId,
      delegate_account: input.delegateId,
      delegate_key_id: input.delegateKeyId,
      allowed_settlement_per_operation: input.maxAmountPerOperation,
      allowed_settlement_per_window: input.maxAmountPerWindow,
      window_seconds: decimal(input.windowSeconds),
      expires_at: decimal(input.expiresAt),
      delegate_epoch: input.delegateEpoch,
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
  const rpc = new NearRpc(config.rpcUrl, { allowInsecureLocalhost: config.allowInsecureLocalhost })
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
