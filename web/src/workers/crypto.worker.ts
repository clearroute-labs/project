import { NearRpc } from '@confidential-lending/client'
import {
  CryptoRuntime,
  HistoryRecovery,
  Keyring,
  LedgerWallet,
  ProofBuilder,
  type AgreementDraft as PrivateAgreementDraft,
  type Ciphertext,
  type Commitment,
  type EncryptionPublicKey,
  type KeyReference,
  type ReaderView,
  type RepaymentTerms,
  type SpendingState,
  type PreparedCall,
  type WalletMaterial,
} from '@confidential-lending/wallet'
import { CoreWallet, type CoreProofContext } from '../../../packages/wallet/src/core'
import type {
  AgreementDraft,
  AuditCiphertextBundle,
  AuthorizationKeyRegistration,
  BrokerKeyPreparation,
  BrokerSummary,
  DecryptedAuditView,
  KeyRegistration,
  LoanManagementPreparation,
  LoanSummary,
  PreparedProof,
  PrivateAccountView,
  ProposalSummary,
} from '../lib/types'

type WorkerRequest = { id: number; method: string; payload?: unknown }
type WorkerReply = { id: number; ok: true; value: unknown } | { id: number; ok: false; category: string; message: string }

interface WorkerConfiguration {
  manifestUrl?: string
  baseUrl?: string
  expectedProfileHash: string
  expectedManifestHash?: string
  networkId: string
  coreAccountId: string
  assetId: string
  funded: boolean
  rpcUrl?: string
  allowInsecureLocalhost?: boolean
  subjectId?: string
}

interface RawAssetProfile {
  token_account: string
  issuer_key: { key_id: string | number; public_key: unknown }
  token_auditor_key: { key_id: string | number; public_key: unknown }
}
interface RawHolder {
  owner: string; asset_id: string; key_id: string | number; public_key?: unknown; encryption_public_key?: unknown; encryption_key?: { public_key?: unknown }
  spending_ciphertext: unknown; inbox_ciphertext: unknown; issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown
  spending_commitment?: unknown; inbox_commitment?: unknown; spending_version: string | number
}
interface RawBroker {
  broker_id: string | number; owner: string; vault_id: string | number; encryption_key_id: string | number; encryption_public_key?: unknown; spending_ciphertext: unknown; inbox_ciphertext: unknown
  issuer_balance_ciphertext?: unknown; auditor_balance_ciphertext?: unknown; spending_commitment?: unknown; inbox_commitment?: unknown
  active_principal_ciphertext?: unknown; impaired_principal_ciphertext?: unknown; active_principal_commitment?: unknown; impaired_principal_commitment?: unknown
  loan_book_root?: unknown; accounting_leaf?: unknown; book_version?: string | number; accounting_version?: string | number; debt_total?: string | number; impairment_provision?: string | number
}
interface WorkerState {
  configuration: WorkerConfiguration
  runtime: CryptoRuntime
  keyring: Keyring
  proofs: ProofBuilder
  recovery: HistoryRecovery
  ledger?: LedgerWallet
  core?: CoreWallet
  drafts: Map<string, PrivateAgreementDraft>
  authKeys: Map<string, { privateKey: CryptoKey; publicKey: string }>
  subjectId?: string
  ready: boolean
}

type BackupMaterial = WalletMaterial & {
  drafts?: Array<[string, PrivateAgreementDraft]>
  authKeys?: Array<{ keyId: string; privateKey: string; publicKey: string }>
}

let state: WorkerState | undefined
let initializing: Promise<void> | undefined

declare const self: { postMessage(message: unknown): void; onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null; location: Location }
function reply(message: WorkerReply): void { self.postMessage(message) }

function failureMessage(error: unknown): string {
  if (error instanceof Error && /^INBOX_MERGE_REQUIRED:(?:[a-z-]+)$/.test(error.message)) return error.message
  if (error instanceof Error && /manifest|profile|artifact|configuration|deployment|RPC|Core|context/i.test(error.message)) return error.message.slice(0, 240)
  return 'Confidential crypto operation failed.'
}
function text(value: unknown, name: string): string { if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`); return value }
function decimal(value: unknown, name: string): string {
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) return value
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value)
  throw new Error(`${name} must be a canonical decimal string`)
}
function bytes(value: unknown, name: string): number[] { if (!Array.isArray(value) || value.some(item => !Number.isInteger(item) || item < 0 || item > 255)) throw new Error(`${name} is not a byte array`); return value as number[] }
function hexBytes(value: string): number[] {
  const normalized = value.trim().replace(/^0x/, '')
  if (!normalized || normalized.length % 2 !== 0 || !/^[a-f\d]+$/i.test(normalized)) throw new Error('Expected canonical hexadecimal bytes')
  const result: number[] = []; for (let i = 0; i < normalized.length; i += 2) result.push(Number.parseInt(normalized.slice(i, i + 2), 16)); return result
}
function toHex(value: ArrayLike<number>): string { let result = ''; for (let i = 0; i < value.length; i += 1) result += Number(value[i]).toString(16).padStart(2, '0'); return result }
function jsonHex(value: unknown): string { return toHex(new TextEncoder().encode(JSON.stringify(value))) }
function fromJsonHex(value: string, name: string): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(hexBytes(value)))) as unknown } catch { throw new Error(`${name} is not canonical crypto JSON`) } }
function asCiphertext(value: unknown, name = 'ciphertext'): Ciphertext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} is not a ciphertext`)
  const candidate = value as Record<string, unknown>; const ephemeral = text(candidate.ephemeral, `${name}.ephemeral`); const message = text(candidate.message, `${name}.message`)
  if (!/^[a-f0-9]+$/.test(ephemeral) || !/^[a-f0-9]+$/.test(message)) throw new Error(`${name} has invalid point encoding`)
  return { ephemeral, message }
}
function ciphertextFromHex(value: string, name = 'ciphertext'): Ciphertext { return asCiphertext(fromJsonHex(value, name), name) }
function ciphertextHex(value: Ciphertext): string { return jsonHex(value) }
function asCommitment(value: unknown): Commitment { if (!value || typeof value !== 'object' || Array.isArray(value) || typeof (value as Record<string, unknown>).point !== 'string') throw new Error('Crypto statement commitment is invalid'); return { point: (value as Record<string, string>).point } }
function commitmentHex(value: Commitment): string { return jsonHex(value) }
function publicKeyFromHex(value: string, name = 'public key'): EncryptionPublicKey {
  let decoded: unknown
  try { decoded = fromJsonHex(value, name) } catch { decoded = undefined }
  if (decoded && typeof decoded === 'object' && !Array.isArray(decoded) && typeof (decoded as Record<string, unknown>).point === 'string') return { point: (decoded as Record<string, string>).point }
  if (/^[a-f0-9]+$/.test(value) && value.length === 64) return { point: value }
  throw new Error(`${name} is not a registered encryption key`)
}
function publicKeyHex(value: EncryptionPublicKey): string { return jsonHex(value) }
function publicKeyFromRaw(value: unknown, name = 'public key'): EncryptionPublicKey { return typeof value === 'string' ? publicKeyFromHex(value, name) : publicKeyFromHex(toHex(bytes(value, name)), name) }
function randomKeyId(): string { const random = crypto.getRandomValues(new Uint8Array(8)); let value = 0n; for (const byte of random) value = (value << 8n) | BigInt(byte); return (value & 0x7fff_ffff_ffff_ffffn).toString() }
function requireState(): WorkerState { if (!state?.ready) throw new Error('The pinned browser crypto runtime is not initialized'); return state }
function requireSubject(current = requireState()): string { if (!current.subjectId) throw new Error('Connect a NEAR account before using private operations'); return current.subjectId }
function keyCandidates(current: WorkerState, role: KeyReference['role'], subjectId: string, keyId: string): KeyReference[] { const candidates: KeyReference[] = [{ role, subjectId, keyId }]; if (role !== 'holder') candidates.push({ role: 'holder', subjectId: current.subjectId || subjectId, keyId }); return candidates }
function resolveKey(current: WorkerState, role: KeyReference['role'], subjectId: string, keyId: string): KeyReference { const fixed = decimal(keyId, 'key ID'); for (const candidate of keyCandidates(current, role, subjectId, fixed)) { try { current.keyring.publicKey(candidate); return candidate } catch { /* try the next role */ } } throw new Error(`Private key ${fixed} is not available in this browser wallet`) }
function resolveLoanAuditorKey(current: WorkerState, loanId: string, keyId: string, publicKey: string | undefined): KeyReference {
  const expected = publicKeyFromHex(text(publicKey, 'loan auditor public key'), 'loan auditor public key').point
  const fixed = decimal(keyId, 'loan auditor key ID')
  const matches = current.keyring.exportMaterial().keys.filter((candidate) => candidate.role === 'loan_auditor' && candidate.keyId === fixed && candidate.publicKey.point === expected)
  if (matches.length !== 1) throw new Error(`The registered loan-auditor key for loan ${loanId} is not available in this browser wallet`)
  return { role: 'loan_auditor', subjectId: matches[0]!.subjectId, keyId: matches[0]!.keyId }
}
async function readAsset(current: WorkerState): Promise<RawAssetProfile> { if (!current.core) throw new Error('Core RPC is not configured for this deployment'); return (await current.core.read<RawAssetProfile>('get_asset_profile')).value }
async function readHolder(current: WorkerState, accountId: string): Promise<RawHolder> { if (!current.core) throw new Error('Core RPC is not configured for this deployment'); const holder = (await current.core.read<RawHolder | null>('get_holder', { owner: accountId })).value; if (!holder) throw new Error('The requested account has no registered confidential holder key'); return holder }
async function readBroker(current: WorkerState, brokerId: string): Promise<RawBroker> { if (!current.core) throw new Error('Core RPC is not configured for this deployment'); const broker = (await current.core.read<RawBroker | null>('get_broker', { broker_id: brokerId })).value; if (!broker) throw new Error('The requested broker is not available'); return broker }
function rawCiphertext(value: unknown, name: string): string { return typeof value === 'string' ? value : toHex(bytes(value, name)) }
function rawKey(value: RawHolder | RawBroker): EncryptionPublicKey { const candidate = 'encryption_key' in value ? value.encryption_key?.public_key : undefined; const raw = (value as RawHolder).public_key ?? (value as RawHolder).encryption_public_key ?? (value as RawBroker).encryption_public_key ?? candidate; if (raw === undefined) throw new Error('Core did not return a registered encryption public key'); return publicKeyFromRaw(raw) }
function viewCiphertext(value: unknown, name: string): Ciphertext { return ciphertextFromHex(rawCiphertext(value, name), name) }
async function decryptCiphertext(_current: WorkerState, _reference: KeyReference, _ciphertext: Ciphertext): Promise<string> {
  throw new Error('Ciphertext decryption requires a finalized, operation-specific recovery path')
}
function spendingState(reference: KeyReference, ciphertext: Ciphertext, version: string, amount: string): SpendingState { return { key: reference, ciphertext, version, amount } }
const statementKinds: Record<string, number> = { KeyPossession: 1, PublicConversion: 2, ConfidentialTransfer: 3, Origination: 4, Repayment: 5, Reconciliation: 6, ZeroBalance: 7, Ownership: 8 }
async function digestHex(value: string): Promise<string> { return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))) }
async function prepared(current: WorkerState, operation: { statement: Record<string, unknown>; envelope: { context_digest: string; proof: string; profile_hash: string; statement_kind: string; public_inputs: string[]; verifying_key_hash: string } }, operationArgs: Record<string, unknown> = {}): Promise<PreparedProof> { const statement = JSON.stringify(operation.statement); return { context: operation.envelope.context_digest, proof: operation.envelope.proof, statement, publicInputs: operation.envelope.public_inputs, profileHash: operation.envelope.profile_hash, artifactHash: current.configuration.expectedManifestHash || '', statementDigest: await digestHex(statement), statementKind: statementKinds[operation.envelope.statement_kind], verifyingKeyHash: operation.envelope.verifying_key_hash, operationArgs } }
function statementFields(proof: PreparedProof, family: string): Record<string, unknown> { const value = JSON.parse(proof.statement) as Record<string, unknown>; const fields = value[family]; if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new Error(`Crypto statement does not contain ${family}`); return fields as Record<string, unknown> }
function viewsHex(value: unknown): string[] { if (!Array.isArray(value)) throw new Error('Crypto statement views are missing'); return value.map((item, index) => { if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`Crypto view ${index} is invalid`); return ciphertextHex(asCiphertext((item as Record<string, unknown>).ciphertext, `view ${index}`)) }) }
function encryptionKeys(asset: RawAssetProfile, borrower: EncryptionPublicKey, broker: EncryptionPublicKey, auditor: EncryptionPublicKey) { return { issuer: publicKeyFromRaw(asset.issuer_key.public_key, 'issuer public key'), tokenAuditor: publicKeyFromRaw(asset.token_auditor_key.public_key, 'token auditor public key'), borrower, broker, auditor } }
function preparedMerge(current: WorkerState, newSpending: Ciphertext): PreparedProof { return { context: '', proof: '', statement: 'merge-inbox', publicInputs: [], profileHash: current.configuration.expectedProfileHash, artifactHash: current.configuration.expectedManifestHash || '', statementDigest: '', operationArgs: { new_spending_ciphertext: ciphertextHex(newSpending) } } }
function wirePublicValue(value: unknown, name: string): unknown {
  if (Array.isArray(value) && value.every(item => Number.isInteger(item) && item >= 0 && item <= 255)) return toHex(value as number[])
  if (Array.isArray(value) && value.every(item => Array.isArray(item) && item.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255))) return (value as number[][]).map(bytesValue => toHex(bytesValue))
  if (name === 'reconciliation' && value && typeof value === 'object' && !Array.isArray(value)) {
    const child = value as Record<string, unknown>; const result: Record<string, unknown> = {}
    for (const [key, childValue] of Object.entries(child)) result[key] = key === 'proof' ? wireProofEnvelope(childValue) : wirePublicValue(childValue, key)
    return result
  }
  if (name === 'zero_proof' && value && typeof value === 'object' && !Array.isArray(value)) {
    const child = value as Record<string, unknown>; const result: Record<string, unknown> = {}
    for (const [key, childValue] of Object.entries(child)) result[key] = key.endsWith('_proof') ? wireProofEnvelope(childValue) : childValue
    return result
  }
  return value
}
function wireProofEnvelope(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Ledger returned an invalid nested proof envelope')
  const candidate = value as Record<string, unknown>; const statement = Array.isArray(candidate.statement) ? new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes(candidate.statement, 'nested statement'))) : candidate.statement
  const result: Record<string, unknown> = { ...candidate, statement }
  for (const key of ['context', 'proof', 'verifying_key_hash', 'profile_hash']) if (Array.isArray(result[key])) result[key] = toHex(bytes(result[key], `nested proof ${key}`))
  if (Array.isArray(result.public_inputs)) result.public_inputs = (result.public_inputs as unknown[]).map((item, index) => Array.isArray(item) ? toHex(bytes(item, `nested public input ${index}`)) : item)
  return result
}
function ledgerOperationArgs(call: PreparedCall): Record<string, unknown> {
  const outer = call.args as Record<string, unknown>; const raw = outer.args && typeof outer.args === 'object' && !Array.isArray(outer.args) ? outer.args as Record<string, unknown> : outer
  const result: Record<string, unknown> = {}
  const allowed = new Set(['new_spending_ciphertext', 'issuer_ciphertext', 'auditor_ciphertext', 'broker_ciphertext', 'broker_spending_commitment', 'broker_inbox_commitment', 'borrower_spending_ciphertext', 'borrower_issuer_ciphertext', 'borrower_auditor_ciphertext', 'broker_spending_ciphertext', 'broker_issuer_ciphertext', 'broker_auditor_ciphertext', 'loan_principal_ciphertexts', 'loan_initial_owed_ciphertexts', 'loan_periodic_payment_ciphertexts', 'principal_commitment', 'owed_commitment', 'payment_commitment', 'broker_active_principal_ciphertext', 'broker_impaired_principal_ciphertext', 'broker_book_root', 'accounting_leaf', 'broker_active_principal_commitment', 'broker_impaired_principal_commitment', 'sender_spending_ciphertext', 'sender_issuer_ciphertext', 'sender_auditor_ciphertext', 'destination_inbox_ciphertext', 'destination_issuer_ciphertext', 'destination_auditor_ciphertext', 'transfer_views', 'commitment', 'broker_inbox_ciphertext', 'amount_owed_ciphertexts', 'principal_remaining_ciphertexts', 'cumulative_repaid_ciphertexts', 'broker_inbox_commitment', 'settlement_views', 'expected_spending_version', 'expected_loan_version', 'expected_borrower_spending_version', 'expected_book_version', 'expected_accounting_version', 'checkpoint_id', 'broker_id', 'loan_id', 'proposal_id', 'expected_risk_version', 'new_broker_debt', 'new_broker_provision', 'loss', 'new_vault_total', 'reconciliation', 'zero_proof'])
  for (const [key, value] of Object.entries(raw)) if (key !== 'proof' && allowed.has(key)) result[key] = wirePublicValue(value, key)
  return result
}
function preparedCallArgs(call: PreparedCall, name: string): Record<string, unknown> {
  if (!call.args || typeof call.args !== 'object' || Array.isArray(call.args)) throw new Error(`Core returned an invalid ${name} argument envelope`)
  const outer = call.args as Record<string, unknown>
  const raw = outer.args
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`Core returned an invalid ${name} argument object`)
  return raw as Record<string, unknown>
}
async function preparedLedger(current: WorkerState, call: PreparedCall): Promise<PreparedProof> {
  if (!call.proof) throw new Error(`Core returned no proof for ${call.method}`)
  const envelope = call.proof.envelope; const statement = JSON.stringify(call.proof.statement); const kind = statementKinds[envelope.statement_kind] || (typeof envelope.statement_kind === 'number' ? envelope.statement_kind : undefined)
  if (kind === undefined) throw new Error('Core returned an unknown proof statement kind')
  return { context: envelope.context_digest, proof: envelope.proof, statement, publicInputs: envelope.public_inputs, profileHash: envelope.profile_hash, artifactHash: current.configuration.expectedManifestHash || '', statementDigest: await digestHex(statement), statementKind: kind, verifyingKeyHash: envelope.verifying_key_hash, operationArgs: ledgerOperationArgs(call) }
}
async function context(current: WorkerState, request: Parameters<CoreWallet['getProofContext']>[0]): Promise<CoreProofContext> { if (!current.core) throw new Error('Core RPC is not configured for this deployment'); const value = await current.core.getProofContext(request); if (!value) throw new Error(`Core did not expose a proof context for ${request.operation}`); return value }

async function makeKeyRegistration(current: WorkerState): Promise<KeyRegistration> {
  const subject = requireSubject(current); const encryptionKeyId = randomKeyId();
  if (current.ledger) {
    const call = await current.ledger.prepareHolderRegistration(subject, encryptionKeyId)
    const raw = preparedCallArgs(call, 'holder registration')
    const publicKey = toHex(bytes(raw.encryption_public_key, 'holder encryption public key'))
    return { encryptionPublicKey: publicKey, encryptionKeyId, possessionProof: await preparedLedger(current, call), authorizationPublicKey: publicKey, authorizationSignature: '' }
  }
  const reference: KeyReference = { role: 'holder', subjectId: subject, keyId: encryptionKeyId }; const publicKey = await current.keyring.generate(reference)
  // Core's holder registration uses the encryption public key for both legacy
  // public-key fields. Authorization keys are registered separately; an
  // Ed25519 session key must never be substituted into this operation.
  const registrationContext = await context(current, { operation: 'register-holder', accountId: subject, primaryId: encryptionKeyId }); const proof = await current.proofs.possession(registrationContext.operationContext, reference)
  const publicKeyValue = publicKeyHex(publicKey)
  return { encryptionPublicKey: publicKeyValue, encryptionKeyId, possessionProof: await prepared(current, proof), authorizationPublicKey: publicKeyValue, authorizationSignature: '' }
}
async function makeAuthorizationRegistration(current: WorkerState): Promise<AuthorizationKeyRegistration> {
  requireSubject(current); const keyId = randomKeyId(); const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair; const exported = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)); const publicKey = toHex(exported); current.authKeys.set(keyId, { privateKey: pair.privateKey, publicKey })
  // Core's authorization-key registration is direct account authority. It
  // deliberately has no proof-of-possession field; never substitute a holder
  // encryption proof for this application-key registration.
  return { keyId, publicKey }
}

async function shield(current: WorkerState, input: { account: PrivateAccountView; claimId: string }): Promise<PreparedProof> {
  if (!current.ledger) throw new Error('Shielding requires the configured finalized Core wallet')
  return preparedLedger(current, await current.ledger.prepareShield(requireSubject(current), decimal(input.claimId, 'claim ID')))
}

async function unshield(current: WorkerState, input: { account: PrivateAccountView; amount: string }): Promise<PreparedProof> {
  if (!current.ledger) throw new Error('Unshielding requires the configured finalized Core wallet')
  return preparedLedger(current, await current.ledger.prepareUnshield(requireSubject(current), decimal(input.amount, 'amount')))
}

async function brokerClosure(current: WorkerState, input: { brokerId: string }): Promise<PreparedProof> {
  if (!current.ledger) throw new Error('Broker closure requires the configured finalized Core wallet')
  return preparedLedger(current, await current.ledger.prepareBrokerClosure(decimal(input.brokerId, 'broker ID')))
}
async function brokerKeyRegistration(current: WorkerState, input: { ownerId: string; vaultId: string; encryptionKeyId: string; debtMaximum: string }): Promise<BrokerKeyPreparation> {
  if (!current.ledger) throw new Error('Broker creation requires the configured finalized Core wallet')
  if (requireSubject(current) !== input.ownerId) throw new Error('The connected account must own the broker key')
  const snapshot = await current.ledger.snapshot()
  const counters = await current.ledger.view<{ broker_high_water: string }>(snapshot.block, 'get_counters')
  const expectedBrokerId = (BigInt(counters.broker_high_water) + 1n).toString()
  let existing = false
  try { current.keyring.publicKey({ role: 'broker', subjectId: expectedBrokerId, keyId: decimal(input.encryptionKeyId, 'broker encryption key ID') }); existing = true } catch { /* first preparation for this broker */ }
  const call = await current.ledger.prepareBrokerCreation(input.ownerId, decimal(input.vaultId, 'vault ID'), decimal(input.encryptionKeyId, 'broker encryption key ID'), decimal(input.debtMaximum, 'debt maximum'))
  if (call.brokerId !== expectedBrokerId) throw new Error('The broker sequence changed while preparing the registration; refresh and try again')
  const raw = preparedCallArgs(call, 'broker creation')
  return { brokerId: call.brokerId, encryptionKeyId: decimal(raw.encryption_key_id, 'broker encryption key ID'), encryptionPublicKey: toHex(bytes(raw.encryption_public_key, 'broker encryption public key')), possessionProof: await preparedLedger(current, call), newKeyGenerated: !existing }
}
async function loanManagement(current: WorkerState, input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<LoanManagementPreparation> {
  if (!current.ledger) throw new Error('Loan management requires the configured finalized Core wallet')
  const action = input.operation === 'impair' ? 'Impair' : input.operation === 'unimpair' ? 'Unimpair' : 'Default'
  const call = await current.ledger.prepareManagement(input.loan.loanId, action)
  const raw = preparedCallArgs(call, 'loan management')
  const loanId = decimal(raw.loan_id, 'loan ID'); const expectedLoanVersion = decimal(raw.expected_loan_version, 'loan version')
  if (loanId !== input.loan.loanId || expectedLoanVersion !== input.loan.stateVersion) throw new Error('Core loan management preparation changed the selected loan version')
  return { loanId, operation: input.operation, expectedLoanVersion }
}

async function agreement(current: WorkerState, input: { brokerId?: string; borrowerId?: string; publicKeys: { borrower: string; broker: string; issuer: string; tokenAuditor: string; loanAuditor: string }; principal: string; initialOwed: string; periodicPayment: string; paymentCount: number; maxPaymentCount: number }): Promise<AgreementDraft> {
  const keys = { borrower: publicKeyFromHex(input.publicKeys.borrower, 'borrower public key'), broker: publicKeyFromHex(input.publicKeys.broker, 'broker public key'), issuer: publicKeyFromHex(input.publicKeys.issuer, 'issuer public key'), tokenAuditor: publicKeyFromHex(input.publicKeys.tokenAuditor, 'token auditor public key'), loanAuditor: publicKeyFromHex(input.publicKeys.loanAuditor, 'loan auditor public key') }
  const draft = current.ledger && input.brokerId && input.borrowerId
    ? await current.ledger.agreement(input.brokerId, input.borrowerId, keys.loanAuditor, { principal: decimal(input.principal, 'principal'), initialOwed: decimal(input.initialOwed, 'initial owed'), periodicPayment: decimal(input.periodicPayment, 'periodic payment'), paymentCount: input.paymentCount })
    : await current.proofs.agreement({ principal: decimal(input.principal, 'principal'), initialOwed: decimal(input.initialOwed, 'initial owed'), periodicPayment: decimal(input.periodicPayment, 'periodic payment'), paymentCount: input.paymentCount, maxPaymentCount: input.maxPaymentCount, transferKeys: [keys.broker, keys.borrower, keys.issuer, keys.tokenAuditor, keys.loanAuditor], loanKeys: [keys.borrower, keys.broker, keys.loanAuditor] })
  const draftId = crypto.randomUUID(); current.drafts.set(draftId, draft)
  const publicEnvelope = {
    version: 1,
    principal: draft.principal.views,
    owed: draft.owed.views,
    payment: draft.payment.views,
    principalCommitment: draft.principalCommitment.commitment,
    owedCommitment: draft.owedCommitment.commitment,
    paymentCommitment: draft.paymentCommitment.commitment,
    recovery: {
      principal: draft.principal.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]),
      owed: draft.owed.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]),
      payment: draft.payment.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]),
    },
  }
  return { draftId, principalCiphertexts: draft.principal.views.map(view => ciphertextHex(view.ciphertext)), initialOwedCiphertexts: draft.owed.views.map(view => ciphertextHex(view.ciphertext)), periodicPaymentCiphertexts: draft.payment.views.map(view => ciphertextHex(view.ciphertext)), principalCommitment: commitmentHex(draft.principalCommitment.commitment), owedCommitment: commitmentHex(draft.owedCommitment.commitment), paymentCommitment: commitmentHex(draft.paymentCommitment.commitment), encryptedAgreement: jsonHex(publicEnvelope), transferRecovery: draft.principal.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]), owedRecovery: draft.owed.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]), paymentRecovery: draft.payment.recovery.map(pair => [ciphertextHex(pair.low_limb), ciphertextHex(pair.high_limb)]) }
}

async function confidentialTransfer(current: WorkerState, input: { sender: PrivateAccountView; destinationAccountId: string; amount: string; destinationEncryptionKeyId: string; destinationEncryptionPublicKey?: string }): Promise<PreparedProof> {
  if (current.ledger) return preparedLedger(current, await current.ledger.prepareTransfer(requireSubject(current), input.destinationAccountId, input.amount))
  if (current.core) throw new Error('Confidential transfers require the configured finalized Core wallet')
  const subject = requireSubject(current); if (!input.destinationEncryptionPublicKey) throw new Error('The destination registered encryption key must be resolved before proving a transfer'); const asset = await readAsset(current); const senderReference = resolveKey(current, 'holder', subject, input.sender.encryptionKeyId); const senderCiphertext = ciphertextFromHex(input.sender.balanceCiphertext, 'sender balance'); const sender = spendingState(senderReference, senderCiphertext, input.sender.spendingVersion, await decryptCiphertext(current, senderReference, senderCiphertext)); const destination = publicKeyFromHex(input.destinationEncryptionPublicKey, 'destination public key'); const senderKey = current.keyring.publicKey(senderReference); const keys = encryptionKeys(asset, senderKey, destination, destination); const proofContext = await context(current, { operation: 'confidential-send', accountId: subject, destination: input.destinationAccountId }); const operation = await current.proofs.transfer(proofContext.operationContext, sender, input.amount, [keys.borrower, keys.broker, keys.issuer, keys.tokenAuditor, keys.broker]); const proof = await prepared(current, operation); const fields = statementFields(proof, 'ConfidentialTransfer'); return { ...proof, operationArgs: { sender_spending_ciphertext: ciphertextHex(asCiphertext(fields.sender_spending_after)), transfer_views: viewsHex(fields.transfer_views), commitment: commitmentHex(asCommitment(fields.amount_commitment)) } }
}
async function merge(current: WorkerState, input: { account: PrivateAccountView; scope: 'holder' | 'broker'; brokerId?: string }): Promise<PreparedProof> {
  if (current.ledger && (input.scope === 'holder' || input.brokerId)) {
    const call = input.scope === 'holder' ? await current.ledger.prepareMergeHolder(requireSubject(current)) : await current.ledger.prepareMergeBroker(input.brokerId!)
    const raw = preparedCallArgs(call, 'inbox merge')
    return { context: '', proof: '', statement: 'merge-inbox', publicInputs: [], profileHash: current.configuration.expectedProfileHash, artifactHash: current.configuration.expectedManifestHash || '', statementDigest: '', operationArgs: { new_spending_ciphertext: toHex(bytes(raw.new_spending_ciphertext, 'new spending ciphertext')) } }
  }
  if (current.core) throw new Error('Inbox merges require the configured finalized Core wallet')
  return preparedMerge(current, await current.proofs.combine('add', ciphertextFromHex(input.account.balanceCiphertext, 'spending ciphertext'), ciphertextFromHex(input.account.inboxCiphertext, 'inbox ciphertext')))
}
async function draw(current: WorkerState, input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> {
  if (current.ledger) return preparedLedger(current, await current.ledger.prepareDraw(input.broker.brokerId, input.amount))
  if (current.core) throw new Error('Broker draws require the configured finalized Core wallet')
  const asset = await readAsset(current); const brokerRaw = await readBroker(current, input.broker.brokerId); const brokerReference = resolveKey(current, 'broker', input.broker.brokerId, input.broker.privateBalanceKeyId); const brokerPublicKey = rawKey(brokerRaw); const inbox = viewCiphertext(brokerRaw.inbox_ciphertext, 'broker inbox'); const balance = spendingState(brokerReference, inbox, input.expectedSpendingVersion, await decryptCiphertext(current, brokerReference, inbox)); const proofContext = await context(current, { operation: 'draw', brokerId: input.broker.brokerId, amount: input.amount }); const keys = encryptionKeys(asset, brokerPublicKey, brokerPublicKey, brokerPublicKey); const operation = await current.proofs.conversion(proofContext.operationContext, balance, input.amount, [keys.broker, keys.issuer, keys.tokenAuditor], 'Credit'); const proof = await prepared(current, operation); const fields = statementFields(proof, 'PublicConversion'); const views = viewsHex(fields.views); return { ...proof, operationArgs: { broker_ciphertext: views[0], issuer_ciphertext: views[1], auditor_ciphertext: views[2], broker_spending_commitment: input.broker.spendingCommitment, broker_inbox_commitment: input.broker.inboxCommitment } }
}
function draftForProposal(current: WorkerState, proposal: ProposalSummary): PrivateAgreementDraft { const target = (proposal.encryptedPrincipal || []).join('|'); for (const draft of current.drafts.values()) if (draft.principal.views.map(view => ciphertextHex(view.ciphertext)).join('|') === target) return draft; throw new Error('The private agreement draft is no longer in this browser worker; prepare a new proposal') }
async function brokerOrigination(current: WorkerState, input: { proposal: ProposalSummary; broker: BrokerSummary }): Promise<PreparedProof> {
  const draft = draftForProposal(current, input.proposal); if (current.ledger) return preparedLedger(current, await current.ledger.prepareOrigination(input.proposal.proposalId, draft))
  if (current.core) throw new Error('Loan origination requires the configured finalized Core wallet')
  const brokerRaw = await readBroker(current, input.proposal.brokerId); const borrowerRaw = await readHolder(current, input.proposal.borrowerId); const brokerReference = resolveKey(current, 'broker', input.proposal.brokerId, input.broker.privateBalanceKeyId); const spending = viewCiphertext(brokerRaw.spending_ciphertext, 'broker spending'); const balance = spendingState(brokerReference, spending, input.broker.spendingVersion, await decryptCiphertext(current, brokerReference, spending)); const proofContext = await context(current, { operation: 'originate', primaryId: input.proposal.proposalId }); const operation = await current.proofs.originate(proofContext.operationContext, balance, draft); const proof = await prepared(current, operation); const fields = statementFields(proof, 'Origination'); const principalViews = viewsHex(fields.transfer_views); const issuerDelta = ciphertextFromHex(principalViews[2]!, 'issuer delta'); const auditorDelta = ciphertextFromHex(principalViews[3]!, 'auditor delta'); const borrowerIssuer = await current.proofs.combine('add', viewCiphertext(borrowerRaw.issuer_balance_ciphertext, 'borrower issuer balance'), issuerDelta); const borrowerAuditor = await current.proofs.combine('add', viewCiphertext(borrowerRaw.auditor_balance_ciphertext, 'borrower auditor balance'), auditorDelta); const brokerIssuer = await current.proofs.combine('sub', viewCiphertext(brokerRaw.issuer_balance_ciphertext, 'broker issuer balance'), issuerDelta); const brokerAuditor = await current.proofs.combine('sub', viewCiphertext(brokerRaw.auditor_balance_ciphertext, 'broker auditor balance'), auditorDelta); const active = await current.proofs.combine('add', viewCiphertext(brokerRaw.active_principal_ciphertext, 'active principal'), ciphertextFromHex(principalViews[0]!, 'principal delta')); return { ...proof, operationArgs: { borrower_spending_ciphertext: principalViews[1], borrower_issuer_ciphertext: ciphertextHex(borrowerIssuer), borrower_auditor_ciphertext: ciphertextHex(borrowerAuditor), broker_spending_ciphertext: ciphertextHex(asCiphertext(fields.broker_spending_after)), broker_issuer_ciphertext: ciphertextHex(brokerIssuer), broker_auditor_ciphertext: ciphertextHex(brokerAuditor), loan_principal_ciphertexts: principalViews, loan_initial_owed_ciphertexts: viewsHex(fields.owed_views), loan_periodic_payment_ciphertexts: viewsHex(fields.payment_views), principal_commitment: commitmentHex(asCommitment(fields.principal_commitment)), owed_commitment: commitmentHex(asCommitment(fields.owed_commitment)), payment_commitment: commitmentHex(asCommitment(fields.payment_commitment)), broker_active_principal_ciphertext: ciphertextHex(active), broker_impaired_principal_ciphertext: rawCiphertext(brokerRaw.impaired_principal_ciphertext, 'impaired principal'), broker_spending_commitment: input.broker.spendingCommitment, broker_active_principal_commitment: input.broker.activePrincipalCommitment, broker_impaired_principal_commitment: input.broker.impairedPrincipalCommitment } }
}

async function repayment(current: WorkerState, input: { loan: LoanSummary; borrower: PrivateAccountView; mode: 'regular' | 'full' }): Promise<PreparedProof> {
  if (current.ledger) return preparedLedger(current, await current.ledger.prepareRepayment(requireSubject(current), input.loan.loanId, input.mode === 'full' ? 'Full' : 'Regular'))
  if (current.core) throw new Error('Loan repayment requires the configured finalized Core wallet')
  const subject = requireSubject(current); const asset = await readAsset(current); const brokerRaw = await readBroker(current, input.loan.brokerId); const brokerKey = rawKey(brokerRaw); const borrowerReference = resolveKey(current, 'holder', subject, input.borrower.encryptionKeyId); const borrowerKey = current.keyring.publicKey(borrowerReference); const auditor = publicKeyFromHex(text(input.loan.auditorPublicKey, 'loan auditor public key'), 'loan auditor public key'); const keys = encryptionKeys(asset, borrowerKey, brokerKey, auditor); const readerKeys = [keys.borrower, keys.broker, keys.auditor]; const readerViews = (values: string[] | undefined, name: string): ReaderView[] => { if (!values || values.length !== 3) throw new Error(`Core did not return three ${name} ciphertext views`); return values.map((value, index) => ({ reader_key: readerKeys[index]!, ciphertext: ciphertextFromHex(value, `${name}[${index}]`) })) }; const owedViews = readerViews(input.loan.amountOwedCiphertexts, 'owed'); const periodicViews = readerViews(input.loan.periodicPaymentCiphertexts, 'periodic payment'); const principalViews = readerViews(input.loan.principalRemainingCiphertexts, 'principal remaining'); const terms: RepaymentTerms = { owed: await decryptCiphertext(current, borrowerReference, owedViews[0]!.ciphertext), periodicPayment: await decryptCiphertext(current, borrowerReference, periodicViews[0]!.ciphertext), principalRemaining: await decryptCiphertext(current, borrowerReference, principalViews[0]!.ciphertext), owedViews, paymentViews: periodicViews, principalViews, transferKeys: [keys.borrower, keys.broker, keys.issuer, keys.tokenAuditor, keys.auditor], paymentRemaining: input.loan.paymentRemaining, loanVersion: input.loan.stateVersion }; const balanceCiphertext = ciphertextFromHex(input.borrower.balanceCiphertext, 'borrower spending'); const balance = spendingState(borrowerReference, balanceCiphertext, input.borrower.spendingVersion, await decryptCiphertext(current, borrowerReference, balanceCiphertext)); const proofContext = await context(current, { operation: 'repay', primaryId: input.loan.loanId }); const operation = await current.proofs.repay(proofContext.operationContext, balance, terms, input.mode === 'full' ? 'Full' : 'Regular'); const proof = await prepared(current, operation); const fields = statementFields(proof, 'Repayment'); const transfer = viewsHex(fields.transfer_views); const owedAfter = viewsHex(fields.owed_after); const principalAfter = viewsHex(fields.principal_after); const owedDelta = viewsHex(fields.owed_delta); const borrowerIssuer = await current.proofs.combine('sub', viewCiphertext(input.borrower.issuerBalanceCiphertext, 'borrower issuer balance'), ciphertextFromHex(transfer[2]!, 'issuer delta')); const borrowerAuditor = await current.proofs.combine('sub', viewCiphertext(input.borrower.auditorBalanceCiphertext, 'borrower auditor balance'), ciphertextFromHex(transfer[3]!, 'auditor delta')); const brokerIssuer = await current.proofs.combine('add', viewCiphertext(brokerRaw.issuer_balance_ciphertext, 'broker issuer balance'), ciphertextFromHex(transfer[2]!, 'issuer delta')); const brokerAuditor = await current.proofs.combine('add', viewCiphertext(brokerRaw.auditor_balance_ciphertext, 'broker auditor balance'), ciphertextFromHex(transfer[3]!, 'auditor delta')); const cumulativeValues = await Promise.all((input.loan.cumulativeRepaidCiphertexts || []).map((value, index) => current.proofs.combine('add', ciphertextFromHex(value, `cumulative repaid ${index}`), ciphertextFromHex(owedDelta[index]!, `owed delta ${index}`)))); return { ...proof, operationArgs: { borrower_spending_ciphertext: ciphertextHex(asCiphertext(fields.borrower_spending_after)), borrower_issuer_ciphertext: ciphertextHex(borrowerIssuer), borrower_auditor_ciphertext: ciphertextHex(borrowerAuditor), broker_inbox_ciphertext: transfer[1], broker_issuer_ciphertext: ciphertextHex(brokerIssuer), broker_auditor_ciphertext: ciphertextHex(brokerAuditor), amount_owed_ciphertexts: owedAfter, principal_remaining_ciphertexts: principalAfter, cumulative_repaid_ciphertexts: cumulativeValues.map(ciphertextHex), broker_active_principal_ciphertext: rawCiphertext(brokerRaw.active_principal_ciphertext, 'active principal'), broker_impaired_principal_ciphertext: rawCiphertext(brokerRaw.impaired_principal_ciphertext, 'impaired principal'), transfer_views: transfer, commitment: commitmentHex(asCommitment(fields.principal_delta_commitment)) } }
}
async function settlement(current: WorkerState, input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> {
  if (current.ledger) return preparedLedger(current, await current.ledger.prepareSettlement(input.broker.brokerId, input.amount))
  if (current.core) throw new Error('Broker settlement requires the configured finalized Core wallet')
  const asset = await readAsset(current); const brokerRaw = await readBroker(current, input.broker.brokerId); const brokerReference = resolveKey(current, 'broker', input.broker.brokerId, input.broker.privateBalanceKeyId); const brokerKey = rawKey(brokerRaw); const spending = viewCiphertext(brokerRaw.spending_ciphertext, 'broker spending'); const balance = spendingState(brokerReference, spending, input.expectedSpendingVersion, await decryptCiphertext(current, brokerReference, spending)); if (await decryptCiphertext(current, brokerReference, viewCiphertext(brokerRaw.inbox_ciphertext, 'broker inbox')) !== '0') throw new Error('Merge the broker inbox before settling private funds'); const proofContext = await context(current, { operation: 'settle', brokerId: input.broker.brokerId, amount: input.amount }); const operation = await current.proofs.conversion(proofContext.operationContext, balance, input.amount, [brokerKey, publicKeyFromRaw(asset.issuer_key.public_key), publicKeyFromRaw(asset.token_auditor_key.public_key)], 'Debit'); const proof = await prepared(current, operation); const fields = statementFields(proof, 'PublicConversion'); const views = viewsHex(fields.views); const issuer = await current.proofs.combine('sub', viewCiphertext(brokerRaw.issuer_balance_ciphertext, 'broker issuer balance'), ciphertextFromHex(views[1]!, 'issuer delta')); const auditor = await current.proofs.combine('sub', viewCiphertext(brokerRaw.auditor_balance_ciphertext, 'auditor delta'), ciphertextFromHex(views[2]!, 'auditor delta')); return { ...proof, operationArgs: { broker_spending_ciphertext: ciphertextHex(asCiphertext(fields.spending_after)), broker_issuer_ciphertext: ciphertextHex(issuer), broker_auditor_ciphertext: ciphertextHex(auditor), settlement_views: views, broker_spending_commitment: input.broker.spendingCommitment, broker_inbox_commitment: input.broker.inboxCommitment } }
}
async function reconciliation(current: WorkerState, input: { broker: BrokerSummary; expectedBookVersion: string; checkpointId?: string }): Promise<PreparedProof> {
  if (!current.ledger || !input.checkpointId) throw new Error('A finalized checkpoint is required before preparing reconciliation')
  return preparedLedger(current, await current.ledger.prepareReconciliation(input.broker.brokerId, input.checkpointId))
}
type RecoveryPairHex = readonly [string, string]

function recoveryPairFromHex(value: unknown, name: string): RecoveryPairHex {
  if (!Array.isArray(value) || value.length !== 2 || value.some((item) => typeof item !== 'string' || !/^(?:[a-f\d]{2})+$/i.test(item))) throw new Error(`${name} is not a canonical recovery pair`)
  return [value[0]!.toLowerCase(), value[1]!.toLowerCase()]
}

function recoveryPairsFromHex(value: unknown, name: string, expected: number): RecoveryPairHex[] {
  if (!Array.isArray(value) || value.length !== expected) throw new Error(`${name} must contain ${expected} recovery pairs`)
  return value.map((pair, index) => recoveryPairFromHex(pair, `${name}[${index}]`))
}

function equalRecoveryPairs(left: RecoveryPairHex[], right: RecoveryPairHex[], name: string): void {
  if (left.length !== right.length || left.some((pair, index) => pair[0] !== right[index]![0] || pair[1] !== right[index]![1])) throw new Error(`${name} does not match the encrypted proposal envelope`)
}

function envelopeCiphertexts(value: unknown, name: string, expected: string[]): void {
  if (!Array.isArray(value) || value.length !== expected.length) throw new Error(`${name} ciphertext views do not match the finalized proposal`)
  value.forEach((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`${name}[${index}] is not an encrypted reader view`)
    const ciphertext = (item as Record<string, unknown>).ciphertext
    if (ciphertextHex(asCiphertext(ciphertext, `${name}[${index}]`)).toLowerCase() !== expected[index]!.toLowerCase()) throw new Error(`${name} ciphertexts do not match the finalized proposal`)
  })
}

function envelopeCommitment(value: unknown, expected: string, name: string): void {
  const actual = asCommitment(value)
  const authoritative = asCommitment(fromJsonHex(expected, name))
  if (actual.point.toLowerCase() !== authoritative.point.toLowerCase()) throw new Error(`${name} does not match the finalized proposal`)
}

async function decryptAgreement(current: WorkerState, proposal: ProposalSummary): Promise<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string }> {
  if (!current.ledger) throw new Error('Agreement review requires the configured finalized Core wallet')
  const subject = requireSubject(current)
  if (proposal.borrowerId !== subject) throw new Error('Only the registered borrower key can decrypt this agreement')
  const reference = resolveKey(current, 'holder', subject, proposal.borrowerKeyId || proposal.encryptionKeyId)
  const principal = proposal.encryptedPrincipal || []
  const owed = proposal.encryptedOwed || []
  const payment = proposal.encryptedPayment || []
  if (principal.length !== 5 || owed.length !== 3 || payment.length !== 3 || !proposal.principalCommitment || !proposal.owedCommitment || !proposal.paymentCommitment) throw new Error('Finalized proposal does not contain the complete encrypted agreement')
  if (!proposal.transferRecovery || !proposal.owedRecovery || !proposal.paymentRecovery) throw new Error('The encrypted proposal package does not contain recovery ciphertexts')
  const envelope = fromJsonHex(proposal.encryptedAgreement, 'encrypted agreement')
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('The encrypted agreement envelope is invalid')
  const root = envelope as Record<string, unknown>
  if (root.version !== 1 || !root.recovery || typeof root.recovery !== 'object' || Array.isArray(root.recovery)) throw new Error('The encrypted agreement envelope version is unsupported')
  envelopeCiphertexts(root.principal, 'Principal', principal)
  envelopeCiphertexts(root.owed, 'Initial owed', owed)
  envelopeCiphertexts(root.payment, 'Periodic payment', payment)
  envelopeCommitment(root.principalCommitment, proposal.principalCommitment, 'Principal commitment')
  envelopeCommitment(root.owedCommitment, proposal.owedCommitment, 'Initial owed commitment')
  envelopeCommitment(root.paymentCommitment, proposal.paymentCommitment, 'Periodic payment commitment')
  const recovery = root.recovery as Record<string, unknown>
  const transferRecovery = recoveryPairsFromHex(recovery.principal, 'Principal recovery', 5)
  const owedRecovery = recoveryPairsFromHex(recovery.owed, 'Initial owed recovery', 3)
  const paymentRecovery = recoveryPairsFromHex(recovery.payment, 'Periodic payment recovery', 3)
  equalRecoveryPairs(transferRecovery, proposal.transferRecovery, 'Principal recovery')
  equalRecoveryPairs(owedRecovery, proposal.owedRecovery, 'Initial owed recovery')
  equalRecoveryPairs(paymentRecovery, proposal.paymentRecovery, 'Periodic payment recovery')
  const amount = async (ciphertext: string, pair: RecoveryPairHex, name: string): Promise<string> => {
    const recovered = await current.recovery.amount({ recovery: { low_limb: ciphertextFromHex(pair[0], `${name} low limb`), high_limb: ciphertextFromHex(pair[1], `${name} high limb`) } }, reference)
    await current.recovery.verify(reference, ciphertextFromHex(ciphertext, name), recovered)
    return recovered.toString()
  }
  return {
    fields: [
      { label: 'Principal', value: await amount(principal[1]!, transferRecovery[1]!, 'Principal'), unit: 'base units' },
      { label: 'Initial amount owed', value: await amount(owed[0]!, owedRecovery[0]!, 'Initial amount owed'), unit: 'base units' },
      { label: 'Periodic payment', value: await amount(payment[0]!, paymentRecovery[0]!, 'Periodic payment'), unit: 'base units' },
    ],
    digest: proposal.termsDigest,
  }
}
async function decryptBalance(current: WorkerState, view: PrivateAccountView): Promise<string> {
  if (!current.ledger) throw new Error('Private balance review requires the configured finalized Core wallet')
  const subject = requireSubject(current)
  if (subject !== view.accountId) throw new Error('The connected account does not own this encrypted balance')
  const recovered = await current.ledger.holder(subject)
  if (recovered.record.key_id !== view.encryptionKeyId || recovered.record.spending_version !== view.spendingVersion) throw new Error('The private balance view is stale; refresh finalized Core state and try again')
  return recovered.spending
}
async function inspectBalance(current: WorkerState, view: PrivateAccountView): Promise<{ spending: string; inbox: string; spendingVersion: string }> {
  if (!current.ledger) throw new Error('Private balance inspection requires the configured finalized Core wallet')
  const subject = requireSubject(current)
  if (subject !== view.accountId) throw new Error('The connected account does not own this encrypted balance')
  const recovered = await current.ledger.holder(subject)
  if (recovered.record.key_id !== view.encryptionKeyId || recovered.record.spending_version !== view.spendingVersion) throw new Error('The private balance view is stale; refresh finalized Core state and try again')
  return { spending: recovered.spending, inbox: recovered.inbox, spendingVersion: recovered.record.spending_version }
}
type TokenAuditReaderRole = 'issuer' | 'token_auditor'
type TokenAuditLedger = {
  auditBalance: (kind: 'holder' | 'broker', subjectId: string, readerRole: TokenAuditReaderRole) => Promise<{ mirror: string }>
}

async function decryptTokenAudit(current: WorkerState, bundle: AuditCiphertextBundle): Promise<DecryptedAuditView> {
  if (!current.ledger) throw new Error('Token audit recovery requires the configured finalized Core wallet')
  if (bundle.subjectKind !== 'holder' && bundle.subjectKind !== 'broker') throw new Error('Token audit subject scope is incomplete')
  if (bundle.readerRole !== 'issuer' && bundle.readerRole !== 'token_auditor') throw new Error('Token audit reader scope is incomplete')
  const ledger = current.ledger as unknown as TokenAuditLedger
  if (typeof ledger.auditBalance !== 'function') throw new Error('This wallet runtime does not support finalized token-audit recovery')
  const recovered = await ledger.auditBalance(bundle.subjectKind, bundle.subjectId, bundle.readerRole)
  if (!/^(0|[1-9]\d*)$/.test(recovered.mirror)) throw new Error('Finalized token-audit recovery returned an invalid mirror amount')
  const label = bundle.readerRole === 'issuer' ? 'Issuer balance mirror' : 'Token-auditor balance mirror'
  const fields = [{ label, value: recovered.mirror, unit: 'base units' }]
  return { scope: bundle.scope, subjectId: bundle.subjectId, fields, sourceDigest: await digestHex(JSON.stringify(bundle)), decryptedAt: Date.now() }
}

async function decryptAudit(current: WorkerState, bundle: AuditCiphertextBundle): Promise<DecryptedAuditView> {
  if (bundle.scope === 'loan' && current.ledger) {
    const reference = resolveLoanAuditorKey(current, bundle.subjectId, bundle.auditorKeyId, bundle.auditorPublicKey)
    const recovered = await current.ledger.loan(bundle.subjectId, reference)
    const fields = [
      { label: 'Principal', value: recovered.amounts.principal, unit: 'base units' },
      { label: 'Initial amount owed', value: recovered.amounts.initialOwed, unit: 'base units' },
      { label: 'Amount owed', value: recovered.amounts.owed, unit: 'base units' },
      { label: 'Periodic payment', value: recovered.amounts.periodic, unit: 'base units' },
      { label: 'Principal remaining', value: recovered.amounts.principalRemaining, unit: 'base units' },
      { label: 'Cumulative repaid', value: recovered.amounts.cumulativePaid, unit: 'base units' },
    ]
    return { scope: bundle.scope, subjectId: bundle.subjectId, fields, sourceDigest: await digestHex(JSON.stringify(bundle)), decryptedAt: Date.now() }
  }
  if (bundle.scope === 'token') return decryptTokenAudit(current, bundle)
  throw new Error('This audit scope requires a finalized, typed recovery path')
}

function backupDraft(value: unknown): value is PrivateAgreementDraft {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const draft = value as Record<string, unknown>
  const terms = draft.terms
  const amount = (entry: unknown): boolean => Boolean(entry && typeof entry === 'object' && Array.isArray((entry as Record<string, unknown>).views) && Array.isArray((entry as Record<string, unknown>).recovery) && Array.isArray((entry as Record<string, unknown>).randomness) && Array.isArray((entry as Record<string, unknown>).recovery_randomness))
  return Boolean(terms && typeof terms === 'object' && amount(draft.principal) && amount(draft.owed) && amount(draft.payment) && draft.principalCommitment && draft.owedCommitment && draft.paymentCommitment)
}

async function backupMaterial(current: WorkerState): Promise<BackupMaterial> {
  const authKeys = await Promise.all(Array.from(current.authKeys.entries(), async ([keyId, value]) => ({ keyId, privateKey: toHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', value.privateKey))), publicKey: value.publicKey })))
  return {
    ...current.keyring.exportMaterial(),
    drafts: Array.from(current.drafts.entries()),
    authKeys,
  }
}

async function restoreBackupMaterial(current: WorkerState, value: BackupMaterial): Promise<void> {
  if (value.drafts !== undefined) {
    if (!Array.isArray(value.drafts) || value.drafts.length > 1024 || value.drafts.some((entry) => !Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || !backupDraft(entry[1]))) throw new Error('Invalid encrypted agreement draft backup')
  }
  const authKeys = value.authKeys || []
  if (!Array.isArray(authKeys) || authKeys.length > 1024 || authKeys.some((entry) => !entry || typeof entry !== 'object' || !/^(0|[1-9]\d*)$/.test(entry.keyId) || !/^[a-f\d]+$/i.test(entry.privateKey) || entry.privateKey.length % 2 !== 0 || !/^[a-f\d]{64}$/i.test(entry.publicKey))) throw new Error('Invalid authorization-key backup')
  const stagedAuthKeys = new Map(current.authKeys)
  for (const entry of authKeys) {
    const privateKey = await crypto.subtle.importKey('pkcs8', Uint8Array.from(hexBytes(entry.privateKey)), { name: 'Ed25519' }, true, ['sign'])
    const publicKey = await crypto.subtle.importKey('raw', Uint8Array.from(hexBytes(entry.publicKey)), { name: 'Ed25519' }, false, ['verify'])
    const probe = new TextEncoder().encode(`confidential-lending-auth:${entry.keyId}`)
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, probe)
    if (!await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, probe)) throw new Error('Authorization-key backup does not match its public key')
    const existing = stagedAuthKeys.get(entry.keyId)
    if (existing && existing.publicKey !== entry.publicKey) throw new Error('Backup would replace a different authorization key')
    stagedAuthKeys.set(entry.keyId, { privateKey, publicKey: entry.publicKey.toLowerCase() })
  }
  await current.keyring.importMaterial(value)
  current.drafts.clear()
  for (const [id, draft] of value.drafts || []) current.drafts.set(id, draft)
  current.authKeys.clear()
  for (const [id, key] of stagedAuthKeys) current.authKeys.set(id, key)
}

async function initialize(configuration: WorkerConfiguration): Promise<void> {
  if (state?.ready) return; if (!configuration.manifestUrl) throw new Error('Crypto manifest URL is not configured'); const manifestUrl = new URL(configuration.manifestUrl, self.location.href); const response = await fetch(manifestUrl.href, { credentials: 'omit', cache: 'no-store', redirect: 'error' }); if (!response.ok) throw new Error(`Crypto manifest returned HTTP ${response.status}`); const manifest = await response.json() as unknown; if (!manifest || typeof manifest !== 'object') throw new Error('Crypto manifest is invalid'); const baseUrl = configuration.baseUrl ? new URL(configuration.baseUrl, manifestUrl.href).href : new URL('.', manifestUrl.href).href; const runtime = new CryptoRuntime({ baseUrl, manifest: manifest as never, expected: { profileHash: configuration.expectedProfileHash, manifestHash: configuration.expectedManifestHash || '', networkId: configuration.networkId, coreAccountId: configuration.coreAccountId, funded: configuration.funded } }); await runtime.initialize(); const executor = { execute: <T>(method: string, params: unknown, options?: { artifactName?: string; signal?: AbortSignal }) => runtime.execute(method, params, options?.artifactName) as Promise<T> }; const keyring = new Keyring({ networkId: configuration.networkId, coreAccountId: configuration.coreAccountId, assetId: configuration.assetId, profileHash: configuration.expectedProfileHash }, executor); const proofs = new ProofBuilder(executor, keyring); const recovery = new HistoryRecovery(executor, keyring); let core: CoreWallet | undefined; let ledger: LedgerWallet | undefined; if (configuration.rpcUrl) { const rpc = new NearRpc(configuration.rpcUrl, { allowInsecureLocalhost: configuration.allowInsecureLocalhost }); core = CoreWallet.fromNearRpc(rpc, { networkId: configuration.networkId, coreAccountId: configuration.coreAccountId, assetId: configuration.assetId, profileHash: configuration.expectedProfileHash, manifestHash: configuration.expectedManifestHash }, { crypto: executor, keys: keyring, proofs, recovery }); ledger = new LedgerWallet(rpc, keyring, executor, configuration.expectedManifestHash || '') } state = { configuration, runtime, keyring, proofs, recovery, core, ledger, drafts: new Map(), authKeys: new Map(), subjectId: configuration.subjectId, ready: true }
}
async function handle(request: WorkerRequest): Promise<unknown> {
  if (request.method === 'initialize') { const configuration = request.payload as WorkerConfiguration; initializing ||= initialize(configuration); await initializing; return { available: true, profileHash: configuration.expectedProfileHash, artifactHash: configuration.expectedManifestHash, wasmVersion: 'wasm-bindings-v1', message: 'Secure account protection is ready.' } }
  if (request.method === 'status') { if (!state?.ready) throw new Error('Secure account protection is not initialized'); return { available: true, profileHash: state.configuration.expectedProfileHash, artifactHash: state.configuration.expectedManifestHash, wasmVersion: 'wasm-bindings-v1', walletKeyCount: state.keyring.exportMaterial().keys.length, draftCount: state.drafts.size, message: 'Secure account protection is ready.' } }
  if (request.method === 'set_subject') {
    const current = requireState()
    const nextSubject = request.payload === undefined ? undefined : text(request.payload, 'subject account')
    if (current.subjectId !== nextSubject) {
      // Account changes must not retain a previous holder/broker key set or
      // agreement randomness.  The user can export an encrypted backup before
      // switching; the worker itself never carries secrets across identities.
      current.keyring.clear()
      current.drafts.clear()
      current.authKeys.clear()
    }
    current.subjectId = nextSubject
    return undefined
  }
  const current = requireState(); switch (request.method) {
    case 'export_wallet_material': return backupMaterial(current)
    case 'import_wallet_material': await restoreBackupMaterial(current, request.payload as BackupMaterial); return undefined
    case 'create_key_registration': return makeKeyRegistration(current)
    case 'create_authorization_key_registration': return makeAuthorizationRegistration(current)
    case 'prepare_agreement': return agreement(current, request.payload as Parameters<typeof agreement>[1])
    case 'prepare_confidential_transfer': return confidentialTransfer(current, request.payload as Parameters<typeof confidentialTransfer>[1])
    case 'prepare_merge': return merge(current, request.payload as Parameters<typeof merge>[1])
    case 'prepare_draw': return draw(current, request.payload as Parameters<typeof draw>[1])
    case 'prepare_broker_origination': return brokerOrigination(current, request.payload as Parameters<typeof brokerOrigination>[1])
    case 'prepare_shield': return shield(current, request.payload as Parameters<typeof shield>[1])
    case 'prepare_unshield': return unshield(current, request.payload as Parameters<typeof unshield>[1])
    case 'prepare_broker_closure': return brokerClosure(current, request.payload as Parameters<typeof brokerClosure>[1])
    case 'prepare_repayment': return repayment(current, request.payload as Parameters<typeof repayment>[1])
    case 'prepare_settlement': return settlement(current, request.payload as Parameters<typeof settlement>[1])
    case 'authorize_agreement': return { authorizationSignature: '' }
    case 'decrypt_agreement': return decryptAgreement(current, request.payload as ProposalSummary)
    case 'decrypt_private_balance': return decryptBalance(current, request.payload as PrivateAccountView)
    case 'inspect_private_balance': return inspectBalance(current, request.payload as PrivateAccountView)
    case 'decrypt_audit': return decryptAudit(current, request.payload as AuditCiphertextBundle)
    case 'prepare_broker_key_registration': return brokerKeyRegistration(current, request.payload as Parameters<typeof brokerKeyRegistration>[1])
    case 'prepare_loan_management': return loanManagement(current, request.payload as Parameters<typeof loanManagement>[1])
    case 'prepare_reconciliation': return reconciliation(current, request.payload as Parameters<typeof reconciliation>[1])
    default: throw new Error('Unknown confidential crypto operation')
  }
}
self.onmessage = (event: MessageEvent<WorkerRequest>) => { const request = event.data; void handle(request).then(value => reply({ id: request.id, ok: true, value })).catch(error => reply({ id: request.id, ok: false, category: 'CRYPTO_OPERATION_FAILED', message: failureMessage(error) })) }

export {}
