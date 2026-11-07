import { useCallback, useRef, useState } from 'react'
import { TransactionFailure, TransactionPendingError } from '@confidential-lending/client'
import { ProtocolError, type ActionReceipt, type ProtocolErrorShape } from './types'

export type ActionPhase = 'idle' | 'preparing' | 'awaiting_wallet' | 'submitted' | 'pending' | 'succeeded' | 'failed'

export interface PendingTransaction {
  /** Public NEAR transaction identity. No receipt logs or call arguments are retained. */
  transactionHash?: string
  signerId?: string
}

export type PendingStatusReader = (pending: PendingTransaction) => Promise<ActionReceipt>

export interface ActionState {
  phase: ActionPhase
  label?: string
  receipt?: ActionReceipt
  error?: ProtocolError
  pending?: PendingTransaction
  pendingStatusChecking?: boolean
  /** Read-only resolver. It never submits or rebroadcasts a transaction. */
  resolvePending?: () => Promise<void>
}

let pendingStatusReader: PendingStatusReader | undefined

/** Install the finalized status read used by real RPC-backed actions. */
export function installPendingStatusReader(reader?: PendingStatusReader): void {
  pendingStatusReader = reader
}

const CORE_ERROR_MESSAGES: Partial<Record<ProtocolErrorShape['category'], string>> = {
  INVALID_ENCODING: 'Core rejected the request encoding.',
  INVALID_AMOUNT: 'Core rejected the amount.',
  WRONG_ASSET: 'The action used the wrong configured asset.',
  UNAUTHORIZED: 'The connected account is not authorized for this action.',
  ACCOUNT_FROZEN: 'This account or asset is frozen.',
  NOT_REGISTERED: 'Required on-chain registration is missing.',
  WRONG_PHASE: 'The vault is not in a phase that allows this action.',
  EXPIRED: 'This proposal or operation has expired.',
  STALE_STATE: 'Finalized protocol state changed before this action. Refresh and prepare it again.',
  BAD_PROOF: 'The confidential proof was rejected. Prepare a fresh proof from finalized state.',
  INSUFFICIENT_PUBLIC_FUNDS: 'Public funds or liquidity are insufficient.',
  INSUFFICIENT_PRIVATE_FUNDS: 'Private spending funds are insufficient.',
  DEBT_LIMIT: 'The broker debt limit would be exceeded.',
  ACCOUNTING_PENDING: 'Required accounting is still pending.',
  TOO_SOON: 'The action is not yet eligible.',
  LOAN_CLOSED: 'The loan is already closed.',
  HAS_OBLIGATIONS: 'Outstanding obligations prevent this action.',
  SLIPPAGE: 'The requested amount exceeds the allowed slippage.',
  OPERATION_PENDING: 'The operation is already pending.',
  UNSUPPORTED_PROFILE: 'This deployment does not support the requested profile.',
  REPLAY: 'This identifier has already been consumed, revoked, or replayed.',
  NOT_FOUND: 'The requested protocol record was not found.',
  STORAGE: 'This account needs more NEAR storage before the action can continue.',
  GAS_EXCEEDED: 'The transaction ran out of gas before Core completed. No state change was confirmed.',
}

const RETRYABLE_CATEGORIES = new Set<ProtocolErrorShape['category']>(['STALE_STATE', 'GAS_EXCEEDED'])
const SAFE_TRANSACTION_HASH = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/
const SAFE_ACCOUNT_ID = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function publicHash(value: unknown): string | undefined {
  return typeof value === 'string' && SAFE_TRANSACTION_HASH.test(value) ? value : undefined
}

function publicSigner(value: unknown): string | undefined {
  return typeof value === 'string' && value.length <= 64 && SAFE_ACCOUNT_ID.test(value) ? value : undefined
}

function metadataFrom(value: unknown): PendingTransaction {
  if (!isRecord(value)) return {}
  const outcome = isRecord(value.outcome) ? value.outcome : value
  const transaction = isRecord(outcome.transaction) ? outcome.transaction : outcome
  const transactionHash = publicHash(transaction.transactionHash ?? transaction.hash)
  const signerId = publicSigner(transaction.signerId ?? transaction.signer_id)
  return {
    ...(transactionHash ? { transactionHash } : {}),
    ...(signerId ? { signerId } : {}),
  }
}

function metadataFromReceipt(receipt: ActionReceipt): PendingTransaction {
  return metadataFrom({ transactionHash: receipt.transactionHash, signerId: receipt.signerId })
}

function hasPendingIdentity(value: PendingTransaction | undefined): value is Required<PendingTransaction> {
  return Boolean(value?.transactionHash && value.signerId)
}

function executionErrorFromFailure(error: unknown): string | undefined {
  if (!isRecord(error) || !isRecord(error.outcome)) return undefined
  const outcome = error.outcome
  if (!isRecord(outcome.status) || !('Failure' in outcome.status)) return undefined
  const failure = outcome.status.Failure
  if (!isRecord(failure) || !isRecord(failure.ActionError)) return undefined
  const actionError = failure.ActionError
  if (!isRecord(actionError.kind) || !isRecord(actionError.kind.FunctionCallError)) return undefined
  const functionCallError = actionError.kind.FunctionCallError
  return typeof functionCallError.ExecutionError === 'string' ? functionCallError.ExecutionError : undefined
}

function categoryFromExecutionError(value: string | undefined): ProtocolErrorShape['category'] {
  if (!value) return 'UNKNOWN'
  const normalized = value.toUpperCase()
  if (normalized.includes('EXCEEDED THE PREPAID GAS') || normalized.includes('GAS_EXCEEDED')) return 'GAS_EXCEEDED'
  const categories: ProtocolErrorShape['category'][] = [
    'INVALID_ENCODING',
    'INVALID_AMOUNT',
    'WRONG_ASSET',
    'UNAUTHORIZED',
    'ACCOUNT_FROZEN',
    'NOT_REGISTERED',
    'WRONG_PHASE',
    'EXPIRED',
    'STALE_STATE',
    'BAD_PROOF',
    'INSUFFICIENT_PUBLIC_FUNDS',
    'INSUFFICIENT_PRIVATE_FUNDS',
    'DEBT_LIMIT',
    'ACCOUNTING_PENDING',
    'TOO_SOON',
    'LOAN_CLOSED',
    'HAS_OBLIGATIONS',
    'SLIPPAGE',
    'OPERATION_PENDING',
    'UNSUPPORTED_PROFILE',
    'REPLAY',
    'NOT_FOUND',
    'STORAGE',
  ]
  return categories.find((category) => normalized.includes(category)) || 'UNKNOWN'
}

export function isClientTransactionError(error: unknown): boolean {
  if (error instanceof TransactionFailure || error instanceof TransactionPendingError) return true
  if (!isRecord(error)) return false
  return error.name === 'TransactionFailure' || error.name === 'TransactionPendingError' || error.name === 'PendingTransaction'
}

function isPendingTransactionError(error: unknown): boolean {
  if (error instanceof TransactionPendingError) return true
  return isRecord(error) && (error.name === 'TransactionPendingError' || error.name === 'PendingTransaction')
}

function isTransactionFailure(error: unknown): boolean {
  if (error instanceof TransactionFailure) return true
  return isRecord(error) && error.name === 'TransactionFailure'
}

function transactionError(error: unknown): ProtocolError {
  const metadata = metadataFrom(error)
  if (isPendingTransactionError(error)) {
    return new ProtocolError({
      category: 'OPERATION_PENDING',
      message: 'The transaction is still pending finality. Check its status before retrying.',
      retryable: false,
      ...metadata,
    })
  }
  const category = categoryFromExecutionError(isTransactionFailure(error) ? executionErrorFromFailure(error) : undefined)
  const message = CORE_ERROR_MESSAGES[category] || 'The transaction failed on-chain. No state change was confirmed.'
  return new ProtocolError({
    category,
    message,
    ...(RETRYABLE_CATEGORIES.has(category) ? { retryable: true } : {}),
    ...metadata,
  })
}

export function toProtocolError(error: unknown): ProtocolError {
  if (error instanceof ProtocolError) return error
  if (isClientTransactionError(error)) return transactionError(error)
  if (error instanceof Error) {
    return new ProtocolError({ category: 'UNKNOWN', message: error.message || 'The operation failed.' })
  }
  return new ProtocolError({ category: 'UNKNOWN', message: 'The operation failed.' })
}

export function requireFinalized(receipt: ActionReceipt, label: string): ActionReceipt {
  if (receipt.status === 'succeeded' && receipt.finalized) return receipt
  const metadata = metadataFromReceipt(receipt)
  if (receipt.status === 'failed') throw new ProtocolError({ category: 'UNKNOWN', message: `${label} failed. No state was changed.`, ...metadata })
  throw new ProtocolError({ category: 'OPERATION_PENDING', message: `${label} remains unresolved. Wait for finality before retrying.`, retryable: false, ...metadata })
}

/** Marker emitted by the finalized LedgerWallet when spending is short but
 * spending plus the recovered inbox can satisfy the requested debit. */
export function isInboxMergeRequired(error: unknown): boolean {
  return error instanceof Error && /^INBOX_MERGE_REQUIRED:(?:[a-z-]+)$/.test(error.message)
}

export function useAction() {
  const initialState: ActionState = { phase: 'idle' }
  const [state, setState] = useState<ActionState>(initialState)
  const stateRef = useRef<ActionState>(initialState)
  const commit = useCallback((next: ActionState) => {
    stateRef.current = next
    setState(next)
  }, [])

  const resolvePending = useCallback(async () => {
    const current = stateRef.current
    if (current.phase !== 'pending' || !hasPendingIdentity(current.pending) || current.pendingStatusChecking) return
    const pending = current.pending
    const reader = pendingStatusReader
    if (!reader) {
      commit({ ...current, error: new ProtocolError({ category: 'ADAPTER_UNAVAILABLE', message: 'The read-only transaction status check is not connected. Keep this operation pending and reconnect before retrying.', retryable: true }), pendingStatusChecking: false, resolvePending })
      return
    }
    commit({ ...current, pendingStatusChecking: true })
    try {
      const receipt = await reader(pending)
      if (receipt.status === 'succeeded' && receipt.finalized) {
        commit({ phase: 'succeeded', label: current.label, receipt })
        return
      }
      if (receipt.status === 'failed') {
        commit({
          phase: 'failed',
          label: current.label,
          receipt,
          error: new ProtocolError({ category: 'UNKNOWN', message: 'The transaction finalized with failure. No state change was confirmed.', ...metadataFromReceipt(receipt) }),
        })
        return
      }
      commit({ ...current, receipt, pendingStatusChecking: false, resolvePending })
    } catch (error) {
      // A failed status read does not prove that the transaction failed. Keep
      // the action locked and make the same read-only check available again.
      commit({ ...current, error: toProtocolError(error), pendingStatusChecking: false, resolvePending })
    }
  }, [commit])

  const makePendingState = useCallback((label: string, receipt?: ActionReceipt, error?: ProtocolError): ActionState => {
    const pending = receipt ? metadataFromReceipt(receipt) : error ? metadataFrom(error.details) : {}
    return {
      phase: 'pending',
      label,
      ...(receipt ? { receipt } : {}),
      ...(error ? { error } : {}),
      ...(hasPendingIdentity(pending) ? { pending, resolvePending } : {}),
    }
  }, [resolvePending])

  const run = useCallback(async <T extends ActionReceipt>(label: string, action: () => Promise<T>): Promise<T | undefined> => {
    // An unresolved spend must be resolved by a read-only status check before
    // another action can be prepared; this prevents duplicate submissions.
    if (stateRef.current.phase === 'pending') return undefined
    commit({ phase: 'preparing', label })
    try {
      commit({ phase: 'awaiting_wallet', label })
      const receipt = await action()
      if (receipt.status === 'succeeded' && receipt.finalized) commit({ phase: 'succeeded', label, receipt })
      else if (receipt.status === 'failed') commit({ phase: 'failed', label, receipt, error: new ProtocolError({ category: 'UNKNOWN', message: `${label} failed. No state was changed.`, ...metadataFromReceipt(receipt) }) })
      else commit(makePendingState(label, receipt))
      return receipt
    } catch (error) {
      const protocolError = toProtocolError(error)
      if (protocolError.details.category === 'OPERATION_PENDING') commit(makePendingState(label, undefined, protocolError))
      else commit({ phase: 'failed', label, error: protocolError })
      return undefined
    }
  }, [commit, makePendingState])

  const reset = useCallback(() => {
    if (stateRef.current.phase === 'pending') return
    commit({ phase: 'idle' })
  }, [commit])

  return { state, run, reset }
}
