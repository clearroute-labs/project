import { describe, expect, it } from 'vitest'
import { TransactionFailure, TransactionPendingError } from '@confidential-lending/client'
import { isClientTransactionError, toProtocolError } from '../src/lib/actionState'
import { ProtocolError } from '../src/lib/types'

const transactionHash = 'A'.repeat(44)
const transaction = { hash: transactionHash, signer_id: 'alice.testnet', receiver_id: 'core.testnet' }
const receipt = { id: 'B'.repeat(44), outcome: { executor_id: 'core.testnet', logs: [], status: {} } }

function failedTransaction(executionError: string): TransactionFailure {
  return new TransactionFailure({
    status: { Failure: { ActionError: { kind: { FunctionCallError: { ExecutionError: executionError } } } } },
    transaction,
    transaction_outcome: receipt,
    receipts_outcome: [],
  } as ConstructorParameters<typeof TransactionFailure>[0])
}

describe('action errors', () => {
  it('preserves protocol categories without exposing witnesses', () => {
    const error = new ProtocolError({ category: 'BAD_PROOF', message: 'Proof rejected.' })
    expect(toProtocolError(error)).toBe(error)
    expect(toProtocolError(new Error('network down')).details.category).toBe('UNKNOWN')
    expect(toProtocolError('anything').details.message).toBe('The operation failed.')
  })

  it('maps nested Core stale-state failures without exposing the receipt payload', () => {
    const error = failedTransaction('Smart contract panicked: STALE_STATE; witness=private-value')
    const mapped = toProtocolError(error)
    expect(isClientTransactionError(error)).toBe(true)
    expect(mapped.details.category).toBe('STALE_STATE')
    expect(mapped.details.retryable).toBe(true)
    expect(mapped.details.transactionHash).toBe(transactionHash)
    expect(mapped.details.signerId).toBe('alice.testnet')
    expect(mapped.details.message).not.toContain('private-value')
    expect(mapped.details.message).not.toContain('STALE_STATE')
  })

  it('maps the known gas failure to a safe retryable category', () => {
    const mapped = toProtocolError(failedTransaction('Exceeded the prepaid gas.'))
    expect(mapped.details.category).toBe('GAS_EXCEEDED')
    expect(mapped.details.retryable).toBe(true)
    expect(mapped.details.message).toContain('ran out of gas')
  })

  it('redacts an unknown on-chain failure instead of echoing arbitrary receipt data', () => {
    const mapped = toProtocolError(failedTransaction('private witness plaintext: do-not-display'))
    expect(mapped.details.category).toBe('UNKNOWN')
    expect(mapped.details.message).toBe('The transaction failed on-chain. No state change was confirmed.')
    expect(mapped.details.message).not.toContain('do-not-display')
  })

  it('preserves the public identity of a transaction that is still pending', () => {
    const error = new TransactionPendingError(transactionHash, 'alice.testnet')
    const mapped = toProtocolError(error)
    expect(isClientTransactionError(error)).toBe(true)
    expect(mapped.details.category).toBe('OPERATION_PENDING')
    expect(mapped.details.retryable).toBe(false)
    expect(mapped.details.transactionHash).toBe(transactionHash)
    expect(mapped.details.signerId).toBe('alice.testnet')
    expect(mapped.details.message).not.toContain(transactionHash)
  })
})
