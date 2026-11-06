import { useCallback, useState } from 'react'
import { ProtocolError, type ActionReceipt } from './types'

export type ActionPhase = 'idle' | 'preparing' | 'awaiting_wallet' | 'submitted' | 'pending' | 'succeeded' | 'failed'

export interface ActionState {
  phase: ActionPhase
  label?: string
  receipt?: ActionReceipt
  error?: ProtocolError
}

export function toProtocolError(error: unknown): ProtocolError {
  if (error instanceof ProtocolError) return error
  if (error instanceof Error) {
    return new ProtocolError({ category: 'UNKNOWN', message: error.message || 'The operation failed.' })
  }
  return new ProtocolError({ category: 'UNKNOWN', message: 'The operation failed.' })
}

export function requireFinalized(receipt: ActionReceipt, label: string): ActionReceipt {
  if (receipt.status === 'succeeded' && receipt.finalized) return receipt
  if (receipt.status === 'failed') throw new ProtocolError({ category: 'UNKNOWN', message: `${label} failed. No state was changed.` })
  throw new ProtocolError({ category: 'OPERATION_PENDING', message: `${label} remains unresolved. Wait for finality before retrying.`, retryable: false })
}

export function useAction() {
  const [state, setState] = useState<ActionState>({ phase: 'idle' })

  const run = useCallback(async <T extends ActionReceipt>(label: string, action: () => Promise<T>): Promise<T | undefined> => {
    setState({ phase: 'preparing', label })
    try {
      setState({ phase: 'awaiting_wallet', label })
      const receipt = await action()
      const phase = receipt.status === 'succeeded' && receipt.finalized ? 'succeeded' : receipt.status === 'failed' ? 'failed' : 'pending'
      setState({ phase, label, receipt })
      return receipt
    } catch (error) {
      const protocolError = toProtocolError(error)
      setState({ phase: 'failed', label, error: protocolError })
      return undefined
    }
  }, [])

  const reset = useCallback(() => setState({ phase: 'idle' }), [])

  return { state, run, reset }
}
