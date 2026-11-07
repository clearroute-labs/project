/* @vitest-environment jsdom */

import { act } from 'react'
import { createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { installPendingStatusReader, useAction, type ActionState } from '../src/lib/actionState'
import type { ActionReceipt } from '../src/lib/types'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

const transactionHash = 'A'.repeat(44)
const signerId = 'alice.testnet'

function receipt(status: ActionReceipt['status'], finalized: boolean): ActionReceipt {
  return { operationId: transactionHash, transactionHash, signerId, status, finalized }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

type ActionApi = ReturnType<typeof useAction>

describe('useAction pending recovery', () => {
  let root: Root
  let container: HTMLDivElement
  let api: ActionApi

  function Harness() {
    api = useAction()
    return null
  }

  beforeEach(async () => {
    container = document.createElement('div')
    document.body.append(container)
    await act(async () => {
      root = createRoot(container)
      root.render(createElement(Harness))
    })
  })

  afterEach(async () => {
    installPendingStatusReader(undefined)
    await act(async () => root.unmount())
    container.remove()
  })

  async function runPending(): Promise<void> {
    await act(async () => {
      await api.run('Unknown outcome', async () => receipt('pending', false))
    })
    expect(api.state.phase).toBe('pending')
  }

  it('blocks another run and reset while a transaction is unresolved', async () => {
    const secondAction = vi.fn(async () => receipt('succeeded', true))
    await runPending()

    api.reset()
    expect(api.state.phase).toBe('pending')
    await act(async () => {
      await api.run('Do not rebroadcast', secondAction)
    })
    expect(secondAction).not.toHaveBeenCalled()
    expect(api.state.phase).toBe('pending')
  })

  it('resolves a pending transaction successfully, then permits the next action', async () => {
    const reader = vi.fn(async () => receipt('succeeded', true))
    installPendingStatusReader(reader)
    await runPending()

    await act(async () => {
      await api.state.resolvePending?.()
    })
    expect(reader).toHaveBeenCalledWith({ transactionHash, signerId })
    expect(api.state.phase).toBe('succeeded')
    const nextAction = vi.fn(async () => receipt('succeeded', true))
    await act(async () => {
      await api.run('Next action', nextAction)
    })
    expect(nextAction).toHaveBeenCalledOnce()
  })

  it('moves to a finalized failure and permits a later action without rebroadcasting the pending one', async () => {
    installPendingStatusReader(vi.fn(async () => receipt('failed', true)))
    await runPending()

    await act(async () => {
      await api.state.resolvePending?.()
    })
    expect(api.state.phase).toBe('failed')
    expect(api.state.error?.details.message).toContain('finalized with a failure')
    const nextAction = vi.fn(async () => receipt('succeeded', true))
    await act(async () => {
      await api.run('Retry after finalized failure', nextAction)
    })
    expect(nextAction).toHaveBeenCalledOnce()
  })

  it('keeps the action locked when the status read is unavailable or itself fails', async () => {
    await runPending()
    await act(async () => {
      await api.state.resolvePending?.()
    })
    expect(api.state.phase).toBe('pending')
    expect(api.state.error?.details.category).toBe('ADAPTER_UNAVAILABLE')

    installPendingStatusReader(vi.fn(async () => { throw new Error('RPC temporarily unavailable') }))
    await act(async () => {
      await api.state.resolvePending?.()
    })
    expect(api.state.phase).toBe('pending')
    expect(api.state.pendingStatusChecking).toBe(false)
    const nextAction = vi.fn(async () => receipt('succeeded', true))
    await act(async () => {
      await api.run('Still locked', nextAction)
    })
    expect(nextAction).not.toHaveBeenCalled()
  })

  it('blocks concurrent calls while the first action is awaiting the wallet', async () => {
    const first = deferred<ActionReceipt>()
    const firstAction = vi.fn(() => first.promise)
    const secondAction = vi.fn(async () => receipt('succeeded', true))
    let firstRun: Promise<ActionReceipt | undefined>
    await act(async () => {
      firstRun = api.run('First action', firstAction)
    })
    expect(api.state.phase).toBe('awaiting_wallet')

    await act(async () => {
      await api.run('Second action', secondAction)
    })
    expect(secondAction).not.toHaveBeenCalled()
    expect(api.state.label).toBe('First action')

    first.resolve(receipt('succeeded', true))
    await act(async () => {
      await firstRun
    })
    expect(api.state.phase).toBe('succeeded')
  })

  it('exposes only the public transaction identity needed for status recovery', async () => {
    await runPending()
    const state = api.state as ActionState
    expect(state.pending).toEqual({ transactionHash, signerId })
    expect(state.resolvePending).toEqual(expect.any(Function))
  })
})
