/* @vitest-environment jsdom */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AppAdapters } from '../src/lib/types'

vi.mock('../src/lib/adapters', () => ({ createBrowserAdapters: vi.fn() }))
vi.mock('../src/components/Layout', () => ({ Layout: ({ children }: { children: React.ReactNode }) => children, getRoleFromPath: () => undefined }))
vi.mock('../src/pages/LenderPage', () => ({ LenderPage: () => { const context = useAppContext(); return <div>{context.accountId}:{context.cryptoStatus?.message}</div> } }))
vi.mock('../src/pages/BrokerPage', () => ({ BrokerPage: () => null }))
vi.mock('../src/pages/BorrowerPage', () => ({ BorrowerPage: () => null }))
vi.mock('../src/pages/AuditorPage', () => ({ AuditorPage: () => null }))
vi.mock('../src/pages/SecurityPage', () => ({ SecurityPage: () => null }))
import { App, useAppContext } from '../src/App'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

describe('wallet account session isolation', () => {
  let root: Root | undefined
  let container: HTMLDivElement | undefined
  afterEach(async () => { await act(async () => root?.unmount()); container?.remove() })

  it('clears the confidential subject on disconnect and ignores a late failed-read status after switching accounts', async () => {
    let rejectDashboard!: (reason: Error) => void
    const dashboard = new Promise((_, reject) => { rejectDashboard = reject })
    let resolveOldStatus!: (value: unknown) => void
    const oldStatus = new Promise((resolve) => { resolveOldStatus = resolve })
    const listeners = new Set<() => void>()
    const notify = () => { for (const listener of listeners) listener() }
    const wallet = { accountId: 'alice.testnet' as string | undefined, status: 'connected', subscribe: (fn: () => void) => { listeners.add(fn); return () => { listeners.delete(fn) } } }
    const setSubject = vi.fn()
    const getStatus = vi.fn().mockResolvedValueOnce({ available: true, message: 'alice' }).mockReturnValueOnce(oldStatus).mockResolvedValue({ available: true, message: 'bob' })
    const adapters = { wallet, crypto: { setSubject, getStatus }, protocol: { config: { coreAccountId: 'core.testnet' }, getDashboard: vi.fn().mockReturnValueOnce(dashboard).mockResolvedValue({}) } } as unknown as AppAdapters
    container = document.createElement('div')
    document.body.append(container)
    root = createRoot(container)
    await act(async () => root!.render(<App adapters={adapters} />))
    await act(async () => rejectDashboard(new Error('read failed')))
    expect(getStatus).toHaveBeenCalledTimes(2)
    await act(async () => { wallet.accountId = 'bob.testnet'; notify() })
    expect(container.textContent).toBe('bob.testnet:bob')
    await act(async () => resolveOldStatus({ available: true, message: 'alice private session' }))
    expect(container.textContent).toBe('bob.testnet:bob')
    await act(async () => { wallet.accountId = undefined; wallet.status = 'disconnected'; notify() })
    expect(setSubject.mock.calls.map(([account]) => account)).toEqual(['alice.testnet', 'bob.testnet', undefined])
    expect(container.textContent).not.toContain('bob')
  })
})
