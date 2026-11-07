import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { createRequire } from 'node:module'
import { afterEach, describe, expect, it, vi } from 'vitest'

const executor = readFileSync(createRequire(import.meta.url).resolve('@peerfolio/privy-near-connect/executor'), 'utf8')

function harness() {
  const listeners = new Set<(event: { data: unknown }) => void>()
  const popup = { closed: false, close: vi.fn(), postMessage: vi.fn(), windowIdPromise: Promise.resolve('popup') }
  const storage = { set: vi.fn(), get: vi.fn(), remove: vi.fn() }
  let wallet!: { manifest: object; signIn(params: object): Promise<unknown> }
  runInNewContext(executor, { setTimeout, clearTimeout, setInterval, clearInterval, console, window: {
    selector: { open: () => popup, storage, ready: (value: typeof wallet) => { wallet = value } },
    addEventListener: (_type: string, handler: (event: { data: unknown }) => void) => listeners.add(handler),
    removeEventListener: (_type: string, handler: (event: { data: unknown }) => void) => listeners.delete(handler),
  } })
  wallet.manifest = { metadata: { signPageURL: 'https://app.example/wallet/privy', debug: false } }
  const send = (type: string, extra = {}) => { for (const handler of listeners) handler({ data: { source: 'privy-near-connect', type, ...extra } }) }
  return { wallet, popup, send, storage }
}

describe('pinned Privy executor handshake', () => {
  afterEach(() => vi.useRealTimers())
  it('allows time for login after READY and repeats the unchanged request for wallet binding', async () => {
    vi.useFakeTimers()
    const { wallet, popup, send, storage } = harness()
    const result = wallet.signIn({ network: 'testnet' })
    send('READY')
    const request = popup.postMessage.mock.calls[0][0]
    await vi.advanceTimersByTimeAsync(120_000)
    expect(popup.close).not.toHaveBeenCalled()
    send('READY')
    expect(popup.postMessage.mock.calls[1][0]).toEqual(request)
    send('RESULT', { result: [{ accountId: 'a'.repeat(64) }] })
    await expect(result).resolves.toEqual([{ accountId: 'a'.repeat(64) }])
    expect(storage.set).toHaveBeenCalledWith('privy-near-connect:account-id', 'a'.repeat(64))
  })
  it('rejects a closed login popup and does not record an account', async () => {
    vi.useFakeTimers()
    const { wallet, popup, storage } = harness()
    const result = wallet.signIn({ network: 'testnet' })
    const rejected = expect(result).rejects.toThrow(/window closed/)
    popup.closed = true
    await vi.advanceTimersByTimeAsync(300)
    await rejected
    expect(storage.set).not.toHaveBeenCalled()
  })
})
