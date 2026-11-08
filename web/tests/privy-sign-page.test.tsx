/* @vitest-environment jsdom */
import { act, type ReactNode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mock = vi.hoisted(() => ({
  authenticated: false,
  login: vi.fn(), logout: vi.fn(), initialize: vi.fn(), construct: vi.fn(), provider: vi.fn(), getUser: vi.fn(), createWallet: vi.fn(), handshake: vi.fn(), sign: vi.fn(),
  config: { networkId: 'testnet', coreAccountId: 'core.testnet', tokenAccountId: 'token.testnet', rpcUrl: 'https://rpc.testnet.near.org', cryptoProfileHash: '', assetDecimals: 6, assetSymbol: 'USD', privyAppId: 'app', privyClientId: 'client' },
}))
vi.mock('../src/lib/deploymentConfig', () => ({ deploymentConfigFromEnv: () => mock.config }))
vi.mock('@privy-io/js-sdk-core', () => ({ default: class { constructor(options: unknown) { mock.construct(options) } initialize = mock.initialize; user = { get: mock.getUser } }, LocalStorage: class {} }))
vi.mock('@privy-io/react-auth', () => ({ PrivyProvider: ({ children, appId, clientId }: { children: ReactNode; appId: string; clientId?: string }) => { mock.provider({ appId, clientId }); return children }, usePrivy: () => ({ ready: true, authenticated: mock.authenticated, user: mock.authenticated ? { id: 'user' } : undefined, login: mock.login, logout: mock.logout }) }))
vi.mock('@privy-io/react-auth/extended-chains', () => ({ useCreateWallet: () => ({ createWallet: mock.createWallet }) }))
vi.mock('@peerfolio/privy-near-connect/sign-page', () => ({ initSigningPage: mock.handshake }))
import PrivySignPage from '../src/PrivySignPage'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
const wallet = { type: 'wallet', wallet_client_type: 'privy', chain_type: 'near', id: 'wallet', address: 'a'.repeat(64) }
const payload = { kind: 'signAndSendTransaction', network: 'testnet', signerId: wallet.address, receiverId: 'core.testnet', actions: [{ type: 'FunctionCall', params: { methodName: 'storage_deposit', args: { account_id: wallet.address }, gas: '300000000000000', deposit: '10000000000000000000000' } }] }

describe('Privy authentication and approval page', () => {
  let root: Root
  let container: HTMLDivElement
  async function render() { await act(async () => root.render(<PrivySignPage />)) }
  async function click(label: string) {
    const button = [...container.querySelectorAll('button')].find((value) => value.textContent === label)
    expect(button, label).toBeDefined()
    await act(async () => button!.click())
  }
  beforeEach(() => {
    vi.clearAllMocks()
    mock.authenticated = false
    mock.config.privyAppId = 'app'
    mock.config.privyClientId = 'client'
    mock.initialize.mockResolvedValue(undefined)
    mock.getUser.mockResolvedValue({ user: { linked_accounts: [wallet] } })
    mock.handshake.mockImplementation(async () => ({ payload, targetOrigin: window.location.origin, sign: mock.sign }))
    mock.sign.mockResolvedValue(undefined)
    mock.logout.mockResolvedValue(undefined)
    Object.defineProperty(window, 'opener', { configurable: true, value: { postMessage: vi.fn() } })
    container = document.createElement('div')
    document.body.append(container)
    root = createRoot(container)
  })
  afterEach(async () => { await act(async () => root.unmount()); container.remove() })

  it.each(['', 'client'])('initializes React auth and NEAR signing with the same optional client: %s', async (clientId) => {
    mock.config.privyClientId = clientId
    await render()
    const identity = { appId: 'app', clientId: clientId || undefined }
    expect(mock.provider).toHaveBeenCalledWith(identity)
    expect(mock.construct).toHaveBeenCalledWith(expect.objectContaining(identity))
    expect(mock.initialize).toHaveBeenCalledOnce()
    expect(mock.handshake).toHaveBeenCalledOnce()
    expect(container.textContent).toContain('Sign in')
  })

  it('starts the handshake before login and waits for authentication before offering approval', async () => {
    await render()
    expect(mock.handshake).toHaveBeenCalledOnce()
    expect(mock.handshake.mock.calls[0][1]).toMatchObject({ allowedOrigins: [window.location.origin], debug: false })
    expect(container.textContent).not.toContain('Approve transaction')
    await click('Sign in')
    expect(mock.login).toHaveBeenCalledOnce()
    expect(mock.sign).not.toHaveBeenCalled()
  })
  it('shows exact transaction amounts and binds the approved wallet before signing once', async () => {
    mock.authenticated = true
    await render()
    expect(container.textContent).toContain('0.01 NEAR')
    expect(container.textContent).toContain('300 Tgas')
    expect(mock.sign).not.toHaveBeenCalled()
    await click('Approve transaction')
    expect(mock.handshake.mock.calls[1][1].wallet).toEqual(wallet)
    expect(mock.sign).toHaveBeenCalledOnce()
  })
  it('rejects an account switch between review and approval', async () => {
    mock.authenticated = true
    await render()
    mock.getUser.mockResolvedValue({ user: { linked_accounts: [{ ...wallet, address: 'b'.repeat(64) }] } })
    await click('Approve transaction')
    expect(mock.sign).not.toHaveBeenCalled()
    expect(mock.handshake).toHaveBeenCalledOnce()
    expect(container.textContent).toContain('check its finalized status')
  })
  it('rejects a changed request during wallet binding', async () => {
    mock.authenticated = true
    await render()
    mock.handshake.mockResolvedValueOnce({ payload: { ...payload, receiverId: 'other.testnet' }, targetOrigin: window.location.origin, sign: mock.sign })
    await click('Approve transaction')
    expect(mock.sign).not.toHaveBeenCalled()
  })
  it('creates a NEAR wallet only on request and rechecks for a previous successful creation', async () => {
    mock.authenticated = true
    mock.getUser.mockResolvedValueOnce({ user: { linked_accounts: [] } })
    await render()
    expect(mock.createWallet).not.toHaveBeenCalled()
    await click('Create NEAR wallet')
    expect(mock.createWallet).not.toHaveBeenCalled()
    expect(container.textContent).toContain(wallet.address)
  })
  it('does not initialize Privy without configuration or an opener', async () => {
    mock.config.privyAppId = ''
    await render()
    expect(container.textContent).toContain('Social login is not configured')
    expect(mock.initialize).not.toHaveBeenCalled()
  })
  it('reports an explicit rejection when cancelled before approval', async () => {
    await render()
    const close = vi.spyOn(window, 'close').mockImplementation(() => {})
    await click('Cancel')
    expect(window.opener.postMessage).toHaveBeenCalledWith({ source: 'privy-near-connect', type: 'ERROR', error: { type: 'UserRejectedRequest', message: 'User rejected the request.' } }, window.location.origin)
    expect(mock.sign).not.toHaveBeenCalled()
    close.mockRestore()
  })
  it('does not initialize Privy when opened directly', async () => {
    Object.defineProperty(window, 'opener', { configurable: true, value: null })
    await render()
    expect(container.textContent).toContain('Open this page from your wallet')
    expect(mock.initialize).not.toHaveBeenCalled()
  })
})
