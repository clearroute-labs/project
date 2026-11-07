import { describe, expect, it, vi } from 'vitest'
import type {
  NearConnectorOptions,
  NearWalletBase,
  WalletManifest,
} from '@hot-labs/near-connect'
import {
  NearConnectWallet,
  type NearConnectConnector,
} from '../src/lib/nearConnectWallet'
import type { DeploymentConfig } from '../src/lib/types'

const config: DeploymentConfig = {
  networkId: 'testnet',
  coreAccountId: 'core.testnet',
  tokenAccountId: 'token.testnet',
  rpcUrl: 'https://rpc.testnet.near.org',
  cryptoProfileHash: 'a'.repeat(64),
  assetDecimals: 6,
  assetSymbol: 'USDC',
}

const transactionHash = 'A'.repeat(44)
const ecosystemManifest = {
  id: 'ecosystem',
  name: 'Ecosystem',
  features: { signAndSendTransaction: true, mainnet: true, testnet: true },
} as WalletManifest

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

async function settle() {
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
}

function makeWallet(accountId: string, outcome?: unknown) {
  const getAccounts = vi.fn(async () => [{ accountId }])
  const signAndSendTransaction = vi.fn(async (_params: unknown): Promise<unknown> => outcome)
  const signOut = vi.fn(async () => undefined)
  const wallet = {
    manifest: ecosystemManifest,
    getAccounts,
    signAndSendTransaction,
    signOut,
  } as unknown as NearWalletBase
  return { wallet, getAccounts, signAndSendTransaction, signOut }
}

class FakeConnector {
  readonly whenManifestLoaded: Promise<void>
  readonly manifests: WalletManifest[] = [ecosystemManifest]
  readonly registerWallet = vi.fn(async (manifest: WalletManifest) => {
    this.manifests.push(manifest)
  })
  readonly connect = vi.fn(async () => this.connectImplementation())
  readonly disconnect = vi.fn(async (_wallet?: NearWalletBase) => undefined)
  readonly getConnectedWallet = vi.fn(async () => {
    if (!this.restored) throw new Error('No persisted wallet')
    return this.restored
  })

  restored?: { wallet: NearWalletBase; accounts: Array<{ accountId: string }> }
  connectImplementation: () => Promise<NearWalletBase> = async () => makeWallet('alice.testnet').wallet

  private readonly listeners = new Map<string, Array<(payload: unknown) => void>>()

  constructor(manifestLoaded: Promise<void> = Promise.resolve()) {
    this.whenManifestLoaded = manifestLoaded
  }

  on(event: string, listener: (payload: unknown) => void): void {
    const listeners = this.listeners.get(event) || []
    listeners.push(listener)
    this.listeners.set(event, listeners)
  }

  emitSignIn(wallet: NearWalletBase, accountId: string, success = true): void {
    const payload = { wallet, accounts: [{ accountId }], success }
    for (const event of ['wallet:signIn', 'wallet:signInAndSignMessage']) {
      for (const listener of this.listeners.get(event) || []) listener(payload)
    }
  }

  emitSignOut(): void {
    for (const listener of this.listeners.get('wallet:signOut') || []) listener(undefined)
  }

  asConnector(): NearConnectConnector {
    return this as unknown as NearConnectConnector
  }
}

function adapterFor(connector: FakeConnector, options: { additionalWallets?: WalletManifest[] } = {}) {
  const connectorFactory = vi.fn((_connectorOptions: NearConnectorOptions) => connector.asConnector())
  const adapter = new NearConnectWallet(config, { ...options, connectorFactory })
  return { adapter, connector, connectorFactory }
}

describe('NearConnectWallet', () => {
  it('lazily creates the connector, retains ecosystem wallets, and registers additions after the manifest', async () => {
    const manifestLoaded = deferred<void>()
    const connector = new FakeConnector(manifestLoaded.promise)
    const addedManifest = { id: 'privy', name: 'Configured Privy' } as WalletManifest
    const { adapter, connectorFactory } = adapterFor(connector, { additionalWallets: [addedManifest] })

    expect(connectorFactory).not.toHaveBeenCalled()
    const connecting = adapter.connect()
    await settle()
    expect(connector.registerWallet).not.toHaveBeenCalled()

    manifestLoaded.resolve()
    await connecting

    expect(connectorFactory).toHaveBeenCalledWith(expect.objectContaining({
      network: 'testnet',
      autoConnect: false,
      features: expect.objectContaining({ signAndSendTransaction: true, testnet: true }),
    }))
    expect(connector.registerWallet).toHaveBeenCalledWith(addedManifest)
    expect(connector.manifests.map((manifest) => manifest.id)).toEqual(['ecosystem', 'privy'])
    expect(adapter.status).toBe('connected')
    expect(adapter.accountId).toBe('alice.testnet')
  })

  it('cancels a pending picker, ignores the stale result, and permits a retry', async () => {
    const connector = new FakeConnector()
    const firstConnection = deferred<NearWalletBase>()
    connector.connectImplementation = () => firstConnection.promise
    const { adapter } = adapterFor(connector)

    const pending = adapter.connect()
    await settle()
    expect(adapter.status).toBe('connecting')
    for (let attempt = 0; attempt < 10 && connector.connect.mock.calls.length === 0; attempt += 1) await settle()
    expect(connector.connect).toHaveBeenCalledTimes(1)

    await adapter.disconnect()
    await expect(pending).rejects.toMatchObject({ name: 'CancelledConnectionError' })
    expect(adapter.status).toBe('disconnected')
    expect(adapter.accountId).toBeUndefined()

    connector.connectImplementation = async () => makeWallet('retry.testnet').wallet
    await adapter.connect()
    expect(adapter.status).toBe('connected')
    expect(adapter.accountId).toBe('retry.testnet')

    connector.disconnect.mockImplementation(async () => { connector.emitSignOut() })
    const stale = makeWallet('stale.testnet')
    firstConnection.resolve(stale.wallet)
    await new Promise((resolve) => setTimeout(resolve, 0))
    await settle()
    expect(adapter.accountId).toBe('retry.testnet')
    expect(connector.disconnect).not.toHaveBeenCalled()
    expect(stale.signOut).toHaveBeenCalledWith({ network: 'testnet' })
    expect(connector.connect).toHaveBeenCalledTimes(2)
  })

  it('restores a selected wallet only during an explicit connect', async () => {
    const connector = new FakeConnector()
    const restored = makeWallet('restored.testnet')
    connector.restored = { wallet: restored.wallet, accounts: [{ accountId: 'restored.near' }] }
    const { adapter } = adapterFor(connector)

    expect(adapter.status).toBe('disconnected')
    await adapter.connect()

    expect(connector.getConnectedWallet).toHaveBeenCalledTimes(1)
    expect(connector.connect).not.toHaveBeenCalled()
    expect(restored.getAccounts).toHaveBeenCalledWith({ network: 'testnet' })
    expect(adapter.accountId).toBe('restored.testnet')
  })

  it('waits for sign-out to finish before reconnecting', async () => {
    const connector = new FakeConnector()
    const { adapter } = adapterFor(connector)
    await adapter.connect()
    const signingOut = deferred<void>()
    connector.disconnect.mockImplementation(async () => { await signingOut.promise; connector.emitSignOut() })
    const disconnect = adapter.disconnect()
    connector.connectImplementation = async () => makeWallet('bob.testnet').wallet
    const reconnect = adapter.connect()
    await settle()
    expect(connector.connect).toHaveBeenCalledTimes(1)
    signingOut.resolve()
    await disconnect
    await reconnect
    expect(adapter.accountId).toBe('bob.testnet')
    expect(adapter.status).toBe('connected')
  })

  it('rejects sign-in events from a wallet without deployment-network support', async () => {
    const connector = new FakeConnector()
    const { adapter } = adapterFor(connector)
    await adapter.connect()
    const unsupported = makeWallet('other.near')
    unsupported.wallet.manifest = { ...ecosystemManifest, features: { ...ecosystemManifest.features, testnet: false } }
    connector.emitSignIn(unsupported.wallet, 'other.near')
    expect(adapter.status).toBe('error')
    expect(adapter.accountId).toBeUndefined()
  })

  it('does not clobber an account switch with a stale connect result, and ignores sign-in after sign-out', async () => {
    const connector = new FakeConnector()
    const accountLookup = deferred<Array<{ accountId: string }>>()
    const first = makeWallet('alice.testnet')
    first.getAccounts.mockImplementation(async () => accountLookup.promise)
    const switched = makeWallet('bob.testnet')
    connector.connectImplementation = async () => first.wallet
    const { adapter } = adapterFor(connector)

    const connecting = adapter.connect()
    for (let attempt = 0; attempt < 10 && first.getAccounts.mock.calls.length === 0; attempt += 1) await settle()
    expect(first.getAccounts).toHaveBeenCalled()

    connector.emitSignIn(switched.wallet, 'bob.testnet')
    expect(adapter.accountId).toBe('bob.testnet')
    accountLookup.resolve([{ accountId: 'alice.testnet' }])
    await connecting
    expect(adapter.accountId).toBe('bob.testnet')

    connector.emitSignOut()
    expect(adapter.status).toBe('disconnected')
    expect(adapter.accountId).toBeUndefined()
    connector.emitSignIn(switched.wallet, 'carol.testnet')
    expect(adapter.status).toBe('disconnected')
    expect(adapter.accountId).toBeUndefined()
  })

  it('forwards the exact signing request and preserves the returned signer and hash', async () => {
    const handle = makeWallet('alice.testnet', { transaction: { hash: transactionHash, signer_id: 'alice.testnet' } })
    const connector = new FakeConnector()
    connector.connectImplementation = async () => handle.wallet
    const { adapter } = adapterFor(connector)
    await adapter.connect()

    const actions = [{
      type: 'FunctionCall' as const,
      params: { methodName: 'settle', args: { proof: 'ciphertext', nonce: 7 }, gas: '300000000000000', deposit: '0' },
    }]
    const result = await adapter.signAndSendTransaction({ receiverId: 'core.testnet', actions })

    expect(handle.signAndSendTransaction).toHaveBeenCalledWith({
      network: 'testnet',
      signerId: 'alice.testnet',
      receiverId: 'core.testnet',
      actions,
    })
    expect(result).toEqual({ transaction: { hash: transactionHash, signer_id: 'alice.testnet' } })
  })

  it('keeps mismatched results unresolved and does not retry an unknown result', async () => {
    const mismatch = makeWallet('alice.testnet', { transaction: { hash: transactionHash, signer_id: 'bob.testnet' } })
    const connector = new FakeConnector()
    connector.connectImplementation = async () => mismatch.wallet
    const { adapter } = adapterFor(connector)
    await adapter.connect()

    const request = { receiverId: 'core.testnet', actions: [{ type: 'FunctionCall' as const, params: { methodName: 'ping', args: {}, gas: '300000000000000', deposit: '0' } }] }
    await expect(adapter.signAndSendTransaction(request)).rejects.toMatchObject({ name: 'TransactionPendingError' })

    const noResult = makeWallet('alice.testnet')
    connector.emitSignIn(noResult.wallet, 'alice.testnet')
    noResult.signAndSendTransaction.mockResolvedValue(undefined)
    const result = await adapter.signAndSendTransaction(request)
    expect(result).toBeUndefined()
    expect(noResult.signAndSendTransaction).toHaveBeenCalledTimes(1)

    const transportFailure = makeWallet('alice.testnet')
    transportFailure.signAndSendTransaction.mockRejectedValue(new Error('RPC connection reset'))
    connector.emitSignIn(transportFailure.wallet, 'alice.testnet')
    await expect(adapter.signAndSendTransaction(request)).rejects.toMatchObject({ name: 'TransactionPendingError' })

    const userRejected = makeWallet('alice.testnet')
    const rejection = new Error('User rejected the request.')
    rejection.name = 'UserRejectedRequest'
    userRejected.signAndSendTransaction.mockRejectedValue(rejection)
    connector.emitSignIn(userRejected.wallet, 'alice.testnet')
    await expect(adapter.signAndSendTransaction(request)).rejects.toMatchObject({ name: 'UserRejectedRequest' })
  })

  it('validates the selected network and account IDs before invoking a wallet', async () => {
    const unsupported = new NearConnectWallet({ ...config, networkId: 'sandbox' }, {
      connectorFactory: vi.fn(() => { throw new Error('factory must not run') }),
    })
    await expect(unsupported.connect()).rejects.toThrow(/does not support network sandbox/)

    const handle = makeWallet('alice.testnet')
    const connector = new FakeConnector()
    connector.connectImplementation = async () => handle.wallet
    const { adapter } = adapterFor(connector)
    await adapter.connect()
    await expect(adapter.signAndSendTransaction({
      receiverId: 'not an account',
      actions: [],
    })).rejects.toThrow(/invalid NEAR account/)
    expect(handle.signAndSendTransaction).not.toHaveBeenCalled()
  })
})
