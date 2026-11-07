import {
  NearConnector,
  type NearConnectorOptions,
  type NearWalletBase,
  type WalletManifest,
} from '@hot-labs/near-connect'
import { assertAccountId } from '@confidential-lending/client'
import type { DeploymentConfig, NetworkId, WalletAdapter } from './types'

type PublicNetwork = 'mainnet' | 'testnet'

interface SignInEvent {
  wallet: NearWalletBase
  accounts: Array<{ accountId: string }>
  success: boolean
}
interface ConnectedWallet {
  wallet: NearWalletBase
  accounts: Array<{ accountId: string }>
}

/**
 * The small part of NearConnector used by the application. Keeping this
 * boundary structural lets tests exercise connection races without loading
 * the iframe-backed connector.
 */
export interface NearConnectConnector {
  readonly whenManifestLoaded: Promise<void>
  on(event: 'wallet:signIn', listener: (event: SignInEvent) => void): void
  on(event: 'wallet:signInAndSignMessage', listener: (event: SignInEvent) => void): void
  on(event: 'wallet:signOut', listener: () => void): void
  registerWallet(manifest: WalletManifest): Promise<void>
  connect(): Promise<NearWalletBase>
  disconnect(wallet?: NearWalletBase): Promise<void>
  getConnectedWallet?(): Promise<ConnectedWallet>
}

export interface NearConnectWalletOptions {
  /** Additional manifests, such as an explicitly configured Privy wallet. */
  additionalWallets?: WalletManifest[]
  /** Injectable only for tests; production uses NearConnector. */
  connectorFactory?: (options: NearConnectorOptions) => NearConnectConnector
}

const SAFE_TRANSACTION_HASH = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/

class CancelledConnectionError extends Error {
  constructor() {
    super('Wallet connection was cancelled.')
    this.name = 'CancelledConnectionError'
  }
}

/**
 * A transaction result that cannot be tied to a trusted signer must remain
 * unresolved. actionState recognizes this name and keeps the action locked
 * instead of presenting it as a successful submission or inviting a retry.
 */
class UnresolvedTransactionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TransactionPendingError'
  }
}

/**
 * NEAR Connect adapter for the browser-facing WalletAdapter contract.
 *
 * The connector is intentionally lazy: constructing the adapter does not load
 * a manifest, open a wallet popup, or restore a persisted wallet. A restore is
 * attempted only from an explicit connect() call, and is read-only.
 */
export class NearConnectWallet implements WalletAdapter {
  status: WalletAdapter['status'] = 'disconnected'
  error?: string
  readonly networkId: NetworkId

  private readonly config: DeploymentConfig
  private readonly additionalWallets: WalletManifest[]
  private readonly connectorFactory: (options: NearConnectorOptions) => NearConnectConnector
  private connector?: NearConnectConnector
  private connectorSetup?: Promise<NearConnectConnector>
  private activeWallet?: NearWalletBase
  private account?: string
  private connectPromise?: Promise<void>
  private disconnectPromise?: Promise<void>
  private cancelConnect?: (error: Error) => void
  private lifecycleEpoch = 0
  private sessionEpoch = 0
  private readonly listeners = new Set<() => void>()
  private acceptingEvents = false

  constructor(config: DeploymentConfig, options: NearConnectWalletOptions = {}) {
    this.config = config
    this.networkId = config.networkId
    this.additionalWallets = [...(options.additionalWallets || [])]
    this.connectorFactory = options.connectorFactory || ((connectorOptions) => new NearConnector(connectorOptions))
  }

  get accountId(): string | undefined {
    return this.account
  }

  connect(): Promise<void> {
    if (this.disconnectPromise) return this.disconnectPromise.then(() => this.connect())
    if (this.status === 'connected' && this.account && this.activeWallet) return Promise.resolve()
    if (this.connectPromise) return this.connectPromise

    const epoch = ++this.lifecycleEpoch
    this.status = 'connecting'
    this.error = undefined
    this.emit()

    let rejectCancellation!: (error: Error) => void
    const cancellation = new Promise<never>((_, reject) => { rejectCancellation = reject })
    this.cancelConnect = rejectCancellation

    const operation = this.connectInner(epoch)
    // Promise.race attaches a rejection handler to operation, so a connector
    // that resolves after cancellation cannot become an unhandled rejection.
    const pending = Promise.race([operation, cancellation]).catch((error: unknown) => {
      if (this.lifecycleEpoch === epoch && !(error instanceof CancelledConnectionError)) {
        this.acceptingEvents = false
        this.clearSession()
        this.status = 'error'
        this.error = error instanceof Error ? error.message : 'Wallet connection failed.'
        this.emit()
      }
      throw error
    }).finally(() => {
      if (this.connectPromise === pending) this.connectPromise = undefined
      if (this.cancelConnect === rejectCancellation) this.cancelConnect = undefined
    })

    this.connectPromise = pending
    return pending
  }

  disconnect(): Promise<void> {
    if (this.disconnectPromise) return this.disconnectPromise
    const pending = this.disconnectInner().finally(() => {
      if (this.disconnectPromise === pending) this.disconnectPromise = undefined
    })
    this.disconnectPromise = pending
    return pending
  }

  private async disconnectInner(): Promise<void> {
    const connector = this.connector
    const wallet = this.activeWallet
    this.lifecycleEpoch += 1
    this.cancelConnect?.(new CancelledConnectionError())
    this.cancelConnect = undefined

    this.acceptingEvents = false
    this.clearSession()
    this.status = 'disconnected'
    this.error = undefined
    this.emit()

    // If connect() is still waiting for a wallet popup there may be no wallet
    // to sign out yet. connectInner will clean up a wallet that arrives later.
    if (!connector || !wallet) return
    try {
      await connector.disconnect(wallet)
    } catch (error) {
      // The account is already cleared. Surface a sign-out failure without
      // allowing the stale account to become active again.
      this.status = 'error'
      this.error = error instanceof Error ? error.message : 'Wallet sign-out failed.'
      this.emit()
      throw error
    }
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async signAndSendTransaction(params: {
    receiverId: string
    actions: Array<{ type: 'FunctionCall'; params: { methodName: string; args: Record<string, unknown>; gas: string; deposit: string } }>
  }): Promise<{ transaction: { hash: string; signer_id: string } } | void> {
    const network = this.publicNetwork()
    const wallet = this.activeWallet
    const signerId = this.account
    if (this.status !== 'connected' || !wallet || !signerId) throw new Error('Connect a NEAR wallet before signing.')

    try {
      assertAccountId(signerId)
      assertAccountId(params.receiverId)
    } catch {
      throw new Error('The connected wallet returned an invalid NEAR account.')
    }

    this.ensureWalletSupportsSigning(wallet, network)
    const lifecycleEpoch = this.lifecycleEpoch
    const sessionEpoch = this.sessionEpoch
    let accounts: Array<{ accountId: string }>
    try {
      accounts = await wallet.getAccounts({ network })
    } catch (error) {
      if (lifecycleEpoch !== this.lifecycleEpoch || sessionEpoch !== this.sessionEpoch) {
        throw new UnresolvedTransactionError('The wallet session changed before signing; inspect the original operation before retrying.')
      }
      throw error
    }
    if (lifecycleEpoch !== this.lifecycleEpoch || sessionEpoch !== this.sessionEpoch || this.status !== 'connected' || this.activeWallet !== wallet || this.account !== signerId) {
      throw new UnresolvedTransactionError('The wallet session changed before signing; inspect the original operation before retrying.')
    }
    if (!accounts.some(({ accountId }) => {
      try { assertAccountId(accountId); return accountId === signerId } catch { return false }
    })) {
      throw new UnresolvedTransactionError('The wallet account changed before signing; inspect the original operation before retrying.')
    }

    let outcome: Awaited<ReturnType<NearWalletBase['signAndSendTransaction']>>
    try {
      outcome = await wallet.signAndSendTransaction({
        network,
        signerId,
        receiverId: params.receiverId,
        actions: params.actions as never,
      })
    } catch (error) {
      if (this.isExplicitUserCancellation(error)) throw error
      throw new UnresolvedTransactionError('The wallet did not provide a trustworthy transaction outcome; inspect the original operation before retrying.')
    }

    if (!outcome) {
      if (lifecycleEpoch !== this.lifecycleEpoch || sessionEpoch !== this.sessionEpoch) {
        throw new UnresolvedTransactionError('The wallet session changed before the transaction result was available; inspect the original operation before retrying.')
      }
      // Redirect-based wallets can return no outcome. Preserve that unknown
      // state; never manufacture a hash or resend the transaction.
      return undefined
    }

    const transaction = outcome.transaction as unknown as { hash?: unknown; signer_id?: unknown } | undefined
    const hash = transaction?.hash
    const returnedSigner = transaction?.signer_id
    if (typeof hash !== 'string' || !SAFE_TRANSACTION_HASH.test(hash) || returnedSigner !== signerId) {
      throw new UnresolvedTransactionError('The wallet returned an untrusted transaction result; inspect the original operation before retrying.')
    }

    // A valid result is safe to return even when the UI switched accounts
    // while the wallet popup was open: its signer is bound to the captured
    // account and can be checked by the read-only pending-status path.
    return { transaction: { hash, signer_id: returnedSigner } }
  }

  private async connectInner(epoch: number): Promise<void> {
    const connector = await this.ensureConnector()
    this.ensureCurrent(epoch)
    this.acceptingEvents = true

    const restored = await this.restoreConnected(connector, epoch)
    if (restored) return

    const connectSessionEpoch = this.sessionEpoch
    const wallet = await connector.connect()
    if (!this.isCurrent(epoch)) {
      await this.safeDisconnect(wallet)
      throw new CancelledConnectionError()
    }
    // A sign-in event may arrive before connector.connect() resolves. In that
    // case its account is authoritative; do not overwrite a user-initiated
    // account switch with the popup's stale account below.
    if (this.sessionEpoch !== connectSessionEpoch && this.status === 'connected') return

    let accounts: Array<{ accountId: string }>
    try {
      accounts = await wallet.getAccounts({ network: this.publicNetwork() })
    } catch (error) {
      if (!this.isCurrent(epoch)) {
        await this.safeDisconnect(wallet)
        throw new CancelledConnectionError()
      }
      if (this.sessionEpoch !== connectSessionEpoch && this.status === 'connected') return
      throw error
    }
    if (!this.isCurrent(epoch)) {
      await this.safeDisconnect(wallet)
      throw new CancelledConnectionError()
    }
    if (this.sessionEpoch !== connectSessionEpoch && this.status === 'connected') return
    if (!accounts.length) throw new Error('The selected wallet returned no NEAR accounts.')
    this.adoptWallet(connector, wallet, accounts, epoch)
  }

  private async ensureConnector(): Promise<NearConnectConnector> {
    if (this.connectorSetup) return this.connectorSetup
    if (this.connector) return this.connector

    const setup = this.createConnector()
    const pending = setup.finally(() => {
      if (this.connectorSetup === pending) this.connectorSetup = undefined
    })
    this.connectorSetup = pending
    return pending
  }

  private async createConnector(): Promise<NearConnectConnector> {
    const network = this.publicNetwork()
    const connector = this.connectorFactory({
      network,
      autoConnect: false,
      features: {
        signAndSendTransaction: true,
        [network]: true,
      },
    })
    this.connector = connector
    connector.on('wallet:signIn', (event) => this.onSignIn(connector, event))
    connector.on('wallet:signInAndSignMessage', (event) => this.onSignIn(connector, event))
    connector.on('wallet:signOut', () => this.onSignOut(connector))

    try {
      await connector.whenManifestLoaded
      for (const manifest of this.additionalWallets) await connector.registerWallet(manifest)
      return connector
    } catch (error) {
      if (this.connector === connector) this.connector = undefined
      throw error
    }
  }

  private async restoreConnected(connector: NearConnectConnector, epoch: number): Promise<boolean> {
    if (!connector.getConnectedWallet) return false
    const sessionEpoch = this.sessionEpoch
    try {
      const connected = await connector.getConnectedWallet()
      this.ensureCurrent(epoch)
      if (this.sessionEpoch !== sessionEpoch && this.status === 'connected') return true
      // getConnectedWallet() omits the network in its own getAccounts call.
      const accounts = await connected.wallet.getAccounts({ network: this.publicNetwork() })
      this.ensureCurrent(epoch)
      if (this.sessionEpoch !== sessionEpoch && this.status === 'connected') return true
      if (!accounts.length) return false
      this.adoptWallet(connector, connected.wallet, accounts, epoch)
      return true
    } catch (error) {
      if (error instanceof CancelledConnectionError) throw error
      // A stale persisted wallet, or a wallet that is no longer available,
      // should fall through to the normal explicit wallet picker.
      return false
    }
  }

  private onSignIn(connector: NearConnectConnector, event: SignInEvent): void {
    if (connector !== this.connector || !this.acceptingEvents || event.success === false) return
    try {
      this.adoptWallet(connector, event.wallet, event.accounts, this.lifecycleEpoch)
    } catch (error) {
      this.clearSession()
      this.status = 'error'
      this.error = error instanceof Error ? error.message : 'The wallet returned no valid NEAR account.'
      this.emit()
    }
  }

  private onSignOut(connector: NearConnectConnector): void {
    if (connector !== this.connector) return
    this.lifecycleEpoch += 1
    this.cancelConnect?.(new CancelledConnectionError())
    this.cancelConnect = undefined
    this.acceptingEvents = false
    this.clearSession()
    this.status = 'disconnected'
    this.error = undefined
    this.emit()
  }

  private adoptWallet(connector: NearConnectConnector, wallet: NearWalletBase, accounts: Array<{ accountId: string }>, epoch: number): void {
    this.ensureCurrent(epoch)
    this.ensureWalletSupportsSigning(wallet, this.publicNetwork())
    const account = accounts[0]?.accountId
    if (!account) throw new Error('The selected wallet returned no NEAR accounts.')
    try { assertAccountId(account) } catch { throw new Error('The selected wallet returned an invalid NEAR account.') }

    const changed = this.account !== account || this.activeWallet !== wallet || this.status !== 'connected'
    this.connector = connector
    this.activeWallet = wallet
    this.account = account
    this.status = 'connected'
    this.error = undefined
    if (changed) this.sessionEpoch += 1
    if (changed) this.emit()
  }

  private clearSession(): void {
    this.activeWallet = undefined
    this.account = undefined
    this.sessionEpoch += 1
  }

  private async safeDisconnect(wallet: NearWalletBase): Promise<void> {
    if (this.activeWallet === wallet) return
    // An obsolete popup must not clear the connector's newer selected-wallet
    // record. Sign out only that old wallet, leaving connector state alone.
    try { await wallet.signOut({ network: this.publicNetwork() }) } catch { /* the original connection was already cancelled */ }
  }

  private ensureWalletSupportsSigning(wallet: NearWalletBase, network: PublicNetwork): void {
    const features = wallet.manifest?.features
    if (features?.signAndSendTransaction !== true || features[network] !== true) {
      throw new Error(`The selected wallet does not support NEAR ${network} transaction signing.`)
    }
  }

  private isExplicitUserCancellation(error: unknown): boolean {
    if (!(error instanceof Error)) return false
    if (/^(?:User(?:Rejected|Cancelled|Canceled)(?:Request|Error)?|Rejected|Cancelled|Canceled)$/.test(error.name)) return true
    return /(?:user\s+(?:rejected|denied|cancelled|canceled)|(?:rejected|denied)\s+by\s+user)/i.test(error.message)
  }

  private ensureCurrent(epoch: number): void {
    if (!this.isCurrent(epoch)) throw new CancelledConnectionError()
  }

  private isCurrent(epoch: number): boolean {
    return epoch === this.lifecycleEpoch && this.connector !== undefined
  }

  private publicNetwork(): PublicNetwork {
    const network = this.config.networkId
    if (network !== 'mainnet' && network !== 'testnet') {
      throw new Error(`NEAR Connect does not support network ${network}.`)
    }
    return network as PublicNetwork
  }

  private emit(): void {
    for (const listener of this.listeners) listener()
  }
}
