import { setupWalletSelector, type Action as SelectorAction, type WalletSelector } from '@near-wallet-selector/core'
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet'
import { setupModal, type WalletSelectorModal } from '@near-wallet-selector/modal-ui'
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet'
import type { DeploymentConfig, WalletAdapter } from './types'

import '@near-wallet-selector/modal-ui/styles.css'

/**
 * A real Wallet Selector session. No account ID is embedded in the app: the
 * user chooses a supported wallet and account in the selector modal.
 */
export class NearWalletSelectorSession implements WalletAdapter {
  status: WalletAdapter['status'] = 'disconnected'
  error?: string
  private selector?: WalletSelector
  private modal?: WalletSelectorModal
  private selectedWalletId?: string
  private readonly listeners = new Set<() => void>()
  private setupPromise?: Promise<void>
  private connectWaiters: Array<{ resolve: () => void; reject: (error: Error) => void }> = []
  private readonly config: DeploymentConfig

  constructor(config: DeploymentConfig) {
    this.config = config
  }

  get accountId(): string | undefined {
    return this.selector?.store.getState().accounts.find((account) => account.active)?.accountId
  }

  get networkId(): string {
    return this.config.networkId
  }

  async connect(): Promise<void> {
    this.status = 'connecting'
    this.error = undefined
    this.emit()
    try {
      await this.ensureSetup()
      if (this.accountId) {
        this.status = 'connected'
        this.emit()
        return
      }
      await new Promise<void>((resolve, reject) => {
        this.connectWaiters.push({ resolve, reject })
        this.modal?.show()
      })
    } catch (error) {
      this.status = 'error'
      this.error = error instanceof Error ? error.message : 'Wallet selector could not be initialized.'
      this.rejectWaiters(new Error(this.error))
      this.emit()
      throw error
    }
  }

  async disconnect(): Promise<void> {
    if (this.selector && this.selectedWalletId) {
      try {
        const wallet = await this.selector.wallet(this.selectedWalletId)
        await wallet.signOut()
      } catch (error) {
        this.status = 'error'
        this.error = error instanceof Error ? error.message : 'Wallet sign-out failed.'
        this.emit()
        throw error
      }
    }
    this.status = 'disconnected'
    this.selectedWalletId = undefined
    this.emit()
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  /** Adapt Wallet Selector signing to @confidential-lending/client's wallet contract. */
  async signAndSendTransaction(params: { receiverId: string; actions: Array<{ type: 'FunctionCall'; params: { methodName: string; args: Record<string, unknown>; gas: string; deposit: string } }> }): Promise<{ transaction: { hash: string; signer_id: string } } | void> {
    await this.ensureSetup()
    if (!this.accountId) throw new Error('Connect a wallet before submitting a transaction.')
    const wallet = await this.selector!.wallet(this.selectedWalletId)
    const outcome = await wallet.signAndSendTransaction({
      signerId: this.accountId,
      receiverId: params.receiverId,
      actions: params.actions as unknown as SelectorAction[],
    })
    if (!outcome) return undefined
    const transaction = outcome.transaction
    return { transaction: { hash: transaction.hash, signer_id: transaction.signer_id } }
  }

  private async ensureSetup(): Promise<void> {
    if (this.selector) return
    if (this.setupPromise) return this.setupPromise
    if (this.config.networkId !== 'mainnet' && this.config.networkId !== 'testnet') throw new Error(`Wallet Selector does not support network ${this.config.networkId}.`)
    this.setupPromise = setupWalletSelector({
      network: this.config.networkId as 'mainnet' | 'testnet',
      modules: [setupMyNearWallet(), setupMeteorWallet()],
      debug: false,
    }).then((selector) => {
      this.selector = selector
      this.modal = setupModal(selector, {
        contractId: this.config.coreAccountId,
        description: 'Sign confidential lending actions with your NEAR wallet.',
        theme: 'dark',
      })
      const state = selector.store.getState()
      this.selectedWalletId = state.selectedWalletId || undefined
      selector.on('signedIn', (event) => {
        this.selectedWalletId = event.walletId
        this.status = 'connected'
        this.resolveWaiters()
        this.emit()
      })
      selector.on('accountsChanged', () => {
        this.status = this.accountId ? 'connected' : 'disconnected'
        this.resolveWaiters()
        this.emit()
      })
      selector.on('signedOut', () => {
        this.status = 'disconnected'
        this.emit()
      })
      selector.on('networkChanged', (event) => {
        if (event.networkId !== this.config.networkId) {
          this.status = 'error'
          this.error = `Wallet is on ${event.networkId}; this deployment requires ${this.config.networkId}.`
        }
        this.emit()
      })
      if (this.accountId) this.status = 'connected'
    }).finally(() => { this.setupPromise = undefined })
    return this.setupPromise
  }

  private resolveWaiters(): void {
    if (!this.accountId) return
    const waiters = this.connectWaiters.splice(0)
    for (const waiter of waiters) waiter.resolve()
  }

  private rejectWaiters(error: Error): void {
    const waiters = this.connectWaiters.splice(0)
    for (const waiter of waiters) waiter.reject(error)
  }

  private emit(): void {
    for (const listener of this.listeners) listener()
  }
}
