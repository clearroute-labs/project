import { setupWalletSelector, type Action as SelectorAction, type WalletSelector } from '@near-wallet-selector/core'
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet'
import { setupModal, type WalletSelectorModal } from '@near-wallet-selector/modal-ui'
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet'
import { KeyPair, type KeyPairString } from '@near-js/crypto'
import { actionCreators, createTransaction, encodeTransaction, Signature, SignedTransaction } from '@near-js/transactions'
import { base58 } from '@scure/base'
import { NearRpc, assertAccountId, type Arguments } from '@confidential-lending/client'
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

interface SandboxCredentials {
  account_id?: unknown
  private_key?: unknown
  public_key?: unknown
}

interface AccessKeyView {
  nonce: number | string
  block_hash: string
  permission: unknown
}

/**
 * A deliberately narrow localnet signer.  Wallet Selector cannot connect to
 * a sandbox network, while a local demo still needs real signed NEAR
 * transactions.  Credentials are selected by the user, validated, and held
 * only in this object until disconnect or page unload; they are never put in
 * storage, URLs, telemetry, or RPC arguments.
 */
export class SandboxCredentialWallet implements WalletAdapter {
  readonly networkId: string
  readonly credentialImport = { label: 'Import sandbox credentials', accept: 'application/json,.json' }
  status: WalletAdapter['status'] = 'disconnected'
  error?: string
  private account?: string
  private key?: KeyPair
  private readonly listeners = new Set<() => void>()
  private readonly rpc: NearRpc
  private readonly config: DeploymentConfig

  constructor(config: DeploymentConfig, rpc = new NearRpc(config.rpcUrl, { allowInsecureLocalhost: config.allowInsecureLocalhost })) {
    if (!isSandboxCredentialDeployment(config)) throw new TypeError('Sandbox credentials are only available for a sandbox deployment on localhost.')
    this.config = config
    this.networkId = config.networkId
    this.rpc = rpc
  }

  get accountId(): string | undefined { return this.account }

  async connect(): Promise<void> {
    if (!this.key || !this.account) throw new Error('Choose the NEAR credential JSON file for this sandbox account first.')
    this.status = 'connected'
    this.error = undefined
    this.emit()
  }

  async disconnect(): Promise<void> {
    this.key = undefined
    this.account = undefined
    this.status = 'disconnected'
    this.error = undefined
    this.emit()
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async importCredentialFile(file: File): Promise<void> {
    if (!isSandboxCredentialDeployment(this.config)) throw new Error('Sandbox credential import is disabled for this deployment.')
    if (!file || file.size > 64 * 1024) throw new Error('Credential file is missing or exceeds the 64 KiB safety limit.')
    let parsed: SandboxCredentials
    try {
      const text = await file.text()
      const value = JSON.parse(text) as unknown
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Credential file must contain an object.')
      parsed = value as SandboxCredentials
    } catch {
      throw new Error('The selected credential file is not valid JSON.')
    }
    const accountId = parsed.account_id
    const privateKey = parsed.private_key
    if (typeof accountId !== 'string' || !accountId || typeof privateKey !== 'string' || !privateKey.startsWith('ed25519:')) {
      throw new Error('Expected a NEAR sandbox credential with account_id and an Ed25519 private_key.')
    }
    try { assertAccountId(accountId) } catch { throw new Error('Credential account_id is not a valid NEAR account.') }
    let key: KeyPair
    try { key = KeyPair.fromString(privateKey as KeyPairString) } catch { throw new Error('The credential private key is invalid.') }
    if (parsed.public_key !== undefined && (typeof parsed.public_key !== 'string' || key.getPublicKey().toString() !== parsed.public_key)) {
      throw new Error('Credential public_key does not match the private key.')
    }
    this.key = key
    this.account = accountId
    this.status = 'connected'
    this.error = undefined
    this.emit()
  }

  async signAndSendTransaction(params: { receiverId: string; actions: Array<{ type: 'FunctionCall'; params: { methodName: string; args: Record<string, unknown>; gas: string; deposit: string } }> }): Promise<{ transaction: { hash: string; signer_id: string } } | void> {
    if (this.status !== 'connected' || !this.key || !this.account) throw new Error('Import and connect a sandbox credential before signing.')
    assertAccountId(this.account)
    assertAccountId(params.receiverId)
    if (!params.actions.length) throw new Error('A transaction must contain at least one action.')
    const publicKey = this.key.getPublicKey()
    const access = await this.rpc.request<AccessKeyView>('query', { request_type: 'view_access_key', finality: 'final', account_id: this.account, public_key: publicKey.toString() })
    const nonce = canonicalNonce(access.nonce)
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(access.block_hash)) throw new Error('RPC returned an invalid access-key block hash.')
    const blockHash = base58.decode(access.block_hash)
    if (blockHash.length !== 32) throw new Error('RPC returned an invalid access-key block hash.')
    const actions = params.actions.map((action) => {
      if (action.type !== 'FunctionCall') throw new Error('Sandbox signer only accepts function-call actions.')
      if (!/^[a-zA-Z][a-zA-Z0-9_]{0,127}$/.test(action.params.methodName)) throw new Error('Invalid function-call method.')
      const gas = canonicalPositive(action.params.gas, 'gas')
      const deposit = canonicalAmount(action.params.deposit, 'deposit')
      return actionCreators.functionCall(action.params.methodName, action.params.args as Arguments, BigInt(gas), BigInt(deposit))
    })
    const transaction = createTransaction(this.account, publicKey, params.receiverId, nonce + 1n, actions, blockHash)
    const digest = await sha256(encodeTransaction(transaction))
    const signature = this.key.sign(digest)
    const signed = new SignedTransaction({ transaction, signature: new Signature({ keyType: publicKey.keyType, data: signature.signature }) })
    const encoded = encodeTransaction(signed)
    const result = await this.rpc.request<{ transaction?: { hash?: string; signer_id?: string } }>('broadcast_tx_commit', [toBase64(encoded)])
    const hash = result.transaction?.hash
    if (typeof hash !== 'string' || !hash) throw new Error('RPC did not return a transaction hash.')
    return { transaction: { hash, signer_id: this.account } }
  }

  private emit(): void { for (const listener of this.listeners) listener() }
}

export function isSandboxCredentialDeployment(config: Pick<DeploymentConfig, 'networkId' | 'rpcUrl'> & { allowInsecureLocalhost?: boolean }): boolean {
  try {
    const url = new URL(config.rpcUrl)
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    return config.networkId === 'sandbox' && local && (url.protocol === 'https:' || config.allowInsecureLocalhost === true && url.protocol === 'http:')
  } catch { return false }
}

function canonicalNonce(value: unknown): bigint {
  const stringValue = typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : value
  if (typeof stringValue !== 'string' || !/^(0|[1-9]\d*)$/.test(stringValue)) throw new Error('RPC returned an invalid access-key nonce.')
  return BigInt(stringValue)
}

function canonicalPositive(value: string, label: string): string {
  if (!/^[1-9]\d*$/.test(value) || BigInt(value) > 300_000_000_000_000n) throw new Error(`Invalid ${label}.`)
  return value
}

function canonicalAmount(value: string, label: string): string {
  if (!/^(0|[1-9]\d*)$/.test(value)) throw new Error(`Invalid ${label}.`)
  return value
}

function toBase64(bytes: Uint8Array): string {
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text)
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy as unknown as BufferSource))
}
