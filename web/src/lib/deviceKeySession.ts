import { DeviceKeyVault, type DeviceVaultPayload } from './deviceKeyVault'
import type { AppAdapters, CryptoProvider } from './types'
import { clearEncryptedWalletBackup, hasEncryptedWalletBackup, markEncryptedWalletBackupSaved, subscribeEncryptedWalletBackup, walletBackupScope } from './walletBackupGate'

type Vault = Pick<DeviceKeyVault, 'metadata' | 'supported' | 'enroll' | 'unlock' | 'save' | 'lock' | 'remove' | 'isUnlocked'>
export interface DeviceKeyState {
  ready: boolean
  exists: boolean
  unlocked: boolean
  supported: boolean
  busy: boolean
  error?: string
  updatedAt?: string
  sessionVersion: number
  materialVersion: number
}

const mutations = new Set(['createKeyRegistration', 'createAuthorizationKeyRegistration', 'prepareBrokerKeyRegistration', 'prepareAgreement', 'importWalletMaterial'])

/** Coordinates the encrypted browser copy with the worker's account lifetime. */
export class DeviceKeySession {
  readonly crypto: CryptoProvider
  private readonly listeners = new Set<() => void>()
  private state: DeviceKeyState
  private scope?: string
  private epoch = 0
  private queue: Promise<void> = Promise.resolve()
  private metadataReady: Promise<void> = Promise.resolve()
  private changingMaterial = false
  private backupPersistPending = false

  constructor(private readonly adapters: AppAdapters, private readonly vault: Vault = new DeviceKeyVault()) {
    this.state = { ready: false, exists: false, unlocked: false, supported: vault.supported(), busy: false, sessionVersion: 0, materialVersion: 0 }
    this.crypto = new Proxy(adapters.crypto, {
      get: (target, name) => {
        const method = Reflect.get(target, name)
        if (typeof method !== 'function') return method
        if (name === 'getStatus') return method.bind(target)
        if (name === 'lockWallet') return () => this.lock()
        return (...args: unknown[]) => {
          const epoch = this.epoch
          return this.serial(async () => {
            await this.metadataReady
            this.assertCurrent(epoch)
            const mutation = mutations.has(String(name))
            if (mutation && name !== 'importWalletMaterial' && this.state.exists && !this.state.unlocked) {
              throw new Error('Unlock your saved keys in Wallet & security before creating more private material.')
            }
            this.changingMaterial = mutation
            try {
              const result = await Reflect.apply(method, target, args)
              this.assertCurrent(epoch)
              const changed = mutation && (name !== 'prepareBrokerKeyRegistration' || (result as { newKeyGenerated: boolean }).newKeyGenerated)
              if (changed) {
                clearEncryptedWalletBackup(this.scope)
                this.update({ materialVersion: this.state.materialVersion + 1 })
                await this.persist(epoch)
              }
              return result
            } catch (error) {
              // Preparation can generate a key before proof generation fails.
              // Keep that key recoverable and require a fresh file confirmation.
              if (mutation && epoch === this.epoch) {
                clearEncryptedWalletBackup(this.scope)
                this.update({ materialVersion: this.state.materialVersion + 1 })
                await this.persist(epoch)
              }
              throw error
            } finally {
              this.changingMaterial = false
              if (this.backupPersistPending) {
                this.backupPersistPending = false
                if (epoch === this.epoch) void this.serial(() => this.persist(epoch)).catch(() => undefined)
              }
            }
          })
        }
      },
    })
  }

  getSnapshot = (): DeviceKeyState => this.state
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => { this.listeners.delete(listener) }
  }

  start(): () => void {
    const changeAccount = () => {
      const account = this.adapters.wallet.status === 'connected' ? this.adapters.wallet.accountId : undefined
      const scope = walletBackupScope(this.adapters.protocol.config, account)
      if (scope === this.scope && this.state.ready) return
      this.epoch += 1
      const epoch = this.epoch
      this.vault.lock()
      clearEncryptedWalletBackup(this.scope)
      this.scope = scope
      const provider = this.adapters.crypto as CryptoProvider & { setSubject?: (accountId?: string) => Promise<void> | void }
      let subjectReady: Promise<void> | void
      try { subjectReady = provider.setSubject?.(account) }
      catch (error) { subjectReady = Promise.reject(error) }
      this.update({ ready: false, exists: false, unlocked: false, busy: false, error: undefined, updatedAt: undefined, sessionVersion: this.state.sessionVersion + 1, materialVersion: this.state.materialVersion + 1 })
      this.metadataReady = (async () => {
        try { await subjectReady }
        catch {
          if (epoch === this.epoch) this.update({ ready: false, error: 'Private key storage could not be reset for this account. Reload the app before continuing.' })
          throw new Error('The confidential worker could not switch accounts safely.')
        }
        if (epoch !== this.epoch) return
        try {
          const metadata = scope ? await this.vault.metadata(scope) : { exists: false }
          if (epoch === this.epoch) this.update({ ...metadata, ready: true })
        } catch {
          // Do not silently proceed with key creation when an existing copy
          // cannot be read. Recovery-file import remains available.
          if (epoch === this.epoch) this.update({ exists: true, ready: true, error: 'Browser key storage is unavailable. Restore your recovery file to continue.' })
        }
      })()
      void this.metadataReady.catch(() => undefined)
    }
    const unsubscribeWallet = this.adapters.wallet.subscribe(changeAccount)
    const unsubscribeBackup = subscribeEncryptedWalletBackup(() => {
      if (!this.scope || !this.vault.isUnlocked(this.scope)) return
      if (this.changingMaterial) { this.backupPersistPending = true; return }
      const epoch = this.epoch
      void this.serial(() => this.persist(epoch)).catch(() => undefined)
    })
    changeAccount()
    return () => {
      unsubscribeWallet()
      unsubscribeBackup()
      this.epoch += 1
      this.vault.lock()
      clearEncryptedWalletBackup(this.scope)
      this.scope = undefined
      this.update({ ready: false, unlocked: false })
      void this.adapters.crypto.lockWallet?.().catch(() => undefined)
    }
  }

  enroll(): Promise<void> {
    return this.action(async (epoch, scope) => {
      const payload = await this.payload(epoch)
      if (!hasMaterial(payload.walletMaterial)) throw new Error('Generate or restore confidential keys before saving them with a passkey.')
      await this.vault.enroll(scope, this.adapters.wallet.accountId!, payload)
      this.assertCurrent(epoch)
      this.update({ exists: true, unlocked: true })
      await this.refreshMetadata(epoch, scope)
      // Persistence is best effort; the recovery file remains necessary.
      void globalThis.navigator?.storage?.persist?.().catch(() => false)
    })
  }

  unlock(): Promise<void> {
    return this.action(async (epoch, scope) => {
      const current = await this.adapters.crypto.exportWalletMaterial()
      this.assertCurrent(epoch)
      if (hasMaterial(current)) throw new Error('Keys are already loaded. Save a recovery file and use Replace browser copy to replace the saved copy.')
      const payload = await this.vault.unlock(scope)
      this.assertCurrent(epoch)
      await this.adapters.crypto.importWalletMaterial(payload.walletMaterial)
      this.assertCurrent(epoch)
      if (payload.recoveryConfirmed) markEncryptedWalletBackupSaved(scope)
      else clearEncryptedWalletBackup(scope)
      this.update({ unlocked: true, sessionVersion: this.state.sessionVersion + 1, materialVersion: this.state.materialVersion + 1 })
    })
  }

  replace(): Promise<void> {
    return this.action(async (epoch, scope) => {
      const payload = await this.payload(epoch)
      if (!payload.recoveryConfirmed || !hasMaterial(payload.walletMaterial)) throw new Error('Export and confirm a recovery file for your current keys before updating the browser copy.')
      // Authenticate the existing copy without importing its older material.
      await this.vault.unlock(scope)
      this.assertCurrent(epoch)
      await this.vault.save(scope, payload)
      this.assertCurrent(epoch)
      this.update({ unlocked: true })
      await this.refreshMetadata(epoch, scope)
    })
  }

  async lock(): Promise<void> {
    const epoch = this.epoch
    if (this.scope && !this.vault.isUnlocked(this.scope) && !hasEncryptedWalletBackup(this.scope)) {
      const material = await this.adapters.crypto.exportWalletMaterial()
      this.assertCurrent(epoch)
      if (hasMaterial(material)) throw new Error('Save your keys with a passkey or confirm a recovery file before locking them.')
    }
    this.epoch += 1
    this.vault.lock()
    clearEncryptedWalletBackup(this.scope)
    this.update({ unlocked: false, busy: false, sessionVersion: this.state.sessionVersion + 1, materialVersion: this.state.materialVersion + 1 })
    await this.adapters.crypto.lockWallet?.()
  }

  remove(): Promise<void> {
    return this.action(async (epoch, scope) => {
      if (!hasEncryptedWalletBackup(scope)) throw new Error('Unlock or restore your keys and confirm a recovery file before removing this browser copy.')
      await this.vault.remove(scope)
      this.assertCurrent(epoch)
      this.update({ exists: false, unlocked: false, updatedAt: undefined })
    })
  }

  private update(update: Partial<DeviceKeyState>): void {
    this.state = { ...this.state, ...update }
    for (const listener of this.listeners) listener()
  }

  private assertCurrent(epoch: number): void {
    if (epoch !== this.epoch || !this.scope) throw new Error('The private session changed. Retry with the current account.')
  }

  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation)
    // The queue must not retain a resolved export containing private keys.
    this.queue = result.then(() => undefined, () => undefined)
    return result
  }

  private action(operation: (epoch: number, scope: string) => Promise<void>): Promise<void> {
    if (this.state.busy) return Promise.reject(new Error('Finish the current passkey action first.'))
    const epoch = this.epoch
    this.update({ busy: true, error: undefined })
    return this.serial(async () => {
      try {
        await this.metadataReady
        this.assertCurrent(epoch)
        await operation(epoch, this.scope!)
      }
      catch (error) {
        if (epoch === this.epoch) {
          this.vault.lock()
          this.update({ unlocked: false, error: message(error) })
        }
        throw error
      } finally { if (epoch === this.epoch) this.update({ busy: false }) }
    })
  }

  private async payload(epoch: number): Promise<DeviceVaultPayload> {
    const walletMaterial = await this.adapters.crypto.exportWalletMaterial()
    this.assertCurrent(epoch)
    return { walletMaterial, recoveryConfirmed: hasEncryptedWalletBackup(this.scope) }
  }

  private async persist(epoch: number): Promise<void> {
    this.assertCurrent(epoch)
    if (!this.vault.isUnlocked(this.scope!)) return
    const scope = this.scope!
    try {
      await this.vault.save(scope, await this.payload(epoch))
      this.assertCurrent(epoch)
      await this.refreshMetadata(epoch, scope)
    } catch (error) {
      if (epoch === this.epoch) {
        this.vault.lock()
        this.update({ unlocked: false, error: 'The browser copy could not be updated. Export a recovery file for your current keys before closing this page.' })
      }
      throw error
    }
  }

  private async refreshMetadata(epoch: number, scope: string): Promise<void> {
    const metadata = await this.vault.metadata(scope)
    this.assertCurrent(epoch)
    this.update(metadata)
  }
}

function hasMaterial(material: Record<string, unknown>): boolean {
  return ['keys', 'drafts', 'authKeys'].some(name => Array.isArray(material[name]) && material[name].length > 0)
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'The passkey action could not be completed.'
}
