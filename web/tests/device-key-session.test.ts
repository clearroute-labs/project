import { describe, expect, it, vi } from 'vitest'
import { DeviceKeySession } from '../src/lib/deviceKeySession'
import type { DeviceVaultPayload } from '../src/lib/deviceKeyVault'
import type { AppAdapters, CryptoProvider, DeploymentConfig, WalletAdapter } from '../src/lib/types'
import { clearEncryptedWalletBackup, hasEncryptedWalletBackup, markEncryptedWalletBackupSaved, walletBackupScope } from '../src/lib/walletBackupGate'

const config: DeploymentConfig = { networkId: 'testnet', coreAccountId: 'core.testnet', tokenAccountId: 'token.testnet', rpcUrl: 'https://rpc.testnet.near.org', cryptoProfileHash: 'a'.repeat(64), assetDecimals: 6, assetSymbol: 'TEST' }
const material = () => ({ keys: [{ private: 'test-only-key' }], drafts: [], authKeys: [] })

function setup() {
  let current: Record<string, unknown> = { keys: [] }
  const listeners = new Set<() => void>()
  const wallet = {
    accountId: 'alice.testnet', status: 'connected',
    subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener) } },
  } as WalletAdapter & { accountId: string; status: WalletAdapter['status'] }
  let unlocked = false
  const records = new Map<string, DeviceVaultPayload>()
  const vault = {
    supported: () => true,
    metadata: vi.fn(async (scope: string) => ({ exists: records.has(scope) })),
    isUnlocked: () => unlocked,
    lock: vi.fn(() => { unlocked = false }),
    enroll: vi.fn(async (scope: string, _label: string, payload: DeviceVaultPayload) => { records.set(scope, structuredClone(payload)); unlocked = true }),
    unlock: vi.fn(async (scope: string) => { unlocked = true; return structuredClone(records.get(scope)!) }),
    save: vi.fn(async (scope: string, payload: DeviceVaultPayload) => { records.set(scope, structuredClone(payload)) }),
    remove: vi.fn(async (scope: string) => { records.delete(scope); unlocked = false }),
  }
  const raw = {
    getStatus: vi.fn(async () => ({ available: true, message: 'Ready' })),
    exportWalletMaterial: vi.fn(async () => structuredClone(current)),
    importWalletMaterial: vi.fn(async (value: Record<string, unknown>) => { current = structuredClone(value) }),
    createKeyRegistration: vi.fn(async () => { current = material(); return { encryptionKeyId: '1' } }),
    prepareBrokerKeyRegistration: vi.fn(async () => ({ newKeyGenerated: false })),
    lockWallet: vi.fn(async () => { current = { keys: [] } }),
    setSubject: vi.fn(() => { current = { keys: [] } }),
    decryptPrivateBalance: vi.fn(async () => '42'),
  }
  const adapters = { wallet, protocol: { config }, crypto: raw as unknown as CryptoProvider } as AppAdapters
  const session = new DeviceKeySession(adapters, vault)
  const stop = session.start()
  const scope = walletBackupScope(config, wallet.accountId)!
  clearEncryptedWalletBackup(scope)
  return { session, raw, vault, records, wallet, scope, stop, switchAccount: (id: string) => { wallet.accountId = id; for (const listener of listeners) listener() } }
}

describe('private key session', () => {
  it('saves only encrypted-vault payloads, autosaves mutations, and preserves recovery confirmation across unlock', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      expect(f.records.get(f.scope)?.recoveryConfirmed).toBe(false)
      markEncryptedWalletBackupSaved(f.scope)
      await vi.waitFor(() => expect(f.records.get(f.scope)?.recoveryConfirmed).toBe(true))
      await f.session.lock()
      expect(hasEncryptedWalletBackup(f.scope)).toBe(false)
      await f.session.unlock()
      expect(hasEncryptedWalletBackup(f.scope)).toBe(true)
      expect(f.raw.importWalletMaterial).toHaveBeenCalledWith(material())
      await f.session.crypto.createKeyRegistration()
      expect(f.records.get(f.scope)?.recoveryConfirmed).toBe(false)
      expect(hasEncryptedWalletBackup(f.scope)).toBe(false)
    } finally { f.stop() }
  })

  it('blocks new keys while a saved copy is locked, and never overwrites a manually restored wallet during unlock', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      await f.session.lock()
      await expect(f.session.crypto.createKeyRegistration()).rejects.toThrow('Unlock your saved keys')
      await f.session.crypto.importWalletMaterial(material())
      await expect(f.session.unlock()).rejects.toThrow('Keys are already loaded')
      expect(f.vault.unlock).not.toHaveBeenCalled()
      await expect(f.session.replace()).rejects.toThrow('confirm a recovery file')
      markEncryptedWalletBackupSaved(f.scope)
      await f.session.replace()
      expect(f.records.get(f.scope)?.walletMaterial).toEqual(material())
      expect(f.session.getSnapshot().unlocked).toBe(true)
    } finally { f.stop() }
  })

  it('does not return private values from an account that changed during an operation', async () => {
    const f = setup()
    try {
      let resolve!: (value: string) => void
      f.raw.decryptPrivateBalance.mockImplementation(() => new Promise(r => { resolve = r }))
      const read = f.session.crypto.decryptPrivateBalance({} as never)
      const rejected = expect(read).rejects.toThrow('private session changed')
      await vi.waitFor(() => expect(resolve).toBeTypeOf('function'))
      f.switchAccount('bob.testnet')
      resolve('sensitive old balance')
      await rejected
      expect(f.raw.setSubject).toHaveBeenLastCalledWith('bob.testnet')
      expect(f.session.getSnapshot().unlocked).toBe(false)
    } finally { f.stop() }
  })

  it('does not import a late passkey result into a different account', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      await f.session.lock()
      let resolve!: (value: DeviceVaultPayload) => void
      f.vault.unlock.mockImplementation(() => new Promise(r => { resolve = r }))
      const unlock = f.session.unlock()
      const rejected = expect(unlock).rejects.toThrow('private session changed')
      await vi.waitFor(() => expect(resolve).toBeTypeOf('function'))
      f.switchAccount('bob.testnet')
      resolve({ walletMaterial: material(), recoveryConfirmed: true })
      await rejected
      expect(f.raw.importWalletMaterial).not.toHaveBeenCalled()
    } finally { f.stop() }
  })

  it('surfaces autosave failures without claiming that the browser copy is current', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      f.vault.save.mockRejectedValueOnce(new Error('storage full'))
      await expect(f.session.crypto.createKeyRegistration()).rejects.toThrow('storage full')
      expect(f.session.getSnapshot()).toMatchObject({ unlocked: false, error: expect.stringContaining('Export a recovery file') })
      expect(await f.session.crypto.exportWalletMaterial()).toEqual(material())
    } finally { f.stop() }
  })

  it('does not discard the only copy when locking newly generated keys', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await expect(f.session.lock()).rejects.toThrow('before locking')
      expect(f.raw.lockWallet).not.toHaveBeenCalled()
      expect(await f.session.crypto.exportWalletMaterial()).toEqual(material())
    } finally { f.stop() }
  })

  it('waits for worker account reset and blocks private work if that reset fails', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      f.raw.createKeyRegistration.mockClear()
      f.raw.setSubject.mockImplementationOnce(() => { throw new Error('worker reset failed') })
      // A synchronous transport failure is handled just like a rejected reset.
      expect(() => f.switchAccount('bob.testnet')).not.toThrow()
      await expect(f.session.crypto.createKeyRegistration()).rejects.toThrow('switch accounts safely')
      expect(f.raw.createKeyRegistration).not.toHaveBeenCalled()
      expect(f.session.getSnapshot().ready).toBe(false)
    } finally { f.stop() }
  })

  it('persists a confirmation that arrives during a pending encrypted save', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      let finish!: () => void
      f.vault.save.mockImplementationOnce(async (scope, payload) => {
        await new Promise<void>(resolve => { finish = resolve })
        f.records.set(scope, structuredClone(payload))
      })
      const mutation = f.session.crypto.createKeyRegistration()
      await vi.waitFor(() => expect(finish).toBeTypeOf('function'))
      markEncryptedWalletBackupSaved(f.scope)
      finish()
      await mutation
      await vi.waitFor(() => expect(f.records.get(f.scope)?.recoveryConfirmed).toBe(true))
    } finally { f.stop() }
  })

  it('keeps the recovery confirmation when regenerating a proof for an already backed-up broker key', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      markEncryptedWalletBackupSaved(f.scope)
      await f.session.crypto.prepareBrokerKeyRegistration({} as never)
      expect(hasEncryptedWalletBackup(f.scope)).toBe(true)
    } finally { f.stop() }
  })

  it('requires a fresh recovery file when key preparation fails after partially changing material', async () => {
    const f = setup()
    try {
      markEncryptedWalletBackupSaved(f.scope)
      f.raw.createKeyRegistration.mockRejectedValueOnce(new Error('proof generation failed'))
      await expect(f.session.crypto.createKeyRegistration()).rejects.toThrow('proof generation failed')
      expect(hasEncryptedWalletBackup(f.scope)).toBe(false)
    } finally { f.stop() }
  })

  it('requires recovery confirmation before deleting the encrypted browser copy', async () => {
    const f = setup()
    try {
      await f.session.crypto.createKeyRegistration()
      await f.session.enroll()
      await expect(f.session.remove()).rejects.toThrow('confirm a recovery file')
      expect(f.vault.remove).not.toHaveBeenCalled()
      markEncryptedWalletBackupSaved(f.scope)
      await f.session.remove()
      expect(f.records.has(f.scope)).toBe(false)
      expect(await f.session.crypto.exportWalletMaterial()).toEqual(material())
    } finally { f.stop() }
  })
})
