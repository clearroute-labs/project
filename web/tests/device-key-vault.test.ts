import { describe, expect, it } from 'vitest'
import {
  DEVICE_VAULT_LIMITS,
  DeviceKeyVault,
  DeviceKeyVaultError,
  type DeviceKeyVaultCredentialTransport,
  type DeviceKeyVaultStorage,
} from '../src/lib/deviceKeyVault'

const testCrypto = globalThis.crypto

function copy<T>(value: T): T {
  return structuredClone(value)
}

class MemoryStorage implements DeviceKeyVaultStorage {
  readonly records = new Map<string, unknown>()
  readonly events: string[] = []

  get(scope: string): Promise<unknown | undefined> {
    return Promise.resolve(this.records.has(scope) ? copy(this.records.get(scope)) : undefined)
  }

  put(scope: string, record: unknown): Promise<void> {
    this.events.push('put')
    this.records.set(scope, copy(record))
    return Promise.resolve()
  }

  insertIfAbsent(scope: string, record: unknown): Promise<boolean> {
    if (this.records.has(scope)) return Promise.resolve(false)
    this.records.set(scope, copy(record))
    this.events.push('insert')
    return Promise.resolve(true)
  }

  compareAndPut(scope: string, expectedRevision: number, record: unknown, expectedFingerprint: string): Promise<boolean> {
    const current = this.records.get(scope)
    if (!current || typeof current !== 'object' || (current as { revision?: unknown }).revision !== expectedRevision || JSON.stringify(current) !== expectedFingerprint) return Promise.resolve(false)
    this.events.push('compare-and-put')
    this.records.set(scope, copy(record))
    return Promise.resolve(true)
  }

  compareAndRemove(scope: string, expectedRevision: number, expectedFingerprint: string): Promise<boolean> {
    const current = this.records.get(scope)
    if (!current || typeof current !== 'object' || (current as { revision?: unknown }).revision !== expectedRevision || JSON.stringify(current) !== expectedFingerprint) return Promise.resolve(false)
    this.events.push('compare-and-remove')
    this.records.delete(scope)
    return Promise.resolve(true)
  }

  remove(scope: string): Promise<void> {
    this.events.push('remove')
    this.records.delete(scope)
    return Promise.resolve()
  }

  available(): boolean {
    return true
  }
}

interface CredentialOptions {
  id?: Uint8Array
  prf?: Uint8Array
  registrationHasResult?: boolean
  enabled?: boolean
  getError?: unknown
}

class FakeCredentials implements DeviceKeyVaultCredentialTransport {
  readonly id: Uint8Array
  prf: Uint8Array
  registrationHasResult: boolean
  enabled: boolean
  getError?: unknown
  createCount = 0
  getCount = 0
  createOptions: PublicKeyCredentialCreationOptions[] = []
  getOptions: PublicKeyCredentialRequestOptions[] = []

  constructor(options: CredentialOptions = {}) {
    this.id = options.id ? new Uint8Array(options.id) : Uint8Array.from([11, 22, 33, 44])
    this.prf = options.prf ? new Uint8Array(options.prf) : Uint8Array.from({ length: 32 }, (_, index) => index + 1)
    this.registrationHasResult = options.registrationHasResult ?? false
    this.enabled = options.enabled ?? true
    this.getError = options.getError
  }

  available(): boolean {
    return true
  }

  create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential> {
    this.createCount += 1
    this.createOptions.push(options)
    const extensions = this.enabled
      ? { prf: { enabled: true, ...(this.registrationHasResult ? { results: { first: this.prf.buffer.slice(0) } } : {}) } }
      : { prf: { enabled: false } }
    return Promise.resolve(fakeCredential(this.id, extensions))
  }

  get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential> {
    this.getCount += 1
    this.getOptions.push(options)
    if (this.getError !== undefined) return Promise.reject(this.getError)
    const extensions = this.enabled ? { prf: { results: { first: this.prf.buffer.slice(0) } } } : { prf: { enabled: false } }
    return Promise.resolve(fakeCredential(this.id, extensions))
  }
}

class DeferredCredentials extends FakeCredentials {
  private readonly pending: Promise<PublicKeyCredential>
  private resolvePending!: (credential: PublicKeyCredential) => void

  constructor() {
    super()
    this.pending = new Promise(resolve => {
      this.resolvePending = resolve
    })
  }

  override get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential> {
    this.getCount += 1
    this.getOptions.push(options)
    return this.pending
  }

  resolveGet(): void {
    this.resolvePending(fakeCredential(this.id, { prf: { results: { first: this.prf.buffer.slice(0) } } }))
  }
}

class BlockingCasStorage extends MemoryStorage {
  started = Promise.resolve()
  release!: () => void
  private resolveStarted!: () => void

  constructor() {
    super()
    this.started = new Promise(resolve => {
      this.resolveStarted = resolve
    })
  }

  override compareAndPut(scope: string, expectedRevision: number, record: unknown, expectedFingerprint: string): Promise<boolean> {
    this.events.push('compare-and-put-start')
    this.resolveStarted()
    return new Promise(resolve => {
      this.release = () => {
        const current = this.records.get(scope)
        if (!current || typeof current !== 'object' || (current as { revision?: unknown }).revision !== expectedRevision || JSON.stringify(current) !== expectedFingerprint) {
          resolve(false)
          return
        }
        this.events.push('compare-and-put')
        this.records.set(scope, copy(record))
        resolve(true)
      }
    })
  }
}

function fakeCredential(id: Uint8Array, extensions: unknown): PublicKeyCredential {
  const rawId = id.buffer.slice(id.byteOffset, id.byteOffset + id.byteLength)
  return {
    rawId,
    getClientExtensionResults: () => copy(extensions),
  } as unknown as PublicKeyCredential
}

function makeVault(storage: DeviceKeyVaultStorage, credentials: DeviceKeyVaultCredentialTransport): DeviceKeyVault {
  if (!testCrypto) throw new Error('WebCrypto is required for these tests.')
  return new DeviceKeyVault({ storage, credentials, crypto: testCrypto, origin: 'http://localhost:5175' })
}

const payload = {
  walletMaterial: { accountId: 'alice.testnet', privateKey: 'private-key-never-log' },
  recoveryConfirmed: true,
}

describe('device key vault', () => {
  it('round-trips using PRF-derived wrapping and does not store plaintext', async () => {
    const storage = new MemoryStorage()
    const credentials = new FakeCredentials()
    const vault = makeVault(storage, credentials)

    expect(vault.supported()).toBe(true)
    await vault.enroll('testnet:alice.testnet', 'alice.testnet', payload)
    expect(vault.isUnlocked('testnet:alice.testnet')).toBe(true)
    const stored = JSON.stringify(storage.records.get('testnet:alice.testnet'))
    expect(stored).not.toContain('private-key-never-log')
    await expect(vault.unlock('testnet:alice.testnet')).resolves.toEqual(payload)
    await vault.save('testnet:alice.testnet', { ...payload, recoveryConfirmed: false })
    vault.lock()
    await expect(vault.unlock('testnet:alice.testnet')).resolves.toEqual({ ...payload, recoveryConfirmed: false })
    expect(credentials.createOptions[0].authenticatorSelection?.userVerification).toBe('required')
    expect(credentials.getOptions[0].userVerification).toBe('required')
  })

  it('rejects wrong credential and wrong PRF output', async () => {
    const storage = new MemoryStorage()
    const original = new FakeCredentials()
    const vault = makeVault(storage, original)
    await vault.enroll('scope', 'account', payload)
    vault.lock()

    const wrongCredential = makeVault(storage, new FakeCredentials({ id: Uint8Array.from([1, 2, 3, 4]) }))
    await expect(wrongCredential.unlock('scope')).rejects.toMatchObject({ code: 'credential' })

    const wrongPrf = makeVault(storage, new FakeCredentials({ prf: Uint8Array.from({ length: 32 }, () => 99) }))
    await expect(wrongPrf.unlock('scope')).rejects.toBeInstanceOf(DeviceKeyVaultError)
  })

  it('rejects tampering, scope mismatch, unsupported PRF, and oversized input', async () => {
    const storage = new MemoryStorage()
    const credentials = new FakeCredentials()
    const vault = makeVault(storage, credentials)
    await vault.enroll('scope', 'account', payload)

    const tampered = copy(storage.records.get('scope')) as { payloadCiphertext: string }
    tampered.payloadCiphertext = `${tampered.payloadCiphertext.slice(0, -1)}${tampered.payloadCiphertext.endsWith('A') ? 'B' : 'A'}`
    storage.records.set('scope', tampered)
    vault.lock()
    await expect(vault.unlock('scope')).rejects.toMatchObject({ code: 'corrupt' })

    const mismatched = copy(storage.records.get('scope')) as { scope: string }
    mismatched.scope = 'other-scope'
    storage.records.set('scope', mismatched)
    await expect(vault.metadata('scope')).rejects.toMatchObject({ code: 'corrupt' })

    const unsupportedStorage = new MemoryStorage()
    const unsupported = makeVault(unsupportedStorage, new FakeCredentials({ enabled: false }))
    await expect(unsupported.enroll('scope', 'account', payload)).rejects.toMatchObject({ code: 'unsupported' })
    await expect(unsupported.enroll('scope', 'account', { walletMaterial: { tooBig: 'x'.repeat(DEVICE_VAULT_LIMITS.maxPayloadBytes) }, recoveryConfirmed: false })).rejects.toMatchObject({ code: 'invalid-payload' })
    expect((await unsupported.metadata('scope')).exists).toBe(false)
  })

  it('maps cancellation and prevents re-enrollment from replacing an existing vault', async () => {
    const storage = new MemoryStorage()
    const first = new FakeCredentials()
    const cancelled: DeviceKeyVaultCredentialTransport = {
      available: () => true,
      create: () => Promise.reject({ name: 'AbortError' }),
      get: first.get.bind(first),
    }
    await expect(makeVault(storage, cancelled).enroll('cancelled', 'account', payload)).rejects.toMatchObject({ code: 'cancelled' })
    const vault = makeVault(storage, first)
    await vault.enroll('scope', 'account', payload)
    const existing = copy(storage.records.get('scope'))
    const second = new FakeCredentials()
    await expect(makeVault(storage, second).enroll('scope', 'new-account', { ...payload, recoveryConfirmed: false })).rejects.toMatchObject({ code: 'exists' })
    expect(second.createCount).toBe(0)
    expect(storage.records.get('scope')).toEqual(existing)
  })

  it('invalidates an unlock after lock and serializes save before remove', async () => {
    const storage = new MemoryStorage()
    const first = new FakeCredentials()
    const vault = makeVault(storage, first)
    await vault.enroll('scope', 'account', payload)
    vault.lock()

    const deferredCredentials = new DeferredCredentials()
    const staleVault = makeVault(storage, deferredCredentials)
    const pendingUnlock = staleVault.unlock('scope')
    await new Promise<void>(resolve => {
      const waitForGet = () => deferredCredentials.getCount > 0 ? resolve() : setTimeout(waitForGet, 0)
      waitForGet()
    })
    staleVault.lock()
    deferredCredentials.resolveGet()
    await expect(pendingUnlock).rejects.toMatchObject({ code: 'stale' })

    const blocking = new BlockingCasStorage()
    const saveVault = makeVault(blocking, new FakeCredentials())
    await saveVault.enroll('scope', 'account', payload)
    const pendingSave = saveVault.save('scope', { ...payload, recoveryConfirmed: false })
    await blocking.started
    const pendingRemove = saveVault.remove('scope')
    blocking.release()
    await expect(pendingSave).rejects.toMatchObject({ code: 'stale' })
    await expect(pendingRemove).rejects.toMatchObject({ code: 'stale' })
    expect((await saveVault.metadata('scope')).exists).toBe(true)
    await saveVault.remove('scope')
    expect((await saveVault.metadata('scope')).exists).toBe(false)
    expect(blocking.events.slice(-2)).toEqual(['compare-and-put', 'compare-and-remove'])
  })

  it('does not let two tabs race an enrollment or start queued work after lock', async () => {
    const storage = new MemoryStorage()
    const first = makeVault(storage, new FakeCredentials())
    const second = makeVault(storage, new FakeCredentials())
    const results = await Promise.allSettled([
      first.enroll('long:'.repeat(80), 'account', payload),
      second.enroll('long:'.repeat(80), 'account', payload),
    ])
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1)
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1)
    const rejected = results.find(result => result.status === 'rejected')
    expect(rejected && rejected.status === 'rejected' ? rejected.reason.code : undefined).toBe('exists')

    const queuedStorage = new MemoryStorage()
    const queuedVault = makeVault(queuedStorage, new FakeCredentials())
    const pending = queuedVault.enroll('queued', 'account', payload)
    queuedVault.lock()
    await expect(pending).rejects.toMatchObject({ code: 'stale' })
    expect((await queuedVault.metadata('queued')).exists).toBe(false)
  })

  it('rejects a stale tab save and deletion after another tab saved newer keys', async () => {
    const storage = new MemoryStorage()
    const first = makeVault(storage, new FakeCredentials())
    const second = makeVault(storage, new FakeCredentials())
    await first.enroll('scope', 'account', payload)
    await second.unlock('scope')
    const newer = { walletMaterial: { privateKey: 'newer-test-key' }, recoveryConfirmed: false }
    await first.save('scope', newer)
    await expect(second.save('scope', payload)).rejects.toMatchObject({ code: 'stale' })
    await expect(second.remove('scope')).rejects.toMatchObject({ code: 'stale' })
    await expect(first.unlock('scope')).resolves.toEqual(newer)
  })

  it('rejects unknown envelope versions and binds ciphertext to the browser origin', async () => {
    const storage = new MemoryStorage()
    const vault = makeVault(storage, new FakeCredentials())
    await vault.enroll('scope', 'account', payload)
    const original = copy(storage.records.get('scope')) as Record<string, unknown>
    storage.records.set('scope', { ...original, version: 99 })
    await expect(vault.unlock('scope')).rejects.toMatchObject({ code: 'corrupt' })
    storage.records.set('scope', { ...original, origin: 'https://different.example' })
    const differentOrigin = new DeviceKeyVault({ storage, credentials: new FakeCredentials(), crypto: testCrypto, origin: 'https://different.example' })
    await expect(differentOrigin.unlock('scope')).rejects.toMatchObject({ code: 'corrupt' })
  })

  it('cannot overwrite a newly enrolled vault even when its revision matches the old one', async () => {
    const storage = new BlockingCasStorage()
    const first = makeVault(storage, new FakeCredentials())
    await first.enroll('scope', 'account', payload)
    const pending = first.save('scope', { ...payload, recoveryConfirmed: false })
    const rejected = expect(pending).rejects.toMatchObject({ code: 'stale' })
    await storage.started
    // Another tab removes and enrolls a different credential at revision one.
    storage.records.delete('scope')
    const second = makeVault(storage, new FakeCredentials({ id: Uint8Array.of(5, 6, 7, 8) }))
    await second.enroll('scope', 'account', payload)
    const replacement = copy(storage.records.get('scope'))
    storage.release()
    await rejected
    expect(storage.records.get('scope')).toEqual(replacement)
  })
})
