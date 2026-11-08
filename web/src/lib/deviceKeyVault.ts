const VAULT_FORMAT = 'confidential-lending-device-vault'
const VAULT_VERSION = 1 as const
const AES_KEY_BYTES = 32
const AES_GCM_IV_BYTES = 12
const AES_GCM_TAG_BYTES = 16
const PRF_SALT_BYTES = 32
const MAX_JSON_DEPTH = 32
const MAX_JSON_NODES = 10_000

export const DEVICE_VAULT_LIMITS = {
  maxScopeLength: 512,
  maxAccountLabelLength: 200,
  maxPayloadBytes: 1_048_576,
  maxRecordBytes: 2_500_000,
} as const

export interface DeviceVaultPayload {
  walletMaterial: Record<string, unknown>
  recoveryConfirmed: boolean
}

export interface DeviceKeyVaultStorage {
  get(scope: string): Promise<unknown | undefined>
  put(scope: string, record: unknown): Promise<void>
  /** Atomically create a record only when the scope has no existing record. */
  insertIfAbsent?(scope: string, record: unknown): Promise<boolean>
  /** Atomically delete a record only when its revision and fingerprint are unchanged. */
  compareAndRemove?(scope: string, expectedRevision: number, expectedFingerprint: string): Promise<boolean>
  remove(scope: string): Promise<void>
  /** Atomically replace a record only when its revision is unchanged. */
  compareAndPut?(scope: string, expectedRevision: number, record: unknown, expectedFingerprint: string): Promise<boolean>
  available?(): boolean
}

export interface DeviceKeyVaultCredentialTransport {
  create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null>
  get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential | null>
  available?(): boolean
}

export interface DeviceKeyVaultOptions {
  storage?: DeviceKeyVaultStorage
  credentials?: DeviceKeyVaultCredentialTransport
  crypto?: Crypto
  origin?: string
  now?: () => Date
  randomBytes?: (length: number) => Uint8Array
}

export type DeviceKeyVaultErrorCode =
  | 'unsupported'
  | 'cancelled'
  | 'credential'
  | 'exists'
  | 'missing'
  | 'locked'
  | 'stale'
  | 'corrupt'
  | 'invalid-payload'
  | 'invalid-scope'
  | 'storage-read'
  | 'storage-write'
  | 'storage-delete'

export class DeviceKeyVaultError extends Error {
  readonly code: DeviceKeyVaultErrorCode

  constructor(code: DeviceKeyVaultErrorCode, message: string) {
    super(message)
    this.name = 'DeviceKeyVaultError'
    this.code = code
  }
}

interface StoredVaultRecord {
  format: typeof VAULT_FORMAT
  version: typeof VAULT_VERSION
  revision: number
  scope: string
  origin: string
  accountLabel: string
  credentialId: string
  salt: string
  wrappedDekIv: string
  wrappedDekCiphertext: string
  payloadIv: string
  payloadCiphertext: string
  updatedAt: string
}

const STORED_RECORD_KEYS = [
  'format',
  'version',
  'revision',
  'scope',
  'origin',
  'accountLabel',
  'credentialId',
  'salt',
  'wrappedDekIv',
  'wrappedDekCiphertext',
  'payloadIv',
  'payloadCiphertext',
  'updatedAt',
] as const

const textEncoder = new TextEncoder()

function browserOrigin(): string {
  if (typeof location !== 'undefined' && typeof location.origin === 'string' && location.origin) return location.origin
  return 'unknown-origin'
}

function browserCrypto(): Crypto | undefined {
  return (globalThis as { crypto?: Crypto }).crypto
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function hasExactlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  if (Object.keys(value).length !== keys.length) return false
  return keys.every(key => Object.prototype.hasOwnProperty.call(value, key))
}

function isJsonValue(value: unknown, depth = 0, state = { nodes: 0 }): boolean {
  if (depth > MAX_JSON_DEPTH || ++state.nodes > MAX_JSON_NODES) return false
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (Array.isArray(value)) return value.every(item => isJsonValue(item, depth + 1, state))
  if (!isPlainRecord(value)) return false
  return Object.entries(value).every(([key, item]) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return false
    return key.length <= 512 && isJsonValue(item, depth + 1, state)
  })
}

function toBytes(value: unknown): Uint8Array | undefined {
  if (value instanceof Uint8Array) return new Uint8Array(value)
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0))
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView
    const buffer = view.buffer as ArrayBuffer
    return new Uint8Array(buffer.slice(view.byteOffset, view.byteOffset + view.byteLength))
  }
  return undefined
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer
}

function base64UrlEncode(value: Uint8Array): string {
  let binary = ''
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, Math.min(offset + 0x8000, value.length)))
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function base64UrlDecode(value: unknown): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(padded)
  } catch {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index]
  return difference === 0
}

function validateBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
}

function payloadBytes(payload: unknown): Uint8Array {
  if (!isPlainRecord(payload) || !hasExactlyKeys(payload, ['walletMaterial', 'recoveryConfirmed'])) {
    throw new DeviceKeyVaultError('invalid-payload', 'The device key vault payload is invalid or too large.')
  }
  if (!isPlainRecord(payload.walletMaterial) || typeof payload.recoveryConfirmed !== 'boolean' || !isJsonValue(payload)) {
    throw new DeviceKeyVaultError('invalid-payload', 'The device key vault payload is invalid or too large.')
  }
  let encoded: string
  try {
    encoded = JSON.stringify(payload)
  } catch {
    throw new DeviceKeyVaultError('invalid-payload', 'The device key vault payload is invalid or too large.')
  }
  if (typeof encoded !== 'string') throw new DeviceKeyVaultError('invalid-payload', 'The device key vault payload is invalid or too large.')
  const bytes = textEncoder.encode(encoded)
  if (bytes.length > DEVICE_VAULT_LIMITS.maxPayloadBytes) {
    throw new DeviceKeyVaultError('invalid-payload', 'The device key vault payload is invalid or too large.')
  }
  return bytes
}

function decodePayload(bytes: Uint8Array): DeviceVaultPayload {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  let validatedBytes: Uint8Array | undefined
  try {
    validatedBytes = payloadBytes(parsed)
  } catch {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  } finally {
    validatedBytes?.fill(0)
  }
  return parsed as DeviceVaultPayload
}

function validateStoredRecord(raw: unknown): StoredVaultRecord {
  if (!isPlainRecord(raw) || !hasExactlyKeys(raw, STORED_RECORD_KEYS)) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  let recordJson: string
  try {
    recordJson = JSON.stringify(raw)
  } catch {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  if (typeof recordJson !== 'string' || textEncoder.encode(recordJson).length > DEVICE_VAULT_LIMITS.maxRecordBytes) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  if (raw.format !== VAULT_FORMAT || raw.version !== VAULT_VERSION || typeof raw.revision !== 'number' || !Number.isSafeInteger(raw.revision) || raw.revision < 1) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  if (!validateBoundedString(raw.scope, DEVICE_VAULT_LIMITS.maxScopeLength) || !validateBoundedString(raw.origin, 512) || !validateBoundedString(raw.accountLabel, DEVICE_VAULT_LIMITS.maxAccountLabelLength)) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  if (!validateBoundedString(raw.credentialId, 1_024) || !validateBoundedString(raw.salt, 128) || !validateBoundedString(raw.wrappedDekIv, 64) || !validateBoundedString(raw.wrappedDekCiphertext, 256) || !validateBoundedString(raw.payloadIv, 64) || !validateBoundedString(raw.payloadCiphertext, DEVICE_VAULT_LIMITS.maxRecordBytes)) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  if (!validateBoundedString(raw.updatedAt, 64) || !Number.isFinite(Date.parse(raw.updatedAt))) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  const credentialId = base64UrlDecode(raw.credentialId)
  const salt = base64UrlDecode(raw.salt)
  const wrappedDekIv = base64UrlDecode(raw.wrappedDekIv)
  const wrappedDekCiphertext = base64UrlDecode(raw.wrappedDekCiphertext)
  const payloadIv = base64UrlDecode(raw.payloadIv)
  const payloadCiphertext = base64UrlDecode(raw.payloadCiphertext)
  if (credentialId.length === 0 || credentialId.length > 512 || salt.length !== PRF_SALT_BYTES || wrappedDekIv.length !== AES_GCM_IV_BYTES || wrappedDekCiphertext.length !== AES_KEY_BYTES + AES_GCM_TAG_BYTES || payloadIv.length !== AES_GCM_IV_BYTES || payloadCiphertext.length < AES_GCM_TAG_BYTES || payloadCiphertext.length > DEVICE_VAULT_LIMITS.maxPayloadBytes + AES_GCM_TAG_BYTES) {
    throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
  }
  return raw as unknown as StoredVaultRecord
}

function associatedData(origin: string, scope: string, label: 'dek' | 'payload'): Uint8Array {
  return textEncoder.encode(`${VAULT_FORMAT}|${VAULT_VERSION}|${origin}|${scope}|${label}`)
}

function errorName(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const name = (error as { name?: unknown }).name
  return typeof name === 'string' ? name : undefined
}

function mapCredentialError(error: unknown): DeviceKeyVaultError {
  if (error instanceof DeviceKeyVaultError) return error
  const name = errorName(error)
  if (name === 'AbortError' || name === 'NotAllowedError') return new DeviceKeyVaultError('cancelled', 'Passkey authorization was cancelled.')
  return new DeviceKeyVaultError('credential', 'Passkey authorization failed.')
}

function browserCredentialTransport(): DeviceKeyVaultCredentialTransport {
  return {
    available: () => typeof navigator !== 'undefined' && !!navigator.credentials && typeof PublicKeyCredential !== 'undefined',
    create: async options => {
      if (typeof navigator === 'undefined' || !navigator.credentials) return null
      return await navigator.credentials.create({ publicKey: options }) as PublicKeyCredential | null
    },
    get: async options => {
      if (typeof navigator === 'undefined' || !navigator.credentials) return null
      return await navigator.credentials.get({ publicKey: options }) as PublicKeyCredential | null
    },
  }
}

const VAULT_DB_NAME = 'confidential-lending-device-key-vault'
const VAULT_STORE_NAME = 'vaults'

class IndexedDbVaultStorage implements DeviceKeyVaultStorage {
  private databasePromise?: Promise<IDBDatabase>

  available(): boolean {
    return typeof indexedDB !== 'undefined'
  }

  private open(): Promise<IDBDatabase> {
    if (!this.available()) return Promise.reject(new DeviceKeyVaultError('unsupported', 'Device storage is unavailable.'))
    if (this.databasePromise) return this.databasePromise
    this.databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
      let request: IDBOpenDBRequest
      try {
        request = indexedDB.open(VAULT_DB_NAME, 1)
      } catch (error) {
        reject(error)
        return
      }
      request.onupgradeneeded = () => {
        const database = request.result
        if (!database.objectStoreNames.contains(VAULT_STORE_NAME)) database.createObjectStore(VAULT_STORE_NAME)
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed.'))
      request.onblocked = () => reject(new Error('IndexedDB open blocked.'))
    })
    return this.databasePromise
  }

  async get(scope: string): Promise<unknown | undefined> {
    const database = await this.open()
    return await new Promise<unknown | undefined>((resolve, reject) => {
      let result: unknown | undefined
      const transaction = database.transaction(VAULT_STORE_NAME, 'readonly')
      const request = transaction.objectStore(VAULT_STORE_NAME).get(scope)
      request.onsuccess = () => {
        result = request.result
      }
      request.onerror = () => reject(request.error ?? new Error('IndexedDB read failed.'))
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB read failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB read aborted.'))
      transaction.oncomplete = () => resolve(result)
    })
  }

  async put(scope: string, record: unknown): Promise<void> {
    const database = await this.open()
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(VAULT_STORE_NAME, 'readwrite')
      transaction.objectStore(VAULT_STORE_NAME).put(record, scope)
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB write failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB write aborted.'))
      transaction.oncomplete = () => resolve()
    })
  }

  async insertIfAbsent(scope: string, record: unknown): Promise<boolean> {
    const database = await this.open()
    return await new Promise<boolean>((resolve, reject) => {
      let inserted = false
      const transaction = database.transaction(VAULT_STORE_NAME, 'readwrite')
      const store = transaction.objectStore(VAULT_STORE_NAME)
      const request = store.get(scope)
      request.onsuccess = () => {
        if (request.result === undefined) {
          store.put(record, scope)
          inserted = true
        }
      }
      request.onerror = () => reject(request.error ?? new Error('IndexedDB insert failed.'))
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB insert failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB insert aborted.'))
      transaction.oncomplete = () => resolve(inserted)
    })
  }

  async compareAndPut(scope: string, expectedRevision: number, record: unknown, expectedFingerprint: string): Promise<boolean> {
    const database = await this.open()
    return await new Promise<boolean>((resolve, reject) => {
      let matches = false
      const transaction = database.transaction(VAULT_STORE_NAME, 'readwrite')
      const store = transaction.objectStore(VAULT_STORE_NAME)
      const request = store.get(scope)
      request.onsuccess = () => {
        const current = request.result
        matches = isPlainRecord(current) && current.revision === expectedRevision && recordFingerprint(current as unknown as StoredVaultRecord) === expectedFingerprint
        if (matches) store.put(record, scope)
      }
      request.onerror = () => reject(request.error ?? new Error('IndexedDB compare failed.'))
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB compare failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB compare aborted.'))
      transaction.oncomplete = () => resolve(matches)
    })
  }

  async compareAndRemove(scope: string, expectedRevision: number, expectedFingerprint: string): Promise<boolean> {
    const database = await this.open()
    return await new Promise<boolean>((resolve, reject) => {
      let removed = false
      const transaction = database.transaction(VAULT_STORE_NAME, 'readwrite')
      const store = transaction.objectStore(VAULT_STORE_NAME)
      const request = store.get(scope)
      request.onsuccess = () => {
        const current = request.result
        removed = isPlainRecord(current) && current.revision === expectedRevision && recordFingerprint(current as unknown as StoredVaultRecord) === expectedFingerprint
        if (removed) store.delete(scope)
      }
      request.onerror = () => reject(request.error ?? new Error('IndexedDB compare-delete failed.'))
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB compare-delete failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB compare-delete aborted.'))
      transaction.oncomplete = () => resolve(removed)
    })
  }

  async remove(scope: string): Promise<void> {
    const database = await this.open()
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(VAULT_STORE_NAME, 'readwrite')
      transaction.objectStore(VAULT_STORE_NAME).delete(scope)
      transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB delete failed.'))
      transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB delete aborted.'))
      transaction.oncomplete = () => resolve()
    })
  }
}

interface ActiveVault {
  scope: string
  epoch: number
  dek: CryptoKey
  revision: number
  fingerprint: string
}

function validateScope(scope: unknown): string {
  if (!validateBoundedString(scope, DEVICE_VAULT_LIMITS.maxScopeLength)) {
    throw new DeviceKeyVaultError('invalid-scope', 'The device key vault scope is invalid.')
  }
  return scope
}

function validateAccountLabel(label: unknown): string {
  if (!validateBoundedString(label, DEVICE_VAULT_LIMITS.maxAccountLabelLength)) {
    throw new DeviceKeyVaultError('invalid-payload', 'The device key vault account label is invalid.')
  }
  return label
}

function randomBytesFromCrypto(crypto: Crypto | undefined, length: number): Uint8Array {
  if (!crypto || typeof crypto.getRandomValues !== 'function') {
    throw new DeviceKeyVaultError('unsupported', 'Secure random bytes are unavailable.')
  }
  return crypto.getRandomValues(new Uint8Array(length))
}

function exactRandomBytes(randomBytes: (length: number) => Uint8Array, length: number): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = randomBytes(length)
  } catch (error) {
    if (error instanceof DeviceKeyVaultError) throw error
    throw new DeviceKeyVaultError('unsupported', 'Secure random bytes are unavailable.')
  }
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new DeviceKeyVaultError('unsupported', 'Secure random bytes are unavailable.')
  }
  return new Uint8Array(bytes)
}

function credentialRawId(credential: PublicKeyCredential): Uint8Array {
  const rawId = toBytes(credential.rawId)
  if (!rawId || rawId.length === 0 || rawId.length > 512) {
    throw new DeviceKeyVaultError('credential', 'Passkey authorization returned an invalid credential.')
  }
  return rawId
}

interface PrfOutput {
  first: Uint8Array
}

function readPrfOutput(credential: PublicKeyCredential, requireEnabled: boolean): PrfOutput | undefined {
  let extensions: unknown
  try {
    extensions = credential.getClientExtensionResults()
  } catch {
    throw new DeviceKeyVaultError('unsupported', 'This passkey does not support secure key derivation.')
  }
  if (!isPlainRecord(extensions) || !isPlainRecord(extensions.prf)) {
    throw new DeviceKeyVaultError('unsupported', 'This passkey does not support secure key derivation.')
  }
  const prf = extensions.prf
  if (prf.enabled === false || (requireEnabled && prf.enabled !== true)) {
    throw new DeviceKeyVaultError('unsupported', 'This passkey does not support secure key derivation.')
  }
  if (prf.results === undefined) return undefined
  if (!isPlainRecord(prf.results)) {
    throw new DeviceKeyVaultError('unsupported', 'This passkey does not support secure key derivation.')
  }
  const first = toBytes(prf.results.first)
  if (!first || first.length !== 32) {
    throw new DeviceKeyVaultError('unsupported', 'This passkey did not return a usable key derivation result.')
  }
  return { first }
}

function recordFingerprint(record: StoredVaultRecord): string {
  return JSON.stringify(record)
}

function timestamp(now: () => Date): string {
  try {
    const value = now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error('invalid date')
    return value.toISOString()
  } catch {
    throw new DeviceKeyVaultError('storage-write', 'The device key vault could not be saved.')
  }
}

export class DeviceKeyVault {
  private readonly storage: DeviceKeyVaultStorage
  private readonly credentials: DeviceKeyVaultCredentialTransport
  private readonly crypto?: Crypto
  private readonly origin: string
  private readonly now: () => Date
  private readonly randomBytes: (length: number) => Uint8Array
  private operationQueue: Promise<void> = Promise.resolve()
  private epoch = 0
  private active?: ActiveVault

  constructor(options: DeviceKeyVaultOptions = {}) {
    this.storage = options.storage ?? new IndexedDbVaultStorage()
    this.credentials = options.credentials ?? browserCredentialTransport()
    this.crypto = options.crypto ?? browserCrypto()
    const origin = options.origin ?? browserOrigin()
    if (!validateBoundedString(origin, 512)) throw new TypeError('A valid origin is required.')
    this.origin = origin
    this.now = options.now ?? (() => new Date())
    this.randomBytes = options.randomBytes ?? (length => randomBytesFromCrypto(this.crypto, length))
  }

  supported(): boolean {
    if (!this.crypto || !this.crypto.subtle || typeof this.crypto.subtle.encrypt !== 'function') return false
    if (!this.storageAvailable() || !this.credentialsAvailable()) return false
    return typeof this.crypto.getRandomValues === 'function' || typeof this.randomBytes === 'function'
  }

  async metadata(scope: string): Promise<{ exists: boolean; updatedAt?: string }> {
    const scopeValue = validateScope(scope)
    this.requireStorage()
    const record = await this.readRecord(scopeValue)
    if (!record) return { exists: false }
    return { exists: true, updatedAt: record.updatedAt }
  }

  async enroll(scope: string, accountLabel: string, payload: DeviceVaultPayload): Promise<void> {
    const scopeValue = validateScope(scope)
    const accountLabelValue = validateAccountLabel(accountLabel)
    const encodedPayload = payloadBytes(payload)
    try {
      this.requireSupported()
    } catch (error) {
      encodedPayload.fill(0)
      throw error
    }
    const invocationEpoch = this.epoch
    return await this.enqueue(async () => {
      try {
        this.assertEpoch(invocationEpoch)
        const operationEpoch = invocationEpoch
        const existing = await this.readRecord(scopeValue)
        this.assertEpoch(operationEpoch)
        if (existing) throw new DeviceKeyVaultError('exists', 'A device key vault already exists for this account.')

        let salt: Uint8Array | undefined
        let challenge: Uint8Array | undefined
        let userId: Uint8Array | undefined
        let prfOutput: Uint8Array | undefined
        let rawDek: Uint8Array | undefined
        let wrappedDek: Uint8Array | undefined
        let encryptedPayload: Uint8Array | undefined
        try {
          salt = exactRandomBytes(this.randomBytes, PRF_SALT_BYTES)
          challenge = exactRandomBytes(this.randomBytes, 32)
          userId = exactRandomBytes(this.randomBytes, 16)
          const credential = await this.createCredential(accountLabelValue, salt, challenge, userId)
          this.assertEpoch(operationEpoch)
          prfOutput = credential.prf
          const kek = await this.deriveKek(prfOutput, salt, scopeValue)
          this.assertEpoch(operationEpoch)
          rawDek = exactRandomBytes(this.randomBytes, AES_KEY_BYTES)
          const dek = await this.importDek(rawDek)
          const wrappedDekIv = exactRandomBytes(this.randomBytes, AES_GCM_IV_BYTES)
          wrappedDek = await this.encrypt(kek, rawDek, wrappedDekIv, associatedData(this.origin, scopeValue, 'dek'))
          this.assertEpoch(operationEpoch)
          const payloadIv = exactRandomBytes(this.randomBytes, AES_GCM_IV_BYTES)
          encryptedPayload = await this.encrypt(dek, encodedPayload, payloadIv, associatedData(this.origin, scopeValue, 'payload'))
          this.assertEpoch(operationEpoch)

          const record: StoredVaultRecord = {
            format: VAULT_FORMAT,
            version: VAULT_VERSION,
            revision: 1,
            scope: scopeValue,
            origin: this.origin,
            accountLabel: accountLabelValue,
            credentialId: base64UrlEncode(credential.credentialId),
            salt: base64UrlEncode(salt),
            wrappedDekIv: base64UrlEncode(wrappedDekIv),
            wrappedDekCiphertext: base64UrlEncode(wrappedDek),
            payloadIv: base64UrlEncode(payloadIv),
            payloadCiphertext: base64UrlEncode(encryptedPayload),
            updatedAt: timestamp(this.now),
          }
          validateStoredRecord(record)
          const inserted = await this.insertRecord(scopeValue, record)
          if (!inserted) throw new DeviceKeyVaultError('exists', 'A device key vault already exists for this account.')
          this.assertEpoch(operationEpoch)
          this.active = {
            scope: scopeValue,
            epoch: operationEpoch,
            dek,
            revision: record.revision,
            fingerprint: recordFingerprint(record),
          }
        } finally {
          salt?.fill(0)
          challenge?.fill(0)
          userId?.fill(0)
          prfOutput?.fill(0)
          rawDek?.fill(0)
          wrappedDek?.fill(0)
          encryptedPayload?.fill(0)
        }
      } finally {
        encodedPayload.fill(0)
      }
    })
  }

  async unlock(scope: string): Promise<DeviceVaultPayload> {
    const scopeValue = validateScope(scope)
    this.requireSupported()
    const invocationEpoch = this.epoch
    return await this.enqueue(async () => {
      this.assertEpoch(invocationEpoch)
      const operationEpoch = invocationEpoch
      const record = await this.readRecord(scopeValue)
      this.assertEpoch(operationEpoch)
      if (!record) throw new DeviceKeyVaultError('missing', 'No device key vault exists for this account.')

      const credentialId = base64UrlDecode(record.credentialId)
      const salt = base64UrlDecode(record.salt)
      let prfOutput: Uint8Array | undefined
      let wrappedDek: Uint8Array | undefined
      let rawDek: Uint8Array | undefined
      let encryptedPayload: Uint8Array | undefined
      let plaintextPayload: Uint8Array | undefined
      try {
        const credential = await this.getCredential(credentialId, salt)
        this.assertEpoch(operationEpoch)
        prfOutput = credential.prf
        const kek = await this.deriveKek(prfOutput, salt, scopeValue)
        this.assertEpoch(operationEpoch)
        const wrappedDekIv = base64UrlDecode(record.wrappedDekIv)
        wrappedDek = base64UrlDecode(record.wrappedDekCiphertext)
        rawDek = await this.decrypt(kek, wrappedDek, wrappedDekIv, associatedData(this.origin, scopeValue, 'dek'))
        if (rawDek.length !== AES_KEY_BYTES) throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
        const dek = await this.importDek(rawDek)
        const payloadIv = base64UrlDecode(record.payloadIv)
        encryptedPayload = base64UrlDecode(record.payloadCiphertext)
        plaintextPayload = await this.decrypt(dek, encryptedPayload, payloadIv, associatedData(this.origin, scopeValue, 'payload'))
        const payload = decodePayload(plaintextPayload)
        this.assertEpoch(operationEpoch)
        this.active = {
          scope: scopeValue,
          epoch: operationEpoch,
          dek,
          revision: record.revision,
          fingerprint: recordFingerprint(record),
        }
        return payload
      } finally {
        prfOutput?.fill(0)
        wrappedDek?.fill(0)
        rawDek?.fill(0)
        encryptedPayload?.fill(0)
        plaintextPayload?.fill(0)
        credentialId.fill(0)
        salt.fill(0)
      }
    })
  }

  async save(scope: string, payload: DeviceVaultPayload): Promise<void> {
    const scopeValue = validateScope(scope)
    const encodedPayload = payloadBytes(payload)
    try {
      this.requireStorageAndCrypto()
    } catch (error) {
      encodedPayload.fill(0)
      throw error
    }
    const invocationEpoch = this.epoch
    const invocationActive = this.active
    return await this.enqueue(async () => {
      try {
        this.assertEpoch(invocationEpoch)
        const active = invocationActive
        if (!active || active.scope !== scopeValue) {
          throw new DeviceKeyVaultError('locked', 'Unlock the device key vault before saving.')
        }
        const operationEpoch = invocationEpoch
        let encryptedPayload: Uint8Array | undefined
        try {
          const record = await this.readRecord(scopeValue)
          this.assertActive(active, operationEpoch, scopeValue)
          if (!record) throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before saving.')
          if (record.revision !== active.revision || recordFingerprint(record) !== active.fingerprint) {
            throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before saving.')
          }
          if (record.revision >= Number.MAX_SAFE_INTEGER) {
            throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before saving.')
          }
          const payloadIv = exactRandomBytes(this.randomBytes, AES_GCM_IV_BYTES)
          encryptedPayload = await this.encrypt(active.dek, encodedPayload, payloadIv, associatedData(this.origin, scopeValue, 'payload'))
          this.assertActive(active, operationEpoch, scopeValue)
          const nextRecord: StoredVaultRecord = {
            ...record,
            revision: record.revision + 1,
            payloadIv: base64UrlEncode(payloadIv),
            payloadCiphertext: base64UrlEncode(encryptedPayload),
            updatedAt: timestamp(this.now),
          }
          validateStoredRecord(nextRecord)
          let replaced = true
          if (this.storage.compareAndPut) {
            try {
              replaced = await this.storage.compareAndPut(scopeValue, record.revision, nextRecord, active.fingerprint)
            } catch {
              throw new DeviceKeyVaultError('storage-write', 'The device key vault could not be saved.')
            }
          } else {
            await this.writeRecord(scopeValue, nextRecord)
          }
          if (!replaced) throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before saving.')
          this.assertActive(active, operationEpoch, scopeValue)
          this.active = {
            ...active,
            revision: nextRecord.revision,
            fingerprint: recordFingerprint(nextRecord),
          }
        } finally {
          encryptedPayload?.fill(0)
        }
      } finally {
        encodedPayload.fill(0)
      }
    })
  }

  lock(): void {
    this.epoch += 1
    this.active = undefined
  }

  async remove(scope: string): Promise<void> {
    const scopeValue = validateScope(scope)
    const expectedActive = this.active?.scope === scopeValue ? this.active : undefined
    this.lock()
    this.requireStorage()
    const invocationEpoch = this.epoch
    return await this.enqueue(async () => {
      this.assertEpoch(invocationEpoch)
      const current = await this.readRecord(scopeValue)
      this.assertEpoch(invocationEpoch)
      if (!current) return
      if (expectedActive && (current.revision !== expectedActive.revision || recordFingerprint(current) !== expectedActive.fingerprint)) {
        throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before removing.')
      }
      const expectedRevision = expectedActive?.revision ?? current.revision
      const expectedFingerprint = expectedActive?.fingerprint ?? recordFingerprint(current)
      if (this.storage.compareAndRemove) {
        let removed: boolean
        try {
          removed = await this.storage.compareAndRemove(scopeValue, expectedRevision, expectedFingerprint)
        } catch {
          throw new DeviceKeyVaultError('storage-delete', 'The device key vault could not be removed.')
        }
        if (!removed) throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before removing.')
        return
      }
      const latest = await this.readRecord(scopeValue)
      this.assertEpoch(invocationEpoch)
      if (!latest || latest.revision !== expectedRevision || recordFingerprint(latest) !== expectedFingerprint) {
        throw new DeviceKeyVaultError('stale', 'The stored device key vault changed; unlock it again before removing.')
      }
      try {
        await this.storage.remove(scopeValue)
      } catch {
        throw new DeviceKeyVaultError('storage-delete', 'The device key vault could not be removed.')
      }
    })
  }

  isUnlocked(scope: string): boolean {
    return typeof scope === 'string' && this.active?.scope === scope
  }

  private storageAvailable(): boolean {
    try {
      return this.storage.available ? this.storage.available() : true
    } catch {
      return false
    }
  }

  private credentialsAvailable(): boolean {
    try {
      return this.credentials.available ? this.credentials.available() : true
    } catch {
      return false
    }
  }

  private requireStorage(): void {
    if (!this.storageAvailable()) throw new DeviceKeyVaultError('unsupported', 'Device storage is unavailable.')
  }

  private requireStorageAndCrypto(): void {
    this.requireStorage()
    if (!this.crypto || !this.crypto.subtle || typeof this.crypto.subtle.encrypt !== 'function') {
      throw new DeviceKeyVaultError('unsupported', 'Secure encryption is unavailable.')
    }
  }

  private requireSupported(): void {
    if (!this.supported()) throw new DeviceKeyVaultError('unsupported', 'Passkeys with secure key derivation are unavailable.')
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.operationQueue.then(operation, operation)
    this.operationQueue = next.then(() => undefined, () => undefined)
    return next
  }

  private assertEpoch(operationEpoch: number): void {
    if (this.epoch !== operationEpoch) throw new DeviceKeyVaultError('stale', 'The device key vault operation is no longer current.')
  }

  private assertActive(active: ActiveVault, operationEpoch: number, scope: string): void {
    this.assertEpoch(operationEpoch)
    if (this.active !== active || active.scope !== scope) {
      throw new DeviceKeyVaultError('stale', 'The device key vault operation is no longer current.')
    }
  }

  private async readRecord(scope: string): Promise<StoredVaultRecord | undefined> {
    this.requireStorage()
    let raw: unknown | undefined
    try {
      raw = await this.storage.get(scope)
    } catch {
      throw new DeviceKeyVaultError('storage-read', 'The device key vault could not be read.')
    }
    if (raw === undefined) return undefined
    const record = validateStoredRecord(raw)
    if (record.scope !== scope || record.origin !== this.origin) {
      throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
    }
    return record
  }

  private async writeRecord(scope: string, record: StoredVaultRecord): Promise<void> {
    try {
      await this.storage.put(scope, record)
    } catch {
      throw new DeviceKeyVaultError('storage-write', 'The device key vault could not be saved.')
    }
  }

  private async insertRecord(scope: string, record: StoredVaultRecord): Promise<boolean> {
    if (this.storage.insertIfAbsent) {
      try {
        return await this.storage.insertIfAbsent(scope, record)
      } catch {
        throw new DeviceKeyVaultError('storage-write', 'The device key vault could not be saved.')
      }
    }
    const existing = await this.readRecord(scope)
    if (existing) return false
    await this.writeRecord(scope, record)
    return true
  }

  private subtle(): SubtleCrypto {
    if (!this.crypto?.subtle) throw new DeviceKeyVaultError('unsupported', 'Secure encryption is unavailable.')
    return this.crypto.subtle
  }

  private async deriveKek(prfOutput: Uint8Array, salt: Uint8Array, scope: string): Promise<CryptoKey> {
    const subtle = this.subtle()
    const prfCopy = new Uint8Array(prfOutput)
    try {
      const prfKey = await subtle.importKey('raw', toArrayBuffer(prfCopy), 'HKDF', false, ['deriveKey'])
      return await subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: toArrayBuffer(salt),
          info: toArrayBuffer(associatedData(this.origin, scope, 'dek')),
        },
        prfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      )
    } catch {
      throw new DeviceKeyVaultError('credential', 'Passkey authorization could not derive the vault key.')
    } finally {
      prfCopy.fill(0)
    }
  }

  private async importDek(rawDek: Uint8Array): Promise<CryptoKey> {
    try {
      return await this.subtle().importKey('raw', toArrayBuffer(rawDek), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
    } catch {
      throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
    }
  }

  private async encrypt(key: CryptoKey, plaintext: Uint8Array, iv: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
    try {
      const encrypted = await this.subtle().encrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(additionalData), tagLength: 128 },
        key,
        toArrayBuffer(plaintext),
      )
      return new Uint8Array(encrypted)
    } catch {
      throw new DeviceKeyVaultError('storage-write', 'The device key vault could not be encrypted.')
    }
  }

  private async decrypt(key: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
    try {
      const decrypted = await this.subtle().decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(additionalData), tagLength: 128 },
        key,
        toArrayBuffer(ciphertext),
      )
      return new Uint8Array(decrypted)
    } catch {
      throw new DeviceKeyVaultError('corrupt', 'The device key vault is corrupted or unreadable.')
    }
  }

  private async createCredential(accountLabel: string, salt: Uint8Array, challenge: Uint8Array, userId: Uint8Array): Promise<{ credentialId: Uint8Array; prf: Uint8Array }> {
    let created: PublicKeyCredential | null
    try {
      created = await this.credentials.create({
        challenge: toArrayBuffer(challenge),
        rp: { name: 'Confidential Lending' },
        user: { id: toArrayBuffer(userId), name: accountLabel, displayName: accountLabel },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        attestation: 'none',
        extensions: { prf: { eval: { first: toArrayBuffer(salt) } } },
      } as unknown as PublicKeyCredentialCreationOptions)
    } catch (error) {
      throw mapCredentialError(error)
    }
    if (!created) throw new DeviceKeyVaultError('cancelled', 'Passkey authorization was cancelled.')
    const credentialId = credentialRawId(created)
    let prf = readPrfOutput(created, true)
    if (!prf) {
      const assertion = await this.getCredential(credentialId, salt)
      prf = { first: assertion.prf }
    }
    return { credentialId, prf: prf.first }
  }

  private async getCredential(credentialId: Uint8Array, salt: Uint8Array): Promise<{ credentialId: Uint8Array; prf: Uint8Array }> {
    const challenge = exactRandomBytes(this.randomBytes, 32)
    try {
      let credential: PublicKeyCredential | null
      try {
        credential = await this.credentials.get({
          challenge: toArrayBuffer(challenge),
          allowCredentials: [{ type: 'public-key', id: toArrayBuffer(credentialId) }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: toArrayBuffer(salt) } } },
        } as unknown as PublicKeyCredentialRequestOptions)
      } catch (error) {
        throw mapCredentialError(error)
      }
      if (!credential) throw new DeviceKeyVaultError('cancelled', 'Passkey authorization was cancelled.')
      const returnedId = credentialRawId(credential)
      if (!constantTimeEqual(returnedId, credentialId)) {
        throw new DeviceKeyVaultError('credential', 'Passkey authorization returned an unexpected credential.')
      }
      const prf = readPrfOutput(credential, false)
      if (!prf) throw new DeviceKeyVaultError('unsupported', 'This passkey did not return a usable key derivation result.')
      return { credentialId: returnedId, prf: prf.first }
    } finally {
      challenge.fill(0)
    }
  }
}
