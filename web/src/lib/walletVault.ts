import type { EncryptedWalletBackup } from './types'

const PBKDF2_ITERATIONS = 310_000

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const result = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) result[index] = binary.charCodeAt(index)
  return result
}

function asBufferSource(bytes: Uint8Array): BufferSource {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function assertPassphrase(passphrase: string): void {
  if (passphrase.length < 12) {
    throw new Error('Use a passphrase of at least 12 characters for the encrypted backup.')
  }
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  assertPassphrase(passphrase)
  const material = await globalThis.crypto.subtle.importKey(
    'raw',
    asBufferSource(new TextEncoder().encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: asBufferSource(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Encrypts wallet material for a user-selected backup file. The application
 * never writes the supplied payload or passphrase to localStorage.
 */
export async function encryptWalletBackup(
  walletMaterial: Record<string, unknown>,
  passphrase: string,
): Promise<EncryptedWalletBackup> {
  assertPassphrase(passphrase)
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16))
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(passphrase, salt)
  const plaintext = new TextEncoder().encode(JSON.stringify(walletMaterial))
  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: asBufferSource(iv) }, key, asBufferSource(plaintext)),
  )
  return {
    version: 1,
    kdf: 'PBKDF2-SHA-256',
    iterations: PBKDF2_ITERATIONS,
    cipher: 'AES-256-GCM',
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    createdAt: new Date().toISOString(),
  }
}

export async function decryptWalletBackup(
  backup: EncryptedWalletBackup,
  passphrase: string,
): Promise<Record<string, unknown>> {
  if (backup.version !== 1 || backup.kdf !== 'PBKDF2-SHA-256' || backup.cipher !== 'AES-256-GCM') {
    throw new Error('This backup uses an unsupported encryption format.')
  }
  if (backup.iterations !== PBKDF2_ITERATIONS) {
    throw new Error('This backup uses an unsupported key-derivation setting.')
  }
  const salt = fromBase64(backup.salt)
  const iv = fromBase64(backup.iv)
  const key = await deriveKey(passphrase, salt)
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv) },
      key,
      asBufferSource(fromBase64(backup.ciphertext)),
    )
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid backup payload.')
    return parsed as Record<string, unknown>
  } catch {
    throw new Error('Unable to decrypt this backup. Check the passphrase or file integrity.')
  }
}

export function downloadWalletBackup(backup: EncryptedWalletBackup, filename = 'private-ledger-wallet.backup.json'): void {
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export async function readWalletBackup(file: File): Promise<EncryptedWalletBackup> {
  const parsed = JSON.parse(await file.text()) as Partial<EncryptedWalletBackup>
  if (
    parsed.version !== 1 ||
    parsed.kdf !== 'PBKDF2-SHA-256' ||
    parsed.cipher !== 'AES-256-GCM' ||
    typeof parsed.salt !== 'string' ||
    typeof parsed.iv !== 'string' ||
    typeof parsed.ciphertext !== 'string' ||
    typeof parsed.iterations !== 'number'
  ) {
    throw new Error('The selected file is not a valid encrypted wallet backup.')
  }
  return parsed as EncryptedWalletBackup
}
