export interface EncryptedWalletBackup {
  version: 1; kdf: 'PBKDF2-SHA-256'; iterations: 310000; cipher: 'AES-256-GCM';
  salt: string; iv: string; ciphertext: string; createdAt: string;
}
const iterations = 310_000;
const maxBytes = 8 * 1024 * 1024;
function base64(bytes: Uint8Array): string {
  let text = '';
  for (let offset = 0; offset < bytes.length; offset += 4096) text += String.fromCharCode(...bytes.subarray(offset, offset + 4096));
  return btoa(text);
}
function decode(value: string, maximum: number): Uint8Array {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4) throw new Error('Invalid encrypted backup encoding');
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (bytes.length > maximum || base64(bytes) !== value) throw new Error('Invalid encrypted backup encoding');
  return bytes;
}
async function key(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (passphrase.length < 12 || passphrase.length > 4096) throw new Error('Use a backup passphrase between 12 and 4096 characters');
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: new Uint8Array(salt), iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Explicit file backup only; callers must not persist clear wallet material or passphrases. */
export async function encryptWalletBackup(material: object, passphrase: string): Promise<EncryptedWalletBackup> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(material));
  if (plaintext.length > maxBytes) throw new Error('Wallet backup exceeds size bound');
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(passphrase, salt), plaintext);
    return { version: 1, kdf: 'PBKDF2-SHA-256', iterations, cipher: 'AES-256-GCM', salt: base64(salt), iv: base64(iv), ciphertext: base64(new Uint8Array(ciphertext)), createdAt: new Date().toISOString() };
  } finally { plaintext.fill(0); }
}

export async function decryptWalletBackup(value: unknown, passphrase: string): Promise<Record<string, unknown>> {
  let plaintext: Uint8Array | undefined;
  try {
    if (!value || typeof value !== 'object') throw new Error();
    const backup = value as EncryptedWalletBackup;
    if (backup.version !== 1 || backup.kdf !== 'PBKDF2-SHA-256' || backup.iterations !== iterations || backup.cipher !== 'AES-256-GCM') throw new Error();
    const salt = decode(backup.salt, 16), iv = decode(backup.iv, 12), ciphertext = decode(backup.ciphertext, maxBytes + 16);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) throw new Error();
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, await key(passphrase, salt), new Uint8Array(ciphertext)));
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch { throw new Error('Unable to decrypt wallet backup; check the passphrase and file integrity'); }
  finally { plaintext?.fill(0); }
}
