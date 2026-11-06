export type KeyRole = 'holder' | 'broker' | 'issuer' | 'token_auditor' | 'loan_auditor';
export interface KeyReference { role: KeyRole; subjectId: string; keyId: string }
export interface EncryptionPublicKey { point: string }
export interface WalletKey extends KeyReference { secretKey: string; publicKey: EncryptionPublicKey }
export interface WalletIdentity { networkId: string; coreAccountId: string; assetId: string; profileHash: string }
export interface WalletMaterial { schema: 'confidential-lending-wallet/v1'; identity: WalletIdentity; keys: WalletKey[] }
export interface CryptoExecutor { execute<T>(method: string, params: unknown, options?: { artifactName?: string; signal?: AbortSignal }): Promise<T> }

const roles = new Set<KeyRole>(['holder', 'broker', 'issuer', 'token_auditor', 'loan_auditor']);

export function freshSeed(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

function referenceKey(reference: KeyReference): string {
  if (!roles.has(reference.role) || typeof reference.subjectId !== 'string' || reference.subjectId.length < 1 || reference.subjectId.length > 128
    || !/^(0|[1-9]\d{0,19})$/.test(reference.keyId) || BigInt(reference.keyId) > 0xffff_ffff_ffff_ffffn) throw new Error('Invalid wallet key reference');
  return JSON.stringify([reference.role, reference.subjectId, reference.keyId]);
}

/** Instantiate inside the crypto worker; only explicit backup export returns private keys. */
export class Keyring {
  readonly #keys = new Map<string, WalletKey>();
  #tail: Promise<unknown> = Promise.resolve();
  #epoch = 0;
  readonly identity: Readonly<WalletIdentity>;

  constructor(identity: WalletIdentity, readonly crypto: CryptoExecutor) { this.identity = Object.freeze({ ...identity }); }

  async generate(reference: KeyReference): Promise<EncryptionPublicKey> {
    const fixed = { ...reference };
    return this.mutate(() => this.generateInner(fixed));
  }

  private async generateInner(reference: KeyReference): Promise<EncryptionPublicKey> {
    const id = referenceKey(reference);
    const existing = this.#keys.get(id);
    if (existing) return { ...existing.publicKey };
    if (this.#keys.size >= 1024) throw new Error('Wallet key count exceeds bound');
    const epoch = this.#epoch;
    const material = await this.crypto.execute<{ secret_key: string; public_key: EncryptionPublicKey }>('keygen', { seed_hex: freshSeed() });
    if (!/^[a-f0-9]{64}$/.test(material.secret_key) || !/^[a-f0-9]{64}$/.test(material.public_key.point)) throw new Error('Invalid key generation output');
    if (epoch !== this.#epoch) throw new Error('Wallet was locked during key generation');
    this.#keys.set(id, { ...reference, secretKey: material.secret_key, publicKey: { ...material.public_key } });
    return { ...material.public_key };
  }

  publicKey(reference: KeyReference): EncryptionPublicKey {
    const key = this.#keys.get(referenceKey(reference));
    if (!key) throw new Error('Wallet key is unavailable');
    return { ...key.publicKey };
  }

  /** Private worker code uses this when constructing a witness; never send it to RPC. */
  secret(reference: KeyReference): string {
    const key = this.#keys.get(referenceKey(reference));
    if (!key) throw new Error('Wallet key is unavailable');
    return key.secretKey;
  }

  exportMaterial(): WalletMaterial {
    return { schema: 'confidential-lending-wallet/v1', identity: { ...this.identity }, keys: Array.from(this.#keys.values(), key => ({ ...key, publicKey: { ...key.publicKey } })) };
  }

  async importMaterial(value: unknown): Promise<void> {
    const fixed = structuredClone(value);
    return this.mutate(() => this.importInner(fixed));
  }

  private async importInner(value: unknown): Promise<void> {
    const epoch = this.#epoch;
    if (!value || typeof value !== 'object') throw new Error('Invalid wallet material');
    const material = value as WalletMaterial;
    if (material.schema !== 'confidential-lending-wallet/v1' || !material.identity || !Array.isArray(material.keys) || material.keys.length > 1024) throw new Error('Invalid wallet material');
    for (const field of ['networkId', 'coreAccountId', 'assetId', 'profileHash'] as const) {
      if (material.identity[field] !== this.identity[field]) throw new Error('Wallet backup belongs to a different deployment');
    }
    const staged = new Map(this.#keys);
    for (const key of material.keys) {
      const id = referenceKey(key);
      if (!/^[a-f0-9]{64}$/.test(key.secretKey) || !key.publicKey || !/^[a-f0-9]{64}$/.test(key.publicKey.point)) throw new Error('Invalid wallet key encoding');
      const existing = staged.get(id);
      if (existing && (existing.secretKey !== key.secretKey || existing.publicKey.point !== key.publicKey.point)) throw new Error('Backup would replace a different key at an existing reference');
      const derived = await this.crypto.execute<EncryptionPublicKey>('public_key_from_secret', { secret_key: key.secretKey });
      if (derived.point !== key.publicKey.point) throw new Error('Backup key does not match its public key');
      staged.set(id, { role: key.role, subjectId: key.subjectId, keyId: key.keyId, secretKey: key.secretKey, publicKey: { ...key.publicKey } });
    }
    if (staged.size > 1024) throw new Error('Wallet key count exceeds bound');
    if (epoch !== this.#epoch) throw new Error('Wallet was locked during import');
    this.#keys.clear();
    for (const [id, key] of staged) this.#keys.set(id, key);
  }

  clear(): void { this.#epoch++; this.#keys.clear(); }

  private mutate<T>(operation: () => Promise<T>): Promise<T> {
    const epoch = this.#epoch;
    const result = this.#tail.then(() => {
      if (epoch !== this.#epoch) throw new Error('Wallet was locked before this operation');
      return operation();
    });
    this.#tail = result.catch(() => {});
    return result;
  }
}
