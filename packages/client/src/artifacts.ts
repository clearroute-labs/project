export interface ArtifactEntry {
  path: string;
  sha256: string;
  bytes: number;
}

export interface CryptoManifest {
  schema: 'confidential-lending-artifacts/v1';
  profileHash: string;
  networkId: string;
  coreAccountId: string;
  setup: 'development-single-party' | 'reviewed-ceremony';
  artifacts: Record<string, ArtifactEntry>;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
  return Array.from(digest, x => x.toString(16).padStart(2, '0')).join('');
}

export async function loadArtifact(baseUrl: string, entry: ArtifactEntry, options: { signal?: AbortSignal; maxBytes?: number; fetch?: typeof fetch } = {}): Promise<Uint8Array> {
  if (!/^[a-f0-9]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || entry.bytes > (options.maxBytes ?? 512 * 1024 * 1024)) {
    throw new Error('Invalid artifact manifest entry');
  }
  const base = new URL(baseUrl);
  const url = new URL(entry.path, base);
  if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`)) throw new Error('Artifact path escapes its configured base');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw new Error('Artifacts require HTTPS');
  const response = await (options.fetch ?? fetch)(url, { ...(options.signal ? { signal: options.signal } : {}), credentials: 'omit', redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Artifact download failed');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > entry.bytes) throw new Error('Artifact exceeds its declared size');
      chunks.push(item.value);
    }
  } catch (error) {
    await reader.cancel();
    throw error;
  } finally { reader.releaseLock(); }
  if (size !== entry.bytes) throw new Error('Artifact size mismatch');
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  if (await sha256Hex(bytes) !== entry.sha256) throw new Error('Artifact hash mismatch');
  return bytes;
}

export function validateManifest(manifest: CryptoManifest, expected: { profileHash: string; networkId: string; coreAccountId: string; funded: boolean }): void {
  if (manifest.schema !== 'confidential-lending-artifacts/v1' || manifest.profileHash !== expected.profileHash || manifest.networkId !== expected.networkId || manifest.coreAccountId !== expected.coreAccountId) throw new Error('Artifact manifest does not match this deployment');
  if (manifest.setup !== 'reviewed-ceremony' && manifest.setup !== 'development-single-party') throw new Error('Unknown setup provenance');
  if (expected.funded && manifest.setup !== 'reviewed-ceremony') throw new Error('Development setup is not permitted for a funded deployment');
}
