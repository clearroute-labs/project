import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadArtifact, sha256Hex, validateManifest, type CryptoManifest } from '../src/index.js';

test('artifact contents must match their pinned hash and size', async () => {
  const bytes = new TextEncoder().encode('verifier artifact fixture');
  const entry = { path: 'proof.bin', sha256: await sha256Hex(bytes), bytes: bytes.length };
  const fetch = (async () => new Response(bytes)) as typeof globalThis.fetch;
  assert.deepEqual(await loadArtifact('https://example.com/artifacts/', entry, { fetch }), bytes);
  await assert.rejects(loadArtifact('https://example.com/artifacts/', { ...entry, sha256: '0'.repeat(64) }, { fetch }), /hash mismatch/);
  await assert.rejects(loadArtifact('https://example.com/artifacts/', { ...entry, bytes: 1 }, { fetch }), /exceeds/);
  await assert.rejects(loadArtifact('https://example.com/artifacts/', { ...entry, path: '../outside.bin' }, { fetch }), /escapes/);
});

test('development setup and wrong-deployment artifacts are rejected for funded releases', () => {
  const manifest: CryptoManifest = {
    schema: 'confidential-lending-artifacts/v1', profileHash: 'a'.repeat(64),
    networkId: 'sandbox', coreAccountId: 'core.test.near', setup: 'development-single-party', artifacts: {},
  };
  assert.throws(() => validateManifest(manifest, { ...manifest, funded: true }), /Development setup/);
  assert.throws(() => validateManifest(manifest, { ...manifest, networkId: 'mainnet', funded: false }), /does not match/);
});
