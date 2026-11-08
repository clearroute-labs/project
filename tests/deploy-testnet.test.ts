import assert from 'node:assert/strict';
import test from 'node:test';
import { KeyPair } from 'near-workspaces';
import { deploymentManifest, validateCredential, validateRpcUrl } from '../scripts/deploy-testnet.js';
import { proofFamilies } from '../scripts/development-artifacts.js';
import type { CryptoManifest } from '../packages/client/src/artifacts.js';

test('deployment rejects a credential for another network or mismatched signing key', () => {
  const key = KeyPair.fromRandom('ed25519');
  const credential = { accountId: 'deployment.testnet', publicKey: key.getPublicKey().toString(), secretKey: key.toString() };
  assert.doesNotThrow(() => validateCredential(credential));
  assert.throws(() => validateCredential({ ...credential, accountId: 'deployment.near' }), /testnet/);
  assert.throws(() => validateCredential({ ...credential, publicKey: KeyPair.fromRandom('ed25519').getPublicKey().toString() }), /do not match/);
  assert.throws(() => validateCredential({ ...credential, secretKey: 'do-not-log-this-secret' }), error => error instanceof Error && !error.message.includes('do-not-log-this-secret'));
});

test('deployment RPC rejects insecure URLs and embedded credentials', () => {
  validateRpcUrl('https://test.rpc.fastnear.com');
  for (const url of ['http://test.rpc.fastnear.com', 'https://user:password@test.rpc.fastnear.com', 'https://test.rpc.fastnear.com/#token']) assert.throws(() => validateRpcUrl(url));
});

test('deployment binds all public artifacts and rejects extra files or path traversal', () => {
  const names = ['native.prover', 'browser.glue', 'browser.wasm', ...proofFamilies.flatMap(family => ['pk', 'vk', 'prepared-vk'].map(suffix => `${family}.${suffix}`))];
  const manifest: CryptoManifest = {
    schema: 'confidential-lending-artifacts/v1', setup: 'development-single-party', networkId: 'sandbox', coreAccountId: 'core.test.near', profileHash: 'a'.repeat(64),
    artifacts: Object.fromEntries(names.map(name => [name, { path: name, bytes: 1, sha256: 'b'.repeat(64) }])),
  };
  const rebound = deploymentManifest(manifest, 'core.testnet');
  assert.equal(rebound.networkId, 'testnet');
  assert.equal(rebound.coreAccountId, 'core.testnet');
  assert.deepEqual(rebound.artifacts, manifest.artifacts);
  assert.equal(manifest.networkId, 'sandbox');
  for (const path of ['..', '../credential.json', '/credential.json', 'secret-key.json']) {
    const corrupt = structuredClone(manifest);
    corrupt.artifacts['browser.glue']!.path = path;
    assert.throws(() => deploymentManifest(corrupt, 'core.testnet'), /Unsafe/);
  }
  const extra = structuredClone(manifest);
  extra.artifacts['account.credentials'] = { path: 'account.json', bytes: 1, sha256: 'c'.repeat(64) };
  assert.throws(() => deploymentManifest(extra, 'core.testnet'), /Unsafe/);
  delete extra.artifacts['account.credentials'];
  delete extra.artifacts['origination.pk'];
  assert.throws(() => deploymentManifest(extra, 'core.testnet'), /Missing/);
});
