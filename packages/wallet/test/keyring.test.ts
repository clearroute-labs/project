import test from 'node:test';
import assert from 'node:assert/strict';
import { Keyring, type CryptoExecutor, type WalletIdentity, type KeyReference } from '../src/keyring.js';

const identity: WalletIdentity = { networkId: 'sandbox', coreAccountId: 'core.test.near', assetId: 'token.test.near', profileHash: 'a'.repeat(64) };
const reference: KeyReference = { role: 'holder', subjectId: 'alice.test.near', keyId: '1' };
const executor: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
  if (method === 'keygen') return { secret_key: 'b'.repeat(64), public_key: { point: 'c'.repeat(64) } } as T;
  return { point: (params as { secret_key: string }).secret_key === 'b'.repeat(64) ? 'c'.repeat(64) : 'd'.repeat(64) } as T;
} };

test('backup import validates keys and deployment atomically without replacing existing keys', async () => {
  const ring = new Keyring(identity, executor);
  await ring.generate(reference);
  const snapshot = ring.exportMaterial();
  const bad = structuredClone(snapshot);
  bad.keys[0]!.publicKey.point = 'd'.repeat(64);
  await assert.rejects(ring.importMaterial(bad), /replace a different key/);
  assert.deepEqual(ring.exportMaterial(), snapshot);
  const wrongDeployment = structuredClone(snapshot);
  wrongDeployment.identity.assetId = 'another.test.near';
  await assert.rejects(ring.importMaterial(wrongDeployment), /different deployment/);
  const second = new Keyring(identity, executor);
  await assert.rejects(second.importMaterial(bad), /does not match/);
  assert.deepEqual(second.exportMaterial().keys, []);
  await second.importMaterial(snapshot);
  assert.deepEqual(second.publicKey(reference), ring.publicKey(reference));
  second.clear();
  assert.throws(() => second.secret(reference), /unavailable/);
});

test('duplicate generation retains the same secret and large key IDs remain exact', async () => {
  const ring = new Keyring(identity, executor);
  const large = { ...reference, keyId: '18446744073709551615' };
  const first = await ring.generate(large);
  assert.deepEqual(await ring.generate(large), first);
  assert.equal(ring.exportMaterial().keys.length, 1);
  await assert.rejects(ring.generate({ ...reference, keyId: '18446744073709551616' }), /Invalid wallet key reference/);
});

test('concurrent generation cannot replace a key and locking cancels in-flight mutations', async () => {
  let generations = 0;
  let release!: () => void;
  let entered!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  const slow: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
    generations++; entered(); await blocked; return executor.execute<T>(method, params);
  } };
  const ring = new Keyring(identity, slow);
  const first = ring.generate(reference);
  const second = ring.generate(reference);
  await started;
  release();
  assert.deepEqual(await first, await second);
  assert.equal(generations, 1);
  const locked = new Keyring(identity, slow);
  const generation = locked.generate(reference);
  locked.clear();
  await assert.rejects(generation, /locked/);
  assert.deepEqual(locked.exportMaterial().keys, []);
});
