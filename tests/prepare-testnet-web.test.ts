import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { manifestHash, type CryptoManifest } from '../packages/client/src/artifacts.js';
import { proofFamilies } from '../scripts/development-artifacts.js';
import { prepareTestnetWeb } from '../scripts/prepare-testnet-web.js';

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'testnet-web-'));
  const artifacts = join(root, 'artifacts'), web = join(root, 'web'), deploymentPath = join(root, 'public.json');
  await mkdir(artifacts); await mkdir(web);
  const manifest: CryptoManifest = { schema: 'confidential-lending-artifacts/v1', networkId: 'testnet', coreAccountId: 'core.testnet', profileHash: 'a'.repeat(64), setup: 'development-single-party', artifacts: {} };
  const names = ['browser.glue', 'browser.wasm', ...proofFamilies.flatMap(family => ['pk', 'vk', 'prepared-vk'].map(suffix => `${family}.${suffix}`))];
  for (const name of names) {
    const bytes = Buffer.from(`public ${name}`);
    await writeFile(join(artifacts, name), bytes);
    manifest.artifacts[name] = { path: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
  }
  await writeFile(join(artifacts, 'private-credentials.json'), 'must not be published');
  await writeFile(join(artifacts, 'manifest.json'), JSON.stringify(manifest));
  const deployment = { schema: 'confidential-lending-testnet/v1', networkId: 'testnet', coreAccountId: 'core.testnet', tokenAccountId: 'token.testnet', rpcUrl: 'https://rpc.testnet.near.org', profileHash: manifest.profileHash, manifestHash: await manifestHash(manifest), token: { symbol: 'TEST', decimals: 6 }, verifier: { activated: true, keyCount: 8 } };
  await writeFile(deploymentPath, JSON.stringify(deployment));
  return { root, artifacts, web, deploymentPath, deployment, names };
}

test('testnet web preparation publishes pinned artifacts and only public configuration', async () => {
  const f = await fixture();
  try {
    await prepareTestnetWeb(f.deploymentPath, f.artifacts, f.web);
    assert.deepEqual((await readdir(join(f.web, 'public/crypto'))).sort(), [...f.names, 'manifest.json'].sort());
    const config = JSON.parse(await readFile(join(f.web, 'src/config/testnet.json'), 'utf8'));
    assert.equal(config.coreAccountId, f.deployment.coreAccountId);
    assert.equal(config.cryptoArtifactHash, f.deployment.manifestHash);
    assert.equal(config.cryptoManifestUrl, '/crypto/manifest.json');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('a corrupted artifact leaves the prior public bundle intact', async () => {
  const f = await fixture();
  try {
    await prepareTestnetWeb(f.deploymentPath, f.artifacts, f.web);
    const before = await readFile(join(f.web, 'public/crypto/browser.glue'), 'utf8');
    await writeFile(join(f.artifacts, 'browser.glue'), 'corrupted');
    await assert.rejects(prepareTestnetWeb(f.deploymentPath, f.artifacts, f.web), /mismatch/);
    assert.equal(await readFile(join(f.web, 'public/crypto/browser.glue'), 'utf8'), before);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('testnet web preparation rejects other networks before publishing anything', async () => {
  const f = await fixture();
  try {
    await writeFile(f.deploymentPath, JSON.stringify({ ...f.deployment, networkId: 'mainnet' }));
    await assert.rejects(prepareTestnetWeb(f.deploymentPath, f.artifacts, f.web), /testnet deployment/);
    assert.deepEqual(await readdir(f.web), []);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
