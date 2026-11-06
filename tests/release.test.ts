import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, symlink, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { checkEntry, checkRelease, PROOF_KINDS, type ReleaseManifest } from '../scripts/release.js';
import type { ArtifactEntry, CryptoManifest } from '../packages/client/src/artifacts.js';
import { manifestHash } from '../packages/client/src/artifacts.js';

test('release checks verify bytes and reject symlink escape, missing proof families and unfunded setup claims', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'lending-release-'));
  const root = join(directory, 'bundle');
  await mkdir(root);
  try {
    const bytes = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
    await writeFile(join(root, 'artifact'), bytes);
    const entry: ArtifactEntry = { path: 'artifact', bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    await checkEntry(root, entry);
    await assert.rejects(checkEntry(root, { ...entry, sha256: 'a'.repeat(64) }), /hash mismatch/);
    await writeFile(join(directory, 'outside'), bytes);
    await symlink(join(directory, 'outside'), join(root, 'escape'));
    await assert.rejects(checkEntry(root, { ...entry, path: 'escape' }), /escapes/);
    const deployment = { networkId: 'sandbox', coreAccountId: 'core.test.near', tokenAccountId: 'token.test.near', profileHash: 'b'.repeat(64), funded: false };
    const crypto: CryptoManifest = { schema: 'confidential-lending-artifacts/v1', ...deployment, setup: 'development-single-party', artifacts: {} };
    const manifest: ReleaseManifest = {
      schema: 'confidential-lending-release/v1', deployment, cryptoManifest: 'crypto.json', cryptoManifestHash: '', coreWasm: entry, sourceCommit: 'c'.repeat(40),
      setupEvidence: entry, reviewEvidence: null, invariantEvidence: entry, custodyRecoveryEvidence: entry, vectorsEvidence: entry,
      upgradePolicy: 'No upgrade access key.', issuerPolicy: 'Issuer controls the token.', auditorPolicy: 'Separate token and loan auditors.', keeperPolicy: 'Scoped settlement permissions.', measurements: {},
    };
    for (const kind of PROOF_KINDS) {
      for (const suffix of ['pk', 'vk', 'prepared-vk']) crypto.artifacts[`${kind}.${suffix}`] = entry;
      manifest.measurements[kind] = { maxGas: '100000000000000', publicInputs: 193, transactionBytes: 10_000, proverMilliseconds: 1_000, proverPeakBytes: 100_000, recoveryMilliseconds: 100 };
    }
    for (const name of ['native.prover', 'browser.wasm', 'browser.glue']) crypto.artifacts[name] = entry;
    const save = async () => { manifest.cryptoManifestHash = await manifestHash(crypto); await writeFile(join(root, 'crypto.json'), JSON.stringify(crypto)); await writeFile(join(root, 'release.json'), JSON.stringify(manifest)); };
    await save();
    assert.equal((await checkRelease(join(root, 'release.json'))).checkedArtifacts, 32);
    manifest.cryptoManifestHash = 'f'.repeat(64);
    await writeFile(join(root, 'release.json'), JSON.stringify(manifest));
    await assert.rejects(checkRelease(join(root, 'release.json')), /manifest hash mismatch/);
    manifest.deployment.funded = true;
    await save();
    await assert.rejects(checkRelease(join(root, 'release.json')), /Funded release/);
    manifest.deployment.funded = false;
    delete crypto.artifacts['repayment.vk'];
    await save();
    await assert.rejects(checkRelease(join(root, 'release.json')), /Missing repayment.vk/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
