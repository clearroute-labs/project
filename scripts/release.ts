import { createReadStream } from 'node:fs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { assertAccountId, type ArtifactEntry, type CryptoManifest } from '../packages/client/src/index.js';

export const PROOF_KINDS = ['key_possession', 'public_conversion', 'confidential_transfer', 'origination', 'repayment', 'reconciliation', 'zero_balance', 'ownership'] as const;

export interface ReleaseManifest {
  schema: 'confidential-lending-release/v1';
  deployment: { networkId: string; coreAccountId: string; tokenAccountId: string; profileHash: string; funded: boolean };
  cryptoManifest: string;
  coreWasm: ArtifactEntry;
  sourceCommit: string;
  setupEvidence: ArtifactEntry;
  reviewEvidence: ArtifactEntry | null;
  invariantEvidence: ArtifactEntry;
  custodyRecoveryEvidence: ArtifactEntry;
  upgradePolicy: string;
  issuerPolicy: string;
  auditorPolicy: string;
  keeperPolicy: string;
  measurements: Record<string, { maxGas: string; publicInputs: number; transactionBytes: number; proverMilliseconds: number; proverPeakBytes: number; recoveryMilliseconds: number }>;
}

function boundedText(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length < 12 || value.length > 16_384) throw new Error(`Missing or invalid ${name}`);
}

export async function confinedPath(root: string, path: string): Promise<string> {
  if (!path || isAbsolute(path)) throw new Error('Release paths must be relative');
  const canonicalRoot = await realpath(root);
  const canonicalFile = await realpath(resolve(root, path));
  const difference = relative(canonicalRoot, canonicalFile);
  if (difference === '..' || difference.startsWith(`..${sep}`) || isAbsolute(difference)) throw new Error('Release path escapes bundle');
  return canonicalFile;
}

export async function checkEntry(root: string, entry: ArtifactEntry): Promise<string> {
  if (!entry || !/^[a-f0-9]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || entry.bytes > 2 ** 32) throw new Error('Invalid release artifact entry');
  const path = await confinedPath(root, entry.path);
  const details = await stat(path);
  if (!details.isFile() || details.size !== entry.bytes) throw new Error(`Artifact size mismatch: ${entry.path}`);
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  if (digest.digest('hex') !== entry.sha256) throw new Error(`Artifact hash mismatch: ${entry.path}`);
  return path;
}

export async function checkRelease(manifestPath: string): Promise<{ manifest: ReleaseManifest; checkedArtifacts: number }> {
  const root = dirname(resolve(manifestPath));
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as ReleaseManifest;
  if (manifest.schema !== 'confidential-lending-release/v1') throw new Error('Unsupported release manifest');
  const deployment = manifest.deployment;
  if (!deployment || typeof deployment.funded !== 'boolean' || !/^[a-f0-9]{64}$/.test(deployment.profileHash) || !/^[a-f0-9]{40}$/.test(manifest.sourceCommit)) throw new Error('Invalid deployment or source identity');
  assertAccountId(deployment.coreAccountId);
  assertAccountId(deployment.tokenAccountId);
  if (!/^[a-z0-9_-]{1,64}$/.test(deployment.networkId)) throw new Error('Invalid network identity');
  for (const name of ['upgradePolicy', 'issuerPolicy', 'auditorPolicy', 'keeperPolicy'] as const) boundedText(manifest[name], name);
  const cryptoPath = await confinedPath(root, manifest.cryptoManifest);
  const crypto = JSON.parse(await readFile(cryptoPath, 'utf8')) as CryptoManifest;
  if (crypto.schema !== 'confidential-lending-artifacts/v1' || crypto.profileHash !== deployment.profileHash || crypto.networkId !== deployment.networkId || crypto.coreAccountId !== deployment.coreAccountId) throw new Error('Crypto manifest deployment mismatch');
  if (!['development-single-party', 'reviewed-ceremony'].includes(crypto.setup)) throw new Error('Unknown setup provenance');
  if (deployment.funded && (crypto.setup !== 'reviewed-ceremony' || !manifest.reviewEvidence)) throw new Error('Funded release requires reviewed setup and independent review evidence');
  const entries = [manifest.coreWasm, manifest.setupEvidence, manifest.invariantEvidence, manifest.custodyRecoveryEvidence];
  if (manifest.reviewEvidence) entries.push(manifest.reviewEvidence);
  for (const entry of entries) await checkEntry(root, entry);
  const wasmPath = await confinedPath(root, manifest.coreWasm.path);
  const wasm = await readFile(wasmPath);
  if (!wasm.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) throw new Error('Core artifact is not WebAssembly v1');
  for (const kind of PROOF_KINDS) {
    for (const suffix of ['proving_key', 'verifying_key', 'vectors']) {
      const entry = crypto.artifacts[`${kind}.${suffix}`];
      if (!entry) throw new Error(`Missing ${kind}.${suffix}`);
    }
    const measurement = manifest.measurements[kind];
    if (!measurement || !/^[1-9]\d*$/.test(measurement.maxGas) || BigInt(measurement.maxGas) > 300_000_000_000_000n
      || !Number.isSafeInteger(measurement.publicInputs) || measurement.publicInputs < 1 || measurement.publicInputs > 2048
      || !Number.isSafeInteger(measurement.transactionBytes) || measurement.transactionBytes < 1 || measurement.transactionBytes > 1_000_000
      || !Number.isFinite(measurement.proverMilliseconds) || measurement.proverMilliseconds <= 0
      || !Number.isSafeInteger(measurement.proverPeakBytes) || measurement.proverPeakBytes <= 0
      || !Number.isFinite(measurement.recoveryMilliseconds) || measurement.recoveryMilliseconds <= 0) throw new Error(`Missing or invalid worst-case measurements: ${kind}`);
  }
  for (const [name, entry] of Object.entries(crypto.artifacts)) {
    if (/toxic|secret|witness|private[-_]?key/i.test(name) || /(?:^|\/)(?:secrets?|witness|toxic)(?:[./_-]|$)/i.test(entry.path)) throw new Error('Secret material must not appear in a release bundle');
    await checkEntry(dirname(cryptoPath), entry);
  }
  return { manifest, checkedArtifacts: entries.length + Object.keys(crypto.artifacts).length };
}
