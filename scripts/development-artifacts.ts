import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { chmod, copyFile, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import lockfile from 'proper-lockfile';
import { manifestHash, type ArtifactEntry, type CryptoManifest } from '../packages/client/src/artifacts.js';

export const proofFamilies = ['key-possession', 'public-conversion', 'confidential-transfer', 'origination', 'repayment', 'reconciliation', 'zero-balance', 'ownership'] as const;
export interface DevelopmentSetup {
  output: string;
  executable: string;
  prepareKeyExecutable: string;
  browserGlue: string;
  browserWasm: string;
  networkId: string;
  coreAccountId: string;
  progress?: (message: string) => void;
}
interface Checkpoint {
  schema: 'confidential-lending-development-setup/v1';
  inputs: Record<string, string>;
  manifest: CryptoManifest;
}

async function describe(path: string, name: string): Promise<ArtifactEntry> {
  const details = await stat(path);
  if (!details.isFile() || details.size < 1 || details.size > 2 ** 32) throw new Error('Invalid artifact file');
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return { path: name, sha256: digest.digest('hex'), bytes: details.size };
}

async function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const output: Buffer[] = [];
    let length = 0;
    let excessive = false;
    child.on('error', () => reject(new Error('Setup tool could not start')));
    child.stdout.on('data', (chunk: Buffer) => {
      length += chunk.length;
      if (length > 1_000_000) { excessive = true; child.kill('SIGTERM'); }
      else output.push(chunk);
    });
    child.stderr.resume();
    child.on('close', code => {
      if (code !== 0 || excessive) reject(new Error(`Setup tool failed: ${basename(command)}`));
      else resolveResult(Buffer.concat(output).toString('utf8'));
    });
  });
}

async function atomicJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  await rename(temporary, path);
}

async function absent(path: string): Promise<boolean> {
  try { await stat(path); return false; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true; throw error; }
}

/** Generates public development artifacts only. Resuming never replaces keys for an existing deployment. */
export async function buildDevelopmentArtifacts(options: DevelopmentSetup): Promise<{ manifest: CryptoManifest; manifestHash: string }> {
  if (!['sandbox', 'localnet', 'testnet'].includes(options.networkId) || !/^[a-z0-9._-]{2,64}$/.test(options.coreAccountId)) throw new Error('Development setup requires a development network and valid Core account');
  const output = resolve(options.output);
  await mkdir(output, { recursive: true, mode: 0o700 });
  let compromised = false;
  const release = await lockfile.lock(output, { realpath: true, stale: 30_000, update: 5_000, retries: 0, onCompromised: () => { compromised = true; } });
  const checkLock = () => { if (compromised) throw new Error('Setup lock was lost'); };
  try { return await buildLocked(options, output, checkLock); }
  finally { await release(); }
}

async function buildLocked(options: DevelopmentSetup, output: string, checkLock: () => void): Promise<{ manifest: CryptoManifest; manifestHash: string }> {
  const sources = {
    'native.prover': resolve(options.executable), 'browser.glue': resolve(options.browserGlue),
    'browser.wasm': resolve(options.browserWasm),
  };
  const inputs: Record<string, string> = { networkId: options.networkId, coreAccountId: options.coreAccountId };
  for (const [name, path] of Object.entries(sources)) inputs[name] = (await describe(path, name)).sha256;
  inputs.prepareKey = (await describe(resolve(options.prepareKeyExecutable), 'prepare-key')).sha256;
  const profile = JSON.parse(await run(resolve(options.executable), ['inspect-profile'])) as { profile_hash?: string };
  if (!profile.profile_hash || !/^[a-f0-9]{64}$/.test(profile.profile_hash)) throw new Error('Setup tool returned an invalid profile');
  inputs.profileHash = profile.profile_hash;
  const checkpointPath = join(output, 'setup-checkpoint.json');
  let checkpoint: Checkpoint;
  if (await absent(checkpointPath)) {
    checkpoint = { schema: 'confidential-lending-development-setup/v1', inputs, manifest: {
      schema: 'confidential-lending-artifacts/v1', profileHash: profile.profile_hash,
      networkId: options.networkId, coreAccountId: options.coreAccountId,
      setup: 'development-single-party', artifacts: {},
    } };
    await atomicJson(checkpointPath, checkpoint);
  } else {
    checkpoint = JSON.parse(await readFile(checkpointPath, 'utf8')) as Checkpoint;
    if (checkpoint.schema !== 'confidential-lending-development-setup/v1' || JSON.stringify(checkpoint.inputs) !== JSON.stringify(inputs)) throw new Error('Existing setup uses different binaries or deployment; choose a fresh output directory');
    if (checkpoint.manifest.profileHash !== profile.profile_hash || checkpoint.manifest.setup !== 'development-single-party' || checkpoint.manifest.networkId !== options.networkId || checkpoint.manifest.coreAccountId !== options.coreAccountId) throw new Error('Invalid setup checkpoint');
    for (const entry of Object.values(checkpoint.manifest.artifacts)) {
      if (basename(entry.path) !== entry.path) throw new Error('Invalid checkpoint artifact path');
      const current = await describe(join(output, entry.path), entry.path);
      if (current.sha256 !== entry.sha256 || current.bytes !== entry.bytes) throw new Error('Existing setup artifact changed; refusing to replace it');
    }
  }
  const save = () => { checkLock(); return atomicJson(checkpointPath, checkpoint); };
  for (const [name, source] of Object.entries(sources)) {
    if (checkpoint.manifest.artifacts[name]) continue;
    const filename = name === 'native.prover' ? 'confidential-crypto' : name === 'browser.glue' ? 'confidential_crypto.js' : 'confidential_crypto_bg.wasm';
    const destination = join(output, filename);
    checkLock();
    await copyFile(source, destination, 1); // COPYFILE_EXCL: never replace deployment artifacts.
    await chmod(destination, name === 'native.prover' ? 0o700 : 0o600);
    checkpoint.manifest.artifacts[name] = await describe(destination, filename);
    await save();
  }
  for (const family of proofFamilies) {
    const names = ['pk', 'vk', 'prepared-vk'].map(suffix => `${family}.${suffix}`);
    if (names.every(name => checkpoint.manifest.artifacts[name])) continue;
    if (names.some(name => checkpoint.manifest.artifacts[name])) throw new Error('Incomplete setup checkpoint');
    for (const name of names) if (!await absent(join(output, name))) throw new Error('Uncheckpointed setup files exist; choose a fresh output directory');
    options.progress?.(`Generating ${family} development proving and verification keys`);
    const staging = join(output, `.pending-${family}-${randomUUID()}`);
    await mkdir(staging, { mode: 0o700 });
    const prefix = join(staging, family);
    await run(resolve(options.executable), ['dev', 'setup', family, prefix]);
    await run(resolve(options.prepareKeyExecutable), [`${prefix}.vk`, `${prefix}.prepared-vk`]);
    checkLock();
    const entries: Record<string, ArtifactEntry> = {};
    for (const name of names) entries[name] = await describe(join(staging, name), name);
    for (const name of names) await copyFile(join(staging, name), join(output, name), 1);
    Object.assign(checkpoint.manifest.artifacts, entries);
    await save();
    await rm(staging, { recursive: true });
  }
  const pin = await manifestHash(checkpoint.manifest);
  checkLock();
  await atomicJson(join(output, 'manifest.json'), checkpoint.manifest);
  await atomicJson(join(output, 'deployment-pin.json'), {
    networkId: options.networkId, coreAccountId: options.coreAccountId,
    profileHash: profile.profile_hash, manifestHash: pin, funded: false,
    setup: 'development-single-party',
  });
  return { manifest: checkpoint.manifest, manifestHash: pin };
}
