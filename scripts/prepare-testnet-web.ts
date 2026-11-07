import { copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertAccountId, validateManifest, verifyManifestPin, type CryptoManifest } from '../packages/client/src/index.js';
import { proofFamilies } from './development-artifacts.js';
import { checkEntry } from './release.js';

interface PublicDeployment {
  schema: string;
  networkId: string;
  coreAccountId: string;
  tokenAccountId: string;
  rpcUrl: string;
  profileHash: string;
  manifestHash: string;
  token: { decimals: number; symbol: string };
  verifier: { activated: boolean; keyCount: number };
}

/** Publish only pinned public proving artifacts; never copy a deployment directory wholesale. */
export async function prepareTestnetWeb(deploymentPath: string, artifactRoot: string, webRoot: string): Promise<void> {
  const deployment = JSON.parse(await readFile(deploymentPath, 'utf8')) as PublicDeployment;
  if (deployment.schema !== 'confidential-lending-testnet/v1' || deployment.networkId !== 'testnet' || !deployment.verifier?.activated || deployment.verifier.keyCount !== proofFamilies.length) throw new Error('An activated testnet deployment is required');
  assertAccountId(deployment.coreAccountId);
  assertAccountId(deployment.tokenAccountId);
  const rpc = new URL(deployment.rpcUrl);
  if (rpc.protocol !== 'https:' || rpc.username || rpc.password || rpc.hash) throw new Error('Testnet RPC must use HTTPS without credentials');
  if (deployment.token?.decimals !== 6 || deployment.token.symbol !== 'TEST') throw new Error('Unexpected testnet asset profile');
  const manifest = JSON.parse(await readFile(resolve(artifactRoot, 'manifest.json'), 'utf8')) as CryptoManifest;
  validateManifest(manifest, { networkId: 'testnet', coreAccountId: deployment.coreAccountId, profileHash: deployment.profileHash, funded: false });
  await verifyManifestPin(manifest, deployment.manifestHash);
  const names = ['browser.glue', 'browser.wasm', ...proofFamilies.flatMap(family => ['pk', 'vk', 'prepared-vk'].map(suffix => `${family}.${suffix}`))];
  const publicRoot = resolve(webRoot, 'public');
  await mkdir(publicRoot, { recursive: true });
  // Stage outside public/ so Vite cannot serve a partial bundle.
  const staging = await mkdtemp(resolve(webRoot, '.crypto-staging-'));
  const destination = resolve(publicRoot, 'crypto');
  const previous = resolve(webRoot, '.crypto-previous');
  try {
    for (const name of names) {
      const entry = manifest.artifacts[name];
      if (!entry || basename(entry.path) !== entry.path || /secret|private|witness|toxic/i.test(entry.path)) throw new Error(`Missing or unsafe public artifact: ${name}`);
      const path = await checkEntry(artifactRoot, entry);
      await copyFile(path, resolve(staging, entry.path));
      await checkEntry(staging, entry);
    }
    await writeFile(resolve(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    await rm(previous, { recursive: true, force: true });
    let moved = false;
    try { await rename(destination, previous); moved = true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    try { await rename(staging, destination); }
    catch (error) { if (moved) await rename(previous, destination); throw error; }
    await rm(previous, { recursive: true, force: true });
    const configPath = resolve(webRoot, 'src/config/testnet.json');
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, `${JSON.stringify({
      networkId: 'testnet', coreAccountId: deployment.coreAccountId, tokenAccountId: deployment.tokenAccountId,
      rpcUrl: deployment.rpcUrl, cryptoProfileHash: deployment.profileHash, cryptoArtifactHash: deployment.manifestHash,
      cryptoManifestUrl: '/crypto/manifest.json', assetDecimals: deployment.token.decimals, assetSymbol: deployment.token.symbol,
    }, null, 2)}\n`);
  } finally { await rm(staging, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await prepareTestnetWeb(resolve(process.argv[2] ?? '.local/testnet/public.json'), resolve(process.argv[3] ?? '.artifacts/testnet'), resolve('web'));
  console.log('Verified testnet configuration and public artifacts prepared for pnpm dev / pnpm build.');
}
