import { createServer } from 'node:http';
import { createReadStream, constants } from 'node:fs';
import { mkdir, open, chmod } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { KeyPair } from 'near-workspaces';
import { actionCreators } from '@near-js/transactions';
import { encryptWalletBackup } from '../packages/wallet/src/backup.js';
import { Keyring } from '../packages/wallet/src/keyring.js';
import { LedgerWallet } from '../packages/wallet/src/ledger.js';
import { confinedPath } from './release.js';
import { deployProtocol, maximumGas } from '../tests/e2e/deployment.js';

const artifactDirectory = resolve(process.argv[2] ?? '.artifacts/development');
const webPort = Number(process.env.DEMO_PORT ?? '5174');
if (!Number.isInteger(webPort) || webPort < 1024 || webPort > 65535) throw new Error('DEMO_PORT must be an integer from 1024 to 65535');
const output = resolve('.local/demo');
await mkdir(join(output, 'credentials'), { recursive: true, mode: 0o700 });
await chmod(output, 0o700);
await chmod(join(output, 'credentials'), 0o700);
const deployment = await deployProtocol(artifactDirectory);
let web: ReturnType<typeof spawn> | undefined;
const assetPaths = new Map(Object.values(deployment.manifest.artifacts).map(entry => [`/${entry.path}`, entry.path]));
assetPaths.set('/manifest.json', 'manifest.json');
const server = createServer(async (request, response) => {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  if (request.method !== 'GET' && request.method !== 'HEAD') { response.writeHead(405).end(); return; }
  const path = assetPaths.get(new URL(request.url ?? '/', 'http://localhost').pathname);
  if (!path) { response.writeHead(404).end(); return; }
  try {
    const source = await confinedPath(artifactDirectory, path);
    response.setHeader('Content-Type', path.endsWith('.json') ? 'application/json' : path.endsWith('.js') ? 'text/javascript' : path.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream');
    response.setHeader('Cache-Control', 'no-store');
    if (request.method === 'HEAD') response.end();
    else createReadStream(source).on('error', () => response.destroy()).pipe(response);
  } catch { response.writeHead(404).end(); }
});
const stopped = new Promise<void>(resolveStop => {
  process.once('SIGINT', resolveStop); process.once('SIGTERM', resolveStop);
  server.once('close', resolveStop);
});
async function privateFile(path: string, value: string): Promise<void> {
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
  try { await file.chmod(0o600); await file.writeFile(value); await file.sync(); }
  finally { await file.close(); }
}
try {
  const keeperKey = KeyPair.fromRandom('ed25519');
  const keeperGrant = await deployment.actors.keeper.batch(deployment.actors.keeper)
    .addKey(keeperKey.getPublicKey(), actionCreators.functionCallAccessKey(deployment.core.accountId, ['merge_broker_inbox', 'settle'], 10n ** 24n)).transact();
  if (keeperGrant.failed) throw new Error('Sandbox keeper key installation failed');
  const keeperKeys = new Keyring(deployment.keys.identity, deployment.crypto);
  try {
    const ledger = new LedgerWallet(deployment.rpc, keeperKeys, deployment.crypto, deployment.manifestHash);
    const registration = await ledger.prepareHolderRegistration(deployment.actors.keeper.accountId, '1');
    await deployment.actors.keeper.call(deployment.core, registration.method, registration.args, { gas: maximumGas });
    await deployment.actors.keeper.call(deployment.core, 'register_authorization_key', { args: {
      key_id: '1', public_key: Array.from(keeperKey.getPublicKey().data),
    } }, { gas: maximumGas });
    const backupPassword = randomBytes(32).toString('base64url');
    await privateFile(join(output, 'keeper-account-backup.json'), JSON.stringify(await encryptWalletBackup(keeperKeys.exportMaterial(), backupPassword), null, 2));
    await privateFile(join(output, 'keeper-account-backup-passphrase.txt'), `${backupPassword}\n`);
  } finally { keeperKeys.clear(); }
  for (const [name, account] of Object.entries(deployment.actors)) {
    const key = name === 'keeper' ? keeperKey : await account.getKey();
    if (!key) throw new Error('Sandbox actor has no signing key');
    await privateFile(join(output, 'credentials', `${name}.json`), JSON.stringify({ account_id: account.accountId, public_key: key.getPublicKey().toString(), private_key: key.toString() }, null, 2));
  }
  const auditor = { role: 'loan_auditor' as const, subjectId: deployment.actors.auditor.accountId, keyId: '1' };
  const loanAuditorKey = await deployment.keys.generate(auditor);
  const passphrase = randomBytes(32).toString('base64url');
  await privateFile(join(output, 'auditor-backup.json'), JSON.stringify(await encryptWalletBackup(deployment.keys.exportMaterial(), passphrase), null, 2));
  await privateFile(join(output, 'auditor-backup-passphrase.txt'), `${passphrase}\n`);
  await new Promise<void>((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Artifact server did not bind');
  const artifactBase = `http://127.0.0.1:${address.port}/`;
  await privateFile(join(output, 'public.json'), JSON.stringify({ networkId: 'sandbox', coreAccountId: deployment.core.accountId,
    webUrl: `http://127.0.0.1:${webPort}/tests/browser/sandbox.html`,
    tokenAccountId: deployment.token.accountId, rpcUrl: deployment.rpc.url, manifestHash: deployment.manifestHash,
    profileHash: deployment.manifest.profileHash, coreWasmHash: deployment.coreWasmHash, artifactBase, loanAuditorKey,
    keeperAuthorization: { keyId: '1', epoch: '2', accountId: deployment.actors.keeper.accountId },
    accounts: Object.fromEntries(Object.entries(deployment.actors).map(([name, account]) => [name, account.accountId])) }, null, 2));
  console.log(`Sandbox ready. Import a signing credential from ${join(output, 'credentials')} in the local wallet. These accounts hold test tokens only.`);
  console.log(`Loan auditor public key and deployment configuration: ${join(output, 'public.json')}`);
  web = spawn('pnpm', ['--dir', 'web', 'dev', '--host', '127.0.0.1', '--port', String(webPort), '--strictPort'], {
    stdio: 'inherit', env: { ...process.env,
      VITE_NETWORK_ID: 'sandbox', VITE_CORE_ACCOUNT_ID: deployment.core.accountId, VITE_TOKEN_ACCOUNT_ID: deployment.token.accountId,
      VITE_RPC_URL: deployment.rpc.url, VITE_ALLOW_INSECURE_LOCALHOST: 'true', VITE_CRYPTO_PROFILE_HASH: deployment.manifest.profileHash,
      VITE_CRYPTO_ARTIFACT_HASH: deployment.manifestHash, VITE_CRYPTO_MANIFEST_URL: `${artifactBase}manifest.json`,
      VITE_CRYPTO_ARTIFACT_BASE_URL: artifactBase, VITE_FUNDED_DEPLOYMENT: 'false', VITE_ASSET_DECIMALS: '6', VITE_ASSET_SYMBOL: 'TEST',
    },
  });
  await Promise.race([stopped, new Promise<void>((done, reject) => { web!.once('error', reject); web!.once('exit', () => done()); })]);
} finally {
  web?.kill('SIGTERM'); server.closeAllConnections(); server.close();
  deployment.keys.clear(); await deployment.worker.tearDown();
}
