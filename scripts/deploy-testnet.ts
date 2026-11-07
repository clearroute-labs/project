import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, open, readFile, realpath, rename, stat, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KeyPair, TestnetManager, hashContract, type KeyStore } from 'near-workspaces';
import { assertAccountId, canonicalManifest, manifestHash, validateManifest, type CryptoManifest } from '../packages/client/src/index.js';
import { Keyring, type KeyReference, type WalletMaterial } from '../packages/wallet/src/keyring.js';
import { NativeCrypto } from '../packages/wallet/src/native.js';
import { proofFamilies } from './development-artifacts.js';
import { checkEntry } from './release.js';

const near = 10n ** 24n;
const maxGas = 300_000_000_000_000n;
const networkId = 'testnet';
const helperUrl = 'https://helper.nearprotocol.com/account';
// The legacy rpc.testnet.near.org endpoint now returns a deprecation 429.
// FastNear is the documented current Testnet JSON-RPC endpoint; callers can
// still override it for an organization-managed provider.
const rpcUrl = process.env.NEAR_TESTNET_RPC_URL ?? 'https://test.rpc.fastnear.com';
const localRoot = resolve(process.env.TESTNET_LOCAL_DIR ?? '.local/testnet');
const artifactRoot = resolve(process.env.TESTNET_ARTIFACT_DIR ?? '.artifacts/testnet');
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = resolve(process.env.CRYPTO_ARTIFACT_SOURCE ?? (await existing(join(artifactRoot, 'manifest.json')) ? artifactRoot : join(repoRoot, '.artifacts/development')));
const archivedContracts = join(artifactRoot, 'contracts');
const contractRoot = resolve(process.env.CONTRACT_ARTIFACT_DIR ?? (await existing(join(archivedContracts, 'confidential_core.wasm')) ? archivedContracts : join(repoRoot, '.artifacts/contracts')));

type Role = 'owner' | 'core' | 'token';
type Credential = { accountId: string; publicKey: string; secretKey: string };

export function validateCredential(value: Credential): void {
  assertAccountId(value.accountId);
  if (!value.accountId.endsWith('.testnet')) fail('Deployment accounts must belong to testnet');
  let matches = false;
  try { matches = KeyPair.fromString(value.secretKey as Parameters<typeof KeyPair.fromString>[0]).getPublicKey().toString() === value.publicKey; }
  catch { /* Do not include invalid secret material in an error. */ }
  if (!matches) fail('Deployment credential public and secret keys do not match');
}

export function validateRpcUrl(value: string): void {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) fail('Testnet RPC must use HTTPS without embedded credentials');
}

class UninitializedContractError extends Error {}

async function query<T>(params: Record<string, unknown>): Promise<T | null> {
  const response = await fetch(rpcUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'deployment', method: 'query', params: { finality: 'final', ...params } }),
    signal: AbortSignal.timeout(30_000), redirect: 'error', credentials: 'omit',
  });
  if (!response.ok) fail(`Testnet RPC returned HTTP ${response.status}`);
  const body = await response.json() as { result?: T; error?: { cause?: { name?: string; info?: { error_message?: string } } } };
  if (body.error?.cause?.name === 'UNKNOWN_ACCOUNT') return null;
  const cause = body.error?.cause;
  if (cause?.name === 'CONTRACT_EXECUTION_ERROR' && cause.info?.error_message?.includes('The contract is not initialized')) throw new UninitializedContractError();
  if (body.error || body.result === undefined) fail(`Testnet RPC query failed (${cause?.name ?? 'unknown'}); no deployment state was inferred`);
  return body.result;
}

async function ensureAccount(credential: Credential): Promise<void> {
  validateCredential(credential);
  if (!await query({ request_type: 'view_account', account_id: credential.accountId })) {
    // The key is already durable. An ambiguous helper response can safely be
    // retried on the next run using this exact same account and key.
    await faucetCreate(credential.accountId, credential.publicKey);
    for (let attempt = 0; attempt < 10; attempt += 1) {
      if (await query({ request_type: 'view_account', account_id: credential.accountId })) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  const key = await query<{ permission: unknown }>({ request_type: 'view_access_key', account_id: credential.accountId, public_key: credential.publicKey });
  if (key?.permission !== 'FullAccess') fail('Deployment account requires its matching full-access key');
}

async function initialized(accountId: string, method: string): Promise<boolean> {
  const account = await query<{ code_hash: string }>({ request_type: 'view_account', account_id: accountId });
  if (!account) fail('Deployment account disappeared');
  if (account.code_hash === '11111111111111111111111111111111') return false;
  try {
    await query({ request_type: 'call_function', account_id: accountId, method_name: method, args_base64: 'e30=' });
    return true;
  } catch (error) {
    if (error instanceof UninitializedContractError) return false;
    throw error;
  }
}
type PublicDeployment = {
  schema: 'confidential-lending-testnet/v1';
  networkId: 'testnet';
  rpcUrl: string;
  coreAccountId: string;
  tokenAccountId: string;
  controllerAccountId: string;
  profileHash: string;
  manifestHash: string;
  coreWasmHash: string;
  tokenWasmHash: string;
  artifactBaseUrl: string | null;
  artifactHosting: 'not-hosted';
  token: {
    symbol: 'TEST';
    decimals: 6;
    mintAuthority: string;
    registrationMethod: 'storage_deposit';
    mintMethod: 'mint';
    mintAuthorityIsNotPublic: true;
    metadataMethod: 'ft_metadata';
    faucetClaimMethod: 'faucet_claim';
    faucetHasClaimedMethod: 'faucet_has_claimed';
    faucetClaimAmount: string;
    faucetRequiresStorageRegistration: true;
  };
  verifier: { statementKinds: number[]; activated: true; keyCount: number };
};

function fail(message: string): never { throw new Error(message); }

function hexBytes(value: unknown): string {
  if (typeof value === 'string' && /^[a-f0-9]+$/.test(value)) return value;
  if (Array.isArray(value) && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return Buffer.from(value).toString('hex');
  return '';
}

async function privateJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
  } finally { await handle.close(); }
  await rename(temporary, path);
  await chmod(path, 0o600);
}

async function publicJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  await rename(temporary, path);
  await chmod(path, 0o644);
}

async function fileHash(path: string): Promise<{ sha256: string; bytes: number }> {
  const bytes = await readFile(path);
  return { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.byteLength };
}

async function existing(path: string): Promise<boolean> {
  try { await stat(path); return true; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
}

function accountIdFromPublicKey(publicKey: string, role: Role): string {
  const suffix = createHash('sha256').update(publicKey).digest('hex').slice(0, 8);
  return `clearroute-${role}-${suffix}.testnet`;
}

async function faucetCreate(accountId: string, publicKey: string): Promise<void> {
  const response = await fetch(helperUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ newAccountId: accountId, newAccountPublicKey: publicKey }),
    redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) fail(`NEAR Testnet helper returned HTTP ${response.status}`);
  const body = await response.json() as { status?: unknown; final_execution_status?: string };
  if (!body.status || typeof body.status !== 'object' || !Object.hasOwn(body.status, 'SuccessValue')) {
    fail('NEAR Testnet helper did not return a successful account-creation outcome');
  }
}

async function createCredential(role: Role): Promise<Credential> {
  const keyPair = KeyPair.fromRandom('ed25519');
  const publicKey = keyPair.getPublicKey().toString();
  const accountId = accountIdFromPublicKey(publicKey, role);
  const credential: Credential = { accountId, publicKey, secretKey: keyPair.toString() };
  await privateJson(join(localRoot, `${role}-account.json`), credential);
  return credential;
}

async function readCredential(role: Role, expectedAccountId: string | undefined): Promise<Credential> {
  const candidates = [
    join(localRoot, 'credentials', `${role}.json`),
    join(localRoot, `${role}-account.json`),
    role === 'owner' ? join(localRoot, 'faucet-account.json') : '',
  ].filter(Boolean);
  let value: unknown;
  let source = '';
  for (const candidate of candidates) {
    if (!await existing(candidate)) continue;
    const details = await lstat(candidate);
    if (!details.isFile() || details.isSymbolicLink()) fail('Deployment credentials must be regular files');
    await chmod(candidate, 0o600);
    value = JSON.parse(await readFile(candidate, 'utf8'));
    source = candidate;
    break;
  }
  if (!value || typeof value !== 'object') fail(`Missing ${role} credential under ${localRoot}`);
  const raw = value as Record<string, unknown>;
  const accountId = typeof raw.accountId === 'string' ? raw.accountId : typeof raw.account_id === 'string' ? raw.account_id : '';
  const publicKey = typeof raw.publicKey === 'string' ? raw.publicKey : typeof raw.public_key === 'string' ? raw.public_key : '';
  const secretKey = typeof raw.secretKey === 'string' ? raw.secretKey : typeof raw.secret_key === 'string' ? raw.secret_key : typeof raw.private_key === 'string' ? raw.private_key : '';
  if (!accountId || !publicKey || !secretKey) fail(`Invalid ${role} credential at ${source}`);
  if (expectedAccountId && accountId !== expectedAccountId) fail(`${role} credential account does not match the configured account`);
  validateCredential({ accountId, publicKey, secretKey });
  return { accountId, publicKey, secretKey };
}

async function loadOrCreateCredential(role: Role, expectedAccountId: string | undefined): Promise<Credential> {
  try { return await readCredential(role, expectedAccountId); }
  catch (error) {
    if (expectedAccountId || !(error instanceof Error) || !error.message.startsWith('Missing ')) throw error;
    return createCredential(role);
  }
}

function memoryKeyStore(credentials: Credential[]): KeyStore {
  const keys = new Map(credentials.map(value => [`${networkId}:${value.accountId}`, KeyPair.fromString(value.secretKey as Parameters<typeof KeyPair.fromString>[0])]));
  return {
    async setKey(network: string, accountId: string, keyPair: KeyPair) { keys.set(`${network}:${accountId}`, keyPair); },
    async getKey(network: string, accountId: string) { return keys.get(`${network}:${accountId}`) ?? null; },
    async removeKey(network: string, accountId: string) { keys.delete(`${network}:${accountId}`); },
    async clear() { keys.clear(); },
    async getAccounts(network: string) { return [...keys.keys()].filter(key => key.startsWith(`${network}:`)).map(key => key.slice(network.length + 1)); },
  } as KeyStore;
}

export function deploymentManifest(sourceManifest: CryptoManifest, coreAccountId: string): CryptoManifest {
  validateManifest(sourceManifest, { networkId: sourceManifest.networkId, coreAccountId: sourceManifest.coreAccountId, profileHash: sourceManifest.profileHash, funded: false });
  if (sourceManifest.setup !== 'development-single-party') fail('Expected the existing development artifact manifest');
  const allowedArtifactNames = new Set([
    'native.prover', 'browser.glue', 'browser.wasm',
    ...proofFamilies.flatMap(family => ['pk', 'vk', 'prepared-vk'].map(suffix => `${family}.${suffix}`)),
  ]);
  for (const [name, entry] of Object.entries(sourceManifest.artifacts)) {
    if (!allowedArtifactNames.has(name) || !entry.path || entry.path !== entry.path.split('/').pop() || entry.path === '.' || entry.path === '..' || /secret|private|witness|toxic/i.test(entry.path)) fail(`Unsafe or non-public artifact entry: ${name}`);
  }
  for (const name of allowedArtifactNames) if (!sourceManifest.artifacts[name]) fail(`Missing deployment artifact: ${name}`);
  return { ...sourceManifest, networkId, coreAccountId };
}

async function prepareArtifacts(manifest: CryptoManifest, pin: string): Promise<void> {
  const manifestPath = join(artifactRoot, 'manifest.json');
  if (await existing(manifestPath) && await manifestHash(JSON.parse(await readFile(manifestPath, 'utf8')) as CryptoManifest) !== pin) fail('Existing artifact directory belongs to a different deployment; it was not modified');
  // Validate the complete input before changing any output file.
  for (const entry of Object.values(manifest.artifacts)) await checkEntry(sourceRoot, entry);
  await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  for (const [name, entry] of Object.entries(manifest.artifacts)) {
    const source = await checkEntry(sourceRoot, entry);
    const destination = join(artifactRoot, entry.path);
    if (await existing(destination)) {
      const destinationReal = await realpath(destination);
      const artifactBase = await realpath(artifactRoot);
      if (destinationReal !== artifactBase && !destinationReal.startsWith(`${artifactBase}${sep}`)) fail(`Artifact destination escapes the configured output directory: ${name}`);
    }
    if (!await existing(destination)) await copyFile(source, destination);
    const copied = await fileHash(destination);
    if (copied.sha256 !== entry.sha256 || copied.bytes !== entry.bytes) fail(`Copied artifact changed: ${name}`);
    await chmod(destination, name === 'native.prover' ? 0o700 : 0o644);
  }
  await publicJson(join(artifactRoot, 'manifest.json'), manifest);
  await publicJson(join(artifactRoot, 'deployment-pin.json'), {
    networkId, coreAccountId: manifest.coreAccountId, profileHash: manifest.profileHash, manifestHash: pin,
    setup: manifest.setup, funded: false,
  });
}

async function loadWalletKeys(manifest: CryptoManifest, tokenAccountId: string): Promise<{ crypto: NativeCrypto; keys: Keyring; issuer: KeyReference; auditor: KeyReference }> {
  const native = manifest.artifacts['native.prover'];
  if (!native) fail('Native prover artifact is missing');
  const crypto = new NativeCrypto(artifactRoot, native, manifest.artifacts);
  const identity = { networkId, coreAccountId: manifest.coreAccountId, assetId: tokenAccountId, profileHash: manifest.profileHash };
  const keys = new Keyring(identity, crypto);
  const issuer: KeyReference = { role: 'issuer', subjectId: tokenAccountId, keyId: '1' };
  const auditor: KeyReference = { role: 'token_auditor', subjectId: tokenAccountId, keyId: '1' };
  const keyPath = join(localRoot, 'crypto-keys.json');
  if (await existing(keyPath)) await keys.importMaterial(JSON.parse(await readFile(keyPath, 'utf8')) as WalletMaterial);
  else {
    await keys.generate(issuer); await keys.generate(auditor);
    await privateJson(keyPath, keys.exportMaterial());
  }
  return { crypto, keys, issuer, auditor };
}

function txHash(result: unknown): string | null {
  if (!result || typeof result !== 'object') return null;
  const receipt = (result as { transactionReceipt?: { hash?: unknown } }).transactionReceipt;
  return receipt && typeof receipt.hash === 'string' ? receipt.hash : null;
}

async function run(): Promise<void> {
  validateRpcUrl(rpcUrl);
  await mkdir(localRoot, { recursive: true, mode: 0o700 });
  await chmod(localRoot, 0o700);
  const { values } = parseArgs({ options: {
    owner: { type: 'string' }, core: { type: 'string' }, token: { type: 'string' },
    'artifact-base-url': { type: 'string' },
  }, allowPositionals: false });
  const owner = await loadOrCreateCredential('owner', values.owner ?? process.env.TESTNET_OWNER_ACCOUNT);
  const core = await loadOrCreateCredential('core', values.core ?? process.env.TESTNET_CORE_ACCOUNT);
  const token = await loadOrCreateCredential('token', values.token ?? process.env.TESTNET_TOKEN_ACCOUNT);
  for (const credential of [owner, core, token]) await ensureAccount(credential);
  const manifest = deploymentManifest(JSON.parse(await readFile(join(sourceRoot, 'manifest.json'), 'utf8')) as CryptoManifest, core.accountId);
  const pin = await manifestHash(manifest);
  const manager = new TestnetManager({
    network: networkId, rootAccountId: owner.accountId, testnetMasterAccountId: 'testnet',
    rpcAddr: rpcUrl, helperUrl, homeDir: localRoot, port: 0, rm: false, refDir: null,
    keyStore: memoryKeyStore([owner, core, token]),
  });
  const ownerAccount = manager.getAccount(owner.accountId);
  const coreAccount = manager.getAccount(core.accountId);
  const tokenAccount = manager.getAccount(token.accountId);
  const coreWasm = await readFile(join(contractRoot, 'confidential_core.wasm'));
  const tokenWasm = await readFile(join(contractRoot, 'test_token.wasm'));
  const expectedCoreHash = hashContract(coreWasm);
  const expectedTokenHash = hashContract(tokenWasm);
  const coreView = await coreAccount.accountView();
  if (coreView.code_hash !== '11111111111111111111111111111111' && coreView.code_hash !== expectedCoreHash) fail('Core account already contains a different contract; restore the exact deployed WASM');
  const tokenView = await tokenAccount.accountView();
  if (tokenView.code_hash !== '11111111111111111111111111111111' && tokenView.code_hash !== expectedTokenHash && process.env.TESTNET_ALLOW_TOKEN_UPGRADE !== 'true') fail('Token account already contains a different contract; set TESTNET_ALLOW_TOKEN_UPGRADE=true to apply a state-preserving test-token upgrade');
  const coreInitialized = await initialized(core.accountId, 'get_asset_profile');
  if (coreInitialized) {
    const asset = await coreAccount.view('get_asset_profile', {}) as { token_account: string; network_id: string; crypto_profile_hash: number[]; controller_account: string };
    const verifier = await coreAccount.view('get_verifier_config', {}) as { profile_hash: number[]; manifest_hash: number[] };
    if (asset.token_account !== token.accountId || asset.network_id !== networkId || asset.controller_account !== owner.accountId || hexBytes(asset.crypto_profile_hash) !== manifest.profileHash || hexBytes(verifier.profile_hash) !== manifest.profileHash || hexBytes(verifier.manifest_hash) !== pin) fail('Initialized Core does not match the requested deployment; no artifacts were modified');
  }
  await prepareArtifacts(manifest, pin);
  await mkdir(archivedContracts, { recursive: true, mode: 0o700 });
  for (const [name, bytes] of [['confidential_core.wasm', coreWasm], ['test_token.wasm', tokenWasm]] as const) {
    const destination = join(archivedContracts, name);
    if (await existing(destination) && hashContract(await readFile(destination)) === hashContract(bytes)) continue;
    const temporary = `${destination}.${process.pid}.tmp`;
    await writeFile(temporary, bytes, { flag: 'wx', mode: 0o644 });
    await rename(temporary, destination);
  }
  if (coreInitialized && !await existing(join(localRoot, 'crypto-keys.json'))) fail('Issuer/auditor keys for the initialized Core are missing; restore them before resuming');
  const wallet = await loadWalletKeys(manifest, token.accountId);
  if (coreInitialized) {
    const asset = await coreAccount.view('get_asset_profile', {}) as { issuer_key: { public_key: number[] }; token_auditor_key: { public_key: number[] } };
    const encoded = (key: KeyReference) => Buffer.from(JSON.stringify(wallet.keys.publicKey(key))).toString('hex');
    if (hexBytes(asset.issuer_key.public_key) !== encoded(wallet.issuer) || hexBytes(asset.token_auditor_key.public_key) !== encoded(wallet.auditor)) fail('Local issuer/auditor keys do not match the initialized Core');
  }
  const statePath = join(localRoot, 'deployment-state.json');
  let state: Record<string, unknown>;
  if (await existing(statePath)) {
    state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    const accounts = state.accounts as Record<string, unknown> | undefined;
    if (state.schema !== 'confidential-lending-testnet-state/v1' || state.networkId !== networkId || accounts?.owner !== owner.accountId || accounts.core !== core.accountId || accounts.token !== token.accountId) fail('Existing deployment state belongs to different Testnet accounts');
    if (!state.transactions || typeof state.transactions !== 'object' || Array.isArray(state.transactions)) state.transactions = {};
  } else {
    state = { schema: 'confidential-lending-testnet-state/v1', networkId, accounts: { owner: owner.accountId, core: core.accountId, token: token.accountId }, transactions: {} };
  }
  const record = async (name: string, result: unknown) => {
    (state.transactions as Record<string, unknown>)[name] = txHash(result);
    await privateJson(statePath, state);
  };
  const recordCall = async (name: string, result: unknown) => {
    await record(name, result);
    if (!result || typeof result !== 'object' || !(result as { succeeded?: boolean }).succeeded) fail(`${name} transaction failed`);
  };

  // The helper funds each account separately. The token account's surplus
  // covers Core's larger WASM while preserving the owner's storage budget.
  const ownerMinimum = 6n * near;
  const coreTarget = 16n * near;
  const tokenTarget = 3n * near;
  if (BigInt(coreWasm.length) * (near / 100_000n) + near > coreTarget || BigInt(tokenWasm.length) * (near / 100_000n) + near > tokenTarget) fail('Contract code exceeds the bounded deployment storage budget');
  const ownerBalance = BigInt((await ownerAccount.accountView()).amount);
  const coreBalance = BigInt((await coreAccount.accountView()).amount);
  let tokenBalance = BigInt((await tokenAccount.accountView()).amount);
  let coreTopUp = coreBalance < coreTarget ? coreTarget - coreBalance : 0n;
  const tokenSurplus = tokenBalance > tokenTarget ? tokenBalance - tokenTarget : 0n;
  const tokenContribution = coreTopUp < tokenSurplus ? coreTopUp : tokenSurplus;
  if (tokenContribution > 0n) {
    const result = await tokenAccount.transfer(core.accountId, tokenContribution);
    await recordCall('fundCoreFromToken', result);
    coreTopUp -= tokenContribution;
    tokenBalance = BigInt((await tokenAccount.accountView()).amount);
  }
  const tokenTopUp = tokenBalance < tokenTarget ? tokenTarget - tokenBalance : 0n;
  if ((coreTopUp > 0n || tokenTopUp > 0n) && ownerBalance < coreTopUp + tokenTopUp + ownerMinimum) fail('Owner account is not funded enough for bounded Testnet deployment top-ups');
  if (coreTopUp > 0n) {
    const result = await ownerAccount.transfer(core.accountId, coreTopUp);
    await record('fundCore', result);
    if (!result.succeeded) fail('Core funding transfer failed');
  }
  if (tokenTopUp > 0n) {
    const result = await ownerAccount.transfer(token.accountId, tokenTopUp);
    await record('fundToken', result);
    if (!result.succeeded) fail('Token funding transfer failed');
  }

  if (coreView.code_hash === '11111111111111111111111111111111') {
    const result = await coreAccount.deploy(coreWasm); await record('deployCore', result);
    if (!result.succeeded) fail('Core deployment failed');
  } else if (coreView.code_hash !== expectedCoreHash) fail('Core account already contains a different contract');
  if (tokenView.code_hash === '11111111111111111111111111111111') {
    const result = await tokenAccount.deploy(tokenWasm); await record('deployToken', result);
    if (!result.succeeded) fail('Token deployment failed');
  } else if (tokenView.code_hash !== expectedTokenHash) {
    if (process.env.TESTNET_ALLOW_TOKEN_UPGRADE !== 'true') {
      fail('Token account already contains a different contract; set TESTNET_ALLOW_TOKEN_UPGRADE=true to apply the state-preserving test-token upgrade');
    }
    const result = await tokenAccount.deploy(tokenWasm); await record('upgradeToken', result);
    if (!result.succeeded) fail('Token upgrade failed');
  }

  const tokenInitialized = await initialized(token.accountId, 'ft_total_supply');
  if (!tokenInitialized) {
    const result = await ownerAccount.callRaw(token.accountId, 'new', { owner_id: owner.accountId }, { gas: maxGas });
    await recordCall('initializeToken', result);
  }
  if (!coreInitialized) {
    const result = await ownerAccount.callRaw(core.accountId, 'new', { args: {
      token_account: token.accountId, decimals: 6, controller_account: owner.accountId,
      issuer_key_id: '1', issuer_public_key: Array.from(new TextEncoder().encode(JSON.stringify(wallet.keys.publicKey(wallet.issuer)))),
      token_auditor_key_id: '1', token_auditor_public_key: Array.from(new TextEncoder().encode(JSON.stringify(wallet.keys.publicKey(wallet.auditor)))),
      crypto_profile_hash: Array.from(Buffer.from(manifest.profileHash, 'hex')), network_id: networkId,
      token_trust_policy: 'testnet-test-token-v1', authorization_policy: 'permissionless-v1', freeze_policy: 'controller-freeze-v1',
      custody_cap: ((1n << 63n) - 1n).toString(), verifier_key: [],
      verifier_manifest_hash: Array.from(Buffer.from(pin, 'hex')), verifier_manifest_json: canonicalManifest(manifest),
    } }, { gas: maxGas });
    await recordCall('initializeCore', result);
  }
  const coreStorage = await coreAccount.view('storage_balance_of', { account_id: core.accountId }) as string;
  if (BigInt(coreStorage) === 0n) {
    const result = await coreAccount.callRaw(core.accountId, 'storage_deposit', { account_id: core.accountId }, { attachedDeposit: 2n * near, gas: maxGas });
    await recordCall('coreStorageDeposit', result);
  }
  const ownerStorage = await coreAccount.view('storage_balance_of', { account_id: owner.accountId }) as string;
  if (BigInt(ownerStorage) === 0n) {
    const result = await ownerAccount.callRaw(core.accountId, 'storage_deposit', { account_id: owner.accountId }, { attachedDeposit: 5n * near, gas: maxGas });
    await recordCall('ownerCoreStorageDeposit', result);
  }
  const verifier = await coreAccount.view('get_verifier_config', {}) as { activated: boolean; key_count: number };
  if (!verifier.activated) {
    for (const [index, family] of proofFamilies.entries()) {
      const entry = manifest.artifacts[`${family}.prepared-vk`];
      if (!entry) fail(`Missing prepared verifier key for ${family}`);
      // A provider outage can happen after a transaction is finalized but
      // before the client receives its response. Resume by checking the
      // immutable on-chain record instead of replaying a staged key.
      const existingKey = await coreAccount.view('get_verifier_key', { statement_kind: index + 1 }) as { verifying_key_hash?: number[] } | null;
      if (existingKey) continue;
      const preparedKey = await readFile(join(artifactRoot, entry.path));
      const result = await ownerAccount.callRaw(core.accountId, 'stage_verifier_key', { statement_kind: index + 1, prepared_key: Array.from(preparedKey) }, { gas: maxGas });
      await recordCall(`stageVerifierKey${index + 1}`, result);
    }
    const result = await ownerAccount.callRaw(core.accountId, 'activate_verifier_keys', {}, { gas: maxGas });
    await recordCall('activateVerifierKeys', result);
  }
  for (const accountId of [owner.accountId, core.accountId]) {
    const storage = await tokenAccount.view('storage_balance_of', { account_id: accountId }) as { total?: string } | null;
    if (!storage) {
      const result = await ownerAccount.callRaw(token.accountId, 'storage_deposit', { account_id: accountId, registration_only: true }, { attachedDeposit: near / 100n, gas: maxGas });
      await recordCall(`tokenStorageDeposit:${accountId}`, result);
    }
  }
  const tokenSupply = await tokenAccount.view('ft_total_supply', {}) as string;
  if (BigInt(tokenSupply) === 0n) {
    const result = await ownerAccount.callRaw(token.accountId, 'mint', { receiver_id: owner.accountId, amount: '1000000000000' }, { gas: maxGas });
    await recordCall('mintOperatorTest', result);
  }
  const tokenMetadata = await tokenAccount.view('ft_metadata', {}) as { symbol: string; decimals: number };
  const faucetAmount = await tokenAccount.view('faucet_claim_amount', {}) as string;
  if (tokenMetadata.symbol !== 'TEST' || tokenMetadata.decimals !== 6 || faucetAmount !== '1000000000') fail('Test-token metadata or faucet readback did not match the pinned ABI');
  const asset = await coreAccount.view('get_asset_profile', {}) as { token_account: string; network_id: string; crypto_profile_hash: number[] };
  const activated = await coreAccount.view('get_verifier_config', {}) as { activated: boolean; key_count: number };
  if (asset.token_account !== token.accountId || asset.network_id !== networkId || !activated.activated || activated.key_count !== proofFamilies.length) fail('Testnet deployment readback did not match the requested identities');
  const publicConfig: PublicDeployment = {
    schema: 'confidential-lending-testnet/v1', networkId, rpcUrl,
    coreAccountId: core.accountId, tokenAccountId: token.accountId, controllerAccountId: owner.accountId,
    profileHash: manifest.profileHash, manifestHash: pin, coreWasmHash: expectedCoreHash, tokenWasmHash: expectedTokenHash,
    artifactBaseUrl: process.env.TESTNET_ARTIFACT_BASE_URL ?? values['artifact-base-url'] ?? null, artifactHosting: 'not-hosted',
    token: {
      symbol: 'TEST', decimals: 6, mintAuthority: owner.accountId, registrationMethod: 'storage_deposit', mintMethod: 'mint', mintAuthorityIsNotPublic: true,
      metadataMethod: 'ft_metadata', faucetClaimMethod: 'faucet_claim', faucetHasClaimedMethod: 'faucet_has_claimed', faucetClaimAmount: faucetAmount,
      faucetRequiresStorageRegistration: true,
    },
    verifier: { statementKinds: proofFamilies.map((_, index) => index + 1), activated: true, keyCount: proofFamilies.length },
  };
  await publicJson(join(localRoot, 'public.json'), publicConfig);
  await privateJson(statePath, state);
  wallet.keys.clear();
  console.log(`Testnet deployment verified. Core: ${core.accountId}; token: ${token.accountId}`);
  console.log(`Public configuration: ${join(localRoot, 'public.json')}`);
  console.log(`Public artifact directory is prepared at ${artifactRoot}; hosting is not configured.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await run();
