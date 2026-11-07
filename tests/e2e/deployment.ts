import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
import type { NearAccount, Worker } from 'near-workspaces';
import { NearRpc, canonicalManifest, verifyManifestPin, type CryptoManifest } from '../../packages/client/src/index.js';
import { Keyring, type KeyReference } from '../../packages/wallet/src/keyring.js';
import { NativeCrypto } from '../../packages/wallet/src/native.js';
import { ProofBuilder, jsonBytes, wireBytes } from '../../packages/wallet/src/proofs.js';
import { proofFamilies } from '../../scripts/development-artifacts.js';
import { startSandbox } from '../sandbox.js';

export const maximumGas = 300_000_000_000_000n;
export const near = 10n ** 24n;
export interface TestDeployment {
  worker: Worker;
  core: NearAccount;
  token: NearAccount;
  actors: Record<'lender' | 'broker' | 'borrower' | 'recipient' | 'issuer' | 'auditor' | 'keeper', NearAccount>;
  rpc: NearRpc;
  crypto: NativeCrypto;
  keys: Keyring;
  proofs: ProofBuilder;
  manifest: CryptoManifest;
  manifestHash: string;
  coreWasmHash: string;
}

/** Deploys real contracts and real proof keys into an isolated ephemeral chain. No state patching or verifier bypass. */
export async function deployProtocol(directory = process.env.CRYPTO_ARTIFACT_DIR ?? '.artifacts/development'): Promise<TestDeployment> {
  const artifactRoot = resolve(directory);
  const manifest = JSON.parse(await readFile(join(artifactRoot, 'manifest.json'), 'utf8')) as CryptoManifest;
  const pin = JSON.parse(await readFile(join(artifactRoot, 'deployment-pin.json'), 'utf8')) as { manifestHash: string };
  await verifyManifestPin(manifest, pin.manifestHash);
  if (manifest.networkId !== 'sandbox' || manifest.setup !== 'development-single-party') throw new Error('Sandbox fixtures require development-only sandbox artifacts');
  const crypto = new NativeCrypto(artifactRoot, manifest.artifacts['native.prover']!, manifest.artifacts);
  const worker = await startSandbox();
  try {
    const core = await worker.rootAccount.createSubAccount('core', { initialBalance: 1_000n * near });
    const token = await worker.rootAccount.createSubAccount('token', { initialBalance: 100n * near });
    if (core.accountId !== manifest.coreAccountId) throw new Error('Sandbox Core identity does not match artifacts');
    const actors = {} as TestDeployment['actors'];
    for (const name of ['lender', 'broker', 'borrower', 'recipient', 'issuer', 'auditor', 'keeper'] as const) {
      actors[name] = await worker.rootAccount.createSubAccount(name, { initialBalance: 200n * near });
    }
    const keys = new Keyring({ networkId: manifest.networkId, coreAccountId: core.accountId, assetId: token.accountId, profileHash: manifest.profileHash }, crypto);
    const issuerKey: KeyReference = { role: 'issuer', subjectId: token.accountId, keyId: '1' };
    const auditorKey: KeyReference = { role: 'token_auditor', subjectId: token.accountId, keyId: '1' };
    await keys.generate(issuerKey);
    await keys.generate(auditorKey);
    await token.deploy(resolve('.artifacts/contracts/test_token.wasm'));
    await worker.rootAccount.call(token, 'new', { owner_id: worker.rootAccount.accountId });
    const coreWasm = await readFile(resolve('.artifacts/contracts/confidential_core.wasm'));
    const coreWasmHash = createHash('sha256').update(coreWasm).digest('hex');
    await core.deploy(coreWasm);
    await worker.rootAccount.call(core, 'new', { args: {
      token_account: token.accountId, decimals: 6, controller_account: actors.issuer.accountId,
      issuer_key_id: '1', issuer_public_key: jsonBytes(keys.publicKey(issuerKey)),
      token_auditor_key_id: '1', token_auditor_public_key: jsonBytes(keys.publicKey(auditorKey)),
      crypto_profile_hash: wireBytes(manifest.profileHash), network_id: manifest.networkId,
      token_trust_policy: 'sandbox-test-token-v1', authorization_policy: 'permissionless-v1', freeze_policy: 'controller-freeze-v1',
      custody_cap: ((1n << 63n) - 1n).toString(), verifier_key: [], verifier_manifest_hash: wireBytes(pin.manifestHash),
      verifier_manifest_json: canonicalManifest(manifest),
    } }, { gas: maximumGas });
    for (const [index, family] of proofFamilies.entries()) {
      const entry = manifest.artifacts[`${family}.prepared-vk`];
      if (!entry) throw new Error('Missing prepared verification key');
      const prepared = await readFile(join(artifactRoot, entry.path));
      await worker.rootAccount.call(core, 'stage_verifier_key', { statement_kind: index + 1, prepared_key: Array.from(prepared) }, { gas: maximumGas });
    }
    await worker.rootAccount.call(core, 'activate_verifier_keys', {}, { gas: maximumGas });
    for (const account of [worker.rootAccount, core, ...Object.values(actors)]) {
      await worker.rootAccount.call(token, 'storage_deposit', { account_id: account.accountId, registration_only: true }, { attachedDeposit: near });
      if (account !== core) await account.call(core, 'storage_deposit', { account_id: account.accountId }, { attachedDeposit: 20n * near });
    }
    for (const actor of [actors.lender, actors.borrower]) await worker.rootAccount.call(token, 'mint', { receiver_id: actor.accountId, amount: '1000000000' });
    return { worker, core, token, actors, rpc: new NearRpc(worker.provider.connection.url, { allowInsecureLocalhost: true }), crypto, keys, proofs: new ProofBuilder(crypto, keys), manifest, manifestHash: pin.manifestHash, coreWasmHash };
  } catch (error) { await worker.tearDown(); throw error; }
}
