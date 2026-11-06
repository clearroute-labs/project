import { join } from 'node:path';
import { abortableDelay, NearRpc, validateManifest, verifyManifestPin, type CryptoManifest } from '@confidential-lending/client';
import { decryptWalletBackup, Keyring, LedgerWallet } from '@confidential-lending/wallet';
import { NativeCrypto } from '@confidential-lending/wallet/native';
import { readBoundedFile, readConfig, readPassphrase } from './config.js';
import { KeeperEngine } from './engine.js';
import { Journal } from './journal.js';
import { SettlementPlanner, type KeeperNotice } from './planner.js';
import { KeeperSigner } from './signer.js';
import { NativeKeeperWallet } from './wallet.js';
import { classifyKeeperError } from './errors.js';

const command = process.argv[2], configPath = process.argv[3];
if (!['run', 'once', 'rebroadcast'].includes(command ?? '') || !configPath || process.argv.length !== 4) {
  console.error('Usage: pnpm --filter @confidential-lending/keeper start <run|once|rebroadcast> <config.json> < passphrase-file');
  process.exitCode = 2;
} else {
  const controller = new AbortController();
  const stop = () => controller.abort(new Error('Keeper stopped'));
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  let keys: Keyring | undefined;
  try {
    const config = await readConfig(configPath);
    const rpc = new NearRpc(config.rpcUrl, { allowInsecureLocalhost: config.allowInsecureLocalhost });
    const manifest = JSON.parse(await readBoundedFile(join(config.artifactDirectory, 'manifest.json'), 256 * 1024)) as CryptoManifest;
    validateManifest(manifest, config);
    await verifyManifestPin(manifest, config.manifestHash);
    const native = manifest.artifacts['native.prover'];
    if (!native) throw new Error('Native prover is absent from the deployment manifest');
    const crypto = new NativeCrypto(config.artifactDirectory, native, manifest.artifacts, 10 * 60_000, controller.signal);
    keys = new Keyring({ networkId: config.networkId, coreAccountId: config.coreAccountId, assetId: config.assetId, profileHash: config.profileHash }, crypto);
    const material = await decryptWalletBackup(JSON.parse(await readBoundedFile(config.encryptedBackupFile, 12 * 1024 * 1024, true)), await readPassphrase());
    await keys.importMaterial(material);
    const allowed = new Set(config.brokers.map(policy => policy.brokerId));
    if (keys.exportMaterial().keys.some(key => key.role !== 'broker' || !allowed.has(key.subjectId))) throw new Error('Provision a keeper-only backup containing keys for its configured brokers');
    const signer = await KeeperSigner.fromFile(rpc, config.coreAccountId, config.credentialsFile);
    const reported = new Map<string, string>();
    const report = (notice: KeeperNotice) => {
      if (reported.get(notice.brokerId) === notice.state) return;
      reported.set(notice.brokerId, notice.state);
      console.log(JSON.stringify({ at: new Date().toISOString(), ...notice }));
    };
    const planner = new SettlementPlanner(new NativeKeeperWallet(new LedgerWallet(rpc, keys, crypto, config.manifestHash), signer.signerId), signer, config.brokers, report);
    const engine = new KeeperEngine(new Journal(config.journalFile), planner, config.intervalMs);
    do {
      controller.signal.throwIfAborted();
      try {
        const result = command === 'rebroadcast' ? await engine.rebroadcastPending() : await engine.tick();
        if (result.state !== 'idle') console.log(JSON.stringify({ at: new Date().toISOString(), ...result, ...(result.state === 'failed' ? { reason: signer.lastFailure } : {}) }));
      } catch (error) {
        if (controller.signal.aborted) break;
        // Do not emit untrusted exception messages: prover/RPC payloads can contain private data.
        console.error(JSON.stringify({ at: new Date().toISOString(), state: classifyKeeperError(error), pendingTransactionPreserved: true }));
        if (command !== 'run') { process.exitCode = 1; break; }
      }
      if (command !== 'run') break;
      await abortableDelay(config.intervalMs, controller.signal);
    } while (!controller.signal.aborted);
  } catch {
    if (!controller.signal.aborted) { console.error('Keeper initialization failed. Check deployment pins, file permissions, backup provisioning, and account scope.'); process.exitCode = 1; }
  } finally { keys?.clear(); process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
