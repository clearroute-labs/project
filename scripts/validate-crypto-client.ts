import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { verifyManifestPin, type CryptoManifest } from '../packages/client/src/artifacts.js';
import { NativeCrypto } from '../packages/wallet/src/native.js';
import { validateCryptoClient } from '../tests/crypto-fixtures.js';

const directory = resolve(process.argv[2] ?? '.artifacts/development');
const manifest = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8')) as CryptoManifest;
const pin = JSON.parse(await readFile(join(directory, 'deployment-pin.json'), 'utf8')) as { manifestHash: string };
await verifyManifestPin(manifest, pin.manifestHash);
const crypto = new NativeCrypto(directory, manifest.artifacts['native.prover']!, manifest.artifacts);
const result = await validateCryptoClient(crypto, {
  networkId: manifest.networkId, coreAccountId: manifest.coreAccountId, assetId: 'token.test.near', profileHash: manifest.profileHash,
}, measurement => { process.stdout.write('Verified ' + measurement.operation + '\n'); });
await writeFile(join(directory, 'client-validation.json'), JSON.stringify({
  profileHash: manifest.profileHash, manifestHash: pin.manifestHash,
  measurements: result.measurements, modifiedContextRejected: result.modifiedContextRejected,
}, null, 2) + '\n');
await writeFile(join(directory, 'client-operations.json'), JSON.stringify(result.operations) + '\n');
process.stdout.write('All eight proof families passed native client integration.\n');
