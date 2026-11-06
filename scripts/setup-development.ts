import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { buildDevelopmentArtifacts } from './development-artifacts.js';

const { values } = parseArgs({ options: {
  network: { type: 'string', default: 'sandbox' }, core: { type: 'string', default: 'core.test.near' },
  output: { type: 'string', default: '.artifacts/development' },
  native: { type: 'string', default: 'target/prover/confidential-crypto' },
  'prepare-key': { type: 'string', default: 'target/release/examples/prepare_key' },
  'browser-dir': { type: 'string', default: '.artifacts/browser' },
} });
const result = await buildDevelopmentArtifacts({
  output: values.output!, networkId: values.network!, coreAccountId: values.core!,
  executable: resolve(values.native!),
  prepareKeyExecutable: resolve(values['prepare-key']!),
  browserGlue: resolve(values['browser-dir']!, 'confidential_crypto.js'),
  browserWasm: resolve(values['browser-dir']!, 'confidential_crypto_bg.wasm'),
  progress: message => process.stdout.write(`${message}\n`),
});
process.stdout.write(`Development artifacts ready. Deployment manifest SHA-256: ${result.manifestHash}\n`);
