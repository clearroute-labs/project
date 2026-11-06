import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { buildDevelopmentArtifacts } from './development-artifacts.js';

const { values } = parseArgs({ options: {
  network: { type: 'string', default: 'sandbox' }, core: { type: 'string', default: 'core.test.near' },
  output: { type: 'string', default: '.artifacts/development' },
} });
const result = await buildDevelopmentArtifacts({
  output: values.output!, networkId: values.network!, coreAccountId: values.core!,
  executable: resolve('target/prover/confidential-crypto'),
  prepareKeyExecutable: resolve('target/release/examples/prepare_key'),
  browserGlue: resolve('.artifacts/browser/confidential_crypto.js'),
  browserWasm: resolve('.artifacts/browser/confidential_crypto_bg.wasm'),
  progress: message => process.stdout.write(`${message}\n`),
});
process.stdout.write(`Development artifacts ready. Deployment manifest SHA-256: ${result.manifestHash}\n`);
