import type { CryptoManifest } from '../../packages/client/src/artifacts.js';
import { BrowserProver } from '../../packages/wallet/src/prover.js';
import { validateCryptoClient, type ProofMeasurement } from '../crypto-fixtures.js';

declare global { interface Window { validation: { status: 'running' | 'passed' | 'failed'; measurements: ProofMeasurement[]; result?: unknown; error?: string } } }
const progress = document.querySelector('#progress')!;
window.validation = { status: 'running', measurements: [] };
let prover: BrowserProver | undefined;
try {
  const baseUrl = new URLSearchParams(location.search).get('artifacts');
  if (!baseUrl || new URL(baseUrl).hostname !== '127.0.0.1' || new URL(baseUrl).protocol !== 'http:') throw new Error('Validation requires local artifacts');
  const manifest = await (await fetch(`${baseUrl}/manifest.json`)).json() as CryptoManifest;
  const pin = await (await fetch(`${baseUrl}/deployment-pin.json`)).json() as { manifestHash: string };
  if (manifest.networkId !== 'sandbox' || manifest.setup !== 'development-single-party') throw new Error('Validation requires sandbox development artifacts');
  prover = new BrowserProver(new Worker(new URL('../../packages/wallet/src/worker.ts', import.meta.url), { type: 'module' }), {
    baseUrl, manifest, expected: { manifestHash: pin.manifestHash, profileHash: manifest.profileHash, networkId: manifest.networkId, coreAccountId: manifest.coreAccountId, funded: false },
  });
  const result = await validateCryptoClient(prover, { networkId: manifest.networkId, coreAccountId: manifest.coreAccountId, assetId: 'token.test.near', profileHash: manifest.profileHash }, async measurement => {
    Object.assign(measurement, await prover!.execute('runtime_metrics', {}));
    window.validation.measurements.push(measurement);
    progress.textContent = JSON.stringify(window.validation.measurements, null, 2);
    console.info(`Verified browser ${measurement.operation} in ${measurement.milliseconds}ms`);
  });
  window.validation = { status: 'passed', measurements: result.measurements, result: { ...result, profileHash: manifest.profileHash, manifestHash: pin.manifestHash } };
  progress.textContent += '\nAll proof families passed, modified context rejected.';
} catch (error) {
  window.validation.status = 'failed';
  // Executor errors contain categories, never request bodies or private witnesses.
  window.validation.error = error instanceof Error ? error.message : 'Browser validation failed';
  progress.textContent += `\n${window.validation.error}`;
} finally { prover?.close(); }
