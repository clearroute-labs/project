import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { startSandbox } from '../sandbox.js';

test('real NEAR host verification accepts the proof and rejects modified public inputs', { timeout: 120_000 }, async () => {
  const fixture = JSON.parse(await readFile(resolve('.artifacts/verifier-fixture.json'), 'utf8')) as {
    verifying_key_hex: string; proof_hex: string; public_inputs: string[]; wrong_inputs: string[];
  };
  const worker = await startSandbox();
  try {
    const probe = await worker.rootAccount.createSubAccount('verifier', { initialBalance: 100n * 10n ** 24n });
    await probe.deploy(resolve('target/wasm32-unknown-unknown/release/verifier_probe.wasm'));
    const initialize = await worker.rootAccount.callRaw(probe, 'new', { verifying_key_hex: fixture.verifying_key_hex }, { gas: 300_000_000_000_000n });
    assert.equal(initialize.succeeded, true);
    const valid = await worker.rootAccount.callRaw(probe, 'verify', {
      proof_hex: fixture.proof_hex, public_inputs: fixture.public_inputs,
    }, { gas: 300_000_000_000_000n });
    assert.equal(valid.parseResult<boolean>(), true);
    await writeFile(resolve('.artifacts/verifier-benchmark.json'), JSON.stringify({ publicInputs: fixture.public_inputs.length, gasBurnt: valid.gas_burnt, initializationGasBurnt: initialize.gas_burnt, runtime: 'near-sandbox 2.14.0', durationMs: valid.durationMs }, null, 2));
    const invalid = await worker.rootAccount.call<boolean>(probe, 'verify', {
      proof_hex: fixture.proof_hex, public_inputs: fixture.wrong_inputs,
    }, { gas: 300_000_000_000_000n });
    assert.equal(invalid, false);
    const malformed = await worker.rootAccount.call<boolean>(probe, 'verify', {
      proof_hex: '00', public_inputs: fixture.public_inputs,
    }, { gas: 300_000_000_000_000n });
    assert.equal(malformed, false);
  } finally { await worker.tearDown(); }
});
