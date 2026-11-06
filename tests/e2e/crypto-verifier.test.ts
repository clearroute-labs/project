import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { startSandbox } from '../sandbox.js';

const KINDS = [
  'key-possession',
  'public-conversion',
  'confidential-transfer',
  'origination',
  'repayment',
  'reconciliation',
  'zero-balance',
  'ownership',
] as const;

type Kind = (typeof KINDS)[number];
type OperationFixture = { name: string; statement: unknown; envelope: unknown };
type Manifest = {
  artifacts: Record<string, { path: string; sha256: string; bytes: number }>;
};
type GasMeasurement = {
  status: 'passed' | 'failed' | 'rejected';
  publicInputs: number;
  gasBurnt: string;
  within300T: boolean;
  durationMs: number | undefined;
  error?: string;
};

const fixtureDirectory = resolve(process.env.CRYPTO_ARTIFACT_DIR ?? '.artifacts/integration-v2');
const benchmarkGas = 300_000_000_000_000n;

async function available(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function jsonText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function statementKind(operation: OperationFixture): Kind {
  const statement = typeof operation.statement === 'string' ? JSON.parse(operation.statement) as Record<string, unknown> : operation.statement as Record<string, unknown>;
  const variant = Object.keys(statement)[0];
  const variants: Record<string, Kind> = {
    KeyPossession: 'key-possession', PublicConversion: 'public-conversion',
    ConfidentialTransfer: 'confidential-transfer', Origination: 'origination',
    Repayment: 'repayment', Reconciliation: 'reconciliation',
    ZeroBalance: 'zero-balance', Ownership: 'ownership',
  };
  const kind = variants[variant ?? ''];
  if (!kind) throw new Error(`fixture ${operation.name} has an unknown Statement variant`);
  return kind;
}

function gasString(value: unknown): string {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value).toString();
  if (typeof value === 'string' && /^\d+$/.test(value)) return value;
  throw new Error('Sandbox returned an invalid gas value');
}

function gasStringOrUnknown(value: unknown): string {
  try {
    return gasString(value);
  } catch {
    return 'unknown';
  }
}

function errorString(value: unknown): string {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return 'unknown execution error';
  }
}

function mutateStatement(value: unknown): unknown {
  let changed = false;
  const mutate = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(mutate);
    if (node === null || typeof node !== 'object') return node;
    const object = node as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(object)) {
      if (!changed && key === 'expiry' && typeof child === 'string') {
        result[key] = child === '0' ? '1' : '0';
        changed = true;
      } else {
        result[key] = mutate(child);
      }
    }
    return result;
  };
  const result = mutate(value);
  if (!changed) throw new Error('Fixture statement has no mutable context expiry');
  return result;
}

async function preparedKeyHex(manifest: Manifest, kind: Kind): Promise<string> {
  const name = `${kind}.prepared-vk`;
  const entry = manifest.artifacts[name];
  assert.ok(entry, `manifest is missing ${name}`);
  assert.match(entry.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(entry.bytes) && entry.bytes > 0);
  const bytes = await readFile(resolve(fixtureDirectory, entry.path));
  assert.equal(bytes.byteLength, entry.bytes, `${name} size mismatch`);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256, `${name} hash mismatch`);
  return bytes.toString('hex');
}

test('typed NEAR host verification accepts all real proof families and rejects changed statements', { timeout: 600_000 }, async (t) => {
  const operationsPath = resolve(fixtureDirectory, 'client-operations.json');
  const manifestPath = resolve(fixtureDirectory, 'manifest.json');
  if (!(await available(operationsPath)) || !(await available(manifestPath))) {
    t.skip(`real crypto fixtures are not installed at ${fixtureDirectory}`);
    return;
  }
  const wasmPath = resolve(process.env.CRYPTO_PROBE_WASM ?? 'target/wasm32-unknown-unknown/release/verifier_probe.wasm');
  assert.ok(await available(wasmPath), 'build verifier-probe.wasm before running this test');

  const operations = JSON.parse(await readFile(operationsPath, 'utf8')) as OperationFixture[];
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as Manifest;
  assert.ok(operations.length >= KINDS.length, 'expected real proofs covering all families');
  const familyCoverage = new Set(operations.map(statementKind));
  assert.deepEqual([...familyCoverage].sort(), [...KINDS].sort());

  const worker = await startSandbox();
  try {
    const probe = await worker.rootAccount.createSubAccount('typed-verifier', { initialBalance: 100n * 10n ** 24n });
    await probe.deploy(wasmPath);
    const initialize = await worker.rootAccount.callRaw(probe, 'new_typed', {}, { gas: benchmarkGas });
    assert.equal(initialize.succeeded, true);

    const keys = await Promise.all(KINDS.map(async kind => ({ kind, prepared_key_hex: await preparedKeyHex(manifest, kind) })));
    for (const key of keys) {
      const installed = await worker.rootAccount.callRaw(probe, 'install_verifying_key', key, { gas: benchmarkGas });
      assert.equal(installed.succeeded, true, `install ${key.kind} failed`);
      assert.equal(installed.parseResult<boolean>(), true, `install ${key.kind} was not acknowledged`);
    }
    const duplicate = await worker.rootAccount.callRaw(probe, 'install_verifying_key', keys[0]!, { gas: benchmarkGas });
    assert.equal(duplicate.succeeded, true);
    assert.equal(duplicate.parseResult<boolean>(), false, 'per-kind key replacement must be rejected');
    const installedKinds = await worker.rootAccount.callRaw(probe, 'installed_kinds', {}, { gas: benchmarkGas });
    assert.equal(installedKinds.succeeded, true);
    assert.deepEqual(installedKinds.parseResult<string[]>().sort(), [...KINDS].sort());

    const families: Record<string, { operations: string[]; measurements: Record<string, GasMeasurement> }> = {};
    for (const kind of KINDS) families[kind] = { operations: [], measurements: {} };
    const writeMeasurements = async (): Promise<void> => {
      await writeFile(resolve(fixtureDirectory, 'verifier-probe-gas.json'), `${JSON.stringify({
        schema: 'confidential-lending-verifier-probe/v1',
        runtime: 'near-sandbox 2.14.0',
        gasLimit: '300000000000000',
        benchmarkGas: benchmarkGas.toString(),
        initializationGasBurnt: gasString(initialize.gas_burnt),
        families,
      }, null, 2)}\n`);
    };
    for (const operation of operations) {
      const kind = statementKind(operation);
      const statementJson = jsonText(operation.statement);
      const envelopeJson = jsonText(operation.envelope);
      const derived = await worker.rootAccount.callRaw(probe, 'derive_public_inputs', { statement_json: statementJson }, { gas: benchmarkGas });
      if (!derived.succeeded) {
        families[kind]!.operations.push(operation.name);
        families[kind]!.measurements[operation.name] = {
          status: 'failed', publicInputs: 0, gasBurnt: gasStringOrUnknown(derived.gas_burnt),
          within300T: false, durationMs: derived.durationMs, error: errorString(derived),
        };
        await writeMeasurements();
      }
      assert.equal(derived.succeeded, true, `derive ${kind} failed`);
      const statementInputs = derived.parseResult<string[]>() ?? [];
      const envelope = typeof operation.envelope === 'string' ? JSON.parse(operation.envelope) as Record<string, unknown> : operation.envelope as Record<string, unknown>;
      assert.deepEqual(statementInputs, envelope.public_inputs, `${kind} Core/public-input derivation mismatch`);

      const valid = await worker.rootAccount.callRaw(probe, 'verify_typed', { statement_json: statementJson, envelope_json: envelopeJson }, { gas: benchmarkGas });
      if (!valid.succeeded) {
        families[kind]!.operations.push(operation.name);
        families[kind]!.measurements[operation.name] = {
          status: 'failed', publicInputs: statementInputs.length, gasBurnt: gasStringOrUnknown(valid.gas_burnt),
          within300T: false, durationMs: valid.durationMs, error: errorString(valid),
        };
        await writeMeasurements();
      }
      assert.equal(valid.succeeded, true, `verify ${kind} execution failed`);
      const validResult = valid.parseResult<boolean>();
      if (!validResult) {
        families[kind]!.operations.push(operation.name);
        families[kind]!.measurements[operation.name] = {
          status: 'rejected', publicInputs: statementInputs.length, gasBurnt: gasStringOrUnknown(valid.gas_burnt),
          within300T: false, durationMs: valid.durationMs, error: 'valid proof was rejected',
        };
        await writeMeasurements();
      }
      assert.equal(validResult, true, `real ${kind} proof was rejected`);
      const gasBurnt = gasString(valid.gas_burnt);
      const within300T = BigInt(gasBurnt) <= 300_000_000_000_000n;
      families[kind]!.operations.push(operation.name);
      families[kind]!.measurements[operation.name] = { status: 'passed', publicInputs: statementInputs.length, gasBurnt, within300T, durationMs: valid.durationMs };
      await writeMeasurements();

      const statementValue = typeof operation.statement === 'string' ? JSON.parse(operation.statement) : operation.statement;
      const changed = await worker.rootAccount.callRaw(probe, 'verify_typed', {
        statement_json: jsonText(mutateStatement(statementValue)), envelope_json: envelopeJson,
      }, { gas: benchmarkGas });
      assert.equal(changed.succeeded, true, `changed ${kind} execution failed`);
      assert.equal(changed.parseResult<boolean>(), false, `changed ${kind} statement was accepted`);
    }
    await writeMeasurements();
  } finally {
    await worker.tearDown();
  }
});
