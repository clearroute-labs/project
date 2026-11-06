import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Journal, type PreparedTransaction } from '../src/journal.js';
import { KeeperEngine, type KeeperDriver } from '../src/engine.js';

const transaction: PreparedTransaction = { hash: 'A'.repeat(44), signerId: 'keeper.test.near', signedTransactionBase64: 'AA==', brokerId: '1', action: 'settle', preparedAt: 0 };

async function fixture(run: (journal: Journal) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'lending-keeper-'));
  try { await run(new Journal(join(directory, 'journal.json'))); }
  finally { await rm(directory, { force: true, recursive: true }); }
}

test('lost RPC response and restart cannot create a second transaction', async () => fixture(async journal => {
  let prepared = 0;
  let broadcasts = 0;
  let outcome: 'unknown' | 'success' | 'failure' = 'unknown';
  const driver: KeeperDriver = {
    prepareNext: async () => { prepared++; return transaction; },
    broadcast: async value => {
      broadcasts++;
      assert.deepEqual((await journal.read()).pending, value, 'signed bytes must be durable before transmission');
      throw new Error('connection lost after accepting transaction');
    },
    status: async () => outcome,
  };
  const engine = new KeeperEngine(journal, driver, 1_000, () => 10_000);
  assert.equal((await engine.tick()).state, 'pending');
  const restarted = new KeeperEngine(new Journal(journal.path), driver, 1_000, () => 10_000);
  for (let i = 0; i < 3; i++) assert.equal((await restarted.tick()).state, 'pending');
  assert.equal(prepared, 1);
  assert.equal(broadcasts, 1);
  outcome = 'success';
  assert.equal((await restarted.tick()).state, 'confirmed');
  assert.equal((await restarted.tick()).state, 'idle');
  assert.equal((await journal.read()).pending, null);
  assert.equal((await stat(journal.path)).mode & 0o077, 0);
}));

test('explicit rebroadcast uses the identical signed transaction', async () => fixture(async journal => {
  const sent: PreparedTransaction[] = [];
  const driver: KeeperDriver = { prepareNext: async () => transaction, broadcast: async value => { sent.push(value); }, status: async () => 'unknown' };
  const engine = new KeeperEngine(journal, driver, 1_000, () => 10_000);
  assert.equal((await engine.tick()).state, 'submitted');
  assert.equal((await engine.rebroadcastPending()).state, 'pending');
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[0], sent[1]);
}));

test('concurrent keepers cannot both prepare a transaction', async () => fixture(async journal => {
  let release!: () => void;
  let entered!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const engine = new KeeperEngine(journal, {
    prepareNext: async () => { entered(); await blocked; return transaction; },
    broadcast: async () => {}, status: async () => 'unknown',
  }, 1_000, () => 10_000);
  const first = engine.tick();
  await ready;
  try { await assert.rejects(engine.tick(), /already being held/); }
  finally { release(); }
  assert.equal((await first).state, 'submitted');
}));

test('known chain failure is recorded before a later plan can run', async () => fixture(async journal => {
  let now = 10_000;
  let preparations = 0;
  const engine = new KeeperEngine(journal, {
    prepareNext: async () => { preparations++; return transaction; },
    broadcast: async () => {}, status: async () => 'failure',
  }, 1_000, () => now);
  await engine.tick();
  assert.equal((await engine.tick()).state, 'failed');
  assert.deepEqual((await journal.read()).lastResult, { hash: transaction.hash, outcome: 'failure' });
  assert.equal((await engine.tick()).state, 'idle');
  now += 1_000;
  assert.equal((await engine.tick()).state, 'submitted');
  assert.equal(preparations, 2);
}));
