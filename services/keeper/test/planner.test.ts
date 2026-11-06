import test from 'node:test';
import assert from 'node:assert/strict';
import { SettlementPlanner, type KeeperSnapshot, type KeeperWallet, type TransactionSigner } from '../src/planner.js';

function fixture() {
  const snapshot: KeeperSnapshot = { brokerId: '7', owner: 'broker.near', timestampSeconds: 100n, frozen: false, spending: 500n, inbox: 0n, authorizationEpoch: '1', settlementDue: true,
    grants: [{ delegate_account: 'keeper.near', delegate_key_id: '1', delegate_epoch: '2', active: true, expires_at: '200', allowed_settlement_per_operation: '100', allowed_settlement_per_window: '250', window_seconds: '60', window_started_at: '80', window_spent: '210', revocation_epoch: '1', allowed_operations: ['MergeInbox', 'Settle'] }] };
  const planned: { action: string; amount?: bigint }[] = [];
  const wallet: KeeperWallet = {
    snapshot: async () => snapshot,
    merge: async () => { planned.push({ action: 'merge' }); return {}; },
    settle: async (_id, amount) => { planned.push({ action: 'settle', amount }); return {}; },
  };
  const signer: TransactionSigner = {
    signerId: 'keeper.near',
    prepare: async (action, brokerId) => ({ hash: 'hash', signerId: 'keeper.near', action, brokerId, signedTransactionBase64: 'bytes', preparedAt: 0 }),
    broadcast: async () => {}, status: async () => 'unknown',
  };
  return { snapshot, planned, wallet, signer, planner: new SettlementPlanner(wallet, signer, [{ brokerId: '7', maximumSettlement: 90n, minimumSettlement: 10n }]) };
}

test('settlement respects remaining on-chain window, operation and local limits', async () => {
  const f = fixture();
  await f.planner.prepareNext(new AbortController().signal);
  assert.deepEqual(f.planned, [{ action: 'settle', amount: 40n }]);
  f.snapshot.timestampSeconds = 140n;
  await f.planner.prepareNext(new AbortController().signal);
  assert.deepEqual(f.planned[1], { action: 'settle', amount: 90n });
});

test('merge precedes settlement, and frozen, expired or insufficient windows do no work', async () => {
  const f = fixture();
  f.snapshot.inbox = 1n;
  assert.equal((await f.planner.prepareNext(new AbortController().signal))?.action, 'merge');
  f.snapshot.frozen = true;
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
  f.snapshot.frozen = false; f.snapshot.timestampSeconds = 201n;
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
  f.snapshot.timestampSeconds = 100n; f.snapshot.inbox = 0n; f.snapshot.grants[0]!.window_spent = '249';
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
});

test('owner authority, numeric JSON grants and substituted broker snapshots fail closed', async () => {
  const f = fixture();
  f.snapshot.owner = 'keeper.near';
  await assert.rejects(f.planner.prepareNext(new AbortController().signal), /dedicated delegate/);
  f.snapshot.owner = 'broker.near'; f.snapshot.grants[0]!.window_spent = 210 as unknown as string;
  await assert.rejects(f.planner.prepareNext(new AbortController().signal), /Invalid finalized/);
  f.snapshot.brokerId = '8';
  await assert.rejects(f.planner.prepareNext(new AbortController().signal), /identity/);
});

test('cadence and operation-specific grant scope survive local policy changes', async () => {
  const f = fixture();
  f.snapshot.settlementDue = false;
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
  f.snapshot.inbox = 5n;
  assert.equal((await f.planner.prepareNext(new AbortController().signal))?.action, 'merge');
  f.snapshot.grants[0]!.allowed_operations = ['Settle'];
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
  f.snapshot.settlementDue = true;
  assert.equal((await f.planner.prepareNext(new AbortController().signal))?.action, 'settle');
  f.snapshot.grants[0]!.revocation_epoch = '0';
  assert.equal(await f.planner.prepareNext(new AbortController().signal), null);
});
