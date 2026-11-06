import test from 'node:test';
import assert from 'node:assert/strict';
import type { LedgerWallet } from '@confidential-lending/wallet';
import { NativeKeeperWallet } from '../src/wallet.js';

test('keeper reads broker grant epochs separately from encryption keys and rejects revoked delegate keys', async () => {
  const block = { hash: 'finalized-block', height: 50 };
  let revoked = false;
  const requested: string[] = [];
  const ledger = {
    snapshot: async () => ({ block }),
    broker: async () => ({ spending: '200', inbox: '0', record: { broker_id: '1', owner: 'broker.near', vault_id: '1', authorization_epoch: '4', last_settlement_at: '10' } }),
    view: async (selected: unknown, method: string) => {
      assert.equal(selected, block); requested.push(method);
      if (method === 'get_keeper_grants') return [{ delegate_account: 'keeper.near', delegate_key_id: '7', delegate_epoch: '2', active: true, revocation_epoch: '4' }];
      if (method === 'get_vault') return { checkpoint_policy: { epoch_seconds: '60' } };
      if (method === 'get_freeze_status') return { asset_frozen: false, holder_frozen: false };
      if (method === 'get_authorization_key') return { owner: 'keeper.near', epoch: '2', revoked };
      throw new Error('Unexpected view');
    },
    rpc: { request: async () => ({ header: { hash: block.hash, height: block.height, timestamp_nanosec: '100000000000' } }) },
  } as unknown as LedgerWallet;
  const wallet = new NativeKeeperWallet(ledger, 'keeper.near');
  let snapshot = await wallet.snapshot('1', new AbortController().signal);
  assert.equal(snapshot.authorizationEpoch, '4');
  assert.equal(snapshot.grants[0]?.active, true);
  assert.equal(snapshot.settlementDue, true);
  assert.equal(requested.includes('get_broker_key'), false, 'Encryption key registration epoch does not authorize keeper grants');
  revoked = true;
  snapshot = await wallet.snapshot('1', new AbortController().signal);
  assert.equal(snapshot.grants[0]?.active, false);
});
