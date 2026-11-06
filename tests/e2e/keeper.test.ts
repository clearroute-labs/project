import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyPair } from 'near-workspaces';
import { actionCreators } from '@near-js/transactions';
import { LedgerWallet } from '../../packages/wallet/src/ledger.js';
import { KeeperSigner } from '../../services/keeper/src/signer.js';
import { Journal } from '../../services/keeper/src/journal.js';
import { KeeperEngine } from '../../services/keeper/src/engine.js';
import { SettlementPlanner, type KeeperNotice } from '../../services/keeper/src/planner.js';
import { NativeKeeperWallet } from '../../services/keeper/src/wallet.js';
import { deployProtocol, maximumGas } from './deployment.js';

test('a real restricted keeper merges, settles within limits, resumes its journal and honors revocation', { timeout: 900_000 }, async () => {
  const { worker, core, token, actors, rpc, crypto, keys, manifestHash } = await deployProtocol();
  const directory = await mkdtemp(join(tmpdir(), 'lending-keeper-chain-'));
  const ledger = new LedgerWallet(rpc, keys, crypto, manifestHash), signal = new AbortController().signal;
  const key = KeyPair.fromRandom('ed25519');
  try {
    const registration = await ledger.prepareHolderRegistration(actors.keeper.accountId, '1');
    await actors.keeper.call(core, registration.method, registration.args, { gas: maximumGas });
    await actors.keeper.call(core, 'register_authorization_key', { args: { key_id: '1', public_key: Array.from(key.getPublicKey().data) } }, { gas: maximumGas });
    const installed = await actors.keeper.batch(actors.keeper)
      .addKey(key.getPublicKey(), actionCreators.functionCallAccessKey(core.accountId, ['merge_broker_inbox', 'settle'], 10n ** 24n)).transact();
    assert.equal(installed.failed, false);
    const credentialFile = join(directory, 'key.json');
    await writeFile(credentialFile, JSON.stringify({ account_id: actors.keeper.accountId, public_key: key.getPublicKey().toString(), private_key: key.toString() }), { mode: 0o600 });
    const signer = await KeeperSigner.fromFile(rpc, core.accountId, credentialFile);
    const vault = await actors.broker.call<string>(core, 'create_vault', { args: {
      assets_maximum: '0', kind: 'OpenEnded', phase_times: null, share_scale: 6, shares_transferable: true,
      checkpoint_policy: { epoch_seconds: '60', disclosure_policy: 'aggregate_only' },
    } });
    const brokerRegistration = await ledger.prepareBrokerCreation(actors.broker.accountId, vault, '1', '100000000');
    const broker = await actors.broker.call<string>(core, brokerRegistration.method, brokerRegistration.args, { gas: maximumGas });
    await actors.lender.call(token, 'ft_transfer_call', { receiver_id: core.accountId, amount: '100000000', memo: null,
      msg: JSON.stringify({ version: 1, deposit_id: 'keeper-cash' }) }, { gas: maximumGas, attachedDeposit: 1n });
    const receipt = await core.view<{ claim_id: string }>('get_deposit_receipt', { token_account: token.accountId, sender: actors.lender.accountId, deposit_id: 'keeper-cash' });
    await actors.lender.call(core, 'deposit_to_vault', { args: { claim_id: receipt.claim_id, vault_id: vault, amount: '100000000', min_shares_out: '1', expiry: '18446744073709551615' } });
    const draw = await ledger.prepareDraw(broker, '100000000');
    await actors.broker.call(core, draw.method, draw.args, { gas: maximumGas });
    await actors.broker.call(core, 'grant_keeper', { args: {
      broker_id: broker, delegate_account: actors.keeper.accountId, delegate_key_id: '1', delegate_epoch: '2',
      allowed_settlement_per_operation: '40000000', allowed_settlement_per_window: '70000000', window_seconds: '3600',
      expires_at: '18446744073709551615', allowed_operations: ['MergeInbox', 'Settle'],
    } });
    const notices: KeeperNotice[] = [];
    const planner = new SettlementPlanner(new NativeKeeperWallet(ledger, signer.signerId), signer,
      [{ brokerId: broker, maximumSettlement: 50_000_000n, minimumSettlement: 1n }], notice => notices.push(notice));
    let time = 10_000;
    const journal = new Journal(join(directory, 'journal.json'));
    let engine = new KeeperEngine(journal, planner, 1_000, () => time);
    const confirm = async (): Promise<void> => {
      const pending = (await journal.read()).pending;
      assert.ok(pending);
      await rpc.waitForFinalOutcome(pending.hash, signer.signerId);
      // A fresh engine proves pending signed bytes are recovered after a process restart.
      engine = new KeeperEngine(new Journal(journal.path), planner, 1_000, () => time);
      assert.equal((await engine.tick()).state, 'confirmed');
      assert.equal((await journal.read()).pending, null);
      time += 1_000;
    };
    assert.equal((await engine.tick()).state, 'submitted');
    assert.equal((await journal.read()).pending?.action, 'merge');
    await confirm();
    assert.equal((await ledger.broker(broker)).spending, '100000000');
    assert.equal((await engine.tick()).state, 'submitted');
    await confirm();
    assert.equal((await ledger.broker(broker)).spending, '60000000');
    await worker.provider.fastForward(120);
    assert.equal((await engine.tick()).state, 'submitted');
    await confirm();
    assert.equal((await ledger.broker(broker)).spending, '30000000');
    await worker.provider.fastForward(120);
    assert.equal((await engine.tick()).state, 'idle');
    assert.equal(notices.at(-1)?.state, 'rate_limited');
    assert.equal((await core.view<{ assets_available: string }>('get_vault', { vault_id: vault })).assets_available, '70000000');

    // Prepare a valid merge, then revoke before broadcast. The ledger remains authoritative.
    const merge = await ledger.prepareMergeBroker(broker);
    const staleGrantTransaction = await signer.prepare('merge', broker, merge.args, signal);
    await actors.broker.call(core, 'revoke_keeper', { broker_id: broker, delegate_account: actors.keeper.accountId });
    await signer.broadcast(staleGrantTransaction, signal);
    await rpc.waitForFinalOutcome(staleGrantTransaction.hash, signer.signerId).catch(() => {});
    assert.equal(await signer.status(staleGrantTransaction, signal), 'failure');
    assert.equal(await planner.prepareNext(signal), null);
    assert.equal(notices.at(-1)?.state, 'unauthorized');
    assert.equal((await ledger.broker(broker)).spending, '30000000');
  } finally { keys.clear(); await worker.tearDown(); await rm(directory, { recursive: true, force: true }); }
});
