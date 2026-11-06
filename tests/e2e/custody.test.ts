import test from 'node:test';
import assert from 'node:assert/strict';
import { deployProtocol, maximumGas, near } from './deployment.js';

interface Claim { claim_id: string; owner: string; amount: string; reserved_by: string | null }
interface Payout { status: string; result_tag: number; result_hash: number[] }

test('actual token callbacks preserve custody through duplicate ingress, failed payout and oversized success', { timeout: 300_000 }, async () => {
  const { worker, core, token, actors } = await deployProtocol();
  try {
    const balance = (accountId: string) => token.view<string>('ft_balance_of', { account_id: accountId });
    const initial = BigInt(await balance(actors.lender.accountId));
    const deposit = () => actors.lender.call(token, 'ft_transfer_call', {
      receiver_id: core.accountId, amount: '1000', memo: null,
      msg: JSON.stringify({ version: 1, deposit_id: 'custody-deposit-1' }),
    }, { attachedDeposit: 1n, gas: maximumGas });
    await deposit();
    const receipt = await core.view<{ claim_id: string; amount: string }>('get_deposit_receipt', {
      token_account: token.accountId, sender: actors.lender.accountId, deposit_id: 'custody-deposit-1',
    });
    assert.equal(typeof receipt.claim_id, 'string');
    assert.equal(receipt.amount, '1000');
    const claim = () => core.view<Claim | null>('get_claim', { claim_id: receipt.claim_id });
    assert.equal((await claim())?.amount, '1000');
    assert.equal(BigInt(await balance(actors.lender.accountId)), initial - 1000n);
    await deposit();
    assert.equal(BigInt(await balance(actors.lender.accountId)), initial - 1000n);
    assert.equal(await balance(core.accountId), '1000');
    assert.equal(await core.view('get_custody_total'), '1000');
    const forgedDeposit = await actors.lender.callRaw(core, 'ft_on_transfer', { sender_id: actors.lender.accountId, amount: '1000', msg: JSON.stringify({ version: 1, deposit_id: 'forged' }) }, { gas: maximumGas });
    assert.equal(forgedDeposit.succeeded, false);
    const forgedCallback = await actors.lender.callRaw(core, 'on_payout_result', { operation_id: '1', attempt: 1, result_hash: [] }, { gas: maximumGas });
    assert.equal(forgedCallback.succeeded, false);
    const finalizer = await worker.rootAccount.createSubAccount('finalizer', { initialBalance: near });
    await worker.rootAccount.call(token, 'set_transfer_mode', { mode: 1 });
    await actors.lender.call(core, 'request_payout', { args: { claim_id: receipt.claim_id, recipient: actors.recipient.accountId, operation_id: '9007199254740993' } }, { gas: maximumGas });
    let operation = await core.view<Payout>('get_payout', { operation_id: '9007199254740993' });
    assert.equal(operation.status, 'ResultRecordedFailure');
    assert.equal((await claim())?.reserved_by, '9007199254740993');
    await finalizer.call(core, 'finalize_payout', { operation_id: '9007199254740993' }, { gas: maximumGas });
    assert.equal((await claim())?.reserved_by, null);
    assert.equal(await balance(core.accountId), '1000');
    await finalizer.call(core, 'finalize_payout', { operation_id: '9007199254740993' });
    await worker.rootAccount.call(token, 'set_transfer_mode', { mode: 2 });
    await actors.lender.call(core, 'request_payout', { args: { claim_id: receipt.claim_id, recipient: actors.recipient.accountId, operation_id: '9007199254740994' } }, { gas: maximumGas });
    operation = await core.view<Payout>('get_payout', { operation_id: '9007199254740994' });
    assert.equal(operation.status, 'ResultRecordedSuccess');
    assert.equal(operation.result_hash.length, 32);
    assert.equal(await balance(actors.recipient.accountId), '1000');
    await finalizer.call(core, 'finalize_payout', { operation_id: '9007199254740994' }, { gas: maximumGas });
    await finalizer.call(core, 'finalize_payout', { operation_id: '9007199254740994' }, { gas: maximumGas });
    assert.equal(await claim(), null);
    assert.equal(await balance(core.accountId), '0');
    assert.equal(await core.view('get_custody_total'), '0');
    assert.equal((await core.view<Payout>('get_payout', { operation_id: '9007199254740994' })).status, 'Succeeded');
  } finally { await worker.tearDown(); }
});
