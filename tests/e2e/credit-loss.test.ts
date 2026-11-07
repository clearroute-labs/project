import test from 'node:test';
import assert from 'node:assert/strict';
import type { NearAccount } from 'near-workspaces';
import { LedgerWallet, type LedgerVault, type PreparedCall } from '../../packages/wallet/src/ledger.js';
import { deployProtocol, maximumGas } from './deployment.js';
import { fastForwardFinalized } from '../sandbox.js';

test('multiple brokers reconcile impairment and default without charging the same principal twice', { timeout: 2_400_000 }, async () => {
  const { worker, core, token, actors, rpc, crypto, keys, manifestHash } = await deployProtocol();
  const wallet = new LedgerWallet(rpc, keys, crypto, manifestHash);
  const call = async <T>(actor: NearAccount, method: string, args: Record<string, unknown>): Promise<T> => {
    const outcome = await actor.callRaw(core, method, args, { gas: maximumGas });
    assert.equal(outcome.failed, false, `${method}: ${JSON.stringify(outcome.status)}`);
    await rpc.waitForFinalOutcome(outcome.transactionReceipt.hash, actor.accountId);
    return outcome.parseResult<T>();
  };
  const submit = <T>(actor: NearAccount, prepared: PreparedCall): Promise<T> => call(actor, prepared.method, prepared.args);
  const reject = async (actor: NearAccount, prepared: PreparedCall, category: RegExp): Promise<void> => {
    const outcome = await actor.callRaw(core, prepared.method, prepared.args, { gas: maximumGas });
    assert.equal(outcome.failed, true);
    assert.match(JSON.stringify(outcome.status), category);
  };
  const deposit = async (actor: NearAccount, amount: string, id: string): Promise<string> => {
    const outcome = await actor.callRaw(token, 'ft_transfer_call', {
      receiver_id: core.accountId, amount, memo: null, msg: JSON.stringify({ version: 1, deposit_id: id }),
    }, { gas: maximumGas, attachedDeposit: 1n });
    assert.equal(outcome.failed, false);
    await rpc.waitForFinalOutcome(outcome.transactionReceipt.hash, actor.accountId);
    return (await core.view<{ claim_id: string }>('get_deposit_receipt', {
      token_account: token.accountId, sender: actor.accountId, deposit_id: id,
    })).claim_id;
  };
  try {
    await submit(actors.borrower, await wallet.prepareHolderRegistration(actors.borrower.accountId, '1'));
    await submit(actors.recipient, await wallet.prepareHolderRegistration(actors.recipient.accountId, '1'));
    const auditor = await keys.generate({ role: 'loan_auditor', subjectId: actors.auditor.accountId, keyId: '1' });
    const vaultId = await call<string>(actors.broker, 'create_vault', { args: {
      assets_maximum: '0', kind: 'OpenEnded', phase_times: null, share_scale: 6, shares_transferable: true,
      checkpoint_policy: { epoch_seconds: '60', disclosure_policy: 'aggregate_only' },
    } });
    const firstBroker = await submit<string>(actors.broker, await wallet.prepareBrokerCreation(actors.broker.accountId, vaultId, '1', '300000000'));
    const secondBroker = await submit<string>(actors.broker, await wallet.prepareBrokerCreation(actors.broker.accountId, vaultId, '1', '300000000'));
    const claim = await deposit(actors.lender, '300000000', 'credit-lender');
    await call(actors.lender, 'deposit_to_vault', { args: { claim_id: claim, vault_id: vaultId, amount: '300000000', min_shares_out: '1', expiry: '18446744073709551615' } });
    for (const [broker, amount] of [[firstBroker, '200000000'], [secondBroker, '100000000']] as const) {
      await submit(actors.broker, await wallet.prepareDraw(broker, amount));
      await submit(actors.broker, await wallet.prepareMergeBroker(broker));
    }
    const interestClaim = await deposit(actors.borrower, '60000000', 'credit-interest');
    await submit(actors.borrower, await wallet.prepareShield(actors.borrower.accountId, interestClaim));
    await submit(actors.borrower, await wallet.prepareMergeHolder(actors.borrower.accountId));
    const originate = async (broker: string, borrower: NearAccount, owed: string): Promise<string> => {
      const draft = await wallet.agreement(broker, borrower.accountId, auditor, {
        principal: '100000000', initialOwed: owed, periodicPayment: owed, paymentCount: 1,
      });
      const proposal = await submit<string>(actors.broker, await wallet.prepareProposal(broker, borrower.accountId, '1', draft,
        { interval: '3600', grace: '0', expiry: '18446744073709551615' }));
      await call(borrower, 'sign_proposal', { proposal_id: proposal, signature: [] });
      return submit<string>(actors.broker, await wallet.prepareOrigination(proposal, draft));
    };
    // Interleaving brokers exercises global loan IDs and each broker's independent sparse book.
    const profitableLoan = await originate(firstBroker, actors.borrower, '150000000');
    const recoverableLoan = await originate(secondBroker, actors.borrower, '110000000');
    const defaultingLoan = await originate(firstBroker, actors.recipient, '100000000');
    assert.equal(BigInt(defaultingLoan), BigInt(profitableLoan) + 2n);
    await submit(actors.borrower, await wallet.prepareMergeHolder(actors.borrower.accountId));
    await submit(actors.borrower, await wallet.prepareRepayment(actors.borrower.accountId, profitableLoan, 'Full'));
    await submit(actors.broker, await wallet.prepareMergeBroker(firstBroker));
    const beforeDefault = await wallet.prepareManagement(defaultingLoan, 'Default');
    const premature = await actors.broker.callRaw(core, beforeDefault.method, beforeDefault.args, { gas: maximumGas });
    assert.equal(premature.failed, true, 'An unpaid loan cannot default before its grace deadline');
    assert.ok((await fastForwardFinalized(worker, 4_000)).elapsedSeconds >= 3_600n);
    await submit(actors.broker, await wallet.prepareManagement(defaultingLoan, 'Impair'));
    await submit(actors.broker, await wallet.prepareManagement(recoverableLoan, 'Impair'));
    const lenderShares = await core.view<string>('get_share_balance', { vault_id: vaultId, owner: actors.lender.accountId });
    const whilePending = await actors.lender.callRaw(core, 'redeem_shares', { args: {
      vault_id: vaultId, shares: (BigInt(lenderShares) / 10n).toString(), min_assets_out: '0', expiry: '18446744073709551615',
      sole_shareholder_waiver: false, burn_worthless: false, broker_zero_proofs: [],
    } }, { gas: maximumGas });
    assert.equal(whilePending.failed, true, 'Pending risk accounting must block NAV-sensitive redemption');
    const reconcile = async (broker: string): Promise<void> => {
      const checkpoint = await call<string>(actors.broker, 'prepare_reconciliation', { broker_id: broker });
      assert.ok((await fastForwardFinalized(worker, 120)).elapsedSeconds >= 60n);
      await submit(actors.broker, await wallet.prepareReconciliation(broker, checkpoint));
    };
    await reconcile(firstBroker);
    let vault = await core.view<LedgerVault & { pending_broker_count: string }>('get_vault', { vault_id: vaultId });
    assert.equal(vault.pending_broker_count, '1', 'Reconciling one broker cannot clear another broker risk event');
    await reconcile(secondBroker);
    vault = await core.view('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_total, '300000000'); assert.equal(vault.loss_unrealized, '150000000');
    assert.equal(vault.pending_broker_count, '0');
    assert.equal((await wallet.broker(firstBroker)).record.impairment_provision, '50000000', 'Realized yield cushions aggregate impairment');
    assert.equal((await wallet.broker(secondBroker)).record.impairment_provision, '100000000');

    // A positive provision requires an atomic post-settlement reconciliation.
    // The wallet derives an inline checkpoint; no separate prepare transaction is needed.
    const priorCheckpoint = await call<string>(actors.broker, 'prepare_reconciliation', { broker_id: firstBroker });
    assert.ok((await fastForwardFinalized(worker, 120)).elapsedSeconds >= 60n);
    const staleCheckpoint = await wallet.prepareReconciliation(firstBroker, priorCheckpoint);
    const impairedSettlement = await wallet.prepareSettlement(firstBroker, '50000000');
    assert.equal((impairedSettlement.args.args as { reconciliation: { checkpoint_id: string } }).reconciliation.checkpoint_id, '0');
    await submit(actors.broker, impairedSettlement);
    await reject(actors.broker, staleCheckpoint, /STALE_STATE/);
    vault = await core.view('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_available, '50000000');
    assert.equal(vault.assets_total, '300000000');
    assert.equal(vault.loss_unrealized, '150000000');
    assert.equal((await wallet.broker(firstBroker)).record.debt_total, '150000000');

    await submit(actors.recipient, await wallet.prepareMergeHolder(actors.recipient.accountId));
    const repaymentBeforeDefault = await wallet.prepareRepayment(actors.recipient.accountId, defaultingLoan, 'Full');
    await submit(actors.broker, await wallet.prepareManagement(defaultingLoan, 'Default'));
    await reject(actors.recipient, repaymentBeforeDefault, /LOAN_CLOSED/);
    await reconcile(firstBroker);
    vault = await core.view('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_total, '250000000'); assert.equal(vault.loss_unrealized, '100000000');
    assert.equal((await wallet.broker(firstBroker)).record.debt_total, '100000000');
    await assert.rejects(wallet.prepareRepayment(actors.recipient.accountId, defaultingLoan, 'Full'), /not payable/);
    await submit(actors.broker, await wallet.prepareManagement(recoverableLoan, 'Unimpair'));
    await reconcile(secondBroker);
    vault = await core.view('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_total, '250000000'); assert.equal(vault.loss_unrealized, '0');
    assert.equal((await wallet.broker(secondBroker)).record.debt_total, '100000000', 'Unimpairment cannot forgive principal');
    await submit(actors.broker, await wallet.prepareSettlement(firstBroker, '100000000'));
    await submit(actors.borrower, await wallet.prepareRepayment(actors.borrower.accountId, recoverableLoan, 'Full'));
    await submit(actors.broker, await wallet.prepareMergeBroker(secondBroker));
    await submit(actors.broker, await wallet.prepareSettlement(secondBroker, '110000000'));
    vault = await core.view('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_total, '260000000'); assert.equal(vault.assets_available, '260000000');
    assert.equal(vault.loss_unrealized, '0');
    assert.equal(await core.view('get_custody_total'), '360000000');
    for (const id of [profitableLoan, defaultingLoan, recoverableLoan]) await call(actors.broker, 'delete_loan', { loan_id: id, evidence: [] });
    for (const id of [firstBroker, secondBroker]) await submit(actors.broker, await wallet.prepareBrokerClosure(id));
    const redemption = await call<string>(actors.lender, 'redeem_shares', { args: {
      vault_id: vaultId, shares: lenderShares, min_assets_out: '260000000', expiry: '18446744073709551615',
      sole_shareholder_waiver: false, burn_worthless: false, broker_zero_proofs: [],
    } });
    await call(actors.lender, 'request_payout', { args: { claim_id: redemption, recipient: actors.lender.accountId, operation_id: '9007199254741001' } });
    await call(actors.recipient, 'finalize_payout', { operation_id: '9007199254741001' });
    assert.equal(await token.view('ft_balance_of', { account_id: actors.lender.accountId }), '960000000');
    assert.equal(await core.view('get_custody_total'), '100000000');
    assert.equal((await wallet.holder(actors.recipient.accountId)).spending, '100000000');
  } finally { keys.clear(); await worker.tearDown(); }
});
