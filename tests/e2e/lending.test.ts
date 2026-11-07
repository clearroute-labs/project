import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import type { NearAccount } from 'near-workspaces';
import { decodeWire, LedgerWallet, type LedgerVault, type PreparedCall } from '../../packages/wallet/src/ledger.js';
import { Keyring } from '../../packages/wallet/src/keyring.js';
import { deployProtocol, maximumGas } from './deployment.js';

function assertPrivatePayload(value: unknown, forbiddenAmounts: ReadonlySet<string>): void {
  if (typeof value === 'string' || typeof value === 'number') assert.equal(forbiddenAmounts.has(String(value)), false, 'Private amount appeared as a public field');
  else if (Array.isArray(value)) for (const child of value) assertPrivatePayload(child, forbiddenAmounts);
  else if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    assert.equal(/secret|randomness|private_balance|witness/i.test(key), false, 'Private witness field appeared in transaction');
    assertPrivatePayload(child, forbiddenAmounts);
  }
}

test('real confidential lending funds, spends, repays, settles yield and redeems through token receipts', { timeout: 1_800_000 }, async () => {
  const deployment = await deployProtocol();
  const { worker, core, token, actors, rpc, crypto, keys } = deployment;
  const wallet = new LedgerWallet(rpc, keys, crypto, deployment.manifestHash);
  const auditMirror = async (kind: 'holder' | 'broker', subject: string, role: 'issuer' | 'token_auditor'): Promise<string> => {
    const material = keys.exportMaterial();
    const readerKeys = new Keyring(keys.identity, crypto);
    try {
      await readerKeys.importMaterial({ ...material, keys: material.keys.filter(key => key.role === role) });
      const reader = new LedgerWallet(rpc, readerKeys, crypto, deployment.manifestHash);
      const recovered = kind === 'holder'
        ? await reader.auditBalance('holder', subject, role)
        : await reader.auditBalance('broker', subject, role);
      return recovered.mirror;
    } finally { readerKeys.clear(); }
  };
  const measurements: Array<{ method: string; gas: string; argumentBytes: number; milliseconds: number; storageBytesBefore: number; storageBytesAfter: number; succeeded: boolean }> = [];
  const storageBytes = async (): Promise<number> => {
    const account = await rpc.request<{ storage_usage: number }>('query', { request_type: 'view_account', finality: 'final', account_id: core.accountId });
    assert.ok(Number.isSafeInteger(account.storage_usage) && account.storage_usage >= 0);
    return account.storage_usage;
  };
  const privateAmounts = new Set(['600000000', '660000000', '220000000', '440000000', '40000000', '1000000']);
  const confidentialMethods = new Set(['create_proposal', 'sign_proposal', 'originate', 'confidential_send', 'repay', 'manage_loan', 'delete_loan']);
  const assertNoKeys = (value: unknown): void => {
    const serialized = JSON.stringify(value);
    for (const entry of keys.exportMaterial().keys) {
      assert.equal(serialized.includes(entry.secretKey), false, 'Secret key appeared in public data');
      assert.equal(serialized.includes(JSON.stringify(Array.from(Buffer.from(entry.secretKey, 'hex')))), false, 'Raw secret key bytes appeared in public data');
    }
  };
  await mkdir('.artifacts', { recursive: true });
  const call = async <T>(actor: NearAccount, method: string, input: Record<string, unknown>): Promise<T> => {
    const storageBytesBefore = await storageBytes();
    const before = Date.now();
    assertNoKeys(input);
    if (confidentialMethods.has(method)) assertPrivatePayload(input, privateAmounts);
    const outcome = await actor.callRaw(core, method, input, { gas: maximumGas });
    assertNoKeys(outcome.logs);
    for (const log of outcome.logs) {
      if (confidentialMethods.has(method) && log.startsWith('EVENT_JSON:')) assertPrivatePayload(JSON.parse(log.slice('EVENT_JSON:'.length)), privateAmounts);
    }
    await rpc.waitForFinalOutcome(outcome.transactionReceipt.hash, actor.accountId);
    measurements.push({ method, gas: outcome.gas_burnt, argumentBytes: Buffer.byteLength(JSON.stringify(input)), milliseconds: Date.now() - before, storageBytesBefore, storageBytesAfter: await storageBytes(), succeeded: !outcome.failed });
    await writeFile('.artifacts/lifecycle-benchmark.json', JSON.stringify({ complete: false, core: core.accountId, manifestHash: deployment.manifestHash, coreWasmHash: deployment.coreWasmHash, measurements }, null, 2));
    assert.equal(outcome.failed, false, `${method}: ${JSON.stringify(outcome.status)}`);
    return outcome.parseResult<T>();
  };
  const submit = <T>(actor: NearAccount, prepared: PreparedCall): Promise<T> => call(actor, prepared.method, prepared.args);
  const reject = async (actor: NearAccount, prepared: PreparedCall, reason: RegExp): Promise<void> => {
    const outcome = await actor.callRaw(core, prepared.method, prepared.args, { gas: maximumGas });
    assert.equal(outcome.failed, true, `${prepared.method} unexpectedly succeeded`);
    assert.match(JSON.stringify(outcome.status), reason, 'Rejection must be the expected contract error, not a runtime or gas failure');
  };
  const deposit = async (actor: NearAccount, amount: string, id: string): Promise<string> => {
    const outcome = await actor.callRaw(token, 'ft_transfer_call', { receiver_id: core.accountId, amount, memo: null, msg: JSON.stringify({ version: 1, deposit_id: id }) }, { gas: maximumGas, attachedDeposit: 1n });
    assert.equal(outcome.failed, false);
    await rpc.waitForFinalOutcome(outcome.transactionReceipt.hash, actor.accountId);
    return (await core.view<{ claim_id: string }>('get_deposit_receipt', { token_account: token.accountId, sender: actor.accountId, deposit_id: id })).claim_id;
  };
  try {
    console.log('Lifecycle: registering confidential readers');
    await submit(actors.borrower, await wallet.prepareHolderRegistration(actors.borrower.accountId, '1'));
    await submit(actors.recipient, await wallet.prepareHolderRegistration(actors.recipient.accountId, '1'));
    const auditor = { role: 'loan_auditor' as const, subjectId: actors.auditor.accountId, keyId: '1' };
    const auditorPublicKey = await keys.generate(auditor);
    const vaultId = await call<string>(actors.broker, 'create_vault', { args: { assets_maximum: '0', kind: 'OpenEnded', phase_times: null, share_scale: 6, shares_transferable: true,
      checkpoint_policy: { epoch_seconds: '60', disclosure_policy: 'aggregate_only' } } });
    const brokerCreation = await wallet.prepareBrokerCreation(actors.broker.accountId, vaultId, '1', '1000000000');
    const brokerId = await submit<string>(actors.broker, brokerCreation);
    assert.equal(brokerId, brokerCreation.brokerId);
    const lenderClaim = await deposit(actors.lender, '1000000000', 'lifecycle-lender');
    await call(actors.lender, 'deposit_to_vault', { args: { claim_id: lenderClaim, vault_id: vaultId, amount: '1000000000', min_shares_out: '1', expiry: '18446744073709551615' } });
    await submit(actors.broker, await wallet.prepareDraw(brokerId, '800000000'));
    const brokerMerge = await wallet.prepareMergeBroker(brokerId);
    await reject(actors.recipient, brokerMerge, /UNAUTHORIZED/);
    await submit(actors.broker, brokerMerge);
    const borrowerClaim = await deposit(actors.borrower, '100000000', 'lifecycle-borrower');
    const shieldBeforeIncomingLoan = await wallet.prepareShield(actors.borrower.accountId, borrowerClaim);

    console.log('Lifecycle: joint loan consent and confidential origination');
    const draft = await wallet.agreement(brokerId, actors.borrower.accountId, auditorPublicKey,
      { principal: '600000000', initialOwed: '660000000', periodicPayment: '220000000', paymentCount: 3 });
    const proposal = await wallet.prepareProposal(brokerId, actors.borrower.accountId, '1', draft, { interval: '86400', grace: '3600', expiry: '18446744073709551615' });
    assertPrivatePayload(proposal.args, new Set(['600000000', '660000000', '220000000']));
    const proposalId = await submit<string>(actors.broker, proposal);
    const preparedLoan = await wallet.prepareOrigination(proposalId, draft);
    assertPrivatePayload(preparedLoan.args, new Set(['600000000', '660000000', '220000000']));
    const unsigned = await actors.broker.callRaw(core, 'originate', preparedLoan.args, { gas: maximumGas });
    assert.equal(unsigned.failed, true, 'A broker cannot fund a loan without borrower consent');
    await reject(actors.recipient, preparedLoan, /UNAUTHORIZED/);
    const expired = structuredClone(proposal);
    (expired.args.args as Record<string, unknown>).expiry = '1';
    await reject(actors.broker, expired, /EXPIRED/);
    const mismatchedSignature = structuredClone(proposal);
    (mismatchedSignature.args.args as Record<string, unknown>).borrower_signature = Array(64).fill(7);
    await reject(actors.broker, mismatchedSignature, /UNAUTHORIZED/);
    const revokedId = await submit<string>(actors.broker, proposal);
    await call(actors.borrower, 'revoke_proposal', { proposal_id: revokedId });
    const revoked = structuredClone(preparedLoan);
    (revoked.args.args as Record<string, unknown>).proposal_id = revokedId;
    await reject(actors.broker, revoked, /REPLAY/);
    const borrowerKey = { role: 'holder' as const, subjectId: actors.borrower.accountId, keyId: '1' };
    assert.equal(await wallet.recovery.amount({ recovery: draft.principal.recovery[1]! }, borrowerKey), 600000000n);
    assert.equal(await wallet.recovery.amount({ recovery: draft.owed.recovery[0]! }, borrowerKey), 660000000n);
    assert.equal(await wallet.recovery.amount({ recovery: draft.payment.recovery[0]! }, borrowerKey), 220000000n);
    await call(actors.borrower, 'sign_proposal', { proposal_id: proposalId, signature: [] });
    const loanId = await submit<string>(actors.broker, preparedLoan);
    await reject(actors.broker, preparedLoan, /REPLAY/);
    const borrowerLoan = await wallet.loan(loanId, borrowerKey);
    const auditedLoan = await wallet.loan(loanId, auditor);
    assert.equal(borrowerLoan.amounts.owed, '660000000');
    assert.deepEqual(auditedLoan.amounts, borrowerLoan.amounts);
    assertPrivatePayload(borrowerLoan.record, privateAmounts);
    assertNoKeys(borrowerLoan.record);
    // Origination credited the inbox after this proof was prepared. Public
    // shielding adds its proved delta to the current inbox without replacing it.
    await submit(actors.borrower, shieldBeforeIncomingLoan);
    assert.equal((await wallet.holder(actors.borrower.accountId)).inbox, '700000000');
    await submit(actors.borrower, await wallet.prepareMergeHolder(actors.borrower.accountId));

    console.log('Lifecycle: private spending and repayment with a concurrent inbox credit');
    const staleTransfer = await wallet.prepareTransfer(actors.borrower.accountId, actors.recipient.accountId, '40000000');
    const merge = await wallet.prepareMergeHolder(actors.borrower.accountId);
    await submit(actors.borrower, merge);
    await reject(actors.borrower, merge, /STALE_STATE/);
    await reject(actors.borrower, staleTransfer, /STALE_STATE/);
    const transfer = await wallet.prepareTransfer(actors.borrower.accountId, actors.recipient.accountId, '40000000');
    await call(actors.issuer, 'set_holder_frozen', { account_id: actors.borrower.accountId, frozen: true });
    await reject(actors.borrower, transfer, /ACCOUNT_FROZEN/);
    await call(actors.issuer, 'set_holder_frozen', { account_id: actors.borrower.accountId, frozen: false });
    await submit(actors.borrower, transfer);
    await reject(actors.borrower, transfer, /STALE_STATE/);
    await submit(actors.recipient, await wallet.prepareMergeHolder(actors.recipient.accountId));
    for (const invalidAmount of ['0', '219999999', '660000000', '660000001']) {
      await assert.rejects(wallet.prepareRepayment(actors.borrower.accountId, loanId, 'Regular', invalidAmount), /Invalid loan repayment/);
    }
    const installment = await wallet.prepareRepayment(actors.borrower.accountId, loanId, 'Regular', '220000000');
    assertPrivatePayload(installment.args, new Set(['600000000', '660000000', '220000000']));
    await submit(actors.recipient, await wallet.prepareTransfer(actors.recipient.accountId, actors.borrower.accountId, '1000000'));
    await submit(actors.borrower, installment);
    await reject(actors.borrower, installment, /STALE_STATE/);
    assert.equal((await wallet.loan(loanId, borrowerKey)).amounts.principalRemaining, '380000000');
    await submit(actors.borrower, await wallet.prepareRepayment(actors.borrower.accountId, loanId, 'Full'));
    const paid = await wallet.loan(loanId, borrowerKey);
    assert.equal(paid.record.status, 'Paid');
    assert.equal(paid.amounts.owed, '0'); assert.equal(paid.amounts.principalRemaining, '0');
    assert.equal(paid.record.payment_remaining, 0);
    const schedule = await core.view<{ next_due: string | null }>('get_loan', { loan_id: loanId });
    assert.equal(schedule.next_due, null);
    assert.equal(BigInt(paid.record.loan_version), BigInt(borrowerLoan.record.loan_version) + 2n);
    await reject(actors.broker, await wallet.prepareManagement(loanId, 'Default'), /LOAN_CLOSED/);
    await assert.rejects(wallet.prepareRepayment(actors.borrower.accountId, loanId, 'Full'), /not payable/);

    console.log('Lifecycle: public yield settlement and lender redemption');
    await submit(actors.broker, await wallet.prepareMergeBroker(brokerId));
    const beforeSettlement = await wallet.broker(brokerId);
    assert.equal(beforeSettlement.spending, '860000000');
    assert.equal(beforeSettlement.record.debt_total, '800000000');
    assert.equal(await auditMirror('broker', brokerId, 'token_auditor'), '860000000');
    assert.equal(await auditMirror('holder', actors.borrower.accountId, 'issuer'), '1000000');
    await submit(actors.broker, await wallet.prepareSettlement(brokerId, '860000000'));
    const vault = await core.view<LedgerVault>('get_vault', { vault_id: vaultId });
    assert.equal(vault.assets_total, '1060000000'); assert.equal(vault.assets_available, '1060000000');
    const shares = BigInt(await core.view<string>('get_share_balance', { vault_id: vaultId, owner: actors.lender.accountId }));
    const requestedAssets = 530000001n;
    const totalAssets = BigInt(vault.assets_total);
    const requiredShares = (requestedAssets * shares + totalAssets - 1n) / totalAssets;
    const amountRedemption = { vault_id: vaultId, assets_out: requestedAssets.toString(), max_shares_in: requiredShares.toString(),
      expiry: '18446744073709551615', sole_shareholder_waiver: false, broker_zero_proofs: [] };
    const slippage = await actors.lender.callRaw(core, 'redeem_amount', { args: { ...amountRedemption, max_shares_in: (requiredShares - 1n).toString() } }, { gas: maximumGas });
    assert.equal(slippage.failed, true); assert.match(JSON.stringify(slippage.status), /SLIPPAGE/);
    const redemption = await call<string>(actors.lender, 'redeem_amount', { args: amountRedemption });
    assert.equal(await core.view('get_share_balance', { vault_id: vaultId, owner: actors.lender.accountId }), (shares - requiredShares).toString());
    assert.equal((await core.view<{ amount: string }>('get_claim', { claim_id: redemption })).amount, requestedAssets.toString());
    await call(actors.lender, 'request_payout', { args: { claim_id: redemption, recipient: actors.lender.accountId, operation_id: '9007199254740995' } });
    await call(actors.recipient, 'finalize_payout', { operation_id: '9007199254740995' });
    assert.equal(await token.view('ft_balance_of', { account_id: actors.lender.accountId }), '530000001');
    assert.equal(await core.view('get_custody_total'), '569999999');
    assert.equal((await wallet.holder(actors.borrower.accountId)).inbox, '1000000');
    assert.equal((await wallet.holder(actors.recipient.accountId)).spending, '39000000');
    await call(actors.broker, 'delete_loan', { loan_id: loanId, evidence: [] });
    await submit(actors.broker, await wallet.prepareBrokerClosure(brokerId));
    const finalClaim = await call<string>(actors.lender, 'redeem_shares', { args: { vault_id: vaultId, shares: (shares - requiredShares).toString(), min_assets_out: '529999999', expiry: '18446744073709551615', sole_shareholder_waiver: false, burn_worthless: false, broker_zero_proofs: [] } });
    await call(actors.lender, 'request_payout', { args: { claim_id: finalClaim, recipient: actors.lender.accountId, operation_id: '9007199254740996' } });
    await call(actors.recipient, 'finalize_payout', { operation_id: '9007199254740996' });
    assert.equal(await token.view('ft_balance_of', { account_id: actors.lender.accountId }), '1060000000');
    assert.equal(await core.view('get_custody_total'), '40000000');
    const closedVault = await core.view<LedgerVault>('get_vault', { vault_id: vaultId });
    assert.equal(closedVault.assets_total, '0'); assert.equal(closedVault.assets_available, '0');

    console.log('Lifecycle: zero-balance key rotation preserves issuer controls and starts recoverable history');
    await submit(actors.borrower, await wallet.prepareMergeHolder(actors.borrower.accountId));
    const convertedClaim = await submit<string>(actors.borrower, await wallet.prepareUnshield(actors.borrower.accountId, '1000000'));
    await call(actors.issuer, 'set_holder_frozen', { account_id: actors.borrower.accountId, frozen: true });
    await submit(actors.borrower, await wallet.prepareHolderRegistration(actors.borrower.accountId, '2'));
    assert.equal((await core.view<{ holder_frozen: boolean }>('get_freeze_status', { account_id: actors.borrower.accountId })).holder_frozen, true,
      'Changing an encryption key cannot remove the issuer freeze');
    const rotated = await wallet.holder(actors.borrower.accountId);
    assert.equal(rotated.record.key_id, '2'); assert.equal(rotated.spending, '0'); assert.equal(rotated.inbox, '0');
    assert.ok(BigInt(rotated.record.recovery_start_sequence ?? '0') > 0n);
    await call(actors.issuer, 'set_holder_frozen', { account_id: actors.borrower.accountId, frozen: false });
    await submit(actors.borrower, await wallet.prepareShield(actors.borrower.accountId, convertedClaim));
    const restored = await wallet.holder(actors.borrower.accountId);
    assert.equal(restored.inbox, '1000000'); assert.equal(restored.spending, '0');
    await wallet.recovery.verify({ role: 'issuer', subjectId: token.accountId, keyId: '1' }, decodeWire(restored.record.issuer_balance_ciphertext), 1000000n);
    await wallet.recovery.verify({ role: 'token_auditor', subjectId: token.accountId, keyId: '1' }, decodeWire(restored.record.auditor_balance_ciphertext), 1000000n);
    assert.equal(await auditMirror('holder', actors.borrower.accountId, 'issuer'), '1000000');
    assert.equal(await auditMirror('holder', actors.borrower.accountId, 'token_auditor'), '1000000');
    assert.equal(await core.view('get_custody_total'), '40000000');
    await mkdir('.artifacts', { recursive: true });
    await writeFile('.artifacts/lifecycle-benchmark.json', JSON.stringify({ complete: true, core: core.accountId, manifestHash: deployment.manifestHash, coreWasmHash: deployment.coreWasmHash, measurements }, null, 2));
  } finally { keys.clear(); await worker.tearDown(); }
});
