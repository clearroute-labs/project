import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { verifyManifestPin, type CryptoManifest } from '../packages/client/src/artifacts.js';
import { NativeCrypto } from '../packages/wallet/src/native.js';
import { Keyring, freshSeed, type EncryptionPublicKey, type KeyReference } from '../packages/wallet/src/keyring.js';
import { ProofBuilder, type Ciphertext, type OperationContext, type ProvenOperation, type ReaderView, type RepaymentTerms, type SpendingState } from '../packages/wallet/src/proofs.js';

const directory = resolve(process.argv[2] ?? '.artifacts/development');
const manifest = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8')) as CryptoManifest;
const pin = JSON.parse(await readFile(join(directory, 'deployment-pin.json'), 'utf8')) as { manifestHash: string };
await verifyManifestPin(manifest, pin.manifestHash);
const crypto = new NativeCrypto(directory, manifest.artifacts['native.prover']!, manifest.artifacts);
const keyring = new Keyring({ networkId: manifest.networkId, coreAccountId: manifest.coreAccountId, assetId: 'token.test.near', profileHash: manifest.profileHash }, crypto);
const builder = new ProofBuilder(crypto, keyring);
const reference = (role: KeyReference['role'], subjectId: string): KeyReference => ({ role, subjectId, keyId: '1' });
const broker = reference('broker', '1'), borrower = reference('holder', 'borrower.test.near');
const recipient = reference('holder', 'recipient.test.near'), issuer = reference('issuer', 'token.test.near');
const auditor = reference('token_auditor', 'token.test.near'), loanAuditor = reference('loan_auditor', '1');
for (const key of [broker, borrower, recipient, issuer, auditor, loanAuditor]) await keyring.generate(key);
const pk = (key: KeyReference) => keyring.publicKey(key);
let sequence = 0;
function context(): OperationContext {
  return {
    network_id: Array(32).fill(1), core_account: Array(32).fill(2), asset_id: Array(32).fill(3),
    operation_id: Array.from(createHash('sha256').update(`integration-fixture-${++sequence}`).digest()),
    vault_id: Array(32).fill(4), broker_id: Array(32).fill(5), loan_id: Array(32).fill(6), proposal_id: Array(32).fill(7),
    expected_versions: Array(8).fill('0'), authorization_epochs: Array(4).fill('0'), expiry: '0',
  };
}
async function encrypted(key: EncryptionPublicKey, amount: string): Promise<Ciphertext> {
  const result = await crypto.execute<{ views: ReaderView[] }>('encrypt_views', { public_keys: [key], amount, seed_hex: freshSeed() });
  return result.views[0]!.ciphertext;
}
async function spending(key: KeyReference, amount: string): Promise<SpendingState> {
  return { key, amount, version: '0', ciphertext: await encrypted(pk(key), amount) };
}
const measurements: Array<{ operation: string; milliseconds: number; proofBytes: number; publicInputs: number }> = [];
async function measure(name: string, action: () => Promise<ProvenOperation>): Promise<ProvenOperation> {
  const start = performance.now();
  const result = await action();
  measurements.push({ operation: name, milliseconds: Math.ceil(performance.now() - start), proofBytes: result.envelope.proof.length / 2, publicInputs: result.envelope.public_inputs.length });
  process.stdout.write(`Verified ${name}\n`);
  return result;
}

const possession = await measure('key-possession', () => builder.possession(context(), broker));
const borrowerBalance = await spending(borrower, '100');
await measure('public-credit', async () => builder.conversion(context(), await spending(borrower, '0'), '100', [pk(borrower), pk(issuer), pk(auditor)], 'Credit'));
await measure('public-debit', () => builder.conversion(context(), borrowerBalance, '20', [pk(borrower), pk(issuer), pk(auditor)], 'Debit'));
await measure('confidential-transfer', () => builder.transfer(context(), borrowerBalance, '10', [pk(borrower), pk(recipient), pk(issuer), pk(auditor), pk(recipient)]));
const draft = await builder.agreement({ principal: '50', initialOwed: '60', periodicPayment: '20', paymentCount: 3, maxPaymentCount: 120,
  transferKeys: [pk(broker), pk(borrower), pk(issuer), pk(auditor), pk(loanAuditor)], loanKeys: [pk(borrower), pk(broker), pk(loanAuditor)] });
await measure('origination', async () => builder.originate(context(), await spending(broker, '200'), draft));
const loan: RepaymentTerms = {
  owed: '60', periodicPayment: '20', principalRemaining: '50', owedViews: draft.owed.views, paymentViews: draft.payment.views,
  principalViews: [draft.principal.views[1]!, draft.principal.views[0]!, draft.principal.views[4]!],
  transferKeys: [pk(borrower), pk(broker), pk(issuer), pk(auditor), pk(loanAuditor)], paymentRemaining: 3, loanVersion: '0',
};
const regular = await measure('regular-repayment', () => builder.repay(context(), borrowerBalance, loan, 'Regular'));
const after = regular.statement.Repayment!;
await measure('full-repayment', () => builder.repay(context(), { ...borrowerBalance, ciphertext: after.borrower_spending_after as Ciphertext, amount: '80', version: '1' },
  { ...loan, owed: '40', principalRemaining: '30', owedViews: after.owed_after as ReaderView[], principalViews: after.principal_after as ReaderView[], paymentRemaining: 2, loanVersion: '1' }, 'Full'));
await measure('reconciliation', async () => builder.reconcile(context(), {
  brokerKey: broker, cash: { ciphertext: await encrypted(pk(broker), '100'), amount: '100' },
  activePrincipal: { ciphertext: await encrypted(pk(broker), '50'), amount: '50' },
  impairedPrincipal: { ciphertext: await encrypted(pk(broker), '50'), amount: '50' },
  debt: '200', vaultAssets: '200', vaultProvision: '0', brokerProvision: '0', bookVersion: '2', accountingVersion: '1',
}));
await measure('zero-balance', async () => builder.balance(context(), await spending(broker, '0'), true));
await measure('ownership', async () => builder.balance(context(), await spending(broker, '1'), false));
const altered = structuredClone(possession.statement);
(altered.KeyPossession!.context as OperationContext).expiry = '1';
let rejected = false;
try { await crypto.execute('verify', { statement: JSON.stringify(altered), envelope: JSON.stringify(possession.envelope) }, { artifactName: 'key-possession.vk' }); }
catch { rejected = true; }
if (!rejected) throw new Error('Verifier accepted a modified operation context');
await writeFile(join(directory, 'client-validation.json'), `${JSON.stringify({ profileHash: manifest.profileHash, manifestHash: pin.manifestHash, measurements, modifiedContextRejected: true }, null, 2)}\n`);
process.stdout.write('All eight proof families passed native client integration.\n');
