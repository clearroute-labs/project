import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { access, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
  try {
    await access('.local/playwright');
    process.env.PLAYWRIGHT_BROWSERS_PATH = resolve('.local/playwright');
  } catch { /* Use Playwright's normal cache when no repository-local installation exists. */ }
}
const { chromium, expect } = await import('@playwright/test');

// All mutations go through rendered product forms. RPC is used only to verify
// finalized results; no injected adapters, prebuilt proofs or signing shortcuts.
assert.ok(process.argv.slice(2).every(arg => arg === '--resume-funding'), 'Unknown validation option');
const resumeFunding = process.argv.includes('--resume-funding');
const demo = JSON.parse(await readFile('.local/demo/public.json', 'utf8'));
assert.equal(demo.networkId, 'sandbox', 'Product validation is limited to local test accounts');
for (const url of [demo.rpcUrl, demo.webUrl]) assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(url).hostname));
const output = resolve('.local/demo/product-validation');
await mkdir(output, { recursive: true, mode: 0o700 });
await chmod(output, 0o700);
const evidencePath = resolve('.artifacts/product-validation.json');
const evidence = resumeFunding ? JSON.parse(await readFile(evidencePath, 'utf8')) : { complete: false, coreWasmHash: demo.coreWasmHash, manifestHash: demo.manifestHash, actions: [] };
const passphrases = resumeFunding ? JSON.parse(await readFile(resolve(output, 'passphrases.json'), 'utf8')) : {};
let rpcId = 0;
async function rpc(method, params) {
  const response = await fetch(demo.rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
  assert.ok(response.ok, 'Sandbox RPC must remain available');
  const result = await response.json();
  if (result.error) throw new Error(`Read-only RPC ${method} failed`);
  return result.result;
}
async function view(method, args = {}, account = demo.coreAccountId) {
  const response = await rpc('query', { request_type: 'call_function', finality: 'final', account_id: account,
    method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  if (response.error) throw new Error(`Finalized view ${method} failed`);
  return JSON.parse(Buffer.from(response.result).toString('utf8'));
}
const browser = await chromium.launch({ channel: 'chromium', headless: true });
const errors = [];
const roles = new Map();
const card = (page, title) => page.locator('.card').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
const button = (scope, name) => scope.getByRole('button', { name, exact: true });
async function nav(page, role, label) {
  const selector = page.getByLabel('Active workspace');
  if (await selector.inputValue() !== role) await selector.selectOption(role);
  await button(page.locator('.primary-nav'), label).click();
}
async function refresh(page, role) {
  await nav(page, role, role === 'broker' ? 'Desk overview' : role === 'borrower' ? 'Home' : 'Overview');
  await button(page, 'Refresh state').click();
}
async function connect(page, role) {
  await page.goto(demo.webUrl, { waitUntil: 'domcontentloaded' });
  await page.locator('input[aria-label="Import sandbox credentials"]').setInputFiles(resolve(`.local/demo/credentials/${role}.json`));
  await expect(button(page, 'Switch sandbox account')).toBeVisible({ timeout: 30_000 });
}
async function openRole(role, workspace = role) {
  console.log(`Product validation: open ${role} session`);
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  page.on('pageerror', () => errors.push(role));
  page.setDefaultTimeout(30_000);
  roles.set(role, page);
  await connect(page, role);
  console.log(`Product validation: ${role} wallet connected`);
  await nav(page, workspace, 'Wallet & security');
  await expect(button(page, 'Generate key')).toBeEnabled({ timeout: 90_000 });
  console.log(`Product validation: ${role} crypto ready`);
  return page;
}
async function action(page, scope, trigger, name, role) {
  const previous = await scope.locator('.action-success').allTextContents();
  const started = performance.now();
  console.log(`Product validation: ${name}`);
  await trigger.click();
  let hash;
  while (!hash && performance.now() - started < 600_000) {
    const failures = scope.locator('.field-error, .action-failed');
    if (await failures.count()) throw new Error(name + ': ' + await failures.first().innerText());
    for (const text of await scope.locator('.action-success').allTextContents()) {
      if (previous.includes(text)) continue;
      const match = text.match(/Transaction\s+([A-Za-z0-9]+)\./);
      if (match) { hash = match[1]; break; }
    }
    if (!hash) await page.waitForTimeout(500);
  }
  assert.ok(hash, name + ' must reach fresh finalized feedback');
  const result = await rpc('tx', { tx_hash: hash, sender_account_id: demo.accounts[role], wait_until: 'FINAL' });
  assert.ok('SuccessValue' in result.status, `${name} must succeed on chain`);
  for (const outcome of result.receipts_outcome) assert.ok(!('Failure' in outcome.outcome.status), `${name} contains a failed receipt`);
  evidence.actions.push({ name, transactionHash: hash, finalized: true, signerId: result.transaction.signer_id, receiverId: result.transaction.receiver_id, milliseconds: Math.round(performance.now() - started) });
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
}
async function download(page, trigger, name) {
  const pending = page.waitForEvent('download', { timeout: 90_000 });
  await trigger.click();
  const file = resolve(output, name);
  await (await pending).saveAs(file);
  await chmod(file, 0o600);
  return file;
}
async function backup(page, role, workspace = role) {
  await nav(page, workspace, 'Wallet & security');
  const passphrase = passphrases[role] ??= randomBytes(24).toString('hex');
  await writeFile(resolve(output, 'passphrases.json'), JSON.stringify(passphrases), { mode: 0o600 });
  await page.locator('#backup-export-pass').fill(passphrase);
  await page.locator('#backup-export-confirm').fill(passphrase);
  const file = await download(page, button(page, 'Encrypt & download backup'), `${role}-backup.json`);
  await button(page, 'I saved this encrypted backup').click();
  return file;
}
async function restore(page, role, file, passphrase, workspace = role) {
  await nav(page, workspace, 'Wallet & security');
  await page.locator('#backup-file').setInputFiles(file);
  await page.locator('#backup-import-pass').fill(passphrase);
  await button(page, 'Decrypt & restore').click();
  await expect(page.getByText('Wallet material restored into the browser crypto worker.', { exact: false })).toBeVisible({ timeout: 90_000 });
  await button(page, 'I saved this encrypted backup').click();
}
async function registerHolder(page, role, workspace = role) {
  await nav(page, workspace, 'Wallet & security');
  await button(page, 'Generate key').click();
  await expect(button(page, 'Register key')).toBeVisible({ timeout: 90_000 });
  await backup(page, role, workspace);
  await action(page, card(page, 'Encryption key'), button(page, 'Register key'), `${role} encryption registration`, role);
  assert.ok(await view('get_holder', { owner: demo.accounts[role] }));
}
async function depositClaim(page, role, amount) {
  await nav(page, 'lender', 'Vaults');
  await page.locator('#token-deposit-amount').fill(amount);
  await page.locator('#token-deposit-id').fill(`product-${role}-${Date.now()}`);
  await action(page, card(page, 'Fund a public claim'), button(page, 'Send token & create claim'), `${role} public token ingress`, role);
}
async function selectAvailable(page, selector) {
  await expect.poll(async () => page.locator(`${selector} option`).count()).toBeGreaterThan(1);
  await page.locator(selector).selectOption({ index: 1 });
}
async function loadPrivate(page) {
  await nav(page, 'borrower', 'Private balance');
  const load = button(page, 'Load encrypted account');
  const decrypt = button(page, 'Decrypt balance');
  await expect(load.or(decrypt).first()).toBeVisible({ timeout: 30_000 });
  if (await load.isVisible()) await load.click();
  await expect(decrypt).toBeVisible({ timeout: 30_000 });
}

async function publishAgreement(broker, borrower, brokerId) {
  await nav(broker, 'broker', 'Loan book');
  await broker.locator('#proposal-broker').selectOption(brokerId);
  for (const [id, value] of Object.entries({ 'proposal-borrower': demo.accounts.borrower, 'proposal-auditor': '1', 'proposal-auditor-public': demo.loanAuditorKey.point,
    'proposal-principal': '60', 'proposal-owed': '66', 'proposal-payment': '22', 'proposal-count': '3', 'proposal-interval': '86400', 'proposal-grace': '3600', 'proposal-expiry': '43200' })) {
    await broker.locator(`#${id}`).fill(value);
  }
  await button(broker, 'Encrypt agreement locally').click();
  await expect(broker.getByText('Agreement draft ready', { exact: true })).toBeVisible({ timeout: 90_000 });
  await action(broker, card(broker, 'Build a private agreement'), button(broker, 'Publish broker-authorized proposal'), 'Publish encrypted loan proposal', 'broker');
  const proposalId = (await view('get_counters')).proposal_high_water;
  const proposalPackage = await download(broker, button(broker, 'Download encrypted package'), 'proposal-package.json');
  await backup(broker, 'broker');
  await refresh(borrower, 'borrower');
  await nav(borrower, 'borrower', 'Agreements');
  await borrower.getByRole('table', { name: 'Encrypted loan proposals' }).locator('tbody tr').filter({ has: borrower.locator('td:first-child').getByText(proposalId, { exact: true }) }).click();
  await borrower.locator('#proposal-package').setInputFiles(proposalPackage);
  await button(borrower, 'Decrypt & inspect').click();
  await expect(button(borrower, 'Authorize proposal')).toBeEnabled({ timeout: 90_000 });
  await action(borrower, card(borrower, 'Review before authorization'), button(borrower, 'Authorize proposal'), 'Borrower reviews and authorizes agreement', 'borrower');
  return proposalId;
}

try {
  const deployed = await rpc('query', { request_type: 'view_code', finality: 'final', account_id: demo.coreAccountId });
  assert.equal(createHash('sha256').update(Buffer.from(deployed.code_base64, 'base64')).digest('hex'), demo.coreWasmHash);
  if (!resumeFunding) {
    assert.equal(await view('get_holder', { owner: demo.accounts.borrower }), null, 'Use a freshly launched demo for product validation');
    assert.equal(await view('get_custody_total'), '0', 'Product validation requires an unfunded fresh demo');
  }
  const currentLenderBalance = BigInt(await view('ft_balance_of', { account_id: demo.accounts.lender }, demo.tokenAccountId));
  const initialLenderBalance = resumeFunding ? currentLenderBalance + 100_000_000n : currentLenderBalance;
  let vaultId, brokerId, proposalId;
  const broker = await openRole('broker');
  const borrower = await openRole('borrower');
  const lender = await openRole('lender');
  const recipient = await openRole('recipient', 'borrower');
  if (resumeFunding) {
    assert.equal(evidence.complete, false);
    assert.equal(evidence.coreWasmHash, demo.coreWasmHash);
    assert.equal(evidence.manifestHash, demo.manifestHash);
    assert.ok(evidence.actions.length >= 13 && (evidence.actions.length - 13) % 3 === 0, 'Resume is only supported after agreement authorization and before funding');
    assert.equal(evidence.actions.at(-1).name, 'Borrower reviews and authorizes agreement');
    // Every recorded action was written only after its complete FINAL receipt
    // passed the assertions in action(). Sandbox RPC prunes old transaction
    // outcomes, so recovery validates that durable evidence and current state.
    const expectedNames = ['borrower encryption registration', 'recipient encryption registration', 'Register broker application authorization', 'Core storage top-up', 'Create public vault', 'Register backed-up broker key', 'lender public token ingress', 'Fund vault with lender claim', 'borrower public token ingress', 'Shield borrower funds', 'Draw restricted broker funding', 'Publish encrypted loan proposal', 'Borrower reviews and authorizes agreement'];
    for (const [index, recorded] of evidence.actions.entries()) {
      assert.equal(recorded.name, index < 13 ? expectedNames[index] : ['Revoke interrupted proposal', 'Publish encrypted loan proposal', 'Borrower reviews and authorizes agreement'][(index - 13) % 3]);
      assert.match(recorded.transactionHash, /^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
      assert.ok(recorded.milliseconds > 0 && Number.isFinite(recorded.milliseconds));
    }
    assert.equal(new Set(evidence.actions.map(item => item.transactionHash)).size, evidence.actions.length);
    const counters = await view('get_counters');
    assert.equal(counters.loan_high_water, '0', 'Never resubmit an already funded proposal');
    assert.equal(counters.vault_high_water, '1');
    assert.equal(counters.broker_high_water, '1');
    assert.equal(counters.proposal_high_water, String(1 + (evidence.actions.length - 13) / 3));
    [vaultId, brokerId, proposalId] = ['1', '1', counters.proposal_high_water];
    assert.equal(await view('get_custody_total'), '110000000');
    assert.equal((await view('get_vault', { vault_id: vaultId })).assets_available, '20000000');
    assert.equal((await view('get_broker', { broker_id: brokerId })).debt_total, '80000000');
    assert.equal(currentLenderBalance, 900_000_000n);
    for (const [role, page, workspace] of [['broker', broker, 'broker'], ['borrower', borrower, 'borrower'], ['recipient', recipient, 'borrower']]) {
      await restore(page, role, resolve(output, role + '-backup.json'), passphrases[role], workspace);
    }
    evidence.resumedFromEncryptedBackups = true;
    console.log('Product validation: validated recorded final receipts and current state; private sessions restored');
    await refresh(broker, 'broker');
    await nav(broker, 'broker', 'Loan book');
    await broker.locator('#originate-proposal').selectOption(proposalId);
    const oldProposal = await view('get_proposal', { proposal_id: proposalId });
    if (BigInt(oldProposal.expiry) <= BigInt(Math.floor(Date.now() / 1000))) await expect(button(broker, 'Prepare funding')).toBeDisabled();
    await action(broker, card(broker, 'Originate an authorized proposal'), button(broker, 'Revoke'), 'Revoke interrupted proposal', 'broker');
    proposalId = await publishAgreement(broker, borrower, brokerId);
  } else {
  await registerHolder(borrower, 'borrower');
  await registerHolder(recipient, 'recipient', 'borrower');
  await button(broker, 'Generate auth key').click();
  await expect(button(broker, 'Register auth key')).toBeVisible();
  await backup(broker, 'broker');
  await action(broker, card(broker, 'Register account key'), button(broker, 'Register auth key'), 'Register broker application authorization', 'broker');
  assert.equal(await view('get_holder', { owner: demo.accounts.broker }), null);
  await nav(lender, 'lender', 'Wallet & security');
  await lender.locator('#storage-deposit').fill('0.1');
  await action(lender, card(lender, 'Keep this account funded'), button(lender, 'Add NEAR storage'), 'Core storage top-up', 'lender');

  await nav(broker, 'broker', 'Vaults & brokers');
  await broker.locator('#vault-maximum').fill('1000');
  await broker.locator('#vault-share-scale').fill('6');
  await broker.locator('#vault-epoch').fill('60');
  await action(broker, card(broker, 'Create a vault'), button(broker, 'Create vault'), 'Create public vault', 'broker');
  vaultId = (await view('get_counters')).vault_high_water;
  const fillBroker = async () => {
    await broker.locator('#broker-vault').selectOption(vaultId);
    await broker.locator('#broker-key-id').fill('1');
    await broker.locator('#broker-ceiling').fill('100');
  };
  await fillBroker();
  await card(broker, 'Create a broker').locator('button[type="submit"]').click();
  await expect(card(broker, 'Create a broker').getByText('A new broker key was generated', { exact: false })).toBeVisible({ timeout: 90_000 });
  await backup(broker, 'broker');
  await nav(broker, 'broker', 'Vaults & brokers');
  await fillBroker();
  await action(broker, card(broker, 'Create a broker'), card(broker, 'Create a broker').locator('button[type="submit"]'), 'Register backed-up broker key', 'broker');
  brokerId = (await view('get_counters')).broker_high_water;

  await depositClaim(lender, 'lender', '100');
  await lender.locator('#deposit-vault').selectOption(vaultId);
  await selectAvailable(lender, '#deposit-claim');
  await lender.locator('#deposit-amount').fill('100');
  await lender.locator('#deposit-min-shares').fill('0');
  await action(lender, card(lender, 'Deposit claim into a vault'), button(lender, 'Deposit claim'), 'Fund vault with lender claim', 'lender');
  await depositClaim(borrower, 'borrower', '10');
  await loadPrivate(borrower);
  await selectAvailable(borrower, '#shield-claim');
  await action(borrower, card(borrower, 'Shield a public claim'), button(borrower, 'Shield claim'), 'Shield borrower funds', 'borrower');
  await nav(broker, 'broker', 'Operations');
  await broker.locator('#draw-broker').selectOption(brokerId);
  await broker.locator('#draw-amount').fill('80');
  await action(broker, card(broker, 'Draw vault liquidity'), button(broker, 'Prepare & draw'), 'Draw restricted broker funding', 'broker');

  proposalId = await publishAgreement(broker, borrower, brokerId);
  }
  await refresh(broker, 'broker');
  await nav(broker, 'broker', 'Loan book');
  await broker.locator('#originate-proposal').selectOption(proposalId);
  await action(broker, card(broker, 'Originate an authorized proposal'), button(broker, 'Prepare funding'), 'Fund confidential loan', 'broker');
  const loanId = (await view('get_counters')).loan_high_water;

  await refresh(borrower, 'borrower');
  await loadPrivate(borrower);
  await borrower.locator('#transfer-destination').fill(demo.accounts.recipient);
  await button(borrower, 'Resolve key').click();
  await borrower.locator('#transfer-amount').fill('1');
  await action(borrower, card(borrower, 'Transfer privately'), button(borrower, 'Prepare private transfer'), 'Spend loan funds confidentially', 'borrower');
  await borrower.locator('#repay-loan').selectOption(loanId);
  await action(borrower, card(borrower, 'Repay privately'), button(borrower, 'Prepare repayment proof'), 'Regular confidential repayment', 'borrower');
  await borrower.locator('#repay-mode').selectOption('full');
  await action(borrower, card(borrower, 'Repay privately'), button(borrower, 'Prepare repayment proof'), 'Full confidential repayment', 'borrower');
  assert.equal((await view('get_loan', { loan_id: loanId })).status, 'Paid');
  await nav(broker, 'broker', 'Operations');
  await broker.locator('#settle-broker').selectOption(brokerId);
  await broker.locator('#settle-amount').fill('86');
  await action(broker, card(broker, 'Settle broker funds'), button(broker, 'Prepare & settle'), 'Settle principal and public yield', 'broker');
  assert.equal((await view('get_vault', { vault_id: vaultId })).assets_total, '106000000');

  await refresh(broker, 'broker');
  await nav(broker, 'broker', 'Loan book');
  await broker.locator('#delete-loan').selectOption(loanId);
  await action(broker, card(broker, 'Delete a closed loan record'), button(broker, 'Delete display record'), 'Archive terminal loan', 'broker');
  await nav(broker, 'broker', 'Operations');
  await broker.locator('#close-broker').selectOption(brokerId);
  await action(broker, card(broker, 'Close a broker account'), button(broker, 'Close broker account'), 'Close settled broker', 'broker');
  await refresh(lender, 'lender');
  await nav(lender, 'lender', 'Vaults');
  await lender.locator('#redeem-vault').selectOption(vaultId);
  // Initial share units are asset base units multiplied by 10^share_scale.
  await lender.locator('#redeem-shares').fill('100000000');
  await lender.locator('#redeem-min-amount').fill('106');
  await action(lender, card(lender, 'Redeem from a vault'), button(lender, 'Redeem shares'), 'Redeem final lender shares', 'lender');
  await nav(lender, 'lender', 'Claims & payouts');
  await selectAvailable(lender, '#payout-claim');
  await lender.locator('#payout-recipient').fill(demo.accounts.lender);
  await action(lender, card(lender, 'Request payout'), button(lender, 'Reserve payout'), 'Reserve lender payout', 'lender');
  await expect(button(lender, 'Finalize payout')).toBeVisible({ timeout: 90_000 });
  await action(lender, card(lender, 'Payout status'), button(lender, 'Finalize payout'), 'Finalize authenticated payout result', 'lender');
  assert.equal(BigInt(await view('ft_balance_of', { account_id: demo.accounts.lender }, demo.tokenAccountId)), initialLenderBalance + 6_000_000n);
  assert.equal(await view('get_custody_total'), '4000000');
  assert.equal((await view('get_vault', { vault_id: vaultId })).shares_total, '0');

  const auditor = await openRole('auditor');
  const auditorPassphrase = (await readFile('.local/demo/auditor-backup-passphrase.txt', 'utf8')).trim();
  await restore(auditor, 'auditor', resolve('.local/demo/auditor-backup.json'), auditorPassphrase);
  await nav(auditor, 'auditor', 'Loan exports');
  await auditor.locator('#audit-subject').fill(loanId);
  await button(auditor, 'Load & decrypt authorized view').click();
  await expect(auditor.getByText('Decrypted locally', { exact: true })).toBeVisible({ timeout: 90_000 });
  assert.ok(await view('get_archived_loan', { loan_id: loanId }));
  assert.equal(await view('get_broker', { broker_id: brokerId }), null);
  await connect(borrower, 'borrower');
  await restore(borrower, 'borrower', resolve(output, 'borrower-backup.json'), passphrases.borrower);
  await loadPrivate(borrower);
  await button(borrower, 'Decrypt balance').click();
  await expect(borrower.locator('.balance-value')).toHaveText('3000000', { timeout: 90_000 });
  assert.deepEqual(errors, [], 'Product must not produce browser page errors');
  evidence.complete = true;
  evidence.finalState = { vaultId, brokerId, proposalId, loanId, loanArchived: true, brokerClosed: true, backupRestored: true, auditDecrypted: true };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log('Complete product UI validation passed; public evidence: .artifacts/product-validation.json');
} finally {
  await browser.close();
}
