#!/usr/bin/env node

import { chromium } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const baseUrl = process.env.UI_BASE_URL || 'http://127.0.0.1:5175/app'
const screenshotDir = path.resolve(process.env.UI_SCREENSHOT_DIR || path.join(process.cwd(), '.artifacts', 'ui'))
const credentialFile = process.env.UI_CREDENTIAL_FILE
const scriptRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const localRoot = process.env.UI_LOCAL_ROOT || (fs.existsSync(path.join(scriptRoot, '.local')) ? path.join(scriptRoot, '.local') : path.resolve(scriptRoot, '..', '..', '.local'))
const credentialDir = process.env.UI_CREDENTIAL_DIR || path.join(localRoot, 'demo', 'credentials')
const backupFile = process.env.UI_BACKUP_FILE
const backupPassphraseFile = process.env.UI_BACKUP_PASSPHRASE_FILE
const backupPassphrase = backupPassphraseFile ? fs.readFileSync(backupPassphraseFile, 'utf8').trim() : undefined
const headed = process.env.UI_HEADED === '1'
const publicConfigFile = process.env.UI_PUBLIC_CONFIG_FILE || path.join(localRoot, 'demo', 'public.json')
const publicConfig = fs.existsSync(publicConfigFile) ? JSON.parse(fs.readFileSync(publicConfigFile, 'utf8')) : {}
const rpcUrl = process.env.UI_RPC_URL || publicConfig.rpcUrl
const coreAccountId = process.env.UI_CORE_ACCOUNT_ID || publicConfig.coreAccountId

function check(condition, message) {
  if (!condition) throw new Error(message)
}

async function visible(locator, message) {
  try {
    await locator.waitFor({ state: 'visible', timeout: 5_000 })
  } catch {
    throw new Error(message)
  }
}

async function expectVisibleText(page, text, message = `Expected visible text: ${text}`) {
  await visible(page.getByText(text, { exact: true }).first(), message)
}

async function openWorkspace(page, role, navigationLabel) {
  const selector = page.getByLabel('Active workspace')
  await visible(selector, 'The workspace selector must remain accessible on this viewport.')
  await selector.selectOption(role)
  await page.waitForTimeout(100)
  await visible(page.getByRole('button', { name: navigationLabel, exact: true }), `Expected ${role} navigation after workspace switch.`)
}

async function inspectViewport(page, viewport, screenshotName) {
  await page.setViewportSize(viewport)
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 })
  await visible(page.getByRole('main').getByRole('button', { name: 'Connect wallet', exact: true }), 'Disconnected state should invite a wallet connection.')
  await visible(page.getByRole('main').getByRole('heading', { name: 'Credit, on your terms.', exact: true }), 'Disconnected screen should explain wallet entry.')
  await openWorkspace(page, 'broker', 'Loan book')
  await openWorkspace(page, 'borrower', 'Agreements')
  await openWorkspace(page, 'auditor', 'Loan exports')
  await openWorkspace(page, 'lender', 'Wallet & security')
  await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
  await visible(page.getByRole('main').getByRole('button', { name: 'Connect wallet', exact: true }), 'Settings should prompt for a wallet while disconnected.')
  check(await page.getByLabel('Backup file').count() === 0, 'Recovery controls should appear only after connection.')
  await page.screenshot({ path: path.join(screenshotDir, screenshotName), fullPage: true })
}

async function inspectOptionalCredentialFlow(page) {
  if (!credentialFile) return
  check(fs.existsSync(credentialFile), `Credential file does not exist: ${credentialFile}`)
  const input = page.locator('input[aria-label="Import sandbox credentials"]')
  if ((await input.count()) === 0) {
    // Navigation checks can leave a responsive sidebar in a transient route;
    // reset to the disconnected landing state before importing credentials.
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 })
    await page.getByRole('main').getByRole('button', { name: 'Connect wallet', exact: true }).waitFor({ state: 'visible', timeout: 15_000 })
  }
  if ((await input.count()) === 0) {
    const controls = await page.locator('input').evaluateAll((elements) => elements.map((element) => ({ type: element.type, aria: element.getAttribute('aria-label'), id: element.id })))
    throw new Error(`Sandbox credential import should be visible for a local deployment. Controls: ${JSON.stringify(controls)}`)
  }
  await input.setInputFiles(credentialFile)
  await page.waitForTimeout(500)
  await visible(page.getByRole('button', { name: 'Switch sandbox account', exact: true }), 'Imported sandbox credentials should produce a connected wallet state.')
  if (backupFile) {
    check(fs.existsSync(backupFile), `Backup file does not exist: ${backupFile}`)
    check(backupPassphraseFile && fs.existsSync(backupPassphraseFile), 'A backup passphrase file is required; passphrases are never accepted from environment values.')
    await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
    await page.getByLabel('Backup file').setInputFiles(backupFile)
    if (backupPassphrase) await page.locator('#backup-import-pass').fill(backupPassphrase)
    const restore = page.getByRole('button', { name: 'Decrypt & restore', exact: true })
    await visible(restore, 'Connected security settings should expose backup restore.')
    // File parsing and worker availability update independently of the input
    // event; wait for the selected encrypted material to reach React state.
    for (let attempt = 0; attempt < 20 && await restore.isDisabled(); attempt += 1) await page.waitForTimeout(250)
    check(!(await restore.isDisabled()), 'A selected encrypted backup with a passphrase must enable restore.')
    await restore.click()
    await visible(page.getByText('Wallet material restored into the browser crypto worker.', { exact: false }), 'Encrypted backup restore should report success.')
  }
}

function finalizedHash(text, action) {
  const match = text.match(/Transaction\s+([A-Za-z0-9]+)\.?/)
  if (!match) throw new Error(`${action} did not expose a finalized transaction hash.`)
  return match[1]
}

async function waitForFinalizedAction(page, action) {
  const success = page.locator('.action-feedback.action-success').filter({ hasText: `${action} finalized.` }).last()
  const failure = page.locator('.action-feedback.action-failed').filter({ hasText: `${action} could not be completed.` }).last()
  const deadline = Date.now() + 180_000
  let lastState = ''
  while (Date.now() < deadline) {
    if (await failure.count()) throw new Error(`${action} failed: ${await failure.innerText()}`)
    if (await success.count()) return finalizedHash(await success.innerText(), action)
    const pending = page.locator('.action-feedback').filter({ hasText: action }).last()
    if (await pending.count()) lastState = await pending.innerText()
    await page.waitForTimeout(100)
  }
  throw new Error(`${action} did not report finality within 180000ms. Last state: ${lastState || 'not rendered'}`)
}

async function clickAndWaitFinalized(page, locator, action, timeout = 180_000) {
  const broadcast = page.waitForResponse((response) => {
    if (response.request().method() !== 'POST') return false
    try { return JSON.parse(response.request().postData() || '{}').method === 'broadcast_tx_commit' } catch { return false }
  }, { timeout })
  await locator.click()
  let response
  try {
    response = await broadcast
  } catch (error) {
    const failure = await page.locator('.action-feedback.action-failed, .field-error').allTextContents()
    if (failure.length) throw new Error(`${action} produced no finalized transaction: ${failure.join(' ')}`)
    throw error
  }
  const body = await response.json()
  if (body.error) {
    const cause = body.error.cause?.name || body.error.name || 'RPC_ERROR'
    throw new Error(`${action} RPC submission failed before finality (${cause}).`)
  }
  const result = body.result
  if (!result || typeof result !== 'object' || !result.transaction || typeof result.transaction.hash !== 'string' || !result.transaction.hash) throw new Error(`${action} did not return a finalized transaction hash.`)
  if (result.status && typeof result.status === 'object' && 'Failure' in result.status) throw new Error(`${action} finalized with a contract failure.`)
  // Sandbox final-access-key reads can lag the broadcast receipt by one block;
  // let the next signed action observe the nonce that just finalized.
  await page.waitForTimeout(1_500)
  return result.transaction.hash
}

function credentialPath(role) {
  return process.env[`UI_${role.toUpperCase()}_CREDENTIAL_FILE`] || path.join(credentialDir, `${role}.json`)
}

function accountIdFromCredential(file) {
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
  if (typeof parsed.account_id !== 'string' || !parsed.account_id.trim()) throw new Error(`Credential file has no account_id: ${file}`)
  return parsed.account_id
}

async function switchSandboxAccount(page, file) {
  check(fs.existsSync(file), `Credential file does not exist: ${file}`)
  const expected = accountIdFromCredential(file)
  const input = page.locator('input[aria-label="Import sandbox credentials"]')
  await input.waitFor({ state: 'attached', timeout: 15_000 })
  await input.setInputFiles(file)
  await page.getByRole('button', { name: 'Switch sandbox account', exact: true }).waitFor({ state: 'visible', timeout: 30_000 })
  await page.locator('.account-chip').filter({ hasText: expected }).waitFor({ state: 'visible', timeout: 10_000 })
}

async function selectLatestAvailable(page, selector) {
  let value = ''
  const deadline = Date.now() + 30_000
  while (!value && Date.now() < deadline) {
    value = await page.locator(`${selector} option`).evaluateAll((options) => {
      const matches = options.filter((option) => option.value && /available|restored/i.test(option.textContent || ''))
      return matches.at(-1)?.value || ''
    })
    if (!value) await page.waitForTimeout(250)
  }
  check(value, `No available option was returned for ${selector}.`)
  await page.locator(selector).selectOption(value)
  return value
}

async function finalizedView(accountId, method, args) {
  check(typeof rpcUrl === 'string' && rpcUrl, 'UI_RPC_URL or a local public.json is required for finalized state assertions.')
  check(typeof accountId === 'string' && accountId, `A configured account is required for finalized ${method} assertions.`)
  const request = { jsonrpc: '2.0', id: `ui-${method}`, method: 'query', params: { request_type: 'call_function', finality: 'final', account_id: accountId, method_name: method, args_base64: Buffer.from(JSON.stringify(args || {})).toString('base64') } }
  const response = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) })
  const body = await response.json()
  if (!response.ok || body.error) throw new Error(`Finalized Core ${method} read failed.`)
  const bytes = body.result?.result
  if (!Array.isArray(bytes)) throw new Error(`Finalized Core ${method} returned an invalid result.`)
  return JSON.parse(Buffer.from(bytes).toString('utf8'))
}

async function finalizedCoreView(method, args) {
  check(typeof coreAccountId === 'string' && coreAccountId, 'UI_CORE_ACCOUNT_ID or a local public.json is required for finalized state assertions.')
  return finalizedView(coreAccountId, method, args)
}

async function finalizedTokenView(method, args) {
  check(typeof publicConfig.tokenAccountId === 'string' && publicConfig.tokenAccountId, 'The deployment public.json must include tokenAccountId for payout assertions.')
  return finalizedView(publicConfig.tokenAccountId, method, args)
}

/** Connected public flow using only rendered product forms. */
async function inspectConnectedPublicFlow(page) {
  if (process.env.UI_RUN_PUBLIC_FLOW !== '1') return
  const evidence = { baseUrl, generatedAt: new Date().toISOString(), actions: [], finalState: {} }
  const record = (name, txHash) => evidence.actions.push({ name, txHash, expected: 'finalized' })
  const brokerCredential = credentialPath('broker')
  const lenderCredential = credentialPath('lender')
  check(fs.existsSync(brokerCredential), `A broker credential is required to create a fresh public vault: ${brokerCredential}`)
  check(fs.existsSync(lenderCredential), `A lender credential is required for the public flow: ${lenderCredential}`)

  await switchSandboxAccount(page, brokerCredential)
  await openWorkspace(page, 'broker', 'Vaults & brokers')
  await page.getByRole('button', { name: 'Vaults & brokers', exact: true }).click()
  const vaultRows = page.locator('table').filter({ hasText: 'Public vault records' }).locator('tbody tr')
  let vaultId = ''
  if (await vaultRows.count()) {
    const firstRow = await vaultRows.first().innerText()
    if (!/No finalized vault records/i.test(firstRow)) vaultId = firstRow.trim().split(/\s+/)[0]
  }
  if (!vaultId) {
    await page.locator('#vault-maximum').fill(process.env.UI_VAULT_MAXIMUM || '1')
    await page.locator('#vault-share-scale').fill(process.env.UI_VAULT_SHARE_SCALE || '6')
    await page.locator('#vault-epoch').fill(process.env.UI_VAULT_EPOCH || '60')
    await page.locator('#vault-disclosure').fill(process.env.UI_VAULT_DISCLOSURE || 'aggregate_only')
    record('create vault', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Create vault', exact: true }), 'Create vault', 30_000))
    await page.locator('table').filter({ hasText: 'Public vault records' }).locator('tbody tr').first().waitFor({ state: 'visible', timeout: 30_000 })
    vaultId = (await page.locator('table').filter({ hasText: 'Public vault records' }).locator('tbody tr').first().locator('td').first().innerText()).trim().split(/\s+/)[0]
  }

  await switchSandboxAccount(page, lenderCredential)
  await openWorkspace(page, 'lender', 'Vaults')
  await page.getByRole('button', { name: 'Vaults', exact: true }).click()
  await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
  const storageDeposit = page.locator('#storage-deposit')
  if (await storageDeposit.count()) {
    await storageDeposit.fill(process.env.UI_STORAGE_TOPUP || '0.1')
    record('storage top-up', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Add NEAR storage', exact: true }), 'Add NEAR storage', 30_000))
  }
  await page.getByRole('button', { name: 'Vaults', exact: true }).click()
  const depositAmount = process.env.UI_PUBLIC_DEPOSIT_AMOUNT || '0.0001'
  await page.locator('#token-deposit-amount').fill(depositAmount)
  record('token ingress → public claim', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Send token & create claim', exact: true }), 'Fund public claim', 30_000))
  await page.locator('#deposit-vault').selectOption(vaultId)
  await selectLatestAvailable(page, '#deposit-claim')
  // The ingress refresh can remount the form while its claim options arrive;
  // pin the vault again immediately before submitting the claim.
  await page.locator('#deposit-vault').selectOption(vaultId)
  await page.locator('#deposit-amount').fill(depositAmount)
  await page.locator('#deposit-min-shares').fill('0')
  record('public claim → vault shares', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Deposit claim', exact: true }), 'Deposit claim to vault', 30_000))
  await page.locator('#redeem-vault').selectOption(vaultId)
  // With the demo's share scale of six, 50 human shares equals 50 base asset
  // units at a one-to-one NAV. Tiny fractional share inputs round to zero and
  // are correctly rejected by Core's slippage guard.
  await page.locator('#redeem-shares').fill(process.env.UI_PUBLIC_REDEEM_SHARES || '50')
  await page.locator('#redeem-min-amount').fill('0')
  record('vault shares → public claim', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Redeem shares', exact: true }), 'Redeem shares', 30_000))
  await page.getByRole('button', { name: 'Claims & payouts', exact: true }).click()
  const payoutClaimId = await selectLatestAvailable(page, '#payout-claim')
  const payoutRecipient = process.env.UI_PAYOUT_RECIPIENT || 'recipient.test.near'
  await page.getByLabel('Recipient account').fill(payoutRecipient)
  const lenderAccount = accountIdFromCredential(lenderCredential)
  const tokenBalanceBefore = BigInt(String(await finalizedTokenView('ft_balance_of', { account_id: payoutRecipient })))
  record('claim payout reservation', await clickAndWaitFinalized(page, page.getByRole('button', { name: 'Reserve payout', exact: true }), 'Request external payout', 30_000))
  const [vault, claims, payouts] = await Promise.all([
    finalizedCoreView('get_vault', { vault_id: vaultId }),
    finalizedCoreView('list_claims', { owner: lenderAccount, cursor: '0', limit: 50 }),
    finalizedCoreView('list_payouts', { owner: lenderAccount, cursor: '0', limit: 50 }),
  ])
  check(vault && String(vault.vault_id) === vaultId, 'Finalized Core state did not return the selected vault.')
  check(Array.isArray(claims) && claims.length > 0, 'Finalized Core state did not return a lender claim.')
  check(Array.isArray(payouts) && payouts.length > 0, 'Finalized Core state did not return the payout reservation.')
  const payout = [...payouts].reverse().find((item) => String(item.claim_id) === payoutClaimId)
  check(payout && ['ResultRecordedSuccess', 'ResultRecordedFailure'].includes(String(payout.status)), 'The payout callback did not reach an authenticated result state; the reservation must remain locked.')
  const payoutOperationId = String(payout.operation_id)
  const payoutRow = page.locator('.operation-row').filter({ hasText: payoutOperationId })
  const finalize = payoutRow.getByRole('button', { name: 'Finalize payout', exact: true })
  await finalize.waitFor({ state: 'visible', timeout: 30_000 })
  record('finalize recorded payout', await clickAndWaitFinalized(page, finalize, 'Finalize payout', 30_000))
  const [finalPayout, consumedClaim, tokenBalanceAfter] = await Promise.all([
    finalizedCoreView('get_payout', { operation_id: payoutOperationId }),
    finalizedCoreView('get_claim', { claim_id: payoutClaimId }),
    finalizedTokenView('ft_balance_of', { account_id: payoutRecipient }),
  ])
  check(finalPayout && String(finalPayout.status) === 'Succeeded', 'Finalized Core payout state did not transition to Succeeded.')
  check(consumedClaim === null, 'Finalized payout did not consume the original claim.')
  check(BigInt(String(tokenBalanceAfter)) > tokenBalanceBefore, 'Recipient token balance did not increase after the successful payout.')
  evidence.finalState = {
    vaultId,
    vaultPhase: vault.phase || vault.kind || vault.status || 'unknown',
    accountingVersion: String(vault.accounting_version ?? 'unknown'),
    claimCount: claims.length,
    payoutStatuses: [...payouts.map((item) => String(item.status || 'unknown')), String(finalPayout.status || 'unknown')],
    finalizedPayout: true,
    claimConsumed: true,
    recipientTokenBalanceIncreased: true,
  }
  fs.mkdirSync(screenshotDir, { recursive: true })
  fs.writeFileSync(path.join(screenshotDir, 'connected-public-flow.json'), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o644 })
  console.log(`Connected public flow passed at ${baseUrl}; public evidence: ${path.join(screenshotDir, 'connected-public-flow.json')}`)
}

const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium', headless: !headed })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
const pageErrors = []
page.on('pageerror', (error) => pageErrors.push(error.message.slice(0, 240)))

try {
  fs.mkdirSync(screenshotDir, { recursive: true })
  await inspectViewport(page, { width: 1440, height: 900 }, 'harness-desktop.png')
  await inspectViewport(page, { width: 390, height: 844 }, 'harness-mobile.png')
  await inspectOptionalCredentialFlow(page)
  await inspectConnectedPublicFlow(page)
  check(pageErrors.length === 0, `Browser page errors: ${pageErrors.join('; ')}`)
  console.log(`UI smoke flow passed at ${baseUrl}`)
  console.log(`Screenshots: ${path.join(screenshotDir, 'harness-desktop.png')}, ${path.join(screenshotDir, 'harness-mobile.png')}`)
} finally {
  await browser.close()
}
