#!/usr/bin/env node

import { chromium } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

const baseUrl = process.env.UI_BASE_URL || 'http://127.0.0.1:5175'
const screenshotDir = path.resolve(process.env.UI_SCREENSHOT_DIR || path.join(process.cwd(), '.artifacts', 'ui'))
const credentialFile = process.env.UI_CREDENTIAL_FILE
const backupFile = process.env.UI_BACKUP_FILE
const backupPassphrase = process.env.UI_BACKUP_PASSPHRASE
const headed = process.env.UI_HEADED === '1'

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
  await expectVisibleText(page, 'Connect your NEAR wallet', 'Disconnected state should invite a wallet connection.')
  await expectVisibleText(page, 'Connect a wallet to view balances, loans and claims and authorize actions.')
  await openWorkspace(page, 'broker', 'Loan book')
  await openWorkspace(page, 'borrower', 'Agreements')
  await openWorkspace(page, 'auditor', 'Loan exports')
  await openWorkspace(page, 'lender', 'Wallet & security')
  await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
  await visible(page.getByRole('heading', { name: 'Keep the keys close', exact: true }), 'Security settings should be reachable while disconnected.')
  await visible(page.getByLabel('Backup file'), 'Encrypted backup import should be present.')
  check(await page.getByRole('button', { name: 'Decrypt & restore', exact: true }).isDisabled(), 'Backup restore must remain locked until a connected secure session is ready.')
  await page.screenshot({ path: path.join(screenshotDir, screenshotName), fullPage: true })
}

async function inspectOptionalCredentialFlow(page) {
  if (!credentialFile) return
  check(fs.existsSync(credentialFile), `Credential file does not exist: ${credentialFile}`)
  const input = page.locator('input[aria-label="Import sandbox credentials"]')
  await visible(input, 'Sandbox credential import should be visible for a local deployment.')
  await input.setInputFiles(credentialFile)
  await page.waitForTimeout(500)
  await visible(page.getByText('Ready', { exact: true }).first(), 'Imported sandbox credentials should produce a connected wallet state.')
  if (backupFile) {
    check(fs.existsSync(backupFile), `Backup file does not exist: ${backupFile}`)
    await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
    await page.getByLabel('Backup file').setInputFiles(backupFile)
    if (backupPassphrase) await page.locator('#backup-import-pass').fill(backupPassphrase)
    await visible(page.getByRole('button', { name: 'Decrypt & restore', exact: true }), 'Connected security settings should expose backup restore.')
  }
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
  check(pageErrors.length === 0, `Browser page errors: ${pageErrors.join('; ')}`)
  console.log(`UI smoke flow passed at ${baseUrl}`)
  console.log(`Screenshots: ${path.join(screenshotDir, 'harness-desktop.png')}, ${path.join(screenshotDir, 'harness-mobile.png')}`)
} finally {
  await browser.close()
}
