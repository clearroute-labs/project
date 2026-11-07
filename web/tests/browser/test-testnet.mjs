#!/usr/bin/env node
import { chromium, expect } from '@playwright/test'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium' })
const probe = resolve(`.local/dev-server-probe-${process.pid}.txt`)
try {
  const page = await browser.newPage()
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(process.env.UI_BASE_URL || 'http://localhost:5175')
  await mkdir(resolve('.local'), { recursive: true, mode: 0o700 })
  await writeFile(probe, 'Harmless access-control probe', { mode: 0o600 })
  const forbidden = await page.request.get(new URL(`/@fs${probe}`, page.url()).href)
  expect(forbidden.status()).toBe(403)
  await expect(page.getByRole('button', { name: 'Connect wallet', exact: true })).toBeVisible()
  await expect(page.getByLabel('Import sandbox credentials', { exact: true })).toHaveCount(0)
  await expect(page.getByText('NEAR testnet', { exact: false }).first()).toBeVisible()
  const result = await page.evaluate(async () => {
    const { createBrowserAdapters, deploymentConfigFromEnv } = await import('/src/lib/adapters.ts')
    const config = deploymentConfigFromEnv()
    if (config.networkId !== 'testnet' || !config.coreAccountId || !config.tokenAccountId) throw new Error('Default testnet deployment is missing')
    const adapters = createBrowserAdapters(config)
    const asset = await adapters.protocol.getAssetProfile()
    const status = await adapters.crypto.getStatus()
    if (!status.available) throw new Error(status.message)
    const faucet = await adapters.protocol.testTokenStatus('clearroute-312a0a7a.testnet')
    if (!/^\d+$/.test(faucet.balance) || typeof faucet.claimed !== 'boolean') throw new Error('Live test-token faucet reads failed')
    return { network: config.networkId, core: config.coreAccountId, token: config.tokenAccountId, asset, profileHash: status.profileHash, artifactHash: status.artifactHash }
  })
  await page.getByRole('button', { name: 'Connect wallet', exact: true }).click()
  await expect(page.locator('.connect-item').first()).toBeVisible({ timeout: 30_000 })
  const walletCount = await page.locator('.connect-item').count()
  if (walletCount < 2) throw new Error('Native NEAR wallet choices are missing')
  await page.keyboard.press('Escape')
  if (errors.length) throw new Error(errors.join('; '))
  console.log(`Live testnet browser validation passed: ${result.core}, token ${result.token}, finalized AssetProfile and faucet reads, pinned WASM initialization, ${walletCount} NEAR Connect choices, no sandbox signer.`)
} finally { await browser.close(); await rm(probe, { force: true }) }
