#!/usr/bin/env node
import { chromium, expect } from '@playwright/test'
import { mkdir } from 'node:fs/promises'

// Uses Vite's source modules and the real NEAR Connect registry/executor.
// No wallet login or transaction is performed; Privy IDs here only register its entry.
const origin = process.env.UI_BASE_URL || 'http://127.0.0.1:5175'
const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium' })
const page = await browser.newPage()
const errors = []
page.on('pageerror', (error) => errors.push(error.message))
try {
  await page.goto(origin)
  await page.evaluate(async () => {
    const { NearConnectWallet } = await import('/src/lib/nearConnectWallet.ts')
    const { privyConfiguration, privyWalletManifest } = await import('/src/lib/privyConfig.ts')
    const config = { networkId: 'testnet', coreAccountId: 'core.testnet', tokenAccountId: 'token.testnet', rpcUrl: 'https://rpc.testnet.near.org', cryptoProfileHash: '', assetDecimals: 6, assetSymbol: 'USD', privyAppId: 'smoke-app', privyClientId: 'smoke-client' }
    window.walletSmoke = new NearConnectWallet(config, { additionalWallets: [privyWalletManifest(privyConfiguration(config, location.origin))] })
    void window.walletSmoke.connect().catch(() => {})
  })
  const social = page.locator('.connect-item[data-type="private-ledger-privy"]')
  await expect(social).toBeVisible({ timeout: 30_000 })
  const count = await page.locator('.connect-item').count()
  if (count < 2) throw new Error('The ecosystem wallet registry was replaced by the Privy entry.')
  await expect.poll(() => social.locator('img').evaluate((image) => image.naturalWidth)).toBeGreaterThan(0)
  await mkdir('.artifacts/ui', { recursive: true })
  await page.screenshot({ path: '.artifacts/ui/near-connect-selector.png' })
  await page.keyboard.press('Escape')
  await expect.poll(() => page.evaluate(() => window.walletSmoke.status)).toBe('error')
  await expect(social).toHaveCount(0)
  await page.evaluate(() => { void window.walletSmoke.connect().catch(() => {}) })
  await expect(social).toBeVisible()
  const opened = page.waitForEvent('popup')
  await social.click()
  const popup = await opened
  popup.on('pageerror', (error) => errors.push(error.message))
  await popup.waitForURL('**/wallet/privy')
  await expect(popup.getByText('Social login is not configured', { exact: true })).toBeVisible({ timeout: 30_000 })
  await popup.close()
  await expect.poll(() => page.evaluate(() => window.walletSmoke.status)).toBe('error')
  if (await page.evaluate(() => window.walletSmoke.accountId)) throw new Error('Closing an unconfigured login created a session.')
  if (process.env.UI_PREVIEW_URL) {
    const production = await browser.newPage()
    production.on('pageerror', (error) => errors.push(error.message))
    await production.goto(new URL('/wallet/privy', process.env.UI_PREVIEW_URL).href)
    await expect(production.getByText('Social login is not configured', { exact: true })).toBeVisible({ timeout: 30_000 })
    await production.close()
  }
  if (errors.length) throw new Error(`Browser errors: ${errors.join('; ')}`)
  console.log(`NEAR Connect smoke passed: ${count} testnet wallet entries, cancellation/retry, local Privy executor and popup route.`)
} catch (error) {
  console.error(await page.evaluate(() => ({ status: window.walletSmoke?.status, error: window.walletSmoke?.error })))
  console.error(await page.locator('.connect-item[data-type="private-ledger-privy"] img').evaluateAll((images) => images.map((image) => ({ src: image.src, complete: image.complete }))))
  throw error
} finally {
  await browser.close()
}
