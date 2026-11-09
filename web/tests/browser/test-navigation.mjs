#!/usr/bin/env node
import { chromium, expect } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

const origin = new URL(process.env.UI_BASE_URL || 'http://localhost:5175').origin
const screenshots = path.resolve(process.env.UI_SCREENSHOT_DIR || '.local/navigation-review')
const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium' })
const errors = []

async function checkAppLayout(page) {
  const main = page.getByRole('main')
  const connect = main.getByRole('button', { name: 'Connect wallet', exact: true })
  await expect(connect).toBeVisible()
  await expect(main.getByRole('heading')).toHaveCount(0)
  const content = await main.boundingBox()
  const button = await connect.boundingBox()
  expect(Math.abs(button.x + button.width / 2 - content.x - content.width / 2)).toBeLessThan(12)
  expect(Math.abs(button.y + button.height / 2 - content.y - content.height / 2)).toBeLessThan(12)
  const workspace = await page.getByLabel('Active workspace').boundingBox()
  const wallet = await page.getByRole('banner').getByRole('button', { name: 'Connect wallet', exact: true }).boundingBox()
  expect(workspace.x + workspace.width).toBeLessThan(wallet.x)
  expect(Math.abs(workspace.y - wallet.y)).toBeLessThan(3)
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(page.viewportSize().width)
  await expect(page.getByRole('button', { name: 'Private Ledger home', exact: true }).locator('svg')).toBeVisible()
  for (const item of await page.getByRole('navigation', { name: /navigation$/ }).getByRole('button').all()) {
    await expect(item.locator('svg')).toBeVisible()
    expect(await item.getAttribute('aria-label')).toBeTruthy()
  }
}

try {
  await mkdir(screenshots, { recursive: true })
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' })
  page.on('pageerror', error => errors.push(error.message))
  const appModuleRequests = []
  page.on('request', request => { if (request.url().includes('/src/App.tsx')) appModuleRequests.push(request.url()) })
  await page.goto(origin)
  const openApp = page.getByRole('link', { name: 'Open app', exact: true })
  await expect(openApp).toBeVisible()
  await expect(page.getByLabel('Active workspace')).toHaveCount(0)
  expect(appModuleRequests).toHaveLength(0)
  await page.screenshot({ path: path.join(screenshots, 'landing-desktop.png') })
  await openApp.click()
  await expect(page).toHaveURL(`${origin}/app`)
  await checkAppLayout(page)
  await page.screenshot({ path: path.join(screenshots, 'app-collapsed-desktop.png') })

  const sidebar = page.locator('.sidebar')
  const width = async () => (await sidebar.boundingBox()).width
  await expect.poll(width).toBeLessThan(100)
  await sidebar.hover()
  await expect.poll(width).toBeGreaterThan(200)
  await page.screenshot({ path: path.join(screenshots, 'app-expanded-desktop.png') })
  await sidebar.getByRole('button', { name: 'Vaults', exact: true }).click()
  await page.mouse.move(1000, 300)
  await expect.poll(width).toBeLessThan(100)

  await sidebar.getByRole('button', { name: 'Private Ledger home', exact: true }).focus()
  await page.keyboard.press('Tab')
  await expect.poll(width).toBeGreaterThan(200)
  await page.getByLabel('Active workspace').focus()
  await expect.poll(width).toBeLessThan(100)
  await page.getByLabel('Active workspace').selectOption('broker')
  await expect(page.getByRole('navigation', { name: 'Broker navigation' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Operations', exact: true }).locator('svg')).toBeVisible()
  await page.goto(`${origin}/#/borrower/agreements`)
  await expect(page).toHaveURL(`${origin}/app#/borrower/agreements`)
  await expect(page.getByLabel('Active workspace')).toHaveValue('borrower')
  await page.goto(origin)
  await openApp.click()
  await page.goBack()
  await expect(openApp).toBeVisible()
  await page.goForward()
  await checkAppLayout(page)

  for (const viewport of [{ width: 390, height: 844 }, { width: 320, height: 740 }]) {
    const touch = await browser.newPage({ viewport, isMobile: true, hasTouch: true, reducedMotion: 'reduce' })
    touch.on('pageerror', error => errors.push(error.message))
    await touch.goto(origin)
    await touch.screenshot({ path: path.join(screenshots, `landing-${viewport.width}.png`), fullPage: true })
    await touch.getByRole('link', { name: 'Open app', exact: true }).tap()
    await checkAppLayout(touch)
    await touch.screenshot({ path: path.join(screenshots, `app-${viewport.width}.png`) })
    await touch.getByRole('button', { name: 'Expand navigation', exact: true }).tap()
    await expect(touch.getByRole('button', { name: 'Collapse navigation', exact: true })).toHaveAttribute('aria-expanded', 'true')
    await touch.screenshot({ path: path.join(screenshots, `navigation-${viewport.width}.png`) })
    await touch.getByRole('button', { name: 'Vaults', exact: true }).tap()
    await expect(touch.getByRole('button', { name: 'Expand navigation', exact: true })).toHaveAttribute('aria-expanded', 'false')
    await touch.getByRole('button', { name: 'Expand navigation', exact: true }).tap()
    await touch.keyboard.press('Escape')
    await expect(touch.getByRole('button', { name: 'Expand navigation', exact: true })).toBeFocused()
    await touch.getByRole('button', { name: 'Expand navigation', exact: true }).tap()
    await touch.getByRole('button', { name: 'Close navigation', exact: true }).tap({ position: { x: viewport.width - 10, y: 100 } })
    await expect(touch.getByRole('button', { name: 'Expand navigation', exact: true })).toHaveAttribute('aria-expanded', 'false')
    await touch.close()
  }
  expect(errors).toEqual([])
  console.log('Landing, app entry, centered wallet, legacy links, hover/keyboard navigation and touch menu passed.')
} finally {
  await browser.close()
}
