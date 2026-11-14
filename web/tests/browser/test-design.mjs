#!/usr/bin/env node

import { chromium, expect } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

const baseUrl = process.env.UI_BASE_URL || 'http://localhost:5175'
const fixtureUrl = new URL('/tests/browser/visual.html', baseUrl)
const screenshotDir = path.resolve(process.env.DESIGN_SCREENSHOT_DIR || '.local/design-review')
const headed = process.env.UI_HEADED === '1'
const browserChannel = process.env.UI_BROWSER_CHANNEL || 'chromium'

const viewports = [
  { name: 'desktop1440x1000', width: 1440, height: 1000 },
  { name: 'tablet768x1024', width: 768, height: 1024 },
  { name: 'mobile390x844', width: 390, height: 844 },
  { name: 'narrow320x844', width: 320, height: 844 },
]

const workspaces = [
  {
    value: 'lender',
    navigation: 'Lender navigation',
    overview: 'Overview',
    overviewHeading: 'Your capital, in view.',
    routes: [
      { key: 'vaults', label: 'Vaults', heading: 'Find your vault.' },
      { key: 'claims', label: 'Claims & payouts', heading: 'Claims & payouts.' },
    ],
  },
  {
    value: 'broker',
    navigation: 'Broker navigation',
    overview: 'Desk overview',
    overviewHeading: 'Credit, coordinated.',
    routes: [
      { key: 'vaults', label: 'Vaults & brokers', heading: 'Vaults & brokers.' },
      { key: 'loan-book', label: 'Loan book', heading: 'Your credit book.' },
      { key: 'operations', label: 'Operations', heading: 'Keep the book current.' },
    ],
  },
  {
    value: 'borrower',
    navigation: 'Borrower navigation',
    overview: 'Home',
    overviewHeading: 'Your next step, clear.',
    routes: [
      { key: 'agreements', label: 'Agreements', heading: 'Your agreements.' },
      { key: 'private-balance', label: 'Private balance', heading: 'Private by design.' },
    ],
  },
  {
    value: 'auditor',
    navigation: 'Auditor navigation',
    overview: 'Audit home',
    overviewHeading: 'Access, with purpose.',
    routes: [
      { key: 'loan-exports', label: 'Loan exports', heading: 'A focused view of each loan.' },
      { key: 'token-audit', label: 'Token audit', heading: 'Trace the authorized view.' },
    ],
  },
]

function fixtureFor(state) {
  const url = new URL(fixtureUrl)
  url.searchParams.set('state', state)
  return url.href
}

async function assertNoHorizontalOverflow(page, label) {
  const metrics = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    document: document.documentElement.scrollWidth,
    viewport: window.innerWidth,
  }))
  if (metrics.body > metrics.viewport + 1 || metrics.document > metrics.viewport + 1) {
    throw new Error(`${label} has horizontal overflow: ${JSON.stringify(metrics)}`)
  }
}

async function assertFocusIndicator(page, label) {
  const indicator = await page.evaluate(() => {
    const active = document.activeElement
    if (!(active instanceof HTMLElement)) return null
    const style = getComputedStyle(active)
    const outlineWidth = Number.parseFloat(style.outlineWidth) || 0
    const outlineVisible = style.outlineStyle !== 'none' && outlineWidth > 0 && style.outlineColor !== 'rgba(0, 0, 0, 0)'
    const shadowVisible = style.boxShadow !== 'none' && style.boxShadow !== ''
    return { tag: active.tagName, outlineVisible, shadowVisible, outline: style.outline, boxShadow: style.boxShadow }
  })
  if (!indicator || (!indicator.outlineVisible && !indicator.shadowVisible)) {
    throw new Error(`${label} has no visible computed focus indicator: ${JSON.stringify(indicator)}`)
  }
}

async function waitForHeading(page, heading) {
  await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible({ timeout: 10_000 })
}

async function inspectWorkspace(page, workspace, state, viewport) {
  const selector = page.getByLabel('Active workspace')
  await selector.selectOption(workspace.value)
  await waitForHeading(page, workspace.overviewHeading)

  await selector.focus()
  await expect(selector).toBeFocused()
  await assertFocusIndicator(page, `${state}/${viewport.name}/${workspace.value} workspace selector`)

  const navigation = page.getByRole('navigation', { name: workspace.navigation })
  for (const route of workspace.routes) {
    if (viewport.width <= 800) { const menu = page.getByRole('button', { name: 'Open navigation', exact: true }); await menu.focus(); await menu.press('Enter') }
    const routeButton = navigation.getByRole('button', { name: route.label, exact: true })
    await routeButton.focus()
    await expect(routeButton).toBeFocused()
    await assertFocusIndicator(page, `${state}/${viewport.name}/${workspace.value}/${route.key}`)
    await routeButton.press('Enter')
    await waitForHeading(page, route.heading)
    if (workspace.value === 'borrower' && route.key === 'private-balance') {
      await page.getByRole('button', { name: 'Load encrypted account', exact: true }).click()
      await expect(page.getByRole('button', { name: 'Decrypt balance', exact: true })).toBeVisible()
    }
    await assertNoHorizontalOverflow(page, `${state}/${viewport.name}/${workspace.value}/${route.key}`)
    await page.getByLabel('Active workspace').focus()
    await page.mouse.move(viewport.width - 4, 4)
    await page.screenshot({
      path: path.join(screenshotDir, `${state}-${viewport.name}-${workspace.value}-${route.key}.png`),
      fullPage: true,
    })
  }

  if (viewport.width <= 800) { const menu = page.getByRole('button', { name: 'Open navigation', exact: true }); await menu.focus(); await menu.press('Enter') }
  const overviewButton = navigation.getByRole('button', { name: workspace.overview, exact: true })
  await overviewButton.focus()
  await overviewButton.press('Enter')
  await waitForHeading(page, workspace.overviewHeading)
  await assertNoHorizontalOverflow(page, `${state}/${viewport.name}/${workspace.value} overview`)

  await page.getByLabel('Active workspace').focus()
  await page.mouse.move(viewport.width - 4, 4)
  await page.screenshot({
    path: path.join(screenshotDir, `${state}-${viewport.name}-${workspace.value}-overview.png`),
    fullPage: true,
  })
}

async function inspectSecurity(page, state, viewport) {
  const selector = page.getByLabel('Active workspace')
  await selector.selectOption('lender')
  await waitForHeading(page, 'Your capital, in view.')
  if (viewport.width <= 800) { const menu = page.getByRole('button', { name: 'Open navigation', exact: true }); await menu.focus(); await menu.press('Enter') }
  const securityButton = page.getByRole('navigation', { name: 'Lender navigation' }).getByRole('button', { name: 'Wallet & security', exact: true })
  await securityButton.focus()
  await expect(securityButton).toBeFocused()
  await assertFocusIndicator(page, `${state}/${viewport.name}/security`)
  await securityButton.press('Enter')
  await waitForHeading(page, 'Your wallet. Your keys.')
  await expect(page.getByText('Connected account:', { exact: false })).toBeVisible()
  await assertNoHorizontalOverflow(page, `${state}/${viewport.name}/security`)
  await page.getByLabel('Active workspace').focus()
  await page.mouse.move(viewport.width - 4, 4)
  await page.screenshot({
    path: path.join(screenshotDir, `${state}-${viewport.name}-security.png`),
    fullPage: true,
  })
}

async function inspectSpecialState(page, state, viewport) {
  await page.goto(fixtureFor(state), { waitUntil: 'domcontentloaded', timeout: 30_000 })
  if (state === 'loading') {
    await expect(page.getByText('Reading finalized Core state…', { exact: true })).toBeVisible({ timeout: 5_000 })
  } else {
    await expect(page.getByRole('heading', { name: 'State could not be read', exact: true })).toBeVisible({ timeout: 10_000 })
    await expect(page.getByRole('button', { name: 'Retry read', exact: true })).toBeVisible()
  }
  await assertNoHorizontalOverflow(page, `${state}/${viewport.name}`)
  await page.getByLabel('Active workspace').focus()
  await page.mouse.move(viewport.width - 4, 4)
  await page.screenshot({
    path: path.join(screenshotDir, `${state}-${viewport.name}.png`),
    fullPage: true,
  })
}

const browser = await chromium.launch({ channel: browserChannel, headless: !headed })
const page = await browser.newPage({ reducedMotion: 'reduce' })
const pageErrors = []
page.on('pageerror', (error) => pageErrors.push(error.message))

try {
  await mkdir(screenshotDir, { recursive: true })
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height })
    for (const state of ['populated', 'empty']) {
      await page.goto(fixtureFor(state), { waitUntil: 'domcontentloaded', timeout: 30_000 })
      await waitForHeading(page, 'Your capital, in view.')
      await assertNoHorizontalOverflow(page, `${state}/${viewport.name}/initial`)
      for (const workspace of workspaces) await inspectWorkspace(page, workspace, state, viewport)
      await inspectSecurity(page, state, viewport)
    }
    await inspectSpecialState(page, 'loading', viewport)
    await inspectSpecialState(page, 'error', viewport)
  }
  if (pageErrors.length) throw new Error(`Browser page errors: ${pageErrors.join('; ')}`)
  console.log(`Design fixture checks passed at ${baseUrl}`)
  console.log(`Screenshots written to ${screenshotDir}`)
} finally {
  await browser.close()
}
