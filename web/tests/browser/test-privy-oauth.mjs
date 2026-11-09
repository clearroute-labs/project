import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chromium, expect } from '@playwright/test'

// Run against a configured Vite server. Real SDKs and NEAR Connect execute;
// OAuth and session responses are synthetic. No Google account is used.
const baseURL = process.env.UI_BASE_URL ?? 'http://localhost:5175'
const browser = await chromium.launch()
const address = 'a'.repeat(64)
const now = Math.floor(Date.now() / 1000)
const user = {
  id: 'did:privy:oauth-browser-regression', created_at: now, has_accepted_terms: true, is_guest: false, mfa_methods: [],
  linked_accounts: [{ type: 'wallet', wallet_client_type: 'privy', connector_type: 'embedded', chain_type: 'near', id: 'test-near-wallet', address, verified_at: now, first_verified_at: now, latest_verified_at: now, public_key: address }],
}

async function run(outcome) {
  const context = await browser.newContext()
  const currentUser = outcome === 'new-wallet' ? { ...user, linked_accounts: [] } : user
  let challenge
  let state
  let exchanges = 0
  let authenticated = false
  const jwt = (appId) => [
    { alg: 'HS256', typ: 'JWT' },
    { iss: 'privy.io', aud: appId, sub: user.id, sid: 'synthetic-session', iat: now, exp: now + 3600 },
  ].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).concat('synthetic-signature').join('.')
  await context.route('https://auth.privy.io/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const reply = (json, status = 200) => route.fulfill({ status, json })
    if (path.endsWith('/oauth/init')) {
      const body = request.postDataJSON()
      assert.equal(body.provider, 'google')
      challenge = body.code_challenge
      state = body.state_code
      const callback = new URL(body.redirect_to)
      assert.equal(callback.origin, new URL(baseURL).origin)
      assert.equal(callback.pathname, '/wallet/privy')
      callback.searchParams.set('privy_oauth_code', 'synthetic-code')
      callback.searchParams.set('privy_oauth_state', outcome === 'wrong-state' ? 'wrong-state' : state)
      callback.searchParams.set('privy_oauth_provider', 'google')
      return reply({ url: callback.href })
    }
    if (path.endsWith('/oauth/authenticate')) {
      exchanges++
      const body = request.postDataJSON()
      assert.equal(body.authorization_code, 'synthetic-code')
      assert.equal(body.state_code, state)
      assert.equal(createHash('sha256').update(body.code_verifier).digest('base64url'), challenge)
      if (outcome === 'rejected') return reply({ error: 'Login expired', code: 'invalid_auth_token' }, 400)
      authenticated = true
      const token = jwt(request.headers()['privy-app-id'])
      assert.equal(body.mode, 'login-or-sign-up')
      return reply({ user: currentUser, token, privy_access_token: token, refresh_token: 'synthetic-refresh-token', session_update_action: 'set', is_new_user: false })
    }
    if (path.endsWith('/sessions') || path.endsWith('/users/me')) {
      assert.equal(authenticated, true)
      const token = jwt(request.headers()['privy-app-id'])
      return reply({ user: currentUser, token, privy_access_token: token, refresh_token: 'synthetic-refresh-token', session_update_action: 'set', is_new_user: false })
    }
    if (path.endsWith('/analytics_events')) return reply({})
    // App configuration is public and is the only API data fetched live.
    if (/\/api\/v1\/apps\/[^/]+$/.test(path) && request.method() === 'GET') return route.continue()
    return reply({ error: 'Unexpected API call in OAuth test' }, 400)
  })
  try {
    const page = await context.newPage()
    await page.goto(new URL('/app', baseURL).href)
    await page.getByRole('button', { name: 'Connect wallet', exact: true }).first().click()
    const opened = page.waitForEvent('popup')
    await page.locator('.connect-item[data-type="private-ledger-privy"]').click()
    const popup = await opened
    await popup.waitForURL('**/wallet/privy')
    await popup.getByRole('button', { name: 'Sign in', exact: true }).click()
    await popup.getByRole('button', { name: /Google/ }).click()
    if (outcome === 'new-wallet') {
      await expect(popup.getByRole('button', { name: 'Create NEAR wallet', exact: true })).toBeVisible({ timeout: 20000 })
      assert.equal(exchanges, 1)
      assert.equal(new URL(popup.url()).search, '')
      await expect(popup.getByRole('button', { name: 'Connect account', exact: true })).toHaveCount(0)
      return
    }
    if (outcome !== 'success') {
      await expect(popup.getByText('Sign-in could not be completed', { exact: true })).toBeVisible({ timeout: 20000 })
      await expect(popup.getByRole('button', { name: 'Start sign-in again' })).toBeVisible()
      assert.equal(exchanges, outcome === 'wrong-state' ? 0 : 1)
      await popup.getByRole('button', { name: 'Start sign-in again' }).click()
      await expect(popup.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 20000 })
      assert.equal(new URL(popup.url()).search, '')
      return
    }
    await expect(popup.getByRole('button', { name: 'Connect account', exact: true })).toBeVisible({ timeout: 20000 })
    assert.equal(exchanges, 1)
    assert.equal(new URL(popup.url()).search, '')
    await expect(popup.getByText(address, { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Connecting…', exact: true }).first()).toBeVisible()
    // A clean reload restores the session without exchanging the code again.
    await popup.reload()
    await expect(popup.getByRole('button', { name: 'Connect account', exact: true })).toBeVisible({ timeout: 20000 })
    assert.equal(exchanges, 1)
    const closed = popup.waitForEvent('close')
    await popup.getByRole('button', { name: 'Connect account', exact: true }).click()
    await closed
    await expect(page.getByRole('button', { name: 'Connect wallet', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Connecting…', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: `Wallet & security: ${address}`, exact: true })).toBeVisible()
  } finally { await context.close() }
}

try {
  for (const outcome of ['success', 'new-wallet', 'rejected', 'wrong-state']) {
    await run(outcome)
    console.log(`Privy OAuth ${outcome}: passed`)
  }
} finally { await browser.close() }
