#!/usr/bin/env node
import { chromium, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'

// Real browser WebAuthn PRF + WebCrypto + IndexedDB, with a virtual authenticator.
// This tests browser integration, not physical Touch ID/Face ID compatibility.
const origin = process.env.UI_BASE_URL || 'http://localhost:5175'
const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium' })
try {
  const context = await browser.newContext()
  const page = await context.newPage()
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  })
  await page.goto(origin)
  const scope = 'testnet|passkey-browser-test|token.testnet|profile|alice.testnet'
  await page.evaluate(async scope => {
    const { DeviceKeyVault } = await import('/src/lib/deviceKeyVault.ts')
    window.testVault = new DeviceKeyVault()
    if (!window.testVault.supported()) throw new Error('Browser reports no WebAuthn support')
    await window.testVault.enroll(scope, 'alice.testnet', { walletMaterial: { keys: [{ private: 'test-only-secret' }], drafts: [] }, recoveryConfirmed: true })
    await window.testVault.save(scope, { walletMaterial: { keys: [{ private: 'updated-test-secret' }], drafts: [] }, recoveryConfirmed: false })
    window.testVault.lock()
    if (window.testVault.isUnlocked(scope)) throw new Error('Lock retained the data key')
  }, scope)
  await page.reload()
  const restored = await page.evaluate(async scope => {
    const { DeviceKeyVault } = await import('/src/lib/deviceKeyVault.ts')
    window.testVault = new DeviceKeyVault()
    const metadata = await window.testVault.metadata(scope)
    if (!metadata.exists) throw new Error('Encrypted copy disappeared after reload')
    const payload = await window.testVault.unlock(scope)
    return { sameMaterial: payload.walletMaterial.keys[0].private === 'updated-test-secret', recoveryConfirmed: payload.recoveryConfirmed }
  }, scope)
  expect(restored).toEqual({ sameMaterial: true, recoveryConfirmed: false })
  const stored = await page.evaluate(async () => {
    const result = []
    for (const { name } of await indexedDB.databases()) {
      const db = await new Promise((resolve, reject) => { const request = indexedDB.open(name); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error) })
      for (const store of db.objectStoreNames) {
        const rows = await new Promise((resolve, reject) => { const request = db.transaction(store).objectStore(store).getAll(); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error) })
        result.push(JSON.stringify(rows))
      }
      db.close()
    }
    return result.join('\n')
  })
  expect(stored).not.toContain('test-only-secret')
  expect(stored).not.toContain('updated-test-secret')
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('secret')
  await page.evaluate(async scope => {
    await window.testVault.remove(scope)
    if ((await window.testVault.metadata(scope)).exists) throw new Error('Encrypted copy was not removed')
  }, scope)
  if (process.env.UI_CREDENTIAL_FILE && process.env.UI_BACKUP_FILE && process.env.UI_BACKUP_PASSPHRASE_FILE) {
    const passphrase = (await readFile(process.env.UI_BACKUP_PASSPHRASE_FILE, 'utf8')).trim()
    const connect = async () => {
      await page.getByLabel('Import sandbox credentials', { exact: true }).setInputFiles(process.env.UI_CREDENTIAL_FILE)
      await page.getByRole('button', { name: 'Wallet & security', exact: true }).click()
      await expect(page.getByRole('button', { name: 'Encrypt & download backup', exact: true })).toBeEnabled({ timeout: 60_000 })
    }
    await connect()
    await page.getByLabel('Backup file', { exact: true }).setInputFiles(process.env.UI_BACKUP_FILE)
    await page.locator('#backup-import-pass').fill(passphrase)
    await page.getByRole('button', { name: 'Decrypt & restore', exact: true }).click()
    await page.getByRole('button', { name: 'I saved this encrypted backup', exact: true }).click()
    const save = page.getByRole('button', { name: 'Save with passkey', exact: true })
    await expect(save).toBeEnabled()
    await save.click()
    await expect(page.getByText('Unlocked', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Lock private keys', exact: true }).click()
    const unlock = page.getByRole('button', { name: 'Unlock with passkey', exact: true })
    await expect(unlock).toBeEnabled()
    await unlock.click()
    await expect(page.getByText('Unlocked', { exact: true })).toBeVisible()
    await expect(page.getByText('Saved confirmation', { exact: true })).toBeVisible()
    await page.reload()
    await connect()
    await expect(unlock).toBeEnabled()
    await unlock.click()
    await expect(page.getByText('Unlocked', { exact: true })).toBeVisible()
    await expect(page.getByText('Saved confirmation', { exact: true })).toBeVisible()
    console.log('Passkey app validation passed: encrypted file restore, save, worker lock, unlock, reload, reconnect and recovery confirmation.')
  }
  console.log('Passkey browser validation passed: PRF enrollment, encrypted autosave, reload/unlock, no plaintext persistence, and removal.')
} finally { await browser.close() }
