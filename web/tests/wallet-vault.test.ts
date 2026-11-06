import { describe, expect, it } from 'vitest'
import { decryptWalletBackup, encryptWalletBackup } from '../src/lib/walletVault'

describe('encrypted wallet backups', () => {
  it('round-trips material with AES-GCM and rejects the wrong passphrase', async () => {
    const backup = await encryptWalletBackup({ privateKey: 'never-log-this', keyId: '7' }, 'correct horse battery staple')
    expect(backup.cipher).toBe('AES-256-GCM')
    expect(backup.ciphertext).not.toContain('never-log-this')
    await expect(decryptWalletBackup(backup, 'incorrect passphrase')).rejects.toThrow(/Unable to decrypt/)
    await expect(decryptWalletBackup(backup, 'correct horse battery staple')).resolves.toEqual({ privateKey: 'never-log-this', keyId: '7' })
  })

  it('requires a strong passphrase', async () => {
    await expect(encryptWalletBackup({ key: 'secret' }, 'too-short')).rejects.toThrow(/12 characters/)
  })
})
