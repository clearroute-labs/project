import {
  decryptWalletBackup as decryptSharedWalletBackup,
  encryptWalletBackup as encryptSharedWalletBackup,
} from '@confidential-lending/wallet'
import type { EncryptedWalletBackup } from './types'

/**
 * Keep the browser UI boundary stable while the shared wallet package owns
 * the audited PBKDF2/AES-GCM format and bounds. Clear wallet material never
 * crosses this module's file/download helpers.
 */
export function encryptWalletBackup(
  walletMaterial: Record<string, unknown>,
  passphrase: string,
): Promise<EncryptedWalletBackup> {
  return encryptSharedWalletBackup(walletMaterial, passphrase) as Promise<EncryptedWalletBackup>
}

export function decryptWalletBackup(
  backup: EncryptedWalletBackup,
  passphrase: string,
): Promise<Record<string, unknown>> {
  return decryptSharedWalletBackup(backup, passphrase)
}

export function downloadWalletBackup(backup: EncryptedWalletBackup, filename = 'private-ledger-wallet.backup.json'): void {
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export async function readWalletBackup(file: File): Promise<EncryptedWalletBackup> {
  const parsed = JSON.parse(await file.text()) as Partial<EncryptedWalletBackup>
  if (
    parsed.version !== 1 ||
    parsed.kdf !== 'PBKDF2-SHA-256' ||
    parsed.cipher !== 'AES-256-GCM' ||
    typeof parsed.salt !== 'string' ||
    typeof parsed.iv !== 'string' ||
    typeof parsed.ciphertext !== 'string' ||
    typeof parsed.iterations !== 'number'
  ) {
    throw new Error('The selected file is not a valid encrypted wallet backup.')
  }
  return parsed as EncryptedWalletBackup
}
