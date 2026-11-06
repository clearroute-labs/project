import { useEffect, useState } from 'react'
import type { DeploymentConfig } from './types'

const savedScopes = new Set<string>()
const listeners = new Set<() => void>()

/** Scope the confirmation to the connected account and immutable deployment. */
export function walletBackupScope(config: DeploymentConfig, accountId?: string): string | undefined {
  if (!accountId) return undefined
  return [config.networkId, config.coreAccountId, config.tokenAccountId, config.cryptoProfileHash, accountId].join('|')
}

export function hasEncryptedWalletBackup(scope: string | undefined): boolean {
  return Boolean(scope && savedScopes.has(scope))
}

/** Mark only after the user confirms that the encrypted file was saved. */
export function markEncryptedWalletBackupSaved(scope: string | undefined): void {
  if (!scope) return
  savedScopes.add(scope)
  for (const listener of listeners) listener()
}

export function clearEncryptedWalletBackup(scope: string | undefined): void {
  if (!scope || !savedScopes.delete(scope)) return
  for (const listener of listeners) listener()
}

export function useEncryptedWalletBackup(scope: string | undefined): boolean {
  const [saved, setSaved] = useState(() => hasEncryptedWalletBackup(scope))
  useEffect(() => {
    const update = () => setSaved(hasEncryptedWalletBackup(scope))
    listeners.add(update)
    update()
    return () => { listeners.delete(update) }
  }, [scope])
  return saved
}
