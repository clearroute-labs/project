import { describe, expect, it } from 'vitest'
import { clearEncryptedWalletBackup, hasEncryptedWalletBackup, markEncryptedWalletBackupSaved, walletBackupScope } from '../src/lib/walletBackupGate'
import type { DeploymentConfig } from '../src/lib/types'

const config: DeploymentConfig = {
  networkId: 'testnet',
  coreAccountId: 'core.testnet',
  tokenAccountId: 'token.testnet',
  rpcUrl: 'https://rpc.testnet.near.org',
  cryptoProfileHash: 'a'.repeat(64),
  assetDecimals: 6,
  assetSymbol: 'USDC',
}

describe('encrypted backup registration gate', () => {
  it('is scoped to the connected account and requires an explicit saved mark', () => {
    const alice = walletBackupScope(config, 'alice.testnet')
    const bob = walletBackupScope(config, 'bob.testnet')
    expect(hasEncryptedWalletBackup(alice)).toBe(false)
    markEncryptedWalletBackupSaved(alice)
    expect(hasEncryptedWalletBackup(alice)).toBe(true)
    expect(hasEncryptedWalletBackup(bob)).toBe(false)
    clearEncryptedWalletBackup(alice)
    expect(hasEncryptedWalletBackup(alice)).toBe(false)
  })
})
