import { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from '../../src/App'
import { Button } from '../../src/components/ui'
import { deploymentConfigFromEnv } from '../../src/lib/deploymentConfig'
import { createRpcProtocolClient } from '../../src/lib/nearClient'
import { createWorkerCryptoProvider } from '../../src/lib/workerCrypto'
import type { AppAdapters, DeploymentConfig, WalletAdapter } from '../../src/lib/types'
import { isSandboxCredentialDeployment, SandboxCredentialWallet } from '../support/sandboxWallet'
import '../../src/styles.css'

export interface SandboxCredentialWalletAdapter extends WalletAdapter {
  readonly credentialImport: { label: string; accept: string }
  importCredentialFile(file: File): Promise<void>
}

/**
 * Build the real RPC, wallet, and crypto adapters used by the local browser
 * integration flow. This factory intentionally lives under tests so the
 * production app cannot accidentally expose sandbox credential handling.
 */
export function createSandboxAdapters(config: DeploymentConfig = deploymentConfigFromEnv()): AppAdapters {
  if (!isSandboxCredentialDeployment(config)) {
    throw new Error('The sandbox fixture requires a sandbox deployment on an explicitly allowed localhost RPC.')
  }
  if (!config.coreAccountId || !config.tokenAccountId || !/^[a-f\d]{64}$/i.test(config.cryptoProfileHash) || !config.cryptoArtifactHash || !/^[a-f\d]{64}$/i.test(config.cryptoArtifactHash) || !Number.isInteger(config.assetDecimals) || config.assetDecimals < 0 || config.assetDecimals > 38) {
    throw new Error('The sandbox fixture requires complete deployment identifiers and pinned crypto hashes.')
  }
  const wallet = new SandboxCredentialWallet(config)
  const { protocol } = createRpcProtocolClient(config, wallet)
  const crypto = createWorkerCryptoProvider({
    expectedProfileHash: config.cryptoProfileHash,
    expectedArtifactHash: config.cryptoArtifactHash,
    manifestUrl: config.cryptoManifestUrl || '/crypto/manifest.json',
    artifactBaseUrl: config.cryptoArtifactBaseUrl,
    networkId: config.networkId,
    coreAccountId: config.coreAccountId,
    assetId: config.tokenAccountId,
    funded: config.cryptoFunded === true,
    rpcUrl: config.rpcUrl,
    allowInsecureLocalhost: config.allowInsecureLocalhost,
  })
  return { protocol, wallet, crypto }
}

/**
 * Mount the production App with explicitly supplied adapters and the local
 * credential control needed by the browser integration harness.
 */
export function SandboxBrowserFixture({ adapters }: { adapters?: AppAdapters } = {}) {
  const fixtureAdapters = useMemo(() => adapters ?? createSandboxAdapters(), [adapters])
  const wallet = asSandboxCredentialWallet(fixtureAdapters.wallet)
  return (
    <>
      <SandboxCredentialImportControl wallet={wallet} />
      <App adapters={fixtureAdapters} />
    </>
  )
}

export function SandboxCredentialImportControl({ wallet }: { wallet: SandboxCredentialWalletAdapter }) {
  const input = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [, setWalletRevision] = useState(0)

  useEffect(() => wallet.subscribe(() => setWalletRevision((revision) => revision + 1)), [wallet])

  const importCredentials = async (file: File) => {
    setBusy(true)
    setError('')
    try {
      await wallet.importCredentialFile(file)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Sandbox credential import failed.')
    } finally {
      setBusy(false)
    }
  }

  const connected = wallet.status === 'connected'
  const label = busy ? 'Importing sandbox credentials…' : connected ? 'Switch sandbox account' : 'Import sandbox credentials'
  return (
    <div style={{ position: 'fixed', top: 12, right: 16, zIndex: 1000, display: 'flex', alignItems: 'center', gap: 8 }} data-testid="sandbox-credential-control">
      <Button variant="secondary" disabled={busy} onClick={() => input.current?.click()}>{label}</Button>
      <input
        ref={input}
        className="credential-file-input"
        type="file"
        accept={wallet.credentialImport.accept}
        aria-label="Import sandbox credentials"
        onChange={(event) => {
          const file = event.currentTarget.files?.[0]
          event.currentTarget.value = ''
          if (file) void importCredentials(file)
        }}
      />
      {error ? <span role="alert" style={{ maxWidth: 320 }}>{error}</span> : null}
    </div>
  )
}

function asSandboxCredentialWallet(wallet: WalletAdapter): SandboxCredentialWalletAdapter {
  if (!('credentialImport' in wallet) || !wallet.credentialImport || typeof (wallet as Partial<SandboxCredentialWalletAdapter>).importCredentialFile !== 'function') {
    throw new TypeError('The sandbox fixture requires a wallet adapter with in-memory credential import support.')
  }
  return wallet as SandboxCredentialWalletAdapter
}

const root = document.getElementById('root')
if (!root) throw new Error('Missing #root element')
createRoot(root).render(<SandboxBrowserFixture />)
