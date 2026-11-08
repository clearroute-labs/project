import type { WalletManifest } from '@hot-labs/near-connect'
import executorAsset from '@peerfolio/privy-near-connect/executor?url'
import walletIcon from '../assets/wallet.svg'
import type { DeploymentConfig } from './types'

export const PRIVY_WALLET_ID = 'private-ledger-privy'
export const PRIVY_SIGN_PATH = '/wallet/privy'

export interface PrivyConfiguration {
  appId: string
  clientId?: string
  network: 'mainnet' | 'testnet'
  rpcUrl: string
  origin: string
  signPageUrl: string
}

/** Social login is opt-in and never connects a public wallet to the local sandbox. */
export function privyConfiguration(config: DeploymentConfig, origin: string): PrivyConfiguration | undefined {
  if (config.networkId !== 'mainnet' && config.networkId !== 'testnet') return undefined
  const appId = config.privyAppId?.trim()
  const clientId = config.privyClientId?.trim() || undefined
  if (!appId) return undefined
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(appId) || (clientId && !/^[a-zA-Z0-9_-]{1,128}$/.test(clientId))) throw new Error('Invalid public Privy application identifiers.')
  const location = new URL(origin)
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)
  if (location.protocol !== 'https:' && !(local && location.protocol === 'http:')) throw new Error('Privy requires HTTPS or a localhost development origin.')
  if (location.username || location.password) throw new Error('Wallet origins must not include credentials.')
  const rpc = new URL(config.rpcUrl)
  if (rpc.protocol !== 'https:' || rpc.username || rpc.password) throw new Error('Public-network wallet RPC must use HTTPS without URL credentials.')
  return { appId, ...(clientId ? { clientId } : {}), network: config.networkId === 'mainnet' ? 'mainnet' : 'testnet', rpcUrl: rpc.href, origin: location.origin, signPageUrl: new URL(PRIVY_SIGN_PATH, location.origin).href }
}

/** The executor comes from the lockfile-pinned package and is served with this app. */
export function privyWalletManifest(config: PrivyConfiguration): WalletManifest & { metadata: { signPageURL: string; debug: false } } {
  return {
    id: PRIVY_WALLET_ID,
    name: 'Email or social login',
    description: 'Sign in with Privy to use a NEAR wallet.',
    icon: new URL(walletIcon, config.origin).href,
    website: config.origin,
    platform: ['browser'],
    version: '0.0.8',
    executor: new URL(executorAsset, config.origin).href,
    type: 'sandbox',
    permissions: { storage: true, allowsOpen: [config.signPageUrl] },
    features: {
      signMessage: false,
      signTransaction: false,
      signAndSendTransaction: true,
      signAndSendTransactions: false,
      signInWithoutAddKey: true,
      signInAndSignMessage: false,
      signInWithFunctionCallKey: false,
      signDelegateActions: false,
      mainnet: config.network === 'mainnet',
      testnet: config.network === 'testnet',
    },
    metadata: { signPageURL: config.signPageUrl, debug: false },
  }
}
