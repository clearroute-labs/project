import type { DeploymentConfig } from './types'

export function deploymentConfigFromEnv(): DeploymentConfig {
  return {
    networkId: import.meta.env.VITE_NETWORK_ID || 'testnet',
    coreAccountId: import.meta.env.VITE_CORE_ACCOUNT_ID || '',
    tokenAccountId: import.meta.env.VITE_TOKEN_ACCOUNT_ID || '',
    rpcUrl: import.meta.env.VITE_RPC_URL || 'https://rpc.testnet.near.org',
    allowInsecureLocalhost: import.meta.env.VITE_ALLOW_INSECURE_LOCALHOST === 'true',
    cryptoProfileHash: import.meta.env.VITE_CRYPTO_PROFILE_HASH || '',
    cryptoArtifactHash: import.meta.env.VITE_CRYPTO_ARTIFACT_HASH || undefined,
    cryptoManifestUrl: import.meta.env.VITE_CRYPTO_MANIFEST_URL || '/crypto/manifest.json',
    cryptoArtifactBaseUrl: import.meta.env.VITE_CRYPTO_ARTIFACT_BASE_URL || undefined,
    cryptoFunded: import.meta.env.VITE_FUNDED_DEPLOYMENT === 'true',
    privyAppId: import.meta.env.VITE_PRIVY_APP_ID?.trim() || undefined,
    privyClientId: import.meta.env.VITE_PRIVY_APP_CLIENT_ID?.trim() || undefined,
    assetDecimals: Number.parseInt(import.meta.env.VITE_ASSET_DECIMALS || '', 10),
    assetSymbol: import.meta.env.VITE_ASSET_SYMBOL || 'ASSET',
  }
}
