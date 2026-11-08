import type { DeploymentConfig } from './types'
import testnet from '../config/testnet.json'

export function deploymentConfigFromEnv(): DeploymentConfig {
  const networkId = import.meta.env.VITE_NETWORK_ID || 'testnet'
  const customDeployment = Boolean(import.meta.env.VITE_CORE_ACCOUNT_ID || import.meta.env.VITE_TOKEN_ACCOUNT_ID || import.meta.env.VITE_CRYPTO_PROFILE_HASH || import.meta.env.VITE_CRYPTO_ARTIFACT_HASH)
  const defaults = networkId === 'testnet' && !customDeployment ? testnet : undefined
  return {
    networkId,
    coreAccountId: import.meta.env.VITE_CORE_ACCOUNT_ID || defaults?.coreAccountId || '',
    tokenAccountId: import.meta.env.VITE_TOKEN_ACCOUNT_ID || defaults?.tokenAccountId || '',
    rpcUrl: import.meta.env.VITE_RPC_URL || defaults?.rpcUrl || (networkId === 'mainnet' ? 'https://free.rpc.fastnear.com' : 'https://test.rpc.fastnear.com'),
    allowInsecureLocalhost: import.meta.env.VITE_ALLOW_INSECURE_LOCALHOST === 'true',
    cryptoProfileHash: import.meta.env.VITE_CRYPTO_PROFILE_HASH || defaults?.cryptoProfileHash || '',
    cryptoArtifactHash: import.meta.env.VITE_CRYPTO_ARTIFACT_HASH || defaults?.cryptoArtifactHash || undefined,
    cryptoManifestUrl: import.meta.env.VITE_CRYPTO_MANIFEST_URL || '/crypto/manifest.json',
    cryptoArtifactBaseUrl: import.meta.env.VITE_CRYPTO_ARTIFACT_BASE_URL || undefined,
    cryptoFunded: import.meta.env.VITE_FUNDED_DEPLOYMENT === 'true',
    privyAppId: import.meta.env.VITE_PRIVY_APP_ID?.trim() || undefined,
    privyClientId: import.meta.env.VITE_PRIVY_APP_CLIENT_ID?.trim() || undefined,
    assetDecimals: Number.parseInt(import.meta.env.VITE_ASSET_DECIMALS || String(defaults?.assetDecimals ?? ''), 10),
    assetSymbol: import.meta.env.VITE_ASSET_SYMBOL || defaults?.assetSymbol || 'ASSET',
    testnetFaucet: networkId === 'testnet' && (import.meta.env.VITE_TESTNET_FAUCET ? import.meta.env.VITE_TESTNET_FAUCET === 'true' : Boolean(defaults)),
  }
}

export function hasProtocolDeployment(config: DeploymentConfig): boolean {
  return Boolean(config.coreAccountId && config.tokenAccountId && /^[a-f\d]{64}$/i.test(config.cryptoProfileHash) && config.cryptoArtifactHash && /^[a-f\d]{64}$/i.test(config.cryptoArtifactHash) && Number.isInteger(config.assetDecimals) && config.assetDecimals >= 0 && config.assetDecimals <= 38)
}
