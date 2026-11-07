import { afterEach, describe, expect, it, vi } from 'vitest'
import { deploymentConfigFromEnv, hasProtocolDeployment } from '../src/lib/deploymentConfig'

afterEach(() => vi.unstubAllEnvs())

describe('public deployment defaults', () => {
  it('selects the real testnet deployment and HTTPS RPC without environment overrides', () => {
    const config = deploymentConfigFromEnv()
    expect(config.networkId).toBe('testnet')
    expect(config.coreAccountId).toBe('clearroute-core-312a0a7a.testnet')
    expect(config.rpcUrl).toBe('https://test.rpc.fastnear.com')
    expect(config.testnetFaucet).toBe(true)
    expect(hasProtocolDeployment(config)).toBe(true)
  })

  it('does not combine a custom Core with default testnet cryptographic pins', () => {
    vi.stubEnv('VITE_CORE_ACCOUNT_ID', 'other.testnet')
    const config = deploymentConfigFromEnv()
    expect(config.coreAccountId).toBe('other.testnet')
    expect(config.cryptoArtifactHash).toBeUndefined()
    expect(config.testnetFaucet).toBe(false)
    expect(hasProtocolDeployment(config)).toBe(false)
  })

  it('never uses testnet contracts or faucet on another network', () => {
    vi.stubEnv('VITE_NETWORK_ID', 'mainnet')
    vi.stubEnv('VITE_TESTNET_FAUCET', 'true')
    const config = deploymentConfigFromEnv()
    expect(config.coreAccountId).toBe('')
    expect(config.testnetFaucet).toBe(false)
    expect(hasProtocolDeployment(config)).toBe(false)
  })

  it('allows the operator to disable the bundled testnet faucet', () => {
    vi.stubEnv('VITE_TESTNET_FAUCET', 'false')
    expect(deploymentConfigFromEnv().testnetFaucet).toBe(false)
  })
})
