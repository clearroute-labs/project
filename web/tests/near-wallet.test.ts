import { describe, expect, it } from 'vitest'
import { KeyPair } from '@near-js/crypto'
import { base58 } from '@scure/base'
import type { NearRpc } from '@confidential-lending/client'
import { isSandboxCredentialDeployment, SandboxCredentialWallet } from './support/sandboxWallet'
import type { DeploymentConfig } from '../src/lib/types'

const config: DeploymentConfig = {
  networkId: 'sandbox',
  coreAccountId: 'core.test.near',
  tokenAccountId: 'token.test.near',
  rpcUrl: 'http://127.0.0.1:3030',
  allowInsecureLocalhost: true,
  cryptoProfileHash: 'a'.repeat(64),
  cryptoArtifactHash: 'b'.repeat(64),
  assetDecimals: 6,
  assetSymbol: 'USDC',
}

describe('sandbox credential wallet', () => {
  it('only enables credential import for a sandbox localhost deployment', () => {
    expect(isSandboxCredentialDeployment(config)).toBe(true)
    expect(isSandboxCredentialDeployment({ ...config, networkId: 'testnet' })).toBe(false)
    expect(isSandboxCredentialDeployment({ ...config, rpcUrl: 'https://rpc.testnet.near.org' })).toBe(false)
  })

  it('starts disconnected and becomes connected only after importing a valid file', async () => {
    const key = KeyPair.fromRandom('ed25519')
    const rpc = { request: async () => ({}) } as unknown as NearRpc
    const wallet = new SandboxCredentialWallet(config, rpc)
    expect(wallet.status).toBe('disconnected')
    await expect(wallet.connect()).rejects.toThrow(/credential JSON/i)
    const file = new File([JSON.stringify({ account_id: 'alice.test.near', private_key: key.toString(), public_key: key.getPublicKey().toString() })], 'alice.json', { type: 'application/json' })
    await wallet.importCredentialFile(file)
    expect(wallet.status).toBe('connected')
    expect(wallet.accountId).toBe('alice.test.near')
    await wallet.disconnect()
    expect(wallet.status).toBe('disconnected')
    expect(wallet.accountId).toBeUndefined()
  })

  it('signs and broadcasts a real transaction without sending the private key', async () => {
    const key = KeyPair.fromRandom('ed25519')
    const blockHash = base58.encode(new Uint8Array(32).fill(7))
    const calls: Array<{ method: string; params: unknown }> = []
    const rpc = {
      request: async <T>(method: string, params: unknown): Promise<T> => {
        calls.push({ method, params })
        if (method === 'query') return { nonce: '7', block_hash: blockHash, permission: 'FullAccess' } as T
        if (method === 'broadcast_tx_commit') return { transaction: { hash: base58.encode(new Uint8Array(32).fill(8)) } } as T
        throw new Error(`unexpected RPC method ${method}`)
      },
    } as unknown as NearRpc
    const wallet = new SandboxCredentialWallet(config, rpc)
    await wallet.importCredentialFile(new File([JSON.stringify({ account_id: 'alice.test.near', private_key: key.toString() })], 'alice.json'))
    const signed = await wallet.signAndSendTransaction({ receiverId: config.coreAccountId, actions: [{ type: 'FunctionCall', params: { methodName: 'ping', args: { public_value: 'aa' }, gas: '1000000000000', deposit: '0' } }] })
    expect(signed?.transaction.signer_id).toBe('alice.test.near')
    expect(calls.map((call) => call.method)).toEqual(['query', 'broadcast_tx_commit'])
    expect(JSON.stringify(calls[0]?.params)).not.toContain(key.toString())
    expect(JSON.stringify(calls[1]?.params)).not.toContain(key.toString())
  })
})
