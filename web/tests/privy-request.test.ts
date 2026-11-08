import { describe, expect, it } from 'vitest'
import { privyConfiguration, privyWalletManifest } from '../src/lib/privyConfig'
import { nearDeposit, validatePrivyRequest } from '../src/lib/privyRequest'
import type { DeploymentConfig } from '../src/lib/types'

const config: DeploymentConfig = { networkId: 'testnet', coreAccountId: 'core.testnet', tokenAccountId: 'token.testnet', rpcUrl: 'https://rpc.testnet.near.org', cryptoProfileHash: '', assetDecimals: 6, assetSymbol: 'USD', privyAppId: 'app-id', privyClientId: 'client-id' }
const call = () => ({ kind: 'signAndSendTransaction', network: 'testnet', signerId: 'a'.repeat(64), receiverId: config.coreAccountId, actions: [{ type: 'FunctionCall', params: { methodName: 'storage_deposit', gas: '300000000000000', deposit: '10000000000000000000000', args: { account_id: 'a'.repeat(64) } } }] })

describe('optional Privy wallet configuration', () => {
  it('requires an App ID and a public NEAR network', () => {
    expect(privyConfiguration({ ...config, privyAppId: undefined }, 'https://app.example')).toBeUndefined()
    expect(privyConfiguration({ ...config, networkId: 'sandbox' }, 'http://localhost:5175')).toBeUndefined()
  })
  it.each([undefined, '', '   '])('enables the wallet with App ID alone when Client ID is %s', (clientId) => {
    const options = privyConfiguration({ ...config, privyClientId: clientId }, 'https://app.example')!
    expect(options.appId).toBe('app-id')
    expect(options.clientId).toBeUndefined()
    expect(privyWalletManifest(options).name).toBe('Email or social login')
  })
  it('preserves an explicit client override and rejects malformed public identifiers', () => {
    expect(privyConfiguration({ ...config, privyClientId: ' client-id ' }, 'https://app.example')?.clientId).toBe('client-id')
    expect(() => privyConfiguration({ ...config, privyClientId: 'invalid client' }, 'https://app.example')).toThrow(/identifiers/)
    expect(() => privyConfiguration({ ...config, privyAppId: 'invalid app' }, 'https://app.example')).toThrow(/identifiers/)
  })
  it('serves the pinned executor locally and limits the wallet to the configured network and signing page', () => {
    const options = privyConfiguration(config, 'https://app.example')!
    const manifest = privyWalletManifest(options)
    expect(manifest.executor).toMatch(/^https:\/\/app.example\//)
    expect(manifest.metadata).toEqual({ signPageURL: 'https://app.example/wallet/privy', debug: false })
    expect(manifest.permissions.allowsOpen).toEqual([options.signPageUrl])
    expect(manifest.features.testnet).toBe(true)
    expect(manifest.features.mainnet).toBe(false)
    expect(manifest.features.signInWithFunctionCallKey).toBe(false)
  })
  it('allows localhost development but rejects insecure remote origins and RPC credentials', () => {
    expect(privyConfiguration(config, 'http://localhost:5174')).toBeDefined()
    expect(() => privyConfiguration(config, 'http://app.example')).toThrow(/HTTPS/)
    expect(() => privyConfiguration({ ...config, rpcUrl: 'https://secret@rpc.example' }, 'https://app.example')).toThrow(/credentials/)
  })
})

describe('Privy signing request boundary', () => {
  it('preserves 300 Tgas, exact deposits, and contract arguments', () => {
    const request = call()
    expect(validatePrivyRequest(request, config, request.signerId)).toBe(request)
    expect(nearDeposit(request.actions[0].params.deposit)).toBe('0.01 NEAR')
    expect(nearDeposit('1')).toBe('0.000000000000000000000001 NEAR')
  })
  it('only permits a read-only sign-in on the deployment network', () => {
    expect(validatePrivyRequest({ kind: 'signIn', network: 'testnet' }, config)).toEqual({ kind: 'signIn', network: 'testnet' })
    expect(() => validatePrivyRequest({ kind: 'signIn', network: 'testnet', addFunctionCallKey: {} }, config)).toThrow(/permissions/)
  })
  it.each([
    ['wrong network', { network: 'mainnet' }],
    ['omitted network', { network: undefined }],
    ['another contract', { receiverId: 'other.testnet' }],
    ['omitted signer', { signerId: undefined }],
    ['raw message signing', { kind: 'signMessage' }],
    ['empty actions', { actions: [] }],
    ['access key addition', { actions: [{ type: 'AddKey', params: {} }] }],
  ])('rejects %s', (_label, change) => {
    expect(() => validatePrivyRequest({ ...call(), ...change }, config)).toThrow()
  })
  it('rejects an account change before approval', () => {
    expect(() => validatePrivyRequest(call(), config, 'b'.repeat(64))).toThrow(/different wallet/)
  })
  it('checks the total gas budget and integer deposit bounds', () => {
    const request = call()
    request.actions.push(request.actions[0])
    expect(() => validatePrivyRequest(request, config)).toThrow(/gas/)
    const overflow = call()
    overflow.actions[0].params.deposit = (2n ** 128n).toString()
    expect(() => validatePrivyRequest(overflow, config)).toThrow(/deposit/)
  })
})
