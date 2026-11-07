import { assertAccountId } from '@confidential-lending/client'
import type { SignPageSession } from '@peerfolio/privy-near-connect/sign-page'
import type { DeploymentConfig } from './types'

type SupportedRequest = Extract<SignPageSession['payload'], { kind: 'signIn' | 'signAndSendTransaction' }>

/** Validate the popup boundary before showing an approval or asking Privy to sign. */
export function validatePrivyRequest(payload: unknown, config: DeploymentConfig, accountId?: string): SupportedRequest {
  if (!payload || typeof payload !== 'object') throw new Error('Invalid wallet request.')
  const value = payload as Record<string, unknown>
  if (value.network !== config.networkId) throw new Error('The request uses a different NEAR network.')
  if (value.kind === 'signIn') {
    if (value.addFunctionCallKey !== undefined) throw new Error('Access key permissions are not supported by this login flow.')
    return payload as SupportedRequest
  }
  if (value.kind !== 'signAndSendTransaction') throw new Error('This wallet request is not supported.')
  if (typeof value.signerId !== 'string') throw new Error('The transaction must identify its signer.')
  assertAccountId(value.signerId)
  if (accountId && value.signerId !== accountId) throw new Error('This request belongs to a different wallet. Sign in with the requested account.')
  if (typeof value.receiverId !== 'string' || ![config.coreAccountId, config.tokenAccountId].includes(value.receiverId)) throw new Error('The transaction is not for this deployment.')
  if (!Array.isArray(value.actions) || value.actions.length === 0 || value.actions.length > 16) throw new Error('Invalid transaction actions.')
  let totalGas = 0n
  for (const action of value.actions) {
    if (!action || action.type !== 'FunctionCall' || !action.params) throw new Error('Only contract calls are supported.')
    const { methodName, gas, deposit, args } = action.params
    if (typeof methodName !== 'string' || !/^[a-zA-Z0-9_]{1,128}$/.test(methodName)) throw new Error('Invalid contract method.')
    if (typeof gas !== 'string' || !/^[1-9][0-9]{0,14}$/.test(gas)) throw new Error('Invalid transaction gas.')
    totalGas += BigInt(gas)
    if (typeof deposit !== 'string' || !/^(0|[1-9][0-9]{0,38})$/.test(deposit) || BigInt(deposit) >= 2n ** 128n) throw new Error('Invalid attached deposit.')
    if (!args || typeof args !== 'object' || Array.isArray(args) || Object.getPrototypeOf(args) !== Object.prototype) throw new Error('Contract arguments must be a JSON object.')
  }
  if (totalGas > 300_000_000_000_000n) throw new Error('Transaction gas exceeds the NEAR limit.')
  if (new TextEncoder().encode(JSON.stringify(payload)).length > 1_500_000) throw new Error('The wallet request is too large.')
  return payload as SupportedRequest
}

export function nearDeposit(yocto: string): string {
  const value = BigInt(yocto)
  const fraction = (value % 10n ** 24n).toString().padStart(24, '0').replace(/0+$/, '')
  return `${value / 10n ** 24n}${fraction ? `.${fraction}` : ''} NEAR`
}
