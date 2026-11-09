import { useEffect, useState } from 'react'
import { useAppContext } from '../App'
import { useAction } from '../lib/actionState'
import { ActionFeedback, Button, Card, Money, Notice, SectionHeading } from './ui'

const STORAGE_TOP_UP = 10n ** 22n

export function TestnetFundsCard() {
  const { accountId, adapters } = useAppContext()
  const protocol = adapters.protocol
  const enabled = protocol.config.networkId === 'testnet' && protocol.config.testnetFaucet
  const [status, setStatus] = useState<{ balance: string; storageBalance: string; claimed: boolean }>()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const action = useAction()
  useEffect(() => {
    let active = true
    setStatus(undefined)
    setError('')
    if (!enabled || !accountId || !protocol.testTokenStatus) return
    setLoading(true)
    void protocol.testTokenStatus(accountId).then(next => { if (active) setStatus(next) }).catch(() => { if (active) setError('Test-token balances could not be read. Retry in a moment.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [accountId, enabled, protocol])
  if (!enabled) return null
  const refresh = async () => {
    if (!accountId || !protocol.testTokenStatus) return
    setLoading(true)
    try { setStatus(await protocol.testTokenStatus(accountId)); setError('') }
    catch { setError('Test-token balances could not be read. Retry in a moment.') }
    finally { setLoading(false) }
  }
  const register = async () => {
    if (!protocol.registerTestTokenStorage) return
    const receipt = await action.run('Register test-token storage', () => protocol.registerTestTokenStorage!())
    if (receipt?.status === 'succeeded') await refresh()
  }
  const claim = async () => {
    if (!protocol.claimTestTokens) return
    const receipt = await action.run('Claim test tokens', () => protocol.claimTestTokens!())
    if (receipt?.status === 'succeeded') await refresh()
  }
  const storageReady = status && BigInt(status.storageBalance) >= STORAGE_TOP_UP
  const busy = ['preparing', 'awaiting_wallet', 'submitted', 'pending'].includes(action.state.phase)
  return <Card className="configuration-card">
    <SectionHeading title="Get test funds" />
    <p className="muted">TEST has no monetary value. You need testnet NEAR for fees and storage.</p>
    <p><a href="https://docs.near.org/getting-started/faucet" target="_blank" rel="noreferrer">Get testnet NEAR</a></p>
    {status ? <p>Wallet balance: <Money units={status.balance} decimals={6} /> TEST{status.claimed ? ' · Faucet already claimed' : ''}</p> : null}
    {!accountId ? <p className="field-hint">Connect your testnet wallet to get started.</p> : null}
    {status && !status.claimed && !storageReady ? <p className="field-hint">First register token storage with a 0.01 testnet NEAR deposit, then claim TEST.</p> : null}
    <div className="review-actions">
      {!status?.claimed && !storageReady ? <Button variant="secondary" disabled={!accountId || !status || loading || busy} onClick={() => void register()}>Register token storage · 0.01 NEAR</Button> : null}
      <Button variant="secondary" disabled={!accountId || !status || !storageReady || status.claimed || loading || busy} onClick={() => void claim()}>Claim 1,000 TEST</Button>
      <Button variant="quiet" disabled={!accountId || loading || busy} onClick={() => void refresh()}>Refresh test funds</Button>
    </div>
    {error ? <Notice tone="warning">{error}</Notice> : null}
    <ActionFeedback state={action.state} />
  </Card>
}
