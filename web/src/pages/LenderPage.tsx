import { useMemo, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, EmptyState, Field, Metric, Mono, Money, Notice, SectionHeading, SelectInput, StatusBadge, Table, TextInput } from '../components/ui'
import { useAction } from '../lib/actionState'
import { parseAmount, parseNonNegativeAmount, randomUint64Decimal, unixSecondsNow } from '../lib/money'
import type { PublicClaim, VaultSummary } from '../lib/types'
import { AmountCell, ConnectionGate, EmptyRow, IdLabel, PageHeader, PublicPrivateNotice, StateFreshness } from './shared'

export function LenderPage() {
  const context = useAppContext()
  return <ConnectionGate role="lender"><LenderWorkspace /></ConnectionGate>
}

function LenderWorkspace() {
  const { path, snapshot, navigate, refresh } = useAppContext()
  if (!snapshot) return null
  if (path.startsWith('/lender/claims')) return <ClaimsPage />
  if (path.startsWith('/lender/vaults')) return <VaultsPage />
  return <LenderOverview onOpenVaults={() => navigate('/lender/vaults')} onOpenClaims={() => navigate('/lender/claims')} onRefresh={refresh} />
}

function LenderOverview({ onOpenVaults, onOpenClaims, onRefresh }: { onOpenVaults: () => void; onOpenClaims: () => void; onRefresh: () => Promise<void> }) {
  const { snapshot } = useAppContext()
  if (!snapshot) return null
  const assets = snapshot.vaults.reduce((total, vault) => total + BigInt(vault.assetsTotal), 0n).toString()
  const available = snapshot.vaults.reduce((total, vault) => total + BigInt(vault.assetsAvailable), 0n).toString()
  const shares = snapshot.vaults.reduce((total, vault) => total + BigInt(vault.yourShares || '0'), 0n).toString()
  const hasData = snapshot.vaults.length > 0 || snapshot.claims.length > 0 || snapshot.payouts.length > 0
  return <>
    <PageHeader eyebrow="Lender workspace" title="A measured view of your capital" description="Vault liquidity and shares are public protocol state. Loan-level cash flows stay encrypted and are never inferred from the dashboard." action={<Button variant="secondary" onClick={() => void onRefresh()}>Refresh state</Button>} />
    <PublicPrivateNotice>Vault assets, available liquidity, share supply and your share balance are public. Individual loan principal, owed amounts and repayment amounts are encrypted; a share is a claim under current accounting, not a guaranteed original price.</PublicPrivateNotice>
    <div className="metrics-grid">
      <Metric label="Vault assets" value={<Money units={assets} decimals={snapshot.asset.decimals} />} supporting={snapshot.asset.tokenAccount || 'Configured asset'} />
      <Metric label="Available liquidity" value={<Money units={available} decimals={snapshot.asset.decimals} />} supporting="Public and withdrawable at the vault" tone="positive" />
      <Metric label="Your shares" value={<Money units={shares} decimals={snapshot.asset.decimals} />} supporting="Across visible vaults" />
      <Metric label="Payout operations" value={String(snapshot.payouts.length)} supporting="Pending and finalized records" tone={snapshot.payouts.some((payout) => payout.status === 'unknown') ? 'warning' : 'default'} />
    </div>
    {!hasData ? <Card><EmptyState icon="▥" title="No vault positions yet" description="Once a real Core adapter returns finalized state, your vaults, shares and claims will appear here. Nothing is estimated while disconnected from protocol state." action={<Button variant="secondary" onClick={onOpenVaults}>Open vaults</Button>} /></Card> : <div className="dashboard-grid"><Card><SectionHeading eyebrow="Public positions" title="Vaults" action={<Button variant="quiet" onClick={onOpenVaults}>View all →</Button>} /><VaultTable vaults={snapshot.vaults.slice(0, 4)} decimals={snapshot.asset.decimals} /></Card><Card><SectionHeading eyebrow="Exit rail" title="Claims & payouts" action={<Button variant="quiet" onClick={onOpenClaims}>Review →</Button>} /><ClaimsSummary claims={snapshot.claims} payouts={snapshot.payouts} decimals={snapshot.asset.decimals} /></Card></div>}
  </>
}

function VaultsPage() {
  const { snapshot, navigate } = useAppContext()
  const [selectedVaultId, setSelectedVaultId] = useState('')
  if (!snapshot) return null
  return <>
    <PageHeader eyebrow="Lender workspace / vaults" title="Vaults & share positions" description="Deposits and redemptions update the public share ledger. External token payout is a separate recoverable operation." action={<Button variant="quiet" onClick={() => navigate('/')}>← Overview</Button>} />
    <PublicPrivateNotice />
    <Card><SectionHeading eyebrow="Public ledger" title="Available vaults" description="Share pricing uses the finalized vault accounting version. A pending checkpoint can pause pricing actions." /><VaultTable vaults={snapshot.vaults} decimals={snapshot.asset.decimals} onSelect={(vault) => setSelectedVaultId(vault.vaultId)} selectedVaultId={selectedVaultId} /></Card>
    <div className="two-column-grid"><DepositCard claims={snapshot.claims} vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} /><RedeemCard vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} /></div><ShareTransferCard vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} /><TokenDepositCard decimals={snapshot.asset.decimals} />
  </>
}

function DepositCard({ claims, vaults, decimals, selectedVaultId }: { claims: PublicClaim[]; vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  const [claimId, setClaimId] = useState('')
  const [amount, setAmount] = useState('')
  const [minShares, setMinShares] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    const vault = vaults.find((item) => item.vaultId === vaultId)
    if (!vault) return setError('Choose a vault.')
    if (!claims.some((claim) => claim.claimId === claimId && ['available', 'restored'].includes(claim.status))) return setError('Choose an available public claim. Fund one below if no claim is listed.')
    try {
      const amountUnits = parseAmount(amount, decimals)
      const minSharesUnits = parseNonNegativeAmount(minShares || '0', vault.shareScale ?? decimals)
      const receipt = await action.run('Deposit claim to vault', () => adapters.protocol.depositToVault({ claimId, vaultId, amount: amountUnits, minShares: minSharesUnits, expiresAt: unixSecondsNow() + 900 }))
      if (receipt) {
        setAmount('')
        setMinShares('')
        void refresh()
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Enter a valid amount.')
    }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Claim → shares" title="Deposit claim into a vault" description="A claim must already exist in Core. The token transfer and vault credit are separate asynchronous steps." /><form onSubmit={submit} className="form-stack"><Field label="Public claim" htmlFor="deposit-claim"><SelectInput id="deposit-claim" value={claimId} onChange={(event) => setClaimId(event.target.value)}><option value="">Select available claim</option>{claims.filter((claim) => ['available', 'restored'].includes(claim.status)).map((claim) => <option key={claim.claimId} value={claim.claimId}>{claim.claimId} · {claim.status}</option>)}</SelectInput></Field><Field label="Vault" htmlFor="deposit-vault"><SelectInput id="deposit-vault" value={vaultId} onChange={(event) => setVaultId(event.target.value)}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label={`Claim amount (${decimals} decimals)`} htmlFor="deposit-amount" hint="Must match the claim's authoritative amount; base-unit conversion is exact."><TextInput id="deposit-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field><Field label="Minimum shares" htmlFor="deposit-min-shares" hint="Slippage guard, in share base units."><TextInput id="deposit-min-shares" inputMode="decimal" value={minShares} onChange={(event) => setMinShares(event.target.value)} placeholder="0" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!vaults.length || !claims.some((claim) => ['available', 'restored'].includes(claim.status))} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Deposit claim</Button><ActionFeedback state={action.state} /></form></Card>
}

function ShareTransferCard({ vaults, decimals, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  const [receiver, setReceiver] = useState('')
  const [shares, setShares] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      const vault = vaults.find((item) => item.vaultId === vaultId)
      if (!vault) throw new Error('Choose a vault.')
      if (!receiver.trim()) throw new Error('Enter the receiving NEAR account.')
      const shareUnits = parseAmount(shares, vault.shareScale ?? decimals)
      const receipt = await action.run('Transfer vault shares', () => adapters.protocol.transferShares({ vaultId, receiverId: receiver.trim(), shares: shareUnits }))
      if (receipt) { setShares(''); void refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Share transfer could not be prepared.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Public share movement" title="Transfer shares" description="Share transfers are public and available only when the vault's immutable policy permits them. No private loan values are involved." /><form onSubmit={submit} className="form-stack"><Field label="Vault" htmlFor="share-transfer-vault"><SelectInput id="share-transfer-vault" value={vaultId} onChange={(event) => setVaultId(event.target.value)}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label="Receiving account" htmlFor="share-transfer-receiver"><TextInput id="share-transfer-receiver" value={receiver} onChange={(event) => setReceiver(event.target.value)} placeholder="receiver.testnet" /></Field><Field label="Shares" htmlFor="share-transfer-shares"><TextInput id="share-transfer-shares" inputMode="decimal" value={shares} onChange={(event) => setShares(event.target.value)} placeholder="0" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!vaults.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Transfer shares</Button><ActionFeedback state={action.state} /></form></Card>
}

function TokenDepositCard({ decimals }: { decimals: number }) {
  const { adapters, refresh } = useAppContext()
  const [amount, setAmount] = useState('')
  const [depositId, setDepositId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      const amountUnits = parseAmount(amount, decimals)
      const id = depositId.trim() || (typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : '')
      if (!id) throw new Error('This browser cannot create a secure deposit ID.')
      const receipt = await action.run('Fund public claim', () => adapters.protocol.depositExternal({ amount: amountUnits, depositId: id }))
      if (receipt) { setDepositId(id); void refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Token deposit could not be prepared.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="External NEP-141 ingress" title="Fund a public claim" description="The configured token calls Core.ft_on_transfer. A finalized callback creates exactly one claim; duplicates are refunded rather than credited twice." /><form onSubmit={submit} className="form-stack"><Field label={`Token amount (${decimals} decimals)`} htmlFor="token-deposit-amount"><TextInput id="token-deposit-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field><Field label="Deposit ID" htmlFor="token-deposit-id" hint="Reuse only to safely resume a known pending operation; Core tombstones duplicates."><TextInput id="token-deposit-id" value={depositId} onChange={(event) => setDepositId(event.target.value)} placeholder="Generated securely if blank" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Send token & create claim</Button><ActionFeedback state={action.state} /></form></Card>
}

function RedeemCard({ vaults, decimals, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  const [shares, setShares] = useState('')
  const [minAmount, setMinAmount] = useState('')
  const [soleShareholderWaiver, setSoleShareholderWaiver] = useState(false)
  const [burnWorthless, setBurnWorthless] = useState(false)
  const [error, setError] = useState('')
  const action = useAction()
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    if (!vaults.some((vault) => vault.vaultId === vaultId)) return setError('Choose a vault.')
    try {
      const vault = vaults.find((item) => item.vaultId === vaultId)
      const shareUnits = parseAmount(shares, vault?.shareScale ?? decimals)
      const minAmountUnits = parseNonNegativeAmount(minAmount || '0', decimals)
      const receipt = await action.run('Redeem shares', () => adapters.protocol.redeemShares({ vaultId, shares: shareUnits, minAmount: minAmountUnits, expiresAt: unixSecondsNow() + 900, soleShareholderWaiver, burnWorthless }))
      if (receipt) {
        setShares('')
        setMinAmount('')
        void refresh()
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Enter a valid share amount.')
    }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Share exit" title="Redeem shares" description="A successful redemption burns shares and creates a public claim. External payout is intentionally separate." /><form onSubmit={submit} className="form-stack"><Field label="Vault" htmlFor="redeem-vault"><SelectInput id="redeem-vault" value={vaultId} onChange={(event) => setVaultId(event.target.value)}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label="Shares" htmlFor="redeem-shares"><TextInput id="redeem-shares" inputMode="decimal" value={shares} onChange={(event) => setShares(event.target.value)} placeholder="0" /></Field><Field label="Minimum claim" htmlFor="redeem-min-amount" hint="Slippage guard, in asset units."><TextInput id="redeem-min-amount" inputMode="decimal" value={minAmount} onChange={(event) => setMinAmount(event.target.value)} placeholder="0" /></Field><label className="checkbox-field"><input type="checkbox" checked={soleShareholderWaiver} onChange={(event) => setSoleShareholderWaiver(event.target.checked)} /> <span>Last-shareholder waiver (only if Core allows)</span></label><label className="checkbox-field"><input type="checkbox" checked={burnWorthless} onChange={(event) => setBurnWorthless(event.target.checked)} /> <span>Burn worthless zero-NAV shares (explicit)</span></label>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!vaults.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Redeem shares</Button><ActionFeedback state={action.state} /></form></Card>
}

function ClaimsPage() {
  const { snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  return <><PageHeader eyebrow="Lender workspace / exit rail" title="Claims & payouts" description="A payout reservation is not a success signal. Unknown results remain locked until authenticated Core evidence is recorded." action={<Button variant="quiet" onClick={() => navigate('/')}>← Overview</Button>} /><Notice tone="warning" title="Payout liveness is explicit">A missing callback cannot be interpreted as failure. The Core keeps an unresolved operation locked; do not resubmit the same claim based on a timeout.</Notice><Card><SectionHeading eyebrow="Public claims" title="Withdrawable claims" /><ClaimsTable claims={snapshot.claims} decimals={snapshot.asset.decimals} /></Card><div className="two-column-grid"><RequestPayoutCard claims={snapshot.claims} /><PayoutStatusCard payouts={snapshot.payouts} decimals={snapshot.asset.decimals} /></div></>
}

function RequestPayoutCard({ claims }: { claims: PublicClaim[] }) {
  const { adapters, accountId, refresh } = useAppContext()
  const [claimId, setClaimId] = useState('')
  const [recipient, setRecipient] = useState(accountId || '')
  const [error, setError] = useState('')
  const action = useAction()
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    const claim = claims.find((item) => item.claimId === claimId)
    if (!claim) return setError('Choose an available claim.')
    if (!recipient.trim()) return setError('Enter the fixed NEAR recipient for this payout.')
    try {
      const operationId = randomUint64Decimal()
      await action.run('Request external payout', () => adapters.protocol.requestPayout({ claimId, operationId, recipientId: recipient.trim() }))
      void refresh()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Payout could not be prepared.')
    }
  }
  const availableClaims = claims.filter((claim) => claim.status === 'available' || claim.status === 'restored')
  return <Card className="form-card"><SectionHeading eyebrow="External token rail" title="Request payout" description="The recipient is bound to this operation. Finalization is permissionless only after an authenticated result is recorded." /><form onSubmit={submit} className="form-stack"><Field label="Claim" htmlFor="payout-claim"><SelectInput id="payout-claim" value={claimId} onChange={(event) => setClaimId(event.target.value)}><option value="">Select a claim</option>{availableClaims.map((claim) => <option key={claim.claimId} value={claim.claimId}>{claim.claimId} · {claim.status}</option>)}</SelectInput></Field><Field label="Recipient account" htmlFor="payout-recipient" hint="Public destination; never enter a secret here."><TextInput id="payout-recipient" value={recipient} onChange={(event) => setRecipient(event.target.value)} placeholder="recipient.testnet" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!availableClaims.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Reserve payout</Button><ActionFeedback state={action.state} /></form></Card>
}

function PayoutStatusCard({ payouts, decimals }: { payouts: import('../lib/types').PayoutSummary[]; decimals: number }) {
  return <Card><SectionHeading eyebrow="Operation monitor" title="Payout status" description="No result is inferred from RPC availability or wallet UI state." />{payouts.length ? <div className="operation-list">{payouts.slice(0, 6).map((payout) => <div className="operation-row" key={payout.operationId}><div><strong>{payout.operationId}</strong><p className="muted">Claim {payout.claimId} · attempt {payout.attempt}</p></div><div className="operation-meta"><AmountCell units={payout.amount} decimals={decimals} /><StatusBadge tone={payout.status === 'succeeded' ? 'success' : payout.status === 'failed' ? 'danger' : payout.status === 'unknown' ? 'warning' : 'neutral'}>{payout.status.replace('_', ' ')}</StatusBadge></div></div>)}</div> : <EmptyState title="No payout operations" description="Finalized payout reservations will appear here." />}</Card>
}

function VaultTable({ vaults, decimals, onSelect, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; onSelect?: (vault: VaultSummary) => void; selectedVaultId?: string }) {
  return <Table caption="Public vault positions"><thead><tr><th scope="col">Vault</th><th scope="col">Phase</th><th scope="col">Assets</th><th scope="col">Available</th><th scope="col">Your shares</th><th scope="col">Accounting</th></tr></thead><tbody>{vaults.length ? vaults.map((vault) => <tr key={vault.vaultId} className={selectedVaultId === vault.vaultId ? 'row-selected' : ''} onClick={() => onSelect?.(vault)} tabIndex={onSelect ? 0 : undefined} onKeyDown={(event) => { if (event.key === 'Enter') onSelect?.(vault) }}><td><Mono>{vault.vaultId}</Mono><small>{vault.assetAccount}</small></td><td><StatusBadge tone={vault.phase === 'open' ? 'success' : vault.phase === 'closed' ? 'danger' : 'warning'}>{vault.phase.replace('_', ' ')}</StatusBadge></td><td><AmountCell units={vault.assetsTotal} decimals={decimals} /></td><td><AmountCell units={vault.assetsAvailable} decimals={decimals} /></td><td><AmountCell units={vault.yourShares} decimals={vault.shareScale ?? decimals} /></td><td><StateFreshness status={vault.checkpointStatus} /><small>v{vault.accountingVersion}</small></td></tr>) : <EmptyRow message="No finalized vault records for this wallet." colSpan={6} />}</tbody></Table>
}

function ClaimsTable({ claims, decimals }: { claims: PublicClaim[]; decimals: number }) {
  return <Table caption="Public withdrawal claims"><thead><tr><th scope="col">Claim</th><th scope="col">Amount</th><th scope="col">Status</th><th scope="col">Payout operation</th></tr></thead><tbody>{claims.length ? claims.map((claim) => <tr key={claim.claimId}><td><Mono>{claim.claimId}</Mono></td><td><AmountCell units={claim.amount} decimals={decimals} /></td><td><StatusBadge tone={claim.status === 'available' || claim.status === 'restored' ? 'success' : claim.status === 'reserved' || claim.status === 'pending' ? 'warning' : claim.status === 'paid' ? 'neutral' : 'danger'}>{claim.status.replace('_', ' ')}</StatusBadge></td><td>{claim.payoutOperationId ? <Mono>{claim.payoutOperationId}</Mono> : '—'}</td></tr>) : <EmptyRow message="No finalized public claims for this wallet." colSpan={4} />}</tbody></Table>
}

function ClaimsSummary({ claims, payouts, decimals }: { claims: PublicClaim[]; payouts: import('../lib/types').PayoutSummary[]; decimals: number }) {
  const claimTotal = useMemo(() => claims.filter((claim) => claim.status !== 'paid').reduce((total, claim) => total + BigInt(claim.amount), 0n).toString(), [claims])
  if (!claims.length && !payouts.length) return <EmptyState title="No exit activity" description="Your finalized public claims and payout reservations will appear here." />
  return <div className="summary-list"><div className="summary-line"><span>Claimed value</span><strong><AmountCell units={claimTotal} decimals={decimals} /></strong></div><div className="summary-line"><span>Open operations</span><strong>{payouts.filter((payout) => !['succeeded', 'failed'].includes(payout.status)).length}</strong></div>{payouts.slice(0, 3).map((payout) => <div className="summary-line summary-muted" key={payout.operationId}><span><Mono>{payout.operationId}</Mono></span><StatusBadge tone={payout.status === 'unknown' ? 'warning' : 'neutral'}>{payout.status.replace('_', ' ')}</StatusBadge></div>)}</div>
}
