import { YieldSummary } from '../components/YieldSummary'
import { WorkspaceMetrics } from '../components/WorkspaceMetrics'
import { accountScope } from '../lib/workspaceMetrics'
import { PrivacyAside } from '../components/PrivacyAside'
import { ActionPanel } from '../components/ActionPanel'
import { ReviewForm } from '../components/ReviewForm'
import { useEffect, useMemo, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, EmptyState, Field, Mono, Notice, SectionHeading, SelectInput, StatusBadge, Table, TextInput } from '../components/ui'
import { useAction } from '../lib/actionState'
import { readBrokerZeroProof, type BrokerZeroProofPackage } from '../lib/brokerZeroProof'
import { MAX_U128_UNITS, parseAmount, parseNonNegativeAmount, randomUint64Decimal, sharesForAssets, unixSecondsNow } from '../lib/money'
import type { PayoutSummary, PublicClaim, VaultSummary } from '../lib/types'
import { AmountCell, ConnectionGate, EmptyRow, IdLabel, PageHeader, StateFreshness, VaultPolicyNotice } from './shared'

export function LenderPage() {
  const context = useAppContext()
  return <ConnectionGate><LenderWorkspace /></ConnectionGate>
}

function LenderWorkspace() {
  const { path, snapshot, navigate, refresh } = useAppContext()
  if (!snapshot) return null
  if (path.startsWith('/lender/claims')) return <ClaimsPage />
  if (path.startsWith('/lender/vaults')) return <VaultsPage />
  return <LenderOverview onOpenVaults={() => navigate('/lender/vaults')} onOpenClaims={() => navigate('/lender/claims')} onRefresh={refresh} />
}

function LenderOverview({ onOpenVaults, onOpenClaims, onRefresh }: { onOpenVaults: () => void; onOpenClaims: () => void; onRefresh: () => Promise<void> }) {
  const { snapshot, accountId } = useAppContext()
  if (!snapshot) return null
  const { positions, claims } = accountScope(snapshot, accountId!)
  const hasData = positions.length > 0 || claims.length > 0 || snapshot.payouts.length > 0
  return <>
    <PageHeader title="Overview" action={<Button variant="secondary" onClick={() => void onRefresh()}>Refresh state</Button>} />
    <WorkspaceMetrics />
    <div className="workspace-overview"><div className="workspace-stack"><YieldSummary />{!hasData ? <Card><EmptyState icon="▥" title="No vault positions yet" description="Deposit into a vault to get started." action={<Button variant="secondary" onClick={onOpenVaults}>Open vaults</Button>} /></Card> : <div className="dashboard-grid"><Card><SectionHeading title="Your vault positions" action={<Button variant="quiet" onClick={onOpenVaults}>View all →</Button>} /><VaultTable vaults={positions.slice(0, 4)} decimals={snapshot.asset.decimals} /></Card><Card><SectionHeading title="Claims & payouts" action={<Button variant="quiet" onClick={onOpenClaims}>Review →</Button>} /><ClaimsSummary claims={claims} payouts={snapshot.payouts} decimals={snapshot.asset.decimals} /></Card></div>}</div><PrivacyAside /></div>
  </>
}

function VaultsPage() {
  const { snapshot, navigate } = useAppContext()
  const [selectedVaultId, setSelectedVaultId] = useState('')
  if (!snapshot) return null
  return <>
    <PageHeader title="Vaults & share positions" action={<Button variant="quiet" onClick={() => navigate('/')}>← Overview</Button>} />

    <Card><SectionHeading title="Available vaults" description="Vault amounts and shares are public. A checkpoint reconciles the loan book with vault accounting; pricing may pause until it finishes." /><VaultTable vaults={snapshot.vaults} decimals={snapshot.asset.decimals} onSelect={(vault) => setSelectedVaultId(vault.vaultId)} selectedVaultId={selectedVaultId} /></Card>
    <div className="capital-actions-heading"><h2>Manage your capital</h2><p className="muted">Start by funding a public receipt, then deposit it into a vault.</p></div><div className="two-column-grid"><TokenDepositCard decimals={snapshot.asset.decimals} /><DepositCard claims={snapshot.claims} vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} /><RedeemCard vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} /></div><ShareTransferCard vaults={snapshot.vaults} decimals={snapshot.asset.decimals} selectedVaultId={selectedVaultId} />
  </>
}

function DepositCard({ claims, vaults, decimals, selectedVaultId }: { claims: PublicClaim[]; vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  useEffect(() => { if (selectedVaultId) setVaultId(selectedVaultId) }, [selectedVaultId])
  const [claimId, setClaimId] = useState('')
  const [amount, setAmount] = useState('')
  const [minShares, setMinShares] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const selectedVault = vaults.find((item) => item.vaultId === vaultId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    const vault = vaults.find((item) => item.vaultId === vaultId)
    if (!vault) return setError('Choose a vault.')
    if (!claims.some((claim) => claim.claimId === claimId && ['available', 'restored'].includes(claim.status))) return setError('Choose an available public claim. Fund one below if no claim is listed.')
    try {
      const amountUnits = parseAmount(amount, decimals)
      const minSharesUnits = parseNonNegativeAmount(minShares || '0', vault.shareScale ?? decimals, MAX_U128_UNITS)
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
  return <ActionPanel className="form-card" title="Deposit claim into a vault" description="A claim is a public receipt for funds held by the protocol. Fund one first, then exchange it for vault shares. Both amounts are public; shares can lose value."><VaultPolicyNotice vault={selectedVault} /><ReviewForm onSubmit={submit} className="form-stack"><Field label="Public claim" htmlFor="deposit-claim"><SelectInput id="deposit-claim" value={claimId} onChange={(event) => setClaimId(event.target.value)}><option value="">Select available claim</option>{claims.filter((claim) => ['available', 'restored'].includes(claim.status)).map((claim) => <option key={claim.claimId} value={claim.claimId}>{claim.claimId} · {claim.status}</option>)}</SelectInput></Field><Field label="Vault" htmlFor="deposit-vault"><SelectInput id="deposit-vault" value={vaultId} onChange={(event) => setVaultId(event.target.value)}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label={`Claim amount (${decimals} decimals)`} htmlFor="deposit-amount" hint="Public amount: visible on-chain. Must match the selected receipt (claim)."><TextInput id="deposit-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field><Field label="Minimum shares" htmlFor="deposit-min-shares" hint="Minimum shares you accept. Enter a share quantity; 0 removes this minimum."><TextInput id="deposit-min-shares" inputMode="decimal" value={minShares} onChange={(event) => setMinShares(event.target.value)} placeholder="0" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!vaults.length || !claims.some((claim) => ['available', 'restored'].includes(claim.status))} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Deposit claim</Button><ActionFeedback state={action.state} /></ReviewForm></ActionPanel>
}

function ShareTransferCard({ vaults, decimals, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  useEffect(() => { if (selectedVaultId) setVaultId(selectedVaultId) }, [selectedVaultId])
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
      const shareUnits = parseAmount(shares, vault.shareScale ?? decimals, MAX_U128_UNITS)
      const receipt = await action.run('Transfer vault shares', () => adapters.protocol.transferShares({ vaultId, receiverId: receiver.trim(), shares: shareUnits }))
      if (receipt) { setShares(''); void refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Share transfer could not be prepared.') }
  }
  return <ActionPanel className="form-card" title="Transfer shares" description="Share transfers are public and available only when the vault's immutable policy permits them. No private loan values are involved."><ReviewForm onSubmit={submit} className="form-stack"><Field label="Vault" htmlFor="share-transfer-vault"><SelectInput id="share-transfer-vault" value={vaultId} onChange={(event) => setVaultId(event.target.value)}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label="Receiving account" htmlFor="share-transfer-receiver"><TextInput id="share-transfer-receiver" value={receiver} onChange={(event) => setReceiver(event.target.value)} placeholder="receiver.testnet" /></Field><Field label="Shares" htmlFor="share-transfer-shares"><TextInput id="share-transfer-shares" inputMode="decimal" value={shares} onChange={(event) => setShares(event.target.value)} placeholder="0" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!vaults.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Transfer shares</Button><ActionFeedback state={action.state} /></ReviewForm></ActionPanel>
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
  return <ActionPanel className="form-card" title="Fund a public claim" description="First transfer tokens from your wallet. The protocol issues a claim: a public receipt you can deposit into a vault or pay out."><ReviewForm onSubmit={submit} className="form-stack"><Field label={`Token amount (${decimals} decimals)`} htmlFor="token-deposit-amount"><TextInput id="token-deposit-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field><Field label="Deposit ID" htmlFor="token-deposit-id" hint="Leave blank for a new deposit. Reuse only to resume a pending deposit."><TextInput id="token-deposit-id" value={depositId} onChange={(event) => setDepositId(event.target.value)} placeholder="Generated securely if blank" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Send token & create claim</Button><ActionFeedback state={action.state} /></ReviewForm></ActionPanel>
}

function RedeemCard({ vaults, decimals, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; selectedVaultId: string }) {
  const { adapters, refresh } = useAppContext()
  const [vaultId, setVaultId] = useState(selectedVaultId)
  useEffect(() => { if (selectedVaultId) setVaultId(selectedVaultId) }, [selectedVaultId])
  const [mode, setMode] = useState<'shares' | 'assets'>('shares')
  const [shares, setShares] = useState('')
  const [assetsOut, setAssetsOut] = useState('')
  const [maxShares, setMaxShares] = useState('')
  const [minAmount, setMinAmount] = useState('')
  const [soleShareholderWaiver, setSoleShareholderWaiver] = useState(false)
  const [burnWorthless, setBurnWorthless] = useState(false)
  const [brokerProofs, setBrokerProofs] = useState<BrokerZeroProofPackage[]>([])
  const [error, setError] = useState('')
  const action = useAction()
  const importBrokerProofs = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || [])
    if (!files.length) return
    setError('')
    try {
      const imported = await Promise.all(files.map((file) => readBrokerZeroProof(file)))
      const merged = [...brokerProofs, ...imported]
      if (new Set(merged.map((item) => item.brokerId)).size !== merged.length) throw new Error('Each broker may contribute only one zero-state proof.')
      setBrokerProofs(merged)
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Broker zero-proof import failed.') }
    event.target.value = ''
  }
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    if (!vaults.some((vault) => vault.vaultId === vaultId)) return setError('Choose a vault.')
    try {
      const vault = vaults.find((item) => item.vaultId === vaultId)
      if (!vault) throw new Error('Choose a vault.')
      const shareUnits = mode === 'shares' ? parseAmount(shares, vault.shareScale ?? decimals, MAX_U128_UNITS) : ''
      const minAmountUnits = mode === 'shares' ? parseNonNegativeAmount(minAmount || '0', decimals) : ''
      const assetUnits = mode === 'assets' ? parseAmount(assetsOut, decimals) : ''
      const maxShareUnits = mode === 'assets' ? parseAmount(maxShares, vault.shareScale ?? decimals, MAX_U128_UNITS) : ''
      const pricedNav = BigInt(vault.assetsTotal) - (soleShareholderWaiver && vault.yourShares === vault.sharesSupply ? 0n : BigInt(vault.lossUnrealized))
      const requiredShares = mode === 'shares' ? shareUnits : sharesForAssets(assetUnits, vault.sharesSupply, pricedNav.toString())
      if (mode === 'assets' && BigInt(requiredShares) > BigInt(maxShareUnits)) throw new Error('The requested amount exceeds the maximum share spend.')
      const finalRedemption = requiredShares === vault.sharesSupply
      let finalProofs: import('../lib/types').PreparedProof[] | undefined
      if (finalRedemption) {
        const brokerIds = await adapters.protocol.getVaultClosureBrokerIds(vaultId)
        if (brokerProofs.length !== brokerIds.length) throw new Error(`Final redemption requires one current zero-state proof for each associated broker (${brokerIds.length} required).`)
        const expectedProfile = adapters.protocol.config.cryptoProfileHash.toLowerCase()
        const expectedArtifact = adapters.protocol.config.cryptoArtifactHash?.toLowerCase()
        const byBroker = new Map(brokerProofs.map((item) => [item.brokerId, item]))
        for (const brokerId of brokerIds) {
          const packageValue = byBroker.get(brokerId)
          if (!packageValue) throw new Error(`Missing zero-state proof for broker ${brokerId}.`)
          if (packageValue.vaultId !== vaultId) throw new Error(`Broker ${brokerId} proof belongs to a different vault.`)
          if (packageValue.profileHash !== expectedProfile) throw new Error(`Broker ${brokerId} proof uses a different crypto profile.`)
          if (expectedArtifact && packageValue.artifactHash !== expectedArtifact) throw new Error(`Broker ${brokerId} proof uses a different artifact manifest.`)
        }
        finalProofs = brokerIds.map((brokerId) => byBroker.get(brokerId)!.proof)
      }
      const receipt = await action.run(mode === 'shares' ? 'Redeem shares' : 'Redeem asset amount', () => mode === 'shares'
        ? adapters.protocol.redeemShares({ vaultId, shares: shareUnits, minAmount: minAmountUnits, expiresAt: unixSecondsNow() + 900, soleShareholderWaiver, burnWorthless, brokerZeroProofs: finalProofs })
        : adapters.protocol.redeemAmount({ vaultId, assetsOut: assetUnits, maxSharesIn: maxShareUnits, expiresAt: unixSecondsNow() + 900, soleShareholderWaiver, brokerZeroProofs: finalProofs }))
      if (receipt) {
        setShares('')
        setAssetsOut('')
        setMaxShares('')
        setMinAmount('')
        setBrokerProofs([])
        void refresh()
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Enter a valid share amount.')
    }
  }
  return <ActionPanel className="form-card" title="Redeem from a vault" description="Exchange shares for a public receipt (claim), then withdraw it in Claims & payouts. Both the share quantity and redemption amount are public."><ReviewForm onSubmit={submit} className="form-stack"><Field label="Vault" htmlFor="redeem-vault"><SelectInput id="redeem-vault" value={vaultId} onChange={(event) => { setVaultId(event.target.value); setBrokerProofs([]) }}><option value="">Select a vault</option>{vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.phase}</option>)}</SelectInput></Field><Field label="Redemption mode" htmlFor="redeem-mode"><SelectInput id="redeem-mode" value={mode} onChange={(event) => { setMode(event.target.value as typeof mode); setBrokerProofs([]) }}><option value="shares">Exact shares</option><option value="assets">Exact asset amount</option></SelectInput></Field>{mode === 'shares' ? <><Field label="Shares" htmlFor="redeem-shares"><TextInput id="redeem-shares" inputMode="decimal" value={shares} onChange={(event) => setShares(event.target.value)} placeholder="0" /></Field><Field label="Minimum claim" htmlFor="redeem-min-amount" hint="Slippage guard, in asset units."><TextInput id="redeem-min-amount" inputMode="decimal" value={minAmount} onChange={(event) => setMinAmount(event.target.value)} placeholder="0" /></Field></> : <><Field label={`Asset amount (${decimals} decimals)`} htmlFor="redeem-assets-out"><TextInput id="redeem-assets-out" inputMode="decimal" value={assetsOut} onChange={(event) => setAssetsOut(event.target.value)} placeholder="0.00" /></Field><Field label="Maximum shares in" htmlFor="redeem-max-shares" hint="Maximum shares you agree to spend."><TextInput id="redeem-max-shares" inputMode="decimal" value={maxShares} onChange={(event) => setMaxShares(event.target.value)} placeholder="0" /></Field></>}<label className="checkbox-field"><input type="checkbox" checked={soleShareholderWaiver} onChange={(event) => setSoleShareholderWaiver(event.target.checked)} /> <span>Last-shareholder waiver (only if Core allows)</span></label>{mode === 'shares' ? <label className="checkbox-field"><input type="checkbox" checked={burnWorthless} onChange={(event) => setBurnWorthless(event.target.checked)} /> <span>Burn worthless zero-NAV shares (exact-share mode only)</span></label> : null}<Field label="Broker closure packages" hint="Required for final redemption. Request closure packages from each broker owner."><input className="file-input" type="file" accept="application/json,.json" multiple onChange={(event) => void importBrokerProofs(event)} />{brokerProofs.length ? <div className="readonly-field"><span>Imported closure packages</span>{brokerProofs.map((item) => <Mono key={item.brokerId}>broker {item.brokerId} · vault {item.vaultId}</Mono>)}</div> : <span className="field-hint">No closure packages imported. Partial redemptions do not require them.</span>}</Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!vaults.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>{mode === 'shares' ? 'Redeem shares' : 'Redeem asset amount'}</Button><ActionFeedback state={action.state} /></ReviewForm></ActionPanel>
}

function ClaimsPage() {
  const { snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  return <><PageHeader title="Claims & payouts" action={<Button variant="quiet" onClick={() => navigate('/')}>← Overview</Button>} /><Notice tone="warning" title="Pending payouts">Wait for a confirmed result before retrying a payout. A timeout does not mean it failed.</Notice><Card><SectionHeading title="Withdrawable claims" /><ClaimsTable claims={snapshot.claims} decimals={snapshot.asset.decimals} /></Card><div className="two-column-grid"><RequestPayoutCard claims={snapshot.claims} /><PayoutStatusCard payouts={snapshot.payouts} decimals={snapshot.asset.decimals} /></div></>
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
  return <ActionPanel className="form-card" title="Request payout" description="The payout amount and recipient are public. The recipient cannot be changed after submission."><ReviewForm onSubmit={submit} className="form-stack"><Field label="Claim" htmlFor="payout-claim"><SelectInput id="payout-claim" value={claimId} onChange={(event) => setClaimId(event.target.value)}><option value="">Select a claim</option>{availableClaims.map((claim) => <option key={claim.claimId} value={claim.claimId}>{claim.claimId} · {claim.status}</option>)}</SelectInput></Field><Field label="Recipient account" htmlFor="payout-recipient"><TextInput id="payout-recipient" value={recipient} onChange={(event) => setRecipient(event.target.value)} placeholder="recipient.testnet" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!availableClaims.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Reserve payout</Button><ActionFeedback state={action.state} /></ReviewForm></ActionPanel>
}

function PayoutStatusCard({ payouts, decimals }: { payouts: PayoutSummary[]; decimals: number }) {
  return <Card><SectionHeading title="Payout status" description="Finalize a payout once its result is confirmed." />{payouts.length ? <div className="operation-list">{payouts.map((payout) => <PayoutOperationRow key={payout.operationId} payout={payout} decimals={decimals} />)}</div> : <EmptyState title="No payout operations" />}</Card>
}

function PayoutOperationRow({ payout, decimals }: { payout: PayoutSummary; decimals: number }) {
  const { adapters, refresh } = useAppContext()
  const action = useAction()
  const finalizable = payout.status === 'result_recorded_success' || payout.status === 'result_recorded_failure'
  const finalize = async () => {
    const receipt = await action.run('Finalize payout', () => adapters.protocol.finalizePayout({ operationId: payout.operationId }))
    if (receipt) void refresh()
  }
  const tone = payout.status === 'succeeded' || payout.status === 'result_recorded_success' ? 'success' : payout.status === 'failed' || payout.status === 'result_recorded_failure' ? 'danger' : payout.status === 'unknown' ? 'warning' : 'neutral'
  const statusLabel = payout.status.replaceAll('_', ' ')
  return <div className="operation-row"><div><strong>{payout.operationId}</strong><p className="muted">Claim {payout.claimId} · attempt {payout.attempt}</p></div><div className="operation-meta"><AmountCell units={payout.amount} decimals={decimals} /><StatusBadge tone={tone}>{statusLabel}</StatusBadge>{finalizable ? <Button type="button" variant="secondary" onClick={() => void finalize()} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Finalize payout</Button> : payout.status === 'unknown' || payout.status === 'requested' || payout.status === 'in_flight' ? <small className="field-hint">Locked until Core records the token result.</small> : null}<ActionFeedback state={action.state} /></div></div>
}

function VaultTable({ vaults, decimals, onSelect, selectedVaultId }: { vaults: VaultSummary[]; decimals: number; onSelect?: (vault: VaultSummary) => void; selectedVaultId?: string }) {
  return <Table caption="Public vault positions"><thead><tr><th scope="col">Vault</th><th scope="col">Phase</th><th scope="col">Gross assets</th><th scope="col">Provision</th><th scope="col">NAV</th><th scope="col">Available</th><th scope="col">Your shares</th><th scope="col">Accounting</th></tr></thead><tbody>{vaults.length ? vaults.map((vault) => <tr key={vault.vaultId} className={selectedVaultId === vault.vaultId ? 'row-selected' : ''} onClick={() => onSelect?.(vault)} tabIndex={onSelect ? 0 : undefined} onKeyDown={(event) => { if (event.key === 'Enter') onSelect?.(vault) }}><td><Mono>{vault.vaultId}</Mono><small>{vault.assetAccount}</small></td><td><StatusBadge tone={vault.phase === 'open' ? 'success' : vault.phase === 'closed' ? 'danger' : 'warning'}>{vault.phase.replace('_', ' ')}</StatusBadge></td><td><AmountCell units={vault.assetsTotal} decimals={decimals} /></td><td><AmountCell units={vault.lossUnrealized} decimals={decimals} /></td><td><AmountCell units={(BigInt(vault.assetsTotal) - BigInt(vault.lossUnrealized)).toString()} decimals={decimals} /></td><td><AmountCell units={vault.assetsAvailable} decimals={decimals} /></td><td><AmountCell units={vault.yourShares} decimals={vault.shareScale ?? decimals} /></td><td><StateFreshness status={vault.checkpointStatus} /><small>v{vault.accountingVersion}</small></td></tr>) : <EmptyRow message="No finalized vault records for this wallet." colSpan={8} />}</tbody></Table>
}

function ClaimsTable({ claims, decimals }: { claims: PublicClaim[]; decimals: number }) {
  return <Table caption="Public withdrawal claims"><thead><tr><th scope="col">Claim</th><th scope="col">Amount</th><th scope="col">Status</th><th scope="col">Payout operation</th></tr></thead><tbody>{claims.length ? claims.map((claim) => <tr key={claim.claimId}><td><Mono>{claim.claimId}</Mono></td><td><AmountCell units={claim.amount} decimals={decimals} /></td><td><StatusBadge tone={claim.status === 'available' || claim.status === 'restored' ? 'success' : claim.status === 'reserved' || claim.status === 'pending' ? 'warning' : claim.status === 'paid' ? 'neutral' : 'danger'}>{claim.status.replace('_', ' ')}</StatusBadge></td><td>{claim.payoutOperationId ? <Mono>{claim.payoutOperationId}</Mono> : '—'}</td></tr>) : <EmptyRow message="No finalized public claims for this wallet." colSpan={4} />}</tbody></Table>
}

function ClaimsSummary({ claims, payouts, decimals }: { claims: PublicClaim[]; payouts: import('../lib/types').PayoutSummary[]; decimals: number }) {
  const claimTotal = useMemo(() => claims.filter((claim) => claim.status !== 'paid').reduce((total, claim) => total + BigInt(claim.amount), 0n).toString(), [claims])
  if (!claims.length && !payouts.length) return <EmptyState title="No exit activity" />
  return <div className="summary-list"><div className="summary-line"><span>Claimed value</span><strong><AmountCell units={claimTotal} decimals={decimals} /></strong></div><div className="summary-line"><span>Open operations</span><strong>{payouts.filter((payout) => !['succeeded', 'failed'].includes(payout.status)).length}</strong></div>{payouts.slice(0, 3).map((payout) => <div className="summary-line summary-muted" key={payout.operationId}><span><Mono>{payout.operationId}</Mono></span><StatusBadge tone={payout.status === 'unknown' ? 'warning' : 'neutral'}>{payout.status.replaceAll('_', ' ')}</StatusBadge></div>)}</div>
}
