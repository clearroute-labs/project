import type { ReactNode } from 'react'
import { useAppContext } from '../App'
import { Button, Card, EmptyState, Mono, Notice, SectionHeading, StatusBadge } from '../components/ui'
import { formatAmount } from '../lib/money'
import type { AssetProfile, ProtocolError, Role, VaultSummary } from '../lib/types'

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action ? <div className="page-header-action">{action}</div> : null}</div>
}

export function ConnectionGate({ role, children }: { role: Role; children: ReactNode }) {
  const { accountId, adapters, loading, loadError, refresh } = useAppContext()
  if (!accountId || adapters.wallet.status !== 'connected') {
    return <><PageHeader eyebrow={role} title="Your workspace is ready" description="Connect a NEAR wallet to view finalized account state and authorize actions." /><Card><EmptyState icon="⌁" title="Connect your NEAR wallet" description="Connect a wallet to view balances, loans and activity." action={<Button onClick={() => void adapters.wallet.connect()}>Connect NEAR wallet</Button>} /></Card></>
  }
  if (loading) return <LoadingState label="Reading finalized Core state…" />
  if (loadError) return <ErrorState error={loadError} onRetry={() => void refresh()} />
  return <>{children}</>
}

export function LoadingState({ label = 'Loading finalized state…' }: { label?: string }) {
  return <Card className="loading-card"><div className="loading-line"><span className="button-spinner" aria-hidden="true" /><span>{label}</span></div></Card>
}

export function ErrorState({ error, onRetry }: { error: ProtocolError; onRetry: () => void }) {
  return <Card><EmptyState icon="!" title="State could not be read" description={`${error.details.message} No financial state was changed.`} action={<Button variant="secondary" onClick={onRetry}>Retry read</Button>} /><div className="diagnostic"><span>Category</span><Mono>{error.details.category}</Mono></div></Card>
}

export function PublicPrivateNotice({ children }: { children?: ReactNode }) {
  return <Notice tone="info" title="Public / private boundary">{children || 'IDs, status, versions, ciphertexts and public boundary amounts are visible on-chain. Loan terms, balances and repayment amounts remain encrypted until an authorized local key is used.'}</Notice>
}

export function AssetBoundary({ asset }: { asset: AssetProfile }) {
  return <Card className="asset-boundary"><SectionHeading eyebrow="Asset boundary" title="Configured public rail" /><div className="config-grid"><div><span>Token account</span><Mono>{asset.tokenAccount || 'Not configured'}</Mono></div><div><span>Controller</span><Mono>{asset.controllerAccount || 'Not reported'}</Mono></div><div><span>Trust policy</span><strong>{asset.tokenTrustPolicy || 'Not reported'}</strong></div><div><span>Authorization</span><strong>{asset.authorizationPolicy || 'Not reported'}</strong></div>{asset.freezePolicy ? <div><span>Freeze policy</span><strong>{asset.freezePolicy}</strong></div> : null}{asset.confidentialOutstanding !== undefined ? <div><span>Confidential outstanding</span><AmountCell units={asset.confidentialOutstanding} decimals={asset.decimals} /></div> : null}</div><p className="field-hint">Controller, token policy and boundary totals are public protocol declarations. A controller is not assumed to be the underlying issuer, and public timing or small cohorts can still reveal financial information by correlation.</p></Card>
}

export function VaultPolicyNotice({ vault }: { vault?: VaultSummary }) {
  if (!vault) return null
  return <Notice tone="info" title="Vault disclosure policy">Checkpoint cadence: {vault.checkpointEpochSeconds ? `${vault.checkpointEpochSeconds} seconds` : 'not reported'} · disclosure: {vault.checkpointDisclosurePolicy || 'not reported'}. Individual loan terms remain encrypted, but public timing and small cohorts can reveal amounts by correlation. No collateral or first-loss guarantee is implied by this view.</Notice>
}

export function StateFreshness({ status }: { status: 'current' | 'pending' | 'stale' | 'unknown' }) {
  const tone = status === 'current' ? 'success' : status === 'pending' ? 'warning' : status === 'stale' ? 'danger' : 'neutral'
  return <StatusBadge tone={tone}>{status === 'current' ? 'Current' : status === 'pending' ? 'Accounting pending' : status === 'stale' ? 'Stale — refresh required' : 'Freshness unknown'}</StatusBadge>
}

export function EmptyRow({ message, colSpan }: { message: string; colSpan: number }) {
  return <tr><td colSpan={colSpan} className="empty-row">{message}</td></tr>
}

export function AmountCell({ units, decimals, symbol = '' }: { units?: string; decimals: number; symbol?: string }) {
  return <span className="amount-cell">{symbol}{formatAmount(units, decimals)}</span>
}

export function RolePill({ role }: { role: Role }) {
  return <span className="role-pill"><span className="role-pill-dot" />{role}</span>
}

export function IdLabel({ label, value }: { label: string; value?: string }) {
  return <div className="id-label"><span>{label}</span>{value ? <Mono>{value}</Mono> : <span>—</span>}</div>
}

export function useSnapshot() {
  const context = useAppContext()
  return context.snapshot
}

export function SectionRule() {
  return <div className="section-rule" aria-hidden="true" />
}

export function ActionCard({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return <Card className="action-card"><SectionHeading title={title} description={description} />{children}</Card>
}
