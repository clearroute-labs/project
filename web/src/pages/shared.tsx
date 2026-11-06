import type { ReactNode } from 'react'
import { useAppContext } from '../App'
import { Button, Card, EmptyState, Mono, Notice, SectionHeading, StatusBadge } from '../components/ui'
import { formatAmount } from '../lib/money'
import type { ProtocolError, Role } from '../lib/types'

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action ? <div className="page-header-action">{action}</div> : null}</div>
}

export function ConnectionGate({ role, children }: { role: Role; children: ReactNode }) {
  const { accountId, adapters, loading, loadError, refresh } = useAppContext()
  if (!accountId || adapters.wallet.status !== 'connected') {
    return <><PageHeader eyebrow={role} title="Your workspace is ready" description="Connect a NEAR wallet to read finalized protocol state and authorize actions." /><Card><EmptyState icon="⌁" title="Wallet not connected" description="No balances or activity are shown until a real wallet session is active. This keeps disconnected demos honest." action={<Button onClick={() => void adapters.wallet.connect()}>Connect NEAR wallet</Button>} /></Card></>
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
