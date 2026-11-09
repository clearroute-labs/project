import { useState, type ReactNode } from 'react'
import { useAppContext } from '../App'
import { Button, Card, EmptyState, Mono, Notice, SectionHeading, StatusBadge } from '../components/ui'
import { formatAmount } from '../lib/money'
import type { ProtocolError, Role, VaultSummary } from '../lib/types'

export function PageHeader({ title, description, action }: { title: ReactNode; description?: string; action?: ReactNode }) {
  return <div className="page-header"><div><h1>{title}</h1>{description ? <p className="page-description">{description}</p> : null}</div>{action ? <div className="page-header-action">{action}</div> : null}</div>
}

export function ConnectWallet() {
  const { adapters } = useAppContext()
  const [connectionError, setConnectionError] = useState('')
  const connect = async () => {
    setConnectionError('')
    try { await adapters.wallet.connect() }
    catch (error) { setConnectionError(error instanceof Error ? error.message : 'Wallet connection failed.') }
  }
  return <section className="welcome" aria-label="Wallet connection">
      <Button disabled={adapters.wallet.status === 'connecting'} onClick={() => void connect()}>{adapters.wallet.status === 'connecting' ? 'Connecting…' : 'Connect wallet'}</Button>
      {connectionError ? <Notice tone="danger">{connectionError}</Notice> : null}
    </section>
}

export function ConnectionGate({ children }: { children: ReactNode }) {
  const { accountId, adapters, loading, loadError, refresh, snapshot } = useAppContext()
  if (!accountId || adapters.wallet.status !== 'connected') return <ConnectWallet />
  // Refresh keeps mounted forms, transaction feedback and local agreement packages.
  // An account switch clears the snapshot in App before its workspace can render.
  if (loading && !snapshot) return <LoadingState label="Reading finalized Core state…" />
  if (loadError) return <ErrorState error={loadError} onRetry={() => void refresh()} />
  return <>{children}</>
}

export function LoadingState({ label = 'Loading finalized state…' }: { label?: string }) {
  return <Card className="loading-card"><div className="loading-line"><span className="button-spinner" aria-hidden="true" /><span>{label}</span></div></Card>
}

export function ErrorState({ error, onRetry }: { error: ProtocolError; onRetry: () => void }) {
  return <Card><EmptyState icon="!" title="State could not be read" description={`${error.details.message} The latest finalized state could not be read. Check any pending transaction before retrying an action.`} action={<Button variant="secondary" onClick={onRetry}>Retry read</Button>} /><div className="diagnostic"><span>Category</span><Mono>{error.details.category}</Mono></div></Card>
}

export function VaultPolicyNotice({ vault }: { vault?: VaultSummary }) {
  if (!vault) return null
  return <details className="inline-details"><summary>Vault risks & disclosure</summary><p>Loans have no collateral or first-loss guarantee. Public timing and small cohorts can reveal amounts.</p><p>Checkpoint interval: {vault.checkpointEpochSeconds ? `${vault.checkpointEpochSeconds} seconds` : 'not reported'} · disclosure: {vault.checkpointDisclosurePolicy || 'not reported'}.</p></details>
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
