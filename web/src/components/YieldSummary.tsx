import { useAppContext } from '../App'
import { realizedPerformance } from '../lib/workspaceMetrics'
import { formatAmount } from '../lib/money'
import { Card, SectionHeading } from './ui'

export function YieldSummary() {
 const { role, snapshot, accountId, adapters } = useAppContext()
 if (role !== 'lender' && role !== 'broker') return null
 const performance = snapshot && accountId ? realizedPerformance(role, snapshot, accountId) : null
 const symbol = adapters.protocol.config.assetSymbol || snapshot?.asset?.tokenAccount || ''
 const money = (units: bigint) => `${units < 0n ? '−' : ''}${formatAmount(units < 0n ? -units : units, snapshot!.asset.decimals)} ${symbol}`
 const placeholder = performance ? 'Unavailable' : '—'
 return <Card className="yield-summary"><SectionHeading title="Realized yield" description={role==='lender' ? 'Lifetime vault totals for your current positions · not your personal profit' : 'Lifetime counters of the broker accounts you currently own'} />
  <dl className="yield-metrics">
   <div><dt>Yield settled to vaults</dt><dd>{performance?.available ? money(performance.yieldUnits) : placeholder}</dd></div>
   <div><dt>Realized losses</dt><dd>{performance?.available ? money(performance.lossUnits) : placeholder}</dd></div>
   <div><dt>Net realized result</dt><dd className={performance?.available && performance.netUnits < 0n ? 'yield-negative' : undefined}>{performance?.available ? money(performance.netUnits) : placeholder}</dd></div>
  </dl>
  <p className="field-hint">{!performance ? 'Connect your wallet to read finalized yield counters. ' : !performance.available ? (performance.historyIncomplete ? 'A closed broker has no historical counters in the current contract view. The incomplete total is not quoted. ' : 'Complete finalized yield counters could not be read. ') : ''}Yield is recognized only after settlement repays broker principal. Net result excludes current unrealized provisions. No annualized rate is inferred.</p>
  {role==='lender' ? <p className="field-hint yield-footnote">Yield accrues to vault assets and share value. Your personal return and APY require deposit, withdrawal and share-transfer history, which this view does not provide.</p> : <p className="field-hint yield-footnote">Closed broker accounts are excluded. These amounts were credited to vaults; they are not broker fees or personal earnings.</p>}
 </Card>
}
