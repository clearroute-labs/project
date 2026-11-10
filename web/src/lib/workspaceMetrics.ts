import { formatAmount } from './money'
import type { DashboardSnapshot, DecryptedAuditView, Role } from './types'

export type WorkspaceMetric = { label: string; value: string; supporting: string; tone?: 'default' | 'positive' | 'warning' }
export const metricLabels: Record<Role, string[]> = {
 lender: ['Your position value', 'Your vault positions', 'Available claims', 'Pending payouts'],
 broker: ['Your broker debt', 'Unused debt ceiling', 'Active loans', 'Accounting to review'],
 borrower: ['Active agreements', 'Proposals to review', 'Next payment', 'Private balance'],
 auditor: ['Audit scope', 'Record in view', 'Decrypted fields', 'Last local reveal'],
}
const liveLoan = (status: string) => status === 'active' || status === 'impaired'

/** Dashboard loans/proposals combine borrower and broker records; split them before presenting a role. */
export function accountScope(snapshot: DashboardSnapshot, accountId: string) {
 const brokers = snapshot.brokers.filter(broker => broker.ownerId === accountId)
 const brokerIds = new Set(brokers.map(broker => broker.brokerId))
 const vaults = snapshot.vaults.filter(vault => vault.assetAccount === snapshot.asset.tokenAccount)
 return {
  vaults,
  positions: vaults.filter(vault => BigInt(vault.yourShares || '0') > 0n),
  claims: snapshot.claims.filter(claim => claim.ownerId === accountId && claim.assetAccount === snapshot.asset.tokenAccount),
  brokers,
  brokerLoans: snapshot.loans.filter(loan => brokerIds.has(loan.brokerId)),
  brokerProposals: snapshot.proposals.filter(proposal => brokerIds.has(proposal.brokerId)),
  borrowerLoans: snapshot.loans.filter(loan => loan.borrowerId === accountId),
  borrowerProposals: snapshot.proposals.filter(proposal => proposal.borrowerId === accountId),
  keeperGrants: snapshot.keeperGrants.filter(grant => brokerIds.has(grant.brokerId)),
 }
}

export function workspaceMetrics(role: Role, snapshot: DashboardSnapshot, accountId: string, symbol: string, now: number): WorkspaceMetric[] {
 const scope = accountScope(snapshot, accountId)
 const labels = metricLabels[role]
 const metric = (index: number, value: string, supporting: string, tone?: WorkspaceMetric['tone']): WorkspaceMetric => ({label:labels[index],value,supporting,tone})
 const money = (units: bigint) => `${formatAmount(units, snapshot.asset.decimals)} ${symbol}`
 if (role === 'lender') {
  const complete = scope.vaults.every(vault => vault.yourShares !== undefined)
  let valuation: bigint | undefined = complete ? 0n : undefined
  for (const vault of scope.positions) {
   const shares = BigInt(vault.yourShares!), supply = BigInt(vault.sharesSupply)
   const netAssets = BigInt(vault.assetsTotal) - BigInt(vault.lossUnrealized)
   if (vault.checkpointStatus !== 'current' || supply <= 0n || shares > supply || netAssets < 0n) { valuation = undefined; break }
   if (valuation !== undefined) valuation += shares * netAssets / supply
  }
  const available = scope.claims.filter(claim => claim.status === 'available' || claim.status === 'restored')
  // getDashboard(accountId) reads payouts with owner=accountId. Recipient is not the owner.
  const pending = snapshot.payouts.filter(payout => !['succeeded','failed'].includes(payout.status))
  return [
   metric(0,valuation === undefined ? 'Unavailable' : money(valuation),valuation === undefined ? 'Current accounting and share balances required' : 'Your share of net assets · indicative, not guaranteed',valuation === undefined ? 'warning' : undefined),
   metric(1,complete ? String(scope.positions.length) : '—',complete ? `Vaults where you hold ${symbol} shares` : 'Share balances incomplete'),
   metric(2,money(available.reduce((sum,claim)=>sum+BigInt(claim.amount),0n)),`${available.length} public receipt${available.length===1?'':'s'} ready to use`),
   metric(3,String(pending.length),pending.length ? 'Awaiting a final outcome or finalization' : 'No unresolved payouts',pending.length ? 'warning' : undefined),
  ]
 }
 if (role === 'broker') {
  const debt = scope.brokers.reduce((sum,broker)=>sum+BigInt(broker.debtTotal),0n)
  const capacity = scope.brokers.reduce((sum,broker)=>sum+(BigInt(broker.debtCeiling)>BigInt(broker.debtTotal)?BigInt(broker.debtCeiling)-BigInt(broker.debtTotal):0n),0n)
  const review = scope.brokers.filter(broker=>broker.checkpointStatus!=='current').length
  const proposals = scope.brokerProposals.filter(proposal=>proposal.expiresAt>now && ['pending','borrower_authorized','broker_authorized'].includes(proposal.status)).length
  return [
   metric(0,money(debt),`Across ${scope.brokers.length} broker account${scope.brokers.length===1?'':'s'} you own`),
   metric(1,money(capacity),'Public ceiling minus debt · not vault liquidity'),
   metric(2,String(scope.brokerLoans.filter(loan=>liveLoan(loan.status)).length),`${proposals} unexpired proposal${proposals===1?'':'s'} in your book`),
   metric(3,String(review),scope.brokers.length ? (review ? 'Broker accounts with pending, stale or unknown accounting' : 'Your broker accounts are current') : 'No broker accounts registered',review ? 'warning' : undefined),
  ]
 }
 if (role === 'borrower') {
  const active = scope.borrowerLoans.filter(loan=>liveLoan(loan.status))
  const review = scope.borrowerProposals.filter(proposal=>proposal.expiresAt>now && ['pending','broker_authorized'].includes(proposal.status) && !proposal.borrowerDirectAuthorized && !proposal.borrowerSignature)
  const scheduled = active.filter(loan=>loan.paymentRemaining>0 && loan.nextPaymentDue>0).sort((a,b)=>a.nextPaymentDue-b.nextPaymentDue)
  const next = scheduled[0]
  const pastDue = scheduled.filter(loan=>loan.nextPaymentDue<now).length
  return [
   metric(0,String(active.length),`${scope.borrowerLoans.filter(loan=>loan.status==='paid').length} paid · only agreements where you are the borrower`),
   metric(1,String(review.length),'Unexpired proposals awaiting your authorization',review.length ? 'warning' : undefined),
   metric(2,next ? new Date(next.nextPaymentDue*1000).toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric',timeZone:'UTC'}) : 'None scheduled',next ? `UTC · Loan ${next.loanId}${pastDue ? ` · ${pastDue} scheduled payment${pastDue===1?'':'s'} past due` : ''}` : 'No scheduled payment in your active agreements',pastDue ? 'warning' : undefined),
   metric(3,'Hidden','Encrypted · open Private balance to decrypt locally'),
  ]
 }
 return auditMetrics('loan', null)
}

/** Only a successfully decrypted result establishes an actual local audit view. */
export function auditMetrics(scope: 'loan' | 'token', view: DecryptedAuditView | null): WorkspaceMetric[] {
 return [
  {label:metricLabels.auditor[0],value:scope==='loan'?'Loan':'Token',supporting:'Selected view · access determined by your key'},
  {label:metricLabels.auditor[1],value:view?.subjectId || 'None',supporting:view ? 'Record successfully decrypted in this browser' : 'No authorized view revealed yet'},
  {label:metricLabels.auditor[2],value:view ? String(view.fields.length) : 'Locked',supporting:'Fields in the current result only'},
  {label:metricLabels.auditor[3],value:view ? new Date(view.decryptedAt).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'}) : '—',supporting:view ? `${new Date(view.decryptedAt).toLocaleDateString('en-GB',{timeZone:'UTC'})} · UTC` : 'Decrypt a record to begin'},
 ]
}

export function realizedPerformance(role: 'lender' | 'broker', snapshot: DashboardSnapshot, accountId: string) {
 const scoped = accountScope(snapshot, accountId)
 const records = role === 'lender' ? scoped.positions : scoped.brokers
 const incomplete = role === 'lender' && scoped.vaults.some(vault => vault.yourShares === undefined)
 const unavailable = incomplete || records.some(record => record.cumulativeYield === undefined || record.cumulativeRealizedLosses === undefined || (role === 'lender' && record.yieldStatus !== 'available'))
 if (unavailable) return { available: false as const, historyIncomplete: records.some(record => record.yieldStatus === 'history_incomplete') }
 const yieldUnits = records.reduce((sum,record)=>sum+BigInt(record.cumulativeYield!),0n)
 const lossUnits = records.reduce((sum,record)=>sum+BigInt(record.cumulativeRealizedLosses!),0n)
 return { available: true as const, yieldUnits, lossUnits, netUnits: yieldUnits-lossUnits }
}
