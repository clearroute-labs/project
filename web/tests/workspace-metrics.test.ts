import { describe, expect, it } from 'vitest'
import { accountScope, auditMetrics, realizedPerformance, workspaceMetrics } from '../src/lib/workspaceMetrics'
import type { AssetProfile, BrokerSummary, DashboardSnapshot, DecryptedAuditView, LoanSummary, ProposalSummary, PublicClaim, VaultSummary } from '../src/lib/types'
const account='alice.testnet'
const now=1_800_000_000
const snapshot=(overrides:Partial<DashboardSnapshot>={}):DashboardSnapshot=>({fetchedAt:now*1000,asset:{tokenAccount:'test.token',decimals:0} as AssetProfile,vaults:[],brokers:[],loans:[],proposals:[],claims:[],payouts:[],keeperGrants:[],...overrides})
const vault=(overrides:Partial<VaultSummary>={}):VaultSummary=>({vaultId:'1',ownerId:'manager.testnet',assetAccount:'test.token',phase:'open',decimals:0,assetsTotal:'1000',lossUnrealized:'100',assetsAvailable:'500',sharesSupply:'100',yourShares:'10',accountingVersion:'1',checkpointStatus:'current',...overrides})
const broker=(overrides:Partial<BrokerSummary>={}):BrokerSummary=>({brokerId:'1',ownerId:account,vaultId:'1',debtTotal:'60',debtCeiling:'100',spendingVersion:'1',privateBalanceKeyId:'1',checkpointStatus:'current',keeperCount:0,...overrides})
const loan=(overrides:Partial<LoanSummary>={}):LoanSummary=>({loanId:'1',brokerId:'1',borrowerId:account,status:'active',paymentRemaining:2,nextPaymentDue:now+86400,...overrides} as LoanSummary)
const proposal=(overrides:Partial<ProposalSummary>={}):ProposalSummary=>({proposalId:'1',brokerId:'1',borrowerId:account,status:'pending',expiresAt:now+86400,...overrides} as ProposalSummary)
const claim=(overrides:Partial<PublicClaim>={}):PublicClaim=>({claimId:'1',ownerId:account,assetAccount:'test.token',amount:'25',status:'available',...overrides})
const metrics=(role:'lender'|'broker'|'borrower',data:DashboardSnapshot)=>workspaceMetrics(role,data,account,'TEST',now)

describe('account-scoped workspace metrics',()=>{
 it('values only owned shares after provisions, not total protocol assets or unrelated assets',()=>{
  const result=metrics('lender',snapshot({vaults:[vault(),vault({vaultId:'2',yourShares:'0',assetsTotal:'999999'}),vault({vaultId:'3',assetAccount:'other.token',assetsTotal:'999999'})]}))
  expect(result[0].value).toBe('90 TEST')
  expect(result[1].value).toBe('1')
  expect(result[0].supporting).toContain('indicative')
 })
 it('uses integer pro-rata arithmetic beyond Number precision',()=>{
  const result=metrics('lender',snapshot({vaults:[vault({assetsTotal:'9007199254740993123456',lossUnrealized:'0',sharesSupply:'10',yourShares:'3'})]}))
  expect(result[0].value).toBe('2,702,159,776,422,297,937,036 TEST')
 })
 it.each([{checkpointStatus:'pending'},{checkpointStatus:'unknown'},{sharesSupply:'0'},{sharesSupply:'1'},{lossUnrealized:'2000'},{yourShares:undefined}] as Partial<VaultSummary>[])('does not quote an incomplete or invalid valuation: %j',overrides=>{
  const result=metrics('lender',snapshot({vaults:[vault(overrides)]}))
  expect(result[0].value).toBe('Unavailable')
 })
 it('excludes reserved, paid, foreign-owner and other-asset claims, but retains restored receipts',()=>{
  const result=metrics('lender',snapshot({claims:[claim(),claim({claimId:'2',status:'restored',amount:'10'}),claim({claimId:'3',status:'reserved'}),claim({claimId:'4',status:'paid'}),claim({claimId:'5',ownerId:'bob.testnet'}),claim({claimId:'6',assetAccount:'other.token'})]}))
  expect(result[2].value).toBe('35 TEST')
  expect(result[2].supporting).toContain('2 public receipts')
 })
 it('counts unresolved payouts, including recorded outcomes that still require finalization',()=>{
  const data=snapshot();data.payouts=['requested','in_flight','result_recorded_success','result_recorded_failure','unknown','succeeded','failed'].map((status,i)=>({operationId:String(i),claimId:String(i),recipientId:'other-recipient.testnet',amount:'1',status:status as DashboardSnapshot['payouts'][number]['status'],attempt:1,lastUpdatedAt:now}))
  expect(metrics('lender',data)[3].value).toBe('5')
 })
 it('separates the broker book from the same wallet’s personal borrowing and clamps each debt ceiling',()=>{
  const data=snapshot({brokers:[broker(),broker({brokerId:'2',ownerId:'bob.testnet',debtTotal:'900'}),broker({brokerId:'3',debtTotal:'120',checkpointStatus:'pending'})],loans:[loan(),loan({loanId:'2',brokerId:'2'}),loan({loanId:'3',brokerId:'3',borrowerId:'bob.testnet',status:'impaired'}),loan({loanId:'4',status:'paid'})],proposals:[proposal(),proposal({proposalId:'2',expiresAt:now}),proposal({proposalId:'3',brokerId:'2'})]})
  expect(metrics('broker',data).map(metric=>metric.value)).toEqual(['180 TEST','40 TEST','2','1'])
  expect(metrics('broker',data)[2].supporting).toBe('1 unexpired proposal in your book')
  expect(accountScope(data,account).brokerLoans).toHaveLength(3)
 })
 it('shows only the borrower’s agreements, excludes authorized/expired proposals and prioritizes the earliest unpaid schedule',()=>{
  const data=snapshot({loans:[loan(),loan({loanId:'2',nextPaymentDue:now-3600}),loan({loanId:'3',borrowerId:'bob.testnet',nextPaymentDue:now-7200}),loan({loanId:'4',status:'paid',nextPaymentDue:now-10000})],proposals:[proposal(),proposal({proposalId:'2',borrowerId:'bob.testnet'}),proposal({proposalId:'3',expiresAt:now}),proposal({proposalId:'4',status:'borrower_authorized'}),proposal({proposalId:'5',borrowerDirectAuthorized:true}),proposal({proposalId:'6',borrowerSignature:'authorized-signature'})]})
  const result=metrics('borrower',data)
  expect(result[0].value).toBe('2');expect(result[1].value).toBe('1')
  expect(result[2].supporting).toContain('Loan 2 · 1 scheduled payment past due')
  expect(result[2].tone).toBe('warning');expect(result[3].value).toBe('Hidden')
 })
 it('does not present empty broker accounting as verified current or invent payment dates',()=>{
  expect(metrics('broker',snapshot())[3].supporting).toBe('No broker accounts registered')
  expect(metrics('borrower',snapshot())[2].value).toBe('None scheduled')
  expect(metrics('lender',snapshot())[0].value).toBe('0 TEST')
 })
 it('scopes audit metrics to the explicitly decrypted result and clears all result metadata when locked',()=>{
  const view={subjectId:'holder.testnet',fields:[{label:'Balance',value:'private',unit:'TEST'}],decryptedAt:now*1000} as DecryptedAuditView
  expect(auditMetrics('token',view).slice(0,3).map(metric=>metric.value)).toEqual(['Token','holder.testnet','1'])
  expect(JSON.stringify(auditMetrics('token',view))).not.toContain('private')
  expect(auditMetrics('loan',null).map(metric=>metric.value)).toEqual(['Loan','None','Locked','—'])
 })
})

describe('realized yield display',()=>{
 it('shows gross yield and losses separately, including a negative net result',()=>{
  const data=snapshot({vaults:[vault({cumulativeYield:'100',cumulativeRealizedLosses:'120',yieldStatus:'available'}),vault({vaultId:'2',yourShares:'0',cumulativeYield:'9000',cumulativeRealizedLosses:'0',yieldStatus:'available'})]})
  expect(realizedPerformance('lender',data,account)).toEqual({available:true,yieldUnits:100n,lossUnits:120n,netUnits:-20n})
 })
 it('never prorates lifetime yield by current shares as though it were personal profit',()=>{
  const data=snapshot({vaults:[vault({yourShares:'1',cumulativeYield:'100',cumulativeRealizedLosses:'0',yieldStatus:'available'})]})
  expect(realizedPerformance('lender',data,account)).toEqual({available:true,yieldUnits:100n,lossUnits:0n,netUnits:100n})
 })
 it('does not replace missing or closed-broker history with zero',()=>{
  expect(realizedPerformance('lender',snapshot({vaults:[vault({yieldStatus:'history_incomplete'})]}),account)).toEqual({available:false,historyIncomplete:true})
  expect(realizedPerformance('broker',snapshot({brokers:[broker()]}),account).available).toBe(false)
 })
 it('uses only counters of broker accounts owned by the connected wallet',()=>{
  const data=snapshot({brokers:[broker({cumulativeYield:'20',cumulativeRealizedLosses:'3'}),broker({brokerId:'2',ownerId:'bob.testnet',cumulativeYield:'1000',cumulativeRealizedLosses:'0'})]})
  expect(realizedPerformance('broker',data,account)).toEqual({available:true,yieldUnits:20n,lossUnits:3n,netUnits:17n})
 })
})
