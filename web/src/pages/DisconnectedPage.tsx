import { YieldSummary } from '../components/YieldSummary'
import { metricLabels } from '../lib/workspaceMetrics'
import { useAppContext } from '../App'
import { Button, Card, Metric, SectionHeading } from '../components/ui'
import { PrivacyAside } from '../components/PrivacyAside'
import { isWorkspaceOverview, workspaceRoute } from '../lib/workspaceRoutes'
import { ConnectWallet, PageHeader } from './shared'

const nextSteps = {
 lender:[{path:'/lender/vaults',title:'Explore vaults',description:'Review liquidity, shares and public accounting.'},{path:'/lender/claims',title:'Claims & payouts',description:'Fund a public receipt, then deposit or withdraw it.'}],
 broker:[{path:'/broker/loans',title:'Open the credit book',description:'Review agreements and prepare a proposal.'},{path:'/broker/operations',title:'Review operations',description:'Merge, reconcile and settle from current state.'}],
 borrower:[{path:'/borrower/agreements',title:'Review agreements',description:'Understand the terms before authorizing.'},{path:'/borrower/balance',title:'Open private balance',description:'Manage incoming funds and private transfers.'}],
 auditor:[{path:'/auditor/loans',title:'Review a loan',description:'Read only the fields your audit key authorizes.'},{path:'/auditor/token',title:'Review token activity',description:'Choose a holder or broker and reader scope.'}],
}


export function DisconnectedPage() {
 const {role,path,navigate}=useAppContext()
 const route=workspaceRoute(role,path)
 const overview=isWorkspaceOverview(path)
 const steps=path==='/settings' ? [
  ['1. Prepare device keys','Encryption and authorization keys are created locally.'],
  ['2. Save an encrypted backup','Keep a recovery file before registering or receiving private funds.'],
  ['3. Register & confirm','Wait for finalized registration before using private operations.'],
 ] : path==='/broker/operations' ? [
  ['1. Merge incoming funds','Collect pending credits before spending.'],
  ['2. Checkpoint the credit book','Reconcile an accounting snapshot before quoting current vault prices.'],
  ['3. Settle back to the vault','Repay public principal first; excess becomes realized yield.'],
 ] : path==='/lender/claims' ? [
  ['1. Fund a claim','Transfer tokens from your wallet to create a public receipt.'],
  ['2. Deposit or withdraw','Use an available claim once. Its amount must match the deposit.'],
  ['3. Follow finality','A pending payout must be checked before retrying.'],
 ] : path==='/borrower/balance' ? [
  ['1. Unlock locally','Your authorized decryption key reveals the encrypted balance.'],
  ['2. Merge incoming funds','Pending credits must be merged before they can be spent.'],
  ['3. Review the destination','Transfers and repayments require current state and a local proof.'],
 ] : null
 return <>
  <PageHeader title={route.title} description={route.description}/>
  {overview ? <section className="metrics-grid" aria-label="Wallet required to read account values">{metricLabels[role].map(label=><Metric key={label} label={label} value={label==='Private balance'?'Hidden':'—'} supporting="Connect to view"/>)}</section>:null}
  <div className="workspace-overview"><div className="workspace-stack">
   {overview && (role==='lender' || role==='broker') ? <YieldSummary /> : null}
   <Card className="connection-panel"><SectionHeading title={route.contentTitle}/><ConnectWallet compact description={route.connection}/></Card>
   {steps ? <Card className="journey-panel"><SectionHeading title={path==='/settings'?'Keep access recoverable':path==='/broker/operations'?'The accounting sequence':'Before you begin'}/>{steps.map(([title,description])=><div className="journey-row" key={title}><h3>{title}</h3><p>{description}</p></div>)}</Card>:null}
   <Card className="next-step-panel"><SectionHeading title={overview?'Your next steps':'Continue exploring'}/>{nextSteps[role].filter(step=>step.path!==path).map(step=><div className="workspace-action-row" key={step.path}><div><h3>{step.title}</h3><p>{step.description}</p></div><Button variant="quiet" onClick={()=>navigate(step.path)} aria-label={step.title}>Open <span aria-hidden="true">↗</span></Button></div>)}{path!=='/settings'?<div className="workspace-action-row"><div><h3>Review your security setup</h3><p>Back up keys before using private features.</p></div><Button variant="quiet" onClick={()=>navigate('/settings')} aria-label="Review your security setup">Review <span aria-hidden="true">↗</span></Button></div>:null}</Card>
  </div><PrivacyAside/></div>
 </>
}
