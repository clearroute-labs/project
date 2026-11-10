import type { Role } from './types'

export type WorkspaceRoute = { title: string; description: string; section: string; contentTitle: string; connection: string }
const overview: Record<Role, WorkspaceRoute> = {
  lender: {title:'Your capital, in view.',description:'A public view of your vaults. A clear next step.',section:'Overview',contentTitle:'Your vaults',connection:'Connect your wallet to read your vault positions, available claims and finalized accounting.'},
  broker: {title:'Credit, coordinated.',description:'A focused view of your book and what needs attention.',section:'Desk overview',contentTitle:'Your credit book',connection:'Connect your broker wallet to read accounts, proposals and the current loan book.'},
  borrower: {title:'Your next step, clear.',description:'Stay on top of agreements and upcoming payments.',section:'Home',contentTitle:'Your agreements',connection:'Connect your wallet to find your agreements and payment schedule. Private amounts stay encrypted.'},
  auditor: {title:'Access, with purpose.',description:'Review only the records your keys are authorized to read.',section:'Audit home',contentTitle:'Authorized audit views',connection:'Connect your wallet, then choose a loan or token subject covered by your local reader keys.'},
}
const routes: Record<string, WorkspaceRoute> = {
 '/lender/vaults': {title:'Find your vault.',description:'Review public accounting before you put capital to work.',section:'Vaults',contentTitle:'Available vaults',connection:'Connect your wallet to read vault liquidity, accounting and your share positions.'},
 '/lender/claims': {title:'Claims & payouts.',description:'Follow funds from your wallet to a vault, and back.',section:'Claims & payouts',contentTitle:'Your public receipts',connection:'Connect your wallet to find available claims and follow payout status. A claim is a public receipt for funds held by the protocol.'},
 '/broker/vaults': {title:'Vaults & brokers.',description:'Public capital and the credit desks that manage it.',section:'Vaults & brokers',contentTitle:'Vaults and broker accounts',connection:'Connect your wallet to read existing vaults, configure a vault or register a broker account.'},
 '/broker/loans': {title:'Your credit book.',description:'Proposals, active agreements and their next steps.',section:'Loan book',contentTitle:'Loans & proposals',connection:'Connect your broker wallet to review the loan book or draft an agreement. Proposals require authorization before origination.'},
 '/broker/operations': {title:'Keep the book current.',description:'Separate operational tasks from credit decisions.',section:'Operations',contentTitle:'Accounting workflow',connection:'Connect your broker wallet to read current versions before merging, reconciling or settling funds.'},
 '/borrower/agreements': {title:'Your agreements.',description:'Review terms, understand obligations, then authorize.',section:'Agreements',contentTitle:'Loans & proposals',connection:'Connect your wallet to find your agreements. Reviewing private terms also requires the matching encrypted package and authorized local keys.'},
 '/borrower/balance': {title:'Private by design.',description:'Your balance is encrypted. Reveal only what you need.',section:'Private balance',contentTitle:'Private balance',connection:'Connect your wallet to load the encrypted account. Only an authorized local key can reveal its balance.'},
 '/auditor/loans': {title:'A focused view of each loan.',description:'Select a loan, verify your reader scope, then decrypt locally.',section:'Loan exports',contentTitle:'Loan audit',connection:'Connect your wallet to select the loan covered by your audit key. Choosing the auditor workspace does not grant access.'},
 '/auditor/token': {title:'Trace the authorized view.',description:'Review token activity within your registered reader scope.',section:'Token audit',contentTitle:'Token audit',connection:'Connect your wallet to select a holder or broker and the authorized token reader scope.'},
 '/settings': {title:'Your wallet. Your keys.',description:'Keep access recoverable and private amounts protected.',section:'Wallet & security',contentTitle:'Private access setup',connection:'Connect your wallet before preparing local keys, saving an encrypted backup or restoring private access.'},
}
export function workspaceRoute(role: Role, path: string): WorkspaceRoute {return routes[path] || overview[role]}
export function isWorkspaceOverview(path: string): boolean {return path==='/' || /^\/(lender|broker|borrower|auditor)(\/overview)?$/.test(path)}
