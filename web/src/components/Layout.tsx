import { useState, type ReactNode } from 'react'
import { Button, Mono, Notice, SelectInput, StatusBadge } from './ui'
import type { Role, WalletAdapter } from '../lib/types'

export interface NavItem {
  path: string
  label: string
  icon: string
}

const roleMeta: Record<Role, { label: string; description: string; nav: NavItem[] }> = {
  lender: {
    label: 'Lender',
    description: 'Liquidity & vault positions',
    nav: [
      { path: '/', label: 'Overview', icon: '◒' },
      { path: '/lender/vaults', label: 'Vaults', icon: '▥' },
      { path: '/lender/claims', label: 'Claims & payouts', icon: '↗' },
      { path: '/settings', label: 'Wallet & security', icon: '⚿' },
    ],
  },
  broker: {
    label: 'Broker',
    description: 'Origination & servicing',
    nav: [
      { path: '/', label: 'Desk overview', icon: '◒' },
      { path: '/broker/vaults', label: 'Vaults & brokers', icon: '▥' },
      { path: '/broker/loans', label: 'Loan book', icon: '▤' },
      { path: '/broker/operations', label: 'Operations', icon: '↻' },
      { path: '/settings', label: 'Wallet & security', icon: '⚿' },
    ],
  },
  borrower: {
    label: 'Borrower',
    description: 'Private credit workspace',
    nav: [
      { path: '/', label: 'Home', icon: '◒' },
      { path: '/borrower/agreements', label: 'Agreements', icon: '▤' },
      { path: '/borrower/balance', label: 'Private balance', icon: '◈' },
      { path: '/settings', label: 'Wallet & security', icon: '⚿' },
    ],
  },
  auditor: {
    label: 'Auditor',
    description: 'Scoped disclosure',
    nav: [
      { path: '/', label: 'Audit home', icon: '◒' },
      { path: '/auditor/loans', label: 'Loan exports', icon: '⇩' },
      { path: '/auditor/token', label: 'Token audit', icon: '⊙' },
      { path: '/settings', label: 'Wallet & security', icon: '⚿' },
    ],
  },
}

export function Layout({ role, path, onNavigate, onRoleChange, wallet, children, adapterReady, notice }: {
  role: Role
  path: string
  onNavigate: (path: string) => void
  onRoleChange: (role: Role) => void
  wallet: WalletAdapter
  children: ReactNode
  adapterReady: boolean
  notice?: string
}) {
  const meta = roleMeta[role]
  const [walletError, setWalletError] = useState('')
  const connect = async () => {
    setWalletError('')
    try { await wallet.connect() } catch (error) { setWalletError(error instanceof Error ? error.message : 'Wallet connection failed.') }
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="brand" onClick={() => onNavigate('/')} aria-label="Private Ledger home">
          <span className="brand-mark"><span /></span>
          <span><strong>private</strong><em>ledger</em></span>
        </button>
        <div className="sidebar-role">
          <p className="eyebrow">Workspace</p>
          <SelectInput aria-label="Active workspace" value={role} onChange={(event) => onRoleChange(event.target.value as Role)}>
            {(Object.keys(roleMeta) as Role[]).map((item) => <option key={item} value={item}>{roleMeta[item].label}</option>)}
          </SelectInput>
          <p className="role-description">{meta.description}</p>
        </div>
        <nav className="primary-nav" aria-label={`${meta.label} navigation`}>
          {meta.nav.map((item) => {
            const selected = item.path === '/' ? path === '/' : path.startsWith(item.path)
            return <button key={item.path} className={`nav-item ${selected ? 'nav-item-active' : ''}`} onClick={() => onNavigate(item.path)}><span className="nav-icon" aria-hidden="true">{item.icon}</span>{item.label}</button>
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="security-note"><span className="lock-mark">⌁</span><div><strong>Private by design</strong><p>Amounts stay encrypted; proofs bind every state change.</p></div></div>
          <p className="sidebar-version">Protocol UI · profile-aware</p>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <div className="mobile-brand"><span className="brand-mark"><span /></span><strong>private ledger</strong></div>
          <div className="topbar-context"><span className="topbar-dot" />{meta.label} workspace<span className="slash">/</span><span className="muted">NEAR {wallet.networkId || 'testnet'}</span></div>
          <div className="topbar-actions">
            <StatusBadge tone={adapterReady ? 'success' : 'warning'}>{adapterReady ? 'Ready' : 'Disconnected'}</StatusBadge>
            {wallet.status === 'connected' && wallet.accountId ? <button className="account-chip" onClick={() => onNavigate('/settings')}><span className="account-dot" />{shortAccount(wallet.accountId)}</button> : <Button variant="secondary" onClick={() => void connect()}>Connect wallet</Button>}
          </div>
        </header>
        <main className="main-content">
          {!adapterReady ? <Notice tone="warning" title="Connect a real NEAR wallet to continue.">This workspace is read-only while disconnected. No balances, claims, proofs or transaction results are simulated.</Notice> : null}
          {walletError ? <Notice tone="danger" title="Wallet connection unavailable">{walletError}</Notice> : null}
          {notice ? <Notice tone="info">{notice}</Notice> : null}
          {children}
        </main>
      </div>
    </div>
  )
}

function shortAccount(accountId: string): string {
  if (accountId.length <= 24) return accountId
  return `${accountId.slice(0, 9)}…${accountId.slice(-8)}`
}

export const roleInformation = roleMeta

export function roleLabel(role: Role): string {
  return roleMeta[role].label
}

export function roleNav(role: Role): NavItem[] {
  return roleMeta[role].nav
}

export function getRoleFromPath(path: string): Role | undefined {
  if (path.startsWith('/lender')) return 'lender'
  if (path.startsWith('/broker')) return 'broker'
  if (path.startsWith('/borrower')) return 'borrower'
  if (path.startsWith('/auditor')) return 'auditor'
  return undefined
}
