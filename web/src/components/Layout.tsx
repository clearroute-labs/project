import { isWorkspaceOverview, workspaceRoute } from '../lib/workspaceRoutes'
import { containDialogFocus } from './dialogFocus'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Button, Notice, SelectInput } from './ui'
import type { Role, WalletAdapter } from '../lib/types'
import { AppLogo } from './AppLogo'
import { NavIcon, type NavIconName } from './NavIcon'

export interface NavItem {
  path: string
  label: string
  icon: NavIconName
}

const roleMeta: Record<Role, { label: string; nav: NavItem[] }> = {
  lender: {
    label: 'Lender',
    nav: [
      { path: '/', label: 'Overview', icon: 'overview' },
      { path: '/lender/vaults', label: 'Vaults', icon: 'vault' },
      { path: '/lender/claims', label: 'Claims & payouts', icon: 'payout' },
      { path: '/settings', label: 'Wallet & security', icon: 'security' },
    ],
  },
  broker: {
    label: 'Broker',
    nav: [
      { path: '/', label: 'Desk overview', icon: 'overview' },
      { path: '/broker/vaults', label: 'Vaults & brokers', icon: 'vault' },
      { path: '/broker/loans', label: 'Loan book', icon: 'loan' },
      { path: '/broker/operations', label: 'Operations', icon: 'operations' },
      { path: '/settings', label: 'Wallet & security', icon: 'security' },
    ],
  },
  borrower: {
    label: 'Borrower',
    nav: [
      { path: '/', label: 'Home', icon: 'overview' },
      { path: '/borrower/agreements', label: 'Agreements', icon: 'loan' },
      { path: '/borrower/balance', label: 'Private balance', icon: 'wallet' },
      { path: '/settings', label: 'Wallet & security', icon: 'security' },
    ],
  },
  auditor: {
    label: 'Auditor',
    nav: [
      { path: '/', label: 'Audit home', icon: 'audit' },
      { path: '/auditor/loans', label: 'Loan exports', icon: 'export' },
      { path: '/auditor/token', label: 'Token audit', icon: 'token' },
      { path: '/settings', label: 'Wallet & security', icon: 'security' },
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
  const route = workspaceRoute(role, path)
  const [mobile, setMobile] = useState(() => window.matchMedia?.('(max-width: 800px)').matches ?? false)
  useEffect(() => {
    const query = window.matchMedia('(max-width: 800px)')
    const update = () => { setMobile(query.matches); if (!query.matches) setNavigationOpen(false) }
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])
  const [walletError, setWalletError] = useState('')
  const [navigationOpen, setNavigationOpen] = useState(false)
  const mobileMenu = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    if (navigationOpen) mobileMenu.current?.showModal()
    else mobileMenu.current?.close()
  }, [navigationOpen])
  const menuToggle = useRef<HTMLButtonElement>(null)
  const mainContent = useRef<HTMLElement>(null)
  const connected = wallet.status === 'connected' && Boolean(wallet.accountId)
  const closeNavigation = () => { setNavigationOpen(false); menuToggle.current?.focus() }
  const navigate = (nextPath: string) => {
    setNavigationOpen(false)
    mobileMenu.current?.close()
    onNavigate(nextPath === '/' ? `/${role}/overview` : nextPath)
    mainContent.current?.focus({ preventScroll: true })
  }
  const connect = async () => {
    setWalletError('')
    try { await wallet.connect() } catch (error) { setWalletError(error instanceof Error ? error.message : 'Wallet connection failed.') }
  }
  const rolePicker = <SelectInput className="workspace-select" aria-label="Active workspace" value={role} onChange={(event) => { setNavigationOpen(false); onRoleChange(event.target.value as Role) }}>
              {(Object.keys(roleMeta) as Role[]).map((item) => <option key={item} value={item}>{roleMeta[item].label}</option>)}
            </SelectInput>
  return (
    <div className="app-shell">
      <a className="skip-link" href="#workspace-content" onClick={(event) => { event.preventDefault(); mainContent.current?.focus() }}>Skip to workspace</a>
      <aside className="sidebar">
        <button className="brand" onClick={() => navigate('/')} aria-label="clear home"><AppLogo /></button>

        <div className="sidebar-workspace"><p className="sidebar-caption">Workspace</p>{!mobile ? rolePicker : null}</div>
        <nav id="desktop-navigation" className="primary-nav" aria-label={`${meta.label} navigation`}>
          {meta.nav.map((item) => {
            const selected = item.path === '/' ? isWorkspaceOverview(path) : path.startsWith(item.path)
            return <button key={item.path} className={`nav-item ${selected ? 'nav-item-active' : ''}`} aria-label={item.label} title={item.label} aria-current={selected ? 'page' : undefined} onClick={() => navigate(item.path)}><NavIcon name={item.icon} /><span className="nav-label" aria-hidden="true">{item.label}</span></button>
          })}
        </nav>
        <div className="sidebar-footer"><p>Public capital.<br />Private credit.</p><a href="/">About clear <span aria-hidden="true">↗</span></a></div>
      </aside>
      <dialog onKeyDown={containDialogFocus} ref={mobileMenu} className="mobile-navigation" aria-label="Workspace navigation" onClose={() => setNavigationOpen(false)}>
        <div className="drawer-header"><AppLogo /><Button variant="quiet" onClick={closeNavigation}>Close navigation</Button></div>
        <nav id="workspace-navigation" className="primary-nav" aria-label={`${meta.label} navigation`}>
          {meta.nav.map((item) => {
            const selected = item.path === '/' ? isWorkspaceOverview(path) : path.startsWith(item.path)
            return <button key={item.path} className={`nav-item ${selected ? 'nav-item-active' : ''}`} aria-label={item.label} title={item.label} aria-current={selected ? 'page' : undefined} onClick={() => navigate(item.path)}><NavIcon name={item.icon} /><span className="nav-label" aria-hidden="true">{item.label}</span></button>
          })}
        </nav>
      </dialog>
      <div className="main-column">
        <header className="topbar"><button ref={menuToggle} className="sidebar-toggle" aria-label="Open navigation" aria-haspopup="dialog" aria-expanded={navigationOpen} aria-controls="workspace-navigation" onClick={() => setNavigationOpen(true)}><NavIcon name="menu" /></button>
          <div className="workspace-breadcrumb"><span>{meta.label}</span><span aria-hidden="true">/</span><strong>{route.section}</strong></div>
          <div className="topbar-actions"><span className="topbar-context">NEAR {wallet.networkId || 'testnet'}</span>
            {mobile ? rolePicker : null}
            {connected && wallet.accountId ? <button className="account-chip" aria-label={`Wallet & security: ${wallet.accountId}`} onClick={() => navigate('/settings')}><span className="account-dot" /><span className="account-name">{shortAccount(wallet.accountId)}</span></button> : null}
            {!connected ? <Button variant="secondary" disabled={wallet.status === 'connecting'} onClick={() => void connect()}>{wallet.status === 'connecting' ? 'Connecting…' : 'Connect wallet'}</Button> : null}
          </div>
        </header>
        <main id="workspace-content" ref={mainContent} tabIndex={-1} className="main-content">
          {connected && !adapterReady ? <Notice tone="warning" title="Lending deployment unavailable">Your wallet is connected. A complete contract and security configuration is required before lending actions are available.</Notice> : null}
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
