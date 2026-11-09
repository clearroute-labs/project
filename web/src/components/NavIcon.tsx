import type { ReactNode } from 'react'

export type NavIconName = 'overview' | 'vault' | 'payout' | 'loan' | 'operations' | 'wallet' | 'security' | 'audit' | 'export' | 'token' | 'menu' | 'close'

const paths: Record<NavIconName, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  vault: <><rect x="3" y="4" width="18" height="16" rx="3" /><circle cx="12" cy="12" r="4" /><path d="M12 8v2m4 2h-2m-2 4v-2m-4-2h2M5 7h1m-1 10h1" /></>,
  payout: <><path d="M13 4h7v7m0-7L10 14M9 4H6a3 3 0 0 0-3 3v11a3 3 0 0 0 3 3h11a3 3 0 0 0 3-3v-3" /></>,
  loan: <><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8m-8 4h5" /></>,
  operations: <><path d="M4 7h16M4 17h16" /><circle cx="9" cy="7" r="3" fill="var(--paper)" /><circle cx="15" cy="17" r="3" fill="var(--paper)" /></>,
  wallet: <><path d="M20 8V6a2 2 0 0 0-2-2H6a3 3 0 0 0 0 6h14v10H6a3 3 0 0 1-3-3V7" /><path d="M20 12h-5v5h5m-3-2.5h.01" /></>,
  security: <><path d="m12 3 8 3v6c0 5-8 9-8 9S4 17 4 12V6z" /><path d="m8.5 12 2.5 2.5 4.5-5" /></>,
  audit: <><circle cx="10.5" cy="10.5" r="7" /><path d="m16 16 5 5m-14-10 2.5 2.5 4-4" /></>,
  export: <><path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5" /></>,
  token: <><circle cx="12" cy="12" r="9" /><path d="m12 6 5 6-5 6-5-6z" /></>,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
}

export function NavIcon({ name }: { name: NavIconName }) {
  return <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{paths[name]}</svg>
}
