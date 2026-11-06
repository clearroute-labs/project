import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Layout, getRoleFromPath } from './components/Layout'
import { createBrowserAdapters } from './lib/adapters'
import { toProtocolError } from './lib/actionState'
import type { AppAdapters, CryptoProviderStatus, DashboardSnapshot, ProtocolError, Role } from './lib/types'
import { AuditorPage } from './pages/AuditorPage'
import { BrokerPage } from './pages/BrokerPage'
import { BorrowerPage } from './pages/BorrowerPage'
import { LenderPage } from './pages/LenderPage'
import { SecurityPage } from './pages/SecurityPage'

export interface AppContextValue {
  adapters: AppAdapters
  role: Role
  accountId?: string
  path: string
  snapshot: DashboardSnapshot | null
  loading: boolean
  loadError?: ProtocolError
  cryptoStatus: CryptoProviderStatus | null
  refresh(): Promise<void>
  navigate(path: string): void
}

const AppContext = createContext<AppContextValue | null>(null)

export function useAppContext(): AppContextValue {
  const context = useContext(AppContext)
  if (!context) throw new Error('useAppContext must be used inside App')
  return context
}

export function App({ adapters: providedAdapters }: { adapters?: AppAdapters }) {
  const adapters = useMemo(() => providedAdapters ?? createBrowserAdapters(), [providedAdapters])
  const [path, setPath] = useState(() => readHashPath())
  const [role, setRole] = useState<Role>(() => getRoleFromPath(readHashPath()) ?? 'lender')
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<ProtocolError | undefined>()
  const [cryptoStatus, setCryptoStatus] = useState<CryptoProviderStatus | null>(null)
  const [, forceWalletUpdate] = useState(0)

  useEffect(() => adapters.wallet.subscribe(() => forceWalletUpdate((value) => value + 1)), [adapters.wallet])

  useEffect(() => {
    const onHashChange = () => {
      const nextPath = readHashPath()
      setPath(nextPath)
      const nextRole = getRoleFromPath(nextPath)
      if (nextRole) setRole(nextRole)
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const accountId = adapters.wallet.accountId

  const refresh = useCallback(async () => {
    if (!accountId || adapters.wallet.status !== 'connected') {
      setSnapshot(null)
      setLoadError(undefined)
      return
    }
    setLoading(true)
    setLoadError(undefined)
    try {
      const [nextSnapshot, nextCryptoStatus] = await Promise.all([
        adapters.protocol.getDashboard(accountId),
        adapters.crypto.getStatus(),
      ])
      setSnapshot(nextSnapshot)
      setCryptoStatus(nextCryptoStatus)
    } catch (error) {
      setSnapshot(null)
      setLoadError(toProtocolError(error))
      try {
        setCryptoStatus(await adapters.crypto.getStatus())
      } catch {
        setCryptoStatus(null)
      }
    } finally {
      setLoading(false)
    }
  }, [accountId, adapters])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const navigate = useCallback((nextPath: string) => {
    if (window.location.hash !== `#${nextPath}`) window.location.hash = nextPath
    else setPath(nextPath)
  }, [])

  const changeRole = useCallback((nextRole: Role) => {
    setRole(nextRole)
    navigate('/')
  }, [navigate])

  const context = useMemo<AppContextValue>(() => ({
    adapters,
    role,
    accountId,
    path,
    snapshot,
    loading,
    loadError,
    cryptoStatus,
    refresh,
    navigate,
  }), [accountId, adapters, cryptoStatus, loadError, loading, navigate, path, refresh, role, snapshot])

  const page = <PageRouter />
  const adapterReady = adapters.wallet.status === 'connected' && Boolean(accountId) && Boolean(adapters.protocol.config.coreAccountId)

  return (
    <AppContext.Provider value={context}>
      <Layout role={role} path={path} onNavigate={navigate} onRoleChange={changeRole} wallet={adapters.wallet} adapterReady={adapterReady}>
        {page}
      </Layout>
    </AppContext.Provider>
  )
}

function PageRouter() {
  const { role, path } = useAppContext()
  if (path === '/settings') return <SecurityPage />
  if (role === 'lender') return <LenderPage />
  if (role === 'broker') return <BrokerPage />
  if (role === 'borrower') return <BorrowerPage />
  return <AuditorPage />
}

function readHashPath(): string {
  if (typeof window === 'undefined') return '/'
  const raw = window.location.hash.replace(/^#/, '')
  return raw.startsWith('/') ? raw : '/'
}

export function AppProviders({ children }: { children: ReactNode }) {
  return <>{children}</>
}
