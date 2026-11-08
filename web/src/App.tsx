import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { Layout, getRoleFromPath } from './components/Layout'
import { createBrowserAdapters } from './lib/adapters'
import { toProtocolError } from './lib/actionState'
import type { AppAdapters, CryptoProviderStatus, DashboardSnapshot, ProtocolError, Role } from './lib/types'
import { AuditorPage } from './pages/AuditorPage'
import { BrokerPage } from './pages/BrokerPage'
import { BorrowerPage } from './pages/BorrowerPage'
import { LenderPage } from './pages/LenderPage'
import { SecurityPage } from './pages/SecurityPage'
import { DeviceKeySession, type DeviceKeyState } from './lib/deviceKeySession'

export interface AppContextValue {
  adapters: AppAdapters
  role: Role
  accountId?: string
  path: string
  snapshot: DashboardSnapshot | null
  loading: boolean
  loadError?: ProtocolError
  cryptoStatus: CryptoProviderStatus | null
  deviceKeys: DeviceKeySession
  deviceKeyState: DeviceKeyState
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
  const rawAdapters = useMemo(() => providedAdapters ?? createBrowserAdapters(), [providedAdapters])
  const deviceKeys = useMemo(() => new DeviceKeySession(rawAdapters), [rawAdapters])
  const adapters = useMemo(() => ({ ...rawAdapters, crypto: deviceKeys.crypto }), [rawAdapters, deviceKeys])
  const deviceKeyState = useSyncExternalStore(deviceKeys.subscribe, deviceKeys.getSnapshot)
  useEffect(() => deviceKeys.start(), [deviceKeys])
  const [path, setPath] = useState(() => readHashPath())
  const [role, setRole] = useState<Role>(() => getRoleFromPath(readHashPath()) ?? 'lender')
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<ProtocolError | undefined>()
  const [cryptoStatus, setCryptoStatus] = useState<CryptoProviderStatus | null>(null)
  const [, forceWalletUpdate] = useState(0)
  const refreshSequence = useRef(0)

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

  useEffect(() => {
    // Do not retain a previous account's public/private dashboard while a new
    // wallet session is being established. In-flight reads are invalidated by
    // the sequence guard in refresh below.
    refreshSequence.current += 1
    setSnapshot(null)
    setLoading(false)
    setCryptoStatus(null)
    setLoadError(undefined)
  }, [accountId, deviceKeyState.sessionVersion])

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current
    if (!accountId || adapters.wallet.status !== 'connected') {
      if (sequence === refreshSequence.current) {
        setSnapshot(null)
        setLoading(false)
        setLoadError(undefined)
      }
      return
    }
    setLoading(true)
    setLoadError(undefined)
    try {
      const [nextSnapshot, nextCryptoStatus] = await Promise.all([
        adapters.protocol.getDashboard(accountId),
        adapters.crypto.getStatus(),
      ])
      if (sequence !== refreshSequence.current) return
      setSnapshot(nextSnapshot)
      setCryptoStatus(nextCryptoStatus)
    } catch (error) {
      if (sequence !== refreshSequence.current) return
      setSnapshot(null)
      setLoadError(toProtocolError(error))
      try {
        const status = await adapters.crypto.getStatus()
        if (sequence === refreshSequence.current) setCryptoStatus(status)
      } catch {
        if (sequence === refreshSequence.current) setCryptoStatus(null)
      }
    } finally {
      if (sequence === refreshSequence.current) setLoading(false)
    }
  }, [accountId, adapters])

  useEffect(() => {
    void refresh()
  }, [refresh, deviceKeyState.sessionVersion, deviceKeyState.materialVersion])

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
    deviceKeys,
    deviceKeyState,
    refresh,
    navigate,
  }), [accountId, adapters, cryptoStatus, deviceKeys, deviceKeyState, loadError, loading, navigate, path, refresh, role, snapshot])

  const page = <PageRouter key={`${accountId || 'disconnected'}:${role}:${deviceKeyState.sessionVersion}`} />
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
