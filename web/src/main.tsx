import './polyfills'
import { lazy, StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { LandingPage } from './pages/LandingPage'
import './styles.css'

const PrivySignPage = lazy(() => import('./PrivySignPage'))
const Application = lazy(() => import('./App').then(({ App }) => ({ default: App })))

const root = document.getElementById('root')
if (!root) throw new Error('Missing #root element')

let path = window.location.pathname.replace(/\/+$/, '') || '/'
if (path === '/' && window.location.hash.startsWith('#/')) {
  window.history.replaceState(window.history.state, '', `/app${window.location.search}${window.location.hash}`)
  path = '/app'
}

createRoot(root).render(path === '/wallet/privy' ?
  <Suspense fallback={<p role="status">Loading wallet…</p>}><PrivySignPage /></Suspense> :
  <StrictMode>
    {path === '/app' ? <Suspense fallback={<p role="status">Opening app…</p>}><Application /></Suspense> : <LandingPage />}
  </StrictMode>,
)
