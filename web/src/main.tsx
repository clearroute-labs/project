import { lazy, StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import './styles.css'

const PrivySignPage = lazy(() => import('./PrivySignPage'))

const root = document.getElementById('root')
if (!root) throw new Error('Missing #root element')

createRoot(root).render(window.location.pathname === '/wallet/privy' ?
  <Suspense fallback={<p role="status">Loading wallet…</p>}><PrivySignPage /></Suspense> :
  <StrictMode>
    <App />
  </StrictMode>,
)
