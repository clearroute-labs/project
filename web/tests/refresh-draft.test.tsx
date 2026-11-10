/* @vitest-environment jsdom */
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import type { AppAdapters } from '../src/lib/types'
vi.mock('../src/lib/adapters', () => ({ createBrowserAdapters: vi.fn() }))
vi.mock('../src/components/Layout', () => ({ Layout: ({ children }: { children: React.ReactNode }) => children, getRoleFromPath: () => undefined }))
vi.mock('../src/pages/LenderPage', () => ({ LenderPage: () => { const context = useAppContext(); return <ConnectionGate><input aria-label="Draft" defaultValue="" /><button onClick={() => void context.refresh()}>Refresh</button></ConnectionGate> } }))
vi.mock('../src/pages/BrokerPage', () => ({ BrokerPage: () => null }))
vi.mock('../src/pages/BorrowerPage', () => ({ BorrowerPage: () => null }))
vi.mock('../src/pages/AuditorPage', () => ({ AuditorPage: () => null }))
vi.mock('../src/pages/SecurityPage', () => ({ SecurityPage: () => null }))
import { App, useAppContext } from '../src/App'
import { ConnectionGate } from '../src/pages/shared'
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
it('retains a draft on failed refresh, blocks stale actions and restores it after a successful retry', async () => {
 const container = document.createElement('div'); document.body.append(container); const root=createRoot(container)
 const getDashboard=vi.fn().mockResolvedValue({})
 const adapters={wallet:{accountId:'alice.testnet',status:'connected',subscribe:()=>()=>{}},crypto:{setSubject:vi.fn(),getStatus:vi.fn().mockResolvedValue({available:true})},protocol:{config:{coreAccountId:'core.testnet'},getDashboard}} as unknown as AppAdapters
 try {
  await act(async()=>root.render(<App adapters={adapters}/>))
  const input=container.querySelector('input')!; input.value='12.5'
  getDashboard.mockRejectedValue(new Error('Offline'))
  await act(async()=>container.querySelector('button')!.click())
  expect(container.querySelector('input')).toBe(input)
  expect(input.value).toBe('12.5')
  expect(container.querySelector('fieldset')?.disabled).toBe(true)
  expect(container.querySelector('fieldset')?.hidden).toBe(true)
  getDashboard.mockResolvedValue({})
  const retry=Array.from(container.querySelectorAll('button')).find(button=>button.textContent==='Retry read')!
  await act(async()=>retry.click())
  expect(container.querySelector('input')).toBe(input)
  expect(input.value).toBe('12.5')
  expect(container.querySelector('fieldset')?.disabled).toBe(false)
  expect(container.querySelector('fieldset')?.hidden).toBe(false)
 } finally {await act(async()=>root.unmount()); container.remove()}
})
