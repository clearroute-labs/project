/* @vitest-environment jsdom */
import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ReviewForm, reviewFields } from '../src/components/ReviewForm'
import { Field, TextInput } from '../src/components/ui'
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })

describe('local operation review', () => {
  let root: Root
  let container: HTMLDivElement
  beforeEach(() => {
    container = document.createElement('div'); document.body.append(container); root = createRoot(container)
    HTMLDialogElement.prototype.showModal = function () { this.open = true }
    HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new Event('close')) }
  })
  afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.restoreAllMocks() })
  it('associates field labels and explanatory hints with controls', async () => {
    await act(async () => root.render(createElement(Field, { label: 'Amount', hint: 'Public on-chain', children: createElement(TextInput, { id: 'existing-control' }) })))
    const input = container.querySelector('input')!
    expect(input.labels?.[0]?.textContent).toBe('Amount')
    expect(document.getElementById(input.getAttribute('aria-describedby')!)?.textContent).toBe('Public on-chain')
  })
  it('masks secrets, packages and textareas in the local review', () => {
    const form = document.createElement('form')
    form.innerHTML = '<label>Amount<input value="12.5"></label><label>Private key<input value="secret-material"></label><label>Recovery<input type="password" value="password-material"></label><label>Package<textarea>private-package</textarea></label>'
    const result = reviewFields(form)
    expect(result[0]).toEqual({ label: 'Amount', value: '12.5' })
    expect(JSON.stringify(result)).not.toMatch(/secret-material|password-material|private-package/)
    expect(result.slice(1).every(item => item.value.includes('hidden'))).toBe(true)
  })
  it('does not call the transaction handler until explicitly confirmed and retains entries on back', async () => {
    const submit = vi.fn()
    await act(async () => root.render(createElement(ReviewForm, { onSubmit: submit }, createElement('input', { defaultValue: '12.5', 'aria-label': 'Amount' }), createElement('button', { type: 'submit' }, 'Deposit'))))
    const form = container.querySelector('form')!
    const input = form.querySelector('input')!
    const button = form.querySelector('button')!
    await act(async () => button.click())
    expect(submit).not.toHaveBeenCalled()
    expect(container.querySelector('dialog')?.open).toBe(true)
    const back = Array.from(container.querySelectorAll('button')).find(b => b.textContent === 'Back to edit')!
    await act(async () => back.click())
    expect(input.value).toBe('12.5')
    await act(async () => button.click())
    const confirm = Array.from(container.querySelectorAll('button')).find(b => b.textContent?.startsWith('Confirm:'))!
    await act(async () => confirm.click())
    expect(submit).toHaveBeenCalledTimes(1)
    expect(container.querySelector('dialog')?.open).toBe(false)
  })
  it('blocks repeated submissions while the handler is pending', async () => {
    let resolve!: () => void
    const submit = vi.fn(() => new Promise<void>(done => { resolve = done }))
    await act(async () => root.render(createElement(ReviewForm, { onSubmit: submit }, createElement('button', { type: 'submit' }, 'Deposit'))))
    const button = container.querySelector('form button') as HTMLButtonElement
    await act(async () => button.click())
    const confirm = Array.from(container.querySelectorAll('button')).find(b => b.textContent?.startsWith('Confirm:'))!
    await act(async () => confirm.click())
    await act(async () => { button.click(); confirm.click() })
    expect(submit).toHaveBeenCalledTimes(1)
    await act(async () => resolve())
  })
})
