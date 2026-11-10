import { containDialogFocus } from './dialogFocus'
import { useId, useRef, useState, type FormHTMLAttributes, type FormEvent } from 'react'
import { Button } from './ui'

type ReviewItem = { label: string; value: string }
export function reviewFields(form: HTMLFormElement): ReviewItem[] {
  return Array.from(form.elements).flatMap((control) => {
    if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement) || control.type === 'hidden') return []
    const label = Array.from(control.labels || []).map((item) => { const copy = item.cloneNode(true) as HTMLElement; copy.querySelectorAll('input,select,textarea').forEach((node) => node.remove()); return copy.textContent }).join(' ').trim() || control.getAttribute('aria-label') || control.name || 'Entry'
    const sensitive = control.type === 'password' || control.type === 'file' || /secret|private key|recovery|witness|salt|package|ciphertext/i.test(label) || control instanceof HTMLTextAreaElement
    const value = sensitive ? (control.value ? 'Provided locally · hidden in review' : 'Not provided') : control instanceof HTMLSelectElement ? control.selectedOptions[0]?.textContent || 'Not selected' : control instanceof HTMLInputElement && control.type === 'checkbox' ? (control.checked ? 'Yes' : 'No') : control.value || 'Not entered'
    return [{ label, value: value.length > 160 ? 'Provided locally · long value hidden' : value }]
  })
}

/** Review is local only. Existing handlers remain responsible for validation and signing. */
export function ReviewForm({ children, onSubmit, ...props }: FormHTMLAttributes<HTMLFormElement>) {
  const form = useRef<HTMLFormElement>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  const approved = useRef(false)
  const submitting = useRef(false)
  const submitter = useRef<HTMLButtonElement | HTMLInputElement | null>(null)
  const titleId = useId()
  const [items, setItems] = useState<ReviewItem[]>([])
  const [action, setAction] = useState('Continue')
  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitting.current) return
    if (approved.current) {
      approved.current = false
      submitting.current = true
      try { await onSubmit?.(event) } finally { submitting.current = false }
      return
    }
    const target = (event.nativeEvent as SubmitEvent).submitter
    submitter.current = target instanceof HTMLButtonElement || target instanceof HTMLInputElement ? target : null
    setAction(target?.textContent?.trim() || 'Continue')
    setItems(reviewFields(event.currentTarget))
    dialog.current?.showModal()
  }
  const confirm = () => {
    if (!form.current || submitting.current || submitter.current?.disabled) return
    dialog.current?.close()
    approved.current = true
    form.current.requestSubmit(submitter.current || undefined)
    approved.current = false
  }
  return <><form {...props} ref={form} onSubmit={(event) => void handleSubmit(event)}>{children}</form>
    <dialog onKeyDown={containDialogFocus} ref={dialog} className="review-dialog" aria-labelledby={titleId} onClose={() => setItems([])}>
      <p className="eyebrow">Before you continue</p><h2 id={titleId}>Review your operation</h2>
      <p>Check the account, amount and destination. This review stays in your browser; your wallet may request authorization next.</p>
      <dl className="review-summary">{items.map((item, index) => <div key={index}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}</dl>
      <p className="field-hint">Public amounts, account IDs and transaction timing remain visible on-chain. Encrypted amounts are readable through authorized keys.</p>
      <div className="review-actions"><Button type="button" variant="secondary" onClick={() => dialog.current?.close()}>Back to edit</Button><Button type="button" onClick={confirm}>Confirm: {action}</Button></div>
    </dialog>
  </>
}
