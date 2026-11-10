import { Children, cloneElement, isValidElement, useId, useLayoutEffect, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'
import type { ActionState } from '../lib/actionState'
import { formatAmount } from '../lib/money'

export function Button({ variant = 'primary', busy = false, children, disabled, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'quiet' | 'danger'; busy?: boolean }) {
  return (
    <button className={`button button-${variant}`} disabled={disabled || busy} aria-busy={busy || undefined} {...props}>
      {busy ? <span className="button-spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  )
}

export function Card({ children, className = '', as: Element = 'section' }: { children: ReactNode; className?: string; as?: 'section' | 'article' | 'div' }) {
  return <Element className={`card ${className}`}>{children}</Element>
}

export function SectionHeading({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="section-heading">
      <div>
        <h2>{title}</h2>
        {description ? <p className="muted section-description">{description}</p> : null}
      </div>
      {action ? <div className="section-heading-action">{action}</div> : null}
    </div>
  )
}

export function Field({ label, hint, error, children, htmlFor }: { label: string; hint?: string; error?: string; children: ReactNode; htmlFor?: string }) {
  const generatedId = useId()
  const control = Children.toArray(children).find(child => isValidElement<InputHTMLAttributes<HTMLInputElement>>(child) && Boolean(child.props.id))
  const id = htmlFor || (isValidElement<InputHTMLAttributes<HTMLInputElement>>(control) ? control.props.id : undefined) || generatedId
  const descriptionId = `${id}-description`
  return <div className="field"><label htmlFor={id}>{label}</label>
    {Children.map(children, (child) => {
      if (!isValidElement<InputHTMLAttributes<HTMLInputElement>>(child) || !(['input', 'select', 'textarea'].includes(String(child.type)) || child.type === TextInput || child.type === SelectInput)) return child
      return cloneElement(child, { id: child.props.id || id, 'aria-describedby': [child.props['aria-describedby'], (hint || error) ? descriptionId : undefined].filter(Boolean).join(' ') || undefined, 'aria-invalid': error ? true : child.props['aria-invalid'] })
    })}
    {error ? <p id={descriptionId} className="field-error" role="alert">{error}</p> : hint ? <p id={descriptionId} className="field-hint">{hint}</p> : null}
  </div>
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }) {
  const { invalid, className = '', ...inputProps } = props
  return <input aria-invalid={invalid || undefined} className={`input ${invalid ? 'input-invalid' : ''} ${className}`} {...inputProps} />
}

export function SelectInput(props: SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = '', ...selectProps } = props
  return <select className={`input select-input ${className}`} {...selectProps} />
}

export function StatusBadge({ tone = 'neutral', children }: { tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info'; children: ReactNode }) {
  return <span className={`status-badge status-${tone}`}><span className="status-dot" aria-hidden="true" />{children}</span>
}

export function Metric({ label, value, supporting, tone = 'default' }: { label: string; value: ReactNode; supporting?: string; tone?: 'default' | 'positive' | 'warning' }) {
  return (
    <div className={`metric metric-${tone}`}>
      <p className="metric-label">{label}</p>
      <p className="metric-value">{value}</p>
      {supporting ? <p className="metric-supporting">{supporting}</p> : null}
    </div>
  )
}

export function EmptyState({ icon, title, description, action }: { icon?: string; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      {icon ? <div className="empty-icon" aria-hidden="true">{icon}</div> : null}
      <h3>{title}</h3>
      {description ? <p className="muted">{description}</p> : null}
      {action ? <div className="empty-action">{action}</div> : null}
    </div>
  )
}

export function ActionFeedback({ state }: { state: ActionState }) {
  if (state.phase === 'idle') return null
  if (state.phase === 'failed') {
    return (
      <div className="action-feedback action-failed" role="alert">
        <div><strong>{state.label || 'Action'} needs review.</strong><p>{state.error?.details.message || 'The transaction outcome needs review. Check its finalized status before trying again.'}</p>{state.error?.details.transactionHash ? <p>Transaction <Mono>{state.error.details.transactionHash}</Mono></p> : null}</div>
        {state.error?.details.category ? <code>{state.error.details.category}</code> : null}
      </div>
    )
  }
  if (state.phase === 'succeeded') {
    return (
      <div className="action-feedback action-success" role="status" aria-atomic="true">
        <div><strong>{state.label || 'Action'} finalized.</strong><p>Transaction {state.receipt?.transactionHash || state.receipt?.operationId || 'confirmed'}.</p></div>
      </div>
    )
  }
  const copy: Record<string, string> = {
    preparing: 'Preparing a secure operation…',
    awaiting_wallet: 'Awaiting wallet authorization…',
    submitted: 'Submitted; waiting for finality…',
    pending: 'Submitted; the operation remains pending on-chain.',
  }
  return (
    <div className="action-feedback action-pending" role="status" aria-atomic="true">
      <span className="button-spinner" aria-hidden="true" />
      <div>
        <strong>{state.label || 'Action'}</strong>
        <p>{state.error?.details.message || copy[state.phase] || 'Working…'} {state.phase === 'pending' ? 'No second submission will be started until this transaction is resolved.' : 'Status updates after the network confirms the operation.'}</p>
        {state.pending?.transactionHash ? <p>Transaction <Mono>{state.pending.transactionHash}</Mono></p> : null}
        {state.resolvePending ? <Button variant="secondary" busy={state.pendingStatusChecking} onClick={() => void state.resolvePending?.()}>Check transaction status</Button> : null}
      </div>
    </div>
  )
}

export function Notice({ tone = 'info', title, children }: { tone?: 'info' | 'warning' | 'danger' | 'success'; title?: string; children: ReactNode }) {
  return <div className={`notice notice-${tone}`}><span className="notice-mark" aria-hidden="true">{tone === 'warning' || tone === 'danger' ? '!' : tone === 'success' ? '✓' : 'i'}</span><div>{title ? <strong>{title}</strong> : null}<div>{children}</div></div></div>
}

export function Mono({ children }: { children: ReactNode }) {
  return <code className="mono">{children}</code>
}

export function Money({ units, decimals, symbol = '' }: { units?: string; decimals: number; symbol?: string }) {
  return <>{symbol}{formatAmount(units, decimals)}</>
}

export function Table({ children, caption }: { children: ReactNode; caption?: string }) {
  const table = useRef<HTMLTableElement>(null)
  useLayoutEffect(() => {
    const headers = Array.from(table.current?.tHead?.rows[0]?.cells || []).map((cell) => cell.textContent || '')
    Array.from(table.current?.tBodies || []).forEach((body) => Array.from(body.rows).forEach((row) => {
      row.setAttribute('role', 'row')
      Array.from(row.cells).forEach((cell, index) => { cell.dataset.label = cell.colSpan > 1 ? '' : headers[index]; cell.setAttribute('role', 'cell') })
    }))
  }, [children])
  return <div className="table-wrap"><table ref={table} role="table">{caption ? <caption>{caption}</caption> : null}{children}</table></div>
}
