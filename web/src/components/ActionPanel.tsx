import { containDialogFocus } from './dialogFocus'
import { useId, useRef, type ReactNode } from 'react'
import { Button, Card } from './ui'

/** Keep forms mounted when closed, so drafts and pending receipts survive. */
export function ActionPanel({ title, description, children, className = '' }: { title: string; description?: string; children: ReactNode; className?: string }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  return <Card className="action-entry">
    <div><h2>{title}</h2>{description ? <p>{description}</p> : null}</div>
    <Button variant="secondary" aria-haspopup="dialog" aria-label={`Open ${title.toLowerCase()}`} onClick={() => dialog.current?.showModal()}>Continue <span aria-hidden="true">↗</span></Button>
    <dialog onKeyDown={containDialogFocus} ref={dialog} className={`action-drawer ${className}`} aria-labelledby={titleId}>
      <div className="drawer-header"><p className="eyebrow">Your workspace</p><Button variant="quiet" type="button" onClick={() => dialog.current?.close()}>Close</Button></div>
      <h2 id={titleId}>{title}</h2>{description ? <p className="drawer-description">{description}</p> : null}
      <p className="draft-note">Closing keeps your entries on this page. Navigating away or changing accounts clears this draft.</p>
      {children}
    </dialog>
  </Card>
}
