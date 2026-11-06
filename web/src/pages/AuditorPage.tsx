import { useState } from 'react'
import { useAppContext } from '../App'
import { Button, Card, EmptyState, Field, Mono, Notice, SectionHeading, SelectInput, StatusBadge, Table } from '../components/ui'
import type { DecryptedAuditView } from '../lib/types'
import { ConnectionGate, EmptyRow, PageHeader, PublicPrivateNotice } from './shared'

export function AuditorPage() {
  return <ConnectionGate role="auditor"><AuditorWorkspace /></ConnectionGate>
}

function AuditorWorkspace() {
  const { path, navigate, snapshot } = useAppContext()
  if (!snapshot) return null
  const scope = path.startsWith('/auditor/token') ? 'token' : 'loan'
  return <><PageHeader eyebrow="Scoped auditor workspace" title="Export only what you are authorized to see" description="Auditor access is fixed by the ciphertext key and scope recorded at origination. Decryption is explicit and exports are deliberate." action={<Button variant="secondary" onClick={() => navigate(scope === 'loan' ? '/auditor/token' : '/auditor/loans')}>{scope === 'loan' ? 'Token audit' : 'Loan audit'} →</Button>} /><PublicPrivateNotice>Token-auditor views cover token transfer and balance mirrors. Loan-auditor views cover the specific loan's encrypted principal, amount owed, periodic payment and repayments. Neither scope silently expands into the other.</PublicPrivateNotice><Notice tone="warning" title="Decrypting creates a local plaintext view">The export action below is intentionally separate. This app does not send decrypted fields to RPC or analytics.</Notice><AuditWorkspace scope={scope} /></>
}

function AuditWorkspace({ scope }: { scope: 'loan' | 'token' }) {
  const { snapshot, adapters } = useAppContext()
  const [subjectId, setSubjectId] = useState('')
  const [decrypted, setDecrypted] = useState<DecryptedAuditView | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  if (!snapshot) return null
  const selectedLoan = snapshot.loans.find((loan) => loan.loanId === subjectId)
  const loadAndDecrypt = async () => {
    setError(''); setDecrypted(null)
    if (!subjectId) return setError(`Select a ${scope === 'loan' ? 'loan' : 'token audit subject'}.`)
    setLoading(true)
    try {
      const bundle = await (scope === 'loan' ? adapters.protocol.getAuditBundle({ scope: 'loan', subjectId }) : adapters.protocol.getAuditBundle({ scope: 'token', subjectId }))
      setDecrypted(await adapters.crypto.decryptAudit(bundle))
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Audit view could not be decrypted.') } finally { setLoading(false) }
  }
  const exportView = () => {
    if (!decrypted) return
    const blob = new Blob([JSON.stringify(decrypted, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${scope}-audit-${decrypted.subjectId}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  return <div className="audit-grid"><Card className="audit-selector"><SectionHeading eyebrow={scope === 'loan' ? 'Loan auditor scope' : 'Token auditor scope'} title={scope === 'loan' ? 'Choose one loan' : 'Choose token subject'} description={scope === 'loan' ? 'Only a loan-specific audit key can open this ciphertext bundle.' : 'Token scope exposes transfer and balance mirrors for the configured asset.'} /><Field label={scope === 'loan' ? 'Loan ID' : 'Token account'} htmlFor="audit-subject">{scope === 'loan' ? <SelectInput id="audit-subject" value={subjectId} onChange={(event) => setSubjectId(event.target.value)}><option value="">Select loan</option>{snapshot.loans.map((loan) => <option key={loan.loanId} value={loan.loanId}>{loan.loanId} · {loan.status}</option>)}</SelectInput> : <SelectInput id="audit-subject" value={subjectId} onChange={(event) => setSubjectId(event.target.value)}><option value="">Select asset</option><option value={snapshot.asset.tokenAccount}>{snapshot.asset.tokenAccount}</option></SelectInput>}</Field>{selectedLoan ? <div className="readonly-field"><span>Auditor key</span><Mono>{selectedLoan.auditorKeyId}</Mono><span>Terms digest</span><Mono>{selectedLoan.termsDigest}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button onClick={() => void loadAndDecrypt()} busy={loading}>Load & decrypt authorized view</Button><p className="field-hint">Fetching ciphertexts is not decryption. The explicit action checks the profile, key ID and ciphertext digests before revealing fields.</p><div className="audit-action-feedback"><StatusBadge tone={decrypted ? 'success' : 'neutral'}>{decrypted ? 'Decrypted locally' : 'Locked'}</StatusBadge></div></Card><Card className="audit-result"><SectionHeading eyebrow="Local result" title="Authorized fields" action={decrypted ? <Button variant="secondary" onClick={exportView}>Export JSON</Button> : undefined} />{decrypted ? <><div className="decrypted-title"><span className="private-orb small">◈</span><strong>Explicitly decrypted in this browser</strong></div><Table caption="Decrypted authorized fields"><thead><tr><th scope="col">Field</th><th scope="col">Value</th><th scope="col">Unit</th></tr></thead><tbody>{decrypted.fields.map((field) => <tr key={field.label}><td>{field.label}</td><td><strong>{field.value}</strong></td><td>{field.unit}</td></tr>)}</tbody></Table><div className="audit-source"><span>Source digest</span><Mono>{decrypted.sourceDigest}</Mono><span>Decrypted at</span><time>{new Date(decrypted.decryptedAt).toLocaleString()}</time></div></> : <EmptyState icon="⌁" title="No plaintext loaded" description="Select the correct subject, then deliberately decrypt. No audit data is inferred or substituted." />}</Card></div>
}
