import { MetricRow } from '../components/WorkspaceMetrics'
import { auditMetrics } from '../lib/workspaceMetrics'
import { useEffect, useRef, useState } from 'react'
import { useAppContext } from '../App'
import { Button, Card, EmptyState, Field, Mono, Notice, SectionHeading, SelectInput, StatusBadge, Table, TextInput } from '../components/ui'
import type { DecryptedAuditView } from '../lib/types'
import { ConnectionGate, EmptyRow, PageHeader, } from './shared'

export function AuditorPage() {
  return <ConnectionGate><AuditorWorkspace /></ConnectionGate>
}

function AuditorWorkspace() {
  const { path, navigate, snapshot } = useAppContext()
  if (!snapshot) return null
  const scope = path.startsWith('/auditor/token') ? 'token' : 'loan'
  return <><PageHeader title="Audit" action={<Button variant="secondary" onClick={() => navigate(scope === 'loan' ? '/auditor/token' : '/auditor/loans')}>{scope === 'loan' ? 'Token audit' : 'Loan audit'} →</Button>} /><AuditWorkspace key={scope} scope={scope} /></>
}

function AuditWorkspace({ scope }: { scope: 'loan' | 'token' }) {
  const { snapshot, adapters, accountId } = useAppContext()
  const [subjectId, setSubjectId] = useState('')
  const [tokenSubjectKind, setTokenSubjectKind] = useState<'holder' | 'broker'>('holder')
  const [tokenReaderRole, setTokenReaderRole] = useState<'issuer' | 'token_auditor'>('token_auditor')
  const [decrypted, setDecrypted] = useState<DecryptedAuditView | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const request = useRef(0)
  const clearResult = () => { request.current += 1; setDecrypted(null); setError(''); setLoading(false) }
  useEffect(() => () => { request.current += 1 }, [])
  if (!snapshot) return null
  const selectedLoan = snapshot.loans.find((loan) => loan.loanId === subjectId)
  const loadAndDecrypt = async () => {
    const sequence = ++request.current
    setError(''); setDecrypted(null)
    if (!subjectId.trim()) return setError(`Select a ${scope === 'loan' ? 'loan' : 'token audit subject'}.`)
    setLoading(true)
    try {
      const bundle = scope === 'loan'
        ? await adapters.protocol.getAuditBundle({ scope: 'loan', subjectId: subjectId.trim() })
        : await adapters.protocol.getAuditBundle({ scope: 'token', subjectId: `${tokenSubjectKind}:${subjectId.trim()}`, readerRole: tokenReaderRole })
      const view = await adapters.crypto.decryptAudit(bundle)
      if (sequence === request.current) setDecrypted(view)
    } catch (caught) { if (sequence === request.current) setError(caught instanceof Error ? caught.message : 'Audit view could not be decrypted.') } finally { if (sequence === request.current) setLoading(false) }
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
  return <><MetricRow metrics={auditMetrics(scope, decrypted)} label="Your current audit view"/><div className="audit-grid"><Card className="audit-selector"><SectionHeading title={scope === 'loan' ? 'Choose one loan' : 'Choose one registered subject'} description={scope === 'loan' ? 'Enter the loan ID covered by your audit key.' : 'Enter the account or broker covered by your audit key.'} />{scope === 'loan' ? <Field label="Loan ID" htmlFor="audit-subject" hint="Use a numeric loan ID."><TextInput id="audit-subject" inputMode="numeric" value={subjectId} onChange={(event) => { clearResult(); setSubjectId(event.target.value) }} placeholder="0" list="audit-loan-ids" /><datalist id="audit-loan-ids">{snapshot.loans.map((loan) => <option key={loan.loanId} value={loan.loanId}>{loan.status}</option>)}</datalist></Field> : <><div className="two-column-inner"><Field label="Subject type" htmlFor="audit-subject-kind"><SelectInput id="audit-subject-kind" value={tokenSubjectKind} onChange={(event) => { setTokenSubjectKind(event.target.value as typeof tokenSubjectKind); setSubjectId(''); clearResult() }}><option value="holder">Holder account</option><option value="broker">Broker ID</option></SelectInput></Field><Field label="Reader scope" htmlFor="audit-reader-role" hint="Use the key authorized by the asset profile."><SelectInput id="audit-reader-role" value={tokenReaderRole} onChange={(event) => { setTokenReaderRole(event.target.value as typeof tokenReaderRole); clearResult() }}><option value="token_auditor">Token auditor</option><option value="issuer">Issuer</option></SelectInput></Field></div><Field label={tokenSubjectKind === 'holder' ? 'Holder account' : 'Broker ID'} htmlFor="audit-subject" hint={tokenSubjectKind === 'holder' ? 'Enter the registered account whose mirror is authorized for this audit.' : 'Enter a canonical decimal broker ID.'}><TextInput id="audit-subject" value={subjectId} onChange={(event) => { clearResult(); setSubjectId(event.target.value) }} placeholder={tokenSubjectKind === 'holder' ? accountId || 'holder.testnet' : '0'} list={tokenSubjectKind === 'broker' ? 'audit-broker-ids' : undefined} />{tokenSubjectKind === 'broker' ? <datalist id="audit-broker-ids">{snapshot.brokers.map((broker) => <option key={broker.brokerId} value={broker.brokerId} />)}</datalist> : null}</Field></>}{selectedLoan ? <div className="readonly-field"><span>Auditor key</span><Mono>{selectedLoan.auditorKeyId}</Mono><span>Terms digest</span><Mono>{selectedLoan.termsDigest}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button onClick={() => void loadAndDecrypt()} busy={loading}>Decrypt</Button><p className="field-hint">Your key determines access. Decrypted values stay in this browser until exported.</p><div className="audit-action-feedback"><StatusBadge tone={decrypted ? 'success' : 'neutral'}>{decrypted ? 'Decrypted locally' : 'Locked'}</StatusBadge></div></Card><Card className="audit-result"><SectionHeading title="Audit results" action={decrypted ? <Button variant="secondary" onClick={exportView}>Export JSON</Button> : undefined} />{decrypted ? <><div className="decrypted-title"><span className="private-orb small">◈</span><strong>Explicitly decrypted in this browser</strong></div><Table caption="Decrypted authorized fields"><thead><tr><th scope="col">Field</th><th scope="col">Value</th><th scope="col">Unit</th></tr></thead><tbody>{decrypted.fields.map((field) => <tr key={field.label}><td>{field.label}</td><td><strong>{field.value}</strong></td><td>{field.unit}</td></tr>)}</tbody></Table><div className="audit-source"><span>Source digest</span><Mono>{decrypted.sourceDigest}</Mono><span>Decrypted at</span><time>{new Date(decrypted.decryptedAt).toLocaleString()}</time></div></> : <EmptyState icon="⌁" title="No results" description="Choose a record to decrypt." />}</Card></div></>
}
