import { useEffect, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, EmptyState, Field, Metric, Mono, Notice, SectionHeading, SelectInput, StatusBadge, Table, TextInput } from '../components/ui'
import { isInboxMergeRequired, requireFinalized, useAction } from '../lib/actionState'
import { parseAmount, unixSecondsNow } from '../lib/money'
import { ProtocolError, type LoanSummary, type PrivateAccountView, type ProposalSummary } from '../lib/types'
import { readProposalPackage, type EncryptedProposalPackage } from '../lib/proposalPackage'
import { useEncryptedWalletBackup, walletBackupScope } from '../lib/walletBackupGate'
import { ConnectionGate, EmptyRow, PageHeader, PublicPrivateNotice, VaultPolicyNotice } from './shared'

export function BorrowerPage() {
  return <ConnectionGate role="borrower"><BorrowerWorkspace /></ConnectionGate>
}

function BorrowerWorkspace() {
  const { path, snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  if (path.startsWith('/borrower/agreements')) return <AgreementsPage />
  if (path.startsWith('/borrower/balance')) return <PrivateBalancePage />
  return <BorrowerOverview onAgreements={() => navigate('/borrower/agreements')} onBalance={() => navigate('/borrower/balance')} />
}

function BorrowerOverview({ onAgreements, onBalance }: { onAgreements: () => void; onBalance: () => void }) {
  const { snapshot, refresh } = useAppContext()
  if (!snapshot) return null
  const loans = snapshot.loans
  const active = loans.filter((loan) => loan.status === 'active' || loan.status === 'impaired').length
  const proposals = snapshot.proposals.filter((proposal) => ['pending', 'broker_authorized'].includes(proposal.status)).length
  return <>
    <PageHeader eyebrow="Borrower workspace" title="Your credit, kept local" description="Loan status and schedule metadata are public. Agreement terms, private balances and repayment amounts are revealed only after you choose to view them." action={<Button variant="secondary" onClick={() => void refresh()}>Refresh state</Button>} />
    <PublicPrivateNotice>Account relationships, proposal IDs, due dates and versions are public. Private terms and balances remain in your browser until you choose to reveal them.</PublicPrivateNotice>
    <div className="metrics-grid"><Metric label="Active agreements" value={String(active)} supporting={`${loans.filter((loan) => loan.status === 'paid').length} paid`} /><Metric label="Pending proposals" value={String(proposals)} supporting="Review before authorizing" tone={proposals ? 'warning' : 'default'} /><Metric label="Private inbox" value="Encrypted" supporting="Merge when you need to spend" /><Metric label="Wallet backup" value="Local only" supporting="AES-GCM encrypted export" tone="positive" /></div>
    <div className="dashboard-grid"><Card><SectionHeading eyebrow="Agreements" title="Review before signing" action={<Button variant="quiet" onClick={onAgreements}>Open agreements →</Button>} />{snapshot.proposals.length ? <ProposalSummary proposals={snapshot.proposals} /> : <EmptyState title="No proposals in view" description="A broker proposal will appear after the Core returns it for this wallet." />}</Card><Card><SectionHeading eyebrow="Private rail" title="Balance & transfers" action={<Button variant="quiet" onClick={onBalance}>Open balance →</Button>} /><div className="private-teaser"><span className="private-orb">◈</span><div><strong>Encrypted until unlocked</strong><p>Your balance and spending state stay private until you unlock them.</p></div></div></Card></div>
    <Card><SectionHeading eyebrow="Payment cadence" title="Upcoming public dates" description="A date is a liveness hint, not a plaintext monetary amount." /><UpcomingLoans loans={loans} /></Card>
  </>
}

function AgreementsPage() {
  const { snapshot, navigate } = useAppContext()
  const [selectedId, setSelectedId] = useState('')
  const [proposalPackage, setProposalPackage] = useState<EncryptedProposalPackage | null>(null)
  const [packageError, setPackageError] = useState('')
  if (!snapshot) return null
  const importPackage = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    try { setProposalPackage(await readProposalPackage(file)); setPackageError('') } catch (caught) { setProposalPackage(null); setPackageError(caught instanceof Error ? caught.message : 'Proposal package could not be imported.') }
    event.target.value = ''
  }
  return <><PageHeader eyebrow="Borrower workspace / agreements" title="Agreements & authorization" description="Decrypt and inspect the signed agreement before authorizing. Terms are tied to the proposal digest and expiry." action={<Button variant="quiet" onClick={() => navigate('/')}>← Home</Button>} /><Notice tone="warning" title="Review before authorizing">Authorization can be revoked before the proposal is consumed. After consumption, the proposal ID is permanently spent and cannot be reused.</Notice><Card><SectionHeading eyebrow="Proposal inbox" title="Broker proposals" /><ProposalTable proposals={snapshot.proposals} onSelect={(proposal) => { setSelectedId(proposal.proposalId); setProposalPackage(null); setPackageError('') }} selectedId={selectedId} /></Card><Card className="form-card"><SectionHeading eyebrow="Signed exchange" title="Import the broker package" description="Import the encrypted, signed package received out-of-band. Its digest and parties are checked against the selected on-chain proposal before decryption." /><Field label="Encrypted proposal package" htmlFor="proposal-package"><input id="proposal-package" className="file-input" type="file" accept="application/json,.json" onChange={(event) => void importPackage(event)} /></Field>{proposalPackage ? <p className="field-hint" role="status">Imported package {proposalPackage.proposalId ? `for proposal ${proposalPackage.proposalId}` : 'without an on-chain ID'} · digest {proposalPackage.termsDigest.slice(0, 18)}…</p> : null}{packageError ? <p className="field-error" role="alert">{packageError}</p> : null}</Card><AgreementReviewCard proposal={snapshot.proposals.find((proposal) => proposal.proposalId === selectedId)} proposalPackage={proposalPackage} /></>
}

function authoritativeProposal(proposal: ProposalSummary, packageValue: EncryptedProposalPackage): ProposalSummary {
  const equal = (left: string | undefined, right: string, label: string) => {
    if (!left || left.toLowerCase() !== right.toLowerCase()) throw new Error(`The package ${label} does not match finalized Core state.`)
  }
  const equalList = (left: string[] | undefined, right: string[], label: string) => {
    if (!left || left.length !== right.length || left.some((value, index) => value.toLowerCase() !== right[index]!.toLowerCase())) throw new Error(`The package ${label} does not match finalized Core state.`)
  }
  if (packageValue.proposalId && packageValue.proposalId !== proposal.proposalId) throw new Error('The imported package belongs to a different proposal.')
  if (packageValue.termsDigest.toLowerCase() !== proposal.termsDigest.toLowerCase() || packageValue.borrowerId !== proposal.borrowerId || packageValue.brokerId !== proposal.brokerId || packageValue.vaultId !== proposal.vaultId || packageValue.expiresAt !== proposal.expiresAt) throw new Error('The imported package parties, digest or expiry do not match finalized Core state.')
  equalList(proposal.encryptedPrincipal, packageValue.encryptedPrincipal, 'principal ciphertexts')
  equalList(proposal.encryptedOwed, packageValue.encryptedOwed, 'owed ciphertexts')
  equalList(proposal.encryptedPayment, packageValue.encryptedPayment, 'payment ciphertexts')
  equal(proposal.principalCommitment, packageValue.principalCommitment, 'principal commitment')
  equal(proposal.owedCommitment, packageValue.owedCommitment, 'owed commitment')
  equal(proposal.paymentCommitment, packageValue.paymentCommitment, 'payment commitment')
  equal(proposal.loanAuditorPublicKey, packageValue.auditorPublicKey, 'loan auditor key')
  equal(proposal.encryptionKeyId, packageValue.auditorKeyId, 'loan auditor key ID')
  equal(proposal.borrowerKeyId, packageValue.borrowerKeyId, 'borrower key ID')
  equal(proposal.brokerKeyId, packageValue.brokerKeyId, 'broker key ID')
  if ((proposal.brokerSignature || '').toLowerCase() !== packageValue.brokerSignature.toLowerCase() || (proposal.borrowerSignature || '').toLowerCase() !== packageValue.borrowerSignature.toLowerCase()) throw new Error('The package signatures do not match finalized Core state.')
  if (proposal.brokerAuthorizationEpoch !== undefined && proposal.brokerAuthorizationEpoch !== packageValue.brokerAuthorizationEpoch) throw new Error('The package broker authorization epoch is stale.')
  if (proposal.borrowerAuthorizationEpoch !== undefined && proposal.borrowerAuthorizationEpoch !== packageValue.borrowerAuthorizationEpoch) throw new Error('The package borrower authorization epoch is stale.')
  return { ...proposal, encryptedAgreement: packageValue.encryptedAgreement, transferRecovery: packageValue.transferRecovery, owedRecovery: packageValue.owedRecovery, paymentRecovery: packageValue.paymentRecovery }
}

function AgreementReviewCard({ proposal, proposalPackage }: { proposal?: ProposalSummary; proposalPackage: EncryptedProposalPackage | null }) {
  const { adapters, snapshot, refresh, accountId } = useAppContext()
  const backupSaved = useEncryptedWalletBackup(walletBackupScope(adapters.protocol.config, accountId))
  const [decrypted, setDecrypted] = useState<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string } | null>(null)
  const [error, setError] = useState('')
  const action = useAction()
  if (!proposal || !snapshot) return <Card><EmptyState title="Select a proposal" description="Decryption is always explicit. Choose a proposal above to inspect its local preview." /></Card>
  const vault = snapshot.vaults.find((item) => item.vaultId === proposal.vaultId)
  const expired = proposal.expiresAt <= unixSecondsNow()
  const decrypt = async () => {
    setError('')
    try {
      if (!backupSaved) throw new Error('Export and confirm an encrypted wallet backup in Security before decrypting or receiving a loan.')
      if (!proposalPackage) throw new Error('Import the matching encrypted proposal package before decrypting.')
      const finalizedProposal = await adapters.protocol.getProposal(proposal.proposalId)
      const reviewedProposal = authoritativeProposal(finalizedProposal, proposalPackage)
      const result = await adapters.crypto.decryptAgreement(reviewedProposal)
      if (result.digest !== finalizedProposal.termsDigest) throw new Error('The decrypted agreement digest does not match the proposal.')
      setDecrypted(result)
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Agreement could not be decrypted locally.') }
  }
  const authorize = async () => {
    setError('')
    if (!decrypted) return setError('Decrypt and inspect the agreement before authorizing.')
    if (!backupSaved) return setError('Export and confirm an encrypted wallet backup in Security before authorizing a loan.')
    if (expired) return setError('This proposal has expired. Ask the broker to issue a new one.')
    try {
      if (!proposalPackage) return setError('Import and decrypt the matching signed proposal package first.')
      const finalizedProposal = await adapters.protocol.getProposal(proposal.proposalId)
      const reviewedProposal = authoritativeProposal(finalizedProposal, proposalPackage)
      const signature = await adapters.crypto.authorizeAgreement(reviewedProposal)
      await action.run('Authorize loan proposal', () => adapters.protocol.authorizeProposal({ proposalId: proposal.proposalId, authorizationSignature: signature.authorizationSignature }))
      void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Authorization failed.') }
  }
  const revoke = async () => {
    setError('')
    if (proposal.status === 'consumed') return setError('A consumed proposal cannot be revoked.')
    const receipt = await action.run('Revoke loan proposal', () => adapters.protocol.revokeProposal({ proposalId: proposal.proposalId }))
    if (receipt) { setDecrypted(null); void refresh() }
  }
  return <Card className="agreement-review"><SectionHeading eyebrow="Explicit local disclosure" title="Review before authorization" description={`Proposal ${proposal.proposalId} · expires ${new Date(proposal.expiresAt * 1000).toLocaleString()}`} action={<StatusBadge tone={expired ? 'danger' : proposal.status === 'consumed' ? 'neutral' : 'warning'}>{expired ? 'expired' : proposal.status.replace('_', ' ')}</StatusBadge>} /><VaultPolicyNotice vault={vault} /><div className="digest-panel"><span>Signed terms digest</span><Mono>{proposal.termsDigest}</Mono><span>Auditor key</span><Mono>{proposal.encryptionKeyId}</Mono></div>{!backupSaved ? <Notice tone="warning" title="Backup required before loan receipt">Export and confirm an encrypted wallet backup in Security before decrypting or authorizing this proposal.</Notice> : null}{decrypted ? <div className="decrypted-terms"><div className="decrypted-title"><span className="private-orb small">◈</span><strong>Decrypted in this browser</strong><StatusBadge tone="success">digest verified</StatusBadge></div><dl>{decrypted.fields.map((field) => <div key={field.label}><dt>{field.label}</dt><dd>{field.value} {field.unit}</dd></div>)}</dl><p className="field-hint">The plaintext preview is held in memory for this session. It has not been written to local storage or sent to RPC.</p></div> : <div className="locked-preview"><span className="lock-large">⌁</span><div><strong>Terms are encrypted</strong><p>Use your local key to decrypt and verify the signed agreement digest.</p></div><Button variant="secondary" onClick={() => void decrypt()} disabled={!backupSaved}>Decrypt & inspect</Button></div>}{error ? <p className="field-error" role="alert">{error}</p> : null}<div className="review-actions"><Button onClick={() => void authorize()} disabled={!backupSaved || !decrypted || expired || ['consumed', 'revoked'].includes(proposal.status)} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Authorize proposal</Button><Button variant="quiet" onClick={() => setDecrypted(null)}>Lock preview</Button><Button variant="danger" onClick={() => void revoke()} disabled={proposal.status === 'consumed' || proposal.status === 'revoked'} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Revoke proposal</Button></div>{proposal.status === 'borrower_authorized' || proposal.status === 'broker_authorized' ? <p className="field-hint">Your authorization can still be revoked until the proposal is consumed. The broker workspace funds the proposal using its private balance; the borrower does not prepare that transaction.</p> : null}<ActionFeedback state={action.state} /></Card>
}

function PrivateBalancePage() {
  const { snapshot, adapters, accountId, navigate } = useAppContext()
  const [view, setView] = useState<PrivateAccountView | null>(null)
  const [balance, setBalance] = useState<string | null>(null)
  const [error, setError] = useState('')
  if (!snapshot || !accountId) return null
  return <><PageHeader eyebrow="Borrower workspace / private rail" title="Balance & transfers" description="Your balance stays private until you choose to view it. Transfers and repayments use the latest account state." action={<Button variant="quiet" onClick={() => navigate('/')}>← Home</Button>} /><Notice tone="warning" title="Merge incoming funds before spending">Incoming transfers remain separate until you merge them. Refresh the account after a merge before starting another operation.</Notice><BalanceCard view={view} balance={balance} onLoad={async () => { setError(''); try { setView(await adapters.protocol.getPrivateAccount(accountId)); setBalance(null) } catch (caught) { setError(caught instanceof Error ? caught.message : 'Private account could not be read.') } }} onDecrypt={async () => { if (!view) return; try { setBalance(await adapters.crypto.decryptPrivateBalance(view)) } catch (caught) { setError(caught instanceof Error ? caught.message : 'Balance could not be decrypted.') } }} error={error} /><div className="two-column-grid"><ShieldCard view={view} /><UnshieldCard view={view} /></div><div className="two-column-grid"><TransferCard view={view} /><RepaymentCard loans={snapshot.loans} view={view} /></div></>
}

function ShieldCard({ view }: { view: PrivateAccountView | null }) {
  const { adapters, accountId, snapshot, refresh } = useAppContext()
  const [claimId, setClaimId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot || !accountId) return null
  const claims = snapshot.claims.filter((claim) => claim.ownerId === accountId && ['available', 'restored'].includes(claim.status))
  const claim = claims.find((item) => item.claimId === claimId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!view) throw new Error('Load your encrypted account first.')
      if (!claim) throw new Error('Choose an available public claim.')
      const proof = await adapters.crypto.prepareShield({ account: view, claimId: claim.claimId })
      const receipt = await action.run('Shield public claim', async () => requireFinalized(await adapters.protocol.shield({ claimId: claim.claimId, amount: claim.amount, proof }), 'Shield'))
      if (receipt) { setClaimId(''); await refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Shield preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Public → private" title="Shield a public claim" description="The claim amount comes from finalized account state. Once confirmed, the claim becomes part of your private balance." /><form onSubmit={submit} className="form-stack"><Field label="Public claim" htmlFor="shield-claim"><SelectInput id="shield-claim" value={claimId} onChange={(event) => setClaimId(event.target.value)}><option value="">Select available claim</option>{claims.map((item) => <option key={item.claimId} value={item.claimId}>{item.claimId} · {item.amount} base units</option>)}</SelectInput></Field>{claim ? <div className="readonly-field"><span>Authoritative amount</span><Mono>{claim.amount}</Mono><span>Status</span><StatusBadge tone="success">{claim.status}</StatusBadge></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!view || !claim} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Shield claim</Button><ActionFeedback state={action.state} /></form></Card>
}

function UnshieldCard({ view }: { view: PrivateAccountView | null }) {
  const { adapters, snapshot, refresh } = useAppContext()
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!view) throw new Error('Load your encrypted account first.')
      const amountUnits = parseAmount(amount, snapshot.asset.decimals)
      const receipt = await action.run('Unshield private balance', async () => {
        let account = await adapters.protocol.getPrivateAccount(view.accountId)
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            const proof = await adapters.crypto.prepareUnshield({ account, amount: amountUnits })
            const expected = typeof proof.operationArgs?.expected_spending_version === 'string' ? proof.operationArgs.expected_spending_version : account.spendingVersion
            return requireFinalized(await adapters.protocol.unshield({ amount: amountUnits, expectedSpendingVersion: expected, proof }), 'Unshield')
          } catch (caught) {
            if (isInboxMergeRequired(caught)) {
              const refreshed = await adapters.protocol.getPrivateAccount(view.accountId)
              const mergeProof = await adapters.crypto.prepareMerge({ account: refreshed, scope: 'holder' })
              requireFinalized(await adapters.protocol.mergeInbox({ accountId: view.accountId, expectedSpendingVersion: refreshed.spendingVersion, proof: mergeProof }), 'Inbox merge')
              account = await adapters.protocol.getPrivateAccount(view.accountId)
              continue
            }
            if (caught instanceof ProtocolError && caught.details.category === 'STALE_STATE' && attempt < 2) {
              account = await adapters.protocol.getPrivateAccount(view.accountId)
              continue
            }
            throw caught
          }
        }
        throw new Error('Unshield state changed repeatedly; refresh and try again.')
      })
      if (receipt) { setAmount(''); await refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Unshield preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Private → public" title="Unshield a private amount" description="Create a new public claim from your private balance. The operation is authorized by your encrypted account state." /><form onSubmit={submit} className="form-stack"><Field label={`Amount (${snapshot.asset.decimals} decimals)`} htmlFor="unshield-amount"><TextInput id="unshield-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field>{view ? <div className="readonly-field"><span>Spending version</span><Mono>{view.spendingVersion}</Mono><span>Claim destination</span><span>New public claim in your account</span></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!view} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Unshield amount</Button><ActionFeedback state={action.state} /></form></Card>
}

function BalanceCard({ view, balance, onLoad, onDecrypt, error }: { view: PrivateAccountView | null; balance: string | null; onLoad: () => Promise<void>; onDecrypt: () => Promise<void>; error: string }) {
  const { adapters, accountId, refresh } = useAppContext()
  const action = useAction()
  const merge = async () => {
    if (!view || !accountId) return
    const receipt = await action.run('Merge private inbox', async () => {
      const proof = await adapters.crypto.prepareMerge({ account: view, scope: 'holder' })
      return adapters.protocol.mergeInbox({ accountId, expectedSpendingVersion: view.spendingVersion, proof })
    })
    if (receipt) await refresh()
  }
  return <Card className="balance-card"><SectionHeading eyebrow="Encrypted holder account" title="Private balance" description="Your balance and incoming transfers stay encrypted until you unlock them. Merge incoming funds when you are ready to spend." action={view ? <StatusBadge tone={view.registered ? 'success' : 'danger'}>{view.registered ? 'registered' : 'not registered'}</StatusBadge> : undefined} />{view ? <><div className="balance-hero">{balance ? <><span className="balance-value">{balance}</span><span className="balance-unit">asset base units · local plaintext</span></> : <><span className="balance-value balance-locked">Encrypted</span><span className="balance-unit">decrypt only with your local key</span></>}</div><div className="balance-meta"><IdPair label="Encryption key" value={view.encryptionKeyId} /><IdPair label="Spending version" value={view.spendingVersion} /><IdPair label="Incoming ciphertext" value={view.inboxCiphertext.slice(0, 18) + '…'} /></div><div className="review-actions"><Button variant="secondary" onClick={() => void onDecrypt()}>Decrypt balance</Button><Button variant="quiet" onClick={() => void merge()} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Merge incoming balance</Button></div><ActionFeedback state={action.state} /></> : <EmptyState icon="◈" title="Private account not loaded" description="Read your encrypted account before preparing a transfer or repayment." action={<Button onClick={() => void onLoad()}>Load encrypted account</Button>} />}{error ? <p className="field-error" role="alert">{error}</p> : null}</Card>
}

function TransferCard({ view }: { view: PrivateAccountView | null }) {
  const { adapters, accountId, snapshot, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [destination, setDestination] = useState('')
  const [destinationKey, setDestinationKey] = useState<import('../lib/types').HolderKeyView | null>(null)
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!view || !accountId) throw new Error('Load your encrypted account first.')
      if (!destination.trim() || !destinationKey) throw new Error('Resolve the destination account’s registered encryption key first.')
      const amountUnits = parseAmount(amount, snapshot.asset.decimals)
      const receipt = await action.run('Send private transfer', async () => {
        let sender = await adapters.protocol.getPrivateAccount(accountId)
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            const proof = await crypto.prepareConfidentialTransfer({ sender, destinationAccountId: destination.trim(), destinationEncryptionKeyId: destinationKey.encryptionKeyId, destinationEncryptionPublicKey: destinationKey.publicKey, amount: amountUnits })
            return requireFinalized(await adapters.protocol.confidentialSend({ senderAccountId: accountId, destinationAccountId: destination.trim(), expectedSpendingVersion: sender.spendingVersion, proof }), 'Private transfer')
          } catch (caught) {
            if (isInboxMergeRequired(caught)) {
              const refreshed = await adapters.protocol.getPrivateAccount(accountId)
              const mergeProof = await crypto.prepareMerge({ account: refreshed, scope: 'holder' })
              requireFinalized(await adapters.protocol.mergeInbox({ accountId, expectedSpendingVersion: refreshed.spendingVersion, proof: mergeProof }), 'Inbox merge')
              sender = await adapters.protocol.getPrivateAccount(accountId)
              continue
            }
            if (caught instanceof ProtocolError && caught.details.category === 'STALE_STATE' && attempt < 2) {
              sender = await adapters.protocol.getPrivateAccount(accountId)
              continue
            }
            throw caught
          }
        }
        throw new Error('Private transfer state changed repeatedly; refresh and try again.')
      })
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Transfer preparation failed.') }
  }
  const resolveDestination = async () => {
    setError('')
    if (!destination.trim()) return setError('Enter a destination account first.')
    try { setDestinationKey(await adapters.protocol.getHolderEncryptionKey(destination.trim())) } catch (caught) { setDestinationKey(null); setError(caught instanceof Error ? caught.message : 'Registered destination key could not be read.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Confidential movement" title="Transfer privately" description="The recipient key is resolved from its registered account state. Amounts remain private while the transfer is prepared." /><form onSubmit={submit} className="form-stack"><Field label="Destination account" htmlFor="transfer-destination"><TextInput id="transfer-destination" value={destination} onChange={(event) => { setDestination(event.target.value); setDestinationKey(null) }} placeholder="recipient.testnet" /></Field><div className="key-resolve-row"><div className="readonly-field">{destinationKey ? <><span>Registered key</span><Mono>{destinationKey.encryptionKeyId}</Mono><span>{destinationKey.publicKey.slice(0, 18)}…</span></> : <span>Destination key not resolved</span>}</div><Button type="button" variant="secondary" onClick={() => void resolveDestination()} disabled={!destination.trim()}>Resolve key</Button></div><Field label={`Amount (${snapshot.asset.decimals} decimals)`} htmlFor="transfer-amount"><TextInput id="transfer-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!view || !destinationKey} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare private transfer</Button><ActionFeedback state={action.state} /></form></Card>
}

function RepaymentCard({ loans, view }: { loans: LoanSummary[]; view: PrivateAccountView | null }) {
  const { adapters, accountId, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [loanId, setLoanId] = useState('')
  const [mode, setMode] = useState<'regular' | 'full'>('regular')
  const [error, setError] = useState('')
  const action = useAction()
  const loan = loans.find((item) => item.loanId === loanId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!view) throw new Error('Load your encrypted account first.')
      if (!loan) throw new Error('Choose an open loan.')
      const receipt = await action.run(mode === 'full' ? 'Prepare full repayment' : 'Prepare regular repayment', async () => {
        let borrower = await adapters.protocol.getPrivateAccount(view.accountId)
        let currentLoan = loan
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            const proof = await crypto.prepareRepayment({ loan: currentLoan, borrower, mode })
            return requireFinalized(await adapters.protocol.repay({ loanId, mode, expectedLoanVersion: currentLoan.stateVersion, expectedBorrowerSpendingVersion: borrower.spendingVersion, proof }), 'Repayment')
          } catch (caught) {
            if (isInboxMergeRequired(caught)) {
              const refreshed = await adapters.protocol.getPrivateAccount(borrower.accountId)
              const mergeProof = await crypto.prepareMerge({ account: refreshed, scope: 'holder' })
              requireFinalized(await adapters.protocol.mergeInbox({ accountId: borrower.accountId, expectedSpendingVersion: refreshed.spendingVersion, proof: mergeProof }), 'Inbox merge')
              borrower = await adapters.protocol.getPrivateAccount(borrower.accountId)
              const refreshedDashboard = await adapters.protocol.getDashboard(borrower.accountId)
              currentLoan = refreshedDashboard.loans.find((item) => item.loanId === loanId) || (() => { throw new Error('The loan is no longer present in the finalized dashboard.') })()
              continue
            }
            if (!(caught instanceof ProtocolError) || caught.details.category !== 'STALE_STATE' || attempt >= 2) throw caught
            const refreshedDashboard = await adapters.protocol.getDashboard(borrower.accountId)
            currentLoan = refreshedDashboard.loans.find((item) => item.loanId === loanId) || (() => { throw new Error('The loan is no longer present in the finalized dashboard.') })()
            borrower = await adapters.protocol.getPrivateAccount(borrower.accountId)
          }
        }
        throw new Error('Repayment state changed repeatedly; refresh and try again.')
      })
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Repayment preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Loan servicing" title="Repay privately" description="A regular payment must be strictly below the encrypted amount owed. A full payment proves equality and closes the loan; the UI never guesses the hidden amount." /><form onSubmit={submit} className="form-stack"><Field label="Loan" htmlFor="repay-loan"><SelectInput id="repay-loan" value={loanId} onChange={(event) => setLoanId(event.target.value)}><option value="">Select active loan</option>{loans.filter((item) => ['active', 'impaired'].includes(item.status)).map((item) => <option key={item.loanId} value={item.loanId}>{item.loanId} · {item.status}</option>)}</SelectInput></Field><Field label="Repayment mode" htmlFor="repay-mode"><SelectInput id="repay-mode" value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}><option value="regular">Regular payment (strictly below owed)</option><option value="full">Full payment (close loan)</option></SelectInput></Field>{loan ? <div className="readonly-field"><span>Expected loan version</span><Mono>{loan.stateVersion}</Mono><span>{loan.paymentRemaining} payments remaining</span></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!view || !loan} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare repayment proof</Button><ActionFeedback state={action.state} /></form></Card>
}

function ProposalTable({ proposals, onSelect, selectedId }: { proposals: ProposalSummary[]; onSelect: (proposal: ProposalSummary) => void; selectedId: string }) {
  return <Table caption="Encrypted loan proposals"><thead><tr><th scope="col">Proposal</th><th scope="col">Broker</th><th scope="col">Expiry</th><th scope="col">Status</th><th scope="col">Digest</th></tr></thead><tbody>{proposals.length ? proposals.map((proposal) => <tr key={proposal.proposalId} className={selectedId === proposal.proposalId ? 'row-selected' : ''} onClick={() => onSelect(proposal)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onSelect(proposal) }}><td><Mono>{proposal.proposalId}</Mono></td><td><Mono>{proposal.brokerId}</Mono></td><td>{new Date(proposal.expiresAt * 1000).toLocaleString()}</td><td><StatusBadge tone={proposal.status === 'pending' || proposal.status === 'broker_authorized' ? 'warning' : proposal.status === 'consumed' ? 'success' : 'neutral'}>{proposal.status.replace('_', ' ')}</StatusBadge></td><td><Mono>{proposal.termsDigest.slice(0, 18)}…</Mono></td></tr>) : <EmptyRow message="No finalized proposals for this account." colSpan={5} />}</tbody></Table>
}

function ProposalSummary({ proposals }: { proposals: ProposalSummary[] }) {
  return <div className="summary-list">{proposals.slice(0, 4).map((proposal) => <div className="summary-line" key={proposal.proposalId}><span><Mono>{proposal.proposalId}</Mono><small>expires {new Date(proposal.expiresAt * 1000).toLocaleDateString()}</small></span><StatusBadge tone={proposal.status === 'pending' ? 'warning' : 'neutral'}>{proposal.status.replace('_', ' ')}</StatusBadge></div>)}</div>
}

function UpcomingLoans({ loans }: { loans: LoanSummary[] }) {
  const upcoming = loans.filter((loan) => ['active', 'impaired'].includes(loan.status)).sort((left, right) => left.nextPaymentDue - right.nextPaymentDue).slice(0, 5)
  if (!upcoming.length) return <EmptyState title="No upcoming dates" description="Public schedule metadata will appear when a finalized loan is associated with this wallet." />
  return <div className="upcoming-list">{upcoming.map((loan) => <div className="upcoming-row" key={loan.loanId}><div><strong>{loan.loanId}</strong><p className="muted">{loan.paymentRemaining} payments remaining · {loan.gracePeriodSeconds}s grace</p></div><time dateTime={new Date(loan.nextPaymentDue * 1000).toISOString()}>{new Date(loan.nextPaymentDue * 1000).toLocaleDateString()}</time></div>)}</div>
}

function IdPair({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><Mono>{value}</Mono></div>
}
