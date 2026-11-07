import { useMemo, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, EmptyState, Field, Metric, Mono, Money, Notice, SectionHeading, SelectInput, StatusBadge, Table, TextInput } from '../components/ui'
import { isInboxMergeRequired, requireFinalized, useAction } from '../lib/actionState'
import { downloadBrokerZeroProof, makeBrokerZeroProofPackage } from '../lib/brokerZeroProof'
import { parseAmount, parseNonNegativeAmount, unixSecondsNow } from '../lib/money'
import { CORE_MAX_PAYMENT_COUNT, ProtocolError, type AgreementDraft, type BrokerKeyPreparation, type BrokerSummary, type KeeperGrant, type LoanSummary } from '../lib/types'
import { downloadProposalPackage, makeProposalPackage } from '../lib/proposalPackage'
import { clearEncryptedWalletBackup, useEncryptedWalletBackup, walletBackupScope } from '../lib/walletBackupGate'
import { AmountCell, AssetBoundary, ConnectionGate, EmptyRow, IdLabel, PageHeader, PublicPrivateNotice, StateFreshness } from './shared'

export function BrokerPage() {
  return <ConnectionGate role="broker"><BrokerWorkspace /></ConnectionGate>
}

function BrokerWorkspace() {
  const { path, snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  if (path.startsWith('/broker/loans')) return <LoanBookPage />
  if (path.startsWith('/broker/operations')) return <OperationsPage />
  if (path.startsWith('/broker/vaults')) return <VaultBrokerPage />
  return <BrokerOverview onOpenLoans={() => navigate('/broker/loans')} onOpenOperations={() => navigate('/broker/operations')} onOpenVaults={() => navigate('/broker/vaults')} />
}

function BrokerOverview({ onOpenLoans, onOpenOperations, onOpenVaults }: { onOpenLoans: () => void; onOpenOperations: () => void; onOpenVaults: () => void }) {
  const { snapshot, refresh } = useAppContext()
  if (!snapshot) return null
  const debt = snapshot.brokers.reduce((total, broker) => total + BigInt(broker.debtTotal), 0n).toString()
  const ceiling = snapshot.brokers.reduce((total, broker) => total + BigInt(broker.debtCeiling), 0n).toString()
  const activeLoans = snapshot.loans.filter((loan) => loan.status === 'active' || loan.status === 'impaired').length
  return <>
    <PageHeader eyebrow="Broker desk" title="Underwrite with a clear boundary" description="Aggregate debt, loan status and schedule metadata are public. Terms, balances and repayment amounts stay encrypted behind their registered readers." action={<Button variant="secondary" onClick={() => void refresh()}>Refresh state</Button>} />
    <PublicPrivateNotice>Public records reveal account relationships, IDs, schedules, versions and aggregate accounting. They do not reveal private principal, amount owed, periodic payment or confidential balances.</PublicPrivateNotice>
    <AssetBoundary asset={snapshot.asset} />
    <div className="metrics-grid"><Metric label="Aggregate debt" value={<Money units={debt} decimals={snapshot.asset.decimals} />} supporting="Public draw obligation" tone={debt !== '0' ? 'warning' : 'default'} /><Metric label="Debt ceiling" value={<Money units={ceiling} decimals={snapshot.asset.decimals} />} supporting={`${snapshot.brokers.length} broker record${snapshot.brokers.length === 1 ? '' : 's'}`} /><Metric label="Active loans" value={String(activeLoans)} supporting={`${snapshot.loans.filter((loan) => loan.status === 'defaulted').length} defaulted · ${snapshot.loans.filter((loan) => loan.status === 'paid').length} paid`} /><Metric label="Accounting" value={snapshot.brokers.some((broker) => broker.checkpointStatus !== 'current') ? 'Needs review' : 'Current'} supporting="Reconciliation requires a current checkpoint" tone={snapshot.brokers.some((broker) => broker.checkpointStatus !== 'current') ? 'warning' : 'positive'} /></div>
    <div className="dashboard-grid"><Card><SectionHeading eyebrow="Portfolio" title="Broker accounts" action={<Button variant="quiet" onClick={onOpenVaults}>Manage →</Button>} /><BrokerTable brokers={snapshot.brokers} decimals={snapshot.asset.decimals} /></Card><Card><SectionHeading eyebrow="Servicing" title="Loan book" action={<Button variant="quiet" onClick={onOpenLoans}>Open book →</Button>} /><LoanSummaryList loans={snapshot.loans} /></Card></div>
    <div className="dashboard-grid"><Card><SectionHeading eyebrow="Automation" title="Keeper posture" action={<Button variant="quiet" onClick={onOpenOperations}>Operations →</Button>} /><KeeperSummary grants={snapshot.keeperGrants} /></Card><Card><SectionHeading eyebrow="Liveness" title="What needs attention?" /><AttentionList brokers={snapshot.brokers} loans={snapshot.loans} /></Card></div>
  </>
}

function VaultBrokerPage() {
  const { snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  return <><PageHeader eyebrow="Broker desk / setup" title="Vaults & broker accounts" description="Vault and broker creation are public authority changes. Configure the immutable asset and crypto profile before the first draw." action={<Button variant="quiet" onClick={() => navigate('/')}>← Desk overview</Button>} /><PublicPrivateNotice /><Card><SectionHeading eyebrow="Public vaults" title="Configured vaults" /><VaultList vaults={snapshot.vaults} decimals={snapshot.asset.decimals} /></Card><div className="two-column-grid"><CreateVaultCard /><CreateBrokerCard brokers={snapshot.brokers} /></div></>
}

function CreateVaultCard() {
  const { snapshot, adapters, refresh } = useAppContext()
  const [maximum, setMaximum] = useState('')
  const [kind, setKind] = useState<'open_ended' | 'closed_ended'>('open_ended')
  const [shareScale, setShareScale] = useState('0')
  const [epochSeconds, setEpochSeconds] = useState('86400')
  const [disclosurePolicy, setDisclosurePolicy] = useState('aggregate_only')
  const [subscriptionStart, setSubscriptionStart] = useState('')
  const [investmentStart, setInvestmentStart] = useState('')
  const [redemptionStart, setRedemptionStart] = useState('')
  const [redemptionBuffer, setRedemptionBuffer] = useState('0')
  const [transferable, setTransferable] = useState(false)
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      if (!snapshot.asset.tokenAccount) throw new Error('The asset profile has no token account.')
      const assetsMaximum = parseAmount(maximum, snapshot.asset.decimals)
      const scale = Number.parseInt(shareScale, 10)
      const epoch = Number.parseInt(epochSeconds, 10)
      if (!Number.isInteger(scale) || scale < 0 || scale > 18) throw new Error('Share scale must be an integer from 0 to 18.')
      if (!Number.isInteger(epoch) || epoch <= 0) throw new Error('Checkpoint epoch must be a positive number of seconds.')
      const phaseTimes = kind === 'closed_ended' ? {
        subscriptionStart: parseNonNegativeInteger(subscriptionStart, 'Subscription start'),
        investmentStart: parseNonNegativeInteger(investmentStart, 'Investment start'),
        redemptionStart: parseNonNegativeInteger(redemptionStart, 'Redemption start'),
        redemptionBuffer: parseNonNegativeInteger(redemptionBuffer, 'Redemption buffer'),
      } : undefined
      if (phaseTimes && (phaseTimes.subscriptionStart > phaseTimes.investmentStart || phaseTimes.investmentStart > phaseTimes.redemptionStart)) throw new Error('Closed-ended phases must be ordered subscription ≤ investment ≤ redemption.')
      const receipt = await action.run('Create vault', () => adapters.protocol.createVault({ assetAccount: snapshot.asset.tokenAccount, assetsMaximum, kind, phaseTimes, shareScale: scale, sharesTransferable: transferable, checkpointPolicy: { epochSeconds: epoch, disclosurePolicy: disclosurePolicy.trim() || 'aggregate_only' } }))
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Enter valid vault configuration.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Vault authority" title="Create a vault" description="One Core deployment may host multiple vaults for its immutable asset profile. The phase and checkpoint policy are public configuration." /><form onSubmit={submit} className="form-stack"><Field label="Underlying asset" hint="Read from the finalized AssetProfile; not caller supplied."><div className="readonly-field"><Mono>{snapshot.asset.tokenAccount || 'Not configured'}</Mono><span>{snapshot.asset.decimals} decimals</span></div></Field><Field label={`Maximum assets (${snapshot.asset.decimals} decimals)`} htmlFor="vault-maximum"><TextInput id="vault-maximum" inputMode="decimal" value={maximum} onChange={(event) => setMaximum(event.target.value)} placeholder="0.00" /></Field><Field label="Vault kind" htmlFor="vault-kind"><SelectInput id="vault-kind" value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}><option value="open_ended">Open ended</option><option value="closed_ended">Closed ended</option></SelectInput></Field>{kind === 'closed_ended' ? <div className="two-column-inner"><Field label="Subscription start (Unix seconds)" htmlFor="vault-subscription-start"><TextInput id="vault-subscription-start" inputMode="numeric" value={subscriptionStart} onChange={(event) => setSubscriptionStart(event.target.value)} placeholder={String(unixSecondsNow())} /></Field><Field label="Investment start (Unix seconds)" htmlFor="vault-investment-start"><TextInput id="vault-investment-start" inputMode="numeric" value={investmentStart} onChange={(event) => setInvestmentStart(event.target.value)} placeholder={String(unixSecondsNow() + 3600)} /></Field><Field label="Redemption start (Unix seconds)" htmlFor="vault-redemption-start"><TextInput id="vault-redemption-start" inputMode="numeric" value={redemptionStart} onChange={(event) => setRedemptionStart(event.target.value)} placeholder={String(unixSecondsNow() + 86400)} /></Field><Field label="Redemption buffer (seconds)" htmlFor="vault-redemption-buffer"><TextInput id="vault-redemption-buffer" inputMode="numeric" value={redemptionBuffer} onChange={(event) => setRedemptionBuffer(event.target.value)} /></Field></div> : null}<Field label="Share scale" htmlFor="vault-share-scale" hint="Integer decimal scale used by the Core share ledger."><TextInput id="vault-share-scale" inputMode="numeric" value={shareScale} onChange={(event) => setShareScale(event.target.value)} /></Field><Field label="Checkpoint epoch (seconds)" htmlFor="vault-epoch"><TextInput id="vault-epoch" inputMode="numeric" value={epochSeconds} onChange={(event) => setEpochSeconds(event.target.value)} /></Field><Field label="Disclosure policy" htmlFor="vault-disclosure"><TextInput id="vault-disclosure" value={disclosurePolicy} onChange={(event) => setDisclosurePolicy(event.target.value)} /></Field><label className="checkbox-field"><input type="checkbox" checked={transferable} onChange={(event) => setTransferable(event.target.checked)} /> <span>Allow public share transfers</span></label>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Create vault</Button><ActionFeedback state={action.state} /></form></Card>
}

function CreateBrokerCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { adapters, snapshot, refresh, accountId } = useAppContext()
  const backupScope = walletBackupScope(adapters.protocol.config, accountId)
  const backupSaved = useEncryptedWalletBackup(backupScope)
  const crypto = adapters.crypto
  const [vaultId, setVaultId] = useState('')
  const [keyId, setKeyId] = useState('')
  const [ceiling, setCeiling] = useState('')
  const [preparedBroker, setPreparedBroker] = useState<BrokerKeyPreparation | null>(null)
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      if (!snapshot.vaults.some((vault) => vault.vaultId === vaultId)) throw new Error('Choose an existing vault.')
      const debtCeiling = parseAmount(ceiling, snapshot.asset.decimals)
      if (!keyId.trim()) throw new Error('Provide a new broker encryption key ID.')
      if (!accountId) throw new Error('Connect the vault owner account before creating a broker.')
      const prepared = await crypto.prepareBrokerKeyRegistration({ ownerId: accountId, vaultId, encryptionKeyId: keyId.trim(), debtMaximum: debtCeiling })
      setPreparedBroker(prepared)
      if (prepared.newKeyGenerated) {
        clearEncryptedWalletBackup(backupScope)
        throw new Error('A new broker key was generated in the worker. Export and confirm an encrypted backup in Security, then return and submit again.')
      }
      if (!backupSaved) throw new Error('Export and confirm an encrypted wallet backup containing this broker key before registering it.')
      await action.run('Create broker', () => adapters.protocol.createBroker({ vaultId, brokerEncryptionKeyId: prepared.encryptionKeyId, brokerEncryptionKey: prepared.encryptionPublicKey, brokerDebtCeiling: debtCeiling, possessionProof: prepared.possessionProof }))
      void refresh()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Enter valid broker configuration.')
    }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Broker authority" title="Create a broker" description="A broker binds to one vault and a browser-held encryption key. Back up the key before registering it on-chain." />{!backupSaved ? <p className="field-hint">The first submit generates the key locally and pauses. Export and confirm an encrypted wallet backup in Security, then submit again to register it.</p> : null}{preparedBroker ? <div className="readonly-field"><span>Prepared broker</span><Mono>{preparedBroker.brokerId}</Mono><span>Public key generated locally</span></div> : null}<form onSubmit={submit} className="form-stack"><Field label="Vault" htmlFor="broker-vault"><SelectInput id="broker-vault" value={vaultId} onChange={(event) => { setVaultId(event.target.value); setPreparedBroker(null) }}><option value="">Select a vault</option>{snapshot.vaults.map((vault) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId}</option>)}</SelectInput></Field><Field label="Broker encryption key ID" htmlFor="broker-key-id" hint="This ID is bound to a generated key held in the browser."><TextInput id="broker-key-id" inputMode="numeric" value={keyId} onChange={(event) => { setKeyId(event.target.value); setPreparedBroker(null) }} placeholder="new key ID" /></Field><div className="readonly-field"><span>Public key</span><span>Generated after local preparation</span></div><Field label={`Debt ceiling (${snapshot.asset.decimals} decimals)`} htmlFor="broker-ceiling"><TextInput id="broker-ceiling" inputMode="decimal" value={ceiling} onChange={(event) => { setCeiling(event.target.value); setPreparedBroker(null) }} placeholder="0.00" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!snapshot.vaults.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>{backupSaved && preparedBroker ? 'Register broker' : 'Prepare broker key'}</Button><ActionFeedback state={action.state} /></form>{brokers.length ? <p className="form-footnote">{brokers.length} broker record{brokers.length === 1 ? '' : 's'} already visible for this account.</p> : null}</Card>
}

function LoanBookPage() {
  const { snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  return <><PageHeader eyebrow="Broker desk / loan book" title="Loan book & proposals" description="Proposal terms are encrypted for authorized readers. Public lifecycle status and schedule metadata remain visible for liveness." action={<Button variant="quiet" onClick={() => navigate('/')}>← Desk overview</Button>} /><Notice tone="warning" title="Both parties must authorize">Origination requires borrower and broker authorization over the same signed agreement. The broker workspace funds an approved proposal; the borrower reviews and signs.</Notice><Card><SectionHeading eyebrow="Public loan records" title="Loan book" /><LoanTable loans={snapshot.loans} /></Card><div className="two-column-grid"><CreateProposalCard brokers={snapshot.brokers} /><ManageLoanCard loans={snapshot.loans} /></div><BrokerOriginationCard proposals={snapshot.proposals} brokers={snapshot.brokers} /><DeleteLoanCard loans={snapshot.loans} /></>
}

function BrokerOriginationCard({ proposals, brokers }: { proposals: import('../lib/types').ProposalSummary[]; brokers: BrokerSummary[] }) {
  const { adapters, refresh, accountId } = useAppContext()
  const backupSaved = useEncryptedWalletBackup(walletBackupScope(adapters.protocol.config, accountId))
  const crypto = adapters.crypto
  const [proposalId, setProposalId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const proposal = proposals.find((item) => item.proposalId === proposalId)
  const broker = proposal ? brokers.find((item) => item.brokerId === proposal.brokerId) : undefined
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!backupSaved) throw new Error('Export and confirm an encrypted wallet backup before preparing a broker funding proof.')
      if (!proposal || !broker) throw new Error('Choose an authorized proposal with a visible broker record.')
      if (!['borrower_authorized', 'broker_authorized'].includes(proposal.status)) throw new Error('Both party authorizations must be present before funding.')
      const receipt = await action.run('Originate loan from proposal', async () => {
        let currentProposal = proposal
        let currentBroker = broker
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            const proof = await crypto.prepareBrokerOrigination({ proposal: currentProposal, broker: currentBroker })
            return requireFinalized(await adapters.protocol.originate({ proposalId, proof }), 'Origination')
          } catch (caught) {
            if (isInboxMergeRequired(caught)) {
              const brokerAccount = await adapters.protocol.getBrokerPrivateAccount(currentBroker.brokerId)
              const mergeProof = await crypto.prepareMerge({ account: brokerAccount, scope: 'broker', brokerId: currentBroker.brokerId })
              requireFinalized(await adapters.protocol.mergeBrokerInbox({ brokerId: currentBroker.brokerId, expectedSpendingVersion: brokerAccount.spendingVersion, proof: mergeProof }), 'Broker inbox merge')
              if (!accountId) throw new Error('Reconnect the broker account before retrying origination.')
              const refreshed = await adapters.protocol.getDashboard(accountId)
              currentProposal = refreshed.proposals.find((item) => item.proposalId === proposalId) || await adapters.protocol.getProposal(proposalId)
              currentBroker = refreshed.brokers.find((item) => item.brokerId === currentProposal.brokerId) || (() => { throw new Error('The broker is no longer visible in finalized state.') })()
              continue
            }
            if (caught instanceof ProtocolError && caught.details.category === 'STALE_STATE' && attempt < 2) {
              if (!accountId) throw new Error('Reconnect the broker account before retrying origination.')
              const refreshed = await adapters.protocol.getDashboard(accountId)
              currentProposal = refreshed.proposals.find((item) => item.proposalId === proposalId) || await adapters.protocol.getProposal(proposalId)
              currentBroker = refreshed.brokers.find((item) => item.brokerId === currentProposal.brokerId) || (() => { throw new Error('The broker is no longer visible in finalized state.') })()
              continue
            }
            throw caught
          }
        }
        throw new Error('Origination state changed repeatedly; refresh and try again.')
      })
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Origination could not be prepared.') }
  }
  const revoke = async () => {
    setError('')
    if (!proposal) return setError('Choose a proposal first.')
    const receipt = await action.run('Revoke loan proposal', () => adapters.protocol.revokeProposal({ proposalId: proposal.proposalId }))
    if (receipt) void refresh()
  }
  return <Card className="form-card"><SectionHeading eyebrow="Broker funding" title="Originate an authorized proposal" description="Funding uses the broker's private balance and only runs after both parties authorize the same proposal. Either party may revoke before consumption." />{!backupSaved ? <p className="field-hint">Export and confirm an encrypted wallet backup before preparing the funding operation.</p> : null}<form onSubmit={submit} className="form-stack"><Field label="Proposal" htmlFor="originate-proposal"><SelectInput id="originate-proposal" value={proposalId} onChange={(event) => setProposalId(event.target.value)}><option value="">Select authorized proposal</option>{proposals.filter((item) => ['borrower_authorized', 'broker_authorized'].includes(item.status)).map((item) => <option key={item.proposalId} value={item.proposalId}>{item.proposalId} · {item.status}</option>)}</SelectInput></Field>{proposal ? <div className="readonly-field"><span>Terms digest</span><Mono>{proposal.termsDigest}</Mono><span>Broker</span><Mono>{proposal.brokerId}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<div className="review-actions"><Button type="submit" disabled={!proposal || !broker || !backupSaved} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare funding</Button><Button type="button" variant="danger" onClick={() => void revoke()} disabled={!proposal || proposal.status === 'consumed' || proposal.status === 'revoked'} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Revoke</Button></div><ActionFeedback state={action.state} /></form></Card>
}

function CreateProposalCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { snapshot, adapters, refresh, accountId } = useAppContext()
  const backupSaved = useEncryptedWalletBackup(walletBackupScope(adapters.protocol.config, accountId))
  const [brokerId, setBrokerId] = useState('')
  const [borrowerId, setBorrowerId] = useState('')
  const [vaultId, setVaultId] = useState('')
  const [borrowerKeyId, setBorrowerKeyId] = useState('')
  const [borrowerPublicKey, setBorrowerPublicKey] = useState('')
  const [brokerKeyId, setBrokerKeyId] = useState('')
  const [brokerPublicKey, setBrokerPublicKey] = useState('')
  const [auditorKeyId, setAuditorKeyId] = useState('')
  const [auditorPublicKey, setAuditorPublicKey] = useState('')
  const [principal, setPrincipal] = useState('')
  const [initialOwed, setInitialOwed] = useState('')
  const [periodicPayment, setPeriodicPayment] = useState('')
  const [paymentCount, setPaymentCount] = useState('')
  const [paymentInterval, setPaymentInterval] = useState('2592000')
  const [gracePeriod, setGracePeriod] = useState('0')
  const [draft, setDraft] = useState<AgreementDraft | null>(null)
  const [termsDigest, setTermsDigest] = useState('')
  const [createdProposalId, setCreatedProposalId] = useState('')
  const [expiryMinutes, setExpiryMinutes] = useState('60')
  const [building, setBuilding] = useState(false)
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const buildAgreement = async () => {
    setError('')
    try {
      if (!backupSaved) throw new Error('Export and confirm an encrypted wallet backup before creating an agreement draft.')
      if (!broker) throw new Error('Choose a broker.')
      if (!borrowerId.trim() || !auditorKeyId.trim() || !auditorPublicKey.trim()) throw new Error('Provide the borrower account and fixed loan-auditor registered key.')
      if (!snapshot.vaults.some((vault) => vault.vaultId === vaultId)) throw new Error('Choose the associated vault.')
      const count = parseNonNegativeInteger(paymentCount, 'Payment count')
      if (count <= 0) throw new Error('Payment count must be positive.')
      const borrowerKey = await adapters.protocol.getHolderEncryptionKey(borrowerId.trim())
      const brokerKey = await adapters.protocol.getBrokerEncryptionKey(brokerId)
      setBorrowerKeyId(borrowerKey.encryptionKeyId)
      setBorrowerPublicKey(borrowerKey.publicKey)
      setBrokerKeyId(brokerKey.encryptionKeyId)
      setBrokerPublicKey(brokerKey.publicKey)
      const keys = {
        borrower: parseHexValue(borrowerKey.publicKey, 'Registered borrower encryption public key', 32),
        broker: parseHexValue(brokerKey.publicKey, 'Registered broker encryption public key', 32),
        issuer: parseHexValue(snapshot.asset.issuerPublicKey, 'Issuer public key', 32),
        tokenAuditor: parseHexValue(snapshot.asset.tokenAuditorPublicKey, 'Token auditor public key', 32),
        loanAuditor: parseHexValue(auditorPublicKey, 'Loan auditor public key', 32),
      }
      setBuilding(true)
      const next = await adapters.crypto.prepareAgreement({ brokerId, borrowerId: borrowerId.trim(), publicKeys: keys, principal: parseAmount(principal, snapshot.asset.decimals), initialOwed: parseAmount(initialOwed, snapshot.asset.decimals), periodicPayment: parseAmount(periodicPayment, snapshot.asset.decimals), paymentCount: count, maxPaymentCount: CORE_MAX_PAYMENT_COUNT })
      if (next.principalCiphertexts.length !== 5 || next.initialOwedCiphertexts.length !== 3 || next.periodicPaymentCiphertexts.length !== 3) throw new Error('The crypto worker returned an incomplete reader-view set.')
      if (!next.encryptedAgreement.trim()) throw new Error('The crypto worker did not return an encrypted agreement envelope.')
      setDraft(next)
      setTermsDigest('')
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Agreement preparation failed.') } finally { setBuilding(false) }
  }
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker || !draft) throw new Error('Prepare the encrypted agreement locally before publishing.')
      const count = parseNonNegativeInteger(paymentCount, 'Payment count')
      const interval = parseNonNegativeInteger(paymentInterval, 'Payment interval')
      const grace = parseNonNegativeInteger(gracePeriod, 'Grace period')
      if (count <= 0 || interval <= 0) throw new Error('Payment count and interval must be positive.')
      const principalViews = draft.principalCiphertexts.map((value) => parseHexValue(value, 'Principal ciphertext'))
      const owedViews = draft.initialOwedCiphertexts.map((value) => parseHexValue(value, 'Initial owed ciphertext'))
      const paymentViews = draft.periodicPaymentCiphertexts.map((value) => parseHexValue(value, 'Periodic payment ciphertext'))
      const receipt = await action.run('Create joint loan proposal', () => adapters.protocol.createProposal({ brokerId, borrowerId: borrowerId.trim(), vaultId, borrowerKeyId: borrowerKeyId.trim(), brokerKeyId: brokerKeyId.trim(), auditorKeyId: auditorKeyId.trim(), auditorPublicKey: parseHexValue(auditorPublicKey, 'Loan auditor public key', 32), paymentCount: count, paymentIntervalSeconds: interval, gracePeriodSeconds: grace, encryptedPrincipal: principalViews, encryptedOwed: owedViews, encryptedPayment: paymentViews, principalCommitment: parseHexValue(draft.principalCommitment, 'Principal commitment'), owedCommitment: parseHexValue(draft.owedCommitment, 'Initial owed commitment'), paymentCommitment: parseHexValue(draft.paymentCommitment, 'Periodic payment commitment'), encryptedAgreement: draft.encryptedAgreement, termsDigest: '', brokerSignature: '', borrowerSignature: '', expiresAt: unixSecondsNow() + Math.max(5, parseNonNegativeInteger(expiryMinutes, 'Expiry') || 60) * 60 }))
      if (receipt?.returnValue) {
        setCreatedProposalId(receipt.returnValue)
        try { setTermsDigest((await adapters.protocol.getProposal(receipt.returnValue)).termsDigest) } catch { /* dashboard refresh will expose the canonical digest */ }
      }
      void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Proposal could not be published.') }
  }
  const downloadPackage = async () => {
    setError('')
    try {
      if (!draft) throw new Error('Prepare the encrypted agreement first.')
      if (!createdProposalId || !termsDigest.trim()) throw new Error('Publish the proposal and read its canonical Core digest before downloading the exchange package.')
      const canonical = await adapters.protocol.getProposal(createdProposalId)
      downloadProposalPackage(makeProposalPackage({ proposalId: createdProposalId, borrowerId: borrowerId.trim(), brokerId, vaultId, termsDigest: parseHexValue(termsDigest, 'Core agreement digest', 32), encryptedAgreement: draft.encryptedAgreement, encryptedPrincipal: draft.principalCiphertexts.map((value) => parseHexValue(value, 'Principal ciphertext')), encryptedOwed: draft.initialOwedCiphertexts.map((value) => parseHexValue(value, 'Initial owed ciphertext')), encryptedPayment: draft.periodicPaymentCiphertexts.map((value) => parseHexValue(value, 'Periodic payment ciphertext')), principalCommitment: parseHexValue(draft.principalCommitment, 'Principal commitment'), owedCommitment: parseHexValue(draft.owedCommitment, 'Initial owed commitment'), paymentCommitment: parseHexValue(draft.paymentCommitment, 'Periodic payment commitment'), auditorPublicKey: parseHexValue(auditorPublicKey, 'Loan auditor public key', 32), brokerSignature: canonical.brokerSignature || '', borrowerSignature: canonical.borrowerSignature || '', borrowerKeyId: borrowerKeyId.trim(), brokerKeyId: brokerKeyId.trim(), auditorKeyId: auditorKeyId.trim(), brokerAuthorizationEpoch: canonical.brokerAuthorizationEpoch || '0', borrowerAuthorizationEpoch: canonical.borrowerAuthorizationEpoch || '0', expiresAt: canonical.expiresAt, transferRecovery: draft.transferRecovery, owedRecovery: draft.owedRecovery, paymentRecovery: draft.paymentRecovery }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Proposal package could not be downloaded.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Joint authorization" title="Build a private agreement" description="Enter the loan terms in your browser. Core receives encrypted reader views, commitments and the agreement envelope." /><Notice tone="warning" title="Protect the agreement draft">Keep this draft backed up before leaving the session. If it is lost, prepare a new agreement rather than reusing old encrypted terms.</Notice><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="proposal-broker"><SelectInput id="proposal-broker" value={brokerId} onChange={(event) => { setBrokerId(event.target.value); setVaultId(brokers.find((item) => item.brokerId === event.target.value)?.vaultId || ''); setBorrowerKeyId(''); setBorrowerPublicKey(''); setBrokerKeyId(''); setBrokerPublicKey(''); setDraft(null) }}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field><Field label="Borrower account" htmlFor="proposal-borrower"><TextInput id="proposal-borrower" value={borrowerId} onChange={(event) => { setBorrowerId(event.target.value); setBorrowerKeyId(''); setBorrowerPublicKey(''); setDraft(null) }} placeholder="borrower.testnet" /></Field><div className="two-column-inner"><Field label="Borrower encryption key" hint="Resolved from the registered Core holder state."><div className="readonly-field"><span>Key ID</span><Mono>{borrowerKeyId || 'Resolve during local preparation'}</Mono><span>Public key</span><Mono>{borrowerPublicKey ? `${borrowerPublicKey.slice(0, 18)}…` : 'Not resolved'}</Mono></div></Field><Field label="Broker encryption key" hint="Resolved from the selected broker's registered Core key."><div className="readonly-field"><span>Key ID</span><Mono>{brokerKeyId || 'Resolve during local preparation'}</Mono><span>Public key</span><Mono>{brokerPublicKey ? `${brokerPublicKey.slice(0, 18)}…` : 'Not resolved'}</Mono></div></Field></div><Field label="Vault" hint="Bound to the selected broker's registered vault."><div className="readonly-field"><Mono>{vaultId || 'Select a broker first'}</Mono></div></Field><div className="two-column-inner"><Field label="Loan auditor key ID" htmlFor="proposal-auditor"><TextInput id="proposal-auditor" value={auditorKeyId} onChange={(event) => setAuditorKeyId(event.target.value)} placeholder="auditor key ID" /></Field><Field label="Loan auditor public key" htmlFor="proposal-auditor-public"><TextInput id="proposal-auditor-public" value={auditorPublicKey} onChange={(event) => setAuditorPublicKey(event.target.value)} placeholder="32-byte canonical hex public key" /></Field></div><div className="two-column-inner"><Field label={`Principal (${snapshot.asset.decimals} decimals)`} htmlFor="proposal-principal"><TextInput id="proposal-principal" inputMode="decimal" value={principal} onChange={(event) => { setPrincipal(event.target.value); setDraft(null) }} placeholder="0.00" /></Field><Field label={`Initial amount owed (${snapshot.asset.decimals} decimals)`} htmlFor="proposal-owed"><TextInput id="proposal-owed" inputMode="decimal" value={initialOwed} onChange={(event) => { setInitialOwed(event.target.value); setDraft(null) }} placeholder="0.00" /></Field><Field label={`Periodic payment (${snapshot.asset.decimals} decimals)`} htmlFor="proposal-payment"><TextInput id="proposal-payment" inputMode="decimal" value={periodicPayment} onChange={(event) => { setPeriodicPayment(event.target.value); setDraft(null) }} placeholder="0.00" /></Field><Field label="Payment count" htmlFor="proposal-count"><TextInput id="proposal-count" inputMode="numeric" value={paymentCount} onChange={(event) => { setPaymentCount(event.target.value); setDraft(null) }} placeholder="12" /></Field></div><div className="two-column-inner"><Field label="Payment interval (seconds)" htmlFor="proposal-interval"><TextInput id="proposal-interval" inputMode="numeric" value={paymentInterval} onChange={(event) => setPaymentInterval(event.target.value)} /></Field><Field label="Grace period (seconds)" htmlFor="proposal-grace"><TextInput id="proposal-grace" inputMode="numeric" value={gracePeriod} onChange={(event) => setGracePeriod(event.target.value)} /></Field></div><Button type="button" variant="secondary" onClick={() => void buildAgreement()} busy={building}>Encrypt agreement locally</Button>{draft ? <div className="readonly-field"><span>Agreement draft ready</span><Mono>{draft.draftId}</Mono><span>Reader views and recovery data are ready</span></div> : null}<div className="two-column-inner"><Field label="Core agreement digest" hint="Read from finalized Core after publishing."><div className="readonly-field"><Mono>{termsDigest || 'Set after proposal publication'}</Mono></div></Field><Field label="Expires in (minutes)" htmlFor="proposal-expiry"><TextInput id="proposal-expiry" inputMode="numeric" value={expiryMinutes} onChange={(event) => setExpiryMinutes(event.target.value)} /></Field></div>{error ? <p className="field-error" role="alert">{error}</p> : null}<div className="review-actions"><Button type="submit" disabled={!draft || !brokers.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Publish broker-authorized proposal</Button><Button type="button" variant="quiet" onClick={() => void downloadPackage()} disabled={!draft}>Download encrypted package</Button></div><ActionFeedback state={action.state} /></form></Card>
}

function ManageLoanCard({ loans }: { loans: LoanSummary[] }) {
  const { adapters, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [loanId, setLoanId] = useState('')
  const [operation, setOperation] = useState<'impair' | 'unimpair' | 'default'>('impair')
  const [error, setError] = useState('')
  const action = useAction()
  const selected = loans.find((loan) => loan.loanId === loanId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    if (!selected) return setError('Choose an active loan.')
    if (selected.status === 'paid' || selected.status === 'deleted') return setError('Closed loans cannot be managed.')
    try {
      const preparation = await crypto.prepareLoanManagement({ loan: selected, operation })
      const receipt = await action.run(`Mark loan ${operation}`, () => adapters.protocol.manageLoan({ loanId, operation, expectedLoanVersion: selected.stateVersion, preparation }))
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Loan management could not be prepared.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Servicing authority" title="Manage delinquency" description="Default timing is checked by Core against the public due date and grace period. Private exposure is not guessed by this UI." /><form onSubmit={submit} className="form-stack"><Field label="Loan" htmlFor="manage-loan"><SelectInput id="manage-loan" value={loanId} onChange={(event) => setLoanId(event.target.value)}><option value="">Select loan</option>{loans.filter((loan) => !['paid', 'deleted'].includes(loan.status)).map((loan) => <option key={loan.loanId} value={loan.loanId}>{loan.loanId} · {loan.status}</option>)}</SelectInput></Field><Field label="Operation" htmlFor="manage-operation"><SelectInput id="manage-operation" value={operation} onChange={(event) => setOperation(event.target.value as typeof operation)}><option value="impair">Impair</option><option value="unimpair">Unimpair</option><option value="default">Default (after grace)</option></SelectInput></Field>{selected ? <div className="readonly-field"><span>Expected loan version</span><Mono>{selected.stateVersion}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!selected} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Submit management</Button><ActionFeedback state={action.state} /></form></Card>
}

function DeleteLoanCard({ loans }: { loans: LoanSummary[] }) {
  const { adapters, refresh } = useAppContext()
  const [loanId, setLoanId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const selected = loans.find((loan) => loan.loanId === loanId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!selected || !['paid', 'defaulted'].includes(selected.status)) throw new Error('Only paid or defaulted loans can be deleted from the display book.')
      const receipt = await action.run('Delete closed loan record', () => adapters.protocol.deleteLoan({ loanId: selected.loanId }))
      if (receipt) { setLoanId(''); void refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Closed loan deletion failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Book maintenance" title="Delete a closed loan record" description="Deletion removes only the public display record after Core retains its terminal tombstone and accounting evidence. It never erases recovery history." /><form onSubmit={submit} className="form-stack"><Field label="Closed loan" htmlFor="delete-loan"><SelectInput id="delete-loan" value={loanId} onChange={(event) => setLoanId(event.target.value)}><option value="">Select paid or defaulted loan</option>{loans.filter((loan) => ['paid', 'defaulted'].includes(loan.status)).map((loan) => <option key={loan.loanId} value={loan.loanId}>{loan.loanId} · {loan.status}</option>)}</SelectInput></Field>{selected ? <div className="readonly-field"><span>Final state</span><StatusBadge tone={selected.status === 'defaulted' ? 'danger' : 'success'}>{selected.status}</StatusBadge><span>Version</span><Mono>{selected.stateVersion}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!selected} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Delete display record</Button><ActionFeedback state={action.state} /></form></Card>
}

function OperationsPage() {
  const { snapshot, navigate } = useAppContext()
  if (!snapshot) return null
  return <><PageHeader eyebrow="Broker desk / operations" title="Servicing operations" description="Draw, merge, settle and reconcile are separate on-chain operations with explicit versions and failure states." action={<Button variant="quiet" onClick={() => navigate('/')}>← Desk overview</Button>} /><Notice tone="info" title="Keeper scope is narrow by design">Delegates can run only the operations you grant, within their limits and expiry.</Notice><div className="two-column-grid"><DrawCard brokers={snapshot.brokers} /><MergeCard brokers={snapshot.brokers} /></div><div className="two-column-grid"><SettlementCard brokers={snapshot.brokers} /><ReconcileCard brokers={snapshot.brokers} /></div><BrokerClosureCard brokers={snapshot.brokers} /><KeeperCard brokers={snapshot.brokers} grants={snapshot.keeperGrants} /></>
}

function DrawCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { snapshot, adapters, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [brokerId, setBrokerId] = useState('')
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker) throw new Error('Choose a broker.')
      const units = parseAmount(amount, snapshot.asset.decimals)
      const proof = await crypto.prepareDraw({ broker, amount: units, expectedSpendingVersion: broker.spendingVersion })
      await action.run('Draw vault liquidity', () => adapters.protocol.draw({ brokerId, amount: units, expectedSpendingVersion: broker.spendingVersion, proof }).then((receipt) => requireFinalized(receipt, 'Draw')))
      void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Draw preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Public draw" title="Draw vault liquidity" description="A draw increases public broker debt and credits the broker's encrypted spending balance. It uses the current account state." /><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="draw-broker"><SelectInput id="draw-broker" value={brokerId} onChange={(event) => setBrokerId(event.target.value)}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field><Field label={`Amount (${snapshot.asset.decimals} decimals)`} htmlFor="draw-amount"><TextInput id="draw-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field>{broker ? <div className="readonly-field"><span>Spending version</span><Mono>{broker.spendingVersion}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare & draw</Button><ActionFeedback state={action.state} /></form></Card>
}

function MergeCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { adapters, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [brokerId, setBrokerId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    if (!broker) return setError('Choose a broker.')
    try {
      const account = await adapters.protocol.getBrokerPrivateAccount(brokerId)
      const proof = await crypto.prepareMerge({ account, scope: 'broker', brokerId })
      const receipt = await action.run('Merge broker inbox', () => adapters.protocol.mergeBrokerInbox({ brokerId, expectedSpendingVersion: account.spendingVersion, proof }).then((result) => requireFinalized(result, 'Inbox merge')))
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Broker inbox merge preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Inbox stability" title="Merge incoming balance" description="Merge incoming funds before preparing another operation. Refresh the account after every merge." /><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="merge-broker"><SelectInput id="merge-broker" value={brokerId} onChange={(event) => setBrokerId(event.target.value)}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field>{broker ? <><div className="readonly-field"><span>Spending version used for merge</span><Mono>{broker.spendingVersion}</Mono></div><p className="field-hint">Merge is owner- or scoped-keeper-authorized; it is not a free-form balance replacement.</p></> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Merge incoming balance</Button><ActionFeedback state={action.state} /></form></Card>
}

function SettlementCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { snapshot, adapters, accountId, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [brokerId, setBrokerId] = useState('')
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  if (!snapshot) return null
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker) throw new Error('Choose a broker.')
      const units = parseAmount(amount, snapshot.asset.decimals)
      const receipt = await action.run('Settle broker funds', async () => {
        let current = broker
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            if (!current.accountingVersion) throw new Error('The finalized broker view has no accounting version.')
            const proof = await crypto.prepareSettlement({ broker: current, amount: units, expectedSpendingVersion: current.spendingVersion })
            return requireFinalized(await adapters.protocol.settle({ brokerId, amount: units, expectedSpendingVersion: current.spendingVersion, expectedAccountingVersion: current.accountingVersion, proof }), 'Settlement')
          } catch (caught) {
            if (isInboxMergeRequired(caught)) {
              if (!accountId) throw new Error('Reconnect the broker account before merging its inbox.')
              const brokerAccount = await adapters.protocol.getBrokerPrivateAccount(brokerId)
              const mergeProof = await crypto.prepareMerge({ account: brokerAccount, scope: 'broker', brokerId })
              requireFinalized(await adapters.protocol.mergeBrokerInbox({ brokerId, expectedSpendingVersion: brokerAccount.spendingVersion, proof: mergeProof }), 'Broker inbox merge')
              const refreshed = await adapters.protocol.getDashboard(accountId)
              current = refreshed.brokers.find((item) => item.brokerId === brokerId) || (() => { throw new Error('The broker is no longer visible in finalized state.') })()
              continue
            }
            if (!(caught instanceof ProtocolError) || caught.details.category !== 'STALE_STATE' || attempt >= 2 || !accountId) throw caught
            const refreshed = await adapters.protocol.getDashboard(accountId)
            current = refreshed.brokers.find((item) => item.brokerId === brokerId) || (() => { throw new Error('The broker is no longer visible in finalized state.') })()
          }
        }
        throw new Error('Settlement state changed repeatedly; refresh and try again.')
      })
      if (receipt) void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Settlement preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Public settlement" title="Settle broker funds" description="Settlement repays aggregate broker debt first; only excess cash is recognized as vault yield by the Core accounting checkpoint." /><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="settle-broker"><SelectInput id="settle-broker" value={brokerId} onChange={(event) => setBrokerId(event.target.value)}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field><Field label={`Public settlement amount (${snapshot.asset.decimals} decimals)`} htmlFor="settle-amount"><TextInput id="settle-amount" inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="0.00" /></Field>{broker ? <div className="readonly-field"><span>Expected spending version</span><Mono>{broker.spendingVersion}</Mono></div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare & settle</Button><ActionFeedback state={action.state} /></form></Card>
}

function ReconcileCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { adapters, refresh } = useAppContext()
  const crypto = adapters.crypto
  const [brokerId, setBrokerId] = useState('')
  const [prepared, setPrepared] = useState(false)
  const [checkpointId, setCheckpointId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker) throw new Error('Choose a broker.')
      if (!prepared) {
        const receipt = await action.run('Prepare accounting checkpoint', async () => {
          const next = await adapters.protocol.prepareReconciliation({ brokerId })
          if (!next.returnValue) throw new Error('Core did not return the finalized checkpoint ID. No reconciliation proof can be prepared.')
          return next
        })
        if (receipt) {
          const nextCheckpointId = receipt.returnValue
          if (!nextCheckpointId) throw new Error('Core did not return the finalized checkpoint ID. No reconciliation proof can be prepared.')
          setCheckpointId(nextCheckpointId)
          setPrepared(true)
          void refresh()
        }
      } else {
        const expectedBookVersion = broker.bookVersion || broker.spendingVersion
        const proof = await crypto.prepareReconciliation({ broker, expectedBookVersion, checkpointId })
        const receipt = await action.run('Reconcile credit book', () => adapters.protocol.reconcileCredit({ brokerId, expectedBookVersion, proof }))
        if (receipt) { setPrepared(false); void refresh() }
      }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Reconciliation preparation failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Aggregate accounting" title="Checkpoint credit book" description="Prepare the next checkpoint, then reconcile the public credit book against it. Individual amounts remain encrypted." /><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="reconcile-broker"><SelectInput id="reconcile-broker" value={brokerId} onChange={(event) => { setBrokerId(event.target.value); setPrepared(false); setCheckpointId('') }}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field>{broker ? <div className="readonly-field"><span>Book version</span><Mono>{broker.bookVersion || broker.spendingVersion}</Mono><StateFreshness status={broker.checkpointStatus} />{checkpointId ? <><span>Checkpoint</span><Mono>{checkpointId}</Mono></> : null}</div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" variant="secondary" disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>{prepared ? 'Prepare & reconcile' : 'Prepare checkpoint'}</Button><ActionFeedback state={action.state} /></form></Card>
}

function BrokerClosureCard({ brokers }: { brokers: BrokerSummary[] }) {
  const { adapters, refresh } = useAppContext()
  const [brokerId, setBrokerId] = useState('')
  const [preparedProof, setPreparedProof] = useState<import('../lib/types').PreparedProof | null>(null)
  const [error, setError] = useState('')
  const action = useAction()
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const prepare = async () => {
    setError('')
    try {
      if (!broker) throw new Error('Choose a broker.')
      setPreparedProof(await adapters.crypto.prepareBrokerClosure({ brokerId }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Broker closure could not be prepared.') }
  }
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker) throw new Error('Choose a broker.')
      const proof = preparedProof || await adapters.crypto.prepareBrokerClosure({ brokerId })
      const receipt = await action.run('Close broker account', () => adapters.protocol.deleteBroker({ brokerId, proof }))
      if (receipt) { setBrokerId(''); setPreparedProof(null); void refresh() }
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Broker closure could not be prepared.') }
  }
  const download = () => {
    setError('')
    try {
      if (!broker || !preparedProof) throw new Error('Prepare the current zero-state proof first.')
      const value = preparedProof.operationArgs?.zero_proof
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('The worker returned no broker zero-proof envelope.')
      downloadBrokerZeroProof(makeBrokerZeroProofPackage({ brokerId, vaultId: broker.vaultId, profileHash: preparedProof.profileHash, artifactHash: preparedProof.artifactHash, proof: preparedProof }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Broker zero-proof download failed.') }
  }
  return <Card className="form-card"><SectionHeading eyebrow="Book maintenance" title="Close a broker account" description="Close only after all broker balances and obligations are settled. You can share the closure package with the final vault owner." /><form onSubmit={submit} className="form-stack"><Field label="Broker" htmlFor="close-broker"><SelectInput id="close-broker" value={brokerId} onChange={(event) => { setBrokerId(event.target.value); setPreparedProof(null) }}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId} · debt {item.debtTotal}</option>)}</SelectInput></Field>{broker ? <div className="readonly-field"><span>Public debt</span><Mono>{broker.debtTotal}</Mono><span>Accounting</span><StateFreshness status={broker.checkpointStatus} />{preparedProof ? <><span>Zero state ready</span><Mono>broker {brokerId}</Mono></> : null}</div> : null}{error ? <p className="field-error" role="alert">{error}</p> : null}<div className="review-actions"><Button type="button" variant="secondary" onClick={() => void prepare()} disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Prepare closure</Button><Button type="submit" variant="danger" disabled={!broker} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Close broker account</Button><Button type="button" variant="quiet" onClick={download} disabled={!preparedProof}>Download closure package</Button></div><ActionFeedback state={action.state} /></form></Card>
}

function KeeperCard({ brokers, grants }: { brokers: BrokerSummary[]; grants: KeeperGrant[] }) {
  const { adapters, refresh } = useAppContext()
  const [brokerId, setBrokerId] = useState('')
  const [delegateId, setDelegateId] = useState('')
  const [delegateKeyId, setDelegateKeyId] = useState('')
  const [scope, setScope] = useState<KeeperGrant['scope'][number]>('merge')
  const [maxAmountPerOperation, setMaxAmountPerOperation] = useState('')
  const [maxAmountPerWindow, setMaxAmountPerWindow] = useState('')
  const [windowHours, setWindowHours] = useState('24')
  const [delegateEpoch, setDelegateEpoch] = useState('0')
  const [expiryHours, setExpiryHours] = useState('24')
  const [revokeId, setRevokeId] = useState('')
  const [error, setError] = useState('')
  const action = useAction()
  const broker = brokers.find((item) => item.brokerId === brokerId)
  const submitGrant = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    try {
      if (!broker || !delegateId.trim() || !delegateKeyId.trim()) throw new Error('Choose a broker and provide the delegate account and registered key ID.')
      const maxOperation = parseNonNegativeAmount(maxAmountPerOperation, 0)
      const maxWindow = parseNonNegativeAmount(maxAmountPerWindow, 0)
      const windowSeconds = Math.max(1, Number.parseInt(windowHours, 10) || 24) * 3600
      const epoch = delegateEpoch.trim()
      if (!/^\d+$/.test(epoch)) throw new Error('Delegate authorization epoch must be a non-negative integer.')
      if (BigInt(maxOperation) <= 0n || BigInt(maxWindow) < BigInt(maxOperation)) throw new Error('Window limit must be at least the per-operation limit, and both must be positive.')
      await action.run('Grant keeper scope', () => adapters.protocol.grantKeeper({ brokerId, delegateId: delegateId.trim(), delegateKeyId: delegateKeyId.trim(), scope: [scope], maxAmountPerOperation: maxOperation, maxAmountPerWindow: maxWindow, windowSeconds, delegateEpoch: epoch, expiresAt: unixSecondsNow() + Math.max(1, Number.parseInt(expiryHours, 10) || 24) * 3600 }))
      void refresh()
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Keeper grant could not be prepared.') }
  }
  const submitRevoke = async (event: React.FormEvent) => {
    event.preventDefault(); setError('')
    const grant = grants.find((item) => item.delegateId === revokeId)
    if (!grant) return setError('Choose an active grant.')
    await action.run('Revoke keeper scope', () => adapters.protocol.revokeKeeper({ brokerId: grant.brokerId, delegateId: grant.delegateId, expectedEpoch: grant.epoch }))
    void refresh()
  }
  return <Card className="form-card keeper-card"><SectionHeading eyebrow="Scoped automation" title="Keeper grants" description="Set each delegate's allowed operation, limits, validity window and expiry." /><div className="two-column-inner"><form onSubmit={submitGrant} className="form-stack"><h3>Grant a scope</h3><Field label="Broker" htmlFor="keeper-broker"><SelectInput id="keeper-broker" value={brokerId} onChange={(event) => setBrokerId(event.target.value)}><option value="">Select broker</option>{brokers.map((item) => <option key={item.brokerId} value={item.brokerId}>{item.brokerId}</option>)}</SelectInput></Field><Field label="Delegate account" htmlFor="keeper-delegate"><TextInput id="keeper-delegate" value={delegateId} onChange={(event) => setDelegateId(event.target.value)} placeholder="keeper.testnet" /></Field><Field label="Delegate key ID" htmlFor="keeper-key-id" hint="Registered function-call/encryption authorization key ID."><TextInput id="keeper-key-id" inputMode="numeric" value={delegateKeyId} onChange={(event) => setDelegateKeyId(event.target.value)} placeholder="key ID" /></Field><Field label="Operation scope" htmlFor="keeper-scope"><SelectInput id="keeper-scope" value={scope} onChange={(event) => setScope(event.target.value as typeof scope)}><option value="merge">Merge inbox</option><option value="settle">Settle</option></SelectInput></Field><div className="two-column-inner"><Field label="Per-operation limit (base units)" htmlFor="keeper-max-operation"><TextInput id="keeper-max-operation" inputMode="numeric" value={maxAmountPerOperation} onChange={(event) => setMaxAmountPerOperation(event.target.value)} placeholder="1000000" /></Field><Field label="Per-window limit (base units)" htmlFor="keeper-max-window"><TextInput id="keeper-max-window" inputMode="numeric" value={maxAmountPerWindow} onChange={(event) => setMaxAmountPerWindow(event.target.value)} placeholder="5000000" /></Field></div><div className="two-column-inner"><Field label="Window (hours)" htmlFor="keeper-window"><TextInput id="keeper-window" inputMode="numeric" value={windowHours} onChange={(event) => setWindowHours(event.target.value)} /></Field><Field label="Delegate epoch" htmlFor="keeper-epoch"><TextInput id="keeper-epoch" inputMode="numeric" value={delegateEpoch} onChange={(event) => setDelegateEpoch(event.target.value)} /></Field></div><Field label="Expires in (hours)" htmlFor="keeper-expiry"><TextInput id="keeper-expiry" inputMode="numeric" value={expiryHours} onChange={(event) => setExpiryHours(event.target.value)} /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<Button type="submit" disabled={!brokers.length} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Grant scope</Button></form><form onSubmit={submitRevoke} className="form-stack"><h3>Revoke a grant</h3><Field label="Active delegate" htmlFor="keeper-revoke"><SelectInput id="keeper-revoke" value={revokeId} onChange={(event) => setRevokeId(event.target.value)}><option value="">Select delegate</option>{grants.filter((grant) => !grant.revoked).map((grant) => <option key={`${grant.brokerId}-${grant.delegateId}`} value={grant.delegateId}>{grant.delegateId} · {grant.scope.join(', ')}</option>)}</SelectInput></Field><p className="field-hint">Revocation increments the public epoch. Already submitted operations still follow their own proof and replay rules.</p><Button type="submit" variant="danger" disabled={!grants.some((grant) => !grant.revoked)} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Revoke grant</Button></form></div><ActionFeedback state={action.state} /></Card>
}

function BrokerTable({ brokers, decimals }: { brokers: BrokerSummary[]; decimals: number }) {
  return <Table caption="Public broker accounts"><thead><tr><th scope="col">Broker</th><th scope="col">Vault</th><th scope="col">Debt</th><th scope="col">Ceiling</th><th scope="col">State</th></tr></thead><tbody>{brokers.length ? brokers.map((broker) => <tr key={broker.brokerId}><td><Mono>{broker.brokerId}</Mono><small>{broker.ownerId}</small></td><td><Mono>{broker.vaultId}</Mono></td><td><AmountCell units={broker.debtTotal} decimals={decimals} /></td><td><AmountCell units={broker.debtCeiling} decimals={decimals} /></td><td><StateFreshness status={broker.checkpointStatus} /><small>spend v{broker.spendingVersion}</small></td></tr>) : <EmptyRow message="No broker records for this wallet." colSpan={5} />}</tbody></Table>
}

function VaultList({ vaults, decimals }: { vaults: import('../lib/types').VaultSummary[]; decimals: number }) {
  return <Table caption="Public vault records"><thead><tr><th scope="col">Vault</th><th scope="col">Owner / broker</th><th scope="col">Assets</th><th scope="col">Available</th><th scope="col">Phase</th></tr></thead><tbody>{vaults.length ? vaults.map((vault) => <tr key={vault.vaultId}><td><Mono>{vault.vaultId}</Mono><small>{vault.assetAccount}</small></td><td><small>{vault.ownerId}</small><small>{vault.brokerId || 'No broker'}</small></td><td><AmountCell units={vault.assetsTotal} decimals={decimals} /></td><td><AmountCell units={vault.assetsAvailable} decimals={decimals} /></td><td><StatusBadge tone={vault.phase === 'open' ? 'success' : 'warning'}>{vault.phase.replace('_', ' ')}</StatusBadge></td></tr>) : <EmptyRow message="No finalized vault records." colSpan={5} />}</tbody></Table>
}

function LoanTable({ loans }: { loans: LoanSummary[] }) {
  return <Table caption="Public loan records"><thead><tr><th scope="col">Loan</th><th scope="col">Parties</th><th scope="col">Status</th><th scope="col">Schedule</th><th scope="col">Version</th></tr></thead><tbody>{loans.length ? loans.map((loan) => <tr key={loan.loanId}><td><Mono>{loan.loanId}</Mono><small>proposal {loan.proposalId}</small></td><td><small>Broker {loan.brokerId}</small><small>Borrower {loan.borrowerId}</small></td><td><StatusBadge tone={loan.status === 'active' ? 'success' : loan.status === 'defaulted' ? 'danger' : loan.status === 'impaired' ? 'warning' : 'neutral'}>{loan.status}</StatusBadge></td><td><span>{loan.paymentRemaining}/{loan.paymentCount} remaining</span><small>next due {new Date(loan.nextPaymentDue * 1000).toLocaleDateString()}</small></td><td><Mono>{loan.stateVersion}</Mono></td></tr>) : <EmptyRow message="No finalized loans for this broker." colSpan={5} />}</tbody></Table>
}

function LoanSummaryList({ loans }: { loans: LoanSummary[] }) {
  if (!loans.length) return <EmptyState title="No loans in view" description="Jointly authorized proposals and originated loans will appear here." />
  return <div className="summary-list">{loans.slice(0, 5).map((loan) => <div className="summary-line" key={loan.loanId}><span><Mono>{loan.loanId}</Mono><small>{loan.paymentRemaining}/{loan.paymentCount} payments remaining</small></span><StatusBadge tone={loan.status === 'active' ? 'success' : loan.status === 'defaulted' ? 'danger' : 'warning'}>{loan.status}</StatusBadge></div>)}</div>
}

function KeeperSummary({ grants }: { grants: KeeperGrant[] }) {
  const active = grants.filter((grant) => !grant.revoked && grant.expiresAt > unixSecondsNow())
  if (!active.length) return <EmptyState title="No active delegates" description="Scoped keeper grants can automate inbox merge and settlement when explicitly authorized." />
  return <div className="summary-list">{active.slice(0, 4).map((grant) => <div className="summary-line" key={`${grant.brokerId}-${grant.delegateId}`}><span><Mono>{grant.delegateId}</Mono><small>{grant.scope.join(' · ')}</small></span><StatusBadge tone="success">until {new Date(grant.expiresAt * 1000).toLocaleDateString()}</StatusBadge></div>)}</div>
}

function AttentionList({ brokers, loans }: { brokers: BrokerSummary[]; loans: LoanSummary[] }) {
  const attention = [...brokers.filter((broker) => broker.checkpointStatus !== 'current').map((broker) => `Checkpoint ${broker.brokerId}`), ...loans.filter((loan) => loan.status === 'impaired').map((loan) => `Impaired loan ${loan.loanId}`), ...loans.filter((loan) => loan.status === 'defaulted').map((loan) => `Defaulted loan ${loan.loanId}`)]
  return attention.length ? <div className="attention-list">{attention.slice(0, 6).map((item) => <div key={item}><span className="attention-dot" />{item}</div>)}</div> : <EmptyState title="No pending alerts" description="The adapter returned no stale checkpoints or impaired records." />
}

function parseCiphertextViews(input: string, expected: number, label: string): string[] {
  const values = input.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean)
  if (values.length !== expected) throw new Error(`${label} requires exactly ${expected} ciphertext views.`)
  if (values.some((value) => value.replace(/^0x/, '').length % 2 !== 0 || !/^(?:0x)?[a-f\d]+$/i.test(value))) throw new Error(`${label} views must be canonical hex ciphertexts.`)
  return values.map((value) => value.replace(/^0x/, ''))
}

function parseHexValue(input: string, label: string, expectedBytes?: number): string {
  const value = input.trim().replace(/^0x/, '')
  if (!value || value.length % 2 !== 0 || !/^[a-f\d]+$/i.test(value)) throw new Error(`${label} must be canonical hex bytes.`)
  if (expectedBytes !== undefined && value.length !== expectedBytes * 2) throw new Error(`${label} must be exactly ${expectedBytes} bytes.`)
  return value
}

function parseNonNegativeInteger(input: string, label: string): number {
  if (!/^\d+$/.test(input.trim())) throw new Error(`${label} must be a non-negative integer.`)
  const value = Number(input)
  if (!Number.isSafeInteger(value)) throw new Error(`${label} exceeds the safe integer range.`)
  return value
}
