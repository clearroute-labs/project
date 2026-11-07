import { useEffect, useRef, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, Field, Mono, Notice, SectionHeading, StatusBadge, TextInput } from '../components/ui'
import { useAction } from '../lib/actionState'
import { decryptWalletBackup, downloadWalletBackup, encryptWalletBackup, readWalletBackup } from '../lib/walletVault'
import { clearEncryptedWalletBackup, markEncryptedWalletBackupSaved, useEncryptedWalletBackup, walletBackupScope } from '../lib/walletBackupGate'
import type { AuthorizationKeyRegistration, EncryptedWalletBackup, KeyRegistration } from '../lib/types'
import { parseAmount } from '../lib/money'
import { PageHeader } from './shared'

export function SecurityPage() {
  const { adapters, accountId, cryptoStatus, snapshot } = useAppContext()
  const backupScope = walletBackupScope(adapters.protocol.config, accountId)
  const backupSaved = useEncryptedWalletBackup(backupScope)
  const [registration, setRegistration] = useState<KeyRegistration | null>(null)
  const [authorizationRegistration, setAuthorizationRegistration] = useState<AuthorizationKeyRegistration | null>(null)
  const [holderRegistered, setHolderRegistered] = useState(false)
  const [authorizationRegistered, setAuthorizationRegistered] = useState(false)
  const [keyGenerating, setKeyGenerating] = useState(false)
  const [authorizationGenerating, setAuthorizationGenerating] = useState(false)
  const [backupConfirmationPending, setBackupConfirmationPending] = useState(false)
  const [backupMessage, setBackupMessage] = useState('')
  const [backupError, setBackupError] = useState('')
  const [exportPassphrase, setExportPassphrase] = useState('')
  const [exportConfirm, setExportConfirm] = useState('')
  const [importPassphrase, setImportPassphrase] = useState('')
  const [selectedBackup, setSelectedBackup] = useState<EncryptedWalletBackup | null>(null)
  const [keeperBrokerIds, setKeeperBrokerIds] = useState<string[]>([])
  const [keeperPassphrase, setKeeperPassphrase] = useState('')
  const [keeperConfirm, setKeeperConfirm] = useState('')
  const [storageBalance, setStorageBalance] = useState<string | null>(null)
  const [storageError, setStorageError] = useState('')
  const [storageDeposit, setStorageDeposit] = useState('0.1')
  const fileInput = useRef<HTMLInputElement>(null)
  const keyAction = useAction()
  const authorizationAction = useAction()
  const storageAction = useAction()
  const refreshStorage = async () => {
    if (!accountId) { setStorageBalance(null); return }
    try {
      setStorageError('')
      setStorageBalance(await adapters.protocol.storageBalanceOf(accountId))
    } catch (caught) {
      setStorageBalance(null)
      setStorageError(caught instanceof Error ? caught.message : 'Storage budget could not be read.')
    }
  }
  const generateKey = async () => {
    setBackupError('')
    setKeyGenerating(true)
    try {
      setRegistration(await adapters.crypto.createKeyRegistration())
      setHolderRegistered(false)
      clearEncryptedWalletBackup(backupScope)
      setBackupConfirmationPending(false)
      setBackupMessage('A new holder key is ready in the worker. Export and confirm an encrypted backup before registering it on-chain.')
    } catch (caught) {
      setBackupError(caught instanceof Error ? caught.message : 'Key generation failed.')
    } finally {
      setKeyGenerating(false)
    }
  }
  const registerKey = async () => {
    setBackupError('')
    if (!registration) return setBackupError('Generate a holder key first.')
    if (!backupSaved) return setBackupError('Export and confirm an encrypted backup containing this key before registering it.')
    const receipt = await keyAction.run('Register encryption key', () => adapters.protocol.registerHolder(registration))
    if (receipt?.status === 'succeeded') setHolderRegistered(true)
  }
  const generateAuthorizationKey = async () => {
    setBackupError('')
    setAuthorizationGenerating(true)
    try {
      setAuthorizationRegistration(await adapters.crypto.createAuthorizationKeyRegistration())
      setAuthorizationRegistered(false)
      clearEncryptedWalletBackup(backupScope)
      setBackupConfirmationPending(false)
      setBackupMessage('A new authorization key is ready in the worker. Export and confirm an encrypted backup before registering it on-chain.')
    } catch (caught) {
      setBackupError(caught instanceof Error ? caught.message : 'Authorization-key generation failed.')
    } finally {
      setAuthorizationGenerating(false)
    }
  }
  const registerAuthorizationKey = async () => {
    setBackupError('')
    if (!authorizationRegistration) return setBackupError('Generate an authorization key first.')
    if (!backupSaved) return setBackupError('Export and confirm an encrypted backup containing this key before registering it.')
    const receipt = await authorizationAction.run('Register proposal authorization key', () => adapters.protocol.registerAuthorizationKey(authorizationRegistration))
    if (receipt?.status === 'succeeded') setAuthorizationRegistered(true)
  }
  const exportBackup = async (event: React.FormEvent) => {
    event.preventDefault(); setBackupError(''); setBackupMessage('')
    if (exportPassphrase !== exportConfirm) return setBackupError('Passphrases do not match.')
    try {
      const material = await adapters.crypto.exportWalletMaterial()
      const backup = await encryptWalletBackup(material, exportPassphrase)
      downloadWalletBackup(backup)
      setBackupConfirmationPending(true)
      setBackupMessage('Encrypted backup downloaded. Confirm that you saved it before registering any newly generated key.')
      setExportPassphrase(''); setExportConfirm('')
    } catch (caught) { setBackupError(caught instanceof Error ? caught.message : 'Backup export failed.') }
  }
  const confirmBackupSaved = () => {
    markEncryptedWalletBackupSaved(backupScope)
    setBackupConfirmationPending(false)
    setBackupMessage('Backup saved confirmation recorded for this account and deployment. Newly generated keys may now be registered.')
  }
  const importBackup = async (event: React.FormEvent) => {
    event.preventDefault(); setBackupError(''); setBackupMessage('')
    if (!selectedBackup) return setBackupError('Choose an encrypted backup file.')
    try {
      const material = await decryptWalletBackup(selectedBackup, importPassphrase)
      await adapters.crypto.importWalletMaterial(material)
      setBackupConfirmationPending(true)
      setBackupMessage('Wallet material restored into the browser crypto worker. Confirm that this encrypted backup is saved before registering keys or funding a broker proposal.')
      setImportPassphrase(''); setSelectedBackup(null)
      if (fileInput.current) fileInput.current.value = ''
    } catch (caught) { setBackupError(caught instanceof Error ? caught.message : 'Backup restore failed.') }
  }
  const exportKeeperBackup = async (event: React.FormEvent) => {
    event.preventDefault(); setBackupError(''); setBackupMessage('')
    if (!keeperBrokerIds.length) return setBackupError('Select at least one broker key to provision.')
    if (keeperPassphrase !== keeperConfirm) return setBackupError('Keeper backup passphrases do not match.')
    try {
      const material = await adapters.crypto.exportWalletMaterial()
      const scoped = scopeKeeperWalletMaterial(material, keeperBrokerIds)
      const backup = await encryptWalletBackup(scoped, keeperPassphrase)
      downloadWalletBackup(backup, `private-ledger-keeper-${keeperBrokerIds.join('-')}.backup.json`)
      setKeeperPassphrase(''); setKeeperConfirm('')
      setBackupMessage(`Keeper backup downloaded for broker${keeperBrokerIds.length === 1 ? '' : 's'} ${keeperBrokerIds.join(', ')}. It contains only the selected broker encryption keys; no holder, auditor, or agreement draft material.`)
    } catch (caught) { setBackupError(caught instanceof Error ? caught.message : 'Keeper backup export failed.') }
  }
  useEffect(() => {
    // A wallet account change must not leave a prepared key, draft, or keeper
    // selection visible for the next account. The worker clears its private
    // material separately; this resets the browser-side authorization state.
    setRegistration(null)
    setAuthorizationRegistration(null)
    setHolderRegistered(false)
    setAuthorizationRegistered(false)
    setBackupConfirmationPending(false)
    setBackupMessage('')
    setBackupError('')
    setSelectedBackup(null)
    setExportPassphrase('')
    setExportConfirm('')
    setImportPassphrase('')
    setKeeperBrokerIds([])
    setKeeperPassphrase('')
    setKeeperConfirm('')
  }, [accountId])
  useEffect(() => { void refreshStorage() }, [accountId])
  useEffect(() => () => { setExportPassphrase(''); setExportConfirm(''); setImportPassphrase('') }, [])
  return <>
    <PageHeader eyebrow="Wallet & security" title="Keep the keys close" description="NEAR wallet authorization and browser-local encryption are separate. Backups are encrypted files, never plaintext local storage." />
    <Notice tone="warning" title="This is not a recovery service">If you lose every encrypted backup and local key, an administrator cannot manufacture a private balance or decrypt an agreement. Verify a restore before relying on it.</Notice>
    <div className="security-grid"><Card><SectionHeading eyebrow="Wallet security" title="Private session" action={<StatusBadge tone={cryptoStatus?.available ? 'success' : 'warning'}>{cryptoStatus?.available ? 'Ready' : 'Unavailable'}</StatusBadge>} /><div className="security-detail"><span>Status</span><strong>{cryptoStatus?.message || 'Security status will appear after a connected read.'}</strong></div><div className="security-detail"><span>Security profile</span><Mono>{cryptoStatus?.profileHash || adapters.protocol.config.cryptoProfileHash || 'Not configured'}</Mono></div><div className="security-detail"><span>Runtime version</span><Mono>{cryptoStatus?.wasmVersion || 'Not loaded'}</Mono></div><div className="security-detail"><span>Encrypted backup</span><StatusBadge tone={backupSaved ? 'success' : 'warning'}>{backupSaved ? 'Saved confirmation' : 'Required before registration'}</StatusBadge></div><p className="field-hint">Private actions stay locked until the security profile is ready and the current wallet has an encrypted backup.</p></Card><Card><SectionHeading eyebrow="On-chain registration" title="Encryption key" action={<StatusBadge tone={holderRegistered ? 'success' : registration ? 'warning' : 'neutral'}>{holderRegistered ? 'Registered' : registration ? 'Backup required' : 'No new key'}</StatusBadge>} /><p className="muted">Generate a nonzero encryption key, export and confirm its encrypted backup, then register the proof of possession. Private key material never enters RPC.</p>{registration ? <div className="digest-panel"><span>Key ID</span><Mono>{registration.encryptionKeyId}</Mono><span>Public key</span><Mono>{registration.encryptionPublicKey}</Mono></div> : null}<div className="review-actions"><Button variant="secondary" onClick={() => void generateKey()} disabled={!accountId || !cryptoStatus?.available} busy={keyGenerating}>Generate key</Button>{registration ? <Button onClick={() => void registerKey()} disabled={!backupSaved || holderRegistered} busy={['preparing', 'awaiting_wallet'].includes(keyAction.state.phase)}>Register key</Button> : null}</div><ActionFeedback state={keyAction.state} /></Card><Card><SectionHeading eyebrow="Proposal authorization" title="Register account key" action={<StatusBadge tone={authorizationRegistered ? 'success' : authorizationRegistration ? 'warning' : 'neutral'}>{authorizationRegistered ? 'Registered' : authorizationRegistration ? 'Backup required' : 'No new key'}</StatusBadge>} /><p className="muted">Generate the proposal authorization key, export and confirm its encrypted backup, then register it. This key is separate from encryption and never accepts a pasted signature.</p>{authorizationRegistration ? <div className="digest-panel"><span>Key ID</span><Mono>{authorizationRegistration.keyId}</Mono><span>Public key</span><Mono>{authorizationRegistration.publicKey}</Mono></div> : null}<div className="review-actions"><Button variant="secondary" onClick={() => void generateAuthorizationKey()} disabled={!accountId || !cryptoStatus?.available} busy={authorizationGenerating}>Generate auth key</Button>{authorizationRegistration ? <Button onClick={() => void registerAuthorizationKey()} disabled={!backupSaved || authorizationRegistered} busy={['preparing', 'awaiting_wallet'].includes(authorizationAction.state.phase)}>Register auth key</Button> : null}</div><ActionFeedback state={authorizationAction.state} /></Card></div>
    <StorageBudgetCard accountId={accountId} balance={storageBalance} error={storageError} deposit={storageDeposit} onDepositChange={setStorageDeposit} onRefresh={() => void refreshStorage()} action={storageAction} onDeposit={async () => {
      setStorageError('')
      try {
        const depositUnits = parseAmount(storageDeposit, 24)
        const receipt = await storageAction.run('Add Core storage budget', () => adapters.protocol.storageDeposit({ accountId: accountId || '', deposit: depositUnits }))
        if (receipt?.status === 'succeeded') await refreshStorage()
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : 'Storage budget could not be added.'
        setStorageError(/storage/i.test(message) ? `Core storage budget is insufficient. Add more NEAR and retry. (${message})` : message)
      }
    }} />
    <div className="security-grid"><Card><SectionHeading eyebrow="Encrypted backup" title="Export wallet material" /><form onSubmit={exportBackup} className="form-stack"><Field label="Passphrase" htmlFor="backup-export-pass" hint="At least 12 characters. The passphrase never leaves this browser."><TextInput id="backup-export-pass" type="password" autoComplete="new-password" value={exportPassphrase} onChange={(event) => setExportPassphrase(event.target.value)} /></Field><Field label="Confirm passphrase" htmlFor="backup-export-confirm"><TextInput id="backup-export-confirm" type="password" autoComplete="new-password" value={exportConfirm} onChange={(event) => setExportConfirm(event.target.value)} /></Field><Button type="submit" disabled={!cryptoStatus?.available}>Encrypt & download backup</Button></form>{backupConfirmationPending ? <div className="review-actions"><Button type="button" variant="secondary" onClick={confirmBackupSaved}>I saved this encrypted backup</Button></div> : null}</Card><Card><SectionHeading eyebrow="Scoped keeper provision" title="Export broker-only backup" /><p className="muted">Provision a native keeper only with the selected broker encryption keys. This encrypted file deliberately excludes holder keys, auditor keys and in-memory agreement drafts. Anyone holding this file can decrypt the selected broker balance and loan views, so provision it only to an operator you trust.</p><div className="checkbox-list">{snapshot?.brokers.length ? snapshot.brokers.map((broker) => <label className="checkbox-field" key={broker.brokerId}><input type="checkbox" checked={keeperBrokerIds.includes(broker.brokerId)} onChange={(event) => setKeeperBrokerIds((current) => event.target.checked ? [...current, broker.brokerId] : current.filter((id) => id !== broker.brokerId))} />Broker <Mono>{broker.brokerId}</Mono></label>) : <p className="field-hint">No finalized broker records are available for this account.</p>}</div><form onSubmit={exportKeeperBackup} className="form-stack"><Field label="Keeper passphrase" htmlFor="keeper-export-pass" hint="Use a separate passphrase and share it through your approved operator channel."><TextInput id="keeper-export-pass" type="password" autoComplete="new-password" value={keeperPassphrase} onChange={(event) => setKeeperPassphrase(event.target.value)} /></Field><Field label="Confirm keeper passphrase" htmlFor="keeper-export-confirm"><TextInput id="keeper-export-confirm" type="password" autoComplete="new-password" value={keeperConfirm} onChange={(event) => setKeeperConfirm(event.target.value)} /></Field><Button type="submit" variant="secondary" disabled={!cryptoStatus?.available || !keeperBrokerIds.length}>Encrypt & download scoped backup</Button></form></Card><Card><SectionHeading eyebrow="Encrypted backup" title="Import wallet material" /><form onSubmit={importBackup} className="form-stack"><Field label="Backup file" htmlFor="backup-file"><input id="backup-file" ref={fileInput} className="file-input" type="file" accept="application/json,.json,.backup.json" onChange={async (event) => { const file = event.target.files?.[0]; if (!file) return; try { setSelectedBackup(await readWalletBackup(file)); setBackupError('') } catch (caught) { setSelectedBackup(null); setBackupError(caught instanceof Error ? caught.message : 'Invalid backup file.') } }} /></Field><Field label="Passphrase" htmlFor="backup-import-pass"><TextInput id="backup-import-pass" type="password" autoComplete="current-password" value={importPassphrase} onChange={(event) => setImportPassphrase(event.target.value)} /></Field><Button type="submit" variant="secondary" disabled={!selectedBackup || !cryptoStatus?.available}>Decrypt & restore</Button></form></Card></div>
    {backupMessage ? <Notice tone="success">{backupMessage}</Notice> : null}{backupError ? <Notice tone="danger" title="Backup action failed">{backupError}</Notice> : null}
    <Card className="configuration-card"><SectionHeading eyebrow="Deployment" title="Connected configuration" /><div className="config-grid"><div><span>Network</span><strong>{adapters.protocol.config.networkId}</strong></div><div><span>Core account</span><Mono>{adapters.protocol.config.coreAccountId || 'Not configured'}</Mono></div><div><span>Asset account</span><Mono>{adapters.protocol.config.tokenAccountId || 'Not configured'}</Mono></div><div><span>RPC endpoint</span><Mono>{adapters.protocol.config.rpcUrl}</Mono></div></div><p className="field-hint">RPC credentials are never accepted in URLs. Account and asset IDs come from the deployment manifest and finalized AssetProfile.</p></Card>
  </>
}

function formatYoctoNear(value: string | null): string {
  if (value === null || !/^(0|[1-9]\d*)$/.test(value)) return 'Not available'
  const units = BigInt(value), base = 10n ** 24n
  const whole = units / base
  const fraction = (units % base).toString().padStart(24, '0').replace(/0+$/, '')
  return fraction ? `${whole}.${fraction} NEAR` : `${whole} NEAR`
}

function StorageBudgetCard({ accountId, balance, error, deposit, onDepositChange, onRefresh, onDeposit, action }: {
  accountId?: string
  balance: string | null
  error: string
  deposit: string
  onDepositChange: (value: string) => void
  onRefresh: () => void
  onDeposit: () => Promise<void>
  action: ReturnType<typeof useAction>
}) {
  let depositUnits = ''
  try { depositUnits = parseAmount(deposit, 24) } catch { /* keep the action disabled until the decimal is valid */ }
  return <Card className="configuration-card"><SectionHeading eyebrow="Core storage" title="Keep this account funded" action={<StatusBadge tone={balance === null ? 'warning' : 'success'}>{balance === null ? 'Not read' : 'Finalized'}</StatusBadge>} /><p className="muted">Core reserves a small NEAR storage budget for holder, claim and loan records. This is public account infrastructure, separate from confidential asset balances.</p><div className="security-detail"><span>Remaining budget</span><strong>{formatYoctoNear(balance)}</strong></div><div className="security-detail"><span>Exact yoctoNEAR</span><Mono>{balance || '—'}</Mono></div><form className="form-stack" onSubmit={(event) => { event.preventDefault(); void onDeposit() }}><Field label="Top-up amount (NEAR)" htmlFor="storage-deposit" hint="Enter a decimal NEAR amount; it is converted to exact yoctoNEAR for the signed action."><TextInput id="storage-deposit" inputMode="decimal" value={deposit} onChange={(event) => onDepositChange(event.target.value)} placeholder="0.1" /></Field>{error ? <p className="field-error" role="alert">{error}</p> : null}<div className="review-actions"><Button type="submit" variant="secondary" disabled={!accountId || !depositUnits} busy={['preparing', 'awaiting_wallet'].includes(action.state.phase)}>Add NEAR storage</Button><Button type="button" variant="quiet" onClick={onRefresh} disabled={!accountId}>Refresh budget</Button></div><ActionFeedback state={action.state} /></form></Card>
}

function scopeKeeperWalletMaterial(material: Record<string, unknown>, brokerIds: string[]): Record<string, unknown> {
  const keys = material.keys
  if (!Array.isArray(keys)) throw new Error('The worker returned no wallet keys to scope.')
  const selected = new Set(brokerIds)
  const scoped = keys.filter((value): value is Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false
    const key = value as Record<string, unknown>
    return key.role === 'broker' && typeof key.subjectId === 'string' && selected.has(key.subjectId)
  })
  if (!scoped.length) throw new Error('No selected broker encryption key is present in this browser wallet.')
  const missing = brokerIds.filter((id) => !scoped.some((key) => key.subjectId === id))
  if (missing.length) throw new Error(`Selected broker key is not available in this browser wallet: ${missing.join(', ')}`)
  const identity = material.identity
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('The worker returned wallet material without deployment identity.')
  return { schema: material.schema, identity, keys: scoped }
}
