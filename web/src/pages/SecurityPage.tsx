import { useEffect, useRef, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, Field, Mono, Notice, SectionHeading, StatusBadge, TextInput } from '../components/ui'
import { useAction } from '../lib/actionState'
import { decryptWalletBackup, downloadWalletBackup, encryptWalletBackup, readWalletBackup } from '../lib/walletVault'
import { clearEncryptedWalletBackup, markEncryptedWalletBackupSaved, useEncryptedWalletBackup, walletBackupScope } from '../lib/walletBackupGate'
import type { AuthorizationKeyRegistration, EncryptedWalletBackup, KeyRegistration } from '../lib/types'
import { PageHeader } from './shared'

export function SecurityPage() {
  const { adapters, accountId, cryptoStatus } = useAppContext()
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
  const fileInput = useRef<HTMLInputElement>(null)
  const keyAction = useAction()
  const authorizationAction = useAction()
  const generateKey = async () => {
    setBackupError('')
    setKeyGenerating(true)
    try {
      setRegistration(await adapters.crypto.createKeyRegistration())
      setHolderRegistered(false)
      clearEncryptedWalletBackup(backupScope)
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
      setBackupMessage('Wallet material restored into the browser crypto worker. Registering it on-chain is a separate action.')
      setImportPassphrase(''); setSelectedBackup(null)
      if (fileInput.current) fileInput.current.value = ''
    } catch (caught) { setBackupError(caught instanceof Error ? caught.message : 'Backup restore failed.') }
  }
  useEffect(() => () => { setExportPassphrase(''); setExportConfirm(''); setImportPassphrase('') }, [])
  return <>
    <PageHeader eyebrow="Wallet & security" title="Keep the keys close" description="NEAR wallet authorization and browser-local encryption are separate. Backups are encrypted files, never plaintext local storage." />
    <Notice tone="warning" title="This is not a recovery service">If you lose every encrypted backup and local key, an administrator cannot manufacture a private balance or decrypt an agreement. Verify a restore before relying on it.</Notice>
    <div className="security-grid"><Card><SectionHeading eyebrow="Browser crypto" title="Profile & artifacts" action={<StatusBadge tone={cryptoStatus?.available ? 'success' : 'warning'}>{cryptoStatus?.available ? 'Loaded' : 'Not loaded'}</StatusBadge>} /><div className="security-detail"><span>Status</span><strong>{cryptoStatus?.message || 'Crypto worker status will appear after a connected read.'}</strong></div><div className="security-detail"><span>Profile hash</span><Mono>{cryptoStatus?.profileHash || adapters.protocol.config.cryptoProfileHash || 'Not configured'}</Mono></div><div className="security-detail"><span>Artifact hash</span><Mono>{cryptoStatus?.artifactHash || 'Not loaded'}</Mono></div><div className="security-detail"><span>WASM version</span><Mono>{cryptoStatus?.wasmVersion || 'Not loaded'}</Mono></div><div className="security-detail"><span>Encrypted backup</span><StatusBadge tone={backupSaved ? 'success' : 'warning'}>{backupSaved ? 'Saved confirmation' : 'Required before registration'}</StatusBadge></div><p className="field-hint">Proof preparation is blocked when the manifest hash or artifact hash is missing or mismatched. Key registration also stays locked until the current worker material has an encrypted backup.</p></Card><Card><SectionHeading eyebrow="On-chain registration" title="Encryption key" action={<StatusBadge tone={holderRegistered ? 'success' : registration ? 'warning' : 'neutral'}>{holderRegistered ? 'Registered' : registration ? 'Backup required' : 'No new key'}</StatusBadge>} /><p className="muted">Generate a nonzero encryption key, export and confirm its encrypted backup, then register the proof of possession. Private key material never enters RPC.</p>{registration ? <div className="digest-panel"><span>Key ID</span><Mono>{registration.encryptionKeyId}</Mono><span>Public key</span><Mono>{registration.encryptionPublicKey}</Mono></div> : null}<div className="review-actions"><Button variant="secondary" onClick={() => void generateKey()} disabled={!accountId || !cryptoStatus?.available} busy={keyGenerating}>Generate key</Button>{registration ? <Button onClick={() => void registerKey()} disabled={!backupSaved || holderRegistered} busy={['preparing', 'awaiting_wallet'].includes(keyAction.state.phase)}>Register key</Button> : null}</div><ActionFeedback state={keyAction.state} /></Card><Card><SectionHeading eyebrow="Proposal authorization" title="Register account key" action={<StatusBadge tone={authorizationRegistered ? 'success' : authorizationRegistration ? 'warning' : 'neutral'}>{authorizationRegistered ? 'Registered' : authorizationRegistration ? 'Backup required' : 'No new key'}</StatusBadge>} /><p className="muted">Generate the proposal authorization key, export and confirm its encrypted backup, then register it. This key is separate from encryption and never accepts a pasted signature as proof.</p>{authorizationRegistration ? <div className="digest-panel"><span>Key ID</span><Mono>{authorizationRegistration.keyId}</Mono><span>Public key</span><Mono>{authorizationRegistration.publicKey}</Mono></div> : null}<div className="review-actions"><Button variant="secondary" onClick={() => void generateAuthorizationKey()} disabled={!accountId || !cryptoStatus?.available} busy={authorizationGenerating}>Generate auth key</Button>{authorizationRegistration ? <Button onClick={() => void registerAuthorizationKey()} disabled={!backupSaved || authorizationRegistered} busy={['preparing', 'awaiting_wallet'].includes(authorizationAction.state.phase)}>Register auth key</Button> : null}</div><ActionFeedback state={authorizationAction.state} /></Card></div>
    <div className="security-grid"><Card><SectionHeading eyebrow="Encrypted backup" title="Export wallet material" /><form onSubmit={exportBackup} className="form-stack"><Field label="Passphrase" htmlFor="backup-export-pass" hint="At least 12 characters. The passphrase never leaves this browser."><TextInput id="backup-export-pass" type="password" autoComplete="new-password" value={exportPassphrase} onChange={(event) => setExportPassphrase(event.target.value)} /></Field><Field label="Confirm passphrase" htmlFor="backup-export-confirm"><TextInput id="backup-export-confirm" type="password" autoComplete="new-password" value={exportConfirm} onChange={(event) => setExportConfirm(event.target.value)} /></Field><Button type="submit" disabled={!cryptoStatus?.available}>Encrypt & download backup</Button></form>{backupConfirmationPending ? <div className="review-actions"><Button type="button" variant="secondary" onClick={confirmBackupSaved}>I saved this encrypted backup</Button></div> : null}</Card><Card><SectionHeading eyebrow="Encrypted backup" title="Import wallet material" /><form onSubmit={importBackup} className="form-stack"><Field label="Backup file" htmlFor="backup-file"><input id="backup-file" ref={fileInput} className="file-input" type="file" accept="application/json,.json,.backup.json" onChange={async (event) => { const file = event.target.files?.[0]; if (!file) return; try { setSelectedBackup(await readWalletBackup(file)); setBackupError('') } catch (caught) { setSelectedBackup(null); setBackupError(caught instanceof Error ? caught.message : 'Invalid backup file.') } }} /></Field><Field label="Passphrase" htmlFor="backup-import-pass"><TextInput id="backup-import-pass" type="password" autoComplete="current-password" value={importPassphrase} onChange={(event) => setImportPassphrase(event.target.value)} /></Field><Button type="submit" variant="secondary" disabled={!selectedBackup || !cryptoStatus?.available}>Decrypt & restore</Button></form></Card></div>
    {backupMessage ? <Notice tone="success">{backupMessage}</Notice> : null}{backupError ? <Notice tone="danger" title="Backup action failed">{backupError}</Notice> : null}
    <Card className="configuration-card"><SectionHeading eyebrow="Deployment" title="Connected configuration" /><div className="config-grid"><div><span>Network</span><strong>{adapters.protocol.config.networkId}</strong></div><div><span>Core account</span><Mono>{adapters.protocol.config.coreAccountId || 'Not configured'}</Mono></div><div><span>Asset account</span><Mono>{adapters.protocol.config.tokenAccountId || 'Not configured'}</Mono></div><div><span>RPC endpoint</span><Mono>{adapters.protocol.config.rpcUrl}</Mono></div></div><p className="field-hint">RPC credentials are never accepted in URLs. Account and asset IDs come from the deployment manifest and finalized AssetProfile.</p></Card>
  </>
}
