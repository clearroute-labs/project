import { useEffect, useRef, useState } from 'react'
import { useAppContext } from '../App'
import { ActionFeedback, Button, Card, Field, Mono, Notice, SectionHeading, StatusBadge, TextInput } from '../components/ui'
import { useAction } from '../lib/actionState'
import { decryptWalletBackup, downloadWalletBackup, encryptWalletBackup, readWalletBackup } from '../lib/walletVault'
import type { EncryptedWalletBackup, KeyRegistration } from '../lib/types'
import { PageHeader } from './shared'

export function SecurityPage() {
  const { adapters, accountId, cryptoStatus } = useAppContext()
  const [registration, setRegistration] = useState<KeyRegistration | null>(null)
  const [backupMessage, setBackupMessage] = useState('')
  const [backupError, setBackupError] = useState('')
  const [exportPassphrase, setExportPassphrase] = useState('')
  const [exportConfirm, setExportConfirm] = useState('')
  const [importPassphrase, setImportPassphrase] = useState('')
  const [selectedBackup, setSelectedBackup] = useState<EncryptedWalletBackup | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const keyAction = useAction()
  const registerKey = async () => {
    setBackupError('')
    await keyAction.run('Register encryption key', async () => {
      const next = await adapters.crypto.createKeyRegistration()
      setRegistration(next)
      return adapters.protocol.registerHolder(next)
    })
  }
  const exportBackup = async (event: React.FormEvent) => {
    event.preventDefault(); setBackupError(''); setBackupMessage('')
    if (exportPassphrase !== exportConfirm) return setBackupError('Passphrases do not match.')
    try {
      const material = await adapters.crypto.exportWalletMaterial()
      const backup = await encryptWalletBackup(material, exportPassphrase)
      downloadWalletBackup(backup)
      setBackupMessage('Encrypted backup downloaded. Keep it offline and verify that you can restore it.')
      setExportPassphrase(''); setExportConfirm('')
    } catch (caught) { setBackupError(caught instanceof Error ? caught.message : 'Backup export failed.') }
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
    <div className="security-grid"><Card><SectionHeading eyebrow="Browser crypto" title="Profile & artifacts" action={<StatusBadge tone={cryptoStatus?.available ? 'success' : 'warning'}>{cryptoStatus?.available ? 'Loaded' : 'Not loaded'}</StatusBadge>} /><div className="security-detail"><span>Status</span><strong>{cryptoStatus?.message || 'Crypto worker status will appear after a connected read.'}</strong></div><div className="security-detail"><span>Profile hash</span><Mono>{cryptoStatus?.profileHash || adapters.protocol.config.cryptoProfileHash || 'Not configured'}</Mono></div><div className="security-detail"><span>Artifact hash</span><Mono>{cryptoStatus?.artifactHash || 'Not loaded'}</Mono></div><div className="security-detail"><span>WASM version</span><Mono>{cryptoStatus?.wasmVersion || 'Not loaded'}</Mono></div><p className="field-hint">Proof preparation is blocked when the manifest hash or artifact hash is missing or mismatched.</p></Card><Card><SectionHeading eyebrow="On-chain registration" title="Encryption key" action={<StatusBadge tone={registration ? 'success' : 'neutral'}>{registration ? 'Prepared' : 'No new key'}</StatusBadge>} /><p className="muted">Register a nonzero encryption key with proof of possession. The Core will reject overwrites while balances or open loans depend on the old key.</p>{registration ? <div className="digest-panel"><span>Key ID</span><Mono>{registration.encryptionKeyId}</Mono><span>Public key</span><Mono>{registration.encryptionPublicKey}</Mono></div> : null}<Button onClick={() => void registerKey()} disabled={!accountId || !cryptoStatus?.available} busy={['preparing', 'awaiting_wallet'].includes(keyAction.state.phase)}>Generate & register key</Button><ActionFeedback state={keyAction.state} /></Card></div>
    <div className="security-grid"><Card><SectionHeading eyebrow="Encrypted backup" title="Export wallet material" /><form onSubmit={exportBackup} className="form-stack"><Field label="Passphrase" htmlFor="backup-export-pass" hint="At least 12 characters. The passphrase never leaves this browser."><TextInput id="backup-export-pass" type="password" autoComplete="new-password" value={exportPassphrase} onChange={(event) => setExportPassphrase(event.target.value)} /></Field><Field label="Confirm passphrase" htmlFor="backup-export-confirm"><TextInput id="backup-export-confirm" type="password" autoComplete="new-password" value={exportConfirm} onChange={(event) => setExportConfirm(event.target.value)} /></Field><Button type="submit" disabled={!cryptoStatus?.available}>Encrypt & download backup</Button></form></Card><Card><SectionHeading eyebrow="Encrypted backup" title="Import wallet material" /><form onSubmit={importBackup} className="form-stack"><Field label="Backup file" htmlFor="backup-file"><input id="backup-file" ref={fileInput} className="file-input" type="file" accept="application/json,.json,.backup.json" onChange={async (event) => { const file = event.target.files?.[0]; if (!file) return; try { setSelectedBackup(await readWalletBackup(file)); setBackupError('') } catch (caught) { setSelectedBackup(null); setBackupError(caught instanceof Error ? caught.message : 'Invalid backup file.') } }} /></Field><Field label="Passphrase" htmlFor="backup-import-pass"><TextInput id="backup-import-pass" type="password" autoComplete="current-password" value={importPassphrase} onChange={(event) => setImportPassphrase(event.target.value)} /></Field><Button type="submit" variant="secondary" disabled={!selectedBackup || !cryptoStatus?.available}>Decrypt & restore</Button></form></Card></div>
    {backupMessage ? <Notice tone="success">{backupMessage}</Notice> : null}{backupError ? <Notice tone="danger" title="Backup action failed">{backupError}</Notice> : null}
    <Card className="configuration-card"><SectionHeading eyebrow="Deployment" title="Connected configuration" /><div className="config-grid"><div><span>Network</span><strong>{adapters.protocol.config.networkId}</strong></div><div><span>Core account</span><Mono>{adapters.protocol.config.coreAccountId || 'Not configured'}</Mono></div><div><span>Asset account</span><Mono>{adapters.protocol.config.tokenAccountId || 'Not configured'}</Mono></div><div><span>RPC endpoint</span><Mono>{adapters.protocol.config.rpcUrl}</Mono></div></div><p className="field-hint">RPC credentials are never accepted in URLs. Account and asset IDs come from the deployment manifest and finalized AssetProfile.</p></Card>
  </>
}
