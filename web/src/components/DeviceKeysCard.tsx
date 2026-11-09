import { useState } from 'react'
import { useAppContext } from '../App'
import { useEncryptedWalletBackup, walletBackupScope } from '../lib/walletBackupGate'
import { Button, Card, Notice, SectionHeading, StatusBadge } from './ui'

export function DeviceKeysCard() {
  const { deviceKeys, deviceKeyState: state, accountId, cryptoStatus, adapters } = useAppContext()
  const [error, setError] = useState('')
  const backupSaved = useEncryptedWalletBackup(walletBackupScope(adapters.protocol.config, accountId))
  const hasKeys = Boolean((cryptoStatus?.walletKeyCount || 0) + (cryptoStatus?.authorizationKeyCount || 0) + (cryptoStatus?.draftCount || 0))
  const ready = Boolean(accountId && state.ready && cryptoStatus?.available && !state.busy)
  const run = async (operation: () => Promise<void>) => {
    setError('')
    try { await operation() }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'The passkey action could not be completed.') }
  }
  return <Card className="configuration-card">
    <SectionHeading title="Passkey unlock" action={<StatusBadge tone={state.unlocked ? 'success' : 'neutral'}>{state.unlocked ? 'Unlocked' : state.exists ? 'Saved · locked' : 'Not saved'}</StatusBadge>} />
    <p className="muted">Unlock your confidential keys with a passkey. Your wallet still approves transactions.</p>
    <p className="field-hint">Keep a recovery file: a synced passkey cannot restore your keys on another browser or after browser data is cleared.</p>
    {!state.supported ? <Notice tone="info">This browser does not offer passkey encryption here. Use an encrypted recovery file, or open the app in a compatible browser over HTTPS.</Notice> : null}
    {state.exists && !state.unlocked && hasKeys ? <Notice tone="info">Keys are already loaded from this session or a recovery file. Confirm a current recovery file, then replace the saved browser copy with these loaded keys.</Notice> : null}
    <div className="review-actions">
      {!state.exists ? <Button variant="secondary" disabled={!ready || !state.supported || !hasKeys} busy={state.busy} onClick={() => void run(() => deviceKeys.enroll())}>Save with passkey</Button> : null}
      {state.exists && !state.unlocked && !hasKeys ? <Button disabled={!ready || !state.supported} busy={state.busy} onClick={() => void run(() => deviceKeys.unlock())}>Unlock with passkey</Button> : null}
      {state.exists && !state.unlocked && hasKeys ? <Button variant="secondary" disabled={!ready || !state.supported || !backupSaved} busy={state.busy} onClick={() => void run(() => deviceKeys.replace())}>Replace browser copy</Button> : null}
      {hasKeys || state.unlocked ? <Button variant="secondary" disabled={!ready || (!backupSaved && !state.unlocked)} onClick={() => void run(() => deviceKeys.lock())}>Lock private keys</Button> : null}
      {state.exists ? <Button variant="quiet" disabled={!ready || !backupSaved} onClick={() => void run(() => deviceKeys.remove())}>Remove browser copy</Button> : null}
    </div>
    {state.unlocked ? <p className="field-hint">New keys and private agreement drafts are saved automatically while unlocked. Export an updated recovery file when you create new private material.</p> : null}
    {state.exists ? <p className="field-hint">Removing the browser copy leaves your passkey in your password manager. A confirmed recovery file is required first.</p> : null}
    {error || state.error ? <Notice tone="danger">{error || state.error}</Notice> : null}
  </Card>
}
