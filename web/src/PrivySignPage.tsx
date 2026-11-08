import { useEffect, useRef, useState } from 'react'
import Privy, { LocalStorage } from '@privy-io/js-sdk-core'
import { PrivyProvider, usePrivy } from '@privy-io/react-auth'
import { useCreateWallet } from '@privy-io/react-auth/extended-chains'
import { initSigningPage, type SignPageSession, type SignPageOptions } from '@peerfolio/privy-near-connect/sign-page'
import { deploymentConfigFromEnv } from './lib/deploymentConfig'
import { privyConfiguration, type PrivyConfiguration } from './lib/privyConfig'
import { nearDeposit, validatePrivyRequest } from './lib/privyRequest'
import { completePrivyOAuth, withoutPrivyOAuthCallback } from './lib/privyOAuth'
import type { DeploymentConfig } from './lib/types'
import { Button, Notice } from './components/ui'

type NearWallet = NonNullable<SignPageOptions['wallet']>

function firstNearWallet(user: Awaited<ReturnType<Privy['user']['get']>>): NearWallet | undefined {
  return user.user.linked_accounts.find((account): account is NearWallet => account.type === 'wallet' && account.wallet_client_type === 'privy' && account.chain_type === 'near' && typeof account.id === 'string' && /^[a-f0-9]{64}$/.test(account.address))
}

export default function PrivySignPage() {
  const [deployment] = useState(deploymentConfigFromEnv)
  let configuration: PrivyConfiguration | undefined
  try { configuration = privyConfiguration(deployment, window.location.origin) } catch { /* Show a configuration error without starting authentication. */ }
  if (!configuration) return <SigningFrame><Notice tone="warning" title="Social login is not configured">Set a valid public Privy App ID, then restart or rebuild the app. A Client ID is optional.</Notice></SigningFrame>
  if (!window.opener) return <SigningFrame><Notice tone="info" title="Open this page from your wallet">Return to Private Ledger and select Email or social login from Connect wallet.</Notice></SigningFrame>
  return <ConfiguredSigningPage configuration={configuration} deployment={deployment} />
}

function ConfiguredSigningPage({ configuration, deployment }: { configuration: PrivyConfiguration; deployment: DeploymentConfig }) {
  const [client] = useState(() => new Privy({ appId: configuration.appId, clientId: configuration.clientId, storage: new LocalStorage() }))
  const initialization = useRef<Promise<void>>()
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading')

  useEffect(() => {
    let active = true
    // Finish a redirect before mounting React Auth so only one client exchanges
    // the one-time code. Keep the promise across effect replays.
    initialization.current ??= client.initialize().then(() => completePrivyOAuth(client, window.location.href))
    void initialization.current.then(() => { if (active) setStatus('ready') }).catch(() => { if (active) setStatus('error') })
    return () => { active = false }
  }, [client])

  if (status === 'loading') return <SigningFrame><p role="status">Preparing secure login…</p></SigningFrame>
  if (status === 'error') return <SigningFrame>
    <Notice tone="danger" title="Sign-in could not be completed">Your login expired, was cancelled, or could not be verified. Start again to retry.</Notice>
    <Button onClick={() => window.location.replace(withoutPrivyOAuthCallback(window.location.href))}>Start sign-in again</Button>
  </SigningFrame>
  return <PrivyProvider appId={configuration.appId} clientId={configuration.clientId} config={{ loginMethods: ['email', 'google'], appearance: { theme: 'dark', accentColor: '#b8e4c4' }, embeddedWallets: { ethereum: { createOnLogin: 'off' }, solana: { createOnLogin: 'off' } } }}>
    <SigningFlow client={client} configuration={configuration} deployment={deployment} />
  </PrivyProvider>
}

function SigningFrame({ children }: { children: React.ReactNode }) {
  return <main className="wallet-sign-page"><div className="wallet-sign-card"><p className="eyebrow">Private Ledger · NEAR wallet</p>{children}</div></main>
}

function SigningFlow({ client, configuration, deployment }: { client: Privy; configuration: PrivyConfiguration; deployment: DeploymentConfig }) {
  const { ready, authenticated, user, login, logout } = usePrivy()
  const { createWallet } = useCreateWallet()
  const [session, setSession] = useState<SignPageSession>()
  const [wallet, setWallet] = useState<NearWallet>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [walletChecked, setWalletChecked] = useState(false)
  const busyRef = useRef(false)
  const lifetime = useRef<AbortController>()

  useEffect(() => {
    const controller = new AbortController()
    lifetime.current = controller
    const guardRequest = (event: MessageEvent) => {
      if (event.data?.source === 'privy-near-connect' && event.data?.type === 'SIGN_REQUEST' && (event.source !== window.opener || event.origin !== configuration.origin)) event.stopImmediatePropagation()
    }
    window.addEventListener('message', guardRequest, true)
    // Start the handshake before login: the executor waits only 30 seconds for READY.
    void initSigningPage(client, { allowedOrigins: [configuration.origin], rpcOptions: { url: configuration.rpcUrl }, debug: false, signal: controller.signal }).then((value) => {
      if (controller.signal.aborted) return
      validatePrivyRequest(value.payload, deployment)
      setSession(value)
    }).catch(() => {
      if (!controller.signal.aborted) setError('The wallet request could not be opened. Close this window and connect again.')
    })
    return () => {
      controller.abort()
      window.removeEventListener('message', guardRequest, true)
    }
  }, [client, configuration.origin, configuration.rpcUrl, deployment])

  useEffect(() => {
    let active = true
    setWallet(undefined)
    setWalletChecked(false)
    if (ready && authenticated && session) {
      void client.user.get().then((current) => {
        if (!active) return
        setWallet(firstNearWallet(current))
        setWalletChecked(true)
      }).catch(() => { if (active) setError('Your wallet session could not be loaded. Sign out and log in again.') })
    }
    return () => { active = false }
  }, [ready, authenticated, user?.id, client, session])

  const create = async () => {
    if (busyRef.current) return
    busyRef.current = true
    setBusy(true)
    setError('')
    try {
      // Recheck before creation so retrying after a lost response cannot create a second wallet.
      let current = firstNearWallet(await client.user.get())
      if (!current) {
        await createWallet({ chainType: 'near' })
        current = firstNearWallet(await client.user.get())
      }
      if (!current) throw new Error('Wallet creation did not return a NEAR account.')
      setWallet(current)
    } catch { setError('The NEAR wallet could not be created. Check your connection and try again.') }
    finally { busyRef.current = false; setBusy(false) }
  }

  const approve = async () => {
    if (busyRef.current || !session || !wallet || !authenticated) return
    busyRef.current = true
    setBusy(true)
    setError('')
    try {
      const current = firstNearWallet(await client.user.get())
      if (!current || current.address !== wallet.address || current.id !== wallet.id) throw new Error('Your wallet changed. Close this window and reconnect.')
      validatePrivyRequest(session.payload, deployment, wallet.address)
      // Bind signing to the reviewed wallet. Repeating READY asks the executor for
      // the same request; compare it before using the wallet-bound signing session.
      const bound = await initSigningPage(client, { allowedOrigins: [configuration.origin], rpcOptions: { url: configuration.rpcUrl }, wallet: current, debug: false, signal: lifetime.current?.signal })
      if (bound.targetOrigin !== session.targetOrigin || JSON.stringify(bound.payload) !== JSON.stringify(session.payload)) throw new Error('The signing request changed. Close this window and reconnect.')
      await bound.sign()
    } catch {
      setError('The request could not be completed. If you approved a transaction, check its finalized status before trying again.')
    } finally { busyRef.current = false; setBusy(false) }
  }

  const cancel = () => {
    if (busyRef.current) return
    window.opener?.postMessage({ source: 'privy-near-connect', type: 'ERROR', error: { type: 'UserRejectedRequest', message: 'User rejected the request.' } }, configuration.origin)
    window.close()
  }

  let request: ReturnType<typeof validatePrivyRequest> | undefined
  let validationError = ''
  if (session) {
    try { request = validatePrivyRequest(session.payload, deployment, wallet?.address) }
    catch (cause) { validationError = cause instanceof Error ? cause.message : 'Invalid wallet request.' }
  }

  return <SigningFrame>
    <h1>{request?.kind === 'signAndSendTransaction' ? 'Review transaction' : 'Connect your wallet'}</h1>
    <p className="muted">{configuration.origin} · {configuration.network}</p>
    {error || validationError ? <Notice tone="danger" title="Wallet request unavailable">{validationError || error}</Notice> : null}
    {!session || !ready ? <p role="status">Preparing secure login…</p> : !authenticated ? <>
      <p>Sign in with email or Google to use your NEAR wallet.</p>
      <Button onClick={() => login()}>Sign in</Button>
    </> : !walletChecked ? <p role="status">Loading your wallet…</p> : !wallet ? <>
      <p>Create your NEAR wallet to connect to Private Ledger. You will need NEAR on {configuration.network} for transaction fees.</p>
      <Button disabled={busy} onClick={() => void create()}>{busy ? 'Creating wallet…' : 'Create NEAR wallet'}</Button>
    </> : <>
      <p className="eyebrow">Your NEAR account</p><p className="wallet-sign-account">{wallet.address}</p>
      {request?.kind === 'signAndSendTransaction' ? <>
        <p>Contract: <strong>{request.receiverId}</strong></p>
        {request.actions.map((action, index) => action.type === 'FunctionCall' ? <div className="wallet-call" key={index}><strong>{action.params.methodName}</strong><p>Attached deposit: {nearDeposit(action.params.deposit)}</p><p>Gas limit: {Number(BigInt(action.params.gas)) / 1e12} Tgas</p></div> : null)}
        <details><summary>Transaction details</summary><pre className="wallet-request">{JSON.stringify(request, null, 2)}</pre></details>
      </> : <p>Share this account address with Private Ledger.</p>}
      <Button disabled={busy || !!validationError || !!error} onClick={() => void approve()}>{busy ? 'Waiting for wallet…' : request?.kind === 'signAndSendTransaction' ? 'Approve transaction' : 'Connect account'}</Button>
    </>}
    <div className="wallet-sign-actions"><Button variant="secondary" disabled={busy} onClick={cancel}>Cancel</Button>{authenticated ? <Button variant="quiet" disabled={busy} onClick={() => { setError(''); void logout().catch(() => setError('Sign-out failed. Close the window and try again.')) }}>Use another login</Button> : null}</div>
  </SigningFrame>
}
