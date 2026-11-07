import type {
  AgreementDraft,
  AuditCiphertextBundle,
  AuthorizationKeyRegistration,
  BrokerKeyPreparation,
  BrokerSummary,
  CryptoProvider,
  CryptoProviderStatus,
  DecryptedAuditView,
  KeyRegistration,
  LoanSummary,
  LoanManagementPreparation,
  PreparedProof,
  PrivateAccountView,
  ProposalSummary,
} from './types'

type WorkerResponse = { id: number; ok: true; value: unknown } | { id: number; ok: false; category: string; message: string }

export interface WorkerCryptoOptions {
  expectedProfileHash: string
  /** Deployment manifest SHA-256; this is the immutable browser artifact pin. */
  expectedArtifactHash?: string
  manifestUrl?: string
  artifactBaseUrl?: string
  networkId: string
  coreAccountId: string
  assetId: string
  funded: boolean
  rpcUrl?: string
  allowInsecureLocalhost?: boolean
  onProgress?: (progress: number, message: string) => void
}

export class WorkerCryptoProvider implements CryptoProvider {
  private nextId = 0
  private readonly pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>()
  private readonly worker: Worker
  private readonly options: WorkerCryptoOptions
  private readonly status: CryptoProviderStatus
  private initialized?: Promise<void>

  constructor(worker: Worker, options: WorkerCryptoOptions) {
    this.worker = worker
    this.options = options
    this.status = { available: false, profileHash: options.expectedProfileHash, artifactHash: options.expectedArtifactHash, message: 'Secure account protection is loading.' }
    worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => this.onMessage(event.data))
    worker.addEventListener('error', () => {
      for (const pending of this.pending.values()) pending.reject(new Error('Crypto worker stopped unexpectedly.'))
      this.pending.clear()
      this.status.available = false
      this.status.message = 'Crypto worker stopped unexpectedly.'
      this.initialized = undefined
    })
  }

  private onMessage(response: WorkerResponse): void {
    const pending = this.pending.get(response.id)
    if (!pending) return
    this.pending.delete(response.id)
    if (response.ok) pending.resolve(response.value)
    else pending.reject(new Error(response.message))
  }

  private call<T>(method: string, payload?: unknown): Promise<T> {
    const id = ++this.nextId
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject })
      try { this.worker.postMessage({ id, method, payload }) } catch { this.pending.delete(id); reject(new Error('Crypto worker could not receive the operation.')) }
    })
  }

  private ensureInitialized(): Promise<void> {
    if (this.initialized) return this.initialized
    this.initialized = this.call<CryptoProviderStatus>('initialize', {
      manifestUrl: this.options.manifestUrl,
      baseUrl: this.options.artifactBaseUrl,
      expectedProfileHash: this.options.expectedProfileHash,
      expectedManifestHash: this.options.expectedArtifactHash,
      networkId: this.options.networkId,
      coreAccountId: this.options.coreAccountId,
      assetId: this.options.assetId,
      funded: this.options.funded,
      rpcUrl: this.options.rpcUrl,
      allowInsecureLocalhost: this.options.allowInsecureLocalhost,
    }).then(status => {
      Object.assign(this.status, status)
    }).catch(error => {
      this.initialized = undefined
      throw error
    })
    return this.initialized
  }

  /** Keep the worker's key references bound to the selected NEAR account. */
  setSubject(accountId: string | undefined): void {
    void this.ensureInitialized().then(() => this.call('set_subject', accountId)).catch(() => undefined)
  }

  async getStatus(): Promise<CryptoProviderStatus> {
    try {
      await this.ensureInitialized()
      const status = await this.call<CryptoProviderStatus>('status')
      if (status.profileHash !== this.options.expectedProfileHash || (this.options.expectedArtifactHash && status.artifactHash !== this.options.expectedArtifactHash)) {
        Object.assign(this.status, { ...status, available: false, message: 'Crypto profile or manifest hash mismatch.' })
      } else Object.assign(this.status, status)
    } catch (error) {
      Object.assign(this.status, { available: false, message: error instanceof Error ? error.message : 'Secure account protection is unavailable.' })
    }
    return { ...this.status }
  }

  exportWalletMaterial(): Promise<Record<string, unknown>> { return this.ensureInitialized().then(() => this.call('export_wallet_material')) }
  importWalletMaterial(material: Record<string, unknown>): Promise<void> { return this.ensureInitialized().then(() => this.call('import_wallet_material', material)) }
  createKeyRegistration(): Promise<KeyRegistration> { return this.ensureInitialized().then(() => this.call('create_key_registration')) }
  createAuthorizationKeyRegistration(): Promise<AuthorizationKeyRegistration> { return this.ensureInitialized().then(() => this.call('create_authorization_key_registration')) }
  prepareAgreement(input: { brokerId?: string; borrowerId?: string; publicKeys: { borrower: string; broker: string; issuer: string; tokenAuditor: string; loanAuditor: string }; principal: string; initialOwed: string; periodicPayment: string; paymentCount: number; maxPaymentCount: number }): Promise<AgreementDraft> { return this.ensureInitialized().then(() => this.call('prepare_agreement', input)) }
  prepareBrokerKeyRegistration(input: { ownerId: string; vaultId: string; encryptionKeyId: string; debtMaximum: string }): Promise<BrokerKeyPreparation> { return this.ensureInitialized().then(() => this.call('prepare_broker_key_registration', input)) }
  prepareShield(input: { account: PrivateAccountView; claimId: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_shield', input)) }
  prepareUnshield(input: { account: PrivateAccountView; amount: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_unshield', input)) }
  prepareBrokerClosure(input: { brokerId: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_broker_closure', input)) }
  prepareConfidentialTransfer(input: { sender: PrivateAccountView; destinationAccountId: string; amount: string; destinationEncryptionKeyId: string; destinationEncryptionPublicKey?: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_confidential_transfer', input)) }
  prepareMerge(input: { account: PrivateAccountView; scope: 'holder' | 'broker'; brokerId?: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_merge', input)) }
  prepareDraw(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_draw', input)) }
  prepareBrokerOrigination(input: { proposal: ProposalSummary; broker: BrokerSummary }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_broker_origination', input)) }
  prepareRepayment(input: { loan: LoanSummary; borrower: PrivateAccountView; mode: 'regular' | 'full' }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_repayment', input)) }
  prepareLoanManagement(input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<LoanManagementPreparation> { return this.ensureInitialized().then(() => this.call('prepare_loan_management', input)) }
  prepareSettlement(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_settlement', input)) }
  prepareReconciliation(input: { broker: BrokerSummary; expectedBookVersion: string; checkpointId?: string }): Promise<PreparedProof> { return this.ensureInitialized().then(() => this.call('prepare_reconciliation', input)) }
  authorizeAgreement(_proposal: ProposalSummary): Promise<{ authorizationSignature: string }> { return this.ensureInitialized().then(() => this.call('authorize_agreement')) }
  decryptAgreement(proposal: ProposalSummary): Promise<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string }> { return this.ensureInitialized().then(() => this.call('decrypt_agreement', proposal)) }
  decryptPrivateBalance(view: PrivateAccountView): Promise<string> { return this.ensureInitialized().then(() => this.call('decrypt_private_balance', view)) }
  decryptAudit(bundle: AuditCiphertextBundle): Promise<DecryptedAuditView> { return this.ensureInitialized().then(() => this.call('decrypt_audit', bundle)) }
}

export function createWorkerCryptoProvider(options: WorkerCryptoOptions): WorkerCryptoProvider {
  return new WorkerCryptoProvider(new Worker(new URL('../workers/crypto.worker.ts', import.meta.url), { type: 'module' }), options)
}
