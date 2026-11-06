import type {
  AuditCiphertextBundle,
  BrokerSummary,
  CryptoProvider,
  CryptoProviderStatus,
  DecryptedAuditView,
  KeyRegistration,
  LoanSummary,
  PreparedProof,
  PrivateAccountView,
  ProposalSummary,
} from './types'

type WorkerResponse = { id: number; ok: true; value: unknown } | { id: number; ok: false; category: string; message: string } | { id: number; progress: number; message: string }

export interface WorkerCryptoOptions {
  expectedProfileHash: string
  expectedArtifactHash?: string
  onProgress?: (progress: number, message: string) => void
}

export class WorkerCryptoProvider implements CryptoProvider {
  private nextId = 0
  private readonly pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>()
  private readonly worker: Worker
  private readonly options: WorkerCryptoOptions
  private readonly status: CryptoProviderStatus

  constructor(worker: Worker, options: WorkerCryptoOptions) {
    this.worker = worker
    this.options = options
    this.status = { available: false, profileHash: options.expectedProfileHash, message: 'Crypto worker is loading pinned artifacts.' }
    worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => this.onMessage(event.data))
    worker.addEventListener('error', () => {
      for (const pending of this.pending.values()) pending.reject(new Error('Crypto worker stopped unexpectedly.'))
      this.pending.clear()
      this.status.message = 'Crypto worker stopped unexpectedly.'
    })
  }

  private onMessage(response: WorkerResponse): void {
    if ('progress' in response) {
      this.options.onProgress?.(response.progress, response.message)
      return
    }
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
      this.worker.postMessage({ id, method, payload })
    })
  }

  async getStatus(): Promise<CryptoProviderStatus> {
    try {
      const status = await this.call<CryptoProviderStatus>('status')
      if (status.profileHash !== this.options.expectedProfileHash || (this.options.expectedArtifactHash && status.artifactHash !== this.options.expectedArtifactHash)) {
        return { ...status, available: false, message: 'Crypto profile or artifact hash mismatch.' }
      }
      Object.assign(this.status, status)
      return status
    } catch (error) {
      return { ...this.status, available: false, message: error instanceof Error ? error.message : 'Crypto worker unavailable.' }
    }
  }

  exportWalletMaterial(): Promise<Record<string, unknown>> { return this.call('export_wallet_material') }
  importWalletMaterial(material: Record<string, unknown>): Promise<void> { return this.call('import_wallet_material', material) }
  createKeyRegistration(): Promise<KeyRegistration> { return this.call('create_key_registration') }
  prepareConfidentialTransfer(input: { sender: PrivateAccountView; destinationAccountId: string; amount: string; destinationEncryptionKeyId: string }): Promise<PreparedProof> { return this.call('prepare_confidential_transfer', input) }
  prepareMerge(input: { account: PrivateAccountView; scope: 'holder' | 'broker' }): Promise<PreparedProof> { return this.call('prepare_merge', input) }
  prepareDraw(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> { return this.call('prepare_draw', input) }
  prepareOrigination(input: { proposal: ProposalSummary; broker: BrokerSummary; borrower: PrivateAccountView }): Promise<PreparedProof> { return this.call('prepare_origination', input) }
  prepareRepayment(input: { loan: LoanSummary; borrower: PrivateAccountView; mode: 'regular' | 'full' }): Promise<PreparedProof> { return this.call('prepare_repayment', input) }
  prepareLoanManagement(input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<PreparedProof> { return this.call('prepare_loan_management', input) }
  prepareSettlement(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof> { return this.call('prepare_settlement', input) }
  prepareReconciliation(input: { broker: BrokerSummary; expectedBookVersion: string }): Promise<PreparedProof> { return this.call('prepare_reconciliation', input) }
  authorizeAgreement(proposal: ProposalSummary): Promise<{ authorizationSignature: string }> { return this.call('authorize_agreement', proposal) }
  decryptAgreement(proposal: ProposalSummary): Promise<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string }> { return this.call('decrypt_agreement', proposal) }
  decryptPrivateBalance(view: PrivateAccountView): Promise<string> { return this.call('decrypt_private_balance', view) }
  decryptAudit(bundle: AuditCiphertextBundle): Promise<DecryptedAuditView> { return this.call('decrypt_audit', bundle) }
}

export function createWorkerCryptoProvider(options: WorkerCryptoOptions): WorkerCryptoProvider {
  const worker = new Worker(new URL('../workers/crypto.worker.ts', import.meta.url), { type: 'module' })
  return new WorkerCryptoProvider(worker, options)
}
