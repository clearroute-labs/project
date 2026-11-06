import {
  ProtocolError,
  type ActionReceipt,
  type AppAdapters,
  type AuditCiphertextBundle,
  type BrokerSummary,
  type CryptoProvider,
  type CryptoProviderStatus,
  type DashboardSnapshot,
  type DeploymentConfig,
  type KeyRegistration,
  type KeeperGrant,
  type LoanSummary,
  type PrivateAccountView,
  type PreparedProof,
  type ProposalSummary,
  type ProtocolClient,
  type PublicClaim,
  type WalletAdapter,
} from './types'

export function deploymentConfigFromEnv(): DeploymentConfig {
  return {
    networkId: import.meta.env.VITE_NETWORK_ID || 'testnet',
    coreAccountId: import.meta.env.VITE_CORE_ACCOUNT_ID || '',
    tokenAccountId: import.meta.env.VITE_TOKEN_ACCOUNT_ID || '',
    rpcUrl: import.meta.env.VITE_RPC_URL || 'https://rpc.testnet.near.org',
    cryptoProfileHash: import.meta.env.VITE_CRYPTO_PROFILE_HASH || '',
  }
}

function unavailable(message: string): ProtocolError {
  return new ProtocolError({ category: 'ADAPTER_UNAVAILABLE', message, retryable: true })
}

class UnavailableProtocolClient implements ProtocolClient {
  readonly config: DeploymentConfig

  constructor(config: DeploymentConfig) {
    this.config = config
  }

  private fail(): never {
    throw unavailable('The NEAR client adapter is not connected. Configure the deployment and wallet adapter first.')
  }

  getAssetProfile(): Promise<never> { return Promise.reject(this.fail()) }
  getDashboard(_accountId: string): Promise<DashboardSnapshot> { return Promise.reject(this.fail()) }
  getPrivateAccount(_accountId: string): Promise<PrivateAccountView> { return Promise.reject(this.fail()) }
  getBrokerPrivateAccount(_brokerId: string): Promise<PrivateAccountView> { return Promise.reject(this.fail()) }
  getProposal(_proposalId: string): Promise<ProposalSummary> { return Promise.reject(this.fail()) }
  getAuditBundle(_input: { scope: 'loan' | 'token'; subjectId: string }): Promise<AuditCiphertextBundle> { return Promise.reject(this.fail()) }
  registerHolder(_input: KeyRegistration): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createVault(_input: { assetAccount: string; assetsMaximum: string; kind: 'open_ended' | 'closed_ended'; phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }; shareScale: number; sharesTransferable: boolean; checkpointPolicy: { epochSeconds: number; disclosurePolicy: string } }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createBroker(_input: { vaultId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  depositExternal(_input: { amount: string; depositId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  depositToVault(_input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  redeemShares(_input: { vaultId: string; shares: string; minAmount: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  requestPayout(_input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  mergeInbox(_input: { accountId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  mergeBrokerInbox(_input: { brokerId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  draw(_input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createProposal(_input: { brokerId: string; borrowerId: string; vaultId: string; borrowerKeyId: string; brokerKeyId: string; auditorKeyId: string; paymentCount: number; paymentIntervalSeconds: number; gracePeriodSeconds: number; encryptedPrincipal: string; encryptedOwed: string; encryptedPayment: string; encryptedAgreement: string; termsDigest: string; brokerSignature: string; borrowerSignature: string; brokerAuthorizationEpoch: string; borrowerAuthorizationEpoch: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  authorizeProposal(_input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  originate(_input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  confidentialSend(_input: { senderAccountId: string; destinationAccountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  repay(_input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  manageLoan(_input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  settle(_input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  reconcileCredit(_input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  prepareReconciliation(_input: { brokerId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  grantKeeper(_input: { brokerId: string; delegateId: string; scope: KeeperGrant['scope']; maxAmount?: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  revokeKeeper(_input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
}

class UnavailableWalletAdapter implements WalletAdapter {
  status: WalletAdapter['status'] = 'disconnected'
  readonly accountId = undefined
  readonly networkId = undefined
  readonly error = undefined
  private readonly listeners = new Set<() => void>()

  async connect(): Promise<void> {
    throw unavailable('No wallet selector adapter is installed. Connect a supported NEAR wallet to continue.')
  }

  async disconnect(): Promise<void> {
    this.status = 'disconnected'
    for (const listener of this.listeners) listener()
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }
}

class UnavailableCryptoProvider implements CryptoProvider {
  private readonly config: DeploymentConfig

  constructor(config: DeploymentConfig) {
    this.config = config
  }

  async getStatus(): Promise<CryptoProviderStatus> {
    return {
      available: false,
      profileHash: this.config.cryptoProfileHash || undefined,
      message: 'The browser crypto worker and pinned profile artifacts are not loaded.',
    }
  }

  private fail(): never {
    throw unavailable('The browser crypto worker is unavailable. No private operation was submitted.')
  }

  exportWalletMaterial(): Promise<never> { return Promise.reject(this.fail()) }
  importWalletMaterial(_material: Record<string, unknown>): Promise<never> { return Promise.reject(this.fail()) }
  createKeyRegistration(): Promise<never> { return Promise.reject(this.fail()) }
  prepareConfidentialTransfer(_input: { sender: PrivateAccountView; destinationAccountId: string; amount: string; destinationEncryptionKeyId: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareMerge(_input: { account: PrivateAccountView; scope: 'holder' | 'broker' }): Promise<never> { return Promise.reject(this.fail()) }
  prepareDraw(_input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareOrigination(_input: { proposal: ProposalSummary; broker: BrokerSummary; borrower: PrivateAccountView }): Promise<never> { return Promise.reject(this.fail()) }
  prepareRepayment(_input: { loan: LoanSummary; borrower: PrivateAccountView; mode: 'regular' | 'full' }): Promise<never> { return Promise.reject(this.fail()) }
  prepareLoanManagement(_input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<never> { return Promise.reject(this.fail()) }
  prepareSettlement(_input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareReconciliation(_input: { broker: BrokerSummary; expectedBookVersion: string }): Promise<never> { return Promise.reject(this.fail()) }
  authorizeAgreement(_proposal: ProposalSummary): Promise<never> { return Promise.reject(this.fail()) }
  decryptAgreement(_proposal: ProposalSummary): Promise<never> { return Promise.reject(this.fail()) }
  decryptPrivateBalance(_view: PrivateAccountView): Promise<never> { return Promise.reject(this.fail()) }
  decryptAudit(_bundle: AuditCiphertextBundle): Promise<never> { return Promise.reject(this.fail()) }
}

export function createUnavailableAdapters(config = deploymentConfigFromEnv()): AppAdapters {
  return {
    protocol: new UnavailableProtocolClient(config),
    wallet: new UnavailableWalletAdapter(),
    crypto: new UnavailableCryptoProvider(config),
  }
}

declare global {
  interface Window {
    __PRIVATE_LEDGER_ADAPTERS__?: Partial<AppAdapters>
  }
}

/**
 * The root integration can install real adapters before mounting the app. The
 * fallback remains intentionally unavailable; it never fabricates ledger data
 * or successful transactions.
 */
export function createBrowserAdapters(config = deploymentConfigFromEnv()): AppAdapters {
  const fallback = createUnavailableAdapters(config)
  const injected = typeof window !== 'undefined' ? window.__PRIVATE_LEDGER_ADAPTERS__ : undefined
  return {
    protocol: injected?.protocol ?? fallback.protocol,
    wallet: injected?.wallet ?? fallback.wallet,
    crypto: injected?.crypto ?? fallback.crypto,
  }
}
