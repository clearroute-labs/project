export type Role = 'lender' | 'broker' | 'borrower' | 'auditor'

export type NetworkId = 'mainnet' | 'testnet' | (string & {})

export interface DeploymentConfig {
  networkId: NetworkId
  coreAccountId: string
  tokenAccountId: string
  rpcUrl: string
  cryptoProfileHash: string
}

export interface ActionReceipt {
  operationId: string
  transactionHash?: string
  status: 'submitted' | 'pending' | 'succeeded' | 'failed' | 'unknown'
  finalized: boolean
}

export interface ProtocolErrorShape {
  category:
    | 'INVALID_ENCODING'
    | 'INVALID_AMOUNT'
    | 'WRONG_ASSET'
    | 'UNAUTHORIZED'
    | 'ACCOUNT_FROZEN'
    | 'NOT_REGISTERED'
    | 'WRONG_PHASE'
    | 'EXPIRED'
    | 'STALE_STATE'
    | 'BAD_PROOF'
    | 'INSUFFICIENT_PUBLIC_FUNDS'
    | 'INSUFFICIENT_PRIVATE_FUNDS'
    | 'DEBT_LIMIT'
    | 'ACCOUNTING_PENDING'
    | 'TOO_SOON'
    | 'LOAN_CLOSED'
    | 'HAS_OBLIGATIONS'
    | 'SLIPPAGE'
    | 'OPERATION_PENDING'
    | 'UNSUPPORTED_PROFILE'
    | 'ADAPTER_UNAVAILABLE'
    | 'WALLET_REJECTED'
    | 'NETWORK_OFFLINE'
    | 'UNKNOWN'
  message: string
  retryable?: boolean
}

export class ProtocolError extends Error {
  readonly details: ProtocolErrorShape

  constructor(details: ProtocolErrorShape) {
    super(details.message)
    this.name = 'ProtocolError'
    this.details = details
  }
}

export interface AssetProfile {
  tokenAccount: string
  decimals: number
  controllerAccount: string
  issuerKeyId: string
  tokenAuditorKeyId: string
  cryptoProfileHash: string
  tokenTrustPolicy: string
}

export type VaultPhase = 'open' | 'draw_locked' | 'settlement_only' | 'closed'

export interface VaultSummary {
  vaultId: string
  ownerId: string
  brokerId?: string
  phase: VaultPhase
  assetAccount: string
  decimals: number
  assetsTotal: string
  assetsAvailable: string
  sharesSupply: string
  yourShares?: string
  accountingVersion: string
  checkpointStatus: 'current' | 'pending' | 'stale' | 'unknown'
}

export interface BrokerSummary {
  brokerId: string
  ownerId: string
  vaultId: string
  debtTotal: string
  debtCeiling: string
  spendingVersion: string
  inboxVersion: string
  bookVersion?: string
  privateBalanceKeyId: string
  checkpointStatus: 'current' | 'pending' | 'stale' | 'unknown'
  keeperCount: number
}

export type LoanStatus = 'active' | 'impaired' | 'defaulted' | 'paid' | 'deleted'

export interface LoanSummary {
  loanId: string
  proposalId: string
  brokerId: string
  borrowerId: string
  vaultId: string
  auditorKeyId: string
  status: LoanStatus
  paymentRemaining: number
  paymentCount: number
  paymentIntervalSeconds: number
  gracePeriodSeconds: number
  nextPaymentDue: number
  stateVersion: string
  termsDigest: string
  // Monetary terms remain encrypted. The browser can decrypt only after an
  // explicit user action with the appropriate local key.
  principalCiphertextDigest: string
  owedCiphertextDigest: string
}

export interface ProposalSummary {
  proposalId: string
  brokerId: string
  borrowerId: string
  vaultId: string
  expiresAt: number
  status: 'pending' | 'borrower_authorized' | 'broker_authorized' | 'consumed' | 'revoked' | 'expired'
  termsDigest: string
  encryptedAgreement: string
  encryptionKeyId: string
}

export interface PublicClaim {
  claimId: string
  ownerId: string
  amount: string
  assetAccount: string
  status: 'available' | 'reserved' | 'pending' | 'restored' | 'paid'
  payoutOperationId?: string
}

export interface PayoutSummary {
  operationId: string
  claimId: string
  amount: string
  recipientId: string
  status: 'requested' | 'in_flight' | 'result_recorded' | 'succeeded' | 'failed' | 'unknown'
  attempt: number
  lastUpdatedAt: number
}

export interface KeeperGrant {
  delegateId: string
  brokerId: string
  scope: Array<'merge' | 'settle' | 'reconcile' | 'manage_loan'>
  maxAmount?: string
  expiresAt: number
  epoch: string
  revoked: boolean
}

export interface DashboardSnapshot {
  fetchedAt: number
  asset: AssetProfile
  vaults: VaultSummary[]
  brokers: BrokerSummary[]
  loans: LoanSummary[]
  proposals: ProposalSummary[]
  claims: PublicClaim[]
  payouts: PayoutSummary[]
  keeperGrants: KeeperGrant[]
  publicNotice?: string
}

export interface PrivateAccountView {
  accountId: string
  assetAccount: string
  encryptionKeyId: string
  balanceCiphertext: string
  balanceCommitment: string
  inboxCiphertext: string
  inboxCommitment: string
  spendingVersion: string
  inboxVersion: string
  registered: boolean
}

export interface AuditCiphertextBundle {
  scope: 'loan' | 'token'
  subjectId: string
  auditorKeyId: string
  cryptoProfileHash: string
  ciphertexts: Record<string, string>
  commitments: Record<string, string>
  versions: Record<string, string>
  fetchedAt: number
}

export interface DecryptedAuditView {
  scope: 'loan' | 'token'
  subjectId: string
  fields: Array<{ label: string; value: string; unit: string }>
  sourceDigest: string
  decryptedAt: number
}

export interface PreparedProof {
  /** Canonical context digest returned by Core.prepare_context. */
  context: string
  proof: string
  publicInputs: string[]
  profileHash: string
  artifactHash: string
  statementDigest: string
  /** Per-operation ciphertexts/roots produced by the worker. Never plaintext witnesses. */
  operationArgs?: Record<string, unknown>
}

export interface KeyRegistration {
  encryptionPublicKey: string
  encryptionKeyId: string
  possessionProof: string
  authorizationPublicKey: string
}

export interface EncryptedWalletBackup {
  version: 1
  kdf: 'PBKDF2-SHA-256'
  iterations: number
  cipher: 'AES-256-GCM'
  salt: string
  iv: string
  ciphertext: string
  createdAt: string
}

export interface WalletAdapter {
  readonly status: 'disconnected' | 'connecting' | 'connected' | 'error'
  readonly accountId?: string
  readonly networkId?: NetworkId
  readonly error?: string
  connect(): Promise<void>
  disconnect(): Promise<void>
  subscribe(listener: () => void): () => void
}

export interface CryptoProviderStatus {
  available: boolean
  profileHash?: string
  artifactHash?: string
  wasmVersion?: string
  message: string
}

export interface CryptoProvider {
  getStatus(): Promise<CryptoProviderStatus>
  exportWalletMaterial(): Promise<Record<string, unknown>>
  importWalletMaterial(material: Record<string, unknown>): Promise<void>
  createKeyRegistration(): Promise<KeyRegistration>
  prepareConfidentialTransfer(input: {
    sender: PrivateAccountView
    destinationAccountId: string
    amount: string
    destinationEncryptionKeyId: string
  }): Promise<PreparedProof>
  prepareMerge(input: { account: PrivateAccountView; scope: 'holder' | 'broker' }): Promise<PreparedProof>
  prepareDraw(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof>
  prepareOrigination(input: {
    proposal: ProposalSummary
    broker: BrokerSummary
    borrower: PrivateAccountView
  }): Promise<PreparedProof>
  prepareRepayment(input: {
    loan: LoanSummary
    borrower: PrivateAccountView
    mode: 'regular' | 'full'
  }): Promise<PreparedProof>
  prepareLoanManagement(input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<PreparedProof>
  prepareSettlement(input: {
    broker: BrokerSummary
    amount: string
    expectedSpendingVersion: string
  }): Promise<PreparedProof>
  prepareReconciliation(input: { broker: BrokerSummary; expectedBookVersion: string }): Promise<PreparedProof>
  authorizeAgreement(proposal: ProposalSummary): Promise<{ authorizationSignature: string }>
  decryptAgreement(proposal: ProposalSummary): Promise<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string }>
  decryptPrivateBalance(view: PrivateAccountView): Promise<string>
  decryptAudit(bundle: AuditCiphertextBundle): Promise<DecryptedAuditView>
}

export interface ProtocolClient {
  readonly config: DeploymentConfig
  getAssetProfile(): Promise<AssetProfile>
  getDashboard(accountId: string): Promise<DashboardSnapshot>
  getPrivateAccount(accountId: string): Promise<PrivateAccountView>
  getBrokerPrivateAccount(brokerId: string): Promise<PrivateAccountView>
  getProposal(proposalId: string): Promise<ProposalSummary>
  getAuditBundle(input: { scope: 'loan' | 'token'; subjectId: string }): Promise<AuditCiphertextBundle>
  registerHolder(input: KeyRegistration): Promise<ActionReceipt>
  createVault(input: {
    assetAccount: string
    assetsMaximum: string
    kind: 'open_ended' | 'closed_ended'
    phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }
    shareScale: number
    sharesTransferable: boolean
    checkpointPolicy: { epochSeconds: number; disclosurePolicy: string }
  }): Promise<ActionReceipt>
  createBroker(input: { vaultId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: string }): Promise<ActionReceipt>
  depositExternal(input: { amount: string; depositId: string }): Promise<ActionReceipt>
  depositToVault(input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt>
  redeemShares(input: { vaultId: string; shares: string; minAmount: string; expiresAt: number }): Promise<ActionReceipt>
  requestPayout(input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt>
  mergeInbox(input: { accountId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  mergeBrokerInbox(input: { brokerId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  draw(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  createProposal(input: {
    brokerId: string
    borrowerId: string
    vaultId: string
    borrowerKeyId: string
    brokerKeyId: string
    auditorKeyId: string
    paymentCount: number
    paymentIntervalSeconds: number
    gracePeriodSeconds: number
    encryptedPrincipal: string
    encryptedOwed: string
    encryptedPayment: string
    encryptedAgreement: string
    termsDigest: string
    brokerSignature: string
    borrowerSignature: string
    brokerAuthorizationEpoch: string
    borrowerAuthorizationEpoch: string
    expiresAt: number
  }): Promise<ActionReceipt>
  authorizeProposal(input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt>
  originate(input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt>
  confidentialSend(input: {
    senderAccountId: string
    destinationAccountId: string
    expectedSpendingVersion: string
    proof: PreparedProof
  }): Promise<ActionReceipt>
  repay(input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  manageLoan(input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  settle(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  reconcileCredit(input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  prepareReconciliation(input: { brokerId: string }): Promise<ActionReceipt>
  grantKeeper(input: { brokerId: string; delegateId: string; scope: KeeperGrant['scope']; maxAmount?: string; expiresAt: number }): Promise<ActionReceipt>
  revokeKeeper(input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt>
}

export interface AppAdapters {
  protocol: ProtocolClient
  wallet: WalletAdapter
  crypto: CryptoProvider
}
