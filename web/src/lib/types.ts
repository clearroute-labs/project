export type Role = 'lender' | 'broker' | 'borrower' | 'auditor'

export const CORE_MAX_PAYMENT_COUNT = 10_000

export type NetworkId = 'mainnet' | 'testnet' | (string & {})

export interface DeploymentConfig {
  networkId: NetworkId
  coreAccountId: string
  tokenAccountId: string
  rpcUrl: string
  /** Explicitly opt in to HTTP only for a local sandbox RPC. */
  allowInsecureLocalhost?: boolean
  cryptoProfileHash: string
  /** Immutable browser artifact manifest SHA-256 pin. */
  cryptoArtifactHash?: string
  /** Public URL for the deployment-pinned crypto manifest. */
  cryptoManifestUrl?: string
  /** Optional base URL when artifacts are served separately from the manifest. */
  cryptoArtifactBaseUrl?: string
  /** Development manifests are unfunded; production deployments must opt in explicitly. */
  cryptoFunded?: boolean
  assetDecimals: number
  assetSymbol: string
}

export interface ActionReceipt {
  operationId: string
  transactionHash?: string
  /** JSON-decoded method return value when Core returns one (for example a checkpoint ID). */
  returnValue?: string
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
  issuerPublicKey: string
  tokenAuditorKeyId: string
  tokenAuditorPublicKey: string
  cryptoProfileHash: string
  tokenTrustPolicy: string
  authorizationPolicy?: string
  freezePolicy?: string
  custodyCap?: string
  confidentialOutstanding?: string
}

/**
 * Closed-ended vaults expose their actual public lifecycle phase.  Investment
 * is the draw-enabled phase; it must not be rendered as draw-locked.
 */
export type VaultPhase = 'open' | 'subscription' | 'investment' | 'redemption' | 'closed'

export interface VaultSummary {
  vaultId: string
  ownerId: string
  brokerId?: string
  phase: VaultPhase
  assetAccount: string
  decimals: number
  assetsTotal: string
  lossUnrealized: string
  assetsAvailable: string
  sharesSupply: string
  yourShares?: string
  shareScale?: number
  checkpointEpochSeconds?: string
  checkpointDisclosurePolicy?: string
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
  bookVersion?: string
  privateBalanceKeyId: string
  inboxCommitment?: string
  /** Encrypted state required by the local prover; never plaintext values. */
  spendingCiphertext?: string
  inboxCiphertext?: string
  issuerBalanceCiphertext?: string
  auditorBalanceCiphertext?: string
  spendingCommitment?: string
  activePrincipalCiphertext?: string
  impairedPrincipalCiphertext?: string
  activePrincipalCommitment?: string
  impairedPrincipalCommitment?: string
  loanBookRoot?: string
  impairmentProvision?: string
  accountingVersion?: string
  riskVersion?: string
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
  auditorPublicKey?: string
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
  /** Ciphertext views and authenticated leaf data for the local prover. */
  principalCiphertexts?: string[]
  initialOwedCiphertexts?: string[]
  amountOwedCiphertexts?: string[]
  periodicPaymentCiphertexts?: string[]
  principalRemainingCiphertexts?: string[]
  cumulativeRepaidCiphertexts?: string[]
  accountingLeaf?: string
  borrowerKeyId?: string
  brokerKeyId?: string
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
  encryptedPrincipal?: string[]
  encryptedOwed?: string[]
  encryptedPayment?: string[]
  principalCommitment?: string
  owedCommitment?: string
  paymentCommitment?: string
  loanAuditorPublicKey?: string
  brokerSignature?: string
  borrowerSignature?: string
  borrowerKeyId?: string
  brokerKeyId?: string
  brokerAuthorizationEpoch?: string
  borrowerAuthorizationEpoch?: string
  brokerAuthorizationKeyId?: string
  borrowerAuthorizationKeyId?: string
  brokerDirectAuthorized?: boolean
  borrowerDirectAuthorized?: boolean
  /** Public recovery ciphertexts from the broker's encrypted exchange package. */
  transferRecovery?: RecoveryPair[]
  owedRecovery?: RecoveryPair[]
  paymentRecovery?: RecoveryPair[]
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
  status: 'requested' | 'in_flight' | 'result_recorded_success' | 'result_recorded_failure' | 'succeeded' | 'failed' | 'unknown'
  attempt: number
  lastUpdatedAt: number
}

export interface KeeperGrant {
  delegateId: string
  brokerId: string
  /** Core's keeper ABI currently permits only inbox merge and settlement. */
  scope: Array<'merge' | 'settle'>
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
  issuerBalanceCiphertext?: string
  auditorBalanceCiphertext?: string
  spendingVersion: string
  registered: boolean
}

/** Finalized local recovery state used to decide whether an inbox merge is needed. */
export interface PrivateBalanceState {
  spending: string
  inbox: string
  spendingVersion: string
}

export interface HolderKeyView {
  accountId: string
  encryptionKeyId: string
  publicKey: string
}

export interface AuditCiphertextBundle {
  scope: 'loan' | 'token'
  subjectId: string
  auditorKeyId: string
  /** Loan-auditor public key used to bind a local key reference to the chain. */
  auditorPublicKey?: string
  /** Token audits recover one registered account/broker through a declared mirror reader. */
  subjectKind?: 'holder' | 'broker'
  readerRole?: 'issuer' | 'token_auditor'
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
  /** Canonical confidential-crypto Statement JSON, transported as UTF-8 bytes to Core. */
  statement: string
  publicInputs: string[]
  profileHash: string
  artifactHash: string
  statementDigest: string
  /** Optional verifier metadata returned by the pinned crypto artifact. */
  statementKind?: number
  verifyingKeyHash?: string
  /**
   * Per-operation Core argument fields produced by the worker. Keys use the
   * Core ABI's snake_case names (for example `new_spending_ciphertext`,
   * `broker_book_root`, `transfer_views`, or `reconciliation`). Values are
   * canonical hex ciphertexts/commitments/roots or public decimal counters;
   * plaintext values, witnesses and secret keys are rejected by the RPC
   * mapper and must never cross this boundary.
   */
  operationArgs?: Record<string, unknown>
}

export interface KeyRegistration {
  encryptionPublicKey: string
  encryptionKeyId: string
  possessionProof: PreparedProof
  authorizationPublicKey: string
  authorizationSignature: string
}

/** Browser-local preparation for allocating a broker encryption key and its
 * proof-bound Core broker ID. The public key is returned by the worker after
 * key generation; callers never paste or invent it. */
export interface BrokerKeyPreparation {
  brokerId: string
  encryptionKeyId: string
  encryptionPublicKey: string
  possessionProof: PreparedProof
  /** True only when this call generated key material not already in the worker. */
  newKeyGenerated: boolean
}

/** Management is direct broker-owner authority in the current Core ABI. It
 * still refreshes and pins the public loan version before submission. */
export interface LoanManagementPreparation {
  loanId: string
  operation: 'impair' | 'unimpair' | 'default'
  expectedLoanVersion: string
}

export interface AuthorizationKeyRegistration {
  keyId: string
  publicKey: string
}

export interface BrokerKeyView {
  brokerId: string
  encryptionKeyId: string
  publicKey: string
}

export type RecoveryPair = readonly [string, string]

/** Public encrypted agreement material returned by the browser crypto worker. */
export interface AgreementDraft {
  /** Opaque worker-local handle; never sent to Core or persisted in plaintext. */
  draftId: string
  principalCiphertexts: string[]
  initialOwedCiphertexts: string[]
  periodicPaymentCiphertexts: string[]
  principalCommitment: string
  owedCommitment: string
  paymentCommitment: string
  encryptedAgreement: string
  /** Public recovery ciphertext pairs retained for the later origination proof. */
  transferRecovery: RecoveryPair[]
  owedRecovery: RecoveryPair[]
  paymentRecovery: RecoveryPair[]
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
  /**
   * Local sandbox-only credential import. Implementations must keep the
   * secret in memory and must never persist or transmit the credential file.
   */
  readonly credentialImport?: { label: string; accept: string }
  connect(): Promise<void>
  disconnect(): Promise<void>
  subscribe(listener: () => void): () => void
  importCredentialFile?(file: File): Promise<void>
}

export interface CryptoProviderStatus {
  available: boolean
  profileHash?: string
  artifactHash?: string
  wasmVersion?: string
  /** Counts are readiness metadata; private material remains in the worker. */
  walletKeyCount?: number
  draftCount?: number
  message: string
}

export interface CryptoProvider {
  getStatus(): Promise<CryptoProviderStatus>
  exportWalletMaterial(): Promise<Record<string, unknown>>
  importWalletMaterial(material: Record<string, unknown>): Promise<void>
  createKeyRegistration(): Promise<KeyRegistration>
  createAuthorizationKeyRegistration(): Promise<AuthorizationKeyRegistration>
  prepareAgreement(input: {
    brokerId?: string
    borrowerId?: string
    publicKeys: {
      borrower: string
      broker: string
      issuer: string
      tokenAuditor: string
      loanAuditor: string
    }
    principal: string
    initialOwed: string
    periodicPayment: string
    paymentCount: number
    maxPaymentCount: number
  }): Promise<AgreementDraft>
  prepareBrokerKeyRegistration(input: { ownerId: string; vaultId: string; encryptionKeyId: string; debtMaximum: string }): Promise<BrokerKeyPreparation>
  prepareShield(input: { account: PrivateAccountView; claimId: string }): Promise<PreparedProof>
  prepareUnshield(input: { account: PrivateAccountView; amount: string }): Promise<PreparedProof>
  prepareBrokerClosure(input: { brokerId: string }): Promise<PreparedProof>
  prepareConfidentialTransfer(input: {
    sender: PrivateAccountView
    destinationAccountId: string
    amount: string
    destinationEncryptionKeyId: string
    destinationEncryptionPublicKey?: string
  }): Promise<PreparedProof>
  prepareMerge(input: { account: PrivateAccountView; scope: 'holder' | 'broker'; brokerId?: string }): Promise<PreparedProof>
  prepareDraw(input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<PreparedProof>
  prepareBrokerOrigination(input: { proposal: ProposalSummary; broker: BrokerSummary }): Promise<PreparedProof>
  prepareRepayment(input: {
    loan: LoanSummary
    borrower: PrivateAccountView
    mode: 'regular' | 'full'
  }): Promise<PreparedProof>
  prepareLoanManagement(input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<LoanManagementPreparation>
  prepareSettlement(input: {
    broker: BrokerSummary
    amount: string
    expectedSpendingVersion: string
  }): Promise<PreparedProof>
  prepareReconciliation(input: { broker: BrokerSummary; expectedBookVersion: string; checkpointId?: string }): Promise<PreparedProof>
  authorizeAgreement(proposal: ProposalSummary): Promise<{ authorizationSignature: string }>
  decryptAgreement(proposal: ProposalSummary): Promise<{ fields: Array<{ label: string; value: string; unit: string }>; digest: string }>
  decryptPrivateBalance(view: PrivateAccountView): Promise<string>
  inspectPrivateBalance(view: PrivateAccountView): Promise<PrivateBalanceState>
  decryptAudit(bundle: AuditCiphertextBundle): Promise<DecryptedAuditView>
}

export interface ProtocolClient {
  readonly config: DeploymentConfig
  getAssetProfile(): Promise<AssetProfile>
  storageBalanceOf(accountId: string): Promise<string>
  storageDeposit(input: { accountId: string; deposit: string }): Promise<ActionReceipt>
  getDashboard(accountId: string): Promise<DashboardSnapshot>
  getPrivateAccount(accountId: string): Promise<PrivateAccountView>
  getHolderEncryptionKey(accountId: string): Promise<HolderKeyView>
  getBrokerEncryptionKey(brokerId: string): Promise<BrokerKeyView>
  getVaultBrokerIds(vaultId: string): Promise<string[]>
  /**
   * Return only currently live brokers in the vault membership vector. Closed
   * broker IDs remain in Core's append-only membership history, but must not
   * be presented to redemption proof preparation.
   */
  getVaultClosureBrokerIds(vaultId: string): Promise<string[]>
  getBrokerPrivateAccount(brokerId: string): Promise<PrivateAccountView>
  getProposal(proposalId: string): Promise<ProposalSummary>
  getAuditBundle(input: { scope: 'loan' | 'token'; subjectId: string; readerRole?: 'issuer' | 'token_auditor' }): Promise<AuditCiphertextBundle>
  registerHolder(input: KeyRegistration): Promise<ActionReceipt>
  registerAuthorizationKey(input: AuthorizationKeyRegistration): Promise<ActionReceipt>
  revokeAuthorizationKey(input: { keyId: string }): Promise<ActionReceipt>
  createVault(input: {
    assetAccount: string
    assetsMaximum: string
    kind: 'open_ended' | 'closed_ended'
    phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }
    shareScale: number
    sharesTransferable: boolean
    checkpointPolicy: { epochSeconds: number; disclosurePolicy: string }
  }): Promise<ActionReceipt>
  createBroker(input: { vaultId: string; brokerEncryptionKeyId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: PreparedProof }): Promise<ActionReceipt>
  depositExternal(input: { amount: string; depositId: string }): Promise<ActionReceipt>
  depositToVault(input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt>
  redeemShares(input: { vaultId: string; shares: string; minAmount: string; expiresAt: number; soleShareholderWaiver?: boolean; burnWorthless?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt>
  redeemAmount(input: { vaultId: string; assetsOut: string; maxSharesIn: string; expiresAt: number; soleShareholderWaiver?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt>
  transferShares(input: { vaultId: string; receiverId: string; shares: string }): Promise<ActionReceipt>
  requestPayout(input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt>
  finalizePayout(input: { operationId: string }): Promise<ActionReceipt>
  shield(input: { claimId: string; amount: string; proof: PreparedProof }): Promise<ActionReceipt>
  unshield(input: { amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  deleteLoan(input: { loanId: string }): Promise<ActionReceipt>
  deleteBroker(input: { brokerId: string; proof: PreparedProof }): Promise<ActionReceipt>
  mergeInbox(input: { accountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  mergeBrokerInbox(input: { brokerId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  draw(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  createProposal(input: {
    brokerId: string
    borrowerId: string
    vaultId: string
    borrowerKeyId: string
    brokerKeyId: string
    borrowerAuthorizationKeyId?: string
    brokerAuthorizationKeyId?: string
    auditorKeyId: string
    paymentCount: number
    paymentIntervalSeconds: number
    gracePeriodSeconds: number
    encryptedPrincipal: string[]
    encryptedOwed: string[]
    encryptedPayment: string[]
    principalCommitment: string
    owedCommitment: string
    paymentCommitment: string
    auditorPublicKey: string
    encryptedAgreement: string
    termsDigest: string
    brokerSignature: string
    borrowerSignature: string
    brokerAuthorizationEpoch?: string
    borrowerAuthorizationEpoch?: string
    brokerAuthorizationNonce?: string
    borrowerAuthorizationNonce?: string
    expiresAt: number
  }): Promise<ActionReceipt>
  authorizeProposal(input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt>
  revokeProposal(input: { proposalId: string }): Promise<ActionReceipt>
  originate(input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt>
  confidentialSend(input: {
    senderAccountId: string
    destinationAccountId: string
    expectedSpendingVersion: string
    proof: PreparedProof
  }): Promise<ActionReceipt>
  repay(input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; expectedBorrowerSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  manageLoan(input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; preparation?: LoanManagementPreparation; proof?: PreparedProof }): Promise<ActionReceipt>
  settle(input: { brokerId: string; amount: string; expectedSpendingVersion: string; expectedAccountingVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  reconcileCredit(input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt>
  prepareReconciliation(input: { brokerId: string }): Promise<ActionReceipt>
  grantKeeper(input: {
    brokerId: string
    delegateId: string
    delegateKeyId: string
    scope: KeeperGrant['scope']
    maxAmountPerOperation: string
    maxAmountPerWindow: string
    windowSeconds: number
    delegateEpoch: string
    expiresAt: number
  }): Promise<ActionReceipt>
  revokeKeeper(input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt>
}

export interface AppAdapters {
  protocol: ProtocolClient
  wallet: WalletAdapter
  crypto: CryptoProvider
}
