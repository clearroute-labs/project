import {
  ProtocolError,
  type ActionReceipt,
  type AgreementDraft,
  type AuthorizationKeyRegistration,
  type AppAdapters,
  type AuditCiphertextBundle,
  type BrokerKeyPreparation,
  type BrokerKeyView,
  type BrokerSummary,
  type CryptoProvider,
  type CryptoProviderStatus,
  type DashboardSnapshot,
  type DeploymentConfig,
  type KeyRegistration,
  type KeeperGrant,
  type HolderKeyView,
  type LoanSummary,
  type LoanManagementPreparation,
  type PrivateAccountView,
  type PrivateBalanceState,
  type PreparedProof,
  type ProposalSummary,
  type ProtocolClient,
  type PublicClaim,
  type WalletAdapter,
} from './types'
import { createRpcProtocolClient } from './nearClient'
import { isSandboxCredentialDeployment, SandboxCredentialWallet } from './nearWallet'
import { NearConnectWallet } from './nearConnectWallet'
import { privyConfiguration, privyWalletManifest } from './privyConfig'
import { createWorkerCryptoProvider } from './workerCrypto'

import { deploymentConfigFromEnv } from './deploymentConfig'
export { deploymentConfigFromEnv } from './deploymentConfig'

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

  getTransactionStatus(_input: { transactionHash: string; signerId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  getAssetProfile(): Promise<never> { return Promise.reject(this.fail()) }
  storageBalanceOf(_accountId: string): Promise<string> { return Promise.reject(this.fail()) }
  storageDeposit(_input: { accountId: string; deposit: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  getDashboard(_accountId: string): Promise<DashboardSnapshot> { return Promise.reject(this.fail()) }
  getPrivateAccount(_accountId: string): Promise<PrivateAccountView> { return Promise.reject(this.fail()) }
  getHolderEncryptionKey(_accountId: string): Promise<HolderKeyView> { return Promise.reject(this.fail()) }
  getBrokerEncryptionKey(_brokerId: string): Promise<BrokerKeyView> { return Promise.reject(this.fail()) }
  getVaultBrokerIds(_vaultId: string): Promise<string[]> { return Promise.reject(this.fail()) }
  getVaultClosureBrokerIds(_vaultId: string): Promise<string[]> { return Promise.reject(this.fail()) }
  getBrokerPrivateAccount(_brokerId: string): Promise<PrivateAccountView> { return Promise.reject(this.fail()) }
  getProposal(_proposalId: string): Promise<ProposalSummary> { return Promise.reject(this.fail()) }
  getAuditBundle(_input: { scope: 'loan' | 'token'; subjectId: string; readerRole?: 'issuer' | 'token_auditor' }): Promise<AuditCiphertextBundle> { return Promise.reject(this.fail()) }
  registerHolder(_input: KeyRegistration): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  registerAuthorizationKey(_input: AuthorizationKeyRegistration): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  revokeAuthorizationKey(_input: { keyId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createVault(_input: { assetAccount: string; assetsMaximum: string; kind: 'open_ended' | 'closed_ended'; phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }; shareScale: number; sharesTransferable: boolean; checkpointPolicy: { epochSeconds: number; disclosurePolicy: string } }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createBroker(_input: { vaultId: string; brokerEncryptionKeyId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  depositExternal(_input: { amount: string; depositId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  depositToVault(_input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  redeemShares(_input: { vaultId: string; shares: string; minAmount: string; expiresAt: number; soleShareholderWaiver?: boolean; burnWorthless?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  redeemAmount(_input: { vaultId: string; assetsOut: string; maxSharesIn: string; expiresAt: number; soleShareholderWaiver?: boolean; brokerZeroProofs?: PreparedProof[] }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  transferShares(_input: { vaultId: string; receiverId: string; shares: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  requestPayout(_input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  finalizePayout(_input: { operationId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  shield(_input: { claimId: string; amount: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  unshield(_input: { amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  deleteLoan(_input: { loanId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  deleteBroker(_input: { brokerId: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  mergeInbox(_input: { accountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  mergeBrokerInbox(_input: { brokerId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  draw(_input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  createProposal(_input: { brokerId: string; borrowerId: string; vaultId: string; borrowerKeyId: string; brokerKeyId: string; borrowerAuthorizationKeyId?: string; brokerAuthorizationKeyId?: string; auditorKeyId: string; auditorPublicKey: string; paymentCount: number; paymentIntervalSeconds: number; gracePeriodSeconds: number; encryptedPrincipal: string[]; encryptedOwed: string[]; encryptedPayment: string[]; principalCommitment: string; owedCommitment: string; paymentCommitment: string; encryptedAgreement: string; termsDigest: string; brokerSignature: string; borrowerSignature: string; brokerAuthorizationEpoch?: string; borrowerAuthorizationEpoch?: string; brokerAuthorizationNonce?: string; borrowerAuthorizationNonce?: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  authorizeProposal(_input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  revokeProposal(_input: { proposalId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  originate(_input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  confidentialSend(_input: { senderAccountId: string; destinationAccountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  repay(_input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; expectedBorrowerSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  manageLoan(_input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; preparation?: LoanManagementPreparation; proof?: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  settle(_input: { brokerId: string; amount: string; expectedSpendingVersion: string; expectedAccountingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  reconcileCredit(_input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  prepareReconciliation(_input: { brokerId: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  grantKeeper(_input: { brokerId: string; delegateId: string; delegateKeyId: string; scope: KeeperGrant['scope']; maxAmountPerOperation: string; maxAmountPerWindow: string; windowSeconds: number; delegateEpoch: string; expiresAt: number }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
  revokeKeeper(_input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt> { return Promise.reject(this.fail()) }
}

class UnavailableWalletAdapter implements WalletAdapter {
  status: WalletAdapter['status'] = 'disconnected'
  readonly accountId = undefined
  readonly networkId = undefined
  readonly error = undefined
  private readonly listeners = new Set<() => void>()

  async connect(): Promise<void> {
    throw unavailable('Wallet connection is unavailable. Configure the NEAR deployment first.')
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
      message: 'Secure account features are unavailable in this deployment.',
    }
  }

  private fail(): never {
    throw unavailable('Secure account features are unavailable. No private operation was submitted.')
  }

  exportWalletMaterial(): Promise<never> { return Promise.reject(this.fail()) }
  importWalletMaterial(_material: Record<string, unknown>): Promise<never> { return Promise.reject(this.fail()) }
  createKeyRegistration(): Promise<never> { return Promise.reject(this.fail()) }
  createAuthorizationKeyRegistration(): Promise<never> { return Promise.reject(this.fail()) }
  prepareAgreement(_input: { brokerId?: string; borrowerId?: string; publicKeys: { borrower: string; broker: string; issuer: string; tokenAuditor: string; loanAuditor: string }; principal: string; initialOwed: string; periodicPayment: string; paymentCount: number; maxPaymentCount: number }): Promise<AgreementDraft> { return Promise.reject(this.fail()) }
  prepareBrokerKeyRegistration(_input: { ownerId: string; vaultId: string; encryptionKeyId: string; debtMaximum: string }): Promise<BrokerKeyPreparation> { return Promise.reject(this.fail()) }
  prepareShield(_input: { account: PrivateAccountView; claimId: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareUnshield(_input: { account: PrivateAccountView; amount: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareBrokerClosure(_input: { brokerId: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareConfidentialTransfer(_input: { sender: PrivateAccountView; destinationAccountId: string; amount: string; destinationEncryptionKeyId: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareMerge(_input: { account: PrivateAccountView; scope: 'holder' | 'broker'; brokerId?: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareDraw(_input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareBrokerOrigination(_input: { proposal: ProposalSummary; broker: BrokerSummary }): Promise<never> { return Promise.reject(this.fail()) }
  prepareRepayment(_input: { loan: LoanSummary; borrower: PrivateAccountView; mode: 'regular' | 'full' }): Promise<never> { return Promise.reject(this.fail()) }
  prepareLoanManagement(_input: { loan: LoanSummary; operation: 'impair' | 'unimpair' | 'default' }): Promise<LoanManagementPreparation> { return Promise.reject(this.fail()) }
  prepareSettlement(_input: { broker: BrokerSummary; amount: string; expectedSpendingVersion: string }): Promise<never> { return Promise.reject(this.fail()) }
  prepareReconciliation(_input: { broker: BrokerSummary; expectedBookVersion: string; checkpointId?: string }): Promise<never> { return Promise.reject(this.fail()) }
  authorizeAgreement(_proposal: ProposalSummary): Promise<never> { return Promise.reject(this.fail()) }
  decryptAgreement(_proposal: ProposalSummary): Promise<never> { return Promise.reject(this.fail()) }
  decryptPrivateBalance(_view: PrivateAccountView): Promise<never> { return Promise.reject(this.fail()) }
  inspectPrivateBalance(_view: PrivateAccountView): Promise<PrivateBalanceState> { return Promise.reject(this.fail()) }
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
  const manifestUrl = config.cryptoManifestUrl || '/crypto/manifest.json'
  const configured = Boolean(config.coreAccountId && config.tokenAccountId && config.cryptoProfileHash && /^[a-f\d]{64}$/i.test(config.cryptoProfileHash) && config.cryptoArtifactHash && /^[a-f\d]{64}$/i.test(config.cryptoArtifactHash) && Number.isInteger(config.assetDecimals) && config.assetDecimals >= 0 && config.assetDecimals <= 38)
  if (!injected?.protocol && !injected?.wallet && configured) {
    try {
      const privy = typeof window !== 'undefined' ? privyConfiguration(config, window.location.origin) : undefined
      const wallet = isSandboxCredentialDeployment(config)
        ? new SandboxCredentialWallet(config)
        : new NearConnectWallet(config, { additionalWallets: privy ? [privyWalletManifest(privy)] : [] })
      const { protocol } = createRpcProtocolClient(config, wallet)
      let crypto = injected?.crypto
      if (!crypto && config.cryptoArtifactHash && typeof Worker !== 'undefined') {
        crypto = createWorkerCryptoProvider({
          expectedProfileHash: config.cryptoProfileHash,
          expectedArtifactHash: config.cryptoArtifactHash,
          manifestUrl,
          artifactBaseUrl: config.cryptoArtifactBaseUrl,
          networkId: config.networkId,
          coreAccountId: config.coreAccountId,
          assetId: config.tokenAccountId,
          funded: config.cryptoFunded === true,
          rpcUrl: config.rpcUrl,
          allowInsecureLocalhost: config.allowInsecureLocalhost,
        })
      }
      return { protocol, wallet, crypto: crypto ?? fallback.crypto }
    } catch {
      // Invalid deployment transport remains visibly disconnected; no fake client is returned.
    }
  }
  return {
    protocol: injected?.protocol ?? fallback.protocol,
    wallet: injected?.wallet ?? fallback.wallet,
    crypto: injected?.crypto ?? fallback.crypto,
  }
}
