import { useMemo } from 'react'
import { App } from '../../src/App'
import { ProtocolError, type AppAdapters, type AssetProfile, type AuditCiphertextBundle, type BrokerSummary, type CryptoProvider, type CryptoProviderStatus, type DashboardSnapshot, type DeploymentConfig, type HolderKeyView, type LoanSummary, type PrivateAccountView, type ProposalSummary, type ProtocolClient, type VaultSummary, type WalletAdapter } from '../../src/lib/types'

/**
 * Synthetic, test-only data for design review. This fixture never connects to
 * NEAR, creates keys, signs a transaction, or sends a mutation to a network.
 */

export type VisualFixtureState = 'populated' | 'empty' | 'error' | 'loading'

const VISUAL_ACCOUNT_ID = 'design-review.testnet'
const VISUAL_BROKER_ID = 'broker-visual-001'
const VISUAL_VAULT_ID = 'vault-visual-001'
const VISUAL_LOAN_ID = 'loan-visual-001'
const VISUAL_PROPOSAL_ID = 'proposal-visual-001'
const VISUAL_TOKEN_ACCOUNT = 'test-token.visual.testnet'
const VISUAL_PROFILE_HASH = 'a'.repeat(64)
const VISUAL_ARTIFACT_HASH = 'b'.repeat(64)
const VISUAL_NOW = Math.floor(Date.now() / 1000) + 86_400 * 30

const visualConfig: DeploymentConfig = {
  networkId: 'testnet',
  coreAccountId: 'core.visual.testnet',
  tokenAccountId: VISUAL_TOKEN_ACCOUNT,
  rpcUrl: 'https://rpc.testnet.near.org',
  allowInsecureLocalhost: true,
  cryptoProfileHash: VISUAL_PROFILE_HASH,
  cryptoArtifactHash: VISUAL_ARTIFACT_HASH,
  cryptoManifestUrl: '/crypto/manifest.json',
  cryptoFunded: true,
  assetDecimals: 6,
  assetSymbol: 'TEST',
  testnetFaucet: true,
}

const visualAsset: AssetProfile = {
  tokenAccount: VISUAL_TOKEN_ACCOUNT,
  decimals: 6,
  controllerAccount: 'controller.visual.testnet',
  issuerKeyId: 'issuer-key-visual-001',
  issuerPublicKey: 'ed25519:visual-issuer-public-key',
  tokenAuditorKeyId: 'token-auditor-key-visual-001',
  tokenAuditorPublicKey: 'ed25519:visual-token-auditor-public-key',
  cryptoProfileHash: VISUAL_PROFILE_HASH,
  tokenTrustPolicy: 'controller_only',
  authorizationPolicy: 'registered_keys',
  freezePolicy: 'issuer_and_auditor',
  custodyCap: '250000000000',
  confidentialOutstanding: '75000000',
}

const visualVault: VaultSummary = {
  vaultId: VISUAL_VAULT_ID,
  ownerId: VISUAL_ACCOUNT_ID,
  brokerId: VISUAL_BROKER_ID,
  phase: 'investment',
  assetAccount: VISUAL_TOKEN_ACCOUNT,
  decimals: 6,
  assetsTotal: '125000000',
  lossUnrealized: '125000',
  assetsAvailable: '116500000',
  sharesSupply: '125000000',
  yourShares: '42000000',
  shareScale: 6,
  checkpointEpochSeconds: '3600',
  checkpointDisclosurePolicy: 'aggregate_only',
  accountingVersion: '42',
  checkpointStatus: 'current',
}

const visualBroker: BrokerSummary = {
  brokerId: VISUAL_BROKER_ID,
  ownerId: VISUAL_ACCOUNT_ID,
  vaultId: VISUAL_VAULT_ID,
  debtTotal: '75000000',
  debtCeiling: '200000000',
  spendingVersion: '7',
  bookVersion: '18',
  privateBalanceKeyId: 'broker-key-visual-001',
  inboxCommitment: 'commitment-broker-inbox-visual-001',
  spendingCiphertext: 'ciphertext-broker-spending-visual-001',
  inboxCiphertext: 'ciphertext-broker-inbox-visual-001',
  issuerBalanceCiphertext: 'ciphertext-broker-issuer-visual-001',
  auditorBalanceCiphertext: 'ciphertext-broker-auditor-visual-001',
  spendingCommitment: 'commitment-broker-spending-visual-001',
  activePrincipalCiphertext: 'ciphertext-active-principal-visual-001',
  impairedPrincipalCiphertext: 'ciphertext-impaired-principal-visual-001',
  activePrincipalCommitment: 'commitment-active-principal-visual-001',
  impairedPrincipalCommitment: 'commitment-impaired-principal-visual-001',
  loanBookRoot: 'root-loan-book-visual-001',
  impairmentProvision: '250000',
  accountingVersion: '42',
  riskVersion: '3',
  checkpointStatus: 'current',
  keeperCount: 2,
}

const visualLoan: LoanSummary = {
  loanId: VISUAL_LOAN_ID,
  proposalId: VISUAL_PROPOSAL_ID,
  brokerId: VISUAL_BROKER_ID,
  borrowerId: 'borrower-visual.testnet',
  vaultId: VISUAL_VAULT_ID,
  auditorKeyId: 'loan-auditor-key-visual-001',
  auditorPublicKey: 'ed25519:visual-loan-auditor-public-key',
  status: 'active',
  paymentRemaining: 8,
  paymentCount: 12,
  paymentIntervalSeconds: 2_592_000,
  gracePeriodSeconds: 86_400,
  nextPaymentDue: VISUAL_NOW + 86_400 * 7,
  stateVersion: '5',
  termsDigest: 'digest-loan-terms-visual-001',
  principalCiphertextDigest: 'digest-principal-ciphertext-visual-001',
  owedCiphertextDigest: 'digest-owed-ciphertext-visual-001',
  principalCiphertexts: ['ciphertext-principal-visual-001'],
  initialOwedCiphertexts: ['ciphertext-owed-visual-001'],
  amountOwedCiphertexts: ['ciphertext-amount-owed-visual-001'],
  periodicPaymentCiphertexts: ['ciphertext-periodic-payment-visual-001'],
  principalRemainingCiphertexts: ['ciphertext-principal-remaining-visual-001'],
  cumulativeRepaidCiphertexts: ['ciphertext-cumulative-repaid-visual-001'],
  accountingLeaf: 'leaf-accounting-visual-001',
  borrowerKeyId: 'borrower-key-visual-001',
  brokerKeyId: 'broker-key-visual-001',
}

const visualProposal: ProposalSummary = {
  proposalId: VISUAL_PROPOSAL_ID,
  brokerId: VISUAL_BROKER_ID,
  borrowerId: visualLoan.borrowerId,
  vaultId: VISUAL_VAULT_ID,
  expiresAt: VISUAL_NOW + 86_400 * 14,
  status: 'pending',
  termsDigest: visualLoan.termsDigest,
  encryptedAgreement: 'ciphertext-agreement-visual-001',
  encryptionKeyId: 'loan-auditor-key-visual-001',
  encryptedPrincipal: ['ciphertext-proposal-principal-visual-001'],
  encryptedOwed: ['ciphertext-proposal-owed-visual-001'],
  encryptedPayment: ['ciphertext-proposal-payment-visual-001'],
  principalCommitment: 'commitment-proposal-principal-visual-001',
  owedCommitment: 'commitment-proposal-owed-visual-001',
  paymentCommitment: 'commitment-proposal-payment-visual-001',
  loanAuditorPublicKey: visualLoan.auditorPublicKey,
  brokerSignature: 'signature-broker-visual-001',
  borrowerSignature: 'signature-borrower-visual-001',
  borrowerKeyId: 'borrower-key-visual-001',
  brokerKeyId: 'broker-key-visual-001',
  brokerAuthorizationEpoch: '2',
  borrowerAuthorizationEpoch: '1',
  brokerAuthorizationKeyId: 'broker-auth-key-visual-001',
  borrowerAuthorizationKeyId: 'borrower-auth-key-visual-001',
  brokerDirectAuthorized: true,
  borrowerDirectAuthorized: false,
  transferRecovery: [['recovery-transfer-a', 'recovery-transfer-b']],
  owedRecovery: [['recovery-owed-a', 'recovery-owed-b']],
  paymentRecovery: [['recovery-payment-a', 'recovery-payment-b']],
}

const visualPrivateAccount: PrivateAccountView = {
  accountId: VISUAL_ACCOUNT_ID,
  assetAccount: VISUAL_TOKEN_ACCOUNT,
  encryptionKeyId: 'holder-key-visual-001',
  balanceCiphertext: 'ciphertext-holder-balance-visual-001',
  balanceCommitment: 'commitment-holder-balance-visual-001',
  inboxCiphertext: 'ciphertext-holder-inbox-visual-001',
  inboxCommitment: 'commitment-holder-inbox-visual-001',
  spendingVersion: '7',
  registered: true,
}

const visualSnapshot: DashboardSnapshot = {
  fetchedAt: VISUAL_NOW * 1000,
  asset: visualAsset,
  vaults: [visualVault],
  brokers: [visualBroker],
  loans: [visualLoan],
  proposals: [visualProposal],
  claims: [{ claimId: 'claim-visual-001', ownerId: VISUAL_ACCOUNT_ID, amount: '2500000', assetAccount: VISUAL_TOKEN_ACCOUNT, status: 'available' }],
  payouts: [{ operationId: 'payout-visual-001', claimId: 'claim-visual-002', amount: '1250000', recipientId: 'recipient-visual.testnet', status: 'result_recorded_success', attempt: 1, lastUpdatedAt: VISUAL_NOW * 1000 }],
  keeperGrants: [{ delegateId: 'keeper-visual.testnet', brokerId: VISUAL_BROKER_ID, scope: ['merge', 'settle'], maxAmount: '5000000', expiresAt: VISUAL_NOW + 86_400 * 30, epoch: '4', revoked: false }],
  publicNotice: 'Synthetic design-review data. No network state is loaded in this fixture.',
}

const emptySnapshot: DashboardSnapshot = {
  ...visualSnapshot,
  fetchedAt: VISUAL_NOW * 1000,
  vaults: [],
  brokers: [],
  loans: [],
  proposals: [],
  claims: [],
  payouts: [],
  keeperGrants: [],
}

const visualCryptoStatus: CryptoProviderStatus = {
  available: true,
  profileHash: VISUAL_PROFILE_HASH,
  artifactHash: VISUAL_ARTIFACT_HASH,
  wasmVersion: 'visual-fixture-1',
  walletKeyCount: 0,
  authorizationKeyCount: 0,
  draftCount: 0,
  message: 'Design-review crypto provider ready (synthetic; no keys loaded).',
}

function disabledMutation<T>(): Promise<T> {
  throw new Error('Visual fixture mutations are disabled: no keys, signatures, or on-chain writes are available.')
}

function snapshotFor(state: VisualFixtureState): DashboardSnapshot {
  return state === 'empty' ? emptySnapshot : visualSnapshot
}

function createWallet(): WalletAdapter {
  const listeners = new Set<() => void>()
  return {
    get status() { return 'connected' as const },
    get accountId() { return VISUAL_ACCOUNT_ID },
    get networkId() { return 'testnet' },
    get error() { return undefined },
    async connect() { return disabledMutation<void>() },
    async disconnect() { return disabledMutation<void>() },
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
  }
}

function createCrypto(): CryptoProvider {
  return {
    async getStatus() { return visualCryptoStatus },
    async exportWalletMaterial() { return {} },
    async importWalletMaterial() { return disabledMutation<void>() },
    async lockWallet() {},
    createKeyRegistration: disabledMutation,
    createAuthorizationKeyRegistration: disabledMutation,
    prepareAgreement: disabledMutation,
    prepareBrokerKeyRegistration: disabledMutation,
    prepareShield: disabledMutation,
    prepareUnshield: disabledMutation,
    prepareBrokerClosure: disabledMutation,
    prepareConfidentialTransfer: disabledMutation,
    prepareMerge: disabledMutation,
    prepareDraw: disabledMutation,
    prepareBrokerOrigination: disabledMutation,
    prepareRepayment: disabledMutation,
    prepareLoanManagement: disabledMutation,
    prepareSettlement: disabledMutation,
    prepareReconciliation: disabledMutation,
    authorizeAgreement: disabledMutation,
    decryptAgreement: disabledMutation,
    decryptPrivateBalance: disabledMutation,
    inspectPrivateBalance: disabledMutation,
    decryptAudit: disabledMutation,
  }
}

function createProtocol(state: VisualFixtureState): ProtocolClient {
  const snapshot = snapshotFor(state)
  const getDashboard = async () => {
    if (state === 'loading') await new Promise<never>(() => {})
    if (state === 'error') throw new ProtocolError({ category: 'NETWORK_OFFLINE', message: 'Synthetic visual fixture read failed.', retryable: true })
    return snapshot
  }
  return {
    config: visualConfig,
    getTransactionStatus: async () => ({ operationId: 'visual-read-only', status: 'unknown', finalized: false }),
    getAssetProfile: async () => visualAsset,
    storageBalanceOf: async () => '100000000000000000000000',
    storageDeposit: disabledMutation,
    testTokenStatus: async () => ({ balance: '1000000000', storageBalance: '10000000000000000000000', claimed: false }),
    registerTestTokenStorage: disabledMutation,
    claimTestTokens: disabledMutation,
    getDashboard,
    getPrivateAccount: async () => visualPrivateAccount,
    getHolderEncryptionKey: async () => ({ accountId: VISUAL_ACCOUNT_ID, encryptionKeyId: 'holder-key-visual-001', publicKey: 'ed25519:visual-holder-public-key' } satisfies HolderKeyView),
    getBrokerEncryptionKey: async () => ({ brokerId: VISUAL_BROKER_ID, encryptionKeyId: 'broker-key-visual-001', publicKey: 'ed25519:visual-broker-public-key' }),
    getVaultBrokerIds: async () => [VISUAL_BROKER_ID],
    getVaultClosureBrokerIds: async () => [VISUAL_BROKER_ID],
    getBrokerPrivateAccount: async () => ({ ...visualPrivateAccount, accountId: VISUAL_BROKER_ID }),
    getProposal: async () => visualProposal,
    getAuditBundle: async (input): Promise<AuditCiphertextBundle> => ({
      scope: input.scope,
      subjectId: input.subjectId,
      auditorKeyId: input.readerRole === 'issuer' ? visualAsset.issuerKeyId : visualAsset.tokenAuditorKeyId,
      subjectKind: input.scope === 'token' ? 'holder' : undefined,
      readerRole: input.readerRole,
      cryptoProfileHash: VISUAL_PROFILE_HASH,
      ciphertexts: { balance: 'ciphertext-audit-balance-visual-001' },
      commitments: { balance: 'commitment-audit-balance-visual-001' },
      versions: { balance: '1' },
      fetchedAt: VISUAL_NOW * 1000,
    }),
    registerHolder: disabledMutation,
    registerAuthorizationKey: disabledMutation,
    revokeAuthorizationKey: disabledMutation,
    createVault: disabledMutation,
    createBroker: disabledMutation,
    depositExternal: disabledMutation,
    depositToVault: disabledMutation,
    redeemShares: disabledMutation,
    redeemAmount: disabledMutation,
    transferShares: disabledMutation,
    requestPayout: disabledMutation,
    finalizePayout: disabledMutation,
    shield: disabledMutation,
    unshield: disabledMutation,
    deleteLoan: disabledMutation,
    deleteBroker: disabledMutation,
    mergeInbox: disabledMutation,
    mergeBrokerInbox: disabledMutation,
    draw: disabledMutation,
    createProposal: disabledMutation,
    authorizeProposal: disabledMutation,
    revokeProposal: disabledMutation,
    originate: disabledMutation,
    confidentialSend: disabledMutation,
    repay: disabledMutation,
    manageLoan: disabledMutation,
    settle: disabledMutation,
    reconcileCredit: disabledMutation,
    prepareReconciliation: disabledMutation,
    grantKeeper: disabledMutation,
    revokeKeeper: disabledMutation,
  }
}

export function createVisualAdapters(state: VisualFixtureState = readVisualFixtureState()): AppAdapters {
  return { protocol: createProtocol(state), wallet: createWallet(), crypto: createCrypto() }
}

export function readVisualFixtureState(): VisualFixtureState {
  if (typeof window === 'undefined') return 'populated'
  const value = new URLSearchParams(window.location.search).get('state')
  return value === 'empty' || value === 'error' || value === 'loading' ? value : 'populated'
}

export function VisualFixture({ state = readVisualFixtureState() }: { state?: VisualFixtureState }) {
  const adapters = useMemo(() => createVisualAdapters(state), [state])
  return <App adapters={adapters} />
}
