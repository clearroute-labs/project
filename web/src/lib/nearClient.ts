import type {
  ActionReceipt,
  AppAdapters,
  AssetProfile,
  AuditCiphertextBundle,
  BrokerSummary,
  DashboardSnapshot,
  DeploymentConfig,
  KeeperGrant,
  KeyRegistration,
  PrivateAccountView,
  PreparedProof,
  ProposalSummary,
  ProtocolClient,
  WalletAdapter,
} from './types'

/**
 * Minimal bridge expected from the real NEAR SDK. The root client package
 * supplies finality-aware JSON-RPC reads and wallet-signed calls; this adapter
 * only maps typed product actions to the Core API and never manufactures data.
 */
export interface NearContractTransport {
  view<T>(method: string, args?: Record<string, unknown>, signal?: AbortSignal): Promise<T>
  call(method: string, args: Record<string, unknown>, options?: { deposit?: string; gas?: string; receiverId?: string; signal?: AbortSignal }): Promise<NearCallResult | undefined>
}

export interface NearCallResult {
  transactionHash?: string
  operationId?: string
  finalized: boolean
  status: 'succeeded' | 'failed' | 'unknown' | 'pending'
}

export interface NearWalletSession {
  readonly status: WalletAdapter['status']
  readonly accountId?: string
  readonly networkId?: string
  readonly error?: string
  connect(): Promise<void>
  disconnect(): Promise<void>
  subscribe(listener: () => void): () => void
}

function proofArgs(proof: PreparedProof): Record<string, unknown> {
  return {
    ...(proof.operationArgs || {}),
    proof: { context: proof.context, proof: proof.proof },
  }
}

export function createWalletAdapter(session: NearWalletSession): WalletAdapter {
  return session
}

export class NearProtocolClient implements ProtocolClient {
  readonly config: DeploymentConfig
  private readonly transport: NearContractTransport

  constructor(transport: NearContractTransport, config: DeploymentConfig) {
    this.transport = transport
    this.config = config
  }

  getAssetProfile(): Promise<AssetProfile> {
    return this.transport.view<AssetProfile>('get_asset_profile')
  }

  getDashboard(accountId: string): Promise<DashboardSnapshot> {
    return this.transport.view<DashboardSnapshot>('get_dashboard', { account_id: accountId })
  }

  getPrivateAccount(accountId: string): Promise<PrivateAccountView> {
    return this.transport.view<PrivateAccountView>('get_holder', { account_id: accountId, asset_account: this.config.tokenAccountId })
  }

  getBrokerPrivateAccount(brokerId: string): Promise<PrivateAccountView> {
    return this.transport.view<PrivateAccountView>('get_broker', { broker_id: brokerId })
  }

  getProposal(proposalId: string): Promise<ProposalSummary> {
    return this.transport.view<ProposalSummary>('get_proposal', { proposal_id: proposalId })
  }

  getAuditBundle(input: { scope: 'loan' | 'token'; subjectId: string }): Promise<AuditCiphertextBundle> {
    return this.transport.view<AuditCiphertextBundle>('get_audit_bundle', { scope: input.scope, subject_id: input.subjectId })
  }

  private async callWithOptions(method: string, args: Record<string, unknown>, options?: { deposit?: string; gas?: string; receiverId?: string }): Promise<ActionReceipt> {
    const result = await this.transport.call(method, args, options)
    if (!result) return { operationId: `${method}:${Date.now()}`, status: 'pending', finalized: false }
    return {
      operationId: result.operationId || `${method}:${result.transactionHash || Date.now()}`,
      transactionHash: result.transactionHash,
      status: result.status,
      finalized: result.finalized,
    }
  }

  private call(method: string, args: Record<string, unknown>): Promise<ActionReceipt> {
    return this.callWithOptions(method, args)
  }

  registerHolder(input: KeyRegistration): Promise<ActionReceipt> {
    return this.call('register_holder', { encryption_key: input.encryptionPublicKey, encryption_key_id: input.encryptionKeyId, possession_proof: input.possessionProof, authorization_public_key: input.authorizationPublicKey })
  }

  createVault(input: { assetAccount: string; assetsMaximum: string; kind: 'open_ended' | 'closed_ended'; phaseTimes?: { subscriptionStart: number; investmentStart: number; redemptionStart: number; redemptionBuffer: number }; shareScale: number; sharesTransferable: boolean; checkpointPolicy: { epochSeconds: number; disclosurePolicy: string } }): Promise<ActionReceipt> {
    return this.call('create_vault', { assets_maximum: input.assetsMaximum, kind: input.kind === 'open_ended' ? 'OpenEnded' : 'ClosedEnded', phase_times: input.phaseTimes ? { subscription_start: input.phaseTimes.subscriptionStart, investment_start: input.phaseTimes.investmentStart, redemption_start: input.phaseTimes.redemptionStart, redemption_buffer: input.phaseTimes.redemptionBuffer } : null, share_scale: input.shareScale, shares_transferable: input.sharesTransferable, checkpoint_policy: { epoch_seconds: input.checkpointPolicy.epochSeconds, disclosure_policy: input.checkpointPolicy.disclosurePolicy } })
  }

  createBroker(input: { vaultId: string; brokerEncryptionKey: string; brokerDebtCeiling: string; possessionProof: string }): Promise<ActionReceipt> {
    return this.call('create_broker', { vault_id: input.vaultId, broker_encryption_key: input.brokerEncryptionKey, broker_debt_ceiling: input.brokerDebtCeiling, possession_proof: input.possessionProof })
  }

  depositExternal(input: { amount: string; depositId: string }): Promise<ActionReceipt> {
    return this.callWithOptions('ft_transfer_call', { receiver_id: this.config.coreAccountId, amount: input.amount, msg: JSON.stringify({ version: 1, deposit_id: input.depositId }) }, { receiverId: this.config.tokenAccountId, gas: '100000000000000', deposit: '1' })
  }

  depositToVault(input: { claimId: string; vaultId: string; amount: string; minShares: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('deposit_to_vault', { claim_id: input.claimId, vault_id: input.vaultId, amount: input.amount, min_shares: input.minShares, expires_at: input.expiresAt })
  }

  redeemShares(input: { vaultId: string; shares: string; minAmount: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('redeem_shares', { vault_id: input.vaultId, shares: input.shares, min_amount: input.minAmount, expires_at: input.expiresAt })
  }

  requestPayout(input: { claimId: string; operationId: string; recipientId: string }): Promise<ActionReceipt> {
    return this.call('request_payout', { claim_id: input.claimId, operation_id: input.operationId, recipient_id: input.recipientId })
  }

  mergeInbox(input: { accountId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('merge_inbox', { account_id: input.accountId, expected_inbox_version: input.expectedInboxVersion, ...proofArgs(input.proof) })
  }

  mergeBrokerInbox(input: { brokerId: string; expectedInboxVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('merge_broker_inbox', { broker_id: input.brokerId, expected_inbox_version: input.expectedInboxVersion, ...proofArgs(input.proof) })
  }

  draw(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('draw', { broker_id: input.brokerId, amount: input.amount, ...proofArgs(input.proof) })
  }

  createProposal(input: { brokerId: string; borrowerId: string; vaultId: string; borrowerKeyId: string; brokerKeyId: string; auditorKeyId: string; paymentCount: number; paymentIntervalSeconds: number; gracePeriodSeconds: number; encryptedPrincipal: string; encryptedOwed: string; encryptedPayment: string; encryptedAgreement: string; termsDigest: string; brokerSignature: string; borrowerSignature: string; brokerAuthorizationEpoch: string; borrowerAuthorizationEpoch: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('create_proposal', { borrower: input.borrowerId, broker_id: input.brokerId, vault_id: input.vaultId, borrower_key_id: input.borrowerKeyId, broker_key_id: input.brokerKeyId, loan_auditor_key_id: input.auditorKeyId, payment_count: input.paymentCount, payment_interval: input.paymentIntervalSeconds, grace_period: input.gracePeriodSeconds, expiry: input.expiresAt, principal_ciphertexts: [input.encryptedPrincipal], initial_owed_ciphertexts: [input.encryptedOwed], periodic_payment_ciphertexts: [input.encryptedPayment], agreement_digest: input.termsDigest, broker_signature: input.brokerSignature, borrower_signature: input.borrowerSignature, broker_authorization_epoch: input.brokerAuthorizationEpoch, borrower_authorization_epoch: input.borrowerAuthorizationEpoch })
  }

  authorizeProposal(input: { proposalId: string; authorizationSignature: string }): Promise<ActionReceipt> {
    return this.call('sign_proposal', { proposal_id: input.proposalId, signature: input.authorizationSignature })
  }

  originate(input: { proposalId: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('originate', { proposal_id: input.proposalId, proof: input.proof })
  }

  confidentialSend(input: { senderAccountId: string; destinationAccountId: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('confidential_send', { destination: input.destinationAccountId, expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  repay(input: { loanId: string; mode: 'regular' | 'full'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('repay', { loan_id: input.loanId, mode: input.mode === 'regular' ? 'Regular' : 'Full', expected_loan_version: input.expectedLoanVersion, ...proofArgs(input.proof) })
  }

  manageLoan(input: { loanId: string; operation: 'impair' | 'unimpair' | 'default'; expectedLoanVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('manage_loan', { loan_id: input.loanId, action: input.operation === 'impair' ? 'Impair' : input.operation === 'unimpair' ? 'Unimpair' : 'Default', expected_loan_version: input.expectedLoanVersion, ...proofArgs(input.proof) })
  }

  settle(input: { brokerId: string; amount: string; expectedSpendingVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('settle', { broker_id: input.brokerId, amount: input.amount, expected_spending_version: input.expectedSpendingVersion, ...proofArgs(input.proof) })
  }

  reconcileCredit(input: { brokerId: string; expectedBookVersion: string; proof: PreparedProof }): Promise<ActionReceipt> {
    return this.call('reconcile_credit', { broker_id: input.brokerId, expected_book_version: input.expectedBookVersion, ...proofArgs(input.proof) })
  }

  prepareReconciliation(input: { brokerId: string }): Promise<ActionReceipt> {
    return this.call('prepare_reconciliation', { broker_id: input.brokerId })
  }

  grantKeeper(input: { brokerId: string; delegateId: string; scope: KeeperGrant['scope']; maxAmount?: string; expiresAt: number }): Promise<ActionReceipt> {
    return this.call('grant_keeper', { broker_id: input.brokerId, delegate_id: input.delegateId, scope: input.scope, max_amount: input.maxAmount, expires_at: input.expiresAt })
  }

  revokeKeeper(input: { brokerId: string; delegateId: string; expectedEpoch: string }): Promise<ActionReceipt> {
    return this.call('revoke_keeper', { broker_id: input.brokerId, delegate_id: input.delegateId, expected_epoch: input.expectedEpoch })
  }
}

export function createAppAdapters(protocol: ProtocolClient, wallet: WalletAdapter, crypto: AppAdapters['crypto']): AppAdapters {
  return { protocol, wallet, crypto }
}
