import { describe, expect, it } from 'vitest'
import { NearProtocolClient, type NearContractTransport } from '../src/lib/nearClient'
import { createBrowserAdapters } from '../src/lib/adapters'
import { createRpcProtocolClient, type NearWalletSession } from '../src/lib/nearClient'
import { NearWalletSelectorSession } from '../src/lib/nearWallet'
import type { DeploymentConfig, PreparedProof } from '../src/lib/types'

const config: DeploymentConfig = {
  networkId: 'testnet',
  coreAccountId: 'core.testnet',
  tokenAccountId: 'token.testnet',
  rpcUrl: 'https://rpc.testnet.near.org',
  cryptoProfileHash: 'a'.repeat(64),
  cryptoArtifactHash: 'b'.repeat(64),
  assetDecimals: 6,
  assetSymbol: 'USDC',
}

const proof: PreparedProof = {
  context: 'aa',
  proof: 'bb',
  statement: '{}',
  publicInputs: [],
  profileHash: config.cryptoProfileHash,
  artifactHash: 'artifact',
  statementDigest: 'statement',
  operationArgs: {
    sender_spending_ciphertext: 'cc',
    transfer_views: ['dd'],
  },
}

describe('real Core client mapping', () => {
  it('maps proof-bound private calls without adding plaintext amounts', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.confidentialSend({ senderAccountId: 'alice.testnet', destinationAccountId: 'bob.testnet', expectedSpendingVersion: '4', proof })
    expect(captured?.method).toBe('confidential_send')
    expect(captured?.args).toMatchObject({ args: { destination: 'bob.testnet', expected_spending_version: '4', proof: { context: [170], proof: [187], profile_hash: expect.any(Array) }, transfer_views: [[221]] } })
    expect(JSON.stringify(captured?.args)).not.toContain('plaintext')
  })

  it('lets Core derive public-input slots instead of duplicating them in call arguments', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.confidentialSend({ senderAccountId: 'alice.testnet', destinationAccountId: 'bob.testnet', expectedSpendingVersion: '4', proof: { ...proof, publicInputs: ['cc'] } })
    expect(((captured?.args.args as Record<string, unknown>).proof as Record<string, unknown>).public_inputs).toEqual([])
  })

  it('uses the Core API names and finality status for public actions', async () => {
    const calls: string[] = []
    const argsByMethod = new Map<string, Record<string, unknown>>()
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { calls.push(method); argsByMethod.set(method, args); return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.authorizeProposal({ proposalId: '12', authorizationSignature: 'aa' })
    await client.revokeProposal({ proposalId: '12' })
    await client.prepareReconciliation({ brokerId: '2' })
    await client.revokeKeeper({ brokerId: '2', delegateId: 'keeper.testnet', expectedEpoch: '3' })
    expect(calls).toEqual(['sign_proposal', 'revoke_proposal', 'prepare_reconciliation', 'revoke_keeper'])
    expect(argsByMethod.get('sign_proposal')).toEqual({ proposal_id: '12', signature: [170] })
  })

  it('maps a pure inbox merge to the homomorphic Core ABI without a fake proof', async () => {
    const calls: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { calls.push({ method, args }); return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.mergeInbox({ accountId: 'alice.testnet', expectedSpendingVersion: '4', proof: { ...proof, operationArgs: { new_spending_ciphertext: 'aabb' } } })
    await client.mergeBrokerInbox({ brokerId: '2', expectedSpendingVersion: '8', proof: { ...proof, operationArgs: { new_spending_ciphertext: 'ccdd' } } })
    expect(calls).toEqual([
      { method: 'merge_inbox', args: { args: { expected_spending_version: '4', new_spending_ciphertext: [170, 187], proof: null } } },
      { method: 'merge_broker_inbox', args: { broker_id: '2', args: { expected_spending_version: '8', new_spending_ciphertext: [204, 221], proof: null } } },
    ])
  })

  it('allows direct on-chain proposal authorization with the documented empty signature', async () => {
    let args: Record<string, unknown> | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (_method, nextArgs) => { args = nextArgs; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    await new NearProtocolClient(transport, config).authorizeProposal({ proposalId: '12', authorizationSignature: '' })
    expect(args).toEqual({ proposal_id: '12', signature: [] })
  })

  it('maps origination post-state arguments from the browser proof', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.originate({ proposalId: '7', proof: { ...proof, operationArgs: { borrower_spending_ciphertext: 'cc', broker_book_root: 'dd' } } })
    expect(captured).toEqual({ method: 'originate', args: { args: { proposal_id: '7', borrower_spending_ciphertext: [204], broker_book_root: [221], proof: { statement: [123, 125], context: [170], proof: [187], public_inputs: [], verifying_key_hash: [], profile_hash: expect.any(Array) } } } })
  })

  it('maps all proposal ciphertext views and registered authorization key IDs', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.createProposal({ brokerId: '2', borrowerId: 'borrower.testnet', vaultId: '1', borrowerKeyId: '3', brokerKeyId: '4', borrowerAuthorizationKeyId: '8', brokerAuthorizationKeyId: '9', auditorKeyId: '5', auditorPublicKey: 'aa'.repeat(32), paymentCount: 4, paymentIntervalSeconds: 60, gracePeriodSeconds: 30, encryptedPrincipal: ['aa', 'bb', 'cc', 'dd', 'ee'], encryptedOwed: ['ff', '11', '22'], encryptedPayment: ['33', '44', '55'], principalCommitment: '66', owedCommitment: '77', paymentCommitment: '88', encryptedAgreement: '99', termsDigest: 'aa', brokerSignature: 'bb', borrowerSignature: 'cc', brokerAuthorizationEpoch: '1', borrowerAuthorizationEpoch: '2', expiresAt: 9999999999 })
    expect(captured).toEqual({ method: 'create_proposal', args: { args: expect.objectContaining({ broker_authorization_key_id: '9', borrower_authorization_key_id: '8', loan_auditor_public_key: Array(32).fill(170), payment_interval: '60', grace_period: '30', expiry: '9999999999', principal_commitment: [102], owed_commitment: [119], payment_commitment: [136], principal_ciphertexts: [[170], [187], [204], [221], [238]], initial_owed_ciphertexts: [[255], [17], [34]], periodic_payment_ciphertexts: [[51], [68], [85]] }) } })
  })

  it('reads finalized authorization epochs when the proposal caller omits them', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async <T>(method: string) => {
        if (method === 'get_holder') return { authorization_epoch: '12' } as T
        throw new Error(`unexpected view ${method}`)
      },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    await new NearProtocolClient(transport, config).createProposal({ brokerId: '2', borrowerId: 'borrower.testnet', vaultId: '1', borrowerKeyId: '3', brokerKeyId: '4', auditorKeyId: '5', auditorPublicKey: 'aa'.repeat(32), paymentCount: 4, paymentIntervalSeconds: 60, gracePeriodSeconds: 30, encryptedPrincipal: ['aa', 'bb', 'cc', 'dd', 'ee'], encryptedOwed: ['ff', '11', '22'], encryptedPayment: ['33', '44', '55'], principalCommitment: '66', owedCommitment: '77', paymentCommitment: '88', encryptedAgreement: '99', termsDigest: '', brokerSignature: '', borrowerSignature: '', expiresAt: 9999999999 })
    expect(captured).toEqual({ method: 'create_proposal', args: { args: expect.objectContaining({ broker_authorization_epoch: '0', borrower_authorization_epoch: '12', broker_authorization_nonce: '0', borrower_authorization_nonce: '0' }) } })
    expect(captured?.args.args).not.toHaveProperty('broker_authorization_key_id')
    expect(captured?.args.args).not.toHaveProperty('borrower_authorization_key_id')
  })

  it('maps direct loan management without fabricating a proof', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.manageLoan({ loanId: '7', operation: 'impair', expectedLoanVersion: '4', preparation: { loanId: '7', operation: 'impair', expectedLoanVersion: '4' } })
    expect(captured).toEqual({ method: 'manage_loan', args: { args: { loan_id: '7', action: 'Impair', expected_loan_version: '4' } } })
  })

  it('maps shield and unshield proofs without sending clear private balances', async () => {
    const calls: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { calls.push({ method, args }); return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.shield({ claimId: '7', amount: '1000', proof: { ...proof, operationArgs: {} } })
    await client.unshield({ amount: '250', expectedSpendingVersion: '4', proof: { ...proof, operationArgs: {} } })
    expect(calls[0]).toMatchObject({ method: 'shield', args: { args: { claim_id: '7', amount: '1000', proof: expect.any(Object) } } })
    expect(calls[1]).toMatchObject({ method: 'unshield', args: { args: { amount: '250', expected_spending_version: '4', proof: expect.any(Object) } } })
    expect(JSON.stringify(calls)).not.toContain('plaintext')
  })

  it('passes broker zero proofs for final redemption without inventing an empty proof list', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const zeroProof: PreparedProof = {
      ...proof,
      operationArgs: {
        zero_proof: {
          broker_id: '2',
          combined_proof: { statement: '{}', context: 'aa', proof: 'bb', public_inputs: [], profile_hash: config.cryptoProfileHash },
        },
      },
    }
    const client = new NearProtocolClient(transport, config)
    await client.redeemShares({ vaultId: '1', shares: '10', minAmount: '0', expiresAt: 9999999999 })
    expect(captured?.args.args).not.toHaveProperty('broker_zero_proofs')
    await client.redeemShares({ vaultId: '1', shares: '10', minAmount: '0', expiresAt: 9999999999, brokerZeroProofs: [zeroProof] })
    expect(captured?.args).toMatchObject({ args: { broker_zero_proofs: [{ broker_id: '2', combined_proof: { statement: [123, 125], context: [170], proof: [187] } }] } })
  })

  it('maps amount-based redemption to the checked Core ceil/slippage ABI', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    await new NearProtocolClient(transport, config).redeemAmount({ vaultId: '7', assetsOut: '1000000', maxSharesIn: '1000001', expiresAt: 9999999999 })
    expect(captured).toEqual({ method: 'redeem_amount', args: { args: { vault_id: '7', assets_out: '1000000', max_shares_in: '1000001', expiry: '9999999999', sole_shareholder_waiver: false } } })
  })

  it('reads the complete finalized broker membership for a vault', async () => {
    const requests: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async <T>(method: string, args?: Record<string, unknown>) => {
        const nextArgs = args || {}
        requests.push({ method, args: nextArgs })
        if (nextArgs.cursor === '0') return Array.from({ length: 50 }, (_, index) => String(index + 1)) as T
        if (nextArgs.cursor === '50') return ['9007199254740993', '9007199254740994'] as T
        throw new Error(`unexpected cursor ${String(nextArgs.cursor)}`)
      },
      call: async () => { throw new Error('not used') },
    }
    const client = new NearProtocolClient(transport, config)
    await expect(client.getVaultBrokerIds('7')).resolves.toEqual([...Array.from({ length: 50 }, (_, index) => String(index + 1)), '9007199254740993', '9007199254740994'])
    expect(requests).toEqual([
      { method: 'get_vault_broker_ids', args: { vault_id: '7', cursor: '0', limit: 50 } },
      { method: 'get_vault_broker_ids', args: { vault_id: '7', cursor: '50', limit: 50 } },
    ])
  })

  it('paginates every bounded public list through its high-water mark', async () => {
    const requests: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async <T>(method: string, args?: Record<string, unknown>) => {
        const nextArgs = args || {}
        requests.push({ method, args: nextArgs })
        if (method === 'get_asset_profile') return { token_account: 'token.testnet', decimals: 6, controller_account: 'issuer.testnet', crypto_profile_hash: Array(32).fill(1), token_trust_policy: 'fixed', issuer_key: { key_id: '4', public_key: [1] }, token_auditor_key: { key_id: '5', public_key: [2] } } as T
        if (method === 'get_counters') return { vault_high_water: '51', broker_high_water: '51', loan_high_water: '51', proposal_high_water: '51', claim_high_water: '51', payout_high_water: '51' } as T
        if (method === 'get_proposal') return null as T
        if (nextArgs.limit !== undefined) {
          if (nextArgs.limit !== 50) throw new Error('Core bounded list limit must be 50')
          if (method === 'list_vaults' && nextArgs.cursor === '50') return [{ vault_id: '51', owner: 'broker.testnet', asset_id: 'token.testnet', assets_total: '0', assets_available: '0', shares_total: '0', accounting_pending: false, accounting_version: '0', phase: 'Investment', kind: 'ClosedEnded' }] as T
          return [] as T
        }
        if (method === 'get_share_balance') return '0' as T
        throw new Error(`unexpected view ${method}`)
      },
      call: async () => { throw new Error('not used') },
    }
    const dashboard = await new NearProtocolClient(transport, config).getDashboard('alice.testnet')
    expect(dashboard.vaults.map((vault) => vault.vaultId)).toEqual(['51'])
    expect(dashboard.vaults[0]?.phase).toBe('investment')
    const pagedMethods = ['list_vaults', 'list_brokers', 'list_claims', 'list_payouts', 'list_loans']
    for (const method of pagedMethods) {
      const pages = requests.filter((request) => request.method === method)
      expect(pages.length).toBeGreaterThan(0)
      expect(pages.every((request) => request.args.limit === 50)).toBe(true)
      expect(pages.some((request) => request.args.cursor === '50')).toBe(true)
    }
    const proposalReads = requests.filter((request) => request.method === 'get_proposal')
    expect(proposalReads).toHaveLength(51)
    expect(proposalReads[0]).toEqual({ method: 'get_proposal', args: { proposal_id: '1' } })
    expect(proposalReads.at(-1)).toEqual({ method: 'get_proposal', args: { proposal_id: '51' } })
  })

  it('maps nested reconciliation proof fields without recursively rewriting Statement JSON', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.settle({ brokerId: '2', amount: '100', expectedSpendingVersion: '4', expectedAccountingVersion: '8', proof: { ...proof, operationArgs: { broker_spending_ciphertext: 'cc', broker_issuer_ciphertext: 'dd', broker_auditor_ciphertext: 'ee', settlement_views: ['ff', '11', '22'], expected_accounting_version: '8', reconciliation: { checkpoint_id: '3', broker_id: '2', expected_risk_version: '5', expected_accounting_version: '8', new_broker_debt: '90', new_broker_provision: '10', loss: '10', new_vault_total: '990', cash_commitment: 'aa', active_principal_commitment: 'bb', impaired_principal_commitment: 'cc', proof: { statement: '{}', context: 'aa', proof: 'bb', public_inputs: [], profile_hash: config.cryptoProfileHash } } } } })
    expect(captured?.method).toBe('settle')
    const reconciliation = (captured?.args.args as Record<string, unknown>).reconciliation as Record<string, unknown>
    expect(reconciliation).toMatchObject({ checkpoint_id: '3', broker_id: '2', expected_risk_version: '5', new_vault_total: '990', cash_commitment: [170], active_principal_commitment: [187], impaired_principal_commitment: [204], proof: { statement: [123, 125], context: [170], proof: [187] } })
  })

  it('rejects unrecognized proof objects before they can reach RPC', async () => {
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async () => { throw new Error('must not submit') },
    }
    const client = new NearProtocolClient(transport, config)
    expect(() => client.confidentialSend({ senderAccountId: 'alice.testnet', destinationAccountId: 'bob.testnet', expectedSpendingVersion: '4', proof: { ...proof, operationArgs: { pointHex: 'aa' } } })).toThrow(/Unsupported proof argument/)
  })

  it('maps the complete Core keeper grant limits and delegate key', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { captured = { method, args }; return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    await client.grantKeeper({ brokerId: '2', delegateId: 'keeper.testnet', delegateKeyId: '9', scope: ['settle'], maxAmountPerOperation: '100', maxAmountPerWindow: '1000', windowSeconds: 3600, delegateEpoch: '3', expiresAt: 9999999999 })
    expect(captured).toEqual({ method: 'grant_keeper', args: { args: { broker_id: '2', delegate_account: 'keeper.testnet', delegate_key_id: '9', allowed_settlement_per_operation: '100', allowed_settlement_per_window: '1000', window_seconds: '3600', expires_at: '9999999999', delegate_epoch: '3', allowed_operations: ['Settle'] } } })
  })

  it('uses nested Core ProofArgs for holder and broker PoP, with direct authorization-key registration', async () => {
    const calls: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async () => { throw new Error('not used') },
      call: async (method, args) => { calls.push({ method, args }); return { transactionHash: 'tx', status: 'succeeded', finalized: true } },
    }
    const client = new NearProtocolClient(transport, config)
    const pop = { ...proof, operationArgs: {} }
    await client.registerHolder({ encryptionPublicKey: 'aa', encryptionKeyId: '3', possessionProof: pop, authorizationPublicKey: 'bb', authorizationSignature: 'cc' })
    await client.registerAuthorizationKey({ keyId: '4', publicKey: 'dd' })
    await client.createBroker({ vaultId: '1', brokerEncryptionKeyId: '5', brokerEncryptionKey: 'ee', brokerDebtCeiling: '100', possessionProof: pop })
    expect(calls.map(({ method }) => method)).toEqual(['register_holder', 'register_authorization_key', 'create_broker'])
    expect(calls[0].args).toMatchObject({ args: { encryption_public_key: [170], public_key: [187], proof_of_possession: { context: [170], proof: [187], profile_hash: expect.any(Array) } } })
    expect(calls[1].args).toEqual({ args: { key_id: '4', public_key: [221] } })
    expect(calls[2].args).toMatchObject({ args: { proof_of_possession: { context: [170], proof: [187], profile_hash: expect.any(Array) } } })
  })

  it('uses canonical decimal strings for Core U64 view lookups', async () => {
    let captured: { method: string; args: Record<string, unknown> } | undefined
    const transport: NearContractTransport = {
      view: async <T>(method: string, args?: Record<string, unknown>) => { captured = { method, args: args || {} }; return null as T },
      call: async () => { throw new Error('not used') },
    }
    const client = new NearProtocolClient(transport, config)
    await expect(client.getProposal('12')).rejects.toThrow(/proposal/i)
    expect(captured).toEqual({ method: 'get_proposal', args: { proposal_id: '12' } })
  })

  it('maps a scoped holder token-audit subject to finalized Core reads', async () => {
    const calls: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async <T>(method: string, args?: Record<string, unknown>) => {
        calls.push({ method, args: args || {} })
        if (method === 'get_asset_profile') return { token_account: 'token.testnet', decimals: 6, controller_account: 'issuer.testnet', crypto_profile_hash: Array(32).fill(1), token_trust_policy: 'fixed', issuer_key: { key_id: '4', public_key: [1] }, token_auditor_key: { key_id: '5', public_key: [2] } } as T
        if (method === 'get_holder') return { owner: 'alice.testnet', spending_version: '7' } as T
        throw new Error(`unexpected view ${method}`)
      },
      call: async () => { throw new Error('not used') },
    }
    const bundle = await new NearProtocolClient(transport, config).getAuditBundle({ scope: 'token', subjectId: 'holder:alice.testnet', readerRole: 'token_auditor' })
    expect(bundle).toMatchObject({ scope: 'token', subjectId: 'alice.testnet', subjectKind: 'holder', readerRole: 'token_auditor', auditorKeyId: '5', versions: { spending: '7' } })
    expect(calls).toEqual([
      { method: 'get_asset_profile', args: {} },
      { method: 'get_holder', args: { owner: 'alice.testnet' } },
    ])
  })

  it('keeps broker token-audit IDs canonical and never lists unbounded subjects', async () => {
    const calls: Array<{ method: string; args: Record<string, unknown> }> = []
    const transport: NearContractTransport = {
      view: async <T>(method: string, args?: Record<string, unknown>) => {
        calls.push({ method, args: args || {} })
        if (method === 'get_asset_profile') return { token_account: 'token.testnet', decimals: 6, controller_account: 'issuer.testnet', crypto_profile_hash: Array(32).fill(1), token_trust_policy: 'fixed', issuer_key: { key_id: '4', public_key: [1] }, token_auditor_key: { key_id: '5', public_key: [2] } } as T
        if (method === 'get_broker') return { broker_id: '9', spending_version: '12' } as T
        throw new Error(`unexpected view ${method}`)
      },
      call: async () => { throw new Error('not used') },
    }
    const bundle = await new NearProtocolClient(transport, config).getAuditBundle({ scope: 'token', subjectId: 'broker:9', readerRole: 'issuer' })
    expect(bundle).toMatchObject({ scope: 'token', subjectId: '9', subjectKind: 'broker', readerRole: 'issuer', auditorKeyId: '4', versions: { spending: '12' } })
    expect(calls).toEqual([
      { method: 'get_asset_profile', args: {} },
      { method: 'get_broker', args: { broker_id: '9' } },
    ])
  })
})

describe('wallet initialization', () => {
  it('starts disconnected without a funded or hardcoded identity', () => {
    const wallet = new NearWalletSelectorSession(config)
    expect(wallet.status).toBe('disconnected')
    expect(wallet.accountId).toBeUndefined()
    expect(wallet.networkId).toBe('testnet')
  })

  it('creates the real disconnected RPC pair only for a complete deployment', () => {
    const adapters = createBrowserAdapters(config)
    expect(adapters.protocol).toBeInstanceOf(NearProtocolClient)
    expect(adapters.wallet.status).toBe('disconnected')
    expect(adapters.wallet.accountId).toBeUndefined()
  })

  it('stays visibly unavailable when deployment values are incomplete', () => {
    const adapters = createBrowserAdapters({ ...config, coreAccountId: '' })
    expect(adapters.protocol).not.toBeInstanceOf(NearProtocolClient)
    expect(adapters.wallet.status).toBe('disconnected')
  })

  it('keeps a connected signer account in the real RPC pair without embedding identity', () => {
    const session: NearWalletSession = {
      status: 'connected',
      accountId: 'alice.testnet',
      networkId: 'testnet',
      connect: async () => undefined,
      disconnect: async () => undefined,
      subscribe: () => () => undefined,
      signAndSendTransaction: async () => undefined,
    }
    const pair = createRpcProtocolClient(config, session)
    expect(pair.protocol).toBeInstanceOf(NearProtocolClient)
    expect(pair.wallet.accountId).toBe('alice.testnet')
    expect(pair.wallet.status).toBe('connected')
  })
})
