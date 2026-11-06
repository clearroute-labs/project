import { freshSeed, type CryptoExecutor, type EncryptionPublicKey, type KeyReference, type Keyring } from './keyring.js';

export interface Ciphertext { ephemeral: string; message: string }
export interface Commitment { point: string }
export interface ReaderView { reader_key: EncryptionPublicKey; ciphertext: Ciphertext }
export interface RecoveryPair { low_limb: Ciphertext; high_limb: Ciphertext }
export interface OperationContext {
  network_id: number[]; core_account: number[]; asset_id: number[]; operation_id: number[];
  vault_id: number[]; broker_id: number[]; loan_id: number[]; proposal_id: number[];
  expected_versions: string[]; authorization_epochs: string[]; expiry: string;
}
export type StatementName = 'KeyPossession' | 'PublicConversion' | 'ConfidentialTransfer' | 'Origination' | 'Repayment' | 'Reconciliation' | 'ZeroBalance' | 'Ownership';
export type Statement = Partial<Record<StatementName, Record<string, unknown>>>;
export interface ProofEnvelope {
  profile_id: string; profile_hash: string; statement_kind: StatementName;
  context_digest: string; public_inputs: string[]; proof: string; verifying_key_hash: string;
}
export interface ProvenOperation { statement: Statement; envelope: ProofEnvelope }
export interface SpendingState { key: KeyReference; ciphertext: Ciphertext; version: string; amount: string }
interface EncryptedViews {
  views: ReaderView[]; recovery: RecoveryPair[];
  randomness: string[]; recovery_randomness: Array<[string, string]>;
}
interface CommittedAmount { commitment: Commitment; blinding: string }
export interface AgreementTerms {
  principal: string; initialOwed: string; periodicPayment: string; paymentCount: number; maxPaymentCount: number;
  transferKeys: EncryptionPublicKey[]; loanKeys: EncryptionPublicKey[];
}
/** Private draft contains encryption randomness. Keep it in worker memory or an encrypted wallet backup. */
export interface AgreementDraft {
  terms: AgreementTerms; principal: EncryptedViews; owed: EncryptedViews; payment: EncryptedViews;
  principalCommitment: CommittedAmount; owedCommitment: CommittedAmount; paymentCommitment: CommittedAmount;
}
export interface RepaymentTerms {
  owed: string; periodicPayment: string; principalRemaining: string;
  owedViews: ReaderView[]; paymentViews: ReaderView[]; principalViews: ReaderView[];
  transferKeys: EncryptionPublicKey[]; paymentRemaining: number; loanVersion: string;
}
export interface ReconciliationState {
  brokerKey: KeyReference;
  cash: { ciphertext: Ciphertext; amount: string };
  activePrincipal: { ciphertext: Ciphertext; amount: string };
  impairedPrincipal: { ciphertext: Ciphertext; amount: string };
  debt: string; vaultAssets: string; vaultProvision: string; brokerProvision: string;
  bookVersion: string; accountingVersion: string;
}
const maximumAmount = (1n << 63n) - 1n;
const maximum128 = (1n << 128n) - 1n;
const families: Record<StatementName, string> = {
  KeyPossession: 'key-possession', PublicConversion: 'public-conversion', ConfidentialTransfer: 'confidential-transfer',
  Origination: 'origination', Repayment: 'repayment', Reconciliation: 'reconciliation', ZeroBalance: 'zero-balance', Ownership: 'ownership',
};
const kindIds: Record<StatementName, number> = { KeyPossession: 1, PublicConversion: 2, ConfidentialTransfer: 3, Origination: 4, Repayment: 5, Reconciliation: 6, ZeroBalance: 7, Ownership: 8 };

function integer(value: string, maximum = maximumAmount): bigint {
  if (!/^(0|[1-9]\d*)$/.test(value)) throw new Error('Expected canonical decimal amount');
  const result = BigInt(value);
  if (result > maximum) throw new Error('Amount exceeds protocol bound');
  return result;
}
function counter(value: number): void { if (!Number.isInteger(value) || value < 1 || value > 0xffff_ffff) throw new Error('Invalid payment count'); }
function exactReaders(keys: EncryptionPublicKey[], count: number): void { if (keys.length !== count) throw new Error('Incorrect reader count'); }
function nextVersion(value: string): string { return (integer(value, (1n << 64n) - 2n) + 1n).toString(); }
export function wireBytes(value: string): number[] {
  if (!/^(?:[a-f0-9]{2})+$/.test(value)) throw new Error('Invalid canonical hex bytes');
  return Array.from(value.matchAll(/../g), match => Number.parseInt(match[0], 16));
}
export function jsonBytes(value: unknown): number[] { return Array.from(new TextEncoder().encode(JSON.stringify(value))); }

export function proofArguments(operation: ProvenOperation): Record<string, unknown> {
  const envelope = operation.envelope;
  return {
    statement: jsonBytes(operation.statement), context: wireBytes(envelope.context_digest), proof: wireBytes(envelope.proof),
    statement_kind: kindIds[envelope.statement_kind], public_inputs: envelope.public_inputs.map(wireBytes),
    verifying_key_hash: wireBytes(envelope.verifying_key_hash), profile_hash: wireBytes(envelope.profile_hash),
  };
}

/** All witnesses remain in this worker-local object; returned operations contain only public statements and proofs. */
export class ProofBuilder {
  constructor(readonly crypto: CryptoExecutor, readonly keys: Keyring) {}

  async possession(context: OperationContext, reference: KeyReference): Promise<ProvenOperation> {
    return this.prove('KeyPossession', { context, public_key: this.keys.publicKey(reference) }, { kind: 'key-possession', secret_key: this.keys.secret(reference) });
  }

  async conversion(context: OperationContext, balance: SpendingState, amount: string, readers: EncryptionPublicKey[], mode: 'Credit' | 'Debit'): Promise<ProvenOperation> {
    exactReaders(readers, 3);
    const value = integer(amount);
    const before = integer(balance.amount);
    if (value === 0n || (mode === 'Debit' && value > before)) throw new Error('Invalid conversion amount');
    if (mode === 'Credit' && before + value > maximumAmount) throw new Error('Conversion exceeds balance cap');
    const owner = this.keys.publicKey(balance.key);
    if (readers[0]!.point !== owner.point) throw new Error('Conversion owner mismatch');
    const encrypted = await this.encrypt(readers, amount);
    const after = await this.combine(mode === 'Debit' ? 'sub' : 'add', balance.ciphertext, encrypted.views[0]!.ciphertext);
    return this.prove('PublicConversion', {
      context, owner_key: owner, spending_before: balance.ciphertext, spending_after: after,
      views: encrypted.views, public_amount: amount, mode, spending_version: balance.version,
    }, { kind: 'public-conversion', owner_secret: this.keys.secret(balance.key), private_balance: balance.amount,
      delta_randomness: encrypted.randomness[0], randomness: encrypted.randomness });
  }

  async transfer(context: OperationContext, balance: SpendingState, amount: string, readers: EncryptionPublicKey[]): Promise<ProvenOperation> {
    exactReaders(readers, 5);
    if (integer(amount) === 0n || integer(amount) > integer(balance.amount)) throw new Error('Insufficient private spending balance');
    const sender = this.keys.publicKey(balance.key);
    if (readers[0]!.point !== sender.point || readers[4]!.point !== readers[1]!.point) throw new Error('Invalid transfer readers');
    const encrypted = await this.encrypt(readers, amount);
    const commitment = await this.commit(amount);
    const after = await this.combine('sub', balance.ciphertext, encrypted.views[0]!.ciphertext);
    return this.prove('ConfidentialTransfer', {
      context, sender_key: sender, recipient_key: readers[1], sender_spending_before: balance.ciphertext,
      sender_spending_after: after, transfer_views: encrypted.views, transfer_recovery: encrypted.recovery,
      amount_commitment: commitment.commitment, sender_spending_version: balance.version,
    }, { kind: 'confidential-transfer', sender_secret: this.keys.secret(balance.key), sender_balance: balance.amount, amount,
      sender_delta_randomness: encrypted.randomness[0], transfer_randomness: encrypted.randomness,
      transfer_recovery_randomness: encrypted.recovery_randomness, commitment_blinding: commitment.blinding });
  }

  async agreement(terms: AgreementTerms): Promise<AgreementDraft> {
    const fixed = structuredClone(terms);
    exactReaders(fixed.transferKeys, 5); exactReaders(fixed.loanKeys, 3);
    counter(fixed.paymentCount); counter(fixed.maxPaymentCount);
    const p = integer(fixed.principal), o = integer(fixed.initialOwed), q = integer(fixed.periodicPayment);
    if (p === 0n || q === 0n || o < p || q > o || BigInt(fixed.paymentCount) * q < o || fixed.paymentCount > fixed.maxPaymentCount) throw new Error('Invalid loan schedule');
    const [broker, borrower, , , auditor] = fixed.transferKeys;
    if (fixed.loanKeys[0]!.point !== borrower!.point || fixed.loanKeys[1]!.point !== broker!.point || fixed.loanKeys[2]!.point !== auditor!.point) throw new Error('Loan reader ordering mismatch');
    return {
      terms: fixed,
      principal: await this.encrypt(fixed.transferKeys, fixed.principal),
      owed: await this.encrypt(fixed.loanKeys, fixed.initialOwed),
      payment: await this.encrypt(fixed.loanKeys, fixed.periodicPayment),
      principalCommitment: await this.commit(fixed.principal), owedCommitment: await this.commit(fixed.initialOwed),
      paymentCommitment: await this.commit(fixed.periodicPayment),
    };
  }

  async originate(context: OperationContext, balance: SpendingState, draft: AgreementDraft): Promise<ProvenOperation> {
    if (integer(draft.terms.principal) > integer(balance.amount)) throw new Error('Insufficient broker spending balance');
    const broker = this.keys.publicKey(balance.key);
    if (draft.principal.views[0]?.reader_key.point !== broker.point) throw new Error('Agreement belongs to another broker key');
    const after = await this.combine('sub', balance.ciphertext, draft.principal.views[0]!.ciphertext);
    return this.prove('Origination', {
      context, broker_key: broker, borrower_key: draft.terms.transferKeys[1], broker_spending_before: balance.ciphertext,
      broker_spending_after: after, transfer_views: draft.principal.views, transfer_recovery: draft.principal.recovery,
      principal_commitment: draft.principalCommitment.commitment, owed_views: draft.owed.views, owed_recovery: draft.owed.recovery,
      payment_views: draft.payment.views, payment_recovery: draft.payment.recovery,
      owed_commitment: draft.owedCommitment.commitment, payment_commitment: draft.paymentCommitment.commitment,
      payment_count: draft.terms.paymentCount, max_payment_count: draft.terms.maxPaymentCount,
      broker_spending_version: balance.version, loan_version: '0',
    }, {
      kind: 'origination', broker_secret: this.keys.secret(balance.key), broker_balance: balance.amount,
      principal: draft.terms.principal, initial_owed: draft.terms.initialOwed, periodic_payment: draft.terms.periodicPayment,
      transfer_randomness: draft.principal.randomness, transfer_recovery_randomness: draft.principal.recovery_randomness,
      broker_delta_randomness: draft.principal.randomness[0], principal_blinding: draft.principalCommitment.blinding,
      owed_randomness: draft.owed.randomness, owed_recovery_randomness: draft.owed.recovery_randomness,
      payment_randomness: draft.payment.randomness, payment_recovery_randomness: draft.payment.recovery_randomness,
      owed_blinding: draft.owedCommitment.blinding, payment_blinding: draft.paymentCommitment.blinding,
    });
  }

  async repay(context: OperationContext, balance: SpendingState, terms: RepaymentTerms, mode: 'Regular' | 'Full', regularAmount?: string): Promise<ProvenOperation> {
    exactReaders(terms.transferKeys, 5); counter(terms.paymentRemaining);
    for (const views of [terms.owedViews, terms.paymentViews, terms.principalViews]) if (views.length !== 3) throw new Error('Incorrect loan reader count');
    const owed = integer(terms.owed), q = integer(terms.periodicPayment), principal = integer(terms.principalRemaining);
    const payment = mode === 'Full' ? owed : integer(regularAmount ?? terms.periodicPayment);
    if (payment === 0n || payment > integer(balance.amount) || principal > owed
      || (mode === 'Regular' && (payment < q || payment >= owed || terms.paymentRemaining <= 1))) throw new Error('Invalid loan repayment');
    const borrower = this.keys.publicKey(balance.key);
    if (terms.transferKeys[0]!.point !== borrower.point) throw new Error('Repayment borrower mismatch');
    const keys = terms.owedViews.map(view => view.reader_key);
    if (keys[0]!.point !== borrower.point || keys[1]!.point !== terms.transferKeys[1]!.point || keys[2]!.point !== terms.transferKeys[4]!.point) throw new Error('Repayment readers mismatch');
    const paid = payment < principal ? payment : principal;
    const transfer = await this.encrypt(terms.transferKeys, payment.toString());
    const owedDelta = await this.encrypt(keys, payment.toString());
    const principalDelta = await this.encrypt(keys, paid.toString());
    const commitment = await this.commit(paid.toString());
    const owedAfter = await this.subtractViews(terms.owedViews, owedDelta.views);
    const principalAfter = await this.subtractViews(terms.principalViews, principalDelta.views);
    return this.prove('Repayment', {
      context, borrower_key: borrower, broker_key: terms.transferKeys[1], borrower_spending_before: balance.ciphertext,
      borrower_spending_after: await this.combine('sub', balance.ciphertext, transfer.views[0]!.ciphertext),
      transfer_views: transfer.views, transfer_recovery: transfer.recovery,
      owed_before: terms.owedViews, owed_after: owedAfter, owed_delta: owedDelta.views, owed_delta_recovery: owedDelta.recovery,
      periodic_payment: terms.paymentViews, principal_before: terms.principalViews, principal_after: principalAfter,
      principal_delta: principalDelta.views, principal_delta_recovery: principalDelta.recovery,
      principal_delta_commitment: commitment.commitment, mode, payment_remaining_before: terms.paymentRemaining,
      payment_remaining_after: mode === 'Full' ? 0 : terms.paymentRemaining - 1, borrower_spending_version: balance.version,
      loan_version_before: terms.loanVersion, loan_version_after: nextVersion(terms.loanVersion),
    }, {
      kind: 'repayment', borrower_secret: this.keys.secret(balance.key), borrower_balance: balance.amount,
      payment: payment.toString(), owed_before: terms.owed, periodic_payment: terms.periodicPayment,
      principal_before: terms.principalRemaining, principal_paid: paid.toString(), transfer_randomness: transfer.randomness,
      transfer_recovery_randomness: transfer.recovery_randomness, borrower_delta_randomness: transfer.randomness[0],
      owed_delta_randomness: owedDelta.randomness, owed_delta_recovery_randomness: owedDelta.recovery_randomness,
      principal_delta_randomness: principalDelta.randomness, principal_delta_recovery_randomness: principalDelta.recovery_randomness,
      principal_paid_blinding: commitment.blinding,
    });
  }

  async reconcile(context: OperationContext, state: ReconciliationState): Promise<ProvenOperation> {
    const cash = integer(state.cash.amount), active = integer(state.activePrincipal.amount, maximum128), impaired = integer(state.impairedPrincipal.amount, maximum128);
    const debt = integer(state.debt), total = integer(state.vaultAssets), vaultU = integer(state.vaultProvision), oldU = integer(state.brokerProvision);
    if (impaired > active || cash + active > maximum128 || oldU > vaultU) throw new Error('Invalid reconciliation book');
    const loss = debt > cash + active ? debt - cash - active : 0n;
    const debtAfter = debt - loss;
    const healthy = cash + active - impaired;
    const provision = debtAfter > healthy ? debtAfter - healthy : 0n;
    const nextU = vaultU - oldU + provision;
    if (loss > total || nextU > total - loss) throw new Error('Invalid reconciliation result');
    const c = await this.commit(state.cash.amount, true), a = await this.commit(state.activePrincipal.amount, true), i = await this.commit(state.impairedPrincipal.amount, true);
    return this.prove('Reconciliation', {
      context, broker_key: this.keys.publicKey(state.brokerKey), cash: state.cash.ciphertext,
      active_principal: state.activePrincipal.ciphertext, impaired_principal: state.impairedPrincipal.ciphertext,
      cash_commitment: c.commitment, active_principal_commitment: a.commitment, impaired_principal_commitment: i.commitment,
      debt_before: state.debt, debt_after: debtAfter.toString(), vault_assets_before: state.vaultAssets, vault_assets_after: (total - loss).toString(),
      vault_provision_before: state.vaultProvision, vault_provision_after: nextU.toString(), provision_before: state.brokerProvision,
      provision_after: provision.toString(), realized_loss: loss.toString(), book_version: state.bookVersion, accounting_version: state.accountingVersion,
    }, { kind: 'reconciliation', broker_secret: this.keys.secret(state.brokerKey), cash: state.cash.amount,
      active_principal: state.activePrincipal.amount, impaired_principal: state.impairedPrincipal.amount,
      cash_blinding: c.blinding, active_principal_blinding: a.blinding, impaired_principal_blinding: i.blinding });
  }

  async balance(context: OperationContext, state: SpendingState, zero: boolean): Promise<ProvenOperation> {
    integer(state.amount);
    if (zero && state.amount !== '0') throw new Error('Balance is not zero');
    return this.prove(zero ? 'ZeroBalance' : 'Ownership', {
      context, owner_key: this.keys.publicKey(state.key), ciphertext: state.ciphertext,
      expected_amount: state.amount, spending_version: state.version,
    }, { kind: 'balance', secret_key: this.keys.secret(state.key) });
  }

  async combine(operation: 'add' | 'sub', left: Ciphertext, right: Ciphertext): Promise<Ciphertext> {
    return this.crypto.execute(`ciphertext_${operation}`, { left: JSON.stringify(left), right: JSON.stringify(right) });
  }

  private async encrypt(publicKeys: EncryptionPublicKey[], amount: string): Promise<EncryptedViews> {
    return this.crypto.execute('encrypt_views', { public_keys: publicKeys, amount, seed_hex: freshSeed() });
  }
  private async commit(amount: string, wide = false): Promise<CommittedAmount> {
    integer(amount, wide ? maximum128 : maximumAmount);
    const sample = await this.crypto.execute<{ secret_key: string }>('keygen', { seed_hex: freshSeed() });
    const commitment = await this.crypto.execute<Commitment>(wide ? 'commitment_create_u128' : 'commitment_create', { amount, blinding: sample.secret_key });
    return { commitment, blinding: sample.secret_key };
  }
  private async subtractViews(before: ReaderView[], delta: ReaderView[]): Promise<ReaderView[]> {
    const result: ReaderView[] = [];
    for (let i = 0; i < before.length; i++) {
      if (before[i]!.reader_key.point !== delta[i]!.reader_key.point) throw new Error('Loan reader mismatch');
      result.push({ reader_key: before[i]!.reader_key, ciphertext: await this.combine('sub', before[i]!.ciphertext, delta[i]!.ciphertext) });
    }
    return result;
  }
  private async prove(name: StatementName, fields: Record<string, unknown>, witness: Record<string, unknown>): Promise<ProvenOperation> {
    const statement = { [name]: fields } as Statement;
    const envelope = await this.crypto.execute<ProofEnvelope>('prove', {
      statement: JSON.stringify(statement), witness: JSON.stringify(witness), seed_hex: freshSeed(),
    }, { artifactName: `${families[name]}.pk` });
    if (envelope.profile_hash !== this.keys.identity.profileHash || envelope.statement_kind !== name) throw new Error('Unexpected proof profile or family');
    await this.crypto.execute('verify', { statement: JSON.stringify(statement), envelope: JSON.stringify(envelope) }, { artifactName: `${families[name]}.vk` });
    return { statement, envelope };
  }
}
