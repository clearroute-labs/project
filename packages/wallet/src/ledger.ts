import { NearRpc, type Arguments, type FinalizedBlock } from '@confidential-lending/client';
import type { CryptoExecutor, EncryptionPublicKey, KeyReference, Keyring } from './keyring.js';
import { ProofBuilder, jsonBytes, proofArguments, type AgreementDraft, type AgreementTerms, type Ciphertext, type OperationContext, type ProvenOperation, type ReaderView, type RecoveryPair, type SpendingState, type Statement } from './proofs.js';
import { HistoryRecovery, type BalanceHistoryEntry, type LoanHistoryEntry, type RecoveredLoan } from './recovery.js';

export interface LedgerKey { key_id: string; public_key: number[]; authorization_epoch: string }
export interface LedgerAsset { token_account: string; network_id: string; crypto_profile_hash: number[]; issuer_key: LedgerKey; token_auditor_key: LedgerKey; frozen: boolean }
export interface LedgerHolder {
  owner: string; key_id: string; encryption_public_key: number[]; spending_version: string; authorization_epoch: string;
  recovery_start_sequence?: string;
  spending_ciphertext: number[]; inbox_ciphertext: number[]; issuer_balance_ciphertext: number[]; auditor_balance_ciphertext: number[];
}
export interface LedgerBroker {
  broker_id: string; owner: string; vault_id: string; encryption_key_id: string; encryption_public_key: number[];
  spending_version: string; accounting_version: string; risk_version: string; book_version: string; accounting_pending: boolean; accounting_pending_since: string;
  authorization_epoch: string; last_settlement_at: string;
  reconciliation_checkpoint_id: string | null;
  spending_ciphertext: number[]; inbox_ciphertext: number[]; issuer_balance_ciphertext: number[]; auditor_balance_ciphertext: number[];
  active_principal_ciphertext: number[]; impaired_principal_ciphertext: number[];
  debt_total: string; impairment_provision: string; loan_book_root: number[];
}
export interface LedgerVault { vault_id: string; assets_total: string; assets_available: string; loss_unrealized: string; accounting_version: string; checkpoint_policy: { epoch_seconds: string; disclosure_policy: string } }
export interface LedgerLoan {
  loan_id: string; broker_id: string; borrower: string; loan_version: string; status: 'Active' | 'Impaired' | 'Defaulted' | 'Paid'; impaired: boolean;
  borrower_key_id: string; broker_key_id: string; loan_auditor_key_id: string; loan_auditor_public_key: number[]; payment_remaining: number;
  principal_ciphertexts: number[][]; amount_owed_ciphertexts: number[][]; periodic_payment_ciphertexts: number[][];
  principal_remaining_ciphertexts: number[][]; principal_remaining_commitment: number[];
}
interface HistoryRecord {
  event_id: string; operation: string; subject_key: string; subject_sequence: string; origin_subject_key: string;
  statement: number[] | null; key_ids: string[];
  metadata: { action: string; noop: boolean; loan_id: string | null };
}
interface HistoryPage { records: HistoryRecord[]; next_cursor: string | null; end_cursor: string }
export interface LedgerSnapshot { block: FinalizedBlock; asset: LedgerAsset }
export interface PreparedCall { method: string; args: Arguments; block: FinalizedBlock; proof?: ProvenOperation }
export interface RecoveredBalance<T> { record: T; key: KeyReference; spending: string; inbox: string; snapshot: LedgerSnapshot }
export type AuditSubjectKind = 'holder' | 'broker'
export type AuditReaderRole = 'issuer' | 'token_auditor'
export interface RecoveredAuditBalance<T> { record: T; key: KeyReference; mirror: string; snapshot: LedgerSnapshot }

export function decodeWire<T>(bytes: number[]): T {
  if (!Array.isArray(bytes) || bytes.length > 1_000_000 || bytes.some(value => !Number.isInteger(value) || value < 0 || value > 255)) throw new Error('Invalid ledger byte encoding');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes))) as T;
}
function hex(bytes: number[]): string { return bytes.map(byte => byte.toString(16).padStart(2, '0')).join(''); }
function args(value: unknown): Arguments { return JSON.parse(JSON.stringify(value)) as Arguments; }
function fields(statement: Statement): Record<string, unknown> {
  const values = Object.values(statement);
  if (values.length !== 1 || !values[0] || typeof values[0] !== 'object') throw new Error('Invalid history statement');
  return values[0];
}
function keyMatches(reference: KeyReference, keys: Keyring, views: ReaderView[], index: number): void {
  if (!views[index] || views[index]!.reader_key.point !== keys.publicKey(reference).point) throw new Error('Recovery reader does not match the registered key');
}

/**
 * A private debit may only be prepared from spending.  Incoming credits are
 * intentionally kept in the inbox until the user (or an explicitly scoped
 * keeper) submits a merge.  Returning a stable marker lets the UI refresh,
 * merge at a finalized state, and then rebuild the proof instead of proving
 * against a stale ciphertext or guessing from public commitments.
 */
function requireSpendable(spending: string, inbox: string, amount: string, operation: string): void {
  const available = BigInt(spending);
  const pending = BigInt(inbox);
  const requested = BigInt(amount);
  if (requested <= 0n) throw new Error('Invalid private debit amount');
  if (requested <= available) return;
  if (requested <= available + pending && pending > 0n) throw new Error(`INBOX_MERGE_REQUIRED:${operation}`);
  throw new Error('Insufficient private spending balance');
}

function canonicalAmount(value: unknown, name: string): string {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) throw new Error(`Invalid ${name}`);
  const amount = BigInt(value);
  if (amount > (1n << 63n) - 1n) throw new Error(`${name} exceeds recovery bound`);
  return value;
}

/** Concrete wallet operations. One finalized block supplies every pre-state and recovery page for a proof. */
export class LedgerWallet {
  readonly proofs: ProofBuilder;
  readonly recovery: HistoryRecovery;
  constructor(readonly rpc: NearRpc, readonly keys: Keyring, readonly crypto: CryptoExecutor, readonly manifestHash: string) {
    this.proofs = new ProofBuilder(crypto, keys);
    this.recovery = new HistoryRecovery(crypto, keys);
  }

  async snapshot(signal?: AbortSignal): Promise<LedgerSnapshot> {
    const block = await this.rpc.finalizedBlock(signal);
    const asset = await this.view<LedgerAsset>(block, 'get_asset_profile', {}, signal);
    const verifier = await this.view<{ manifest_hash: number[]; ready: boolean }>(block, 'get_verifier_config', {}, signal);
    if (asset.network_id !== this.keys.identity.networkId || asset.token_account !== this.keys.identity.assetId
      || hex(asset.crypto_profile_hash) !== this.keys.identity.profileHash || hex(verifier.manifest_hash) !== this.manifestHash || !verifier.ready) throw new Error('Core deployment does not match the pinned wallet configuration');
    return { block, asset };
  }

  view<T>(block: FinalizedBlock, method: string, input: Arguments = {}, signal?: AbortSignal): Promise<T> {
    return this.rpc.viewAt<T>(block, this.keys.identity.coreAccountId, method, input, signal);
  }

  async context(snapshot: LedgerSnapshot, request: Arguments, signal?: AbortSignal): Promise<OperationContext> {
    const value = await this.view<{ operation_context: number[] } | null>(snapshot.block, 'get_proof_context', { args: request }, signal);
    if (!value) throw new Error('Proof context is unavailable for this finalized state');
    return decodeWire<OperationContext>(value.operation_context);
  }

  async holder(accountId: string, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<RecoveredBalance<LedgerHolder>> {
    const state = snapshot ?? await this.snapshot(signal);
    const record = await this.view<LedgerHolder | null>(state.block, 'get_holder', { owner: accountId }, signal);
    if (!record) throw new Error('Holder encryption key is not registered');
    const key: KeyReference = { role: 'holder', subjectId: accountId, keyId: record.key_id };
    return { record, key, snapshot: state, ...await this.recoverBalance(state, `holder:${accountId}`, key, record, signal) };
  }

  async broker(brokerId: string, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<RecoveredBalance<LedgerBroker>> {
    const state = snapshot ?? await this.snapshot(signal);
    const record = await this.view<LedgerBroker | null>(state.block, 'get_broker', { broker_id: brokerId }, signal);
    if (!record) throw new Error('Broker does not exist');
    const key: KeyReference = { role: 'broker', subjectId: brokerId, keyId: record.encryption_key_id };
    return { record, key, snapshot: state, ...await this.recoverBalance(state, `broker:${brokerId}`, key, record, signal) };
  }

  /**
   * Recover the asset-level issuer or token-auditor mirror for one registered
   * holder/broker. The reader key is the immutable key in AssetProfile; no
   * holder or broker encryption secret is needed. Every finalized history
   * event is replayed from sequence zero, including events before a holder or
   * broker encryption-key rotation, because the asset mirror spans the full
   * account lifetime. The final reconstruction is checked against the
   * finalized mirror ciphertext before it is returned.
   */
  async auditBalance(kind: 'holder', subjectId: string, readerRole: AuditReaderRole, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<RecoveredAuditBalance<LedgerHolder>>;
  async auditBalance(kind: 'broker', subjectId: string, readerRole: AuditReaderRole, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<RecoveredAuditBalance<LedgerBroker>>;
  async auditBalance(kind: AuditSubjectKind, subjectId: string, readerRole: AuditReaderRole, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<RecoveredAuditBalance<LedgerHolder | LedgerBroker>> {
    if (!subjectId || (kind === 'broker' && !/^(0|[1-9]\d*)$/.test(subjectId))) throw new Error('Audit subject identifier is invalid');
    const state = snapshot ?? await this.snapshot(signal);
    const assetKey = readerRole === 'issuer' ? state.asset.issuer_key : state.asset.token_auditor_key;
    if (!/^(0|[1-9]\d*)$/.test(assetKey.key_id)) throw new Error('Audit reader key ID is invalid');
    const reader: KeyReference = { role: readerRole, subjectId: state.asset.token_account, keyId: assetKey.key_id };
    // publicKey() intentionally fails when the imported wallet does not own
    // the selected audit key. Do not fall back to a holder/broker key.
    this.keys.publicKey(reader);
    const subject = `${kind}:${subjectId}`;
    const record = kind === 'holder'
      ? await this.view<LedgerHolder | null>(state.block, 'get_holder', { owner: subjectId }, signal)
      : await this.view<LedgerBroker | null>(state.block, 'get_broker', { broker_id: subjectId }, signal);
    if (!record) throw new Error(`The requested ${kind} is not registered`);
    const mirrorCiphertext = kind === 'holder'
      ? (readerRole === 'issuer' ? record.issuer_balance_ciphertext : record.auditor_balance_ciphertext)
      : (readerRole === 'issuer' ? record.issuer_balance_ciphertext : record.auditor_balance_ciphertext);
    const mirror = await this.recoverAuditMirror(state, subject, reader, mirrorCiphertext, signal);
    return { record, key: reader, mirror, snapshot: state } as RecoveredAuditBalance<LedgerHolder | LedgerBroker>;
  }

  private async recoverAuditMirror(snapshot: LedgerSnapshot, subject: string, reader: KeyReference, ciphertext: number[], signal?: AbortSignal): Promise<string> {
    const last = await this.historyEnd(snapshot, subject, signal);
    let sequence = 0n;
    let mirror = 0n;
    const max = (1n << 63n) - 1n;
    for await (const record of this.history(snapshot, subject, signal, '0')) {
      const expected = sequence + 1n;
      if (record.subject_sequence !== expected.toString()) throw new Error('Audit history has a gap, duplicate, or mismatched sequence');
      sequence = expected;
      const operation = record.operation;
      if (operation === 'merge-holder' || operation === 'merge-broker' || operation === 'manage-loan' || operation === 'reconcile-credit') continue;
      if (!record.statement) throw new Error('Audit history is missing its statement');
      const statement = fields(decodeWire<Statement>(record.statement));
      let delta: bigint;
      if (operation === 'draw' || operation === 'shield' || operation === 'unshield' || operation === 'settle') {
        const views = statement.views as ReaderView[];
        const readerIndex = reader.role === 'issuer' ? 1 : 2;
        keyMatches(reader, this.keys, views, readerIndex);
        const amount = canonicalAmount(statement.public_amount, 'public audit amount');
        delta = BigInt(amount) * BigInt(operation === 'draw' || operation === 'shield' ? 1 : -1);
      } else if (operation === 'originate' || operation === 'repay' || operation === 'confidential-send') {
        const views = statement.transfer_views as ReaderView[];
        const recoveries = statement.transfer_recovery as RecoveryPair[];
        const readerIndex = reader.role === 'issuer' ? 2 : 3;
        keyMatches(reader, this.keys, views, readerIndex);
        if (!Array.isArray(recoveries) || !recoveries[readerIndex]) throw new Error('Audit history is missing the authorized transfer recovery pair');
        if (record.origin_subject_key !== subject && record.subject_key !== subject) throw new Error('Audit history subject is not a transfer participant');
        const amount = await this.recovery.amount({ recovery: recoveries[readerIndex]! }, reader);
        delta = record.origin_subject_key === subject ? -amount : amount;
      } else throw new Error(`Unsupported financial audit operation: ${operation}`);
      mirror += delta;
      if (mirror < 0n || mirror > max) throw new Error('Invalid confidential audit mirror history');
    }
    if (sequence !== BigInt(last)) throw new Error('Incomplete confidential audit history');
    await this.recovery.verify(reader, decodeWire<Ciphertext>(ciphertext), mirror);
    return mirror.toString();
  }

  private async recoverBalance(snapshot: LedgerSnapshot, subject: string, key: KeyReference, record: { spending_ciphertext: number[]; inbox_ciphertext: number[]; recovery_start_sequence?: string }, signal?: AbortSignal): Promise<{ spending: string; inbox: string }> {
    const last = await this.historyEnd(snapshot, subject, signal);
    const startSequence = record.recovery_start_sequence ?? '0';
    return this.recovery.balance({ key, lastSequence: last, startSequence, spending: decodeWire(record.spending_ciphertext), inbox: decodeWire(record.inbox_ciphertext) }, this.balanceEntries(snapshot, subject, key, signal, startSequence), signal);
  }

  async loan(loanId: string, key: KeyReference, snapshot?: LedgerSnapshot, signal?: AbortSignal): Promise<{ record: LedgerLoan; amounts: RecoveredLoan; snapshot: LedgerSnapshot }> {
    const state = snapshot ?? await this.snapshot(signal);
    const record = await this.view<LedgerLoan | null>(state.block, 'get_loan', { loan_id: loanId }, signal);
    if (!record) throw new Error('Loan does not exist');
    const index = key.role === 'holder' ? 0 : key.role === 'broker' ? 1 : key.role === 'loan_auditor' ? 2 : -1;
    if (index < 0 || [record.borrower_key_id, record.broker_key_id, record.loan_auditor_key_id][index] !== key.keyId) throw new Error('Key is not an authorized loan reader');
    const status = record.status === 'Paid' ? 'closed' : record.status === 'Defaulted' ? 'defaulted' : record.impaired ? 'impaired' : 'active';
    const amounts = await this.recovery.loan({ key, lastSequence: await this.historyEnd(state, `loan:${loanId}`, signal), status,
      principal: decodeWire(record.principal_ciphertexts[index]!), owed: decodeWire(record.amount_owed_ciphertexts[index]!),
      periodic: decodeWire(record.periodic_payment_ciphertexts[index]!), principalRemaining: decodeWire(record.principal_remaining_ciphertexts[index]!),
    }, this.loanEntries(state, loanId, key, index, signal), signal);
    return { record, amounts, snapshot: state };
  }

  private historyEnd(snapshot: LedgerSnapshot, subject: string, signal?: AbortSignal): Promise<string> {
    return this.view<HistoryPage>(snapshot.block, 'list_recovery_history', { subject_key: subject, cursor: '18446744073709551615', limit: 1 }, signal).then(page => page.end_cursor);
  }

  private async *history(snapshot: LedgerSnapshot, subject: string, signal?: AbortSignal, startSequence = '0'): AsyncGenerator<HistoryRecord> {
    let cursor = startSequence;
    for (;;) {
      const page = await this.view<HistoryPage>(snapshot.block, 'list_recovery_history', { subject_key: subject, cursor, limit: 32 }, signal);
      for (const record of page.records) {
        if (record.subject_key !== subject) throw new Error('Recovery subject mismatch');
        yield record;
      }
      if (page.next_cursor === null) return;
      if (BigInt(page.next_cursor) <= BigInt(cursor)) throw new Error('Recovery pagination did not advance');
      cursor = page.next_cursor;
    }
  }

  private async *balanceEntries(snapshot: LedgerSnapshot, subject: string, key: KeyReference, signal?: AbortSignal, startSequence = '0'): AsyncGenerator<BalanceHistoryEntry> {
    for await (const record of this.history(snapshot, subject, signal, startSequence)) {
      const common = { sequence: record.subject_sequence, keyId: key.keyId };
      if (record.operation === 'merge-holder' || record.operation === 'merge-broker') { yield { ...common, change: { operation: 'merge' } }; continue; }
      if (record.operation === 'manage-loan' || record.operation === 'reconcile-credit') { yield { ...common, change: { operation: 'noop' } }; continue; }
      if (!record.statement) throw new Error('Financial history is missing its statement');
      const statement = fields(decodeWire<Statement>(record.statement));
      if (['draw', 'shield', 'unshield', 'settle'].includes(record.operation)) {
        const views = statement.views as ReaderView[];
        keyMatches(key, this.keys, views, 0);
        const credit = record.operation === 'draw' || record.operation === 'shield';
        yield { ...common, change: { operation: credit ? 'credit' : 'debit', bucket: credit ? 'inbox' : 'spending', amount: { publicAmount: statement.public_amount as string } } };
      } else if (['originate', 'repay', 'confidential-send'].includes(record.operation)) {
        const index = record.origin_subject_key === subject ? 0 : 1;
        keyMatches(key, this.keys, statement.transfer_views as ReaderView[], index);
        yield { ...common, change: { operation: index === 0 ? 'debit' : 'credit', bucket: index === 0 ? 'spending' : 'inbox', amount: { recovery: (statement.transfer_recovery as RecoveryPair[])[index]! } } };
      } else throw new Error('Unsupported financial recovery operation');
    }
  }

  private async *loanEntries(snapshot: LedgerSnapshot, loanId: string, key: KeyReference, reader: number, signal?: AbortSignal): AsyncGenerator<LoanHistoryEntry> {
    for await (const record of this.history(snapshot, `loan:${loanId}`, signal)) {
      const common = { sequence: record.subject_sequence, keyId: key.keyId };
      if (record.operation === 'manage-loan') {
        if (!['impair', 'unimpair', 'default'].includes(record.metadata.action) || record.metadata.noop) throw new Error('Invalid loan status recovery record');
        yield { ...common, change: { operation: record.metadata.action as 'impair' | 'unimpair' | 'default' } }; continue;
      }
      if (!record.statement) throw new Error('Loan history is missing its statement');
      const statement = fields(decodeWire<Statement>(record.statement));
      if (record.operation === 'originate') {
        keyMatches(key, this.keys, statement.owed_views as ReaderView[], reader);
        const principalReader = [1, 0, 4][reader]!;
        yield { ...common, change: { operation: 'originate', principal: { recovery: (statement.transfer_recovery as RecoveryPair[])[principalReader]! },
          owed: { recovery: (statement.owed_recovery as RecoveryPair[])[reader]! }, periodic: { recovery: (statement.payment_recovery as RecoveryPair[])[reader]! } } };
      } else if (record.operation === 'repay') {
        keyMatches(key, this.keys, statement.owed_delta as ReaderView[], reader);
        yield { ...common, change: { operation: 'repay', full: statement.mode === 'Full', payment: { recovery: (statement.owed_delta_recovery as RecoveryPair[])[reader]! }, principalPaid: { recovery: (statement.principal_delta_recovery as RecoveryPair[])[reader]! } } };
      } else throw new Error('Unsupported loan recovery operation');
    }
  }

  private spending(balance: RecoveredBalance<LedgerHolder | LedgerBroker>, inbox = false): SpendingState {
    return { key: balance.key, version: balance.record.spending_version,
      ciphertext: decodeWire(inbox ? balance.record.inbox_ciphertext : balance.record.spending_ciphertext), amount: inbox ? balance.inbox : balance.spending };
  }
  private conversionReaders(snapshot: LedgerSnapshot, key: KeyReference): EncryptionPublicKey[] {
    return [this.keys.publicKey(key), decodeWire(snapshot.asset.issuer_key.public_key), decodeWire(snapshot.asset.token_auditor_key.public_key)];
  }
  private prepared(snapshot: LedgerSnapshot, method: string, input: unknown, proof?: ProvenOperation): PreparedCall {
    return { method, args: args(input), block: snapshot.block, ...(proof ? { proof } : {}) };
  }

  async prepareMergeHolder(accountId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.holder(accountId, undefined, signal);
    return this.prepared(balance.snapshot, 'merge_inbox', { args: { expected_spending_version: balance.record.spending_version,
      new_spending_ciphertext: jsonBytes(await this.proofs.combine('add', decodeWire(balance.record.spending_ciphertext), decodeWire(balance.record.inbox_ciphertext))), proof: null } });
  }

  async prepareMergeBroker(brokerId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.broker(brokerId, undefined, signal);
    return this.prepared(balance.snapshot, 'merge_broker_inbox', { broker_id: brokerId, args: { expected_spending_version: balance.record.spending_version,
      new_spending_ciphertext: jsonBytes(await this.proofs.combine('add', decodeWire(balance.record.spending_ciphertext), decodeWire(balance.record.inbox_ciphertext))), proof: null } });
  }

  async prepareDraw(brokerId: string, amount: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.broker(brokerId, undefined, signal), snapshot = balance.snapshot;
    const context = await this.context(snapshot, { operation: 'draw', broker_id: brokerId }, signal);
    const proof = await this.proofs.conversion(context, this.spending(balance, true), amount, this.conversionReaders(snapshot, balance.key), 'Credit');
    return this.prepared(snapshot, 'draw', { args: { broker_id: brokerId, amount, proof: proofArguments(proof) } }, proof);
  }

  async prepareShield(accountId: string, claimId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.holder(accountId, undefined, signal), snapshot = balance.snapshot;
    const claim = await this.view<{ owner: string; amount: string; reserved_by: string | null } | null>(snapshot.block, 'get_claim', { claim_id: claimId }, signal);
    if (!claim || claim.owner !== accountId || claim.reserved_by !== null) throw new Error('Claim is not available to this holder');
    const context = await this.context(snapshot, { operation: 'shield', primary_id: claimId, account_id: accountId }, signal);
    const proof = await this.proofs.conversion(context, this.spending(balance, true), claim.amount, this.conversionReaders(snapshot, balance.key), 'Credit');
    return this.prepared(snapshot, 'shield', { args: { claim_id: claimId, amount: claim.amount, proof: proofArguments(proof) } }, proof);
  }

  async prepareHolderRegistration(accountId: string, keyId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const snapshot = await this.snapshot(signal), key: KeyReference = { role: 'holder', subjectId: accountId, keyId };
    const existing = await this.view<LedgerHolder | null>(snapshot.block, 'get_holder', { owner: accountId }, signal);
    const zeroProofs: ReturnType<typeof proofArguments>[] = [];
    if (existing) {
      if (BigInt(keyId) <= BigInt(existing.key_id)) throw new Error('Key rotation requires a newer key identifier');
      const old = await this.holder(accountId, snapshot, signal);
      if (old.spending !== '0' || old.inbox !== '0') throw new Error('Empty the confidential balance before rotating its key');
      const proof = await this.proofs.balance(await this.context(snapshot, { operation: 'holder-zero-total', account_id: accountId }, signal), {
        key: old.key, version: existing.spending_version, amount: '0',
        ciphertext: await this.proofs.combine('add', decodeWire(existing.spending_ciphertext), decodeWire(existing.inbox_ciphertext)),
      }, true);
      zeroProofs.push(proofArguments(proof));
    }
    const publicKey = await this.keys.generate(key);
    const context = await this.context(snapshot, { operation: 'register-holder', primary_id: keyId, account_id: accountId }, signal);
    const proof = await this.proofs.possession(context, key);
    return this.prepared(snapshot, 'register_holder', { args: { key_id: keyId, encryption_public_key: jsonBytes(publicKey), public_key: jsonBytes(publicKey), proof_of_possession: proofArguments(proof), authorization_signature: [], zero_proofs: zeroProofs } }, proof);
  }

  async prepareBrokerCreation(owner: string, vaultId: string, keyId: string, debtMaximum: string, signal?: AbortSignal): Promise<PreparedCall & { brokerId: string }> {
    const snapshot = await this.snapshot(signal);
    const counters = await this.view<{ broker_high_water: string }>(snapshot.block, 'get_counters', {}, signal);
    const brokerId = (BigInt(counters.broker_high_water) + 1n).toString(), key: KeyReference = { role: 'broker', subjectId: brokerId, keyId };
    const publicKey = await this.keys.generate(key);
    const context = await this.context(snapshot, { operation: 'create-broker', primary_id: vaultId, broker_id: brokerId, account_id: owner, key_id: keyId }, signal);
    const proof = await this.proofs.possession(context, key);
    return { ...this.prepared(snapshot, 'create_broker', { args: { vault_id: vaultId, encryption_key_id: keyId, encryption_public_key: jsonBytes(publicKey), debt_maximum: debtMaximum, proof_of_possession: proofArguments(proof) } }, proof), brokerId };
  }

  async prepareUnshield(accountId: string, amount: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.holder(accountId, undefined, signal), snapshot = balance.snapshot;
    requireSpendable(balance.spending, balance.inbox, amount, 'unshield');
    const context = await this.context(snapshot, { operation: 'unshield', account_id: accountId }, signal);
    const proof = await this.proofs.conversion(context, this.spending(balance), amount, this.conversionReaders(snapshot, balance.key), 'Debit');
    return this.prepared(snapshot, 'unshield', { args: { amount, expected_spending_version: balance.record.spending_version, proof: proofArguments(proof) } }, proof);
  }

  async prepareTransfer(accountId: string, destination: string, amount: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.holder(accountId, undefined, signal), snapshot = balance.snapshot;
    requireSpendable(balance.spending, balance.inbox, amount, 'transfer');
    const target = await this.view<LedgerHolder | null>(snapshot.block, 'get_holder', { owner: destination }, signal);
    if (!target || destination === accountId) throw new Error('Choose another registered holder');
    const recipient = decodeWire<EncryptionPublicKey>(target.encryption_public_key);
    const readers = [this.keys.publicKey(balance.key), recipient, decodeWire<EncryptionPublicKey>(snapshot.asset.issuer_key.public_key), decodeWire<EncryptionPublicKey>(snapshot.asset.token_auditor_key.public_key), recipient];
    const context = await this.context(snapshot, { operation: 'confidential-send', account_id: accountId, destination }, signal);
    const proof = await this.proofs.transfer(context, this.spending(balance), amount, readers);
    return this.prepared(snapshot, 'confidential_send', { args: { destination, expected_spending_version: balance.record.spending_version, proof: proofArguments(proof) } }, proof);
  }

  async agreement(brokerId: string, borrower: string, auditor: EncryptionPublicKey, terms: Pick<AgreementTerms, 'principal' | 'initialOwed' | 'periodicPayment' | 'paymentCount'>, signal?: AbortSignal): Promise<AgreementDraft> {
    const snapshot = await this.snapshot(signal);
    const broker = await this.view<LedgerBroker | null>(snapshot.block, 'get_broker', { broker_id: brokerId }, signal);
    const holder = await this.view<LedgerHolder | null>(snapshot.block, 'get_holder', { owner: borrower }, signal);
    if (!broker || !holder) throw new Error('Broker and borrower must register before agreeing to terms');
    const brokerKey = decodeWire<EncryptionPublicKey>(broker.encryption_public_key), borrowerKey = decodeWire<EncryptionPublicKey>(holder.encryption_public_key);
    return this.proofs.agreement({ ...terms, maxPaymentCount: 10_000,
      transferKeys: [brokerKey, borrowerKey, decodeWire(snapshot.asset.issuer_key.public_key), decodeWire(snapshot.asset.token_auditor_key.public_key), auditor],
      loanKeys: [borrowerKey, brokerKey, auditor] });
  }

  async prepareProposal(brokerId: string, borrower: string, auditorKeyId: string, draft: AgreementDraft,
    schedule: { interval: string; grace: string; expiry: string }, signal?: AbortSignal): Promise<PreparedCall> {
    const snapshot = await this.snapshot(signal);
    const broker = await this.view<LedgerBroker | null>(snapshot.block, 'get_broker', { broker_id: brokerId }, signal);
    const holder = await this.view<LedgerHolder | null>(snapshot.block, 'get_holder', { owner: borrower }, signal);
    const brokerKey = await this.view<LedgerKey | null>(snapshot.block, 'get_broker_key', { broker_id: brokerId, key_id: null }, signal);
    if (!broker || !holder || !brokerKey || decodeWire<EncryptionPublicKey>(broker.encryption_public_key).point !== draft.terms.transferKeys[0]!.point
      || decodeWire<EncryptionPublicKey>(holder.encryption_public_key).point !== draft.terms.transferKeys[1]!.point) throw new Error('Agreement reader registration changed');
    return this.prepared(snapshot, 'create_proposal', { args: {
      borrower, broker_id: brokerId, vault_id: broker.vault_id, borrower_key_id: holder.key_id, broker_key_id: broker.encryption_key_id,
      loan_auditor_key_id: auditorKeyId, loan_auditor_public_key: jsonBytes(draft.terms.loanKeys[2]),
      payment_count: draft.terms.paymentCount, payment_interval: schedule.interval, grace_period: schedule.grace, expiry: schedule.expiry,
      principal_ciphertexts: draft.principal.views.map(view => jsonBytes(view.ciphertext)), initial_owed_ciphertexts: draft.owed.views.map(view => jsonBytes(view.ciphertext)), periodic_payment_ciphertexts: draft.payment.views.map(view => jsonBytes(view.ciphertext)),
      principal_commitment: jsonBytes(draft.principalCommitment.commitment), owed_commitment: jsonBytes(draft.owedCommitment.commitment), payment_commitment: jsonBytes(draft.paymentCommitment.commitment),
      agreement_digest: [], broker_signature: [], borrower_signature: [], broker_authorization_epoch: brokerKey.authorization_epoch,
      borrower_authorization_epoch: holder.authorization_epoch, broker_authorization_nonce: '0', borrower_authorization_nonce: '0', broker_authorization_key_id: null, borrower_authorization_key_id: null,
    } });
  }

  async prepareOrigination(proposalId: string, draft: AgreementDraft, signal?: AbortSignal): Promise<PreparedCall> {
    const snapshot = await this.snapshot(signal);
    const proposal = await this.view<{ broker_id: string; principal_ciphertexts: number[][]; initial_owed_ciphertexts: number[][]; periodic_payment_ciphertexts: number[][]; principal_commitment: number[]; owed_commitment: number[]; payment_commitment: number[]; payment_count: number; consumed: boolean; revoked: boolean } | null>(snapshot.block, 'get_proposal', { proposal_id: proposalId }, signal);
    if (!proposal || proposal.consumed || proposal.revoked || proposal.payment_count !== draft.terms.paymentCount) throw new Error('Proposal is not available for this agreement');
    for (const [stored, values] of [[proposal.principal_ciphertexts, draft.principal.views], [proposal.initial_owed_ciphertexts, draft.owed.views], [proposal.periodic_payment_ciphertexts, draft.payment.views]] as const) {
      if (stored.length !== values.length || stored.some((bytes, index) => JSON.stringify(decodeWire(bytes)) !== JSON.stringify(values[index]!.ciphertext))) throw new Error('Draft ciphertexts do not match the agreed proposal');
    }
    for (const [stored, commitment] of [[proposal.principal_commitment, draft.principalCommitment.commitment], [proposal.owed_commitment, draft.owedCommitment.commitment], [proposal.payment_commitment, draft.paymentCommitment.commitment]] as const) {
      if (decodeWire<{ point: string }>(stored).point !== commitment.point) throw new Error('Draft commitment does not match the agreed proposal');
    }
    const balance = await this.broker(proposal.broker_id, snapshot, signal);
    requireSpendable(balance.spending, balance.inbox, draft.terms.principal, 'origination');
    const proof = await this.proofs.originate(await this.context(snapshot, { operation: 'originate', primary_id: proposalId }, signal), this.spending(balance), draft);
    return this.prepared(snapshot, 'originate', { args: { proposal_id: proposalId, proof: proofArguments(proof) } }, proof);
  }

  async prepareRepayment(accountId: string, loanId: string, mode: 'Regular' | 'Full', amount?: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.holder(accountId, undefined, signal), snapshot = balance.snapshot;
    const loan = await this.loan(loanId, balance.key, snapshot, signal), record = loan.record;
    if (record.borrower !== accountId || !['active', 'impaired'].includes(loan.amounts.status)) throw new Error('Loan is not payable by this account');
    const broker = await this.view<LedgerBroker | null>(snapshot.block, 'get_broker', { broker_id: record.broker_id }, signal);
    if (!broker) throw new Error('Loan broker is unavailable');
    const payment = mode === 'Full' ? loan.amounts.owed : amount ?? loan.amounts.periodic;
    requireSpendable(balance.spending, balance.inbox, payment, 'repayment');
    const borrowerKey = this.keys.publicKey(balance.key), brokerKey = decodeWire<EncryptionPublicKey>(broker.encryption_public_key), auditor = decodeWire<EncryptionPublicKey>(record.loan_auditor_public_key);
    const readers = [borrowerKey, brokerKey, auditor];
    const loanViews = (ciphertexts: number[][]): ReaderView[] => ciphertexts.map((bytes, index) => ({ reader_key: readers[index]!, ciphertext: decodeWire(bytes) }));
    const proof = await this.proofs.repay(await this.context(snapshot, { operation: 'repay', primary_id: loanId }, signal), this.spending(balance), {
      owed: loan.amounts.owed, periodicPayment: loan.amounts.periodic, principalRemaining: loan.amounts.principalRemaining,
      owedViews: loanViews(record.amount_owed_ciphertexts), paymentViews: loanViews(record.periodic_payment_ciphertexts), principalViews: loanViews(record.principal_remaining_ciphertexts),
      transferKeys: [borrowerKey, brokerKey, decodeWire(snapshot.asset.issuer_key.public_key), decodeWire(snapshot.asset.token_auditor_key.public_key), auditor],
      paymentRemaining: record.payment_remaining, loanVersion: record.loan_version,
    }, mode, payment);
    return this.prepared(snapshot, 'repay', { args: { loan_id: loanId, mode, expected_loan_version: record.loan_version,
      expected_borrower_spending_version: balance.record.spending_version, proof: proofArguments(proof) } }, proof);
  }

  async prepareManagement(loanId: string, action: 'Impair' | 'Unimpair' | 'Default', signal?: AbortSignal): Promise<PreparedCall> {
    const snapshot = await this.snapshot(signal);
    const loan = await this.view<LedgerLoan | null>(snapshot.block, 'get_loan', { loan_id: loanId }, signal);
    if (!loan) throw new Error('Loan does not exist');
    return this.prepared(snapshot, 'manage_loan', { args: { loan_id: loanId, action, expected_loan_version: loan.loan_version } });
  }

  /** The aggregate is reconstructed from every live loan, then checked against the Core's encrypted aggregate. */
  async brokerBook(balance: RecoveredBalance<LedgerBroker>, signal?: AbortSignal): Promise<{ active: string; impaired: string }> {
    const snapshot = balance.snapshot;
    const { loan_high_water: maximum } = await this.view<{ loan_high_water: string }>(snapshot.block, 'get_counters', {}, signal);
    let active = 0n, impaired = 0n;
    // Core caps bounded list pages at 50. Keep the cursor stride identical to
    // the requested page size so filtered/deleted loan IDs cannot be skipped.
    for (let cursor = 0n; cursor < BigInt(maximum); cursor += 50n) {
      const loans = await this.view<LedgerLoan[]>(snapshot.block, 'list_loans', { cursor: cursor.toString(), limit: 50, borrower: null, broker_id: balance.record.broker_id }, signal);
      for (const loan of loans) {
        if (loan.broker_id !== balance.record.broker_id || ['Paid', 'Defaulted'].includes(loan.status)) continue;
        const recovered = await this.loan(loan.loan_id, balance.key, snapshot, signal);
        const remaining = BigInt(recovered.amounts.principalRemaining);
        active += remaining;
        if (loan.impaired) impaired += remaining;
      }
    }
    await this.recovery.verify(balance.key, decodeWire(balance.record.active_principal_ciphertext), active);
    await this.recovery.verify(balance.key, decodeWire(balance.record.impaired_principal_ciphertext), impaired);
    return { active: active.toString(), impaired: impaired.toString() };
  }

  private async reconciliation(balance: RecoveredBalance<LedgerBroker>, checkpointId: string, settlement?: { amount: string; proof: ProvenOperation }, signal?: AbortSignal): Promise<{ input: Arguments; proof: ProvenOperation }> {
    const snapshot = balance.snapshot, broker = balance.record;
    const vault = await this.view<LedgerVault | null>(snapshot.block, 'get_vault', { vault_id: broker.vault_id }, signal);
    if (!vault) throw new Error('Broker vault is unavailable');
    const book = await this.brokerBook(balance, signal);
    const context = await this.context(snapshot, settlement && checkpointId === '0'
      ? { operation: 'settle-reconcile', broker_id: broker.broker_id, amount: settlement.amount }
      : { operation: 'reconcile-credit', broker_id: broker.broker_id, checkpoint_id: checkpointId }, signal);
    let cash = BigInt(balance.spending) + BigInt(balance.inbox), debt = BigInt(broker.debt_total), total = BigInt(vault.assets_total);
    let spending = decodeWire<Ciphertext>(broker.spending_ciphertext), accountingVersion = broker.accounting_version;
    if (settlement) {
      const amount = BigInt(settlement.amount), principal = amount < debt ? amount : debt;
      cash -= amount; debt -= principal; total += amount - principal;
      spending = settlement.proof.statement.PublicConversion!.spending_after as Ciphertext;
      accountingVersion = (BigInt(accountingVersion) + 1n).toString();
      context.expected_versions[1] = accountingVersion;
    }
    const proof = await this.proofs.reconcile(context, { brokerKey: balance.key,
      cash: { ciphertext: await this.proofs.combine('add', spending, decodeWire(broker.inbox_ciphertext)), amount: cash.toString() },
      activePrincipal: { ciphertext: decodeWire(broker.active_principal_ciphertext), amount: book.active },
      impairedPrincipal: { ciphertext: decodeWire(broker.impaired_principal_ciphertext), amount: book.impaired },
      debt: debt.toString(), vaultAssets: total.toString(), vaultProvision: vault.loss_unrealized, brokerProvision: broker.impairment_provision,
      bookVersion: broker.book_version, accountingVersion,
    });
    const statement = proof.statement.Reconciliation!;
    return { proof, input: args({ checkpoint_id: checkpointId, broker_id: broker.broker_id, expected_risk_version: broker.risk_version,
      expected_accounting_version: accountingVersion, new_broker_debt: statement.debt_after, new_broker_provision: statement.provision_after,
      loss: statement.realized_loss, new_vault_total: statement.vault_assets_after, proof: proofArguments(proof) }) };
  }

  async prepareReconciliation(brokerId: string, checkpointId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.broker(brokerId, undefined, signal);
    const result = await this.reconciliation(balance, checkpointId, undefined, signal);
    return this.prepared(balance.snapshot, 'reconcile_credit', { args: result.input }, result.proof);
  }

  async prepareSettlement(brokerId: string, amount: string, checkpointId?: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.broker(brokerId, undefined, signal), snapshot = balance.snapshot;
    requireSpendable(balance.spending, balance.inbox, amount, 'settlement');
    const context = await this.context(snapshot, { operation: 'settle', broker_id: brokerId, amount }, signal);
    const proof = await this.proofs.conversion(context, this.spending(balance), amount, this.conversionReaders(snapshot, balance.key), 'Debit');
    const reconciliationId = checkpointId ?? (BigInt(balance.record.impairment_provision) > 0n || balance.record.accounting_pending
      ? balance.record.reconciliation_checkpoint_id ?? '0' : undefined);
    const reconciliation = reconciliationId !== undefined ? (await this.reconciliation(balance, reconciliationId, { amount, proof }, signal)).input : null;
    return this.prepared(snapshot, 'settle', { args: { broker_id: brokerId, amount, expected_spending_version: balance.record.spending_version,
      expected_accounting_version: balance.record.accounting_version, reconciliation, proof: proofArguments(proof) } }, proof);
  }

  async prepareBrokerClosure(brokerId: string, signal?: AbortSignal): Promise<PreparedCall> {
    const balance = await this.broker(brokerId, undefined, signal), snapshot = balance.snapshot;
    const book = await this.brokerBook(balance, signal);
    if ([balance.spending, balance.inbox, book.active, book.impaired, balance.record.debt_total, balance.record.impairment_provision].some(value => value !== '0')) throw new Error('Broker still has balances or obligations');
    const cash = await this.proofs.combine('add', decodeWire(balance.record.spending_ciphertext), decodeWire(balance.record.inbox_ciphertext));
    const principal = await this.proofs.combine('add', decodeWire(balance.record.active_principal_ciphertext), decodeWire(balance.record.impaired_principal_ciphertext));
    const proof = await this.proofs.balance(await this.context(snapshot, { operation: 'broker-zero-total', broker_id: brokerId }, signal), {
      key: balance.key, version: balance.record.spending_version, amount: '0', ciphertext: await this.proofs.combine('add', cash, principal),
    }, true);
    return this.prepared(snapshot, 'delete_broker', { broker_id: brokerId, zero_proof: { broker_id: brokerId, combined_proof: proofArguments(proof) } }, proof);
  }
}

