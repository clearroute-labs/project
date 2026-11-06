import type { CryptoExecutor, KeyReference, Keyring } from './keyring.js';
import type { Ciphertext, RecoveryPair } from './proofs.js';

export type RecoverableAmount = { publicAmount: string } | { recovery: RecoveryPair };
export interface BalanceHistoryEntry {
  sequence: string;
  keyId: string;
  change:
    | { operation: 'merge' }
    | { operation: 'noop' }
    | { operation: 'credit' | 'debit'; bucket: 'spending' | 'inbox'; amount: RecoverableAmount };
}
export interface BalanceSnapshot {
  lastSequence: string;
  key: KeyReference;
  spending: Ciphertext;
  inbox: Ciphertext;
}
export interface LoanHistoryEntry {
  sequence: string;
  keyId: string;
  change:
    | { operation: 'originate'; principal: RecoverableAmount; owed: RecoverableAmount; periodic: RecoverableAmount }
    | { operation: 'repay'; payment: RecoverableAmount; principalPaid: RecoverableAmount; full: boolean }
    | { operation: 'impair' | 'unimpair' | 'default' };
}
export interface LoanSnapshot {
  lastSequence: string;
  key: KeyReference;
  principal: Ciphertext;
  owed: Ciphertext;
  periodic: Ciphertext;
  principalRemaining: Ciphertext;
  status: 'active' | 'impaired' | 'defaulted' | 'closed';
}
export interface RecoveredLoan {
  principal: string; initialOwed: string; owed: string; periodic: string;
  principalRemaining: string; cumulativePaid: string; status: LoanSnapshot['status'];
}
const cap = (1n << 63n) - 1n;
function unsigned(text: string, max = cap): bigint {
  if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error('Invalid recovery integer');
  const value = BigInt(text);
  if (value > max) throw new Error('Recovery integer exceeds bound');
  return value;
}

/** Replay only finalized, contract-authenticated history; check the result against current ciphertexts before use. */
export class HistoryRecovery {
  constructor(readonly crypto: CryptoExecutor, readonly keys: Keyring) {}

  async balance(snapshot: BalanceSnapshot, entries: AsyncIterable<BalanceHistoryEntry>, signal?: AbortSignal): Promise<{ spending: string; inbox: string }> {
    let sequence = 0n, spending = 0n, inbox = 0n;
    const last = unsigned(snapshot.lastSequence, (1n << 64n) - 1n);
    for await (const entry of entries) {
      signal?.throwIfAborted();
      sequence++;
      this.checkSequence(entry, sequence, last, snapshot.key);
      if (entry.change.operation === 'noop') continue;
      if (entry.change.operation === 'merge') { spending += inbox; inbox = 0n; }
      else {
        const amount = await this.amount(entry.change.amount, snapshot.key);
        const delta = entry.change.operation === 'credit' ? amount : -amount;
        if (entry.change.bucket === 'spending') spending += delta;
        else inbox += delta;
      }
      if (spending < 0n || inbox < 0n || spending + inbox > cap) throw new Error('Invalid confidential balance history');
    }
    if (sequence !== last) throw new Error('Incomplete confidential balance history');
    signal?.throwIfAborted();
    await this.verify(snapshot.key, snapshot.spending, spending);
    await this.verify(snapshot.key, snapshot.inbox, inbox);
    return { spending: spending.toString(), inbox: inbox.toString() };
  }

  async loan(snapshot: LoanSnapshot, entries: AsyncIterable<LoanHistoryEntry>, signal?: AbortSignal): Promise<RecoveredLoan> {
    let sequence = 0n, principal = 0n, initialOwed = 0n, owed = 0n, periodic = 0n, remaining = 0n, paid = 0n;
    let status: LoanSnapshot['status'] = 'active';
    const last = unsigned(snapshot.lastSequence, (1n << 64n) - 1n);
    for await (const entry of entries) {
      signal?.throwIfAborted();
      sequence++;
      this.checkSequence(entry, sequence, last, snapshot.key);
      const change = entry.change;
      if (change.operation === 'originate') {
        if (sequence !== 1n) throw new Error('Duplicate loan origination');
        principal = await this.amount(change.principal, snapshot.key);
        owed = initialOwed = await this.amount(change.owed, snapshot.key);
        periodic = await this.amount(change.periodic, snapshot.key);
        remaining = principal;
        if (principal === 0n || owed < principal || periodic === 0n || periodic > owed) throw new Error('Invalid confidential loan terms');
      } else {
        if (sequence === 1n || status === 'closed' || status === 'defaulted') throw new Error('Invalid terminal loan history');
        if (change.operation === 'repay') {
          const amount = await this.amount(change.payment, snapshot.key);
          const principalPaid = await this.amount(change.principalPaid, snapshot.key);
          const expectedPrincipal = amount < remaining ? amount : remaining;
          if (principalPaid !== expectedPrincipal || amount === 0n || amount > owed
            || (change.full ? amount !== owed : amount < periodic || amount >= owed)) throw new Error('Invalid confidential repayment history');
          remaining -= principalPaid; owed -= amount; paid += amount;
          if (change.full) status = 'closed';
        } else if (change.operation === 'default') status = 'defaulted';
        else if (change.operation === 'impair') {
          if (status !== 'active') throw new Error('Invalid impairment history');
          status = 'impaired';
        } else {
          if (status !== 'impaired') throw new Error('Invalid unimpairment history');
          status = 'active';
        }
      }
    }
    if (sequence === 0n || sequence !== last || status !== snapshot.status) throw new Error('Incomplete confidential loan history');
    signal?.throwIfAborted();
    for (const [ciphertext, value] of [[snapshot.principal, principal], [snapshot.owed, owed], [snapshot.periodic, periodic], [snapshot.principalRemaining, remaining]] as const) await this.verify(snapshot.key, ciphertext, value);
    return { principal: principal.toString(), initialOwed: initialOwed.toString(), owed: owed.toString(), periodic: periodic.toString(),
      principalRemaining: remaining.toString(), cumulativePaid: paid.toString(), status };
  }

  async amount(value: RecoverableAmount, reference: KeyReference): Promise<bigint> {
    if ('publicAmount' in value) return unsigned(value.publicAmount);
    const result = await this.crypto.execute<string>('decrypt_recovery_pair', {
      secret_key: this.keys.secret(reference), expected_key: this.keys.publicKey(reference), pair: value.recovery,
    });
    return unsigned(result);
  }

  async verify(reference: KeyReference, ciphertext: Ciphertext, amount: bigint): Promise<void> {
    if (amount < 0n || amount > (1n << 128n) - 1n) throw new Error('Invalid reconstructed amount');
    const valid = await this.crypto.execute<boolean>('verify_plaintext_u128', {
      secret_key: this.keys.secret(reference), ciphertext: JSON.stringify(ciphertext), amount: amount.toString(),
    });
    if (valid !== true) throw new Error('Recovered amount does not match ledger ciphertext');
  }

  private checkSequence(entry: { sequence: string; keyId: string }, sequence: bigint, last: bigint, reference: KeyReference): void {
    if (entry.sequence !== sequence.toString() || sequence > last || entry.keyId !== reference.keyId) throw new Error('Recovery history has a gap, duplicate, or mismatched key');
  }
}
