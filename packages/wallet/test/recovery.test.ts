import test from 'node:test';
import assert from 'node:assert/strict';
import { HistoryRecovery, type BalanceHistoryEntry, type LoanHistoryEntry } from '../src/recovery.js';
import { Keyring, type CryptoExecutor, type KeyReference } from '../src/keyring.js';

const reference: KeyReference = { role: 'holder', subjectId: 'borrower.test.near', keyId: '1' };
const ciphertext = (amount: string) => ({ ephemeral: 'test', message: amount });
const executor: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
  const args = params as Record<string, string>;
  if (method === 'keygen') return { secret_key: '1'.repeat(64), public_key: { point: '2'.repeat(64) } } as T;
  if (method === 'verify_plaintext_u128') return (JSON.parse(args.ciphertext!).message === args.amount) as T;
  throw new Error('Unexpected test operation');
} };
async function* entries<T>(items: T[]): AsyncIterable<T> { yield* items; }
async function recovery(): Promise<HistoryRecovery> {
  const keys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.test.near', assetId: 'token.test.near', profileHash: 'a'.repeat(64) }, executor);
  await keys.generate(reference);
  return new HistoryRecovery(executor, keys);
}

test('restoration rejects omissions, duplicates and a reconstructed amount that does not match final ciphertexts', async () => {
  const reader = await recovery();
  const records: BalanceHistoryEntry[] = [
    { sequence: '1', keyId: '1', change: { operation: 'credit', bucket: 'inbox', amount: { publicAmount: '9007199254740993' } } },
    { sequence: '2', keyId: '1', change: { operation: 'merge' } },
    { sequence: '3', keyId: '1', change: { operation: 'debit', bucket: 'spending', amount: { publicAmount: '9' } } },
  ];
  const snapshot = { lastSequence: '3', key: reference, spending: ciphertext('9007199254740984'), inbox: ciphertext('0') };
  assert.deepEqual(await reader.balance(snapshot, entries(records)), { spending: '9007199254740984', inbox: '0' });
  await assert.rejects(reader.balance(snapshot, entries([records[0]!, records[2]!])), /gap/);
  await assert.rejects(reader.balance(snapshot, entries([records[0]!, records[0]!])), /gap/);
  await assert.rejects(reader.balance(snapshot, entries(records.slice(0, 2))), /Incomplete/);
  await assert.rejects(reader.balance({ ...snapshot, spending: ciphertext('9007199254740985') }, entries(records)), /does not match/);
  await assert.rejects(reader.balance(snapshot, entries([{ ...records[0]!, keyId: '2' }])), /mismatched key/);
});

test('loan recovery preserves a defaulted claim and rejects repayments after default', async () => {
  const reader = await recovery();
  const records: LoanHistoryEntry[] = [
    { sequence: '1', keyId: '1', change: { operation: 'originate', principal: { publicAmount: '100' }, owed: { publicAmount: '120' }, periodic: { publicAmount: '20' } } },
    { sequence: '2', keyId: '1', change: { operation: 'repay', payment: { publicAmount: '30' }, principalPaid: { publicAmount: '30' }, full: false } },
    { sequence: '3', keyId: '1', change: { operation: 'impair' } },
    { sequence: '4', keyId: '1', change: { operation: 'default' } },
  ];
  const snapshot = { lastSequence: '4', key: reference, principal: ciphertext('100'), owed: ciphertext('90'), periodic: ciphertext('20'), principalRemaining: ciphertext('70'), status: 'defaulted' as const };
  const result = await reader.loan(snapshot, entries(records));
  assert.equal(result.principalRemaining, '70');
  assert.equal(result.owed, '90');
  assert.equal(result.cumulativePaid, '30');
  await assert.rejects(reader.loan({ ...snapshot, lastSequence: '5' }, entries([...records, { ...records[1]!, sequence: '5' }])), /terminal loan/);
  const badAllocation: LoanHistoryEntry = { ...records[1]!, change: { operation: 'repay', payment: { publicAmount: '30' }, principalPaid: { publicAmount: '10' }, full: false } };
  await assert.rejects(reader.loan(snapshot, entries([records[0]!, badAllocation, ...records.slice(2)])), /repayment history/);
});
