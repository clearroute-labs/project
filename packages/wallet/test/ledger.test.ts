import test from 'node:test';
import assert from 'node:assert/strict';
import { NearRpc, type Arguments, type FinalizedBlock } from '../../client/src/index.js';
import { Keyring, type CryptoExecutor, type KeyReference } from '../src/keyring.js';
import { LedgerWallet } from '../src/ledger.js';
import { jsonBytes, type Ciphertext } from '../src/proofs.js';

const key = { point: '1'.repeat(64) };
const profileHash = '2'.repeat(64), manifestHash = '3'.repeat(64);
const block: FinalizedBlock = { hash: 'A'.repeat(44), height: 42 };
const cipher = (amount: number): Ciphertext => ({ ephemeral: 'test-public-point', message: String(amount) });
const pair = (amount: number) => ({ low_limb: cipher(amount), high_limb: cipher(0) });
const views = Array.from({ length: 5 }, () => ({ reader_key: key, ciphertext: cipher(0) }));

test('Core history adapter preserves secondary subjects, merges and accounting-only records at one finalized block', async () => {
  const records = [
    { operation: 'draw', statement: { PublicConversion: { public_amount: '100', views } } },
    { operation: 'merge-broker', statement: null },
    { operation: 'originate', statement: { Origination: { transfer_views: views, transfer_recovery: Array(5).fill(pair(60)) } } },
    { operation: 'repay', statement: { Repayment: { transfer_views: views, transfer_recovery: Array(5).fill(pair(30)) } }, origin: 'holder:borrower.near' },
    { operation: 'reconcile-credit', statement: null },
    { operation: 'merge-broker', statement: null },
  ].map((entry, index) => ({ event_id: String(index + 100), operation: entry.operation, subject_key: 'broker:7', subject_sequence: String(index + 1), origin_subject_key: entry.origin ?? 'broker:7', statement: entry.statement ? jsonBytes(entry.statement) : null, key_ids: ['9'], metadata: { action: '', noop: false, loan_id: null } }));
  const requests: Array<{ method: string; args: Arguments }> = [];
  class HistoryRpc extends NearRpc {
    override async finalizedBlock(): Promise<FinalizedBlock> { return block; }
    override async viewAt<T>(at: FinalizedBlock, _account: string, method: string, input: Arguments = {}): Promise<T> {
      assert.deepEqual(at, block); requests.push({ method, args: input });
      let result: unknown;
      if (method === 'get_asset_profile') result = { token_account: 'token.near', network_id: 'sandbox', crypto_profile_hash: Array(32).fill(0x22) };
      else if (method === 'get_verifier_config') result = { manifest_hash: Array(32).fill(0x33), ready: true };
      else if (method === 'get_broker') result = { broker_id: '7', encryption_key_id: '9', spending_ciphertext: jsonBytes(cipher(70)), inbox_ciphertext: jsonBytes(cipher(0)) };
      else if (method === 'list_recovery_history') {
        const cursor = BigInt(input.cursor as string);
        const page = records.filter(record => BigInt(record.subject_sequence) > cursor).slice(0, 2);
        const end = page.at(-1)?.subject_sequence ?? '6';
        result = { records: page, end_cursor: end, next_cursor: BigInt(end) < 6n ? end : null };
      } else throw new Error('Unexpected RPC method');
      return result as T;
    }
  }
  const crypto: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
    const input = params as Record<string, unknown>;
    if (method === 'public_key_from_secret') return key as T;
    if (method === 'decrypt_recovery_pair') return (input.pair as ReturnType<typeof pair>).low_limb.message as T;
    if (method === 'verify_plaintext_u128') return (JSON.parse(input.ciphertext as string).message === input.amount) as T;
    throw new Error('Unexpected crypto call');
  } };
  const keys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.near', assetId: 'token.near', profileHash }, crypto);
  const reference: KeyReference = { role: 'broker', subjectId: '7', keyId: '9' };
  await keys.importMaterial({ schema: 'confidential-lending-wallet/v1', identity: keys.identity, keys: [{ ...reference, publicKey: key, secretKey: '4'.repeat(64) }] });
  const ledger = new LedgerWallet(new HistoryRpc('https://rpc.example'), keys, crypto, manifestHash);
  const recovered = await ledger.broker('7');
  assert.equal(recovered.spending, '70'); assert.equal(recovered.inbox, '0');
  assert.deepEqual(requests.filter(request => request.method === 'list_recovery_history').map(request => request.args.cursor), ['18446744073709551615', '0', '2', '4']);
  records[3]!.origin_subject_key = 'broker:7';
  await assert.rejects(ledger.broker('7'), /Recovered amount does not match/);
});
