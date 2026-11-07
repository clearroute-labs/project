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

function auditViews(issuerKey = key, tokenAuditorKey = { point: '2'.repeat(64) }) {
  return [
    { reader_key: { point: '3'.repeat(64) }, ciphertext: cipher(0) },
    { reader_key: issuerKey, ciphertext: cipher(0) },
    { reader_key: tokenAuditorKey, ciphertext: cipher(0) },
  ];
}

function auditTransferViews(issuerKey = key, tokenAuditorKey = { point: '2'.repeat(64) }) {
  return [
    { reader_key: { point: '3'.repeat(64) }, ciphertext: cipher(0) },
    { reader_key: { point: '4'.repeat(64) }, ciphertext: cipher(0) },
    { reader_key: issuerKey, ciphertext: cipher(25) },
    { reader_key: tokenAuditorKey, ciphertext: cipher(25) },
    { reader_key: { point: '4'.repeat(64) }, ciphertext: cipher(25) },
  ];
}

function auditRecords() {
  const views = auditViews();
  const transferViews = auditTransferViews();
  return [
    { operation: 'shield', statement: { PublicConversion: { public_amount: '50', views } }, origin: 'holder:alice.near' },
    { operation: 'confidential-send', statement: { ConfidentialTransfer: { transfer_views: transferViews, transfer_recovery: Array.from({ length: 5 }, () => pair(25)) } }, origin: 'holder:sender.near' },
    { operation: 'unshield', statement: { PublicConversion: { public_amount: '10', views } }, origin: 'holder:alice.near' },
  ].map((entry, index) => ({ event_id: String(index + 1), operation: entry.operation, subject_key: 'holder:alice.near', subject_sequence: String(index + 1), origin_subject_key: entry.origin, statement: jsonBytes(entry.statement), key_ids: ['1'], metadata: { action: '', noop: false, loan_id: null } }));
}

test('asset audit recovery reconstructs a mirror with only the authorized reader key', async () => {
  const records = auditRecords();
  class AuditRpc extends NearRpc {
    constructor(readonly incomplete = false) { super('https://rpc.example'); }
    override async finalizedBlock(): Promise<FinalizedBlock> { return block; }
    override async viewAt<T>(at: FinalizedBlock, _account: string, method: string, input: Arguments = {}): Promise<T> {
      assert.deepEqual(at, block);
      let result: unknown;
      if (method === 'get_asset_profile') result = { token_account: 'token.near', network_id: 'sandbox', crypto_profile_hash: Array(32).fill(0x22), issuer_key: { key_id: '1', public_key: jsonBytes(key), authorization_epoch: '0' }, token_auditor_key: { key_id: '1', public_key: jsonBytes({ point: '2'.repeat(64) }), authorization_epoch: '0' }, frozen: false };
      else if (method === 'get_verifier_config') result = { manifest_hash: Array(32).fill(0x33), ready: true };
      else if (method === 'get_holder') result = { owner: 'alice.near', key_id: '7', encryption_public_key: jsonBytes({ point: '3'.repeat(64) }), spending_version: '3', authorization_epoch: '0', recovery_start_sequence: '2', spending_ciphertext: jsonBytes(cipher(0)), inbox_ciphertext: jsonBytes(cipher(0)), issuer_balance_ciphertext: jsonBytes(cipher(65)), auditor_balance_ciphertext: jsonBytes(cipher(65)) };
      else if (method === 'list_recovery_history') {
        const cursor = BigInt(input.cursor as string);
        if (cursor === 18446744073709551615n) result = { records: [], end_cursor: '3', next_cursor: null };
        else result = { records: this.incomplete ? records.slice(0, 2) : records, end_cursor: '3', next_cursor: null };
      } else throw new Error(`Unexpected RPC method ${method}`);
      return result as T;
    }
  }
  const crypto: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
    const input = params as Record<string, unknown>;
    if (method === 'public_key_from_secret') return key as T;
    if (method === 'decrypt_recovery_pair') return ((input.pair as ReturnType<typeof pair>).low_limb.message) as T;
    if (method === 'verify_plaintext_u128') return (JSON.parse(input.ciphertext as string).message === input.amount) as T;
    throw new Error(`Unexpected crypto call ${method}`);
  } };
  const keys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.near', assetId: 'token.near', profileHash }, crypto);
  await keys.importMaterial({ schema: 'confidential-lending-wallet/v1', identity: keys.identity, keys: [{ role: 'issuer', subjectId: 'token.near', keyId: '1', publicKey: key, secretKey: '4'.repeat(64) }] });
  const ledger = new LedgerWallet(new AuditRpc(), keys, crypto, manifestHash);
  const recovered = await ledger.auditBalance('holder', 'alice.near', 'issuer');
  assert.equal(recovered.mirror, '65');
  const tokenAuditorKey = { point: '2'.repeat(64) };
  const tokenCrypto: CryptoExecutor = { async execute<T>(method: string, params: unknown): Promise<T> {
    const input = params as Record<string, unknown>;
    if (method === 'public_key_from_secret') return tokenAuditorKey as T;
    if (method === 'decrypt_recovery_pair') return ((input.pair as ReturnType<typeof pair>).low_limb.message) as T;
    if (method === 'verify_plaintext_u128') return (JSON.parse(input.ciphertext as string).message === input.amount) as T;
    throw new Error(`Unexpected token-auditor crypto call ${method}`);
  } };
  const tokenKeys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.near', assetId: 'token.near', profileHash }, tokenCrypto);
  await tokenKeys.importMaterial({ schema: 'confidential-lending-wallet/v1', identity: tokenKeys.identity, keys: [{ role: 'token_auditor', subjectId: 'token.near', keyId: '1', publicKey: tokenAuditorKey, secretKey: '5'.repeat(64) }] });
  const tokenAudit = await new LedgerWallet(new AuditRpc(), tokenKeys, tokenCrypto, manifestHash).auditBalance('holder', 'alice.near', 'token_auditor');
  assert.equal(tokenAudit.mirror, '65');
  await assert.rejects(new LedgerWallet(new AuditRpc(true), keys, crypto, manifestHash).auditBalance('holder', 'alice.near', 'issuer'), /Incomplete confidential audit history/);
  records[1]!.statement = jsonBytes({ ConfidentialTransfer: { transfer_views: auditTransferViews(), transfer_recovery: Array.from({ length: 5 }, () => pair(26)) } });
  await assert.rejects(new LedgerWallet(new AuditRpc(), keys, crypto, manifestHash).auditBalance('holder', 'alice.near', 'issuer'), /Recovered amount does not match/);
});

test('asset audit recovery fails closed when the selected reader key is absent', async () => {
  const crypto: CryptoExecutor = { async execute<T>(): Promise<T> { throw new Error('unexpected crypto call'); } };
  const keys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.near', assetId: 'token.near', profileHash }, crypto);
  class ReaderRpc extends NearRpc {
    override async finalizedBlock(): Promise<FinalizedBlock> { return block; }
    override async viewAt<T>(_at: FinalizedBlock, _account: string, method: string): Promise<T> {
      if (method === 'get_asset_profile') return { token_account: 'token.near', network_id: 'sandbox', crypto_profile_hash: Array(32).fill(0x22), issuer_key: { key_id: '1', public_key: jsonBytes(key), authorization_epoch: '0' }, token_auditor_key: { key_id: '1', public_key: jsonBytes({ point: '2'.repeat(64) }), authorization_epoch: '0' }, frozen: false } as T;
      if (method === 'get_verifier_config') return { manifest_hash: Array(32).fill(0x33), ready: true } as T;
      throw new Error(`Unexpected RPC method ${method}`);
    }
  }
  const ledger = new LedgerWallet(new ReaderRpc('https://rpc.example'), keys, crypto, manifestHash);
  await assert.rejects(ledger.auditBalance('holder', 'alice.near', 'issuer'), /Wallet key is unavailable/);
});

test('broker book pagination stays within Core bounds and does not skip filtered IDs', async () => {
  const requests: Array<{ cursor: string; limit: number }> = [];
  class BookRpc extends NearRpc {
    override async finalizedBlock(): Promise<FinalizedBlock> { return block; }
    override async viewAt<T>(_at: FinalizedBlock, _account: string, method: string, input: Arguments = {}): Promise<T> {
      if (method === 'get_counters') return { loan_high_water: '101' } as T;
      if (method === 'list_loans') {
        requests.push({ cursor: input.cursor as string, limit: input.limit as number });
        // These records occupy the page but belong to another broker. The
        // adapter must still request every bounded page before filtering.
        return [{ loan_id: '1', broker_id: '8', status: 'Active', impaired: false }] as T;
      }
      throw new Error(`Unexpected broker-book method ${method}`);
    }
  }
  const crypto: CryptoExecutor = { async execute<T>(method: string): Promise<T> {
    if (method === 'public_key_from_secret') return key as T;
    if (method === 'verify_plaintext_u128') return true as T;
    throw new Error(`Unexpected broker-book crypto call ${method}`);
  } };
  const keys = new Keyring({ networkId: 'sandbox', coreAccountId: 'core.near', assetId: 'token.near', profileHash }, crypto);
  await keys.importMaterial({ schema: 'confidential-lending-wallet/v1', identity: keys.identity, keys: [{ role: 'broker', subjectId: '7', keyId: '9', publicKey: key, secretKey: '4'.repeat(64) }] });
  const ledger = new LedgerWallet(new BookRpc('https://rpc.example'), keys, crypto, manifestHash);
  const asset = {
    token_account: 'token.near', network_id: 'sandbox', crypto_profile_hash: Array(32).fill(0x22),
    issuer_key: { key_id: '1', public_key: jsonBytes(key), authorization_epoch: '0' },
    token_auditor_key: { key_id: '1', public_key: jsonBytes({ point: '2'.repeat(64) }), authorization_epoch: '0' }, frozen: false,
  };
  const balance = {
    record: { broker_id: '7', active_principal_ciphertext: jsonBytes(cipher(0)), impaired_principal_ciphertext: jsonBytes(cipher(0)) },
    key: { role: 'broker', subjectId: '7', keyId: '9' } as KeyReference, spending: '0', inbox: '0', snapshot: { block, asset },
  } as Parameters<typeof ledger.brokerBook>[0];
  const book = await ledger.brokerBook(balance);
  assert.deepEqual(book, { active: '0', impaired: '0' });
  assert.deepEqual(requests, [{ cursor: '0', limit: 50 }, { cursor: '50', limit: 50 }, { cursor: '100', limit: 50 }]);
});

