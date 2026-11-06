import { open, constants } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { KeyPair, type KeyPairString } from '@near-js/crypto';
import { actionCreators, createTransaction, decodeSignedTransaction, encodeTransaction, Signature, SignedTransaction } from '@near-js/transactions';
import { base58 } from '@scure/base';
import { assertAccountId, NearRpc, RpcError, type Arguments } from '@confidential-lending/client';
import type { PreparedTransaction } from './journal.js';

const METHODS = { merge: 'merge_broker_inbox', settle: 'settle' } as const;
const ALLOWED_METHODS = new Set<string>(Object.values(METHODS));
const MAX_TRANSACTION_BYTES = 900_000;

interface AccessKeyView {
  nonce: number;
  block_hash: string;
  permission: 'FullAccess' | { FunctionCall: { receiver_id: string; method_names: string[]; allowance: string | null } };
}

export class KeeperSigner {
  constructor(readonly rpc: NearRpc, readonly signerId: string, readonly coreAccountId: string, private readonly key: KeyPair) {
    assertAccountId(signerId);
    assertAccountId(coreAccountId);
  }

  static async fromFile(rpc: NearRpc, coreAccountId: string, path: string): Promise<KeeperSigner> {
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const details = await file.stat();
      if (!details.isFile() || details.size > 4096 || (details.mode & 0o077) !== 0 || (process.getuid && details.uid !== process.getuid())) {
        throw new Error('Keeper key file must be an owner-only regular file');
      }
      const credentials = JSON.parse(await file.readFile('utf8')) as { account_id?: string; private_key?: string; public_key?: string };
      if (!credentials.account_id || !credentials.private_key?.startsWith('ed25519:')) throw new Error('Expected NEAR Ed25519 keeper credentials');
      const key = KeyPair.fromString(credentials.private_key as KeyPairString);
      if (credentials.public_key && key.getPublicKey().toString() !== credentials.public_key) throw new Error('Keeper key pair mismatch');
      return new KeeperSigner(rpc, credentials.account_id, coreAccountId, key);
    } finally { await file.close(); }
  }

  async prepare(action: PreparedTransaction['action'], brokerId: string, args: Arguments, signal: AbortSignal): Promise<PreparedTransaction> {
    if (!/^(0|[1-9]\d*)$/.test(brokerId)) throw new Error('Invalid broker ID');
    const method = METHODS[action];
    const publicKey = this.key.getPublicKey();
    const access = await this.rpc.request<AccessKeyView>('query', {
      request_type: 'view_access_key', finality: 'final', account_id: this.signerId, public_key: publicKey.toString(),
    }, signal);
    if (!Number.isSafeInteger(access.nonce) || access.nonce < 0) throw new Error('RPC returned an unsafe access-key nonce');
    const permission = access.permission;
    if (permission === 'FullAccess' || !permission.FunctionCall || permission.FunctionCall.receiver_id !== this.coreAccountId
      || permission.FunctionCall.method_names.length === 0
      || permission.FunctionCall.method_names.some(name => !ALLOWED_METHODS.has(name))
      || !permission.FunctionCall.method_names.includes(method)) {
      throw new Error('Keeper requires a function-call key restricted to this Core and its merge/settle methods');
    }
    const blockHash = base58.decode(access.block_hash);
    if (blockHash.length !== 32) throw new Error('Invalid finalized block hash');
    signal.throwIfAborted();
    const transaction = createTransaction(this.signerId, publicKey, this.coreAccountId, BigInt(access.nonce) + 1n,
      [actionCreators.functionCall(method, args, 300_000_000_000_000n, 0n)], blockHash);
    const digest = createHash('sha256').update(encodeTransaction(transaction)).digest();
    const signature = this.key.sign(digest);
    const signed = new SignedTransaction({ transaction, signature: new Signature({ keyType: publicKey.keyType, data: signature.signature }) });
    const bytes = encodeTransaction(signed);
    if (bytes.length > MAX_TRANSACTION_BYTES) throw new Error('Keeper transaction exceeds the configured size bound');
    return { hash: base58.encode(digest), signerId: this.signerId, signedTransactionBase64: Buffer.from(bytes).toString('base64'), brokerId, action, preparedAt: Date.now() };
  }

  async broadcast(prepared: PreparedTransaction, signal: AbortSignal): Promise<void> {
    this.validate(prepared);
    signal.throwIfAborted();
    const hash = await this.rpc.request<string>('broadcast_tx_async', [prepared.signedTransactionBase64], signal);
    if (hash !== prepared.hash) throw new Error('RPC returned a different transaction hash; retain the pending transaction');
  }

  async status(prepared: PreparedTransaction, signal: AbortSignal): Promise<'unknown' | 'success' | 'failure'> {
    this.validate(prepared);
    try {
      const result = await this.rpc.transactionStatus(prepared.hash, prepared.signerId, signal);
      if (result.final_execution_status !== 'FINAL') return 'unknown';
      if (result.transaction.hash !== prepared.hash || result.transaction.signer_id !== this.signerId || result.transaction.receiver_id !== this.coreAccountId) {
        throw new Error('RPC transaction identity mismatch');
      }
      if ('Failure' in result.status) return 'failure';
      if ('SuccessValue' in result.status) return 'success';
      return 'unknown';
    } catch (error) {
      if (error instanceof RpcError) return 'unknown';
      throw error;
    }
  }

  private validate(prepared: PreparedTransaction): void {
    const bytes = Buffer.from(prepared.signedTransactionBase64, 'base64');
    if (bytes.length > MAX_TRANSACTION_BYTES || bytes.toString('base64') !== prepared.signedTransactionBase64) throw new Error('Invalid journal transaction encoding');
    const signed = decodeSignedTransaction(bytes);
    const transaction = signed.transaction;
    const digest = createHash('sha256').update(encodeTransaction(transaction)).digest();
    const call = transaction.actions[0]?.functionCall;
    // The SDK's Borsh decoder returns plain nested records, despite its class-shaped types.
    const publicKey = this.key.getPublicKey();
    const decodedKey = transaction.publicKey.ed25519Key?.data;
    const decodedSignature = signed.signature.ed25519Signature?.data;
    if (prepared.signerId !== this.signerId || transaction.signerId !== this.signerId || transaction.receiverId !== this.coreAccountId
      || !decodedKey || !Buffer.from(decodedKey).equals(Buffer.from(publicKey.data)) || base58.encode(digest) !== prepared.hash
      || transaction.actions.length !== 1 || !call || call.methodName !== METHODS[prepared.action] || call.deposit !== 0n
      || call.gas > 300_000_000_000_000n || !decodedSignature || !publicKey.verify(digest, Uint8Array.from(decodedSignature))
      || !Buffer.from(encodeTransaction(signed)).equals(bytes)) throw new Error('Journal transaction failed identity or signature validation');
  }
}
