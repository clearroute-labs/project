import test from 'node:test';
import assert from 'node:assert/strict';
import { KeyPair } from '@near-js/crypto';
import { decodeSignedTransaction } from '@near-js/transactions';
import { NearRpc } from '@confidential-lending/client';
import { KeeperSigner } from '../src/signer.js';

const key = KeyPair.fromRandom('ed25519');
const signal = new AbortController().signal;
const blockHash = '1'.repeat(32);

function rpc(handler: (method: string, params: unknown) => unknown): NearRpc {
  return new NearRpc('https://rpc.example.org', { fetch: async (_url, init) => {
    const request = JSON.parse(init?.body as string) as { method: string; params: unknown; id: number };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: handler(request.method, request.params) }));
  } });
}

const access = { nonce: 7, block_hash: blockHash, permission: { FunctionCall: { receiver_id: 'core.test.near', method_names: ['merge_broker_inbox', 'settle'], allowance: '1000000000000000000000000' } } };

test('signed transaction is bound to one Core, method, nonce and zero deposit', async () => {
  let broadcast: unknown;
  const client = rpc((method, params) => { if (method === 'query') return access; broadcast = params; return prepared.hash; });
  const signer = new KeeperSigner(client, 'keeper.test.near', 'core.test.near', key);
  const prepared = await signer.prepare('merge', '1', { broker_id: '1', expected_version: '0' }, signal);
  const decoded = decodeSignedTransaction(Buffer.from(prepared.signedTransactionBase64, 'base64'));
  assert.equal(decoded.transaction.nonce, 8n);
  assert.equal(decoded.transaction.receiverId, 'core.test.near');
  assert.equal(decoded.transaction.actions[0]?.functionCall?.methodName, 'merge_broker_inbox');
  assert.equal(decoded.transaction.actions[0]?.functionCall?.deposit, 0n);
  await signer.broadcast(prepared, signal);
  assert.deepEqual(broadcast, [prepared.signedTransactionBase64]);
  await assert.rejects(signer.broadcast({ ...prepared, hash: '2'.repeat(44) }, signal), /identity or signature/);
  await assert.rejects(signer.broadcast({ ...prepared, action: 'settle' }, signal), /identity or signature/);
});

test('full access, unrestricted methods, wrong receiver and unsafe nonce are rejected', async () => {
  for (const view of [
    { ...access, permission: 'FullAccess' },
    { ...access, permission: { FunctionCall: { ...access.permission.FunctionCall, method_names: [] } } },
    { ...access, permission: { FunctionCall: { ...access.permission.FunctionCall, receiver_id: 'other.test.near' } } },
    { ...access, permission: { FunctionCall: { ...access.permission.FunctionCall, method_names: ['settle', 'draw'] } } },
    { ...access, nonce: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    const signer = new KeeperSigner(rpc(() => view), 'keeper.test.near', 'core.test.near', key);
    await assert.rejects(signer.prepare('settle', '1', {}, signal));
  }
});

test('only FINAL execution can release the durable pending record', async () => {
  let status = 'EXECUTED_OPTIMISTIC';
  const signer = new KeeperSigner(rpc(method => method === 'query' ? access : {
    final_execution_status: status, status: { SuccessValue: '' },
    transaction: { hash: prepared.hash, signer_id: 'keeper.test.near', receiver_id: 'core.test.near' },
  }), 'keeper.test.near', 'core.test.near', key);
  const prepared = await signer.prepare('settle', '1', {}, signal);
  assert.equal(await signer.status(prepared, signal), 'unknown');
  status = 'FINAL';
  assert.equal(await signer.status(prepared, signal), 'success');
});
