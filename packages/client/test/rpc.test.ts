import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NearRpc, RpcError, TransactionPendingError, extractEvents, type FinalOutcome } from '../src/index.js';

function rpcFetch(handler: (request: Record<string, unknown>) => unknown): typeof fetch {
  return (async (_url, init) => {
    const request = JSON.parse(init!.body as string) as Record<string, unknown>;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: handler(request) }), { status: 200 });
  }) as typeof fetch;
}

test('contract reads use finalized state and preserve large decimal strings', async () => {
  const rpc = new NearRpc('https://rpc.testnet.near.org', { fetch: rpcFetch(request => {
    assert.equal(request.method, 'query');
    assert.equal((request.params as Record<string, unknown>).finality, 'final');
    return { result: Array.from(new TextEncoder().encode('{"amount":"9223372036854775807"}')) };
  }) });
  assert.deepEqual(await rpc.view('core.testnet', 'get_claim', { account_id: 'alice.testnet' }), { amount: '9223372036854775807' });
});

test('RPC rejects invalid transport and mismatched response IDs', async () => {
  assert.throws(() => new NearRpc('http://rpc.testnet.near.org'));
  const rpc = new NearRpc('http://127.0.0.1:3030', { allowInsecureLocalhost: true,
    fetch: (async () => new Response('{"jsonrpc":"2.0","id":999,"result":{}}')) as typeof fetch });
  await assert.rejects(rpc.view('core.testnet', 'get_config'), RpcError);
});

test('contract view panics are reported as execution errors without decoding a missing result', async () => {
  const hash = '1'.repeat(32);
  const rpc = new NearRpc('https://rpc.example.org', { fetch: rpcFetch(() => ({
    error: 'wasm execution failed: Smart contract panicked: INVALID_AMOUNT',
    logs: [], block_hash: hash, block_height: 10,
  })) });
  await assert.rejects(rpc.viewAt({ hash, height: 10 }, 'core.near', 'list_loans', { cursor: '0', limit: 64 }),
    (error: unknown) => error instanceof RpcError && error.kind === 'rpc' && /list_loans.*INVALID_AMOUNT/.test(error.message));
});

test('recovery snapshots pin all views to the same finalized block', async () => {
  const hash = '1'.repeat(32);
  let responseHash = hash;
  const rpc = new NearRpc('https://rpc.example.org', { fetch: rpcFetch(request => {
    if (request.method === 'block') {
      assert.deepEqual(request.params, { finality: 'final' });
      return { header: { hash, height: 10 } };
    }
    assert.equal((request.params as Record<string, unknown>).block_id, hash);
    assert.equal((request.params as Record<string, unknown>).finality, undefined);
    return { block_hash: responseHash, block_height: 10, result: Array.from(new TextEncoder().encode('{"version":"42"}')) };
  }) });
  const block = await rpc.finalizedBlock();
  assert.deepEqual(await rpc.viewAt(block, 'core.near', 'get_holder'), { version: '42' });
  responseHash = '2'.repeat(44);
  await assert.rejects(rpc.viewAt(block, 'core.near', 'get_holder'), /different block/);
});

test('unknown transaction outcome remains pending, never turns into a refund', async () => {
  let queries = 0;
  const rpc = new NearRpc('https://rpc.testnet.near.org', { fetch: rpcFetch(request => {
    queries++;
    assert.equal(request.method, 'tx');
    return { final_execution_status: 'EXECUTED', status: { SuccessValue: '' } };
  }) });
  await assert.rejects(rpc.waitForFinalOutcome('1'.repeat(44), 'alice.testnet', { attempts: 2, intervalMs: 0 }), TransactionPendingError);
  assert.equal(queries, 2);
});

test('final transaction failures stay failures', async () => {
  const rpc = new NearRpc('https://rpc.testnet.near.org', { fetch: rpcFetch(() => ({
    final_execution_status: 'FINAL', status: { Failure: { ActionError: 'rejected' } },
  })) });
  const result = await rpc.waitForFinalOutcome('1'.repeat(44), 'alice.testnet');
  assert.ok('Failure' in result.status);
});

test('event extraction excludes foreign and failed receipt logs', () => {
  const log = 'EVENT_JSON:{"standard":"confidential_lending","version":"1.0.0","event":"loan_paid","data":{"loan_id":"7"}}';
  const outcome = {
    status: { SuccessValue: '' }, transaction: { hash: 'h', signer_id: 'a.near', receiver_id: 'core.near' },
    transaction_outcome: { id: 'tx', outcome: { executor_id: 'a.near', logs: [], status: { SuccessReceiptId: 'r1' } } },
    receipts_outcome: [
      { id: 'r1', outcome: { executor_id: 'core.near', logs: [log], status: { SuccessValue: '' } } },
      { id: 'r2', outcome: { executor_id: 'evil.near', logs: [log], status: { SuccessValue: '' } } },
      { id: 'r3', outcome: { executor_id: 'core.near', logs: [log], status: { Failure: {} } } },
    ],
  } satisfies FinalOutcome;
  assert.deepEqual(extractEvents(outcome, 'core.near').map(event => event.receiptId), ['r1']);
});
