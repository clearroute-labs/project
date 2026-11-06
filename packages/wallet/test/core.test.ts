import test from 'node:test';
import assert from 'node:assert/strict';
import { CoreWallet, type CoreReadRpc, type FinalizedBlock } from '../src/core.js';

const profileHash = 'aa'.repeat(32);
const manifestHash = 'bb'.repeat(32);
const block: FinalizedBlock = { hash: 'final-block', height: 42 };

function bytes(value: unknown): number[] { return [...new TextEncoder().encode(JSON.stringify(value))]; }

function contextWire(): Record<string, unknown> {
  const id = Array.from({ length: 32 }, (_, index) => index);
  return { network_id: id, core_account: id, asset_id: id, operation_id: id, vault_id: id, broker_id: id, loan_id: id, proposal_id: id, expected_versions: Array(8).fill('4'), authorization_epochs: Array(4).fill('2'), expiry: '99' };
}

function fakeRpc(view: (method: string, args: Record<string, unknown>) => unknown): CoreReadRpc {
  return { finalizedBlock: async () => block, viewAt: async (_block, _account, method, args) => view(method, args || {}) as never };
}

function wallet(rpc: CoreReadRpc): CoreWallet {
  return new CoreWallet(rpc, { networkId: 'sandbox', coreAccountId: 'core.test.near', assetId: 'token.test.near', profileHash, manifestHash }, { execute: async () => ({}) }, {}, {});
}

test('CoreWallet pins proof contexts and maps canonical byte fields', async () => {
  let captured: { method: string; args: Record<string, unknown> } | undefined;
  const result = wallet(fakeRpc((method, args) => {
    captured = { method, args };
    return { operation: 'draw', asset_account: 'token.test.near', network_id: 'sandbox', profile_hash: Array(32).fill(170), verifier_manifest_hash: Array(32).fill(187), ids: ['1'], account_ids: ['broker.test.near'], versions: Array(8).fill('4'), ciphertexts: [[1, 2]], commitments: [[3]], public_values: ['5'], state_digest: Array(32).fill(9), statement_kind: 2, statement: [123, 125], public_inputs: [[7]], verifying_key_hash: Array(32).fill(8), operation_context: bytes(contextWire()) };
  }));
  const context = await result.getProofContext({ operation: 'draw', brokerId: '1', amount: '3' });
  assert.equal(captured?.method, 'get_proof_context');
  assert.deepEqual(captured?.args, { operation: 'draw', broker_id: '1', amount: '3' });
  assert.equal(context?.profileHash, profileHash);
  assert.equal(context?.manifestHash, manifestHash);
  assert.deepEqual(context?.ciphertexts, ['0102']);
  assert.deepEqual(context?.operationContext.expected_versions, Array(8).fill('4'));
  assert.deepEqual(context?.block, block);
});

test('CoreWallet normalizes finalized recovery pages and rejects noncanonical cursors', async () => {
  const result = wallet(fakeRpc((method) => {
    assert.equal(method, 'list_recovery_history');
    return { records: [{ event_id: '9', operation: 'merge-holder', subject_key: 'holder:alice.test.near', subject_sequence: '2', block_timestamp: '100', statement: [1], key_ids: ['3'], versions: ['4'], metadata: { noop: true } }], next_cursor: null, end_cursor: '2' };
  }));
  const page = await result.listRecoveryHistory('holder:alice.test.near');
  assert.equal(page.records[0]?.event_id, '9');
  assert.equal(page.next_cursor, undefined);
  await assert.rejects(result.listRecoveryHistory('holder:alice.test.near', '01'), /canonical/);
});

test('CoreWallet delegates proof argument conversion without private witnesses', async () => {
  const result = wallet(fakeRpc((method) => {
    assert.equal(method, 'get_proof_context');
    return { operation: 'draw', asset_account: 'token.test.near', network_id: 'sandbox', profile_hash: Array(32).fill(170), verifier_manifest_hash: Array(32).fill(187), ids: [], account_ids: [], versions: Array(8).fill('0'), ciphertexts: [], commitments: [], public_values: [], state_digest: Array(32).fill(0), statement: [123, 125], public_inputs: [], verifying_key_hash: Array(32).fill(8), operation_context: bytes(contextWire()) };
  }));
  const operation = { statement: { PublicConversion: { public_amount: '3' } }, envelope: { context_digest: 'aa', proof: 'bb', statement_kind: 'PublicConversion', public_inputs: ['cc'], verifying_key_hash: 'dd', profile_hash: profileHash } };
  const proved = await result.prove({ operation: 'draw' }, async () => operation);
  assert.deepEqual(proved.args, { statement: [123, 34, 80, 117, 98, 108, 105, 99, 67, 111, 110, 118, 101, 114, 115, 105, 111, 110, 34, 58, 123, 34, 112, 117, 98, 108, 105, 99, 95, 97, 109, 111, 117, 110, 116, 34, 58, 34, 51, 34, 125, 125], context: [170], proof: [187], statement_kind: 2, public_inputs: [[204]], verifying_key_hash: [221], profile_hash: Array(32).fill(170) });
  assert.equal(JSON.stringify(proved.args).includes('private'), false);
});
