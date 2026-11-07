import assert from 'node:assert/strict';
import { test } from 'node:test';
import { originationOperationMessage, registeredAuthorizationMessage, repaymentOperationMessage } from '../src/index.js';

const encoder = new TextEncoder();
const identity = {
  networkId: 'sandbox', coreAccount: 'core.test.near', assetAccount: 'token.test.near',
  owner: 'borrower.test.near', keyId: '7', epoch: '3', nonce: '2',
};
const origination = {
  proposalId: '17', agreementDigest: Uint8Array.from({ length: 32 }, (_, index) => index),
  brokerSpendingVersion: '4', statement: encoder.encode('authoritative-origination-statement'),
};

test('authorization messages match canonical Borsh/SHA-256 vectors', async () => {
  const operation = await originationOperationMessage(origination);
  assert.equal(Buffer.from(operation).toString('hex'), 'efcaf24aff15e35469776a5fec3f58c1790e4ca6fa16bfaefea0f7d96325dadf');
  assert.equal(Buffer.from(await registeredAuthorizationMessage(identity, operation)).toString('hex'),
    '18338af51acce2156f81535c61ff1779d2546c55846792f918f09d89adb2be26');
  const repayment = await repaymentOperationMessage({ loanId: '17', mode: 'Full', loanVersion: '4', spendingVersion: '5', statement: encoder.encode('authoritative-repayment-statement') });
  assert.equal(Buffer.from(repayment).toString('hex'), 'acd1e0cf483cc96b86f31c00bca9b72e8df576142cd4069cd8556daebf13da33');
});

test('authorization binds deployment, authority, epoch, nonce and exact operation', async () => {
  const operation = await originationOperationMessage(origination);
  const signed = await registeredAuthorizationMessage(identity, operation);
  for (const field of Object.keys(identity) as Array<keyof typeof identity>) {
    const changed = { ...identity, [field]: ['keyId', 'epoch', 'nonce'].includes(field) ? '9' : `${identity[field]}-changed` };
    assert.notDeepEqual(await registeredAuthorizationMessage(changed, operation), signed, field);
  }
  for (const changed of [
    { ...origination, proposalId: '18' }, { ...origination, brokerSpendingVersion: '5' },
    { ...origination, agreementDigest: new Uint8Array(32) }, { ...origination, statement: encoder.encode('different statement') },
  ]) assert.notDeepEqual(await registeredAuthorizationMessage(identity, await originationOperationMessage(changed)), signed);
});

test('ambiguous or overflowing authorization identifiers are rejected', async () => {
  const operation = await originationOperationMessage(origination);
  for (const nonce of ['01', '-1', '1e2', '18446744073709551616']) {
    await assert.rejects(registeredAuthorizationMessage({ ...identity, nonce }, operation), RangeError);
  }
  await assert.rejects(registeredAuthorizationMessage(identity, new Uint8Array(31)), RangeError);
  await assert.rejects(originationOperationMessage({ ...origination, agreementDigest: new Uint8Array(31) }), RangeError);
});
