import { parseInteger } from './money.js';

export interface AuthorizationIdentity {
  networkId: string;
  coreAccount: string;
  assetAccount: string;
  owner: string;
  keyId: string;
  epoch: string;
  nonce: string;
}

const encoder = new TextEncoder();
const maximumU64 = (1n << 64n) - 1n;

function bytes(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff_ffff) throw new RangeError('Authorization field is too large');
  const result = new Uint8Array(value.length + 4);
  new DataView(result.buffer).setUint32(0, value.length, true);
  result.set(value, 4);
  return result;
}

function text(value: string): Uint8Array {
  if (!value) throw new RangeError('Authorization identity cannot be empty');
  return bytes(encoder.encode(value));
}

function u64(value: string): Uint8Array {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, parseInteger(value, maximumU64), true);
  return result;
}

async function digest(parts: Uint8Array[]): Promise<Uint8Array> {
  const input = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { input.set(part, offset); offset += part.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

/** Bytes to sign with the registered Ed25519 key, after inspecting the operation. */
export async function registeredAuthorizationMessage(identity: AuthorizationIdentity, operationMessage: Uint8Array): Promise<Uint8Array> {
  if (operationMessage.length !== 32) throw new RangeError('Operation message must be a SHA-256 digest');
  return digest([
    text('registered-authorization-v1'), text(identity.networkId), text(identity.coreAccount),
    text(identity.assetAccount), text(identity.owner), u64(identity.keyId), u64(identity.epoch),
    u64(identity.nonce), bytes(operationMessage),
  ]);
}

/** Hash the exact stored proposal and proof statement; do not reserialize its JSON. */
export async function originationOperationMessage(input: {
  proposalId: string;
  agreementDigest: Uint8Array;
  brokerSpendingVersion: string;
  statement: Uint8Array;
}): Promise<Uint8Array> {
  if (input.agreementDigest.length !== 32 || input.statement.length === 0) throw new RangeError('Invalid origination authorization fields');
  return digest([
    text('originate-authorization-v1'), u64(input.proposalId), bytes(input.agreementDigest),
    u64(input.brokerSpendingVersion), bytes(input.statement),
  ]);
}

export async function repaymentOperationMessage(input: {
  loanId: string;
  mode: 'Regular' | 'Full';
  loanVersion: string;
  spendingVersion: string;
  statement: Uint8Array;
}): Promise<Uint8Array> {
  if (input.statement.length === 0 || !['Regular', 'Full'].includes(input.mode)) throw new RangeError('Invalid repayment authorization fields');
  return digest([
    text('repay-authorization-v1'), u64(input.loanId), new Uint8Array([input.mode === 'Regular' ? 0 : 1]),
    u64(input.loanVersion), u64(input.spendingVersion), bytes(input.statement),
  ]);
}
