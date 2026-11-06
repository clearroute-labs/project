import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MAX_ASSET_UNITS, formatUnits, mulDivCeil, mulDivFloor, parseInteger, parseUnits } from '../src/index.js';

test('asset decimals round-trip without JavaScript number precision loss', () => {
  assert.equal(parseUnits('9223372036854.775807', 6), MAX_ASSET_UNITS);
  assert.equal(formatUnits(MAX_ASSET_UNITS, 6), '9223372036854.775807');
  assert.equal(formatUnits(parseUnits('0.000001', 6), 6), '0.000001');
  assert.equal(formatUnits(1_000_000n, 6), '1');
});

test('ambiguous, signed, exponent and overflowing amounts are rejected', () => {
  for (const value of ['-1', '+1', '01', '1e6', '.5', '1.', '0.0000001', '9223372036854.775808', 'NaN']) {
    assert.throws(() => parseUnits(value, 6), RangeError);
  }
  assert.throws(() => parseInteger('01'));
  assert.throws(() => parseInteger('18446744073709551616', (1n << 64n) - 1n));
});

test('share rounding protects the vault at large precision', () => {
  assert.equal(mulDivFloor(10n, 7n, 3n), 23n);
  assert.equal(mulDivCeil(10n, 7n, 3n), 24n);
  const max = (1n << 128n) - 1n;
  assert.equal(mulDivFloor(max, max, max), max);
  assert.throws(() => mulDivFloor(1n, 1n, 0n));
});
