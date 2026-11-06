export const MAX_ASSET_UNITS = (1n << 63n) - 1n;
const DECIMAL = /^(0|[1-9]\d*)(?:\.(\d+))?$/;

export function parseUnits(value: string, decimals: number, maximum = MAX_ASSET_UNITS): bigint {
  if (!Number.isSafeInteger(decimals) || decimals < 0 || decimals > 38) {
    throw new RangeError('Unsupported asset precision');
  }
  const match = DECIMAL.exec(value.trim());
  if (!match || (match[2]?.length ?? 0) > decimals) {
    throw new RangeError(`Enter a positive decimal with at most ${decimals} decimal places`);
  }
  const result = BigInt(match[1]!) * 10n ** BigInt(decimals)
    + BigInt((match[2] ?? '').padEnd(decimals, '0') || '0');
  if (result > maximum) throw new RangeError('Amount exceeds the protocol limit');
  return result;
}

export function formatUnits(value: bigint | string, decimals: number): string {
  if (!Number.isSafeInteger(decimals) || decimals < 0 || decimals > 38) {
    throw new RangeError('Unsupported asset precision');
  }
  const units = typeof value === 'bigint' ? value : parseInteger(value);
  if (units < 0n) throw new RangeError('Negative asset amount');
  if (!decimals) return units.toString();
  const digits = units.toString().padStart(decimals + 1, '0');
  const fraction = digits.slice(-decimals).replace(/0+$/, '');
  return `${digits.slice(0, -decimals)}${fraction ? `.${fraction}` : ''}`;
}

export function parseInteger(value: string, maximum?: bigint): bigint {
  if (!/^(0|[1-9]\d*)$/.test(value)) throw new RangeError('Expected a canonical unsigned integer');
  const result = BigInt(value);
  if (maximum !== undefined && result > maximum) throw new RangeError('Integer exceeds its limit');
  return result;
}

export function mulDivFloor(a: bigint, b: bigint, denominator: bigint): bigint {
  if (a < 0n || b < 0n || denominator <= 0n) throw new RangeError('Invalid share pricing inputs');
  return a * b / denominator;
}

export function mulDivCeil(a: bigint, b: bigint, denominator: bigint): bigint {
  if (a < 0n || b < 0n || denominator <= 0n) throw new RangeError('Invalid share pricing inputs');
  return (a * b + denominator - 1n) / denominator;
}
