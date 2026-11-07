import { ProtocolError } from './types'

export const MAX_ASSET_UNITS = (2n ** 63n) - 1n
export const MAX_U128_UNITS = (1n << 128n) - 1n

export function parseAmount(input: string, decimals: number, maxUnits = MAX_ASSET_UNITS): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 38) {
    throw new ProtocolError({ category: 'INVALID_ENCODING', message: 'Asset decimals are not supported.' })
  }

  const value = input.trim()
  if (!/^\d+(?:\.\d+)?$/.test(value)) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Enter a non-negative decimal amount.' })
  }

  const [whole, fraction = ''] = value.split('.')
  if (fraction.length > decimals) {
    throw new ProtocolError({
      category: 'INVALID_AMOUNT',
      message: `This asset supports at most ${decimals} decimal places.`,
    })
  }

  const scale = 10n ** BigInt(decimals)
  const units = BigInt(whole) * scale + BigInt(fraction.padEnd(decimals, '0') || '0')
  if (units <= 0n) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Amount must be greater than zero.' })
  }
  if (units > maxUnits) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Amount exceeds the protocol limit.' })
  }
  return units.toString(10)
}

/** Native NEAR deposits use u128 yoctoNEAR, independently of the private asset limit. */
export function parseNearAmount(input: string): string {
  return parseAmount(input, 24, MAX_U128_UNITS)
}

export function parseNonNegativeAmount(input: string, decimals: number, maxUnits = MAX_ASSET_UNITS): string {
  const value = input.trim()
  if (!/^\d+(?:\.\d+)?$/.test(value)) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Enter a non-negative decimal amount.' })
  }
  const [whole, fraction = ''] = value.split('.')
  if (fraction.length > decimals) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: `Use at most ${decimals} decimal places.` })
  }
  const units = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0') || '0')
  if (units > maxUnits) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Amount exceeds the protocol limit.' })
  }
  return units.toString(10)
}

/** Public asset redemption burns ceil(assets * supply / priced NAV) shares. */
export function sharesForAssets(assets: string, supply: string, pricedNav: string): string {
  const amount = BigInt(assets), totalShares = BigInt(supply), nav = BigInt(pricedNav)
  if (amount <= 0n || totalShares <= 0n || nav <= 0n) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Asset redemption requires a positive amount, share supply and net asset value.' })
  }
  const shares = (amount * totalShares + nav - 1n) / nav
  if (shares > MAX_U128_UNITS) throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'Share quantity exceeds the protocol limit.' })
  return shares.toString()
}

export function formatAmount(units: string | bigint | undefined, decimals: number, placeholder = '—'): string {
  if (units === undefined || units === null || units === '') return placeholder
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 38) return placeholder
  let value: bigint
  try {
    value = typeof units === 'bigint' ? units : BigInt(units)
  } catch {
    return placeholder
  }
  if (value < 0n) return placeholder
  const scale = 10n ** BigInt(decimals)
  const whole = value / scale
  const fraction = value % scale
  const grouped = whole.toString(10).replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  if (decimals === 0 || fraction === 0n) return grouped
  const fractionText = fraction.toString(10).padStart(decimals, '0').replace(/0+$/, '')
  return `${grouped}.${fractionText}`
}

export function compareUnits(left: string, right: string): -1 | 0 | 1 {
  const a = BigInt(left)
  const b = BigInt(right)
  return a < b ? -1 : a > b ? 1 : 0
}

export function addUnits(left: string, right: string): string {
  const result = BigInt(left) + BigInt(right)
  if (result < 0n || result > MAX_ASSET_UNITS) {
    throw new ProtocolError({ category: 'INVALID_AMOUNT', message: 'The amount exceeds the protocol limit.' })
  }
  return result.toString(10)
}

export function subtractUnits(left: string, right: string): string {
  const result = BigInt(left) - BigInt(right)
  if (result < 0n) {
    throw new ProtocolError({ category: 'INSUFFICIENT_PUBLIC_FUNDS', message: 'The amount exceeds the available balance.' })
  }
  return result.toString(10)
}

export function isPositiveUnits(value: string): boolean {
  try {
    return BigInt(value) > 0n
  } catch {
    return false
  }
}

export function unixSecondsNow(): number {
  return Math.floor(Date.now() / 1000)
}

/** Generate a Core u64 operation ID without Number precision loss. */
export function randomUint64Decimal(): string {
  const words = new Uint32Array(2)
  globalThis.crypto.getRandomValues(words)
  const value = (BigInt(words[0]) << 32n) | BigInt(words[1])
  return (value === 0n ? 1n : value).toString(10)
}
