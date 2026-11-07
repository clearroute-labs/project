import { describe, expect, it } from 'vitest'
import { MAX_U128_UNITS, addUnits, compareUnits, formatAmount, parseAmount, parseNearAmount, parseNonNegativeAmount, randomUint64Decimal, sharesForAssets, subtractUnits } from '../src/lib/money'

describe('exact money helpers', () => {
  it('converts decimal strings without floating point', () => {
    expect(parseAmount('1.2300', 6)).toBe('1230000')
    expect(parseAmount('0.000001', 6)).toBe('1')
    expect(formatAmount('1230000', 6)).toBe('1.23')
  })

  it('rejects fractional precision and zero action amounts', () => {
    expect(() => parseAmount('1.0000001', 6)).toThrow(/decimal places/)
    expect(() => parseAmount('0', 6)).toThrow(/greater than zero/)
    expect(parseNonNegativeAmount('0', 6)).toBe('0')
  })

  it('accepts native NEAR storage deposits with u128 precision without widening private assets', () => {
    expect(parseNearAmount('0.1')).toBe('100000000000000000000000')
    expect(parseNearAmount('0.000000000000000000000001')).toBe('1')
    expect(parseNearAmount('340282366920938.463463374607431768211455')).toBe(((1n << 128n) - 1n).toString())
    expect(() => parseNearAmount('340282366920938.463463374607431768211456')).toThrow(/protocol limit/)
    expect(() => parseNearAmount('0')).toThrow(/greater than zero/)
    expect(() => parseAmount('9223372036854775808', 0)).toThrow(/protocol limit/)
  })

  it('allows full-width public share quantities and still rejects u128 overflow', () => {
    expect(parseAmount('10000000000000', 6, MAX_U128_UNITS)).toBe('10000000000000000000')
    expect(parseNonNegativeAmount('0', 6, MAX_U128_UNITS)).toBe('0')
    expect(parseAmount(MAX_U128_UNITS.toString(), 0, MAX_U128_UNITS)).toBe(MAX_U128_UNITS.toString())
    expect(() => parseAmount((MAX_U128_UNITS + 1n).toString(), 0, MAX_U128_UNITS)).toThrow(/protocol limit/)
  })

  it('calculates actual asset-redemption shares independently of the maximum-spend guard', () => {
    expect(sharesForAssets('34', '3', '100')).toBe('2')
    expect(sharesForAssets('100', '3', '100')).toBe('3')
    expect(sharesForAssets('50', '100', '80')).toBe('63')
    expect(sharesForAssets('50', '100', '100')).toBe('50')
    expect(sharesForAssets('9223372036854775807', MAX_U128_UNITS.toString(), '9223372036854775807')).toBe(MAX_U128_UNITS.toString())
    expect(() => sharesForAssets('1', '3', '0')).toThrow(/net asset value/)
  })

  it('uses bigint for comparison and checked arithmetic', () => {
    expect(compareUnits('9007199254740993', '9007199254740992')).toBe(1)
    expect(addUnits('9223372036854775800', '7')).toBe('9223372036854775807')
    expect(() => addUnits('9223372036854775807', '1')).toThrow(/protocol limit/)
    expect(subtractUnits('10', '4')).toBe('6')
    expect(() => subtractUnits('4', '10')).toThrow(/available balance/)
  })

  it('creates decimal u64 IDs without lossy Number conversion', () => {
    const id = randomUint64Decimal()
    expect(id).toMatch(/^\d+$/)
    expect(BigInt(id)).toBeGreaterThan(0n)
    expect(BigInt(id)).toBeLessThanOrEqual((2n ** 64n) - 1n)
  })
})
