import { describe, expect, it } from 'vitest'
import { addUnits, compareUnits, formatAmount, parseAmount, parseNonNegativeAmount, subtractUnits } from '../src/lib/money'

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

  it('uses bigint for comparison and checked arithmetic', () => {
    expect(compareUnits('9007199254740993', '9007199254740992')).toBe(1)
    expect(addUnits('9223372036854775800', '7')).toBe('9223372036854775807')
    expect(() => addUnits('9223372036854775807', '1')).toThrow(/protocol limit/)
    expect(subtractUnits('10', '4')).toBe('6')
    expect(() => subtractUnits('4', '10')).toThrow(/available balance/)
  })
})
