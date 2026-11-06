import { describe, expect, it } from 'vitest'
import { toProtocolError } from '../src/lib/actionState'
import { ProtocolError } from '../src/lib/types'

describe('action errors', () => {
  it('preserves protocol categories without exposing witnesses', () => {
    const error = new ProtocolError({ category: 'BAD_PROOF', message: 'Proof rejected.' })
    expect(toProtocolError(error)).toBe(error)
    expect(toProtocolError(new Error('network down')).details.category).toBe('UNKNOWN')
    expect(toProtocolError('anything').details.message).toBe('The operation failed.')
  })
})
