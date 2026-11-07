import { describe, expect, it } from 'vitest'
import { makeBrokerZeroProofPackage, validateBrokerZeroProofPackage } from '../src/lib/brokerZeroProof'
import type { PreparedProof } from '../src/lib/types'

const profileHash = 'a'.repeat(64)
const artifactHash = 'b'.repeat(64)

function proofFor(brokerId: string): PreparedProof {
  return {
    context: 'aa',
    proof: 'bb',
    statement: JSON.stringify({ zero_balance: { broker_id: brokerId } }),
    publicInputs: ['cc'],
    profileHash,
    artifactHash,
    statementDigest: 'dd'.repeat(32),
    statementKind: 7,
    verifyingKeyHash: 'ee'.repeat(32),
    operationArgs: {
      zero_proof: {
        broker_id: brokerId,
        combined_proof: {
          statement: '{}',
          context: 'aa',
          proof: 'bb',
          public_inputs: [],
          profile_hash: profileHash,
        },
      },
    },
  }
}

describe('broker zero-state proof exchange', () => {
  it('binds a downloadable proof to its broker, vault and artifact profile', () => {
    const value = makeBrokerZeroProofPackage({ brokerId: '2', vaultId: '9', profileHash, artifactHash, proof: proofFor('2') })
    expect(value.schema).toBe('confidential-lending/broker-zero-proof/v1')
    expect(value.brokerId).toBe('2')
    expect(value.vaultId).toBe('9')
    expect(JSON.stringify(value)).not.toContain('privateKey')
    expect(() => makeBrokerZeroProofPackage({ ...value, brokerId: '3' })).toThrow(/does not match/)
  })

  it('rejects proof packages with unsupported arguments or mismatched hashes', () => {
    const value = makeBrokerZeroProofPackage({ brokerId: '2', vaultId: '9', profileHash, artifactHash, proof: proofFor('2') })
    expect(() => validateBrokerZeroProofPackage({ ...value, profileHash: 'f'.repeat(64) })).toThrow(/profile does not match/)
    expect(() => validateBrokerZeroProofPackage({ ...value, proof: { ...value.proof, operationArgs: { plaintext: '100' } } })).toThrow(/unsupported operation arguments/)
  })
})
