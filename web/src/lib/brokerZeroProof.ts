import type { PreparedProof } from './types'

export const BROKER_ZERO_PROOF_SCHEMA = 'confidential-lending/broker-zero-proof/v1' as const

export interface BrokerZeroProofPackage {
  schema: typeof BROKER_ZERO_PROOF_SCHEMA
  brokerId: string
  vaultId: string
  profileHash: string
  artifactHash: string
  proof: PreparedProof
}

function decimal(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) throw new Error(`${field} must be a canonical decimal string.`)
  return value
}

function hex(value: unknown, field: string, allowEmpty = false): string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length % 2 !== 0 || (value.length > 0 && !/^[a-f\d]+$/i.test(value))) throw new Error(`${field} must be canonical hexadecimal bytes.`)
  return value.toLowerCase()
}

function validateProof(value: unknown): asserts value is PreparedProof {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Broker zero proof is missing its proof envelope.')
  const proof = value as Partial<PreparedProof>
  hex(proof.context, 'Proof context')
  hex(proof.proof, 'Proof bytes')
  if (typeof proof.statement !== 'string' || !proof.statement.trim()) throw new Error('Broker zero proof statement is missing.')
  try { JSON.parse(proof.statement) } catch { throw new Error('Broker zero proof statement is not valid JSON.') }
  if (!Array.isArray(proof.publicInputs) || proof.publicInputs.some((item) => { try { hex(item, 'Public input'); return false } catch { return true } })) throw new Error('Broker zero proof public inputs are invalid.')
  hex(proof.profileHash, 'Proof profile hash')
  hex(proof.artifactHash, 'Proof artifact hash', true)
  hex(proof.statementDigest, 'Proof statement digest')
  if (proof.statementKind !== undefined && (!Number.isInteger(proof.statementKind) || proof.statementKind < 0)) throw new Error('Broker zero proof statement kind is invalid.')
  if (proof.verifyingKeyHash !== undefined) hex(proof.verifyingKeyHash, 'Proof verifying-key hash')
  if (!proof.operationArgs || typeof proof.operationArgs !== 'object' || Array.isArray(proof.operationArgs)) throw new Error('Broker zero proof operation arguments are missing.')
  const args = proof.operationArgs as Record<string, unknown>
  if (Object.keys(args).some((key) => key !== 'zero_proof')) throw new Error('Broker zero proof contains unsupported operation arguments.')
  const zero = args.zero_proof
  if (!zero || typeof zero !== 'object' || Array.isArray(zero)) throw new Error('Broker zero proof closure arguments are missing.')
  const zeroArgs = zero as Record<string, unknown>
  decimal(zeroArgs.broker_id, 'Broker ID')
  const nested = zeroArgs.combined_proof || zeroArgs.spending_proof
  if (!nested || typeof nested !== 'object' || Array.isArray(nested)) throw new Error('Broker zero proof must include a combined or legacy spending proof.')
}

export function makeBrokerZeroProofPackage(input: Omit<BrokerZeroProofPackage, 'schema'>): BrokerZeroProofPackage {
  const brokerId = decimal(input.brokerId, 'Broker ID')
  const vaultId = decimal(input.vaultId, 'Vault ID')
  const profileHash = hex(input.profileHash, 'Profile hash')
  const artifactHash = hex(input.artifactHash, 'Artifact hash', true)
  validateProof(input.proof)
  const zero = input.proof.operationArgs?.zero_proof
  if (!zero || typeof zero !== 'object' || Array.isArray(zero) || decimal((zero as Record<string, unknown>).broker_id, 'Broker ID') !== brokerId) throw new Error('Broker zero proof does not match its package broker ID.')
  if (!/^(?:[a-f\d]{64})$/i.test(profileHash)) throw new Error('Profile hash must be 32 bytes.')
  if (artifactHash && !/^(?:[a-f\d]{64})$/i.test(artifactHash)) throw new Error('Artifact hash must be 32 bytes.')
  if (input.proof.profileHash.toLowerCase() !== profileHash) throw new Error('Broker zero proof profile does not match its package.')
  if (artifactHash && input.proof.artifactHash.toLowerCase() !== artifactHash) throw new Error('Broker zero proof artifact does not match its package.')
  return { schema: BROKER_ZERO_PROOF_SCHEMA, brokerId, vaultId, profileHash, artifactHash, proof: input.proof }
}

export function validateBrokerZeroProofPackage(value: unknown): asserts value is BrokerZeroProofPackage {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Broker zero proof package must be a JSON object.')
  const candidate = value as Partial<BrokerZeroProofPackage>
  if (candidate.schema !== BROKER_ZERO_PROOF_SCHEMA) throw new Error('Unsupported broker zero proof package schema.')
  if (typeof candidate.brokerId !== 'string' || typeof candidate.vaultId !== 'string' || typeof candidate.profileHash !== 'string' || typeof candidate.artifactHash !== 'string') throw new Error('Broker zero proof package metadata is incomplete.')
  makeBrokerZeroProofPackage({ brokerId: candidate.brokerId, vaultId: candidate.vaultId, profileHash: candidate.profileHash, artifactHash: candidate.artifactHash, proof: candidate.proof as PreparedProof })
}

export function downloadBrokerZeroProof(value: BrokerZeroProofPackage): void {
  validateBrokerZeroProofPackage(value)
  const blob = new Blob([JSON.stringify(value)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `broker-zero-proof-${value.brokerId}.json`
    anchor.click()
  } finally {
    URL.revokeObjectURL(url)
  }
}

export async function readBrokerZeroProof(file: File): Promise<BrokerZeroProofPackage> {
  const text = await file.text()
  if (text.length > 512_000) throw new Error('Broker zero proof package exceeds the browser size limit.')
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { throw new Error('Broker zero proof package is not valid JSON.') }
  validateBrokerZeroProofPackage(parsed)
  return parsed
}
