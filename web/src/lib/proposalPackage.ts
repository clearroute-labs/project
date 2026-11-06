import type { ProposalSummary } from './types'

export const PROPOSAL_PACKAGE_SCHEMA = 'confidential-lending/proposal/v1' as const

export interface EncryptedProposalPackage {
  schema: typeof PROPOSAL_PACKAGE_SCHEMA
  proposalId?: string
  borrowerId: string
  brokerId: string
  vaultId: string
  termsDigest: string
  encryptedAgreement: string
  encryptedPrincipal: string[]
  encryptedOwed: string[]
  encryptedPayment: string[]
  principalCommitment: string
  owedCommitment: string
  paymentCommitment: string
  auditorPublicKey: string
  brokerSignature: string
  borrowerSignature: string
  borrowerKeyId: string
  brokerKeyId: string
  auditorKeyId: string
  brokerAuthorizationEpoch: string
  borrowerAuthorizationEpoch: string
  expiresAt: number
}

export interface ProposalPackageInput extends Omit<EncryptedProposalPackage, 'schema'> {}

export function makeProposalPackage(input: ProposalPackageInput): EncryptedProposalPackage {
  const packageValue: EncryptedProposalPackage = { schema: PROPOSAL_PACKAGE_SCHEMA, ...input }
  validateProposalPackage(packageValue)
  return packageValue
}

export function validateProposalPackage(value: unknown): asserts value is EncryptedProposalPackage {
  if (!value || typeof value !== 'object') throw new Error('Proposal package must be a JSON object.')
  const candidate = value as Partial<EncryptedProposalPackage>
  if (candidate.schema !== PROPOSAL_PACKAGE_SCHEMA) throw new Error('Unsupported proposal package schema.')
  for (const field of ['borrowerId', 'brokerId', 'vaultId', 'termsDigest', 'encryptedAgreement', 'principalCommitment', 'owedCommitment', 'paymentCommitment', 'auditorPublicKey', 'borrowerKeyId', 'brokerKeyId', 'auditorKeyId', 'brokerAuthorizationEpoch', 'borrowerAuthorizationEpoch'] as const) {
    if (typeof candidate[field] !== 'string' || !candidate[field].trim()) throw new Error(`Proposal package field ${field} is missing.`)
  }
  if (!/^(?:[a-f\d]{2}){32}$/i.test(candidate.termsDigest!)) throw new Error('Proposal package termsDigest must be a 32-byte canonical digest.')
  if (typeof candidate.brokerSignature !== 'string') throw new Error('Proposal package brokerSignature must be a string when present.')
  if (candidate.borrowerSignature !== undefined && typeof candidate.borrowerSignature !== 'string') throw new Error('Proposal package borrowerSignature must be a string when present.')
  for (const field of ['encryptedPrincipal', 'encryptedOwed', 'encryptedPayment'] as const) {
    if (!Array.isArray(candidate[field]) || candidate[field].some((item) => typeof item !== 'string' || !item.trim())) throw new Error(`Proposal package field ${field} must contain ciphertext strings.`)
  }
  if (candidate.encryptedPrincipal?.length !== 5 || candidate.encryptedOwed?.length !== 3 || candidate.encryptedPayment?.length !== 3) throw new Error('Proposal package must contain five principal and three each of owed/payment ciphertext views.')
  for (const field of ['principalCommitment', 'owedCommitment', 'paymentCommitment', 'auditorPublicKey'] as const) {
    if (typeof candidate[field] !== 'string' || !/^(?:[a-f\d]{2})+$/i.test(candidate[field])) throw new Error(`Proposal package field ${field} must be canonical hex bytes.`)
  }
  if (candidate.proposalId !== undefined && (typeof candidate.proposalId !== 'string' || !/^\d+$/.test(candidate.proposalId))) throw new Error('Proposal package proposalId must be a decimal ID.')
  const expiresAt = candidate.expiresAt
  if (!Number.isSafeInteger(expiresAt) || (expiresAt as number) <= 0) throw new Error('Proposal package expiry is invalid.')
}

export function proposalPackageFromProposal(proposal: ProposalSummary): EncryptedProposalPackage {
  return makeProposalPackage({
    proposalId: proposal.proposalId,
    borrowerId: proposal.borrowerId,
    brokerId: proposal.brokerId,
    vaultId: proposal.vaultId,
    termsDigest: proposal.termsDigest,
    encryptedAgreement: proposal.encryptedAgreement,
    encryptedPrincipal: proposal.encryptedPrincipal || [],
    encryptedOwed: proposal.encryptedOwed || [],
    encryptedPayment: proposal.encryptedPayment || [],
    principalCommitment: proposal.principalCommitment || '',
    owedCommitment: proposal.owedCommitment || '',
    paymentCommitment: proposal.paymentCommitment || '',
    auditorPublicKey: proposal.loanAuditorPublicKey || '',
    brokerSignature: proposal.brokerSignature || '',
    borrowerSignature: proposal.borrowerSignature || '',
    borrowerKeyId: proposal.borrowerKeyId || '',
    brokerKeyId: proposal.brokerKeyId || '',
    auditorKeyId: proposal.encryptionKeyId,
    brokerAuthorizationEpoch: proposal.brokerAuthorizationEpoch || '0',
    borrowerAuthorizationEpoch: proposal.borrowerAuthorizationEpoch || '0',
    expiresAt: proposal.expiresAt,
  })
}

export function downloadProposalPackage(value: EncryptedProposalPackage): void {
  validateProposalPackage(value)
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `proposal-${value.proposalId || value.termsDigest.slice(0, 16)}.json`
    anchor.click()
  } finally {
    URL.revokeObjectURL(url)
  }
}

export async function readProposalPackage(file: File): Promise<EncryptedProposalPackage> {
  const text = await file.text()
  if (text.length > 2_000_000) throw new Error('Proposal package exceeds the browser size limit.')
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { throw new Error('Proposal package is not valid JSON.') }
  validateProposalPackage(parsed)
  return parsed
}
