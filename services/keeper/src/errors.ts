import { RpcError } from '@confidential-lending/client';

export type KeeperFailure = 'stale_proof' | 'frozen' | 'unauthorized' | 'accounting_pending' | 'unavailable_liquidity' | 'missing_witness' | 'insufficient_spendable_funds' | 'proof_failed' | 'rpc_unavailable' | 'preparation_failed';

/** Map only stable error markers. Never forward an RPC/prover error payload to logs. */
export function classifyKeeperError(error: unknown): KeeperFailure {
  const text = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  if (/ERR_STALE_STATE|ERR_STALE_PROOF/.test(text)) return 'stale_proof';
  if (/ERR_ASSET_FROZEN|ERR_ACCOUNT_FROZEN|ERR_FROZEN/.test(text)) return 'frozen';
  if (/ERR_UNAUTHORIZED|ERR_EXPIRED|ERR_NO_PERMISSION/.test(text)) return 'unauthorized';
  if (/ERR_ACCOUNTING_PENDING|Settlement requires a current reconciliation checkpoint/.test(text)) return 'accounting_pending';
  if (/ERR_INSUFFICIENT_LIQUIDITY/.test(text)) return 'unavailable_liquidity';
  if (text === 'Wallet key is unavailable') return 'missing_witness';
  if (/Insufficient private spending balance|Invalid conversion amount/.test(text)) return 'insufficient_spendable_funds';
  if (/ERR_BAD_PROOF|Native crypto operation failed/.test(text)) return 'proof_failed';
  return error instanceof RpcError ? 'rpc_unavailable' : 'preparation_failed';
}
