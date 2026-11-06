import { assertAccountId, type Arguments, type FinalOutcome, NearRpc } from './rpc.js';

export interface FunctionCallAction {
  type: 'FunctionCall';
  params: { methodName: string; args: Arguments; gas: string; deposit: string };
}

export interface WalletTransaction {
  receiverId: string;
  actions: FunctionCallAction[];
}

export interface WalletAdapter {
  accountId: string;
  signAndSendTransaction(transaction: WalletTransaction): Promise<{ transaction: { hash: string; signer_id: string } } | void>;
}

export interface Deployment {
  networkId: string;
  coreAccountId: string;
  tokenAccountId: string;
  rpcUrl: string;
  profileHash: string;
  assetDecimals: number;
  assetSymbol: string;
}

export class TransactionFailure extends Error {
  constructor(readonly outcome: FinalOutcome) {
    super('The contract rejected this transaction. No success has been confirmed.');
    this.name = 'TransactionFailure';
  }
}

export class ContractClient {
  constructor(readonly rpc: NearRpc, readonly deployment: Deployment) {
    assertAccountId(deployment.coreAccountId);
    assertAccountId(deployment.tokenAccountId);
    if (!/^[a-f0-9]{64}$/.test(deployment.profileHash)) throw new TypeError('Invalid crypto profile hash');
    if (!Number.isInteger(deployment.assetDecimals) || deployment.assetDecimals < 0 || deployment.assetDecimals > 38) throw new TypeError('Invalid asset decimals');
  }

  view<T>(method: string, args: Arguments = {}, signal?: AbortSignal): Promise<T> {
    return this.rpc.view<T>(this.deployment.coreAccountId, method, args, signal);
  }

  async call(wallet: WalletAdapter, method: string, args: Arguments, options: { deposit?: string; gas?: string; signal?: AbortSignal; receiverId?: string } = {}): Promise<FinalOutcome | undefined> {
    assertAccountId(wallet.accountId);
    const receiverId = options.receiverId ?? this.deployment.coreAccountId;
    assertAccountId(receiverId);
    const gas = options.gas ?? '250000000000000';
    const deposit = options.deposit ?? '0';
    if (!/^(0|[1-9]\d*)$/.test(deposit) || !/^[1-9]\d*$/.test(gas) || BigInt(gas) > 300_000_000_000_000n) throw new RangeError('Invalid call gas or deposit');
    options.signal?.throwIfAborted();
    const sent = await wallet.signAndSendTransaction({ receiverId, actions: [{ type: 'FunctionCall', params: { methodName: method, args, gas, deposit } }] });
    // Redirect wallets return no result. The caller resumes from wallet-provided hashes after redirect.
    if (!sent) return undefined;
    const result = await this.rpc.waitForFinalOutcome(sent.transaction.hash, sent.transaction.signer_id,
      options.signal ? { signal: options.signal } : {});
    if ('Failure' in result.status) throw new TransactionFailure(result);
    return result;
  }
}

export interface ProtocolEvent {
  receiptId: string;
  logIndex: number;
  standard: string;
  version: string;
  event: string;
  data: unknown;
}

export function extractEvents(outcome: FinalOutcome, coreAccountId: string): ProtocolEvent[] {
  const events: ProtocolEvent[] = [];
  for (const receipt of [outcome.transaction_outcome, ...outcome.receipts_outcome]) {
    if (receipt.outcome.executor_id !== coreAccountId || 'Failure' in receipt.outcome.status) continue;
    receipt.outcome.logs.forEach((log, logIndex) => {
      if (!log.startsWith('EVENT_JSON:')) return;
      try {
        const event = JSON.parse(log.slice('EVENT_JSON:'.length)) as Record<string, unknown>;
        if (typeof event.standard === 'string' && typeof event.version === 'string' && typeof event.event === 'string') {
          events.push({ receiptId: receipt.id, logIndex, standard: event.standard, version: event.version, event: event.event, data: event.data });
        }
      } catch { /* Foreign or malformed event logs are not protocol state. */ }
    });
  }
  return events;
}
