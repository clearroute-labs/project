export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Arguments = Record<string, Json>;

export class RpcError extends Error {
  constructor(readonly kind: 'network' | 'http' | 'rpc' | 'encoding', message: string, readonly code?: number) {
    super(message);
    this.name = 'RpcError';
  }
}

export class TransactionPendingError extends Error {
  constructor(readonly transactionHash: string, readonly signerId: string) {
    super('Transaction outcome is not yet known. Check its status before submitting again.');
    this.name = 'TransactionPendingError';
  }
}

export interface ReceiptOutcome {
  id: string;
  outcome: { executor_id: string; logs: string[]; status: Record<string, unknown> };
}

export interface FinalOutcome {
  status: { SuccessValue: string } | { Failure: unknown };
  transaction: { hash: string; signer_id: string; receiver_id: string };
  transaction_outcome: ReceiptOutcome;
  receipts_outcome: ReceiptOutcome[];
  final_execution_status?: string;
}

export interface RpcOptions {
  timeoutMs?: number;
  fetch?: typeof fetch;
  allowInsecureLocalhost?: boolean;
}

export function assertAccountId(accountId: string): void {
  if (accountId.length < 2 || accountId.length > 64 || !/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/.test(accountId)) {
    throw new TypeError('Invalid NEAR account ID');
  }
}

function base64Encode(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export function decodeBase64(value: string): Uint8Array {
  try { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
  catch { throw new RpcError('encoding', 'Invalid base64 RPC response'); }
}

export class NearRpc {
  readonly url: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  #requestId = 0;

  constructor(url: string, options: RpcOptions = {}) {
    const parsed = new URL(url);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !(options.allowInsecureLocalhost && local && parsed.protocol === 'http:')) {
      throw new TypeError('RPC requires HTTPS (HTTP is supported only for an explicitly enabled local sandbox)');
    }
    if (parsed.username || parsed.password) throw new TypeError('Do not put RPC credentials in the URL');
    this.url = parsed.href;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = options.timeoutMs ?? 20_000;
  }

  async request<T>(method: string, params: unknown, signal?: AbortSignal): Promise<T> {
    const timeout = AbortSignal.timeout(this.#timeoutMs);
    let response: Response;
    const id = ++this.#requestId;
    try {
      response = await this.#fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
        credentials: 'omit',
        redirect: 'error',
      });
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      throw new RpcError('network', error instanceof DOMException && error.name === 'TimeoutError' ? 'RPC request timed out' : 'RPC unavailable');
    }
    if (!response.ok) throw new RpcError('http', `RPC returned HTTP ${response.status}`, response.status);
    let body: { id?: unknown; result?: T; error?: { code?: number; message?: string } };
    try { body = await response.json() as typeof body; }
    catch { throw new RpcError('encoding', 'RPC returned invalid JSON'); }
    if (body.id !== id) throw new RpcError('encoding', 'RPC response ID mismatch');
    if (body.error) throw new RpcError('rpc', body.error.message ?? 'RPC rejected the request', body.error.code);
    if (!Object.hasOwn(body, 'result')) throw new RpcError('encoding', 'RPC response has no result');
    return body.result as T;
  }

  async view<T>(accountId: string, method: string, args: Arguments = {}, signal?: AbortSignal): Promise<T> {
    assertAccountId(accountId);
    const result = await this.request<{ result: number[] }>('query', {
      request_type: 'call_function', finality: 'final', account_id: accountId,
      method_name: method,
      args_base64: base64Encode(new TextEncoder().encode(JSON.stringify(args))),
    }, signal);
    if (!Array.isArray(result.result) || result.result.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
      throw new RpcError('encoding', 'Malformed contract view response');
    }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(result.result))) as T; }
    catch { throw new RpcError('encoding', 'Contract view returned invalid JSON'); }
  }

  async transactionStatus(hash: string, signerId: string, signal?: AbortSignal): Promise<FinalOutcome> {
    assertAccountId(signerId);
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(hash)) throw new TypeError('Invalid transaction hash');
    return this.request<FinalOutcome>('tx', { tx_hash: hash, sender_account_id: signerId, wait_until: 'FINAL' }, signal);
  }

  async waitForFinalOutcome(hash: string, signerId: string, options: { signal?: AbortSignal; attempts?: number; intervalMs?: number } = {}): Promise<FinalOutcome> {
    for (let attempt = 0; attempt < (options.attempts ?? 20); attempt++) {
      options.signal?.throwIfAborted();
      try {
        const result = await this.transactionStatus(hash, signerId, options.signal);
        if (result.final_execution_status === 'FINAL' && ('SuccessValue' in result.status || 'Failure' in result.status)) return result;
      } catch (error) {
        if (!(error instanceof RpcError)) throw error;
      }
      if (attempt + 1 < (options.attempts ?? 20)) await abortableDelay(options.intervalMs ?? 1_500, options.signal);
    }
    throw new TransactionPendingError(hash, signerId);
  }
}

export function abortableDelay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const abort = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve(); }, milliseconds);
    signal?.addEventListener('abort', abort, { once: true });
  });
}
