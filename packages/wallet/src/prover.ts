import type { RuntimeConfiguration } from './runtime.js';

interface WorkerPort {
  postMessage(value: unknown): void;
  addEventListener(type: 'message' | 'error' | 'messageerror', listener: (event: MessageEvent) => void): void;
  terminate(): void;
}

export class CryptoOperationError extends Error {
  constructor(readonly code: 'ARTIFACT_VALIDATION_FAILED' | 'CRYPTO_OPERATION_FAILED' | 'WORKER_CLOSED' | 'OPERATION_ABORTED') {
    super(code);
    this.name = 'CryptoOperationError';
  }
}

interface Pending {
  resolve(value: unknown): void;
  reject(error: Error): void;
  dispose(): void;
}

/** One worker owns proving memory. Closing the wallet terminates that worker. */
export class BrowserProver {
  #nextId = 0;
  #closed = false;
  readonly #pending = new Map<number, Pending>();
  readonly ready: Promise<void>;

  constructor(readonly worker: WorkerPort, configuration: RuntimeConfiguration) {
    worker.addEventListener('message', event => this.receive(event.data));
    worker.addEventListener('error', () => this.close());
    worker.addEventListener('messageerror', () => this.close());
    this.ready = this.request('initialize', undefined, { configuration }).then(() => {});
  }

  async execute<T>(method: string, params: unknown, options: { artifactName?: string; signal?: AbortSignal; timeoutMs?: number } = {}): Promise<T> {
    options.signal?.throwIfAborted();
    await this.ready;
    return this.request(method, params, options) as Promise<T>;
  }

  close(code: 'WORKER_CLOSED' | 'OPERATION_ABORTED' = 'WORKER_CLOSED'): void {
    if (this.#closed) return;
    this.#closed = true;
    this.worker.terminate();
    for (const pending of this.#pending.values()) { pending.dispose(); pending.reject(new CryptoOperationError(code)); }
    this.#pending.clear();
  }

  private request(method: string, params: unknown, options: { artifactName?: string; configuration?: RuntimeConfiguration; signal?: AbortSignal; timeoutMs?: number }): Promise<unknown> {
    if (this.#closed) return Promise.reject(new CryptoOperationError('WORKER_CLOSED'));
    options.signal?.throwIfAborted();
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const abort = () => this.close('OPERATION_ABORTED');
      const timer = setTimeout(abort, options.timeoutMs ?? 10 * 60_000);
      options.signal?.addEventListener('abort', abort, { once: true });
      const dispose = () => { clearTimeout(timer); options.signal?.removeEventListener('abort', abort); };
      this.#pending.set(id, { resolve, reject, dispose });
      try { this.worker.postMessage({ id, method, params, ...(options.configuration ? { configuration: options.configuration } : {}), ...(options.artifactName ? { artifactName: options.artifactName } : {}) }); }
      catch { this.close(); }
    });
  }

  private receive(value: unknown): void {
    if (!value || typeof value !== 'object') return;
    const response = value as { id?: unknown; ok?: unknown; value?: unknown; code?: unknown };
    if (typeof response.id !== 'number') return;
    const pending = this.#pending.get(response.id);
    if (!pending) return;
    this.#pending.delete(response.id);
    pending.dispose();
    if (response.ok === true) pending.resolve(response.value);
    else pending.reject(new CryptoOperationError(response.code === 'ARTIFACT_VALIDATION_FAILED' ? response.code : 'CRYPTO_OPERATION_FAILED'));
  }
}
