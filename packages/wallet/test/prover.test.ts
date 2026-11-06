import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserProver, CryptoOperationError } from '../src/prover.js';
import type { RuntimeConfiguration } from '../src/runtime.js';

const configuration = { baseUrl: 'https://example.org/artifacts/', manifest: {}, expected: {} } as RuntimeConfiguration;

class Port {
  readonly listeners = new Map<string, (event: MessageEvent) => void>();
  readonly requests: Array<{ id: number; method: string }> = [];
  terminated = false;
  addEventListener(type: string, listener: (event: MessageEvent) => void): void { this.listeners.set(type, listener); }
  postMessage(value: unknown): void { this.requests.push(value as { id: number; method: string }); }
  terminate(): void { this.terminated = true; }
  reply(data: unknown): void { this.listeners.get('message')?.({ data } as MessageEvent); }
}

test('worker boundary waits for verified initialization and resolves matching responses only', async () => {
  const port = new Port();
  const prover = new BrowserProver(port, configuration);
  const operation = prover.execute<{ proof: string }>('prove', { witness: 'private' });
  assert.equal(port.requests.length, 1);
  port.reply({ id: 1, ok: true, value: {} });
  await prover.ready;
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(port.requests[1]?.method, 'prove');
  port.reply({ id: 999, ok: true, value: { proof: 'wrong' } });
  port.reply({ id: 2, ok: true, value: { proof: 'real-response' } });
  assert.deepEqual(await operation, { proof: 'real-response' });
  prover.close();
  assert.equal(port.terminated, true);
});

test('abort terminates proving memory and rejects every queued job', async () => {
  const port = new Port();
  const prover = new BrowserProver(port, configuration);
  port.reply({ id: 1, ok: true });
  await prover.ready;
  const controller = new AbortController();
  const first = prover.execute('prove', {}, { signal: controller.signal });
  const second = prover.execute('prove', {});
  const assertions = Promise.all([assert.rejects(first, /OPERATION_ABORTED/), assert.rejects(second, /OPERATION_ABORTED/)]);
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  await assertions;
  assert.equal(port.terminated, true);
  await assert.rejects(prover.execute('prove', {}), /WORKER_CLOSED/);
});

test('untrusted exception text never crosses into application errors', async () => {
  const port = new Port();
  const prover = new BrowserProver(port, configuration);
  port.reply({ id: 1, ok: true });
  await prover.ready;
  const result = prover.execute('prove', {});
  await new Promise(resolve => setImmediate(resolve));
  port.reply({ id: 2, ok: false, code: 'secret amount 918277', message: 'private witness data' });
  await assert.rejects(result, error => error instanceof CryptoOperationError && error.message === 'CRYPTO_OPERATION_FAILED');
  prover.close();
});

test('cancelling while artifacts load closes the worker immediately', async () => {
  const port = new Port();
  const prover = new BrowserProver(port, configuration);
  const controller = new AbortController();
  const operation = prover.execute('prove', {}, { signal: controller.signal });
  controller.abort();
  assert.equal(port.terminated, true);
  await assert.rejects(operation, /OPERATION_ABORTED/);
});
