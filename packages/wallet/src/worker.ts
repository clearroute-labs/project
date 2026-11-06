import { CryptoRuntime, type RuntimeConfiguration } from './runtime.js';

interface Request {
  id: number;
  method: string;
  params?: unknown;
  artifactName?: string;
  configuration?: RuntimeConfiguration;
}

const scope = globalThis as unknown as { onmessage: ((event: MessageEvent<Request>) => void) | null; postMessage(value: unknown): void };
let runtime: CryptoRuntime | undefined;
let chain = Promise.resolve();

scope.onmessage = (event): void => {
  const request = event.data;
  chain = chain.then(async () => {
    try {
      if (!Number.isSafeInteger(request.id) || request.id < 1) throw new Error('Invalid request');
      if (request.method === 'initialize') {
        if (runtime || !request.configuration) throw new Error('Runtime is already initialized or configuration is missing');
        runtime = new CryptoRuntime(request.configuration);
        await runtime.initialize();
        scope.postMessage({ id: request.id, ok: true, value: { profileHash: request.configuration.expected.profileHash } });
        return;
      }
      if (!runtime) throw new Error('Runtime is not initialized');
      const value = await runtime.execute(request.method, request.params, request.artifactName);
      scope.postMessage({ id: request.id, ok: true, value });
    } catch {
      // WASM/JSON errors may include witness fragments. Return only a stable category.
      scope.postMessage({ id: request.id, ok: false, code: request.method === 'initialize' ? 'ARTIFACT_VALIDATION_FAILED' : 'CRYPTO_OPERATION_FAILED' });
    }
  });
};
