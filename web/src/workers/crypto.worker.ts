/*
 * Transport boundary for the reviewed confidential-crypto WASM package.
 *
 * The worker deliberately has no development verifier or plaintext fallback:
 * until the WASM module is installed and its profile/artifact hashes match,
 * every private operation fails closed. The crypto worker owns witnesses and
 * local key material; only canonical proofs, commitments and ciphertexts leave
 * this boundary.
 */

type WorkerRequest = { id: number; method: string; payload?: unknown }
type WorkerReply = { id: number; ok: true; value: unknown } | { id: number; ok: false; category: string; message: string }
type WorkerProgress = { id: number; progress: number; message: string }

interface ConfidentialCryptoWasm {
  profileHash: string
  artifactHash: string
  wasmVersion: string
  invoke(method: string, payload: unknown, progress: (progress: number, message: string) => void): Promise<unknown>
}

interface WorkerSelf {
  postMessage(message: unknown): void
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null
  __CONFIDENTIAL_CRYPTO_WASM__?: ConfidentialCryptoWasm
  __CONFIDENTIAL_CRYPTO_EXPECTED_PROFILE_HASH__?: string
  __CONFIDENTIAL_CRYPTO_EXPECTED_ARTIFACT_HASH__?: string
}

declare const self: WorkerSelf

function reply(message: WorkerReply | WorkerProgress): void {
  self.postMessage(message)
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const request = event.data
  const wasm = self.__CONFIDENTIAL_CRYPTO_WASM__
  if (!wasm) {
    reply({ id: request.id, ok: false, category: 'UNSUPPORTED_PROFILE', message: 'Confidential crypto WASM artifacts are not loaded.' })
    return
  }
  if (self.__CONFIDENTIAL_CRYPTO_EXPECTED_PROFILE_HASH__ && wasm.profileHash !== self.__CONFIDENTIAL_CRYPTO_EXPECTED_PROFILE_HASH__) {
    reply({ id: request.id, ok: false, category: 'UNSUPPORTED_PROFILE', message: 'Crypto profile hash does not match the deployment manifest.' })
    return
  }
  if (self.__CONFIDENTIAL_CRYPTO_EXPECTED_ARTIFACT_HASH__ && wasm.artifactHash !== self.__CONFIDENTIAL_CRYPTO_EXPECTED_ARTIFACT_HASH__) {
    reply({ id: request.id, ok: false, category: 'UNSUPPORTED_PROFILE', message: 'Crypto artifact hash does not match the deployment manifest.' })
    return
  }
  void wasm.invoke(request.method, request.payload, (progress: number, message: string) => reply({ id: request.id, progress, message })).then(
    (value: unknown) => reply({ id: request.id, ok: true, value }),
    (error: unknown) => reply({ id: request.id, ok: false, category: 'BAD_PROOF', message: error instanceof Error ? error.message : 'Crypto operation failed.' }),
  )
}

export {}
