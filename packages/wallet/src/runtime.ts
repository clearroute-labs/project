import { loadArtifact, validateManifest, type CryptoManifest } from '@confidential-lending/client';

export interface WasmBindings {
  default(input: { module_or_path: Uint8Array }): Promise<unknown>;
  profile_hash(): string;
  execute(requestJson: string, artifactBytes: Uint8Array): string;
}

export interface RuntimeConfiguration {
  baseUrl: string;
  manifest: CryptoManifest;
  expected: { profileHash: string; networkId: string; coreAccountId: string; funded: boolean };
}

export class CryptoRuntime {
  readonly #artifacts = new Map<string, Uint8Array>();
  #wasm: WasmBindings | undefined;

  constructor(readonly configuration: RuntimeConfiguration) {
    validateManifest(configuration.manifest, configuration.expected);
  }

  async initialize(): Promise<void> {
    if (this.#wasm) return;
    const glue = await this.artifact('browser.glue');
    const binary = await this.artifact('browser.wasm');
    // Import the verified bytes, not the original URL, to prevent a second unverified fetch.
    const url = URL.createObjectURL(new Blob([new Uint8Array(glue)], { type: 'text/javascript' }));
    try {
      const module = await import(/* @vite-ignore */ url) as WasmBindings;
      if (typeof module.default !== 'function' || typeof module.execute !== 'function' || typeof module.profile_hash !== 'function') throw new Error('Unsupported WASM interface');
      await module.default({ module_or_path: binary });
      if (module.profile_hash() !== this.configuration.expected.profileHash) throw new Error('WASM profile mismatch');
      this.#wasm = module;
    } finally { URL.revokeObjectURL(url); }
  }

  async execute(method: string, params: unknown, artifactName?: string): Promise<unknown> {
    await this.initialize();
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(method)) throw new Error('Invalid crypto method');
    const request = JSON.stringify({ method, params });
    if (request.length > 1_000_000) throw new Error('Crypto request exceeds bound');
    const artifact = artifactName ? await this.artifact(artifactName) : new Uint8Array();
    const output = this.#wasm!.execute(request, artifact);
    if (output.length > 4_000_000) throw new Error('Crypto response exceeds bound');
    return JSON.parse(output) as unknown;
  }

  private async artifact(name: string): Promise<Uint8Array> {
    const cached = this.#artifacts.get(name);
    if (cached) return cached;
    const entry = this.configuration.manifest.artifacts[name];
    if (!entry) throw new Error(`Missing crypto artifact: ${name}`);
    const bytes = await loadArtifact(this.configuration.baseUrl, entry);
    this.#artifacts.set(name, bytes);
    return bytes;
  }
}
