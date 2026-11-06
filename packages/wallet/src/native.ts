import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { ArtifactEntry } from '@confidential-lending/client';

/** Local proof process. Witnesses go through stdin and never through command-line arguments. */
export class NativeCrypto {
  constructor(readonly root: string, readonly executable: ArtifactEntry, readonly artifacts: Record<string, ArtifactEntry>, readonly timeoutMs = 10 * 60_000, readonly lifetimeSignal?: AbortSignal) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000) throw new Error('Invalid native prover timeout');
  }

  async execute<T>(method: string, params: unknown, options: { artifactName?: string; signal?: AbortSignal } = {}): Promise<T> {
    const signal = options.signal && this.lifetimeSignal ? AbortSignal.any([options.signal, this.lifetimeSignal]) : options.signal ?? this.lifetimeSignal;
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(method)) throw new Error('Invalid crypto method');
    const request = JSON.stringify({ method, params });
    if (Buffer.byteLength(request) > 1_000_000) throw new Error('Crypto request exceeds bound');
    const binary = await this.checkedPath(this.executable);
    const artifact = options.artifactName ? this.artifacts[options.artifactName] : undefined;
    if (options.artifactName && !artifact) throw new Error('Missing native prover artifact');
    const artifactPath = artifact ? await this.checkedPath(artifact) : undefined;
    signal?.throwIfAborted();
    return new Promise<T>((resolveResult, reject) => {
      const child = spawn(binary, ['execute', ...(artifactPath ? ['--artifact', artifactPath] : [])], {
        stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', RUST_BACKTRACE: '0' },
      });
      let settled = false;
      let size = 0;
      const output: Buffer[] = [];
      let forceKill: ReturnType<typeof setTimeout> | undefined;
      const stop = () => {
        child.kill('SIGTERM');
        forceKill = setTimeout(() => child.kill('SIGKILL'), 500);
        forceKill.unref();
      };
      const finish = (error?: Error, value?: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        if (error) { stop(); reject(error); }
        else resolveResult(value as T);
      };
      const abort = () => finish(new Error('Native crypto operation cancelled'));
      const timer = setTimeout(abort, this.timeoutMs);
      signal?.addEventListener('abort', abort, { once: true });
      child.on('error', () => finish(new Error('Native crypto process could not start')));
      child.stdin.on('error', () => finish(new Error('Native crypto process input failed')));
      // Deliberately drain but never forward panic diagnostics that may include witness data.
      child.stderr.resume();
      child.stdout.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 4_000_000) finish(new Error('Native crypto response exceeds bound'));
        else output.push(chunk);
      });
      child.on('close', code => {
        if (forceKill) clearTimeout(forceKill);
        if (settled) return;
        if (code !== 0) { finish(new Error('Native crypto operation failed')); return; }
        try { finish(undefined, JSON.parse(Buffer.concat(output).toString('utf8')) as T); }
        catch { finish(new Error('Native crypto returned invalid output')); }
      });
      child.stdin.end(request);
    });
  }

  private async checkedPath(entry: ArtifactEntry): Promise<string> {
    if (isAbsolute(entry.path) || !/^[a-f0-9]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || entry.bytes > 2 ** 32) throw new Error('Invalid native crypto artifact');
    const root = await realpath(this.root);
    const path = await realpath(resolve(root, entry.path));
    const difference = relative(root, path);
    if (difference === '..' || difference.startsWith(`..${sep}`) || isAbsolute(difference)) throw new Error('Native crypto artifact escapes root');
    const details = await stat(path);
    if (!details.isFile() || details.size !== entry.bytes) throw new Error('Native crypto artifact size mismatch');
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(path)) hash.update(chunk);
    if (hash.digest('hex') !== entry.sha256) throw new Error('Native crypto artifact hash mismatch');
    return path;
  }
}
