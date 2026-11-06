import { open, readFile, rename, mkdir, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import lockfile from 'proper-lockfile';

export interface PreparedTransaction {
  hash: string;
  signerId: string;
  signedTransactionBase64: string;
  brokerId: string;
  action: 'merge' | 'settle';
  preparedAt: number;
}

export interface JournalState {
  schema: 1;
  pending: PreparedTransaction | null;
  lastCompletedAt: number;
  lastResult: { hash: string; outcome: 'success' | 'failure' } | null;
}

export class Journal {
  constructor(readonly path: string) {}

  async initialize(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    try {
      const handle = await open(this.path, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify({ schema: 1, pending: null, lastCompletedAt: 0, lastResult: null })); await handle.sync(); }
      finally { await handle.close(); }
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  }

  async exclusive<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    await this.initialize();
    const controller = new AbortController();
    const release = await lockfile.lock(this.path, {
      stale: 60_000, update: 5_000, retries: 0,
      onCompromised: error => controller.abort(error),
    });
    try { return await operation(controller.signal); }
    finally { await release(); }
  }

  async read(): Promise<JournalState> {
    const details = await stat(this.path);
    if (details.size > 2 * 1024 * 1024 || (details.mode & 0o077) !== 0) throw new Error('Keeper journal has unsafe size or permissions');
    const value = JSON.parse(await readFile(this.path, 'utf8')) as JournalState;
    if (value.schema !== 1 || !Number.isSafeInteger(value.lastCompletedAt) || value.lastCompletedAt < 0) throw new Error('Invalid keeper journal');
    if (value.pending) {
      const pending = value.pending;
      if (!/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(pending.hash) || typeof pending.signerId !== 'string' || !['merge', 'settle'].includes(pending.action) || typeof pending.signedTransactionBase64 !== 'string' || pending.signedTransactionBase64.length > 1_500_000) throw new Error('Invalid pending keeper transaction');
    }
    return value;
  }

  async write(state: JournalState): Promise<void> {
    const temporary = `${this.path}.${randomBytes(8).toString('hex')}.tmp`;
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(JSON.stringify(state)); await handle.sync(); }
    finally { await handle.close(); }
    await rename(temporary, this.path);
    const directory = await open(dirname(this.path), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  }
}
