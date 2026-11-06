import { Journal, type PreparedTransaction } from './journal.js';

export interface KeeperDriver {
  prepareNext(signal: AbortSignal): Promise<PreparedTransaction | null>;
  broadcast(transaction: PreparedTransaction, signal: AbortSignal): Promise<void>;
  status(transaction: PreparedTransaction, signal: AbortSignal): Promise<'unknown' | 'success' | 'failure'>;
}

export type TickResult =
  | { state: 'idle' }
  | { state: 'submitted' | 'pending' | 'confirmed' | 'failed'; hash: string; brokerId: string };

export class KeeperEngine {
  constructor(readonly journal: Journal, readonly driver: KeeperDriver, readonly intervalMs: number, readonly now: () => number = Date.now) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000) throw new Error('Keeper interval must be at least one second');
  }

  async tick(): Promise<TickResult> {
    return this.journal.exclusive(async signal => {
      const state = await this.journal.read();
      if (state.pending) {
        const pending = state.pending;
        const outcome = await this.driver.status(pending, signal);
        signal.throwIfAborted();
        if (outcome === 'unknown') return { state: 'pending', hash: pending.hash, brokerId: pending.brokerId };
        state.pending = null;
        state.lastCompletedAt = this.now();
        state.lastResult = { hash: pending.hash, outcome };
        await this.journal.write(state);
        return { state: outcome === 'success' ? 'confirmed' : 'failed', hash: pending.hash, brokerId: pending.brokerId };
      }
      if (this.now() - state.lastCompletedAt < this.intervalMs) return { state: 'idle' };
      const prepared = await this.driver.prepareNext(signal);
      if (!prepared) return { state: 'idle' };
      signal.throwIfAborted();
      state.pending = prepared;
      await this.journal.write(state);
      signal.throwIfAborted();
      try { await this.driver.broadcast(prepared, signal); }
      catch {
        // A failed RPC response is not evidence that the signed transaction did not execute.
        return { state: 'pending', hash: prepared.hash, brokerId: prepared.brokerId };
      }
      return { state: 'submitted', hash: prepared.hash, brokerId: prepared.brokerId };
    });
  }

  /** Re-submit the identical signed bytes only; this cannot become a second chain transaction. */
  async rebroadcastPending(): Promise<TickResult> {
    return this.journal.exclusive(async signal => {
      const state = await this.journal.read();
      if (!state.pending) return { state: 'idle' };
      const pending = state.pending;
      const outcome = await this.driver.status(pending, signal);
      if (outcome !== 'unknown') throw new Error('Outcome is known; run a normal tick to finalize the journal');
      signal.throwIfAborted();
      await this.driver.broadcast(pending, signal);
      return { state: 'pending', hash: pending.hash, brokerId: pending.brokerId };
    });
  }
}
