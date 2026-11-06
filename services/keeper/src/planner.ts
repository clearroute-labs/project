import type { Arguments } from '@confidential-lending/client';
import type { KeeperDriver } from './engine.js';
import type { PreparedTransaction } from './journal.js';

export interface KeeperGrant {
  delegate_account: string;
  allowed_settlement_per_operation: string;
  allowed_settlement_per_window: string;
  window_seconds: string;
  window_started_at: string;
  window_spent: string;
  expires_at: string;
  active: boolean;
  revocation_epoch: string;
}

export interface KeeperSnapshot {
  brokerId: string;
  owner: string;
  timestampSeconds: bigint;
  frozen: boolean;
  spending: bigint;
  inbox: bigint;
  grants: KeeperGrant[];
  authorizationEpoch: string;
}

export interface KeeperWallet {
  snapshot(brokerId: string, signal: AbortSignal): Promise<KeeperSnapshot>;
  merge(brokerId: string, signal: AbortSignal): Promise<Arguments>;
  settle(brokerId: string, amount: bigint, signal: AbortSignal): Promise<Arguments>;
}

export interface TransactionSigner {
  readonly signerId: string;
  prepare(action: PreparedTransaction['action'], brokerId: string, args: Arguments, signal: AbortSignal): Promise<PreparedTransaction>;
  broadcast(transaction: PreparedTransaction, signal: AbortSignal): Promise<void>;
  status(transaction: PreparedTransaction, signal: AbortSignal): Promise<'unknown' | 'success' | 'failure'>;
}

export interface BrokerPolicy { brokerId: string; maximumSettlement: bigint; minimumSettlement: bigint }

function unsigned(value: string): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,38})$/.test(value)) throw new Error('Invalid finalized keeper grant');
  return BigInt(value);
}

/** Selects only on-chain grants; local policy can tighten but never expand their limits. */
export class SettlementPlanner implements KeeperDriver {
  #next = 0;
  constructor(readonly wallet: KeeperWallet, readonly signer: TransactionSigner, readonly policies: readonly BrokerPolicy[]) {
    if (policies.length === 0 || policies.length > 128 || new Set(policies.map(p => p.brokerId)).size !== policies.length) throw new Error('Configure between one and 128 distinct brokers');
    for (const policy of policies) {
      if (!/^(0|[1-9]\d*)$/.test(policy.brokerId) || BigInt(policy.brokerId) > 0xffff_ffff_ffff_ffffn
        || policy.minimumSettlement < 1n || policy.maximumSettlement < policy.minimumSettlement || policy.maximumSettlement > (1n << 63n) - 1n) throw new Error('Invalid keeper settlement policy');
    }
  }

  async prepareNext(signal: AbortSignal): Promise<PreparedTransaction | null> {
    for (let inspected = 0; inspected < this.policies.length; inspected++) {
      const policy = this.policies[this.#next]!;
      this.#next = (this.#next + 1) % this.policies.length;
      signal.throwIfAborted();
      const snapshot = await this.wallet.snapshot(policy.brokerId, signal);
      if (snapshot.brokerId !== policy.brokerId || snapshot.spending < 0n || snapshot.inbox < 0n) throw new Error('Keeper snapshot identity or balance mismatch');
      if (snapshot.owner === this.signer.signerId) throw new Error('Use a dedicated delegate account; owner authority bypasses keeper grant limits');
      if (snapshot.frozen) continue;
      // Core chooses the first active unexpired grant for this account, so mirror that selection.
      const grant = snapshot.grants.find(g => g.delegate_account === this.signer.signerId && g.active
        && unsigned(g.expires_at) >= snapshot.timestampSeconds && unsigned(g.revocation_epoch) === unsigned(snapshot.authorizationEpoch));
      if (!grant) continue;
      if (snapshot.inbox > 0n) {
        const args = await this.wallet.merge(policy.brokerId, signal);
        return this.signer.prepare('merge', policy.brokerId, args, signal);
      }
      const window = unsigned(grant.window_seconds);
      if (window === 0n) throw new Error('Invalid keeper window');
      const spent = snapshot.timestampSeconds >= unsigned(grant.window_started_at) + window ? 0n : unsigned(grant.window_spent);
      const limit = unsigned(grant.allowed_settlement_per_window);
      const remaining = limit > spent ? limit - spent : 0n;
      const amount = [snapshot.spending, policy.maximumSettlement, unsigned(grant.allowed_settlement_per_operation), remaining].reduce((a, b) => a < b ? a : b);
      if (amount < policy.minimumSettlement) continue;
      const args = await this.wallet.settle(policy.brokerId, amount, signal);
      signal.throwIfAborted();
      return this.signer.prepare('settle', policy.brokerId, args, signal);
    }
    return null;
  }

  broadcast(transaction: PreparedTransaction, signal: AbortSignal): Promise<void> { return this.signer.broadcast(transaction, signal); }
  status(transaction: PreparedTransaction, signal: AbortSignal): Promise<'unknown' | 'success' | 'failure'> { return this.signer.status(transaction, signal); }
}
