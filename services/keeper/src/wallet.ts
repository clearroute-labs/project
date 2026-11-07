import { type Arguments } from '@confidential-lending/client';
import { LedgerWallet, type LedgerVault } from '@confidential-lending/wallet';
import type { KeeperGrant, KeeperSnapshot, KeeperWallet } from './planner.js';

export class NativeKeeperWallet implements KeeperWallet {
  constructor(readonly ledger: LedgerWallet, readonly delegateAccountId: string) {}

  async snapshot(brokerId: string, signal: AbortSignal): Promise<KeeperSnapshot> {
    const snapshot = await this.ledger.snapshot(signal);
    const balance = await this.ledger.broker(brokerId, snapshot, signal);
    const broker = balance.record;
    const [grants, vault, freeze, block] = await Promise.all([
      this.ledger.view<KeeperGrant[] | null>(snapshot.block, 'get_keeper_grants', { broker_id: brokerId }, signal),
      this.ledger.view<LedgerVault | null>(snapshot.block, 'get_vault', { vault_id: broker.vault_id }, signal),
      this.ledger.view<{ asset_frozen: boolean; holder_frozen: boolean }>(snapshot.block, 'get_freeze_status', { account_id: broker.owner }, signal),
      this.ledger.rpc.request<{ header: { hash: string; height: number; timestamp_nanosec: string } }>('block', { block_id: snapshot.block.hash }, signal),
    ]);
    if (!grants || grants.length > 32 || !vault || block.header.hash !== snapshot.block.hash || block.header.height !== snapshot.block.height) throw new Error('Incomplete finalized keeper snapshot');
    const authorizedGrants = await Promise.all(grants.map(async grant => {
      if (grant.delegate_account !== this.delegateAccountId || !grant.active) return grant;
      const key = await this.ledger.view<{ owner: string; epoch: string; revoked: boolean } | null>(snapshot.block,
        'get_authorization_key', { owner: grant.delegate_account, key_id: grant.delegate_key_id }, signal);
      return { ...grant, active: key !== null && key.owner === grant.delegate_account && !key.revoked && key.epoch === grant.delegate_epoch };
    }));
    const timestampSeconds = BigInt(block.header.timestamp_nanosec) / 1_000_000_000n;
    const epoch = BigInt(vault.checkpoint_policy.epoch_seconds);
    if (epoch < 60n || epoch > 86_400n) throw new Error('Invalid finalized checkpoint cadence');
    let settlementDue = timestampSeconds >= BigInt(broker.last_settlement_at) + epoch;
    if (broker.accounting_pending) {
      const since = BigInt(broker.accounting_pending_since);
      if (since <= 0n || since > timestampSeconds) throw new Error('Invalid finalized pending-accounting timestamp');
      const checkpointBoundary = (since / epoch + 1n) * epoch;
      settlementDue &&= timestampSeconds >= checkpointBoundary;
    }
    return { brokerId, owner: broker.owner, timestampSeconds, frozen: freeze.asset_frozen || freeze.holder_frozen,
      spending: BigInt(balance.spending), inbox: BigInt(balance.inbox), grants: authorizedGrants, authorizationEpoch: broker.authorization_epoch,
      settlementDue };
  }

  async merge(brokerId: string, signal: AbortSignal): Promise<Arguments> {
    return (await this.ledger.prepareMergeBroker(brokerId, signal)).args;
  }

  async settle(brokerId: string, amount: bigint, signal: AbortSignal): Promise<Arguments> {
    return (await this.ledger.prepareSettlement(brokerId, amount.toString(), undefined, signal)).args;
  }
}
