import { type Arguments } from '@confidential-lending/client';
import { LedgerWallet, type LedgerBroker, type LedgerKey, type LedgerVault } from '@confidential-lending/wallet';
import type { KeeperGrant, KeeperSnapshot, KeeperWallet } from './planner.js';

export class NativeKeeperWallet implements KeeperWallet {
  constructor(readonly ledger: LedgerWallet) {}

  async snapshot(brokerId: string, signal: AbortSignal): Promise<KeeperSnapshot> {
    const snapshot = await this.ledger.snapshot(signal);
    const balance = await this.ledger.broker(brokerId, snapshot, signal);
    const broker = balance.record as LedgerBroker & { last_settlement_at: string };
    const [grants, key, vault, freeze, block] = await Promise.all([
      this.ledger.view<KeeperGrant[] | null>(snapshot.block, 'get_keeper_grants', { broker_id: brokerId }, signal),
      this.ledger.view<LedgerKey | null>(snapshot.block, 'get_broker_key', { broker_id: brokerId, key_id: null }, signal),
      this.ledger.view<LedgerVault | null>(snapshot.block, 'get_vault', { vault_id: broker.vault_id }, signal),
      this.ledger.view<{ asset_frozen: boolean; holder_frozen: boolean }>(snapshot.block, 'get_freeze_status', { account_id: broker.owner }, signal),
      this.ledger.rpc.request<{ header: { hash: string; height: number; timestamp_nanosec: string } }>('block', { block_id: snapshot.block.hash }, signal),
    ]);
    if (!key || !grants || !vault || block.header.hash !== snapshot.block.hash || block.header.height !== snapshot.block.height) throw new Error('Incomplete finalized keeper snapshot');
    const timestampSeconds = BigInt(block.header.timestamp_nanosec) / 1_000_000_000n;
    return { brokerId, owner: broker.owner, timestampSeconds, frozen: freeze.asset_frozen || freeze.holder_frozen,
      spending: BigInt(balance.spending), inbox: BigInt(balance.inbox), grants, authorizationEpoch: key.authorization_epoch,
      settlementDue: timestampSeconds >= BigInt(broker.last_settlement_at) + BigInt(vault.checkpoint_policy.epoch_seconds) };
  }

  async merge(brokerId: string, signal: AbortSignal): Promise<Arguments> {
    return (await this.ledger.prepareMergeBroker(brokerId, signal)).args;
  }

  async settle(brokerId: string, amount: bigint, signal: AbortSignal): Promise<Arguments> {
    return (await this.ledger.prepareSettlement(brokerId, amount.toString(), undefined, signal)).args;
  }
}
