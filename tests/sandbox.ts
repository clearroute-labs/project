import { access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { Worker } from 'near-workspaces';
import { setTimeout as delay } from 'node:timers/promises';

export async function startSandbox(): Promise<Worker> {
  process.env.NEAR_WORKSPACES_NO_LOGS ??= '1';
  const binary = process.env.NEAR_SANDBOX_BIN_PATH ?? resolve('.local/sandbox/near-sandbox');
  await access(binary).catch(() => { throw new Error('Install the pinned runtime first: pnpm install:sandbox'); });
  // near-sandbox 0.1.x checks BIN_PATH before using BINARY_PATH as a directory.
  process.env.NEAR_SANDBOX_BIN_PATH = binary;
  process.env.NEAR_SANDBOX_BINARY_PATH = dirname(binary);
  return Worker.init();
}

/** A fast-forward RPC acknowledges execution before its new head becomes final. */
export async function fastForwardFinalized(worker: Worker, blocks: number): Promise<{ elapsedSeconds: bigint }> {
  const before = await worker.provider.block({ finality: 'final' });
  await worker.provider.fastForward(blocks);
  const targetHeight = before.header.height + blocks;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const after = await worker.provider.block({ finality: 'final' });
    if (after.header.height >= targetHeight) return { elapsedSeconds: (BigInt(after.header.timestamp_nanosec) - BigInt(before.header.timestamp_nanosec)) / 1_000_000_000n };
    await delay(250);
  }
  throw new Error('Fast-forwarded sandbox state did not become final');
}
