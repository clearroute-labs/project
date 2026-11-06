import { access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { Worker } from 'near-workspaces';

export async function startSandbox(): Promise<Worker> {
  process.env.NEAR_WORKSPACES_NO_LOGS ??= '1';
  const binary = process.env.NEAR_SANDBOX_BIN_PATH ?? resolve('.local/sandbox/near-sandbox');
  await access(binary).catch(() => { throw new Error('Install the pinned runtime first: pnpm install:sandbox'); });
  // near-sandbox 0.1.x checks BIN_PATH before using BINARY_PATH as a directory.
  process.env.NEAR_SANDBOX_BIN_PATH = binary;
  process.env.NEAR_SANDBOX_BINARY_PATH = dirname(binary);
  return Worker.init();
}
