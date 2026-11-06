import { open, constants } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { assertAccountId } from '@confidential-lending/client';
import type { BrokerPolicy } from './planner.js';

export interface KeeperConfig {
  rpcUrl: string;
  networkId: string;
  coreAccountId: string;
  assetId: string;
  profileHash: string;
  manifestHash: string;
  artifactDirectory: string;
  credentialsFile: string;
  encryptedBackupFile: string;
  journalFile: string;
  intervalMs: number;
  funded: boolean;
  allowInsecureLocalhost: boolean;
  brokers: BrokerPolicy[];
}

export async function readBoundedFile(path: string, maximum: number, privateFile = false): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const details = await handle.stat();
    if (!details.isFile() || details.size > maximum || (privateFile && ((details.mode & 0o077) !== 0 || (process.getuid && details.uid !== process.getuid())))) throw new Error('Unsafe configuration or backup file');
    return await handle.readFile('utf8');
  } finally { await handle.close(); }
}

export async function readConfig(path: string): Promise<KeeperConfig> {
  const value = JSON.parse(await readBoundedFile(path, 64 * 1024)) as Record<string, unknown>;
  const directory = dirname(resolve(path));
  const string = (field: string): string => {
    const item = value[field];
    if (typeof item !== 'string' || item.length < 1 || item.length > 4096) throw new Error(`Invalid keeper configuration field: ${field}`);
    return item;
  };
  const bool = (field: string): boolean => {
    if (typeof value[field] !== 'boolean') throw new Error(`Explicit boolean required: ${field}`);
    return value[field];
  };
  const coreAccountId = string('coreAccountId'), assetId = string('assetId');
  assertAccountId(coreAccountId); assertAccountId(assetId);
  const profileHash = string('profileHash'), manifestHash = string('manifestHash');
  if (![profileHash, manifestHash].every(item => /^[a-f0-9]{64}$/.test(item))) throw new Error('Invalid deployment hash pin');
  const intervalMs = value.intervalMs;
  if (!Number.isSafeInteger(intervalMs) || (intervalMs as number) < 1_000 || (intervalMs as number) > 86_400_000) throw new Error('Invalid keeper polling interval');
  if (!Array.isArray(value.brokers) || value.brokers.length > 128) throw new Error('Invalid broker policies');
  const brokers = value.brokers.map((item: unknown): BrokerPolicy => {
    if (!item || typeof item !== 'object') throw new Error('Invalid broker policy');
    const policy = item as Record<string, unknown>;
    if (!['brokerId', 'maximumSettlement', 'minimumSettlement'].every(field => typeof policy[field] === 'string' && /^(0|[1-9]\d{0,19})$/.test(policy[field] as string))) throw new Error('Broker IDs and limits must be decimal strings');
    return { brokerId: policy.brokerId as string, maximumSettlement: BigInt(policy.maximumSettlement as string), minimumSettlement: BigInt(policy.minimumSettlement as string) };
  });
  return {
    rpcUrl: string('rpcUrl'), networkId: string('networkId'), coreAccountId, assetId, profileHash, manifestHash,
    artifactDirectory: resolve(directory, string('artifactDirectory')), credentialsFile: resolve(directory, string('credentialsFile')),
    encryptedBackupFile: resolve(directory, string('encryptedBackupFile')), journalFile: resolve(directory, string('journalFile')),
    intervalMs: intervalMs as number, funded: bool('funded'), allowInsecureLocalhost: bool('allowInsecureLocalhost'), brokers,
  };
}

/** Refuse terminal input so a passphrase cannot accidentally be echoed. Pipe one UTF-8 line. */
export async function readPassphrase(): Promise<string> {
  if (process.stdin.isTTY) throw new Error('Pipe the backup passphrase on standard input; it must not appear in arguments or environment variables');
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of process.stdin) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      size += bytes.length;
      if (size > 16_384) throw new Error('Passphrase input exceeds bound');
      chunks.push(bytes);
    }
    const input = Buffer.concat(chunks);
    try {
      const phrase = new TextDecoder('utf-8', { fatal: true }).decode(input).replace(/\r?\n$/, '');
      if (phrase.length < 12 || phrase.length > 4096 || /[\r\n]/.test(phrase)) throw new Error('Provide exactly one passphrase line');
      return phrase;
    } finally { input.fill(0); }
  } finally { for (const chunk of chunks) chunk.fill(0); }
}
