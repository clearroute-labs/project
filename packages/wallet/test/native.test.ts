import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { NativeCrypto } from '../src/native.js';

test('native transport uses stdin, validates artifact bytes and suppresses process diagnostics', async () => {
  const root = await mkdtemp(join(tmpdir(), 'lending-native-'));
  try {
    const code = '#!/usr/bin/env node\nlet chunks=[]; process.stdin.on("data",x=>chunks.push(x)); process.stdin.on("end",()=>{const r=JSON.parse(Buffer.concat(chunks).toString()); if(r.method==="fail"){console.error("private witness fragment");process.exit(1);} process.stdout.write(JSON.stringify({method:r.method, secretWasInArguments:process.argv.includes(r.params.secret)}));});\n';
    await writeFile(join(root, 'fixture'), code, { mode: 0o700 });
    const entry = { path: 'fixture', bytes: Buffer.byteLength(code), sha256: createHash('sha256').update(code).digest('hex') };
    const crypto = new NativeCrypto(root, entry, {});
    assert.deepEqual(await crypto.execute('prove', { secret: 'test-private-witness' }), { method: 'prove', secretWasInArguments: false });
    await assert.rejects(crypto.execute('fail', {}), error => error instanceof Error && error.message === 'Native crypto operation failed');
    await writeFile(join(root, 'fixture'), code.replace('method:r.method', 'method:"altered"'));
    await assert.rejects(crypto.execute('prove', {}), /size mismatch|hash mismatch/);
  } finally { await rm(root, { force: true, recursive: true }); }
});
