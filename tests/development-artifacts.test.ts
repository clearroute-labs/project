import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildDevelopmentArtifacts, type DevelopmentSetup } from '../scripts/development-artifacts.js';

test('development setup resumes with exactly the same keys and refuses changed artifacts or binaries', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'confidential-setup-'));
  try {
    const executable = join(directory, 'prover');
    const prepareKeyExecutable = join(directory, 'prepare-key');
    await writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs');
const a=process.argv.slice(2);
if(a[0]==='inspect-profile') console.log(JSON.stringify({profile_hash:'a'.repeat(64)}));
else if(a[0]==='dev' && a[1]==='setup') {
  fs.appendFileSync(${JSON.stringify(join(directory, 'calls'))},a[2]+'\\n');
  fs.writeFileSync(a[3]+'.pk', 'pk:'+a[2],{flag:'wx'});
  fs.writeFileSync(a[3]+'.vk', 'vk:'+a[2],{flag:'wx'});
} else process.exit(1);
`, { mode: 0o700 });
    await writeFile(prepareKeyExecutable, `#!/usr/bin/env node
const fs=require('node:fs');
fs.writeFileSync(process.argv[3],Buffer.concat([Buffer.from('prepared:'),fs.readFileSync(process.argv[2])]),{flag:'wx'});
`, { mode: 0o700 });
    const browserGlue = join(directory, 'browser.js');
    const browserWasm = join(directory, 'browser.wasm');
    await writeFile(browserGlue, 'fixture');
    await writeFile(browserWasm, new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    const options: DevelopmentSetup = { output: join(directory, 'output'), executable, prepareKeyExecutable, browserGlue, browserWasm, networkId: 'sandbox', coreAccountId: 'core.test.near' };
    const first = await buildDevelopmentArtifacts(options);
    const second = await buildDevelopmentArtifacts(options);
    assert.equal(first.manifestHash, second.manifestHash);
    assert.equal(Object.keys(second.manifest.artifacts).length, 27);
    assert.equal((await readFile(join(directory, 'calls'), 'utf8')).trim().split('\n').length, 8);
    await writeFile(join(options.output, 'origination.pk'), 'modified');
    await assert.rejects(buildDevelopmentArtifacts(options), /artifact changed/);
    await writeFile(browserGlue, 'different runtime');
    await assert.rejects(buildDevelopmentArtifacts(options), /different binaries/);
    await assert.rejects(buildDevelopmentArtifacts({ ...options, networkId: 'mainnet' }), /development network/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
