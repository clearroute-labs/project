import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const [name, expected] of Object.entries({
  confidential_core: ['panic_utf8', 'sha256', 'alt_bn128_pairing_check'],
  test_token: ['panic_utf8'],
  verifier_probe: ['panic_utf8', 'alt_bn128_pairing_check'],
})) {
  const binary = await readFile(`.artifacts/contracts/${name}.wasm`);
  const imported = WebAssembly.Module.imports(new WebAssembly.Module(binary));
  for (const host of expected) assert.ok(imported.some(entry => entry.module === 'env' && entry.name === host), `${name} must import the NEAR ${host} host function; check --cfg near`);
}
process.stdout.write('Contract artifacts use the required NEAR runtime host functions.\n');
