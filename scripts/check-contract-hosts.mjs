import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const [name, expected] of Object.entries({
  confidential_core: ['panic_utf8', 'sha256', 'alt_bn128_pairing_check'],
  test_token: ['panic_utf8'],
  verifier_probe: ['panic_utf8', 'alt_bn128_pairing_check'],
})) {
  const binary = await readFile(`.artifacts/contracts/${name}.wasm`);
  // Leave 16 KiB for the signed transaction and JSON envelope within a 2 MiB
  // deployment request budget. Function-name metadata alone can exceed it.
  assert.ok(4 * Math.ceil(binary.length / 3) + 16_384 <= 2 * 1024 * 1024, `${name} exceeds the deployment RPC size budget`);
  const module = new WebAssembly.Module(binary);
  assert.equal(WebAssembly.Module.customSections(module, 'name').length, 0, `${name} must strip function-name metadata`);
  const imported = WebAssembly.Module.imports(module);
  for (const host of expected) assert.ok(imported.some(entry => entry.module === 'env' && entry.name === host), `${name} must import the NEAR ${host} host function; check --cfg near`);
}
process.stdout.write('Contract artifacts fit the deployment budget and use the required NEAR runtime host functions.\n');
