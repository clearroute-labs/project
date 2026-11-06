import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptWalletBackup, decryptWalletBackup } from '../src/backup.js';

test('encrypted backups authenticate key material and reject corruption, wrong passwords, and costly unsupported parameters', async () => {
  const material = { keys: [{ secretKey: 'private fixture', keyId: '9007199254740993' }], drafts: [] };
  const backup = await encryptWalletBackup(material, 'a sufficiently long password');
  assert.equal(JSON.stringify(backup).includes('private fixture'), false);
  assert.deepEqual(await decryptWalletBackup(backup, 'a sufficiently long password'), material);
  await assert.rejects(decryptWalletBackup(backup, 'an incorrect long password'), /Unable to decrypt/);
  const changed = { ...backup, ciphertext: `${backup.ciphertext[0] === 'A' ? 'B' : 'A'}${backup.ciphertext.slice(1)}` };
  await assert.rejects(decryptWalletBackup(changed, 'a sufficiently long password'), /Unable to decrypt/);
  await assert.rejects(decryptWalletBackup({ ...backup, iterations: 2 ** 31 }, 'a sufficiently long password'), /Unable to decrypt/);
  await assert.rejects(decryptWalletBackup({ ...backup, iv: 'AA==' }, 'a sufficiently long password'), /Unable to decrypt/);
});
