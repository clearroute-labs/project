import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = '2.14.0';
const platform = process.platform === 'darwin' && process.arch === 'arm64' ? 'Darwin-arm64'
  : process.platform === 'linux' && process.arch === 'x64' ? 'Linux-x86_64' : null;
if (!platform) throw new Error('Use a supported Linux x64 or macOS arm64 NEAR sandbox host');
const directory = resolve(root, '.local', 'sandbox');
const partsDirectory = resolve(directory, `${version}-${platform}-parts`);
await mkdir(partsDirectory, { recursive: true });
const url = `https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/${platform}/${version}/near-sandbox.tar.gz`;
const { stdout: headers } = await execute('curl', ['--fail', '--silent', '--show-error', '--head', '--location', '--max-time', '30', url]);
const length = Number(/content-length:\s*(\d+)/i.exec(headers)?.[1]);
const etag = /etag:\s*"([a-f0-9]+(?:-\d+)?)"/i.exec(headers)?.[1];
if (!Number.isSafeInteger(length) || length < 1 || length > 256 * 1024 * 1024 || !etag) throw new Error('Invalid official sandbox archive metadata');
const chunkSize = 1024 * 1024;
const count = Math.ceil(length / chunkSize);
let next = 0;
let completed = 0;
await Promise.all(Array.from({ length: 8 }, async () => {
  while (next < count) {
    const index = next++;
    const start = index * chunkSize;
    const end = Math.min(length, start + chunkSize) - 1;
    const path = resolve(partsDirectory, String(index));
    if ((await stat(path).catch(() => null))?.size !== end - start + 1) {
      await execute('curl', ['--fail', '--silent', '--show-error', '--location', '--retry', '2', '--max-time', '120', '--range', `${start}-${end}`, '--output', `${path}.partial`, url], { maxBuffer: 1024 * 1024 });
      if ((await stat(`${path}.partial`)).size !== end - start + 1) throw new Error('Sandbox range download has an incorrect size');
      await rename(`${path}.partial`, path);
    }
    console.log(`Sandbox archive: ${++completed}/${count} parts verified`);
  }
}));
const archive = Buffer.concat(await Promise.all(Array.from({ length: count }, (_, i) => readFile(resolve(partsDirectory, String(i))))));
if (archive.length !== length) throw new Error('Sandbox archive length mismatch');
const multipartSize = 8 * 1024 * 1024;
const md5s = [];
for (let offset = 0; offset < archive.length; offset += multipartSize) md5s.push(createHash('md5').update(archive.subarray(offset, offset + multipartSize)).digest());
const actualEtag = etag.includes('-') ? `${createHash('md5').update(Buffer.concat(md5s)).digest('hex')}-${md5s.length}` : createHash('md5').update(archive).digest('hex');
if (actualEtag !== etag) throw new Error('Sandbox archive does not match its official S3 ETag');
const archivePath = resolve(directory, `near-sandbox-${version}.tar.gz`);
await writeFile(archivePath, archive);
await execute('tar', ['-xzf', archivePath, '-C', directory, '--strip-components=1']);
const binary = resolve(directory, 'near-sandbox');
const { stdout } = await execute(binary, ['--version']);
await writeFile(resolve(directory, 'manifest.json'), JSON.stringify({ version, platform, url, bytes: length, etag, sha256: createHash('sha256').update(archive).digest('hex'), binaryVersion: stdout.trim() }, null, 2));
console.log(stdout.trim());
console.log(`Use NEAR_SANDBOX_BIN_PATH=${binary}`);
console.log(`near-workspaces also requires NEAR_SANDBOX_BINARY_PATH=${directory}; the test helper sets both.`);
