import { chromium } from '@playwright/test';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { createServer } from 'node:http';

const origin = process.env.VALIDATION_ORIGIN ?? 'http://127.0.0.1:5174';
if (new URL(origin).hostname !== '127.0.0.1') throw new Error('Browser validation is local only');
const directory = await realpath(resolve(process.env.CRYPTO_ARTIFACT_DIR ?? '.artifacts/integration-v2'));
const manifest = JSON.parse(await readFile(resolve(directory, 'manifest.json'), 'utf8'));
const allowed = new Set(['manifest.json', 'deployment-pin.json', ...Object.values(manifest.artifacts).map(entry => entry.path)]);
// Vite rewrites JavaScript modules. Artifact pins must be checked against the original bytes.
const server = createServer(async (request, response) => {
  try {
    const path = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname).slice(1);
    if (!allowed.has(path)) { response.writeHead(404).end(); return; }
    const file = await realpath(resolve(directory, path));
    if (!file.startsWith(`${directory}${sep}`)) { response.writeHead(404).end(); return; }
    const bytes = await readFile(file);
    response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes.length, 'access-control-allow-origin': origin });
    response.end(bytes);
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const artifactOrigin = `http://127.0.0.1:${server.address().port}`;
const source = resolve('tests/browser/crypto.html');
const target = new URL(`/@fs${source}`, origin);
target.searchParams.set('artifacts', artifactOrigin);
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  page.on('console', message => { if (message.type() === 'info') process.stdout.write(`${message.text()}\n`); });
  page.on('pageerror', error => process.stderr.write(`${error.message}\n`));
  await page.goto(target.href, { waitUntil: 'domcontentloaded' });
  process.stdout.write(`Browser validation page loaded: ${await page.title()}\n`);
  await page.waitForFunction(() => window.validation?.status && window.validation.status !== 'running', undefined, { timeout: 30 * 60_000, polling: 1000 });
  const result = await page.evaluate(() => window.validation);
  await mkdir('.artifacts', { recursive: true });
  await writeFile('.artifacts/browser-validation.json', `${JSON.stringify(result, null, 2)}\n`);
  if (result.status !== 'passed') throw new Error(result.error ?? 'Browser proof validation failed');
  process.stdout.write('All real proof families passed in Chromium using the pinned WASM worker.\n');
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
