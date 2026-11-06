import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';

const target = new URL(process.argv[2] ?? 'http://127.0.0.1:5174/');
if (!['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname)) throw new Error('UI inspection is limited to a local application');
await mkdir('.artifacts/ui', { recursive: true });
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.stack ?? error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('requestfailed', request => errors.push(`${new URL(request.url()).pathname}: ${request.failure()?.errorText}`));
  await page.goto(target.href);
  await page.getByRole('heading').first().waitFor({ timeout: 15_000 }).catch(() => {});
  console.log(await page.locator('body').innerText());
  console.log(JSON.stringify({ links: await page.getByRole('link').evaluateAll(elements => elements.map(element => ({ name: element.textContent, href: element.getAttribute('href') }))), errors }));
  await page.screenshot({ path: '.artifacts/ui/desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '.artifacts/ui/mobile.png', fullPage: true });
  if (errors.length) throw new Error('Application raised browser errors');
} finally { await browser.close(); }
