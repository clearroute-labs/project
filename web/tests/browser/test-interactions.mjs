import { chromium, expect } from '@playwright/test'
const origin = process.env.UI_BASE_URL || 'http://localhost:5176'
const browser = await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chromium' })
try {
 for (const width of [1440,390,320]) {
  const page = await browser.newPage({ viewport:{width,height:900}, reducedMotion:'reduce' })
  const errors=[]; page.on('pageerror',e=>errors.push(e.message))
  await page.goto(`${origin}/tests/browser/visual.html#/lender/vaults`)
  await expect(page.getByRole('heading',{name:'Vaults & share positions',exact:true})).toBeVisible()
  const trigger=page.getByRole('button',{name:'Open deposit claim into a vault',exact:false})
  await trigger.click()
  const drawer=page.getByRole('dialog',{name:'Deposit claim into a vault',exact:true})
  await expect(drawer).toBeVisible()
  await drawer.getByLabel('Public claim',{exact:true}).selectOption({index:1})
  await drawer.getByLabel('Vault',{exact:true}).selectOption({index:1})
  await drawer.locator('#deposit-amount').fill('2.5')
  await drawer.getByRole('button',{name:'Close',exact:true}).click()
  await expect(trigger).toBeFocused()
  await trigger.click()
  await expect(drawer.locator('#deposit-amount')).toHaveValue('2.5')
  await drawer.getByRole('button',{name:'Deposit claim',exact:true}).click()
  const review=page.getByRole('dialog',{name:'Review your operation'})
  await expect(review).toBeVisible()
  await expect(review.getByText('2.5',{exact:true})).toBeVisible()
  for(let i=0;i<5;i++) {await page.keyboard.press('Tab'); expect(await review.evaluate(el=>el.contains(document.activeElement))).toBe(true)}
  await page.keyboard.press('Escape')
  await expect(review).not.toBeVisible()
  await expect(drawer).toBeVisible()
  await expect(drawer.locator('#deposit-amount')).toHaveValue('2.5')
  await page.keyboard.press('Escape')
  await expect(trigger).toBeFocused()
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  expect(errors).toEqual([])
  await page.close()
 }
 console.log('Draft retention, review, focus trapping and Escape passed at 1440, 390 and 320 px.')
} finally {await browser.close()}
