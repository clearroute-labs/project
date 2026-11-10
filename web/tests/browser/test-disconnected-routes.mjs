import { chromium, expect } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
const origin = new URL(process.env.UI_BASE_URL || 'http://localhost:5176').origin
const browser=await chromium.launch({channel:process.env.UI_BROWSER_CHANNEL || 'chromium'})
const roles=[
 ['lender','Your capital, in view.',[['Vaults','/lender/vaults','Find your vault.'],['Claims & payouts','/lender/claims','Claims & payouts.']]],
 ['broker','Credit, coordinated.',[['Vaults & brokers','/broker/vaults','Vaults & brokers.'],['Loan book','/broker/loans','Your credit book.'],['Operations','/broker/operations','Keep the book current.']]],
 ['borrower','Your next step, clear.',[['Agreements','/borrower/agreements','Your agreements.'],['Private balance','/borrower/balance','Private by design.']]],
 ['auditor','Access, with purpose.',[['Loan exports','/auditor/loans','A focused view of each loan.'],['Token audit','/auditor/token','Trace the authorized view.']]],
]
try {
 await mkdir('.local/route-review',{recursive:true})
 for(const width of [1440,390,320]) {
  const page=await browser.newPage({viewport:{width,height:1000},reducedMotion:'reduce'}); const errors=[];page.on('pageerror',e=>errors.push(e.message))
  await page.goto(`${origin}/app`)
  for(const [role,heading,routes] of roles) {
   await page.getByLabel('Active workspace').selectOption(role)
   await expect(page.getByRole('heading',{name:heading,exact:true})).toBeVisible()
   await page.reload(); await expect(page.getByLabel('Active workspace')).toHaveValue(role)
   for(const [label,path,title] of [...routes,['Wallet & security','/settings','Your wallet. Your keys.']]) {
    if(width<=800) await page.getByRole('button',{name:'Open navigation',exact:true}).click()
    await page.getByRole('navigation').getByRole('button',{name:label,exact:true}).click()
    await expect(page).toHaveURL(`${origin}/app#${path}`)
    await expect(page.getByRole('heading',{name:title,exact:true})).toBeVisible()
    await expect(page.getByRole('main').getByRole('button',{name:'Connect wallet',exact:true})).toBeVisible()
    await expect(page.getByRole('main')).toBeFocused()
    expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
    await page.screenshot({path:`.local/route-review/${width}-${role}-${path.split('/').at(-1)}.png`,fullPage:true})
   }
  }
  await page.goto(`${origin}/app#/lender/overview`)
  await page.getByRole('button',{name:'Explore vaults',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Find your vault.',exact:true})).toBeVisible()
  await page.goBack(); await expect(page.getByRole('heading',{name:'Your capital, in view.',exact:true})).toBeVisible()
  await page.goForward(); await expect(page.getByRole('heading',{name:'Find your vault.',exact:true})).toBeVisible()
  expect(errors).toEqual([]); await page.close()
 }
 console.log('Disconnected navigation, distinct screens, deep links, role reload and browser history passed at 1440, 390 and 320 px.')
} finally {await browser.close()}
