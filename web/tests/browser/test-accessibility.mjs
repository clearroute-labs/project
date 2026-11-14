import { chromium, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { mkdir, writeFile } from 'node:fs/promises'
const origin=process.env.UI_BASE_URL || 'http://localhost:5176'
const browser=await chromium.launch({channel:process.env.UI_BROWSER_CHANNEL || 'chromium'})
const failures=[]; let checked=0
async function audit(page,label) {
 const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze()
 checked++
 for(const v of result.violations) failures.push({page:label,id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})
}
try {
 for(const width of [1440,390]) {
  const context=await browser.newContext({viewport:{width,height:1000},reducedMotion:'reduce'}); const page=await context.newPage()
  await page.goto(origin); await page.evaluate(()=>document.fonts.ready); await audit(page,`landing-${width}`)
  await page.goto(`${origin}/app`); await expect(page.getByRole('heading',{name:'Your capital, in view.'})).toBeVisible(); await audit(page,`welcome-${width}`)
  for(const route of ['lender/vaults','lender/claims','broker/vaults','broker/loans','broker/operations','borrower/agreements','borrower/balance','auditor/loans','settings']) {
   await page.goto(`${origin}/app#/${route}`); await expect(page.getByRole('main').getByRole('heading',{level:1})).toBeVisible(); await audit(page,`disconnected/${route}-${width}`)
   await page.goto(`${origin}/tests/browser/visual.html#/${route}`); await expect(page.getByRole('main').getByRole('heading',{level:1})).toBeVisible(); await audit(page,`${route}-${width}`)
   const triggers=page.locator('.action-entry > button')
   for(let i=0;i<await triggers.count();i++) {
    const name=await triggers.nth(i).getAttribute('aria-label')
    await triggers.nth(i).click(); await audit(page,`${route}/${name}-${width}`)
    if(route==='lender/vaults' && name.includes('deposit claim')) {
     await page.getByRole('button',{name:'Deposit claim',exact:true}).click(); await audit(page,`review-${width}`); await page.getByRole('button',{name:'Back to edit',exact:true}).click()
    }
    await page.locator('.action-drawer[open]').getByRole('button',{name:'Close',exact:true}).click()
   }
  }
  if(width<800) {await page.getByRole('button',{name:'Open navigation'}).click(); await audit(page,`navigation-${width}`)}
  await context.close()
 }
 await mkdir('.local',{recursive:true}); await writeFile('.local/accessibility.json',JSON.stringify({checked,failures},null,2))
 if(failures.length) throw new Error(JSON.stringify(failures,null,2))
 console.log(`axe WCAG 2.2 AA: ${checked} views checked, no detected violations.`)
} finally {await browser.close()}
