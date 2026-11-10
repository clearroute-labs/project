import { chromium, expect } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
const origin=process.env.PERF_BASE_URL || 'http://127.0.0.1:4176'
const browser=await chromium.launch({channel:process.env.UI_BROWSER_CHANNEL || 'chromium'})
const reports=[]
try {
 for(const width of [1440,390]) {
  const context=await browser.newContext({viewport:{width,height:900}})
  const page=await context.newPage(); const external=[]; page.on('request',r=>{if(new URL(r.url()).origin!==new URL(origin).origin) external.push(r.url())})
  const cdp=await context.newCDPSession(page)
  await cdp.send('Network.enable'); await cdp.send('Network.setCacheDisabled',{cacheDisabled:true})
  await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:200000,uploadThroughput:93750})
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:4})
  await page.addInitScript(()=>{
   window.__metrics={lcp:0,cls:0,longTasks:[]}
   new PerformanceObserver(list=>{for(const e of list.getEntries()) window.__metrics.lcp=e.startTime}).observe({type:'largest-contentful-paint',buffered:true})
   new PerformanceObserver(list=>{for(const e of list.getEntries()) if(!e.hadRecentInput) window.__metrics.cls+=e.value}).observe({type:'layout-shift',buffered:true})
   new PerformanceObserver(list=>{for(const e of list.getEntries()) window.__metrics.longTasks.push({start:e.startTime,duration:e.duration})}).observe({type:'longtask',buffered:true})
  })
  await page.goto(origin,{waitUntil:'networkidle'}); await page.evaluate(()=>document.fonts.ready)
  await expect(page.locator('#dune-grain')).toHaveAttribute('data-state','running')
  const sampleStart=await page.evaluate(()=>performance.now())
  await page.waitForTimeout(3000)
  const report=await page.evaluate(start=>({...window.__metrics,animationLongTasks:window.__metrics.longTasks.filter(t=>t.start>start),resources:performance.getEntriesByType('resource').map(r=>({name:new URL(r.name).pathname,bytes:r.encodedBodySize}))}),sampleStart)
  expect(external).toEqual([])
  expect(report.resources.filter(r=>/App-|PrivySignPage/.test(r.name))).toEqual([])
  await page.evaluate(()=>scrollTo(0,document.getElementById('desert-hero').offsetHeight+20)); await expect(page.locator('#dune-grain')).toHaveAttribute('data-state','paused')
  await page.evaluate(()=>scrollTo(0,0)); await page.emulateMedia({reducedMotion:'reduce'}); await expect(page.locator('#dune-grain')).toHaveAttribute('data-state','reduced-motion')
  reports.push({width,cpuSlowdown:4,downloadKbps:1600,latencyMs:150,...report})
  await context.close()
 }
 await mkdir('.local',{recursive:true}); await writeFile('.local/performance.json',JSON.stringify(reports,null,2))
 console.log(JSON.stringify(reports.map(({width,lcp,cls,animationLongTasks,resources})=>({width,lcpMs:Math.round(lcp),cls,animationLongTasks:animationLongTasks.length,initialResourceKB:Math.round(resources.reduce((n,r)=>n+r.bytes,0)/1024)}))))
} finally {await browser.close()}
