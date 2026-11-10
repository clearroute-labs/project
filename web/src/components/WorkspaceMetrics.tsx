import { useEffect, useState } from 'react'
import { useAppContext } from '../App'
import { workspaceMetrics, type WorkspaceMetric } from '../lib/workspaceMetrics'
import { Metric } from './ui'

export function MetricRow({ metrics, label }: { metrics: WorkspaceMetric[]; label: string }) {
 return <section className="metrics-grid" aria-label={label}>{metrics.map(metric=><Metric key={metric.label} {...metric}/>)}</section>
}
export function WorkspaceMetrics() {
 const { role, snapshot, accountId, adapters }=useAppContext()
 const [now,setNow]=useState(()=>Math.floor(Date.now()/1000))
 useEffect(()=>{const timer=window.setInterval(()=>setNow(Math.floor(Date.now()/1000)),60000);return()=>window.clearInterval(timer)},[])
 if(!snapshot || !accountId) return null
 return <MetricRow metrics={workspaceMetrics(role,snapshot,accountId,adapters.protocol.config.assetSymbol || snapshot.asset.tokenAccount,now)} label={`Your ${role} metrics`}/>
}
