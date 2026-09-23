import { useEffect, useState } from 'react'
import { listScans, compliance } from '../lib/api'
import { Card } from '../components/ui/Card'
import { ShieldCheck } from 'lucide-react'

export default function Compliance(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [data,setData]=useState(null)
  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{ if(sel) compliance(sel).then(setData).catch(()=>{}) },[sel])
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-3">
          <div className="font-bold flex items-center gap-2"><ShieldCheck size={16} className="text-emerald-400"/> Compliance — FREE Mapping</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
        </div>
        <div className="text-xs text-slate-400 mt-1">Maps to OWASP Top 10, NIST CSF, MITRE ATT&CK, PCI DSS, ISO 27001 — local, free, no external audit tool.</div>
      </Card>
      {data && (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.entries(data.compliance).map(([k,v])=>(
            <Card key={k}>
              <div className="font-bold text-sm">{k}</div>
              <div className="mt-2 text-3xl font-black" style={{color: v.status==='fail'? '#ef4444': v.status==='warn'? '#eab308':'#22c55e'}}>{v.score}/100</div>
              <div className={`inline-block text-xs px-2 py-1 rounded-full font-bold mt-1 ${v.status==='fail'?'bg-red-500 text-white': v.status==='warn'?'bg-yellow-500 text-black':'bg-emerald-500 text-white'}`}>{v.status.toUpperCase()}</div>
              <div className="text-xs text-slate-400 mt-2">Hits: {v.hit_count} • Controls: {v.controls.join(', ')}</div>
            </Card>
          ))}
        </div>
      )}
      {data && <Card><div className="font-bold text-sm">Overall Risk {data.overall}/100 — Fix fail controls first (P0) for biggest compliance lift. 100% free.</div></Card>}
    </div>
  )
}
