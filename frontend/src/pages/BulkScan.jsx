import { useState } from 'react'
import { bulkScan } from '../lib/api'
import { Card } from '../components/ui/Card'
import { Layers, Rocket } from 'lucide-react'

export default function BulkScan(){
  const [targets,setTargets]=useState("https://example.com\nhttps://httpbin.org\nhttps://testphp.vulnweb.com")
  const [mode,setMode]=useState("advance")
  const [res,setRes]=useState(null)
  const [loading,setLoading]=useState(false)
  const launch = async ()=>{
    const list = targets.split("\n").map(s=>s.trim()).filter(Boolean)
    setLoading(true)
    try{
      const r = await bulkScan(list, mode, 2)
      setRes(r)
    } catch(e){ alert(e.response?.data?.detail || e.message)}
    setLoading(false)
  }
  return (
    <div className="space-y-4">
      <Card>
        <div className="font-bold flex items-center gap-2"><Layers size={16} className="text-sky-400"/> Bulk Scan — FREE (up to 20 targets)</div>
        <div className="text-xs text-slate-400 mt-1">Launch parallel deep scans, each gets own graph + risk + websocket. Cost $0 — all free engines.</div>
      </Card>
      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <label className="text-xs font-bold">Targets (one per line)</label>
          <textarea value={targets} onChange={e=>setTargets(e.target.value)} rows={8} className="w-full mt-1 glass rounded-xl p-3 text-sm outline-none mono"/>
          <div className="flex gap-2 mt-3">
            {["quick","advance","comprehensive"].map(m=>(
              <button key={m} onClick={()=>setMode(m)} className={`px-3 py-2 rounded-full text-xs font-bold border ${mode===m?'bg-sky-500 text-white border-sky-400':'glass'}`}>{m.toUpperCase()}</button>
            ))}
          </div>
          <button onClick={launch} disabled={loading} className="w-full mt-3 bg-gradient-to-br from-sky-500 to-indigo-600 text-white font-bold rounded-xl py-3 flex items-center justify-center gap-2 disabled:opacity-60"><Rocket size={16}/>{loading?'Launching...':'Launch Bulk FREE'}</button>
        </Card>
        <Card>
          <div className="font-bold text-sm">Queued Jobs</div>
          {res? (
            <div className="mt-2">
              <div className="text-sm">Created {res.count} scans — IDs:</div>
              <div className="mt-2 space-y-1 mono text-xs">
                {res.jobs.map(j=> <div key={j} className="glass rounded-lg px-2 py-1.5">{j}</div>)}
              </div>
              <div className="text-xs text-slate-400 mt-2">Go to Dashboard / Scanner to watch WebSocket live.</div>
            </div>
          ): <div className="text-sm text-slate-500 mt-2">No bulk yet — enter targets and launch.</div>}
        </Card>
      </div>
    </div>
  )
}
