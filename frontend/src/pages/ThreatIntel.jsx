import { useEffect, useState } from 'react'
import { threatFeed, threatCve } from '../lib/api'
import { Card } from '../components/ui/Card'
import { Globe, Shield, Search } from 'lucide-react'

export default function ThreatIntel(){
  const [feed,setFeed]=useState([])
  const [cve,setCve]=useState("")
  const [cveData,setCveData]=useState(null)
  const [q,setQ]=useState("")
  useEffect(()=>{ threatFeed(8).then(r=>setFeed(r.feed)).catch(()=>{}) },[])
  const lookup = async ()=>{
    if(!cve) return
    const d = await threatCve(cve)
    setCveData(d)
  }
  return (
    <div className="space-y-4">
      <Card>
        <div className="font-bold flex items-center gap-2"><Globe size={16} className="text-emerald-400"/> Threat Intel — 100% FREE (NVD + Local)</div>
        <div className="text-xs text-emerald-300 mt-1">✅ No keys, no payment — uses NVD free API (https://services.nvd.nist.gov) + offline fallback. MITRE ATT&CK + EPSS local.</div>
      </Card>
      <div className="grid lg:grid-cols-[1.1fr_0.9fr] gap-4">
        <Card>
          <div className="font-bold text-sm">Recent Threat Feed (NVD Free)</div>
          <div className="mt-3 space-y-2">
            {feed.map(f=>(
              <div key={f.id} className="glass rounded-xl p-3 border border-slate-800">
                <div className="font-bold text-sm">{f.id} — {f.title.slice(0,90)}</div>
                <div className="text-xs text-slate-400 mt-1">{f.published} • {f.source} <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full px-2 py-0.5 ml-1">FREE</span></div>
              </div>
            ))}
          </div>
        </Card>
        <div className="space-y-3">
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><Search size={14}/> Lookup CVE (Free NVD)</div>
            <div className="flex gap-2 mt-2">
              <input value={cve} onChange={e=>setCve(e.target.value)} placeholder="CVE-2024-1234" className="flex-1 glass rounded-full px-3 py-2 text-sm outline-none"/>
              <button onClick={lookup} className="bg-emerald-500 text-white rounded-full px-4 py-2 text-sm font-bold">Lookup FREE</button>
            </div>
            {cveData && (
              <pre className="mt-3 mono text-xs bg-[#020617] border border-slate-800 rounded-lg p-3 overflow-auto max-h-[260px]">{JSON.stringify(cveData,null,2)}</pre>
            )}
          </Card>
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><Shield size={14} className="text-sky-400"/> MITRE ATT&CK (Free Local)</div>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              {[
                ["T1190","Exploit Public App"],
                ["T1590","Gather Victim Network Info"],
                ["T1078","Valid Accounts"],
                ["T1005","Data from Local System"],
              ].map(([id,name])=>(
                <div key={id} className="glass rounded-lg p-2"><div className="font-bold">{id}</div><div className="text-slate-400">{name}</div></div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
