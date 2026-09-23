import { useEffect, useState } from 'react'
import { listScans, getScanResults, aiExplain, aiPrioritize } from '../lib/api'
import VulnTable from '../components/vuln/VulnTable'
import AIInsights from '../components/ai/AIInsights'
import { Card } from '../components/ui/Card'
import { Brain, ListOrdered } from 'lucide-react'

export default function Findings(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [scan,setScan]=useState(null)
  const [aiData,setAiData]=useState(null)
  const [prioritized,setPrioritized]=useState([])
  const [vulnSel,setVulnSel]=useState(null)

  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{ if(sel) getScanResults(sel).then(r=>setScan(r.scan)).catch(()=>{}) },[sel])

  const explain = async (v)=>{
    setVulnSel(v)
    const res = await aiExplain({job_id: sel, vuln_id: v.id})
    setAiData(res)
  }
  const prioritize = async ()=>{
    const r = await aiPrioritize(sel)
    setPrioritized(r.prioritized)
  }

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-3">
          <div className="font-bold">Findings — Deep Weakness Analysis</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
        </div>
        <div className="text-xs text-slate-400 mt-1">Each weakness shows CVSS, CWE, CVE, OWASP, MITRE, evidence, impact, and copy-paste fix. AI prioritization uses graph centrality to find choke points.</div>
      </Card>

      <div className="grid lg:grid-cols-[1.6fr_0.9fr] gap-4">
        <div>
          {scan? <VulnTable vulns={scan.vulnerabilities} onExplain={explain}/> : <div className="glass rounded-xl p-6 text-slate-500">No scan selected</div>}
        </div>
        <div className="space-y-3">
          <Card>
            <button onClick={prioritize} className="w-full bg-gradient-to-br from-violet-600 to-indigo-600 text-white font-bold rounded-xl py-2.5 flex items-center justify-center gap-2"><Brain size={16}/> AI Prioritize (Graph Centrality)</button>
            {prioritized.length>0 && (
              <div className="mt-3 space-y-2 max-h-[320px] overflow-auto scrollbar">
                {prioritized.map((p,i)=>(
                  <div key={p.vuln_id} className="glass rounded-xl p-2.5 border border-slate-800 flex gap-2">
                    <div className="w-6 h-6 rounded-full bg-sky-500 text-white grid place-items-center text-xs font-black">{i+1}</div>
                    <div className="flex-1">
                      <div className="font-bold text-xs">{p.title}</div>
                      <div className="text-[11px] text-slate-400">AI Score {p.ai_score} • CVSS {p.cvss} • Centrality {p.centrality} {p.on_critical_path? '• On Critical Path 🔥':''}</div>
                      <div className="text-[11px] text-slate-500">{p.reason}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <AIInsights data={aiData} vuln={vulnSel}/>
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><ListOrdered size={14}/> How Weakness Scoring Works</div>
            <ul className="mt-2 text-xs text-slate-400 space-y-1 list-disc pl-4">
              <li>CVSS × exploitability (EPSS) × graph betweenness</li>
              <li>On critical path = ×1.4 multiplier</li>
              <li>Exploit available = +10</li>
              <li>PageRank highlights choke-point services</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  )
}
