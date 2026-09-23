import { useEffect, useState } from 'react'
import { listScans, assetInventory, assetSbom, anomaly } from '../lib/api'
import { Card } from '../components/ui/Card'
import { Package, AlertTriangle } from 'lucide-react'

export default function Assets(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [inv,setInv]=useState(null)
  const [sbom,setSbom]=useState(null)
  const [ano,setAno]=useState(null)
  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{ if(sel){ assetInventory(sel).then(setInv).catch(()=>{}); assetSbom(sel).then(setSbom).catch(()=>{}); anomaly(sel).then(setAno).catch(()=>{}) } },[sel])
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-3">
          <div className="font-bold flex items-center gap-2"><Package size={16} className="text-sky-400"/> Assets & SBOM — FREE Inventory</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
        </div>
        <div className="text-xs text-slate-400 mt-1">Auto-inventories ports, subdomains, paths, techs → SBOM (CycloneDX-free) + shadow IT + anomaly ML (Z-score, free).</div>
      </Card>
      <div className="grid lg:grid-cols-3 gap-4">
        <Card>
          <div className="font-bold text-sm">Inventory</div>
          {inv && (
            <div className="mt-2 text-sm space-y-2">
              <div className="glass rounded-lg p-2 flex justify-between"><span>Total Assets</span><b>{inv.total_assets}</b></div>
              <div className="text-xs text-slate-400">Ports {inv.by_type.ports} • Subs {inv.by_type.subdomains} • Paths {inv.by_type.paths} • Techs {inv.by_type.techs}</div>
              <div className="max-h-[260px] overflow-auto scrollbar space-y-1">
                {inv.assets.slice(0,12).map(a=>(
                  <div key={a.id} className="flex items-center justify-between glass rounded-lg px-2 py-1.5 text-xs"><span>{a.label}</span><span className={`px-2 py-0.5 rounded-full text-xs ${a.risk==='critical'?'bg-red-500 text-white': a.risk==='high'?'bg-orange-500 text-white':'bg-slate-700'}`}>{a.risk}</span></div>
                ))}
              </div>
              {inv.risky_techs.length>0 && <div className="text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg p-2">⚠️ Risky techs: {inv.risky_techs.map(t=>t.name).join(', ')}</div>}
            </div>
          )}
        </Card>
        <Card>
          <div className="font-bold text-sm">SBOM (CycloneDX-free)</div>
          {sbom && (
            <div className="mt-2">
              <div className="text-xs text-slate-400">{sbom.bomFormat} {sbom.specVersion} • {sbom.components.length} components</div>
              <div className="mt-2 space-y-1 max-h-[300px] overflow-auto scrollbar">
                {sbom.components.map(c=>(
                  <div key={c.name} className="glass rounded-lg px-2 py-1.5 flex justify-between text-xs"><span><b>{c.name}</b> {c.version}</span><span className="text-slate-400">{c.type}</span></div>
                ))}
              </div>
              <div className="text-[11px] text-slate-500 mt-2">{sbom.note}</div>
            </div>
          )}
        </Card>
        <Card>
          <div className="font-bold text-sm flex items-center gap-2"><AlertTriangle size={14} className="text-amber-400"/> Anomaly ML (FREE)</div>
          {ano && (
            <div className="mt-2 text-sm space-y-2">
              <div className="glass rounded-lg p-2 flex justify-between"><span>Combined</span><b>{ano.combined_score}/10 — {ano.health}</b></div>
              <div className="text-xs"><b>Scan:</b> {ano.scan_anomaly.level} ({ano.scan_anomaly.anomaly_score}) — {ano.scan_anomaly.recommendation}</div>
              <div className="text-xs"><b>Graph:</b> {ano.graph_anomaly.level} — outliers {ano.graph_anomaly.structural_outliers?.length||0}</div>
              <pre className="mono text-xs bg-[#020617] border border-slate-800 rounded p-2 overflow-auto max-h-[180px]">{JSON.stringify(ano,null,2)}</pre>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
