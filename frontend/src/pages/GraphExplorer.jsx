import { useEffect, useState } from 'react'
import { listScans, getScanResults } from '../lib/api'
import AttackGraph from '../components/graph/AttackGraph'
import { Card } from '../components/ui/Card'
import { Share2, Target, Shield, Info } from 'lucide-react'

export default function GraphExplorer(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [graph,setGraph]=useState(null)
  const [scan,setScan]=useState(null)
  const [highlight,setHighlight]=useState([])
  const [selectedNode,setSelectedNode]=useState(null)

  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{ if(sel) getScanResults(sel).then(r=>{setGraph(r.graph); setScan(r.scan)}).catch(()=>{}) },[sel])

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <div className="font-bold flex items-center gap-2"><Share2 size={16} className="text-sky-400"/> Attack Graph Explorer</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
        </div>
        {graph && <div className="mt-2 text-xs text-slate-400">Nodes {graph.metrics.node_count} • Edges {graph.metrics.edge_count} • Density {graph.metrics.density?.toFixed(3)} • Critical paths {graph.critical_paths?.length||0}</div>}
      </Card>

      <div className="grid lg:grid-cols-[1.7fr_0.9fr] gap-4">
        <Card>
          {graph? <AttackGraph graph={graph} onSelectNode={setSelectedNode} highlightPath={highlight}/> : <div className="h-[520px] grid place-items-center text-slate-500">No graph — run a scan first</div>}
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-cyan-400 rounded-full inline-block mr-1"/>Entry</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-sky-400 rounded-full inline-block mr-1"/>Host</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-violet-400 rounded-full inline-block mr-1"/>Service</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-red-500 rounded-full inline-block mr-1"/>Vuln</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-orange-500 rounded-full inline-block mr-1"/>Privilege</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-yellow-500 rounded-full inline-block mr-1"/>User</span>
            <span className="glass rounded-full px-2 py-1"><span className="w-2 h-2 bg-red-600 rounded-full inline-block mr-1"/>Data</span>
          </div>
        </Card>
        <div className="space-y-3">
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><Target size={14} className="text-red-400"/> Critical Paths (Dijkstra Weighted)</div>
            <div className="mt-2 space-y-2 max-h-[260px] overflow-auto scrollbar">
              {graph?.critical_paths?.map((p,i)=>(
                <button key={i} onClick={()=>setHighlight(p.path)} className={`w-full text-left glass rounded-xl p-3 border hover:border-sky-500/40 ${highlight===p.path? 'border-sky-500 bg-sky-500/10':''}`}>
                  <div className="font-bold text-sm">{p.target_label}</div>
                  <div className="text-xs text-sky-400 mt-1">{p.path_labels.join(' → ')}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`text-[11px] px-2 py-0.5 rounded-full font-bold ${p.severity==='critical'?'bg-red-500 text-white': p.severity==='high'?'bg-orange-500 text-white':'bg-yellow-500 text-black'}`}>{p.severity} • {p.risk_score}/100</span>
                    <span className="text-[11px] text-slate-400">Exploit {p.exploitability}</span>
                  </div>
                </button>
              )) || <div className="text-xs text-slate-500">No critical paths</div>}
              {highlight.length>0 && <button onClick={()=>setHighlight([])} className="text-xs text-sky-400 mt-1">Clear highlight</button>}
            </div>
          </Card>
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><Info size={14} className="text-sky-400"/> Selected Node</div>
            {selectedNode? (
              <div className="mt-2 text-sm">
                <div className="font-bold">{selectedNode.label}</div>
                <div className="text-xs text-slate-400">ID: {selectedNode.id} • Type: {selectedNode.type} {selectedNode.severity? `• ${selectedNode.severity}`:''} {selectedNode.cvss? `• CVSS ${selectedNode.cvss}`:''}</div>
                <div className="mt-2 mono text-xs bg-[#020617] border border-slate-800 rounded p-2">{JSON.stringify(selectedNode,null,2)}</div>
              </div>
            ): <div className="text-xs text-slate-500 mt-2">Click a node in graph</div>}
          </Card>
          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><Shield size={14} className="text-violet-400"/> Graph Metrics</div>
            <pre className="mt-2 mono text-xs bg-[#020617] border border-slate-800 rounded p-2 overflow-auto max-h-[180px]">{JSON.stringify(graph?.metrics||{},null,2)}</pre>
          </Card>
        </div>
      </div>
    </div>
  )
}
