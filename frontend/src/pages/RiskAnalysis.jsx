import { useEffect, useState } from 'react'
import { listScans, getScanResults, riskAnalyze } from '../lib/api'
import RiskMatrix from '../components/risk/RiskMatrix'
import { Card } from '../components/ui/Card'
import { ShieldAlert, TrendingUp, BarChart3 } from 'lucide-react'
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, LineChart, Line } from 'recharts'

export default function RiskAnalysis(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [risk,setRisk]=useState(null)
  const [loading,setLoading]=useState(false)
  const [scan,setScan]=useState(null)
  const [graph,setGraph]=useState(null)

  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{
    if(sel){
      getScanResults(sel).then(r=>{setScan(r.scan); setGraph(r.graph); setRisk(r.risk)}).catch(()=>{})
    }
  },[sel])

  const run = async ()=>{
    setLoading(true)
    try{
      const r = await riskAnalyze({job_id: sel})
      setRisk(r)
    }catch(e){ alert(e.message)} finally{ setLoading(false)}
  }

  const pieData = risk ? Object.entries(risk.compliance).map(([k,v])=>({name:k, value:v.score})) : []
  const COLORS = ["#0ea5e9","#6366f1","#8b5cf6","#ec4899","#f97316"]

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <div className="font-bold flex items-center gap-2"><ShieldAlert size={16} className="text-sky-400"/> Risk Engine — FAIR + Monte Carlo + Graph Centrality</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
          <button onClick={run} disabled={loading || !sel} className="bg-sky-500 text-white font-bold rounded-full px-4 py-1.5 text-sm disabled:opacity-60">{loading? 'Analyzing…':'Re-run Risk Engine'}</button>
        </div>
        <div className="mt-2 text-xs text-slate-400">Own engine — not a wrapper. Quantifies likelihood × impact, maps MITRE & OWASP, outputs financial exposure. Every run is deterministic + seeded Monte Carlo.</div>
      </Card>

      <RiskMatrix risk={risk}/>

      {risk && (
        <>
          <div className="grid lg:grid-cols-2 gap-4">
            <Card>
              <div className="font-bold text-sm flex items-center gap-2"><BarChart3 size={14}/> Node Criticality (PageRank + Betweenness)</div>
              <div className="h-[240px] mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={risk.node_criticality.slice(0,8).map(n=>({name: n.label.slice(0,14), score: n.criticality_score}))} layout="vertical">
                    <XAxis type="number" domain={[0,100]} tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                    <YAxis dataKey="name" type="category" width={110} tick={{fontSize:10, fill:'#e2e8f0'}} axisLine={false} tickLine={false}/>
                    <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                    <Bar dataKey="score" fill="#0ea5e9" radius={[0,8,8,0]}/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card>
              <div className="font-bold text-sm">Path Risk vs Likelihood</div>
              <div className="h-[240px] mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={risk.path_risks.map(p=>({name: p.target_label.slice(0,12), risk: p.risk_score, likelihood: p.likelihood*100}))}>
                    <XAxis dataKey="name" tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                    <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                    <Bar dataKey="risk" fill="#f43f5e" radius={[8,8,0,0]} name="Risk"/>
                    <Bar dataKey="likelihood" fill="#22c55e" radius={[8,8,0,0]} name="Likelihood %"/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>

          <Card>
            <div className="font-bold text-sm flex items-center gap-2"><TrendingUp size={14}/> Monte Carlo Loss Distribution (4000 simulations)</div>
            <div className="h-[180px] mt-3">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={risk.monte_carlo.histogram.map((v,i)=>({bin:`B${i+1}`, loss: v}))}>
                  <XAxis dataKey="bin" tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                  <YAxis tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                  <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                  <Line type="monotone" dataKey="loss" stroke="#8b5cf6" strokeWidth={2} dot={false}/>
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 grid grid-cols-4 gap-2 text-xs">
              <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">Expected</div><div className="font-bold">${risk.monte_carlo.expected_loss.toLocaleString()}</div></div>
              <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">P90</div><div className="font-bold">${risk.monte_carlo.p90_loss.toLocaleString()}</div></div>
              <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">P95</div><div className="font-bold">${risk.monte_carlo.p95_loss.toLocaleString()}</div></div>
              <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">Max</div><div className="font-bold">${risk.monte_carlo.max_loss.toLocaleString()}</div></div>
            </div>
          </Card>

          <div className="grid lg:grid-cols-2 gap-4">
            <Card>
              <div className="font-bold text-sm">Compliance Posture</div>
              <div className="h-[220px] mt-2">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={80} label={({name,value})=>`${name} ${value}` }>
                      {pieData.map((_,i)=><Cell key={i} fill={COLORS[i%COLORS.length]}/>)}
                    </Pie>
                    <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card>
              <div className="font-bold text-sm">Prioritized Remediation Roadmap</div>
              <div className="mt-2 space-y-2 max-h-[260px] overflow-auto scrollbar">
                {risk.recommendations.map((r,i)=>(
                  <div key={i} className="glass rounded-xl p-3 border border-slate-800">
                    <div className="font-bold text-sm">{r.priority} — {r.title}</div>
                    <div className="text-xs text-slate-400 mt-1">{r.action}</div>
                    {r.code && <pre className="mt-2 mono text-[11px] bg-[#020617] border border-slate-800 rounded p-2 overflow-auto max-h-[90px]">{r.code}</pre>}
                    <div className="mt-1 flex gap-2 text-[11px]"><span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full px-2 py-0.5">Effort: {r.effort}</span><span className="bg-sky-500/20 text-sky-300 border border-sky-500/30 rounded-full px-2 py-0.5">Δ Risk -{r.estimated_risk_reduction}</span></div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
