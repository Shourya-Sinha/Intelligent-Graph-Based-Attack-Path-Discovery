import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ShieldCheck, Radar, Share2, AlertTriangle, Activity, ArrowRight, Zap, Globe, Server, Bug } from 'lucide-react'
import { listScans } from '../lib/api'
import { Card, Stat } from '../components/ui/Card'
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar } from 'recharts'

export default function Dashboard(){
  const [scans,setScans]=useState([])
  useEffect(()=>{ listScans().then(setScans).catch(()=>{}) },[])
  const total = scans.length
  const critical = scans.reduce((a,s)=>a + (s.summary?.by_severity?.critical||0),0)
  const running = scans.filter(s=>s.status==='running').length
  const completed = scans.filter(s=>s.status==='completed').length

  const chartData = scans.slice(0,7).map(s=>({name: s.target.slice(0,12), vulns: s.summary?.total_vulns||0, risk: s.summary?.by_severity? (s.summary.by_severity.critical*25 + s.summary.by_severity.high*15) : 0}))
  const sevData = [
    {name:'Critical', value: scans.reduce((a,s)=>a+(s.summary?.by_severity?.critical||0),0)},
    {name:'High', value: scans.reduce((a,s)=>a+(s.summary?.by_severity?.high||0),0)},
    {name:'Medium', value: scans.reduce((a,s)=>a+(s.summary?.by_severity?.medium||0),0)},
    {name:'Low', value: scans.reduce((a,s)=>a+(s.summary?.by_severity?.low||0),0)},
  ]

  return (
    <div className="space-y-6">
      <motion.div initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} className="relative overflow-hidden rounded-[22px] bg-gradient-to-br from-sky-600 via-indigo-600 to-violet-700 p-[1px]">
        <div className="rounded-[20px] bg-[#0a1020] p-6 md:p-8 relative overflow-hidden">
          <div className="absolute -right-10 -top-10 w-64 h-64 bg-sky-500/20 blur-[60px] rounded-full"/>
          <div className="absolute -left-10 -bottom-10 w-64 h-64 bg-violet-500/20 blur-[60px] rounded-full"/>
          <div className="relative">
            <div className="inline-flex items-center gap-2 text-xs tracking-widest text-sky-300 font-bold"><Zap size={14}/> ADVANCED MODE • REAL-WORLD READY</div>
            <h1 className="text-3xl md:text-4xl font-black mt-2 leading-tight">Intelligent Graph-Based<br/><span className="bg-gradient-to-r from-sky-400 to-violet-400 bg-clip-text text-transparent">Attack Path Discovery</span></h1>
            <p className="text-slate-400 mt-3 max-w-2xl text-sm md:text-[15px]">Deep web & network scanner + Custom Risk Engine (FAIR + Monte Carlo + Centrality) + Attack Graph (NetworkX / Dijkstra) + Free Local AI + WebSocket Live • Build once, run continuously.</p>
            <div className="flex flex-wrap gap-3 mt-6">
              <Link to="/scanner" className="bg-white text-slate-900 font-extrabold rounded-full px-5 py-2.5 inline-flex items-center gap-2">Start Advanced Scan <ArrowRight size={16}/></Link>
              <Link to="/graph" className="glass rounded-full px-5 py-2.5 font-bold inline-flex items-center gap-2"><Share2 size={16}/> Explore Graph</Link>
              <span className="hidden md:inline-flex items-center gap-2 text-xs text-slate-400"><span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"/> WebSocket Realtime • CVE/CWE/OWASP/MITRE mapped</span>
            </div>
          </div>
        </div>
      </motion.div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Total Scans" value={total} sub={`${completed} completed • ${running} live`} icon={<Radar size={14}/>}/>
        <Stat label="Critical Vulns" value={critical} sub="Across all scans" icon={<AlertTriangle size={14} className="text-red-400"/>}/>
        <Stat label="Graph Coverage" value={`${scans.length? '● Active': '○ Idle'}`} sub="Dijkstra weighted paths" icon={<Share2 size={14}/>}/>
        <Stat label="Engine Status" value="v2.0" sub="FAIR + Monte Carlo" icon={<ShieldCheck size={14} className="text-emerald-400"/>}/>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <div className="font-bold text-sm">Vulnerabilities per Target</div>
            <span className="text-xs bg-slate-800 rounded-full px-2 py-1">Last {chartData.length} scans</span>
          </div>
          <div className="h-[220px] mt-3">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData.length? chartData: [{name:'example.com', vulns:5, risk:40},{name:'api.demo', vulns:2, risk:12}]}>
                <XAxis dataKey="name" tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                <YAxis tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                <Area type="monotone" dataKey="vulns" stroke="#0ea5e9" fill="rgba(14,165,233,0.25)" strokeWidth={2}/>
                <Area type="monotone" dataKey="risk" stroke="#8b5cf6" fill="rgba(139,92,246,0.18)" strokeWidth={2}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card>
          <div className="font-bold text-sm">Severity Distribution</div>
          <div className="h-[220px] mt-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData}>
                <XAxis dataKey="name" tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                <YAxis tick={{fontSize:10, fill:'#94a3b8'}} axisLine={false} tickLine={false}/>
                <Tooltip contentStyle={{background:'#0f172a', border:'1px solid #1e293b', borderRadius:12}}/>
                <Bar dataKey="value" fill="#0ea5e9" radius={[8,8,0,0]}/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card>
        <div className="flex items-center justify-between">
          <div className="font-bold text-sm flex items-center gap-2"><Activity size={16} className="text-sky-400"/> Recent Scans — Realtime via WebSocket</div>
          <Link to="/scanner" className="text-xs font-bold text-sky-400">View all →</Link>
        </div>
        <div className="mt-3 overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-[11px] tracking-widest text-slate-400 uppercase"><tr><th className="text-left p-2">Target</th><th>Mode</th><th>Status</th><th>Progress</th><th>Vulns</th><th>Risk</th></tr></thead>
            <tbody>
              {scans.slice(0,8).map(s=>(
                <tr key={s.job_id} className="border-t border-slate-800/60">
                  <td className="p-2.5"><div className="font-bold flex items-center gap-2"><Globe size={12} className="text-slate-500"/>{s.target}</div><div className="mono text-[11px] text-slate-500">{s.job_id}</div></td>
                  <td className="p-2.5"><span className="text-xs glass rounded-full px-2 py-1">{s.mode}</span></td>
                  <td className="p-2.5"><span className={`text-xs px-2 py-1 rounded-full font-bold ${s.status==='completed'?'bg-emerald-500 text-white': s.status==='running'?'bg-sky-500 text-white animate-pulse':'bg-slate-700 text-slate-300'}`}>{s.status}</span></td>
                  <td className="p-2.5"><div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-sky-500" style={{width:`${s.progress}%`}}/></div><span className="text-[11px] text-slate-500">{s.progress}%</span></td>
                  <td className="p-2.5"><span className="font-bold">{s.summary?.total_vulns ?? '-'}</span><span className="text-xs text-slate-500 ml-1">({s.summary?.by_severity?.critical||0} crit)</span></td>
                  <td className="p-2.5"><span className={`text-xs font-bold px-2 py-1 rounded-full ${ (s.summary?.by_severity?.critical||0)>0? 'bg-red-500 text-white':'bg-slate-700 text-slate-300'}`}>{s.summary?.risk_hint||'-'}</span></td>
                </tr>
              ))}
              {scans.length===0 && <tr><td colSpan={6} className="p-6 text-center text-slate-500">No scans yet — launch your first deep scan.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid md:grid-cols-3 gap-3">
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Bug size={16} className="text-red-400"/> Deep Bug Details</div>
          <div className="text-xs text-slate-400 mt-1">Every finding ships with CVSS, CWE, CVE, OWASP, MITRE ATT&CK, evidence, and one-click copy-paste fix (Nginx, code, WAF).</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Server size={16} className="text-sky-400"/> Own Risk Engine</div>
          <div className="text-xs text-slate-400 mt-1">Not a wrapper — custom engine built on NetworkX, PageRank, FAIR financial model, Monte Carlo 4k sims.</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Zap size={16} className="text-violet-400"/> Export Everything</div>
          <div className="text-xs text-slate-400 mt-1">JSON, CSV, HTML, PDF, SARIF — plug into Jira, GitHub, SIEM. Reports include graph + remediation roadmap.</div>
        </div>
      </div>
    </div>
  )
}
