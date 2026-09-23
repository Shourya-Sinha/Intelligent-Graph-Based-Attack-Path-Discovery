import { useEffect, useState } from 'react'
import { listScans, enterprisePower } from '../../lib/api'
import { Activity, Search, Zap, Crown } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function Topbar(){
  const [q,setQ]=useState("")
  const [scans,setScans]=useState([])
  const [power,setPower]=useState(null)
  useEffect(()=>{ listScans().then(setScans).catch(()=>{}); enterprisePower().then(setPower).catch(()=>{}) },[])
  const live = scans.filter(s=>s.status==='running').length
  return (
    <div className="sticky top-0 z-30 backdrop-blur-xl bg-[#070b18]/70 border-b border-slate-800/60">
      <div className="max-w-[1400px] mx-auto flex items-center gap-3 px-4 py-3">
        <div className="lg:hidden font-black">AG v2</div>
        <div className="flex items-center gap-2 text-sm">
          <span className="hidden sm:inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/20"><span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"/> Engine Operational</span>
          <span className="hidden md:inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-sky-500/15 text-sky-300 border border-sky-500/20"><Activity size={14}/> {live} live scans</span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {power && (
            <Link to="/enterprise" className={`hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black border ${power.is_enterprise ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' : 'bg-slate-500/10 text-slate-300 border-slate-500/20'}`}>
              {power.is_enterprise ? <Crown size={12} className="text-amber-400"/> : <Zap size={12} className="text-sky-400"/>}
              {power.level} {power.total_power}/100 → Enterprise Power
            </Link>
          )}
          <div className="hidden md:flex items-center gap-2 glass rounded-full px-3 py-1.5">
            <Search size={14} className="text-slate-400"/>
            <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search target, CVE, path…" className="bg-transparent outline-none text-sm w-[260px] placeholder:text-slate-500"/>
          </div>
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-violet-500 to-sky-500 grid place-items-center font-bold text-sm">S</div>
        </div>
      </div>
    </div>
  )
}
