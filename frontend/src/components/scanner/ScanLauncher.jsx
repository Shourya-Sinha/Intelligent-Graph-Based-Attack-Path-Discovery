import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Rocket, Shield, ScanEye, Globe, Zap, Crown } from 'lucide-react'
import { startScan, powerPresets, powerConfig } from '../../lib/api'
import { Link } from 'react-router-dom'

export default function ScanLauncher({ onStarted }){
  const [target,setTarget]=useState("https://example.com")
  const [mode,setMode]=useState("advance")
  const [depth,setDepth]=useState(2)
  const [loading,setLoading]=useState(false)
  const [opts,setOpts]=useState({subdomain:true, port:true, dir:true, vuln:true, graph:true, ai:true})
  const [preset,setPreset]=useState(null)
  const [presets,setPresets]=useState(null)
  const [cfg,setCfg]=useState(null)
  const [powerhouse,setPowerhouse]=useState(false)
  useEffect(()=>{ powerPresets().then(setPresets).catch(()=>{}); powerConfig().then(setCfg).catch(()=>{}) },[])
  useEffect(()=>{ if(cfg && !preset) setPreset(cfg.config?.preset||'balanced') },[cfg])

  const launch = async () => {
    setLoading(true)
    try{
      const payload = {
        target, mode, depth,
        enable_subdomain_enum: opts.subdomain,
        enable_port_scan: opts.port,
        enable_dir_bruteforce: opts.dir,
        enable_vuln_scan: opts.vuln,
        enable_graph_build: opts.graph,
        enable_ai_analysis: opts.ai,
        power_preset: preset,
        powerhouse
      }
      const res = await startScan(payload)
      onStarted?.(res.job_id)
    } catch(e){ alert(e?.response?.data?.detail || e.message) }
    finally{ setLoading(false) }
  }

  return (
    <div className="glass rounded-[20px] p-5 md:p-6">
      <div className="flex items-center gap-2 text-sky-300 font-bold tracking-wide text-sm"><Rocket size={16}/> ADVANCED SCAN LAUNCHER</div>
      <h3 className="text-xl font-extrabold mt-1">Intelligent Deep Scan</h3>
      <p className="text-slate-400 text-sm mt-1">Graph-based discovery • Zero-config recon • Real-time websocket</p>

      <div className="grid md:grid-cols-[1.2fr_0.8fr] gap-4 mt-5">
        <div>
          <label className="text-[11px] tracking-widest text-slate-400 uppercase">Target URL / IP / Domain</label>
          <div className="mt-1 flex items-center gap-2 glass rounded-xl px-3 py-2.5">
            <Globe size={16} className="text-slate-500"/>
            <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="https://app.example.com" className="flex-1 bg-transparent outline-none text-sm"/>
          </div>
          <div className="grid grid-cols-3 gap-2 mt-3">
            {["quick","advance","comprehensive"].map(m=>(
              <button key={m} onClick={()=>setMode(m)} className={`rounded-xl px-3 py-2.5 text-xs font-bold border ${mode===m? 'bg-sky-500 text-white border-sky-400 shadow-glow':'glass text-slate-300 border-transparent'}`}>{m.toUpperCase()}</button>
            ))}
          </div>
          <div className="flex items-center gap-2 mt-3">
            <span className="text-xs text-slate-400">Depth</span>
            <input type="range" min={1} max={5} value={depth} onChange={e=>setDepth(parseInt(e.target.value))} className="flex-1 accent-sky-500"/>
            <span className="mono text-xs bg-slate-800 rounded px-2 py-1">{depth}</span>
          </div>
          <div className="mt-3 p-2.5 rounded-xl bg-gradient-to-br from-sky-500/10 to-violet-500/10 border border-sky-500/20">
            <div className="text-xs font-black flex items-center gap-2"><Zap size={12} className="text-sky-400"/> Power for this scan</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {presets && Object.keys(presets.presets).map(k=>{
                const v=presets.presets[k]
                return <button key={k} onClick={()=>setPreset(k)} className={`px-2.5 py-1 rounded-full text-xs font-bold border ${preset===k ? 'bg-sky-500 text-white border-sky-400' : 'glass border-slate-700'}`}>{k} • {v.power_pct}%</button>
              })}
            </div>
            <label className="flex items-center gap-2 mt-2 text-xs font-bold cursor-pointer">
              <input type="checkbox" checked={powerhouse} onChange={e=>setPowerhouse(e.target.checked)} className="accent-sky-500"/>
              <span className="flex items-center gap-1"><Crown size={12} className="text-amber-400"/> Powerhouse — all {cfg? cfg.config.selected.length : '45'} engines @ max <span className="text-slate-400">(tick for max strength)</span></span>
            </label>
            <div className="text-[11px] text-slate-400 mt-1">Global preset <b>{cfg?.config?.preset}</b> • {cfg?.config?.selected?.length} engines • <Link to="/power" className="text-sky-400 underline">Customize powerhouse → Power Control</Link></div>
          </div>
        </div>
        <div className="glass rounded-xl p-3">
          <div className="text-xs font-bold text-slate-300">Modules</div>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {[
              ["subdomain","Subdomain Enum"],
              ["port","Port Scan"],
              ["dir","Dir Bruteforce"],
              ["vuln","Vuln Probe"],
              ["graph","Graph Build"],
              ["ai","AI Analysis"],
            ].map(([k,label])=>(
              <label key={k} className="flex items-center gap-2 text-xs bg-slate-800/60 rounded-lg px-2 py-2 border border-slate-700/60 cursor-pointer">
                <input type="checkbox" checked={opts[k]} onChange={e=>setOpts({...opts,[k]:e.target.checked})} className="accent-sky-500"/>
                {label}
              </label>
            ))}
          </div>
          <motion.button whileTap={{scale:0.98}} onClick={launch} disabled={loading} className="w-full mt-3 bg-gradient-to-br from-sky-500 to-indigo-600 text-white font-extrabold rounded-xl py-3 shadow-glow disabled:opacity-60 flex items-center justify-center gap-2">
            <ScanEye size={18}/> {loading? 'Launching…':'Launch Deep Scan'}
          </motion.button>
          <div className="text-[11px] text-slate-500 mt-2 flex items-center gap-1"><Shield size={12}/> Authorized testing only — respects rate limits</div>
        </div>
      </div>
    </div>
  )
}
