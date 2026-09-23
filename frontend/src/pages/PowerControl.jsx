import { useEffect, useState } from 'react'
import { powerEngines, powerPresets, powerConfig, powerConfigSet, enterprisePower } from '../lib/api'
import EngineSelector from '../components/enterprise/EngineSelector'
import PowerMeter from '../components/enterprise/PowerMeter'
import { Card } from '../components/ui/Card'
import { Zap, Crown, Sliders, Rocket, Shield, Cpu } from 'lucide-react'

export default function PowerControl(){
  const [engines,setEngines]=useState([])
  const [config,setConfig]=useState(null)
  const [presets,setPresets]=useState(null)
  const [power,setPower]=useState(null)
  const [sel,setSel]=useState([])
  const [preset,setPreset]=useState('balanced')
  const [taskPower,setTaskPower]=useState({scanner:80,graph:75,risk:80,ai:70})
  const [powerhouse,setPowerhouse]=useState(false)
  const [isEnt,setIsEnt]=useState(false)

  const refresh = async()=>{
    const e = await powerEngines().catch(()=>({engines:[]}))
    setEngines(e.engines||[])
    setIsEnt(e.enterprise_unlocked)
    const c = await powerConfig().catch(()=>null)
    if(c){ setConfig(c.config); setSel(c.config.selected); setPreset(c.config.preset); setTaskPower(c.config.task_power); setPowerhouse(c.config.powerhouse) }
    const p = await powerPresets().catch(()=>null)
    if(p) setPresets(p.presets)
    const pow = await enterprisePower().catch(()=>null)
    if(pow) setPower(pow)
  }
  useEffect(()=>{ refresh() },[])

  const toggle = (id)=>{
    setSel(s=> s.includes(id) ? s.filter(x=>x!==id) : [...s, id])
    setPreset('custom')
  }
  const apply = async()=>{
    const res = await powerConfigSet({preset, selected: sel, task_power: taskPower, powerhouse})
    setConfig(res.config)
    setPower(res.power)
    // refresh presets unlock
    refresh()
  }
  const selectPreset = async(k)=>{
    setPreset(k)
    // load preset engines locally for preview
    if(presets && presets[k]){
      setSel(presets[k].engines)
      setPowerhouse(k==='turbo' || k==='overdrive')
    }
    // auto apply
    const res = await powerConfigSet({preset: k})
    setConfig(res.config)
    setSel(res.config.selected)
    setTaskPower(res.config.task_power)
    setPower(res.power)
    refresh()
  }
  const setSlider = (key, v)=>{
    const np = {...taskPower, [key]: v}
    setTaskPower(np)
  }

  return (
    <div className="space-y-4">
      {/* Hero powerhouse banner */}
      <div className="rounded-[20px] p-[1px] bg-gradient-to-br from-sky-500 via-indigo-600 to-violet-600">
        <div className="rounded-[18px] bg-[#0a1020] p-6">
          <div className="flex flex-wrap items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-400 to-violet-600 grid place-items-center"><Rocket size={18} className="text-white"/></div>
            <div>
              <div className="font-black text-lg flex items-center gap-2">Powerhouse Control <span className="text-sky-400">• 45 Engines</span> <span className="hidden md:inline-flex items-center gap-1 text-xs bg-amber-500 text-white px-2 py-1 rounded-full"><Crown size={12}/> {isEnt ? 'ENTERPRISE' : 'FREE'}</span></div>
              <div className="text-xs text-slate-400">Tick / select how much power you want. More engines = more strength. Powerhouse toggles all 44 @ max.</div>
            </div>
            <div className="ml-auto flex items-center gap-2">
              <span className={`px-3 py-1.5 rounded-full text-xs font-black ${power?.is_enterprise ? 'bg-emerald-500 text-white' : 'bg-sky-500 text-white'}`}>{power ? `${power.level} ${power.total_power}/100` : '...'}</span>
              <button onClick={apply} className="px-4 py-2 rounded-full font-black bg-white text-slate-900 text-sm">Apply Power</button>
            </div>
          </div>
          <div className="mt-4 grid md:grid-cols-4 gap-2">
            <label className="flex items-center gap-2 glass rounded-full px-3 py-2 cursor-pointer">
              <input type="checkbox" checked={powerhouse} onChange={e=>setPowerhouse(e.target.checked)} className="accent-sky-500"/>
              <span className="text-sm font-bold flex items-center gap-1"><Zap size={14} className="text-sky-400"/> Powerhouse Mode</span>
              <span className="text-xs text-slate-400">all engines</span>
            </label>
            <div className="glass rounded-full px-3 py-2 text-xs flex items-center gap-2"><Shield size={14} className="text-emerald-400"/> FREE default $0 • enterprise auto if keys</div>
            <div className="glass rounded-full px-3 py-2 text-xs flex items-center gap-2"><Cpu size={14} className="text-violet-400"/> {engines.length} engines • 8 categories</div>
            <div className="glass rounded-full px-3 py-2 text-xs flex items-center gap-2"><Sliders size={14}/> Per-task sliders 0-100</div>
          </div>
        </div>
      </div>

      {/* Presets */}
      <Card>
        <div className="font-black text-sm flex items-center gap-2"><Rocket size={14} className="text-sky-400"/> Power Presets — choose strength for this project</div>
        <div className="grid md:grid-cols-3 lg:grid-cols-5 gap-3 mt-3">
          {presets && Object.entries(presets).map(([k,v])=>(
            <button key={k} onClick={()=>selectPreset(k)} disabled={!v.allowed} className={`text-left rounded-2xl p-4 border transition ${preset===k ? 'bg-sky-500/10 border-sky-500/40' : 'glass border-slate-700/60'} ${!v.allowed ? 'opacity-50 cursor-not-allowed' : 'hover:border-sky-500/30'}`}>
              <div className="font-black text-sm flex items-center gap-1">{v.name} {k==='overdrive' && <Crown size={12} className="text-amber-400"/>}</div>
              <div className="text-xs text-slate-400 mt-1 line-clamp-2">{v.desc}</div>
              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs font-black bg-slate-800 rounded-full px-2 py-1">{v.power_pct}% • {v.engines.length} eng</span>
                {preset===k && <span className="text-xs bg-sky-500 text-white rounded-full px-2 py-0.5 font-bold">active</span>}
              </div>
              {!v.allowed && <div className="text-xs text-amber-400 mt-1">{v.note}</div>}
            </button>
          ))}
        </div>
      </Card>

      {/* Per-task sliders */}
      <Card>
        <div className="font-black text-sm flex items-center gap-2"><Sliders size={14} className="text-violet-400"/> Strengthness Control — per-task power 0-100</div>
        <div className="grid md:grid-cols-4 gap-3 mt-3">
          {Object.entries(taskPower).map(([k,v])=>(
            <div key={k} className="glass rounded-xl p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold capitalize">{k}</span>
                <span className="text-xs font-black bg-slate-800 rounded-full px-2 py-1">{v}/100</span>
              </div>
              <input type="range" min={0} max={100} value={v} onChange={e=>setSlider(k, parseInt(e.target.value))} className="w-full mt-2 accent-sky-500"/>
              <div className="text-xs text-slate-500 mt-1">
                {k==='scanner' && 'More engines, deeper probes'}
                {k==='graph' && 'Dijkstra weight & centrality depth'}
                {k==='risk' && 'FAIR + Monte Carlo iterations'}
                {k==='ai' && 'KB vs LLM chain-of-thought'}
              </div>
            </div>
          ))}
        </div>
        <button onClick={apply} className="mt-3 px-4 py-2 rounded-full bg-sky-500 text-white font-bold text-sm">Save per-task power</button>
      </Card>

      {power && <PowerMeter power={power}/>}

      <Card>
        <EngineSelector engines={engines} selected={sel} onToggle={toggle} isEnterprise={isEnt}
          onSelectAll={()=>{ setSel(engines.filter(e=> !e.enterprise || isEnt).map(e=>e.id)); setPreset('custom') }}
          onClear={()=>{ setSel([]); setPreset('custom') }}
        />
        <div className="mt-3 flex flex-wrap gap-2">
          <button onClick={apply} className="px-5 py-2.5 rounded-full bg-white text-slate-900 font-black">Apply {sel.length} engines</button>
          <button onClick={()=>selectPreset('turbo')} className="px-5 py-2.5 rounded-full glass font-bold">⚡ Turbo all {engines.length}</button>
          <span className="text-xs text-slate-400 self-center">Changes affect next scan via global config — or send per-scan <code>engines</code> array.</span>
        </div>
      </Card>
    </div>
  )
}
