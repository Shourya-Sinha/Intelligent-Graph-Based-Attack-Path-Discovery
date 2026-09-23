import { useEffect, useState } from 'react'
import { Zap, Shield, Cpu, Database, Brain, Globe } from 'lucide-react'

export default function PowerMeter({ power }){
  if(!power) return <div className="glass rounded-xl p-6 text-slate-400">Loading power...</div>
  const pct = power.total_power
  const color = power.color
  const circumference = 2 * Math.PI * 70
  const offset = circumference - (pct/100)*circumference
  return (
    <div className="glass rounded-[22px] p-6">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-400 to-indigo-600 grid place-items-center"><Zap size={18} className="text-white"/></div>
        <div>
          <div className="font-black">Enterprise Power Meter</div>
          <div className="text-xs text-slate-400">Shows how powerful your system is — FREE vs ENTERPRISE</div>
        </div>
        <span className="ml-auto px-3 py-1.5 rounded-full text-xs font-black" style={{background: color, color: power.level==='FREE' ? 'black':'white'}}>{power.level} {pct}/100</span>
      </div>
      <div className="grid md:grid-cols-[220px_1fr] gap-6 mt-6 items-center">
        <div className="relative w-[200px] h-[200px] mx-auto">
          <svg width="200" height="200" className="transform -rotate-90">
            <circle cx="100" cy="100" r="70" stroke="#1e293b" strokeWidth="14" fill="none"/>
            <circle cx="100" cy="100" r="70" stroke={color} strokeWidth="14" fill="none" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} style={{transition: 'stroke-dashoffset 1s ease'}}/>
          </svg>
          <div className="absolute inset-0 grid place-items-center">
            <div className="text-center">
              <div className="text-4xl font-black" style={{color}}>{pct}</div>
              <div className="text-xs tracking-widest text-slate-400 uppercase">{power.tier}</div>
              <div className="text-xs text-slate-500">{power.is_enterprise ? 'Enterprise Unlocked' : 'Free (default, $0)'}</div>
            </div>
          </div>
        </div>
        <div className="space-y-2">
          {Object.entries(power.components).map(([k,v])=>(
            <div key={k} className="glass rounded-xl p-3 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-slate-800 grid place-items-center">
                {k==='ai' && <Brain size={14} className="text-violet-400"/>}
                {k==='scanner' && <Globe size={14} className="text-sky-400"/>}
                {k==='graph' && <Database size={14} className="text-emerald-400"/>}
                {k==='risk' && <Shield size={14} className="text-amber-400"/>}
                {k==='enterprise' && <Zap size={14} className="text-yellow-400"/>}
                {k==='infra' && <Cpu size={14} className="text-slate-400"/>}
              </div>
              <div className="flex-1">
                <div className="text-sm font-bold capitalize flex items-center gap-2">{k} <span className="text-xs text-slate-400">{v.score}/{v.max}</span></div>
                <div className="text-xs text-slate-400">{v.label}</div>
              </div>
              <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full" style={{width: `${(v.score/v.max)*100}%`, background: color}}/>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-6">
        <div className="font-bold text-sm flex items-center gap-2"><Zap size={14} className="text-emerald-400"/> How to Increase Power</div>
        <div className="mt-2 grid md:grid-cols-2 gap-2">
          {power.recommendations?.map((r,i)=>(
            <div key={i} className={`rounded-xl p-3 border flex items-start gap-2 ${r.free ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-sky-500/10 border-sky-500/20'}`}>
              <span className={`px-2 py-1 rounded-full text-xs font-bold ${r.free ? 'bg-emerald-500 text-white' : 'bg-sky-500 text-white'}`}>{r.gain}</span>
              <div className="flex-1">
                <div className="text-sm font-bold">{r.action}</div>
                <div className="text-xs text-slate-400">Cost: {r.cost} {r.free && '• FREE'}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 text-xs text-slate-500 bg-slate-800/50 rounded-lg p-2">
          <b>Scale:</b> Free: {power.scale.free_capacity} • Enterprise: {power.scale.enterprise_capacity} • <b>How:</b> {power.scale.how_to_scale}
        </div>
      </div>
    </div>
  )
}
