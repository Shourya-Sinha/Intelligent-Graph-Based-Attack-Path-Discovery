import { useState, useMemo } from 'react'
import { Crown, Zap, Check, Lock } from 'lucide-react'

export default function EngineSelector({ engines=[], selected=[], onToggle, onSelectAll, onClear, isEnterprise=false, compact=false }){
  const categories = useMemo(()=> {
    const cats={}
    engines.forEach(e=>{
      if(!cats[e.category]) cats[e.category]=[]
      cats[e.category].push(e)
    })
    return cats
  },[engines])
  const totalPower = engines.reduce((a,e)=>a+e.power,0)
  const selPower = engines.filter(e=> selected.includes(e.id)).reduce((a,e)=>a+e.power,0)
  const selCount = selected.length
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="text-sm font-black">Select Power Engines <span className="text-sky-400">{selCount}/{engines.length}</span> — Power {selPower}/{totalPower} ({Math.round(selPower/totalPower*100)||0}%)</div>
        <div className="flex gap-2">
          <button onClick={onSelectAll} className="px-3 py-1.5 rounded-full text-xs font-bold bg-sky-500 text-white">Select all FREE</button>
          <button onClick={onClear} className="px-3 py-1.5 rounded-full text-xs font-bold glass">Clear</button>
        </div>
      </div>
      {Object.entries(categories).map(([cat, list])=>(
        <div key={cat} className="glass rounded-xl p-3">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs font-black tracking-widest uppercase text-slate-300">{cat}</span>
            <span className="text-xs bg-slate-800 rounded-full px-2 py-0.5">{list.length}</span>
            <span className="text-xs text-slate-500">• power {list.reduce((a,e)=>a+e.power,0)}</span>
          </div>
          <div className={`grid gap-2 ${compact ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1 md:grid-cols-2 xl:grid-cols-3'}`}>
            {list.map(e=>{
              const on = selected.includes(e.id)
              const locked = e.enterprise && !isEnterprise
              return (
                <label key={e.id} className={`flex items-start gap-2 p-2.5 rounded-xl border cursor-pointer transition ${on ? 'bg-sky-500/10 border-sky-500/30' : 'bg-slate-800/50 border-slate-700/60'} ${locked ? 'opacity-60' : ''}`}>
                  <input type="checkbox" checked={on} disabled={locked} onChange={()=>onToggle(e.id)} className="mt-1 accent-sky-500"/>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm font-bold truncate">{e.name}</span>
                      <span className={`w-5 h-5 rounded-full grid place-items-center text-xs font-black ${locked ? 'bg-amber-500 text-white' : on ? 'bg-sky-500 text-white' : 'bg-slate-700 text-slate-300'}`}>+{e.power}</span>
                      {e.enterprise ? <Crown size={12} className="text-amber-400"/> : null}
                      {locked ? <Lock size={12} className="text-amber-400"/> : null}
                      {on ? <Check size={12} className="text-emerald-400"/> : null}
                    </div>
                    <div className="text-xs text-slate-400 leading-tight truncate" title={e.desc}>{e.desc}</div>
                    <div className="text-[11px] text-slate-500">{e.tier} • {e.enterprise ? 'enterprise' : 'free'}</div>
                  </div>
                </label>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
