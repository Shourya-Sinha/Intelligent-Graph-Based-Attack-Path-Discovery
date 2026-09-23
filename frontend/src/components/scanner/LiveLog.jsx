import { useEffect, useRef } from 'react'

export default function LiveLog({ logs, progress, stage }){
  const ref = useRef(null)
  useEffect(()=>{ if(ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [logs])
  return (
    <div className="glass rounded-xl p-3">
      <div className="flex items-center justify-between">
        <div className="text-xs font-bold tracking-widest text-slate-400 uppercase">{stage || 'LIVE LOG'}</div>
        <div className="text-xs mono bg-slate-800 rounded-full px-2 py-1">{progress ?? 0}%</div>
      </div>
      <div className="mt-2 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className="h-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all" style={{width: `${progress||0}%`}} />
      </div>
      <div ref={ref} className="mt-3 h-[220px] overflow-auto scrollbar bg-[#020617] rounded-lg p-3 mono text-[11px] leading-5 text-slate-300 border border-slate-800">
        {logs?.length? logs.map((l,i)=><div key={i} className="whitespace-pre-wrap"><span className="text-slate-500">[{String(i+1).padStart(2,'0')}]</span> {l}</div>) : <div className="text-slate-500">Waiting for scan events… websocket will stream here in real time.</div>}
      </div>
    </div>
  )
}
