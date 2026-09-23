import { useState } from 'react'
import { Brain, Sparkles, Copy } from 'lucide-react'

export default function AIInsights({ data, vuln }){
  const [tab,setTab]=useState('analysis')
  if(!data) return <div className="glass rounded-xl p-6 text-sm text-slate-400">Ask AI to explain findings — uses local free intelligence, upgrades to HuggingFace/OpenAI if keys set.</div>
  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="p-3 flex items-center gap-2 border-b border-slate-800">
        <Brain size={16} className="text-violet-400"/>
        <span className="font-bold text-sm">AI Security Analysis</span>
        <span className="text-xs bg-violet-500/20 text-violet-300 border border-violet-500/30 rounded-full px-2 py-1">{data.provider}</span>
        <span className="ml-auto text-xs text-slate-500">{data.local_kb_used? 'Local Intelligence (free)':'External LLM'}</span>
      </div>
      <div className="flex gap-1 p-2">
        {['analysis','fixes','suggestions'].map(t=>(
          <button key={t} onClick={()=>setTab(t)} className={`px-3 py-1.5 rounded-full text-xs font-bold border ${tab===t?'bg-violet-500 text-white border-violet-400':'glass text-slate-300'}`}>{t.toUpperCase()}</button>
        ))}
      </div>
      <div className="p-4 max-h-[420px] overflow-auto scrollbar">
        {tab==='analysis' && (
          <div className="prose prose-invert prose-sm max-w-none">
            <div className="whitespace-pre-wrap text-sm leading-6 text-slate-200">{data.answer}</div>
          </div>
        )}
        {tab==='fixes' && (
          <div className="space-y-3">
            {Object.entries(data.fix_snippets||{}).length? Object.entries(data.fix_snippets).map(([title,code])=>(
              <div key={title}>
                <div className="text-xs font-bold text-slate-300">{title}</div>
                <pre className="mt-1 bg-[#020617] border border-slate-800 rounded-lg p-3 text-xs overflow-auto">{code}</pre>
                <button onClick={()=>navigator.clipboard.writeText(code)} className="mt-1 inline-flex items-center gap-1 text-xs glass rounded-full px-2 py-1"><Copy size={12}/> Copy</button>
              </div>
            )) : <div className="text-sm text-slate-500">No code snippets — select a vuln to generate fix.</div>}
            {vuln?.remediation_code && (
              <div>
                <div className="text-xs font-bold">Recommended Fix — {vuln.title}</div>
                <pre className="mt-1 bg-[#020617] border border-slate-800 rounded-lg p-3 text-xs overflow-auto">{vuln.remediation_code}</pre>
              </div>
            )}
          </div>
        )}
        {tab==='suggestions' && (
          <div className="space-y-2">
            {data.suggestions?.map((s,i)=>(
              <div key={i} className="glass rounded-xl p-3 border border-slate-800">
                <div className="text-sm font-bold flex items-center gap-2"><Sparkles size={14} className="text-sky-400"/>{s.title}</div>
                <div className="text-xs text-slate-400 mt-1">{s.action} • Effort: {s.effort} • Risk reduction: {s.risk_reduction}</div>
              </div>
            ))}
            <div className="mt-2">
              <div className="text-xs font-bold text-slate-300">Follow-ups</div>
              <div className="flex flex-wrap gap-2 mt-2">
                {data.follow_ups?.map((q,i)=><span key={i} className="text-xs glass rounded-full px-3 py-1.5 border border-slate-700">{q}</span>)}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
