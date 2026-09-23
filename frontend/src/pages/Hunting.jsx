import { useEffect, useState } from 'react'
import { Crosshair, Shield, Search, Bug, Lock, Globe, Zap } from 'lucide-react'
import api from '../lib/api'

export default function Hunting(){
  const [queries,setQueries]=useState([])
  const [jobId,setJobId]=useState('')
  const [hits,setHits]=useState(null)
  const [policy,setPolicy]=useState(null)
  const [msg,setMsg]=useState('')

  useEffect(()=>{
    api.get('/api/hunt/queries').then(r=>setQueries(r.data.queries||[])).catch(()=>{})
  },[])

  async function runHunt(qid){
    if(!jobId) return setMsg('Enter a scan job_id first (from Scanner or Dashboard)')
    try{
      const r = await api.post(`/api/hunt/run/${jobId}?query_id=${qid}`)
      setHits(r.data); setMsg(`Hunt ${qid} → ${r.data.count} hits`)
    }catch(e){ setMsg(e.response?.data?.detail||e.message)}
  }
  async function loadPolicy(){
    if(!jobId) return setMsg('Enter job_id')
    try{
      const r = await api.get(`/api/zero-trust/policy/${jobId}`)
      setPolicy(r.data); setMsg(`Zero-trust: ${r.data.count} policies`)
    }catch(e){ setMsg(e.response?.data?.detail||e.message)}
  }

  return (
    <div className="space-y-6">
      <div className="rounded-2xl bg-gradient-to-br from-emerald-600 via-teal-600 to-cyan-600 p-6 text-white">
        <div className="flex items-center gap-3"><Crosshair className="w-7 h-7"/><h1 className="text-2xl font-black">Threat Hunting & Zero-Trust — FREE</h1><span className="ml-auto text-xs bg-white/20 px-3 py-1 rounded-full">121 ENGINES + HUNT</span></div>
        <p className="mt-2 text-white/90 text-sm max-w-3xl">Sigma-like queries run 100% locally on your scan + graph — no paid SIEM. Find shadow IT, crown-jewel paths, exposed secrets, weak TLS→WAF bypass, EOL libraries, API auth bypass. Zero-trust policies auto-generated per finding — apply via gateway/WAF/IaC. Autonomous healer applies them if fix_mode auto.</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex gap-2">
        <input value={jobId} onChange={e=>setJobId(e.target.value)} placeholder="Enter SCAN job_id e.g. SCAN-1060D642" className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-white"/>
        <button onClick={loadPolicy} className="px-4 py-2 bg-violet-600 hover:bg-violet-500 rounded-xl text-sm text-white font-bold flex items-center gap-2"><Lock size={14}/> Zero-Trust Policy</button>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Search className="w-4 h-4 text-emerald-400"/> Hunt Queries (FREE)</h3>
          <div className="mt-3 space-y-2">
            {queries.map(q=>(
              <div key={q.id} className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex items-center justify-between">
                <div>
                  <div className="text-sm font-bold text-white">{q.name} <span className="text-xs font-normal text-slate-400">{q.id}</span></div>
                  <div className="text-xs text-slate-400 mono">{q.query}</div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${q.severity==='critical'?'bg-red-500':q.severity==='high'?'bg-orange-500':'bg-slate-700'} text-white`}>{q.severity}</span>
                </div>
                <button onClick={()=>runHunt(q.id)} className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-xs text-white font-bold flex items-center gap-1"><Crosshair size={12}/> Hunt</button>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Bug className="w-4 h-4 text-cyan-400"/> Hunt Results</h3>
          {!hits && <div className="mt-3 p-6 text-center text-slate-500 text-sm">Pick a query → Hunt. Results are deterministic, local, $0. Feed from your last scan.</div>}
          {hits && (
            <div className="mt-3">
              <div className="text-sm font-bold text-white">Query {hits.query_id} — {hits.count} hits</div>
              <div className="mt-2 space-y-2 max-h-[320px] overflow-auto">
                {hits.hits.map((h,i)=>(
                  <div key={i} className="bg-slate-950 border border-slate-800 rounded-xl p-2 text-xs text-slate-300 mono whitespace-pre-wrap">{JSON.stringify(h,null,2)}</div>
                ))}
              </div>
            </div>
          )}
          {policy && (
            <div className="mt-4 border-t border-slate-800 pt-3">
              <div className="font-bold text-sm text-white flex items-center gap-2"><Shield size={14} className="text-violet-400"/> Zero-Trust Policies</div>
              <div className="mt-2 space-y-2">
                {policy.policies.map((p,i)=>(
                  <div key={i} className="bg-indigo-950/30 border border-violet-800/30 rounded-xl p-2">
                    <div className="text-xs font-bold text-violet-300 flex items-center gap-2"><Lock size={12}/>{p.control}</div>
                    <div className="text-xs text-slate-300 mt-1">{p.policy}</div>
                    <div className="text-xs text-slate-500 mono">enforce: {p.enforce}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-3">
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Zap size={14} className="text-amber-400"/> No SIEM needed</div>
          <div className="text-xs text-slate-400 mt-1">Queries run on scan store + graph (NetworkX) — 100% free, offline, no vendor.</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Globe size={14} className="text-sky-400"/> Shadow IT</div>
          <div className="text-xs text-slate-400 mt-1">Subdomain vs inventory diff, CT logs, favicon JARM — find unmanaged assets.</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="font-bold text-sm flex items-center gap-2"><Shield size={14} className="text-emerald-400"/> Zero-Trust</div>
          <div className="text-xs text-slate-400 mt-1">Policies per CWE → CSP, mTLS, allow-list, least privilege. Autonomous healer applies.</div>
        </div>
      </div>

      {msg && <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-sm text-emerald-300">{msg} <button onClick={()=>setMsg('')} className="ml-2 underline text-xs">dismiss</button></div>}
    </div>
  )
}
