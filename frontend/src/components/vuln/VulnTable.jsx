import { useState } from 'react'
import { ShieldAlert, Copy, ExternalLink, Wrench } from 'lucide-react'

const sevStyle = {
  critical: "bg-red-500 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-emerald-500 text-white",
  info: "bg-slate-600 text-white"
}

export default function VulnTable({ vulns, onExplain }){
  const [filter,setFilter]=useState("all")
  const [q,setQ]=useState("")
  const list = vulns?.filter(v=>{
    if(filter!=="all" && v.severity!==filter) return false
    if(q && !(`${v.title} ${v.cwe} ${v.cve} ${v.description}`.toLowerCase().includes(q.toLowerCase()))) return false
    return true
  }) || []
  return (
    <div className="glass rounded-xl overflow-hidden">
      <div className="p-3 flex flex-wrap gap-2 items-center justify-between border-b border-slate-800">
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} className="text-sky-400"/>
          <span className="font-bold text-sm">Vulnerabilities</span>
          <span className="text-xs bg-slate-800 rounded-full px-2 py-1">{vulns?.length||0}</span>
        </div>
        <div className="flex items-center gap-2">
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search CWE, CVE, title…" className="glass rounded-full px-3 py-1.5 text-xs w-[180px] outline-none"/>
          <select value={filter} onChange={e=>setFilter(e.target.value)} className="glass rounded-full px-3 py-1.5 text-xs outline-none">
            <option value="all">All Sev</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>
      <div className="overflow-auto max-h-[560px] scrollbar">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-[#0f172a] text-[11px] tracking-widest text-slate-400 uppercase">
            <tr><th className="text-left p-2.5">Title</th><th>Sev</th><th>CVSS</th><th>CWE/CVE</th><th>Exploit</th><th>Fix</th></tr>
          </thead>
          <tbody>
            {list.map(v=>(
              <tr key={v.id} className="border-t border-slate-800/60 hover:bg-slate-800/30">
                <td className="p-2.5">
                  <div className="font-bold leading-tight">{v.title}</div>
                  <div className="text-xs text-slate-400 line-clamp-2">{v.description}</div>
                  {v.url && <a href={v.url} target="_blank" className="text-[11px] text-sky-400 inline-flex items-center gap-1">{v.url.slice(0,48)} <ExternalLink size={10}/></a>}
                  {v.evidence && <div className="mt-1 mono text-[11px] bg-[#020617] border border-slate-800 rounded px-2 py-1">{v.evidence.slice(0,120)}</div>}
                </td>
                <td className="p-2.5"><span className={`px-2 py-1 rounded-full text-xs font-bold ${sevStyle[v.severity]}`}>{v.severity}</span></td>
                <td className="p-2.5 font-mono font-bold">{v.cvss}</td>
                <td className="p-2.5 text-xs"><div>{v.cwe||'-'}</div><div className="text-sky-400">{v.cve||''}</div><div className="text-slate-500">{v.owasp||''}</div></td>
                <td className="p-2.5 text-xs"><span className={`px-2 py-1 rounded-full ${v.exploit_available?'bg-red-500/20 text-red-300 border border-red-500/30':'bg-slate-700 text-slate-300'}`}>{v.exploit_available?'Yes':'No'}</span><div className="text-[11px] text-slate-500">EPSS {v.epss}</div></td>
                <td className="p-2.5">
                  <div className="text-xs text-slate-300 line-clamp-3">{v.remediation}</div>
                  {v.remediation_code && <button onClick={()=>{
                    navigator.clipboard.writeText(v.remediation_code)
                  }} className="mt-1 inline-flex items-center gap-1 text-[11px] glass rounded-full px-2 py-1 hover:bg-slate-700"><Copy size={12}/> Copy fix</button>}
                  <button onClick={()=>onExplain?.(v)} className="mt-1 ml-1 inline-flex items-center gap-1 text-[11px] bg-sky-500 text-white rounded-full px-3 py-1"><Wrench size={12}/> Explain & Fix</button>
                </td>
              </tr>
            ))}
            {list.length===0 && <tr><td colSpan={6} className="p-8 text-center text-slate-500">No vulnerabilities match filter</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
