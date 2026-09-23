import { useEffect, useState } from 'react'
import { listScans, exportUrl, getScanResults } from '../lib/api'
import { Card } from '../components/ui/Card'
import { Download, FileText, FileJson, FileSpreadsheet, Shield, ExternalLink } from 'lucide-react'

export default function Reports(){
  const [scans,setScans]=useState([])
  const [sel,setSel]=useState(null)
  const [htmlPreview,setHtmlPreview]=useState("")

  useEffect(()=>{ listScans().then(s=>{setScans(s); if(s.length) setSel(s[0].job_id)}).catch(()=>{}) },[])
  useEffect(()=>{
    if(sel){
      fetch(exportUrl(sel,'html')).then(r=>r.text()).then(t=>setHtmlPreview(t.slice(0,1200))).catch(()=>{})
    }
  },[sel])

  const formats = [
    {id:'json', label:'JSON', icon:FileJson, desc:'Machine-readable • CI/CD, Jira, SIEM'},
    {id:'csv', label:'CSV', icon:FileSpreadsheet, desc:'Spreadsheet • Excel, Sheets'},
    {id:'html', label:'HTML', icon:FileText, desc:'Interactive report • Share with team'},
    {id:'pdf', label:'PDF', icon:Shield, desc:'Executive + technical • Print ready'},
    {id:'sarif', label:'SARIF', icon:FileText, desc:'GitHub Code Scanning • DevSecOps'},
  ]

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-3">
          <div className="font-bold">Reports & Export — Full Data Package</div>
          <select value={sel||''} onChange={e=>setSel(e.target.value)} className="ml-auto glass rounded-full px-3 py-1.5 text-sm outline-none">
            {scans.map(s=> <option key={s.job_id} value={s.job_id}>{s.target} — {s.job_id}</option>)}
          </select>
        </div>
        <div className="text-xs text-slate-400 mt-1">Export with all details: vulnerabilities, graph, risk, Monte Carlo, compliance, fix code. Single click.</div>
      </Card>

      <div className="grid md:grid-cols-3 lg:grid-cols-5 gap-3">
        {formats.map(f=>(
          <a key={f.id} href={sel? exportUrl(sel,f.id):'#'} target="_blank" className="glass rounded-xl p-4 hover:shadow-glow transition group">
            <f.icon size={20} className="text-sky-400"/>
            <div className="font-bold mt-2">{f.label}</div>
            <div className="text-xs text-slate-400 mt-1">{f.desc}</div>
            <span className="mt-3 inline-flex items-center gap-1 text-xs bg-sky-500 text-white rounded-full px-3 py-1 font-bold group-hover:bg-sky-400"><Download size={12}/> Download</span>
          </a>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <div className="font-bold text-sm">HTML Preview (first 1200 chars)</div>
          <pre className="mt-2 bg-[#020617] border border-slate-800 rounded-lg p-3 text-[11px] overflow-auto h-[320px] whitespace-pre-wrap">{htmlPreview || 'Select a scan'}</pre>
          {sel && <a href={exportUrl(sel,'html')} target="_blank" className="mt-2 inline-flex items-center gap-1 text-xs text-sky-400">Open full HTML <ExternalLink size={12}/></a>}
        </Card>
        <Card>
          <div className="font-bold text-sm">What’s inside every export</div>
          <ul className="mt-2 text-sm space-y-2">
            <li className="glass rounded-lg px-3 py-2"><b>Scan metadata:</b> target, mode, duration, tech fingerprint, ports, subdomains, directories, headers, TLS</li>
            <li className="glass rounded-lg px-3 py-2"><b>Vulnerabilities:</b> title, severity, CVSS, CWE, CVE, OWASP, MITRE, URL, param, evidence, description, impact, remediation + code, confidence, EPSS</li>
            <li className="glass rounded-lg px-3 py-2"><b>Attack Graph:</b> nodes/edges, weighted paths, critical paths, betweenness, PageRank, density</li>
            <li className="glass rounded-lg px-3 py-2"><b>Risk Engine:</b> overall risk, exposure, FAIR financial, compliance (OWASP/NIST/PCI/ISO), Monte Carlo, recommendations with fix snippets</li>
            <li className="glass rounded-lg px-3 py-2"><b>AI:</b> explanations, prioritization, follow-ups — all reproducible</li>
          </ul>
          <div className="mt-3 text-xs text-slate-500">Use SARIF to auto-create GitHub Security alerts. Use PDF for board-ready reporting with cover page, executive summary, and remediation roadmap.</div>
        </Card>
      </div>
    </div>
  )
}
