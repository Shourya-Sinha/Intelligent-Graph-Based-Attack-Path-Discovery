import { useEffect, useState } from 'react'
import ScanLauncher from '../components/scanner/ScanLauncher'
import LiveLog from '../components/scanner/LiveLog'
import VulnTable from '../components/vuln/VulnTable'
import { getScanResults, listScans } from '../lib/api'
import { useScanWebSocket, useGlobalWebSocket } from '../hooks/useWebSocket'
import { Card } from '../components/ui/Card'
import { Activity, Download, Share2, Brain, ShieldAlert } from 'lucide-react'
import { aiExplain, exportUrl } from '../lib/api'
import AIInsights from '../components/ai/AIInsights'

export default function Scanner(){
  const [jobId,setJobId]=useState(null)
  const [scan,setScan]=useState(null)
  const [graph,setGraph]=useState(null)
  const [risk,setRisk]=useState(null)
  const [logs,setLogs]=useState([])
  const [progress,setProgress]=useState(0)
  const [stage,setStage]=useState("Idle")
  const [aiData,setAiData]=useState(null)
  const [scans,setScans]=useState([])

  const refreshList = () => listScans().then(setScans).catch(()=>{})
  useEffect(()=>{ refreshList() },[])

  useGlobalWebSocket((msg)=>{
    if(msg.type==='scan_completed_global') refreshList()
  })

  useScanWebSocket(jobId, (msg)=>{
    if(msg.type==='scan_progress'){
      setProgress(msg.progress)
      setStage(msg.stage)
      setLogs(prev=>[...prev, `[${msg.stage} ${msg.progress}%] ${msg.log}`].slice(-120))
    }
    if(msg.type==='graph_ready'){
      // will be fetched via polling
    }
    if(msg.type==='scan_completed'){
      fetchResults(jobId)
      refreshList()
    }
    if(msg.type==='init' && msg.scan){
      setScan(msg.scan)
      setProgress(msg.scan.progress)
      setStage(msg.scan.current_stage)
      if(msg.graph) setGraph(msg.graph)
    }
  })

  const fetchResults = async (id) => {
    try{
      const r = await getScanResults(id)
      setScan(r.scan); setGraph(r.graph); setRisk(r.risk)
      setProgress(r.scan.progress); setStage(r.scan.current_stage)
      if(r.scan.logs) setLogs(r.scan.logs)
    }catch(e){ console.error(e)}
  }

  useEffect(()=>{
    if(jobId) {
      fetchResults(jobId)
      const iv = setInterval(()=>fetchResults(jobId), 3000)
      return ()=>clearInterval(iv)
    }
  },[jobId])

  const handleExplain = async (vuln) => {
    try{
      const res = await aiExplain({job_id: jobId, vuln_id: vuln.id})
      setAiData(res)
      // scroll to ai
      document.getElementById('ai-panel')?.scrollIntoView({behavior:'smooth'})
    }catch(e){ alert(e.message)}
  }

  return (
    <div className="space-y-4">
      <ScanLauncher onStarted={setJobId}/>

      {jobId && (
        <div className="grid lg:grid-cols-[1.1fr_0.9fr] gap-4">
          <LiveLog logs={logs} progress={progress} stage={stage}/>
          <Card>
            <div className="flex items-center justify-between">
              <div className="font-bold text-sm">Scan: {scan?.target || jobId}</div>
              <span className={`text-xs px-2 py-1 rounded-full font-bold ${scan?.status==='completed'?'bg-emerald-500 text-white':'bg-sky-500 text-white animate-pulse'}`}>{scan?.status||'running'}</span>
            </div>
            {scan && (
              <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">Vulns</div><div className="text-lg font-black">{scan.summary?.total_vulns ?? scan.vulnerabilities?.length ?? 0}</div></div>
                <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">Ports</div><div className="text-lg font-black">{scan.ports?.length||0}</div></div>
                <div className="glass rounded-lg p-2 text-center"><div className="text-slate-400">Techs</div><div className="text-lg font-black">{scan.technologies?.length||0}</div></div>
              </div>
            )}
            <div className="mt-3">
              <div className="text-xs font-bold text-slate-300">Technologies</div>
              <div className="flex flex-wrap gap-1 mt-1">{scan?.technologies?.map(t=> <span key={t.name} className="text-xs glass rounded-full px-2 py-1">{t.name}{t.version? ` ${t.version}`:''}</span>) || <span className="text-xs text-slate-500">Detecting…</span>}</div>
            </div>
            <div className="mt-3">
              <div className="text-xs font-bold text-slate-300">Headers & TLS</div>
              <div className="mono text-[11px] bg-[#020617] border border-slate-800 rounded-lg p-2 mt-1 max-h-[90px] overflow-auto">
                {scan?.headers_analysis? JSON.stringify(scan.headers_analysis,null,2).slice(0,600) : 'Analyzing…'}
              </div>
            </div>
            {scan?.status==='completed' && (
              <div className="mt-3 flex flex-wrap gap-2">
                {['json','csv','html','pdf','sarif'].map(fmt=>(
                  <a key={fmt} href={exportUrl(jobId, fmt)} target="_blank" className="inline-flex items-center gap-1 text-xs bg-sky-500 text-white rounded-full px-3 py-1.5 font-bold"><Download size={12}/>{fmt.toUpperCase()}</a>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {scan && <VulnTable vulns={scan.vulnerabilities} onExplain={handleExplain}/>}

      <div id="ai-panel">
        {aiData && <AIInsights data={aiData} vuln={scan?.vulnerabilities?.[0]}/>}
      </div>

      <Card>
        <div className="font-bold text-sm flex items-center gap-2"><Activity size={16} className="text-sky-400"/> All Scans (click to load)</div>
        <div className="mt-3 grid md:grid-cols-2 lg:grid-cols-3 gap-2">
          {scans.map(s=>(
            <button key={s.job_id} onClick={()=>setJobId(s.job_id)} className={`text-left glass rounded-xl p-3 border ${jobId===s.job_id? 'border-sky-500 bg-sky-500/10':'border-slate-800 hover:border-slate-700'}`}>
              <div className="font-bold text-sm truncate">{s.target}</div>
              <div className="mono text-[11px] text-slate-500">{s.job_id} • {s.mode}</div>
              <div className="mt-1 flex items-center gap-2">
                <span className={`text-[11px] px-2 py-0.5 rounded-full font-bold ${s.status==='completed'?'bg-emerald-500 text-white':'bg-slate-700 text-slate-300'}`}>{s.status}</span>
                <span className="text-xs text-slate-400">{s.progress}% • {s.summary?.total_vulns ?? 0} vulns</span>
              </div>
            </button>
          ))}
        </div>
      </Card>
    </div>
  )
}
