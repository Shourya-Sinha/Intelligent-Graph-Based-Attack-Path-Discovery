import { useEffect, useState } from 'react'
import { schedulerList, schedulerCreate } from '../lib/api'
import { Card } from '../components/ui/Card'
import { Clock, Plus } from 'lucide-react'

export default function Scheduler(){
  const [jobs,setJobs]=useState([])
  const [target,setTarget]=useState("https://example.com")
  const [interval,setInterval]=useState(60)
  const refresh = ()=> schedulerList().then(r=>setJobs(r.jobs)).catch(()=>{})
  useEffect(()=>{ refresh() },[])
  const create = async ()=>{
    await schedulerCreate({target, interval_minutes: parseInt(interval)})
    refresh()
  }
  return (
    <div className="space-y-4">
      <Card>
        <div className="font-bold flex items-center gap-2"><Clock size={16} className="text-sky-400"/> Scheduler — FREE (in-memory)</div>
        <div className="text-xs text-slate-400 mt-1">Schedule periodic scans — no Celery/Redis needed, 100% free. For prod, swap to APScheduler.</div>
      </Card>
      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <div className="font-bold text-sm">Create Schedule</div>
          <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="https://app.com" className="w-full mt-2 glass rounded-xl px-3 py-2 text-sm outline-none"/>
          <div className="flex gap-2 mt-2">
            <label className="text-xs flex-1">Every (minutes) <input type="number" value={interval} onChange={e=>setInterval(e.target.value)} className="w-full glass rounded-lg px-2 py-1.5 text-sm outline-none mt-1"/></label>
          </div>
          <button onClick={create} className="w-full mt-3 bg-sky-500 text-white font-bold rounded-xl py-2.5 flex items-center justify-center gap-2"><Plus size={16}/> Schedule FREE</button>
        </Card>
        <Card>
          <div className="font-bold text-sm">Scheduled Jobs ({jobs.length})</div>
          <div className="mt-2 space-y-2 max-h-[300px] overflow-auto scrollbar">
            {jobs.map(j=>(
              <div key={j.id} className="glass rounded-xl p-3 border border-slate-800">
                <div className="font-bold text-sm">{j.target} — {j.mode}</div>
                <div className="text-xs text-slate-400">Every {j.interval_minutes}m • Next {j.next_run} • Runs {j.runs}</div>
              </div>
            ))}
            {jobs.length===0 && <div className="text-sm text-slate-500">No schedules yet.</div>}
          </div>
        </Card>
      </div>
    </div>
  )
}
