import { useEffect, useState } from 'react'
import { autoConfig, autoConfigSet, autoEnableContinuous, autoDisable, notifications, notifTest, fixList, fixAutonomous, powerConfig } from '../lib/api'
import { Bot, Zap, Bell, Play, RotateCcw, Shield, Wrench, Clock } from 'lucide-react'

export default function Autonomous() {
  const [cfg, setCfg] = useState(null)
  const [power, setPower] = useState(null)
  const [notifs, setNotifs] = useState([])
  const [interval, setInterval] = useState(15)
  const [target, setTarget] = useState('example.com')
  const [msg, setMsg] = useState('')
  const [fixes, setFixes] = useState(null)

  async function load() {
    try {
      const a = await autoConfig()
      setCfg(a.config)
      setPower(a.tune)
      const n = await notifications(20)
      setNotifs(n.notifications || [])
      const pc = await powerConfig()
      setPower(pc.config)
    } catch {}
  }
  useEffect(()=>{load(); const id=setInterval(load,6000); return()=>clearInterval(id)},[])

  async function setMode(scan_mode, fix_mode) {
    await autoConfigSet({ scan_mode, fix_mode })
    setMsg(`Mode set scan:${scan_mode} fix:${fix_mode}`)
    load()
  }
  async function setPowerhouse(use100) {
    await autoConfigSet({ use_100_engines: use100, powerhouse: use100, power_preset: use100?'turbo':'balanced' })
    setMsg(use100?'Powerhouse 112 engines ON':'Powerhouse off')
    load()
  }
  async function toggleContinuous() {
    if (cfg?.continuous) {
      await autoDisable(); setMsg('Continuous disabled — manual now')
    } else {
      await autoEnableContinuous([target], interval); setMsg(`Continuous every ${interval}m for ${target} — autonomous healer active`)
    }
    load()
  }
  async function testTune(){
    await notifTest(); setMsg('Tune played — check browser notification + sound')
    load()
  }
  async function demoFix(){
    // demo: create a dummy scan then load fixes
    try {
      const r = await fetch('/api/scan/start', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target, mode:'advance', depth:2})})
      const j = await r.json()
      await new Promise(r=>setTimeout(r, 2100))
      const f = await fixList(j.job_id)
      setFixes(f)
      setMsg(`Demo scan ${j.job_id} — ${f.count} fixes ${f.autonomous?'AUTONOMOUS':'MANUAL'} — tune notified`)
    } catch(e){ setMsg('Demo failed: '+e.message)}
  }
  async function applyAuto(jobId){
    const res = await fixAutonomous(jobId)
    setMsg(`Autonomous applied ${res.total} fixes`)
    load()
  }

  if (!cfg) return <div className="p-6 text-slate-400">Loading autonomous powerhouse…</div>

  return (
    <div className="space-y-6">
      <div className="rounded-2xl bg-gradient-to-br from-violet-600 via-fuchsia-600 to-cyan-500 p-6 text-white shadow-xl">
        <div className="flex items-center gap-3">
          <Bot className="w-8 h-8"/> <h1 className="text-2xl font-black">Autonomous Powerhouse — 112 Engines</h1> <span className="ml-auto text-xs bg-white/20 px-3 py-1 rounded-full">{cfg.mode} • 112 • {cfg.continuous?'CONTINUOUS':'MANUAL'}</span>
        </div>
        <p className="mt-2 text-white/90 text-sm">Auto vs Manual toggles for scanning, fixing, and scheduling. Every-time scans + scheduled cron + continuous monitor. No single problem left — every bug notifies admin with tune + how to remove, and auto-fixes immediately in autonomous mode.</p>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Zap className="w-4 h-4 text-amber-400"/> Scan Mode</h3>
          <p className="text-xs text-slate-400 mt-1">Choose auto or manual for scanning</p>
          <div className="flex gap-2 mt-3">
            {['manual','auto','schedule'].map(m=>(
              <button key={m} onClick={()=>setMode(m, cfg.fix_mode)} className={`px-3 py-2 rounded-xl text-sm font-bold capitalize ${cfg.scan_mode===m?'bg-violet-600 text-white':'bg-slate-800 text-slate-300 border border-slate-700'}`}>{m}</button>
            ))}
          </div>
          <div className="mt-4 p-3 bg-slate-950 rounded-xl border border-slate-800">
            <div className="text-xs text-slate-400">Current:</div><div className="font-bold text-emerald-400">{cfg.scan_mode}</div>
            <div className="text-xs text-slate-500 mt-1">Auto = scans run continuously / on schedule without human. Manual = you trigger.</div>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Wrench className="w-4 h-4 text-emerald-400"/> Fix Mode</h3>
          <p className="text-xs text-slate-400 mt-1">Choose auto or manual for fixing</p>
          <div className="flex gap-2 mt-3">
            {['manual','auto','schedule'].map(m=>(
              <button key={m} onClick={()=>setMode(cfg.scan_mode, m)} className={`px-3 py-2 rounded-xl text-sm font-bold capitalize ${cfg.fix_mode===m?'bg-emerald-600 text-white':'bg-slate-800 text-slate-300 border border-slate-700'}`}>{m}</button>
            ))}
          </div>
          <div className="mt-4 p-3 bg-slate-950 rounded-xl border border-slate-800">
            <div className="text-xs text-slate-400">Current:</div><div className="font-bold text-emerald-400">{cfg.fix_mode}</div>
            <div className="text-xs text-slate-500 mt-1">Auto = generates PR/patch immediately after scan, notifies with tune + how_to_remove. 20 fix engines.</div>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Shield className="w-4 h-4 text-cyan-400"/> Powerhouse 100+</h3>
          <label className="flex items-center gap-3 mt-3 cursor-pointer">
            <input type="checkbox" checked={!!cfg.use_100_engines} onChange={e=>setPowerhouse(e.target.checked)} className="w-5 h-5 accent-fuchsia-500"/>
            <span className="text-sm text-slate-200">Use 100+ engines (112) + autonomous healer</span>
          </label>
          <div className="mt-3 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-300"/><span className="text-xs text-slate-400">Turbo preset when ON, max strength, every check runs</span>
          </div>
          <div className="mt-3 text-xs text-slate-500">All 112 selectable in Powerhouse Control — here toggles powerhouse on for every autonomous scan.</div>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Clock className="w-4 h-4 text-violet-400"/> Every-Time / Continuous</h3>
          <div className="flex gap-2 mt-3">
            <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="example.com" className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-sm text-white"/>
            <select value={interval} onChange={e=>setInterval(parseInt(e.target.value))} className="bg-slate-950 border border-slate-800 rounded-xl px-2 text-sm text-white">
              <option value={5}>5m</option><option value={15}>15m</option><option value={60}>60m</option>
            </select>
          </div>
          <button onClick={toggleContinuous} className={`mt-3 w-full py-2 rounded-xl font-bold flex items-center justify-center gap-2 ${cfg.continuous?'bg-red-600 hover:bg-red-500 text-white':'bg-emerald-600 hover:bg-emerald-500 text-white'}`}>
            {cfg.continuous?<><RotateCcw className="w-4 h-4"/> Disable Continuous</>:<><Play className="w-4 h-4"/> Enable Every-Time (Continuous)</>}
          </button>
          <p className="text-xs text-slate-500 mt-2">When enabled, system scans <b>every {interval}m automatically</b> with 112 engines, auto-fixes, and tunes admin. No lapse.</p>
          <div className="mt-3 p-2 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-400">Status: <b className={cfg.continuous?'text-emerald-400':'text-slate-300'}>{cfg.continuous?'ON — every '+interval+'m':'OFF — manual/schedule'}</b> • auto_targets: {(cfg.auto_targets||[]).join(', ')||'none'}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Bell className="w-4 h-4 text-pink-400"/> Notifications — Tune + How to Fix</h3>
          <button onClick={testTune} className="mt-3 w-full py-2 bg-violet-600 hover:bg-violet-500 rounded-xl text-white font-bold flex items-center justify-center gap-2"><Bell className="w-4 h-4"/> Test Attractive Tune 🔔</button>
          <p className="text-xs text-slate-500 mt-2">Every bug triggers: browser notification + WebAudio tune (880→1320Hz) + how_to_remove steps. Try test above.</p>
          <div className="mt-3 max-h-[180px] overflow-auto divide-y divide-slate-800 border border-slate-800 rounded-xl">
            {notifs.length===0 && <div className="p-3 text-xs text-slate-500">No notifications yet</div>}
            {notifs.slice(0,6).map(n=>(
              <div key={n.id} className="p-2">
                <div className="text-xs font-bold text-white">{n.title}</div>
                <div className="text-xs text-slate-400">{n.message}</div>
                {n.how_to_fix && <div className="text-xs text-emerald-300 mt-1 whitespace-pre-wrap">{n.how_to_fix.slice(0,140)}…</div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
        <h3 className="font-bold text-white">Scheduler — Cron at Schedule Time</h3>
        <p className="text-xs text-slate-500 mt-1">Create scheduled scans via /api/scheduler/schedule (cron). Autonomous loop fires at schedule time. Also supports every-time continuous above.</p>
        <div className="flex gap-2 mt-3">
          <button onClick={async()=>{
            await fetch('/api/scheduler/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target, mode:'advance', interval_minutes: interval})})
            setMsg(`Scheduled every ${interval}m for ${target}`); load()
          }} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-xl text-sm text-white border border-slate-700">Schedule {target} every {interval}m</button>
          <button onClick={demoFix} className="px-4 py-2 bg-fuchsia-600 hover:bg-fuchsia-500 rounded-xl text-sm text-white font-bold">Demo: Scan + Fix (20 engines)</button>
        </div>
        {fixes && (
          <div className="mt-4 border border-slate-800 rounded-xl p-3 bg-slate-950">
            <div className="text-sm font-bold text-white">Fixes for {fixes.job_id} — {fixes.autonomous?'AUTONOMOUS':'MANUAL'} — {fixes.count} items</div>
            <div className="grid md:grid-cols-2 gap-2 mt-2 max-h-[320px] overflow-auto">
              {fixes.fixes.slice(0,8).map(f=>(
                <div key={f.vuln_id} className="bg-slate-900 border border-slate-800 rounded-xl p-2">
                  <div className="text-xs font-bold text-white">{f.vuln_title} <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] ${f.severity==='critical'?'bg-red-500':'bg-orange-500'} text-white`}>{f.severity}</span></div>
                  <div className="text-xs text-slate-400">{f.engine_id} • {f.mode}</div>
                  <pre className="mt-1 text-xs bg-black rounded p-1 text-emerald-300 whitespace-pre-wrap">{String(f.patch).slice(0,140)}</pre>
                  <div className="text-xs text-slate-500 mt-1">Test: {f.test}</div>
                  <details className="mt-1"><summary className="text-xs text-violet-400 cursor-pointer">how_to_remove</summary><pre className="text-xs whitespace-pre-wrap text-slate-300">{f.how_to_remove.slice(0,300)}</pre></details>
                </div>
              ))}
            </div>
            <button onClick={()=>applyAuto(fixes.job_id)} className="mt-2 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-xs text-white">Apply AUTONOMOUS (auto-healer)</button>
          </div>
        )}
      </div>

      {msg && <div className="bg-emerald-950 border border-emerald-800 text-emerald-200 rounded-xl p-3 text-sm">{msg} <button onClick={()=>setMsg('')} className="ml-2 text-xs underline">dismiss</button></div>}
    </div>
  )
}
