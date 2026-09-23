import { useEffect, useState, useRef } from 'react'
import { Bell, Volume2, X, CheckCheck } from 'lucide-react'
import { notifications, notifRead, notifReadAll, notifTest } from '../../lib/api'

export default function NotificationBell() {
  const [list, setList] = useState([])
  const [open, setOpen] = useState(false)
  const [unread, setUnread] = useState(0)
  const audioCtxRef = useRef(null)

  function playTune() {
    try {
      const ctx = audioCtxRef.current || new (window.AudioContext || window.webkitAudioContext)()
      audioCtxRef.current = ctx
      const o = ctx.createOscillator()
      const g = ctx.createGain()
      o.type = 'sine'
      o.frequency.setValueAtTime(880, ctx.currentTime)
      o.frequency.exponentialRampToValueAtTime(1320, ctx.currentTime + 0.15)
      g.gain.setValueAtTime(0.6, ctx.currentTime)
      g.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.6)
      o.connect(g).connect(ctx.destination)
      o.start(); o.stop(ctx.currentTime + 0.6)
      if ('vibrate' in navigator) navigator.vibrate([120, 40, 120])
    } catch {}
  }

  async function load() {
    try {
      const res = await notifications(50)
      const ns = res.notifications || []
      setList(ns)
      setUnread(ns.filter(n => !n.read).length)
    } catch {}
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 8000)
    // WebSocket global for realtime tune
    let ws
    try {
      const proto = location.protocol === 'https:' ? 'wss://' : 'ws://'
      ws = new WebSocket(`${proto}${location.host}/ws/global`)
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'notification' && msg.tune) {
            playTune()
            if (Notification && Notification.permission === 'granted') {
              new Notification(msg.notification.title, { body: msg.notification.message })
            } else if (Notification && Notification.permission !== 'denied') {
              Notification.requestPermission()
            }
            load()
          }
          if (msg.type === 'scan_completed' || msg.type === 'scan_completed_global') {
            load()
          }
        } catch {}
      }
    } catch {}
    if (Notification && Notification.permission === 'default') Notification.requestPermission()
    return () => { clearInterval(id); try{ws?.close()}catch{} }
  }, [])

  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} className="relative p-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">
        <Bell className="w-5 h-5 text-slate-200" />
        {unread > 0 && <span className="absolute -top-1 -right-1 bg-fuchsia-500 text-white text-[10px] px-1.5 py-0.5 rounded-full font-bold">{unread}</span>}
      </button>
      {open && (
        <div className="absolute right-0 mt-2 w-[380px] max-h-[520px] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl z-50 flex flex-col">
          <div className="p-3 border-b border-slate-800 flex items-center justify-between">
            <div className="font-bold text-white flex items-center gap-2"><Volume2 className="w-4 h-4 text-emerald-400"/> Notifications {unread>0 && <span className="text-xs bg-fuchsia-500 px-2 py-0.5 rounded-full">{unread} new</span>}</div>
            <div className="flex gap-1">
              <button onClick={async()=>{await notifTest(); playTune(); load()}} className="text-xs px-2 py-1 bg-violet-600 hover:bg-violet-500 rounded-lg text-white">Test tune</button>
              <button onClick={async()=>{await notifReadAll(); load()}} className="p-1 hover:bg-slate-800 rounded"><CheckCheck className="w-4 h-4"/></button>
              <button onClick={()=>setOpen(false)} className="p-1 hover:bg-slate-800 rounded"><X className="w-4 h-4"/></button>
            </div>
          </div>
          <div className="overflow-auto flex-1 divide-y divide-slate-800">
            {list.length===0 && <div className="p-6 text-center text-slate-500 text-sm">No notifications yet — run a scan, every bug will notify with tune + how to fix.</div>}
            {list.map(n=>(
              <div key={n.id} className={`p-3 hover:bg-slate-800/60 ${!n.read?'bg-violet-950/30':''}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="font-semibold text-sm text-white">{n.title}</div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full ${n.severity==='critical'?'bg-red-500':n.severity==='high'?'bg-orange-500':n.severity==='medium'?'bg-yellow-500 text-black':'bg-slate-600'} text-white`}>{n.severity}</span>
                </div>
                <div className="text-xs text-slate-300 mt-1">{n.message}</div>
                {n.how_to_fix && <div className="mt-2 text-xs bg-slate-950 border border-slate-800 rounded-lg p-2 text-emerald-300 whitespace-pre-wrap">{n.how_to_fix}</div>}
                <div className="flex items-center justify-between mt-2">
                  <span className="text-[10px] text-slate-500">{new Date(n.ts).toLocaleString()} {n.sound && '🔔 tune'}</span>
                  {!n.read && <button onClick={async()=>{await notifRead(n.id); load()}} className="text-xs px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded">Mark read</button>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
