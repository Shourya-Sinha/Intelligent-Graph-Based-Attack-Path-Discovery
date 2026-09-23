import { useState, useRef, useEffect } from 'react'
import { Bot, Send, Sparkles, X, MessageCircle } from 'lucide-react'
import { aiChat } from '../../lib/api'

export default function FreeAIChat({ jobId }){
  const [open,setOpen]=useState(false)
  const [msgs,setMsgs]=useState([{role:'assistant', text:'👋 Hi! I am FREE AI — 100% free, offline, no OpenAI. Ask me: "cheapest fix 50%", "executive summary", "WAF rule", "explain XSS"'}])
  const [input,setInput]=useState("")
  const [loading,setLoading]=useState(false)
  const scrollRef=useRef(null)
  useEffect(()=>{ if(scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight }, [msgs])

  const send = async ()=>{
    if(!input.trim()) return
    const q = input
    setMsgs(m=>[...m, {role:'user', text: q}])
    setInput("")
    setLoading(true)
    try{
      const r = await aiChat(q, jobId)
      setMsgs(m=>[...m, {role:'assistant', text: r.answer, provider: r.provider}])
    } catch(e){
      setMsgs(m=>[...m, {role:'assistant', text: "Free AI offline fallback: try 'cheapest fix', 'WAF rule', 'executive summary'"}])
    }
    setLoading(false)
  }

  return (
    <>
      <button onClick={()=>setOpen(!open)} className="fixed bottom-5 right-5 w-14 h-14 rounded-full bg-gradient-to-br from-violet-600 to-sky-600 text-white grid place-items-center shadow-glow z-50">
        {open? <X/> : <MessageCircle/>}
      </button>
      {open && (
        <div className="fixed bottom-20 right-5 w-[380px] max-w-[92vw] h-[480px] glass rounded-[18px] overflow-hidden flex flex-col z-50 shadow-2xl border border-violet-500/20">
          <div className="p-3 bg-gradient-to-r from-violet-600 to-sky-600 text-white flex items-center gap-2">
            <Bot size={18}/> <span className="font-bold text-sm">FREE AI Chat</span>
            <span className="ml-auto text-xs bg-white/20 rounded-full px-2 py-0.5">100% Free • Offline • $0</span>
          </div>
          <div className="px-2 py-1 text-xs text-emerald-300 bg-emerald-500/10 border-b border-emerald-500/20 flex items-center gap-1"><Sparkles size={12}/> No OpenAI • No payment • Works without internet</div>
          <div ref={scrollRef} className="flex-1 overflow-auto p-3 space-y-2 scrollbar">
            {msgs.map((m,i)=>(
              <div key={i} className={`rounded-xl px-3 py-2 text-sm ${m.role==='user'?'bg-sky-500 text-white ml-8':'glass border border-slate-700 mr-8'}`}>
                <div className="whitespace-pre-wrap leading-5">{m.text}</div>
                {m.provider && <div className="text-[10px] text-slate-400 mt-1">{m.provider}</div>}
              </div>
            ))}
            {loading && <div className="text-xs text-slate-400">Thinking (free local)...</div>}
          </div>
          <div className="p-2 flex gap-2 border-t border-slate-800 bg-[#070b18]">
            <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==='Enter'&&send()} placeholder="Ask free AI..." className="flex-1 glass rounded-full px-3 py-2 text-sm outline-none"/>
            <button onClick={send} className="w-9 h-9 rounded-full bg-sky-500 text-white grid place-items-center"><Send size={14}/></button>
          </div>
          <div className="px-3 py-1 text-[11px] text-slate-500 flex gap-1 flex-wrap">
            {["cheapest fix 50%","executive summary","WAF rule","explain path"].map(s=>(
              <button key={s} onClick={()=>setInput(s)} className="glass rounded-full px-2 py-1 text-xs">{s}</button>
            ))}
          </div>
        </div>
      )}
    </>
  )
}
