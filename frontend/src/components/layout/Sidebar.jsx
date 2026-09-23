import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Radar, Share2, ShieldAlert, FileBarChart, Brain, Settings, Zap } from 'lucide-react'

const items = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scanner", label: "Advanced Scanner", icon: Radar },
  { to: "/graph", label: "Attack Graph", icon: Share2 },
  { to: "/risk", label: "Risk Engine", icon: ShieldAlert },
  { to: "/findings", label: "Findings", icon: FileBarChart },
  { to: "/ai", label: "AI Insights", icon: Brain },
  { to: "/reports", label: "Reports & Export", icon: FileBarChart },
]

export default function Sidebar(){
  return (
    <aside className="w-[260px] shrink-0 hidden lg:flex flex-col gap-4 p-4 sticky top-0 h-screen">
      <div className="glass rounded-[18px] p-4 flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-400 to-indigo-600 grid place-items-center font-black">AG</div>
        <div>
          <div className="font-extrabold leading-none">AttackGraph</div>
          <div className="text-[11px] tracking-widest text-slate-400">ADVANCED v2.0</div>
        </div>
        <div className="ml-auto w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
      </div>
      <nav className="glass rounded-[18px] p-2 flex-1">
        {items.map(({to,label,icon:Icon})=>(
          <NavLink key={to} to={to} className={({isActive})=>`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm ${isActive? 'bg-sky-500/15 text-sky-300 border border-sky-500/20':'text-slate-300 hover:bg-slate-800/50'}`}>
            <Icon size={18}/> {label}
          </NavLink>
        ))}
        <div className="mt-4 p-3 rounded-xl bg-gradient-to-br from-sky-500/20 to-indigo-500/20 border border-sky-500/20">
          <div className="text-xs font-bold flex items-center gap-2"><Zap size={14} className="text-sky-400"/> Realtime Engine</div>
          <div className="text-xs text-slate-300 mt-1">WebSocket live updates • Graph centrality • Monte Carlo • FAIR</div>
        </div>
      </nav>
      <div className="text-[11px] text-slate-500 text-center">Built for real-world pentest & SOC teams</div>
    </aside>
  )
}
