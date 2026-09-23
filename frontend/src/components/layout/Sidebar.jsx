import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Radar, Share2, ShieldAlert, FileBarChart, Brain, Zap, Globe, Layers, Package, Clock, ShieldCheck, Crown, Sliders, Bot, Crosshair } from 'lucide-react'

const items = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scanner", label: "Advanced Scanner", icon: Radar },
  { to: "/bulk", label: "Bulk Scan", icon: Layers },
  { to: "/graph", label: "Attack Graph", icon: Share2 },
  { to: "/risk", label: "Risk Engine", icon: ShieldAlert },
  { to: "/findings", label: "Findings", icon: FileBarChart },
  { to: "/assets", label: "Assets & SBOM", icon: Package },
  { to: "/threat-intel", label: "Threat Intel (FREE)", icon: Globe },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/ai", label: "AI Chat (FREE↔Ent)", icon: Brain },
  { to: "/reports", label: "Reports & Export", icon: FileBarChart },
  { to: "/scheduler", label: "Scheduler", icon: Clock },
  { to: "/power", label: "Powerhouse Control", icon: Sliders },
  { to: "/autonomous", label: "Autonomous (BOT)", icon: Bot },
  { to: "/hunting", label: "Hunting & Zero-Trust", icon: Crosshair },
  { to: "/enterprise", label: "Enterprise Power", icon: Crown },
]

export default function Sidebar(){
  return (
    <aside className="w-[270px] shrink-0 hidden lg:flex flex-col gap-4 p-4 sticky top-0 h-screen">
      <div className="glass rounded-[18px] p-4 flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-400 to-indigo-600 grid place-items-center font-black">AG</div>
        <div>
          <div className="font-extrabold leading-none">AttackGraph</div>
          <div className="text-[11px] tracking-widest text-slate-400">POWERHOUSE 121 • BOT + HUNT</div>
        </div>
        <div className="ml-auto w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
      </div>
      <nav className="glass rounded-[18px] p-2 flex-1 overflow-auto scrollbar">
        {items.map(({to,label,icon:Icon})=>(
          <NavLink key={to} to={to} className={({isActive})=>`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm ${isActive? 'bg-sky-500/15 text-sky-300 border border-sky-500/20':'text-slate-300 hover:bg-slate-800/50'}`}>
            <Icon size={16}/> {label}
          </NavLink>
        ))}
        <div className="mt-3 p-3 rounded-xl bg-gradient-to-br from-emerald-500/20 to-sky-500/20 border border-emerald-500/20">
          <div className="text-xs font-bold flex items-center gap-2"><Zap size={14} className="text-emerald-400"/> FREE by default • $0</div>
          <div className="text-xs text-slate-300 mt-1">No keys = $0 offline local + Cloud/Container/SBOM. 100% free.</div>
        </div>
        <div className="mt-2 p-3 rounded-xl bg-gradient-to-br from-sky-500/15 to-violet-500/15 border border-sky-500/20">
          <div className="text-xs font-bold flex items-center gap-2"><Sliders size={14} className="text-sky-400"/> Powerhouse 121 Engines</div>
          <div className="text-xs text-slate-300 mt-1">121 selectable, presets Eco→Overdrive, per-task 0-100 + persistence & hunt. More engines = more power.</div>
        </div>
        <div className="mt-2 p-3 rounded-xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 border border-violet-500/20">
          <div className="text-xs font-bold flex items-center gap-2"><Bot size={14} className="text-violet-400"/> Autonomous BOT</div>
          <div className="text-xs text-slate-300 mt-1">Auto vs Manual per task: scan every time or at schedule, auto-fixes, tune notifies admin.</div>
        </div>
        <div className="mt-2 p-3 rounded-xl bg-gradient-to-br from-amber-500/15 to-violet-500/15 border border-amber-500/20">
          <div className="text-xs font-bold flex items-center gap-2"><Crown size={14} className="text-amber-400"/> Enterprise Overdrive</div>
          <div className="text-xs text-slate-300 mt-1">Set OPENAI/ANTHROPIC/GEMINI → Turbo 44 engines + GPU → 100/100.</div>
        </div>
      </nav>
      <div className="text-[11px] text-slate-500 text-center">For authorized pentest & SOC — 100% free</div>
    </aside>
  )
}
