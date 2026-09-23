export function Card({ children, className="", hover=false }) {
  return <div className={`glass glow-border rounded-[18px] p-5 ${hover?'hover:shadow-glow transition-shadow':''} ${className}`}>{children}</div>
}
export function Stat({ label, value, sub, icon }) {
  return <div className="glass rounded-2xl p-4">
    <div className="flex items-center justify-between">
      <div className="text-[11px] tracking-widest text-slate-400 uppercase">{label}</div>
      <div className="text-slate-500">{icon}</div>
    </div>
    <div className="text-2xl font-extrabold mt-1">{value}</div>
    {sub && <div className="text-xs text-slate-400 mt-1">{sub}</div>}
  </div>
}
