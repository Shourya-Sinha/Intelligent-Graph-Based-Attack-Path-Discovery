import { Card } from '../ui/Card'

export default function RiskMatrix({ risk }){
  if(!risk) return <div className="glass rounded-xl p-6 text-slate-400 text-sm">No risk analysis yet. Run a scan.</div>
  const levels = [
    {k:"critical", label:"Critical", count: risk.path_risks.filter(p=>p.severity==='critical').length, color:"bg-red-500"},
    {k:"high", label:"High", count: risk.path_risks.filter(p=>p.severity==='high').length, color:"bg-orange-500"},
    {k:"medium", label:"Medium", count: risk.path_risks.filter(p=>p.severity==='medium').length, color:"bg-yellow-500"},
    {k:"low", label:"Low", count: risk.path_risks.filter(p=>p.severity==='low').length, color:"bg-emerald-500"},
  ]
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <Card>
        <div className="text-sm font-bold">Risk Score</div>
        <div className="mt-2 flex items-baseline gap-3">
          <div className="text-5xl font-black" style={{color: risk.overall_risk_score>75? '#ef4444': risk.overall_risk_score>50? '#f97316':'#eab308'}}>{risk.overall_risk_score}</div>
          <div className="text-sm font-bold uppercase tracking-widest px-3 py-1 rounded-full" style={{background: risk.risk_level==='critical'? '#ef4444': risk.risk_level==='high'? '#f97316':'#eab308', color: risk.risk_level==='medium'?'black':'white'}}>{risk.risk_level}</div>
        </div>
        <div className="mt-3 text-xs text-slate-400">Exposure {risk.exposure_score}/100 • Monte Carlo expected loss ${risk.monte_carlo.expected_loss.toLocaleString()}</div>
        <div className="mt-4 grid grid-cols-4 gap-2">
          {levels.map(l=>(
            <div key={l.k} className="glass rounded-xl p-2 text-center">
              <div className={`w-2 h-2 rounded-full mx-auto ${l.color}`}/>
              <div className="text-xs font-bold mt-1">{l.label}</div>
              <div className="text-lg font-black">{l.count}</div>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <div className="text-sm font-bold">Financial Impact (FAIR)</div>
        <div className="mt-2 space-y-2 text-sm">
          <div className="flex justify-between glass rounded-lg px-3 py-2"><span className="text-slate-400">Single Loss Expectancy</span><span className="font-bold">${risk.financial_impact_usd.single_loss_expectancy_usd.toLocaleString()}</span></div>
          <div className="flex justify-between glass rounded-lg px-3 py-2"><span className="text-slate-400">Annualized Low / High</span><span className="font-bold text-xs">${risk.financial_impact_usd.annualized_low_usd.toLocaleString()} — ${risk.financial_impact_usd.annualized_high_usd.toLocaleString()}</span></div>
          <div className="flex justify-between glass rounded-lg px-3 py-2"><span className="text-slate-400">Regulatory Fine Risk</span><span className="font-bold text-amber-300">${risk.financial_impact_usd.regulatory_fine_risk_usd.toLocaleString()}</span></div>
          <div className="text-[11px] text-slate-500">Monte Carlo 4000 sims — P90 ${risk.monte_carlo.p90_loss.toLocaleString()} • P95 ${risk.monte_carlo.p95_loss.toLocaleString()}</div>
        </div>
      </Card>
    </div>
  )
}
