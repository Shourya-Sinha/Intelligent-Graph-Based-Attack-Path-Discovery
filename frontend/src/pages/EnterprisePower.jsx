import { useEffect, useState } from 'react'
import { enterprisePower, enterpriseFeatures, freeInfo } from '../lib/api'
import PowerMeter from '../components/enterprise/PowerMeter'
import { Card } from '../components/ui/Card'
import { ShieldCheck, Zap, Crown, Gift } from 'lucide-react'

export default function EnterprisePower(){
  const [power,setPower]=useState(null)
  const [features,setFeatures]=useState(null)
  const [free,setFree]=useState(null)
  useEffect(()=>{
    enterprisePower().then(setPower).catch(()=>{})
    enterpriseFeatures().then(setFeatures).catch(()=>{})
    freeInfo().then(setFree).catch(()=>{})
  },[])
  const isEnt = power?.is_enterprise
  return (
    <div className="space-y-4">
      <div className={`rounded-[20px] p-[1px] bg-gradient-to-br ${isEnt ? 'from-emerald-500 via-sky-500 to-violet-600' : 'from-sky-500 via-indigo-500 to-violet-600'}`}>
        <div className="rounded-[18px] bg-[#0a1020] p-6">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl grid place-items-center font-black text-white ${isEnt ? 'bg-gradient-to-br from-emerald-500 to-sky-600' : 'bg-gradient-to-br from-sky-500 to-indigo-600'}`}>{isEnt ? '⚡' : '$'}</div>
            <div>
              <div className="font-black text-lg">{isEnt ? 'Enterprise Power — Unlocked' : 'Free Power — Default ($0)'}</div>
              <div className="text-xs text-slate-400">{isEnt ? 'Paid keys detected — enterprise advance intelligence active' : 'No paid keys — running 100% FREE, offline, $0. Set paid keys to unlock Enterprise.'}</div>
            </div>
            <span className={`ml-auto px-4 py-1.5 rounded-full text-xs font-black ${isEnt ? 'bg-emerald-500 text-white' : 'bg-sky-500 text-white'}`}>{power ? `${power.level} ${power.total_power}/100` : '...'}</span>
          </div>
          <div className="mt-3 grid md:grid-cols-3 gap-2 text-xs">
            <div className="glass rounded-xl p-3 flex items-center gap-2"><Gift size={14} className="text-emerald-400"/><div><b>Default: FREE</b><br/><span className="text-slate-400">No keys = $0, offline, local 20+ KB</span></div></div>
            <div className="glass rounded-xl p-3 flex items-center gap-2"><Zap size={14} className="text-sky-400"/><div><b>Pro: HF Free</b><br/><span className="text-slate-400">HF_API_KEY free (no card) → +4 power</span></div></div>
            <div className="glass rounded-xl p-3 flex items-center gap-2"><Crown size={14} className="text-amber-400"/><div><b>Enterprise: Paid</b><br/><span className="text-slate-400">OPENAI/ANTHROPIC/GEMINI keys → +13 power, advance LLM</span></div></div>
          </div>
        </div>
      </div>

      {power && <PowerMeter power={power}/>}

      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <div className="font-bold text-sm flex items-center gap-2"><ShieldCheck size={14} className="text-emerald-400"/> FREE vs ENTERPRISE — Feature Power</div>
          <div className="mt-3 max-h-[420px] overflow-auto scrollbar space-y-1.5">
            {features?.features?.map((f,i)=>(
              <div key={i} className="glass rounded-xl px-3 py-2 flex items-center gap-2 text-xs">
                <span className={`w-2 h-2 rounded-full ${f.free===True ? 'bg-emerald-400' : f.enterprise===True ? 'bg-sky-400' : 'bg-amber-400'}`}/>
                <span className="flex-1 font-bold">{f.name}</span>
                <span className="text-slate-400">{String(f.free)} → {String(f.enterprise)}</span>
                <span className="bg-slate-800 rounded-full px-2 py-0.5 font-bold">+{f.power}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <div className="font-bold text-sm">How Power Works (Enterprise Strength)</div>
          <div className="mt-2 text-sm space-y-2">
            <div className="glass rounded-lg p-3"><b>Power Formula:</b><br/><span className="mono text-xs">AI (0-25) + Scanner (0-20) + Graph (0-20) + Risk (0-15) + Enterprise (0-10) + Infra (0-10) = 0-100</span></div>
            <div className="glass rounded-lg p-3"><b>Tiers:</b><br/>FREE 0-60 • PRO 60-85 • ENTERPRISE 85-100</div>
            <div className="glass rounded-lg p-3"><b>Enterprise Strength:</b><br/>200 bulk targets, 10k+ graph nodes, 20k Monte Carlo, distributed, GPU, Splunk/ELK, SSO/RBAC, auto-PR, paid LLM chain-of-thought.</div>
            <div className="glass rounded-lg p-3"><b>Real-World:</b><br/>Free solves startup/SMB pentest (500 nodes, $0). Enterprise solves Fortune 500 (10k nodes, 200 bulk, compliance SOC2/HIPAA/GDPR, audit logs).</div>
            {free && <div className="text-xs text-slate-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-2">✅ Free: {free.free.provider} • Enterprise: {free.enterprise.unlock}</div>}
          </div>
        </Card>
      </div>
    </div>
  )
}
