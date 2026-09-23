import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import GraphExplorer from './pages/GraphExplorer'
import RiskAnalysis from './pages/RiskAnalysis'
import Findings from './pages/Findings'
import Reports from './pages/Reports'
import ThreatIntel from './pages/ThreatIntel'
import Assets from './pages/Assets'
import BulkScan from './pages/BulkScan'
import Compliance from './pages/Compliance'
import Scheduler from './pages/Scheduler'
import EnterprisePower from './pages/EnterprisePower'
import PowerControl from './pages/PowerControl'
import Autonomous from './pages/Autonomous'
import Hunting from './pages/Hunting'
import FreeAIChat from './components/ai/FreeAIChat'
import ErrorBoundary from './components/ui/ErrorBoundary'
import { useState } from 'react'

function AIPage(){
  return <div className="glass rounded-xl p-6">🤖 <b>FREE↔ENTERPRISE AI</b> — Default $0 free, offline, no OpenAI. If you set <code>OPENAI_API_KEY</code> / <code>ANTHROPIC_API_KEY</code> / <code>GEMINI_API_KEY</code> → auto-unlocks Enterprise (GPT-4o/Claude 3.5/Gemini 1.5). No key → stays 100% FREE. Use floating chat (bottom-right) or Findings → Explain. Enterprise meter: <code>/enterprise</code>.</div>
}

export default function App(){
  const [chatJobId,setChatJobId]=useState(null)
  return (
    <BrowserRouter>
      <div className="min-h-screen flex bg-[#070b18]">
        <Sidebar/>
        <div className="flex-1 min-w-0 flex flex-col">
          <Topbar/>
          <main className="max-w-[1400px] mx-auto w-full p-4 md:p-6 flex-1">
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<Dashboard/>}/>
                <Route path="/scanner" element={<Scanner/>}/>
                <Route path="/bulk" element={<BulkScan/>}/>
                <Route path="/graph" element={<GraphExplorer/>}/>
                <Route path="/risk" element={<RiskAnalysis/>}/>
                <Route path="/findings" element={<Findings/>}/>
                <Route path="/assets" element={<Assets/>}/>
                <Route path="/threat-intel" element={<ThreatIntel/>}/>
                <Route path="/compliance" element={<Compliance/>}/>
                <Route path="/ai" element={<AIPage/>}/>
                <Route path="/reports" element={<Reports/>}/>
                <Route path="/scheduler" element={<Scheduler/>}/>
                <Route path="/power" element={<PowerControl/>}/>
                <Route path="/autonomous" element={<Autonomous/>}/>
                <Route path="/hunting" element={<Hunting/>}/>
                <Route path="/enterprise" element={<EnterprisePower/>}/>
              </Routes>
            </ErrorBoundary>
          </main>
          <footer className="text-center text-[11px] text-slate-500 py-4">© 2026 Intelligent Graph-Based Attack Path Discovery • Powerhouse v2.5 — 121 Engines + Autonomous BOT + Hunting • FREE↔ENTERPRISE • Persistence SQLite • WebSocket Realtime + Tune + RateLimit</footer>
        </div>
      </div>
      <FreeAIChat jobId={chatJobId}/>
    </BrowserRouter>
  )
}
