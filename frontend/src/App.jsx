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
import FreeAIChat from './components/ai/FreeAIChat'
import { useState } from 'react'

function AIPage(){
  return <div className="glass rounded-xl p-6">🤖 <b>FREE AI</b> — 100% free, offline, no OpenAI. Use the floating chat (bottom-right) or go to Findings → Explain. API: <code>/api/ai/chat</code> and <code>/api/ai/explain</code> — both free, no key, no payment.</div>
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
            </Routes>
          </main>
          <footer className="text-center text-[11px] text-slate-500 py-4">© 2026 Intelligent Graph-Based Attack Path Discovery • Advanced v2.1 • FREE AI ($0) • WebSocket Realtime • For authorized use only</footer>
        </div>
      </div>
      <FreeAIChat jobId={chatJobId}/>
    </BrowserRouter>
  )
}
