import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Topbar from './components/layout/Topbar'
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import GraphExplorer from './pages/GraphExplorer'
import RiskAnalysis from './pages/RiskAnalysis'
import Findings from './pages/Findings'
import Reports from './pages/Reports'
import { useState } from 'react'

function AIPage(){
  return <div className="glass rounded-xl p-6">For AI Insights visit Findings or Scanner — AI is contextual to vulns/paths. Use <code>/api/ai/explain</code> directly for custom questions.</div>
}

export default function App(){
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
              <Route path="/graph" element={<GraphExplorer/>}/>
              <Route path="/risk" element={<RiskAnalysis/>}/>
              <Route path="/findings" element={<Findings/>}/>
              <Route path="/ai" element={<AIPage/>}/>
              <Route path="/reports" element={<Reports/>}/>
            </Routes>
          </main>
          <footer className="text-center text-[11px] text-slate-500 py-4">© 2026 Intelligent Graph-Based Attack Path Discovery • Advanced Mode • WebSocket Realtime • For authorized use only</footer>
        </div>
      </div>
    </BrowserRouter>
  )
}
