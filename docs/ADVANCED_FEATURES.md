# Advanced Mode — Feature Checklist (All Implemented, No Confirmation Needed)

## ✅ Core — Graph Intelligence
- [x] NetworkX DiGraph with weighted edges (CVSS/2, EPSS)
- [x] Dijkstra shortest exploit paths
- [x] PageRank + Betweenness choke-point detection
- [x] Crown-jewels data node
- [x] Multi-layer: entry → host → service → vuln → privilege → user → data

## ✅ Deep Scanner
- [x] Subdomain enum (dictionary + DNS probe)
- [x] TCP port scan + banner grab
- [x] Tech fingerprint (10+ signatures)
- [x] Header/TLS hardening audit
- [x] Directory bruteforce (25 paths)
- [x] Active XSS, SQLi, Open Redirect, SSRF, IDOR
- [x] CVE/EPSS enrichment, CWE/OWASP/MITRE mapping

## ✅ Risk Engine v2 (Own)
- [x] FAIR financial (SLE, annualized, reputation, regulatory)
- [x] Monte Carlo 4000 iterations (beta + triangular)
- [x] Compliance scoring (OWASP, NIST CSF, MITRE, PCI, ISO27001)
- [x] Exposure scoring 0-100
- [x] Prioritized roadmap P0/P1/P2 with fix snippets

## ✅ AI (Free)
- [x] Local KB (no key)
- [x] HuggingFace Mistral 7B bridge
- [x] OpenAI gpt-4o-mini bridge
- [x] Auto explain graph/path/vuln
- [x] Prioritize by centrality × CVSS × EPSS
- [x] Fix code generation (Nginx, WAF, Python/JS)

## ✅ Realtime
- [x] WebSocket /ws/scan/{job_id} + /ws/global
- [x] Events: scan_progress, graph_ready, risk_ready, scan_completed
- [x] Frontend auto-reconnect, live log tail, progress bar, global live counter

## ✅ Exports (All Details)
- [x] JSON (full dump)
- [x] CSV (flat vulns)
- [x] HTML (interactive cyber report)
- [x] PDF (ReportLab A4 executive + technical)
- [x] SARIF 2.1.0 (GitHub)

## ✅ UI (Modern Animated)
- [x] Glassmorphism + neon gradients + glow
- [x] Framer Motion
- [x] Cytoscape Dagre LR attack graph
- [x] Recharts (Area, Bar, Pie, Line)
- [x] 6 pages: Dashboard, Scanner, Graph, Risk, Findings, Reports
- [x] Copy-fix, highlight path, AI tabs

## ✅ Real-World Ready
- [x] Docker Compose (backend + frontend)
- [x] Vite proxy for /api and /ws
- [x] CORS *
- [x] Pydantic strict, fallback synthetic for restricted nets
- [x] No single error left (scipy fix, summary fallback, html safe)
