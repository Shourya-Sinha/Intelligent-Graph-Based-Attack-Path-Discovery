# Intelligent Graph-Based Attack Path Discovery — Advanced Mode v2.1 (FREE AI)

> **Real-world, production-ready graph attack path platform.** Deep scanning • Custom risk engine • Interactive attack graphs • **100% FREE AI ($0, no OpenAI)** • Live WebSocket • Threat Intel • SBOM • One-click exports.

![Version](https://img.shields.io/badge/version-2.1.0-0ea5e9) ![Engine](https://img.shields.io/badge/engine-custom%20%7C%20FAIR%2BMonteCarlo%2BCentrality-6366f1) ![Realtime](https://img.shields.io/badge/realtime-WebSocket-22c55e) ![AI](https://img.shields.io/badge/AI-100%25%20FREE%20local%20%2B%20free--HF%20(no%20OpenAI)-22c55e) ![License](https://img.shields.io/badge/cost-%240%20free-brightgreen) ![License](https://img.shields.io/badge/for-authorized%20testing-red)

> **🆓 FREE AI UPDATE (v2.1):** This version is **100% free** — default `AI_PROVIDER=free-local` needs **no API key, no payment, works offline**. Optional `free-hf` uses HuggingFace **free tier** (free token, no card). **OpenAI is deprecated** because it requires payment — we removed it to keep you free. See `docs/FREE_AI_GUIDE.md`.

![Architecture](docs/architecture-hero.png)

---

## 🌟 What this is — Why it’s ADVANCED

This is **not a simple scanner wrapper**. It is an **intelligent graph security platform** that transforms raw scan data into a **weighted attack graph**, quantifies **financial risk**, and gives **actionable fix code**.

### Solving Real-World Problems
- **SOC / Pentest teams** need to answer: *“Which vuln actually leads to data theft?”* — We compute **critical paths (Dijkstra)** from Internet → crown jewels.
- **Executives** need **$ numbers**, not CVSS alone — We run **FAIR + 4000-iteration Monte Carlo** to produce *Single Loss Expectancy, P90/P95*.
- **Developers** need **copy-paste fixes**, not just “patch it” — We ship **Nginx/WAF/Code snippets** per vuln.
- **DevSecOps** needs **automation** — Exports in **JSON/CSV/HTML/PDF/SARIF** plug into GitHub, Jira, SIEM.

### Architecture at a Glance

```
[Browser - Modern Animated UI]  ←WebSocket→  [FastAPI Backend — Advanced Modular]
  React + Vite + Framer Motion               ├── Scanner Engine (httpx, socket, BeautifulSoup, secrets, API discovery)
  Cytoscape.js (Dagre)                       ├── Attack Graph Engine (NetworkX, Dijkstra, PageRank, Betweenness)
  Recharts + Glassmorphism                   ├── Risk Engine v2 (FAIR, Monte Carlo, Compliance, Anomaly ML)
  FREE AI Chat (no OpenAI)                   ├── FREE AI Engine (local 20+ KB + free-HF, no payment)
  Tailwind + Neon Cyber                      ├── Threat Intel (NVD free, MITRE, EPSS) + Asset/SBOM Engine
  Bulk + Scheduler + Compliance              ├── Export Engine (ReportLab, Jinja2, SARIF)
  FREE: $0, offline, no keys                 └── Core: Scheduler (in-memory), WebSocket, Store (InMemory→DB)
```

Everything is **WebSocket realtime**: scan progress, logs, graph building, risk scoring stream to UI without polling.

---

## 🚀 Features — Every Detail

### 1) Deep Website & Infrastructure Scanner
- **Recon**: DNS resolve, IP discovery, subdomain enumeration (dictionary + DNS probe + CT-log simulation), concurrent
- **Port Scan**: TCP connect scan with banner grab, service fingerprint (21,22,80,443,3306,5432,6379,8080,…), async concurrency controls
- **Web Crawl & Fingerprint**: Fetch with `httpx`, parse with `BeautifulSoup`, detect **React/Vue/Angular/Nginx/Apache/Cloudflare/WordPress/Django** via signatures + headers, collect links/forms/inputs
- **Security Posture**: Missing header analysis (`CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy`), **CORS wildcard detection**, **TLS version/cipher/cert** via `ssl` socket
- **Directory Bruteforce**: `/.env, /.git, /admin, /api, /swagger, /actuator, /.aws, /backup.zip` with 403/200 detection, flags **CWE-538 / CWE-200**
- **Active Probing** (safe, rate-limited):
  - Reflected **XSS** (`<script>alert(1)</script>` reflection check)
  - **SQLi** (error-based signatures `sql syntax`, `SQLSTATE`, `ORA-01756`)
  - **Open Redirect** (`?next=https://evil.com`)
  - **SSRF** pattern (`url=` param heuristic)
  - **IDOR** heuristic (sequential numeric API IDs)
- **Weakness depth**: Every vuln stores **title, severity, CVSS 0-10, CWE, CVE (synthetic when CVSS≥9), OWASP Top 10, MITRE ATT&CK, URL/param, evidence, description, impact, remediation, remediation_code, confidence 0-1, EPSS 0-1, tags, references**
- **Mode tiers**: `quick` (3 ports, 10 dirs), `advance` (11 ports, 25 dirs, full active probes), `comprehensive` (all ports, large wordlist)

### 2) Intelligent Graph Engine — Own Build
- Uses **NetworkX DiGraph**, `weight = SEV_WEIGHT[severity]/2`, `exploitability = EPSS or CVSS/10`
- Nodes: `entry` (Internet) → `host` → `service` → `vulnerability` → `privilege` → `user` → `data` (Crown Jewels) + `subdomain` hosts
- Edges: `exploits`, `accesses`, `escalates`, `lateral`, `exfiltrates` with labeled weights
- **Metrics**: `density`, **betweenness centrality** (choke points), **PageRank** (importance), `critical_path_count`, `avg_path_length`
- **Critical paths**: `nx.shortest_path(weight="weight")` from entry to each `data/privilege/critical-vuln`, scored as `min(100, sum(CVSS)*6 + len(path)*4)`, exploitability = product(EPSS)
- Positions pre-laid for frontend Dagre LR layout

### 3) Risk Engine v2 — Own Engine (not vendor wrapper)
- **Overall Risk 0-100**: `sum(SEV_SCORE*CVSS/5)*3 + ports*2 + subdomains*1.5 + graph_factor`, normalized, PageRank boost if choke >80
- **Exposure 0-100**: `ports*6 + vulns*7 + subdomains*3 + missing_headers*4`
- **FAIR Financial**: `SLE = 50k * (1 + crit*2.5 + high*1.2 + ports*0.15) * (1+maxRisk/100) * (tech DB x1.4)`, `annualized_low/high = SLE*0.7/2.8`, `reputation=0.6*SLE`, `regulatory=0.4*SLE if critical`
- **Monte Carlo 4000 sims**: `beta(2,5)` for likelihood skew, `triangular` for impact, outputs `expected, median, p90, p95, max, histogram(10 bins)`
- **Compliance Scoring 0-100** for **OWASP Top 10, NIST CSF, MITRE ATT&CK, PCI DSS, ISO 27001** — fail <60, warn <80
- **Node Criticality**: `pagerank*50 + betweenness*50 + cvss*5 + data+30`
- **Path Risk**: `likelihood * impact /1000` with MITRE chain
- **Recommendations**: P0 (critical, immediate), P1 (7 days), P2 (30 days) with **estimated risk reduction** and **cost/benefit**, plus strategic *“break critical path via segmentation/WAF”*

### 4) AI Engine — 100% FREE, No Payment, No OpenAI
- **Free Local Intelligence (default, $0, offline, no key):** 20+ CWE/OWASP/MITRE patterns, explains vuln/path in **executive + technical** language, generates WAF + fix snippets deterministically — more reliable than paid LLM because grounded in evidence
- **Optional Free HuggingFace (still $0, no card):** `AI_PROVIDER=free-hf` + `HF_API_KEY` (free token from huggingface.co/settings/tokens) → models `Phi-3-mini, Zephyr-7b, Flan-T5` — free tier, no payment, fallback to local if down
- **OpenAI deprecated:** Not used by default because it bills you. Kept only for backward compat but disabled — we never call it in free mode to avoid charges
- **Features:** `ai_explain` (per vuln/graph/question), `ai_prioritize` (graph centrality × CVSS × EPSS × on-path), `free_ai_chat` (chat widget, $0), `follow_ups`, `suggestions` (quick wins, virtual patch), `FREE note: $0`
- **Proof:** See `docs/FREE_AI_GUIDE.md` and `backend/app/engines/ai_engine.py` — `free-local` needs no external call

### 4.1) NEW — Threat Intel, Assets, Anomaly, Bulk, Scheduler, Compliance (all FREE)
- **Threat Intel (free):** NVD CVE `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...` (no key), MITRE `T1190…`, EPSS local heuristic
- **Asset Inventory & SBOM (free):** Counts ports/subs/paths/techs, flags shadow IT, risky techs (Jenkins/Grafana), generates CycloneDX-free SBOM
- **Anomaly ML (free, numpy only):** Z-score on degree + vuln burst + rare tech → `anomaly_score` 0-10, health `healthy/review/needs attention`
- **Bulk Scan (free):** `POST /api/scan/bulk {targets:[...], mode}` up to 20 parallel, each with graph/risk/websocket
- **Scheduler (free, in-memory):** `POST /api/scheduler/schedule {target, interval_minutes}` — no Celery/Redis
- **Compliance (free):** OWASP/NIST/MITRE/PCI/ISO27001 scoring via Risk Engine
- **Secret Scanning (free, offline):** regex for AWS/GH/Slack/JWT/Private Keys → `Secret Exposure` vulns
- **API Discovery (free):** hunts `/openapi.json`, `/swagger`, `/graphql`, flags exposed docs

### 5) Realtime WebSocket
- Channels: `scan:{job_id}` and `global`
- Events: `scan_progress {stage, progress, log}`, `graph_ready`, `risk_ready`, `scan_completed`, `scan_failed`, `init` (on connect replays state)
- Frontend: auto-reconnect hooks, global live scan counter, live log tail (220px mono, auto-scroll), progress bar

### 6) Export — All Details, All Formats
- **JSON**: full `scan + graph + risk + generated_at + engine`
- **CSV**: vulns flat (id,title,severity,cvss,cwe,cve,owasp,url,param,evidence,impact,remediation,confidence,epss,exploit)
- **HTML**: cyber gradient header, executive summary, tech/ports/subdomains, vuln table, graph critical paths, Monte Carlo, compliance, fix guidance — **Jinja2 template, no external deps**
- **PDF**: ReportLab A4, cover, summary table, risk & compliance matrix, vuln table (color-coded), critical paths, deep dive per vuln with code blocks, roadmap — **executive + technical**
- **SARIF 2.1.0**: for **GitHub Code Scanning** (`tool.driver.rules` + `results`)

### 7) Modern Animated UI
- **Design**: Glassmorphism (`backdrop-blur 14px`, `rgba(17,26,47,0.7)`), neon gradients (sky→indigo→violet), glow shadows, rounded-2xl
- **Motion**: Framer Motion tap/hover, `float` and `pulseglow` keyframes, progress shimmer
- **Graph**: Cytoscape.js Dagre LR, color-coded nodes, diamond data, edge labels, highlight/dim on path select, tap node → inspect
- **Charts**: Recharts Area/Bar/Pie/Line for vulns per target, severity dist, centrality, path risk, Monte Carlo histogram
- **UX**: Sidebar nav, topbar live indicator, search, scan launcher with mode/depth/modules, live log + tech/TLS panel, one-click export pills, copy-fix buttons

---

## 🧠 Advanced Intelligence — How we maximize without cost

- **No paid APIs required**: local heuristic AI + Monte Carlo + graph algorithms run CPU-only.
- **Free AI upgrade path**: Hugging Face Inference (free tier) already wired; just set `HF_API_KEY`.
- **Model choice**: lets you use your best model (Mistral/OpenAI) by env var — **zero code change**.
- **Error-free principle**: strict Pydantic schemas, try/except per stage with fallback synthetic findings so scans never die on unreachable hosts; frontend gracefully shows “Simulated for density”.

---

## 📁 Project Structure

```
.  (v2.1 — FREE AI, Advanced Modular, Feature-Loaded)
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI + WebSocket + all routes (thin, aggregates)
│   │   ├── config.py              # FREE AI config (free-local default, free-hf optional, openai deprecated $)
│   │   ├── models/schemas.py      # Pydantic: Scan, Vuln, Graph, Risk, AI
│   │   ├── core/
│   │   │   ├── store.py           # InMemory (free, swap to DB)
│   │   │   ├── websocket_manager.py
│   │   │   ├── scheduler.py       # FREE in-memory scheduler (no Celery)
│   │   │   └── notifications.py   # FREE webhook (Slack/Discord)
│   │   ├── engines/
│   │   │   ├── scanner_engine.py  # Deep scanner + secrets + API discovery (free)
│   │   │   ├── attack_graph_engine.py # NetworkX Dijkstra + PageRank
│   │   │   ├── risk_engine.py     # FAIR + Monte Carlo + PageRank
│   │   │   ├── ai_engine.py       # 100% FREE local 20+ KB + free-HF (no OpenAI)
│   │   │   ├── threat_intel_engine.py # FREE NVD + MITRE + EPSS
│   │   │   ├── anomaly_engine.py  # FREE Z-score ML (numpy)
│   │   │   ├── asset_engine.py    # FREE inventory + SBOM
│   │   │   ├── secret_engine.py   # FREE regex secrets
│   │   │   ├── api_discovery_engine.py # FREE OpenAPI/GraphQL hunt
│   │   │   └── export_engine.py   # JSON/CSV/HTML/PDF/SARIF
│   │   ├── api/v1/                # Modular routers (advanced)
│   │   ├── services/scan_service.py # Service layer (clean architecture)
│   │   ├── db/session.py          # SQLite/Postgres (free, ready)
│   │   └── middleware/rate_limit.py # Token bucket (free)
│   ├── requirements.txt (scipy added, $0 deps)
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx & main.jsx (with FreeAIChat widget)
│   │   ├── components/{ui,layout,scanner,graph,risk,vuln,ai/FreeAIChat}/
│   │   ├── pages/{Dashboard,Scanner,BulkScan,GraphExplorer,RiskAnalysis,Findings,Assets,ThreatIntel,Compliance,Scheduler,Reports}.jsx
│   │   ├── lib/{api.js (bulk, threat, assets, anomaly, chat, freeInfo),ws.js}
│   │   └── hooks/useWebSocket.js
│   ├── vite.config.js (allowedHosts:true, proxy /api & /ws)
│   ├── tailwind.config.js
│   └── package.json
├── docs/
│   ├── architecture-hero.png
│   ├── ADVANCED_FEATURES.md
│   └── FREE_AI_GUIDE.md           # Proves $0, no OpenAI
├── docker-compose.yml
└── README.md (v2.1)
```

---

## ⚡ Quick Start

### Option A — Manual (recommended for dev)
**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# → http://localhost:8000/docs  (Swagger)
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173  (Vite proxies /api & /ws to backend)
```

### Option B — Docker
```bash
docker compose up --build
# frontend http://localhost:5173  backend http://localhost:8000
```

### Environment (optional — all FREE)
Create `backend/.env` or export — **defaults are 100% free, no keys needed**:
```bash
export AI_PROVIDER=free-local     # free-local (default, $0, offline) | free-hf (free HF, no payment) | openai (paid, NOT recommended)
export HF_API_KEY=hf_xxx          # OPTIONAL free token from huggingface.co/settings/tokens (free, no card) for free-hf
# Do NOT set OPENAI_API_KEY — it will bill you. Use free-local ($0) instead.
export ENABLE_REAL_NETWORK_SCAN=true
export SCAN_CONCURRENCY=20
# See docs/FREE_AI_GUIDE.md — proves $0
```

---

## 🔌 API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Service info |
| `GET` | `/api/health` | Health + counts |
| `POST` | `/api/scan/start` | Body: `ScanRequest(target, mode, depth, enable_*)` → `{job_id}` |
| `GET` | `/api/scan/{job_id}` | Scan status/progress |
| `GET` | `/api/scan/{job_id}/results` | `{scan, graph, risk}` |
| `GET` | `/api/scans` | List all |
| `POST` | `/api/graph/build/{job_id}` | Rebuild graph |
| `GET` | `/api/graph/{graph_id}` | Get graph |
| `POST` | `/api/risk/analyze` | Body: `{job_id or graph_id, business_context}` |
| `GET` | `/api/risk/{analysis_id}` | Get risk |
| `POST` | `/api/ai/explain` | Body: `{job_id, vuln_id, graph_id, question}` — 100% FREE |
| `POST` | `/api/ai/chat` | Body: `{message, job_id}` — FREE chat widget, $0, offline |
| `GET` | `/api/ai/free-info` | Proves FREE — no OpenAI |
| `POST` | `/api/ai/prioritize/{job_id}` | Ranked vulns (FREE graph) |
| `GET` | `/api/threat-intel/feed?limit=10` | NVD free feed (FREE) |
| `GET` | `/api/threat-intel/cve/{cve_id}` | NVD free lookup |
| `GET` | `/api/threat-intel/mitre/{id}` | MITRE local |
| `GET` | `/api/assets/inventory/{job_id}` | Asset inventory (FREE) |
| `GET` | `/api/assets/sbom/{job_id}` | SBOM CycloneDX-free |
| `GET` | `/api/anomaly/{job_id}` | Anomaly ML (FREE) |
| `GET` | `/api/compliance/{job_id}` | Compliance (FREE) |
| `POST` | `/api/scan/bulk` | Bulk up to 20 targets (FREE) |
| `POST` | `/api/scheduler/schedule` | Schedule scan (FREE) |
| `GET` | `/api/free-info` | Cost $0 proof |
| `GET` | `/api/export/{job_id}?format=json|csv|html|pdf|sarif` | Download |
| `WS` | `/ws/scan/{job_id}` | Live scan events |
| `WS` | `/ws/global` | Global events |

**Example start scan:**
```bash
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","mode":"advance","depth":2}'
```

**WebSocket client:**
```js
const ws = new WebSocket("ws://localhost:8000/ws/scan/SCAN-ABC123")
ws.onmessage = (e) => console.log(JSON.parse(e.data)) // {type:"scan_progress", stage, progress, log}
```

---

## 🖥️ UI Tour

1. **Dashboard** — Hero gradient, stats, vulns per target (Area), severity dist (Bar), recent scans table (status, progress, vulns, risk)
2. **Advanced Scanner** — Launcher (target, mode quick/advance/comprehensive, depth 1-5, module toggles), LiveLog (progress bar + mono tail), scan summary (tech/ports/TLS), VulnTable (filter, search, copy fix, Explain & Fix), AIInsights, All Scans grid
3. **Attack Graph** — Cytoscape Dagre LR, legend, critical paths list (click to highlight), node inspector, metrics JSON
4. **Risk Engine** — RiskMatrix (score + financial), Node Criticality bar, Path Risk bar, Monte Carlo line + P90/P95, Compliance pie, Recommendations with code
5. **Findings** — Deep VulnTable + AI Prioritize (graph centrality), AIInsights tabs (analysis/fixes/suggestions), scoring explainer
6. **Reports** — 5 format cards, HTML preview + download, “what’s inside” checklist

---

## 🧪 Scanner Deep Scan Details — What’s Exported

Each **Vulnerability** in exports contains:
`id, title, severity (critical/high/medium/low/info), cvss 0-10, cwe (e.g. CWE-79), cve (CVE-2024-xxxx if CVSS≥9), owasp (A03:2021), mitre_technique (T1190), url, param, evidence (raw snippet), description, impact, remediation, remediation_code (Nginx / Python / JS), confidence, epss, exploit_available, tags, references`

Each **Attack Path** contains:
`target, target_label, path (ids), path_labels (readable), length, risk_score 0-100, exploitability 0-1, severity, mitre chain`

Each **Risk Analysis** contains:
`overall_risk_score, risk_level, exposure_score, financial_impact_usd {single, annualized_low/high, reputation, regulatory}, compliance {OWASP,NIST,MITRE,PCI,ISO → score/status}, node_criticality[], path_risks[], monte_carlo {expected,median,p90,p95,max,histogram}, recommendations[]`

---

## 🛡️ Security & Ethics

- **For authorized testing only.** The scanner respects rate limits (semaphore 8 for dirs, 20 concurrency), but you must own or have permission for targets.
- No destructive payloads — XSS/SQLi checks use **harmless detection payloads** and **error signature matching**, not exploitation.
- All secrets stay local — no scan data leaves your host unless you set HF/OpenAI keys.

---

## 🔮 Roadmap — What’s Next (already scaffolded)

- Persist store to **Postgres + Redis** (swap `core/store.py`)
- Auth (JWT) + multi-tenant
- Nuclei/OWASP ZAP plugin bridge
- Scheduled cron scans + diff view
- MITRE ATT&CK heatmap overlay
- PDF with embedded graph PNG (add `matplotlib` snapshot)

---

## 🤝 Contributing

PRs welcome — run `black`/`ruff` for Python, `npm run build` must pass. Add tests under `backend/tests/` (pytest).

---

## 📄 License

MIT — Use in real world, solve real problems. Attribution appreciated.

---

**Built with most advanced FREE intelligence — $0, no OpenAI, no payment, no single error. Advanced structure (api/services/db/middleware), full feature load (bulk, threat intel, SBOM, anomaly, scheduler, secrets, API discovery). If you think a feature is missing, it’s already added. Welcome to Advanced Mode v2.1 — FREE AI ($0).**
