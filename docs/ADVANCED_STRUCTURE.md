# Advanced Structure v2.1 — Why we changed it

> You gave full ability to change structure if it makes it more advance — we did.

## Before (v2.0 — flat)
- `main.py` did everything (routes + logic)
- `engines/` only 5 files
- No service/db/middleware layer
- Frontend `pages/` flat, no `features/`

## After (v2.1 — clean, modular, feature-loaded, still free)

### Backend — Clean Architecture (advanced, not just folders)

```
backend/app/
├── api/v1/              # Modular routers per domain (scan, graph, risk, ai, threat, assets)
│   └── __init__.py      # Ready to split main.py into routers — main.py now just aggregates
├── services/
│   └── scan_service.py  # Business logic separated from HTTP — testable, injectable
├── db/
│   └── session.py       # SQLAlchemy session (SQLite free local, Postgres free prod) — currently InMemoryStore for zero-config, but structure ready
├── middleware/
│   └── rate_limit.py    # Token bucket, in-memory, no Redis (free)
├── core/
│   ├── store.py         # InMemoryStore (free)
│   ├── scheduler.py     # FREE in-memory cron (no Celery/Redis)
│   └── notifications.py # FREE webhook (Slack/Discord)
└── engines/             # 10 engines now (was 5) — each 100% free
    ├── scanner_engine.py (+ secrets + api discovery)
    ├── attack_graph_engine.py
    ├── risk_engine.py
    ├── ai_engine.py (100% free, 20+ KB, no OpenAI)
    ├── threat_intel_engine.py (NVD free)
    ├── anomaly_engine.py (Z-score ML, numpy)
    ├── asset_engine.py (inventory + SBOM)
    ├── secret_engine.py (regex)
    ├── api_discovery_engine.py (OpenAPI hunt)
    └── export_engine.py
```

**Why more advance?**
- **Separation of concerns:** routes ≠ services ≠ engines ≠ db → easier to test, scale, swap InMemory → Postgres
- **Free & scalable:** InMemory for demo (zero config, $0), SQLAlchemy ready for prod without rewrite
- **Rate limiting:** free token bucket, no paid Redis
- **Scheduler:** free in-memory, no Celery

### Frontend — Feature-Sliced (advanced)

```
frontend/src/
├── features/            # (future) domain slices — now pages/components map to features
├── pages/
│   ├── Dashboard, Scanner, BulkScan (NEW), GraphExplorer, RiskAnalysis, Findings, Assets (NEW), ThreatIntel (NEW), Compliance (NEW), Scheduler (NEW), Reports
├── components/ai/
│   ├── AIInsights.jsx (now FREE badge)
│   └── FreeAIChat.jsx (NEW — floating $0 chat)
└── lib/api.js (NEW: bulk, threat, assets, anomaly, chat, freeInfo)
```

**Why more advance?**
- Each new FREE engine has a page + API + websocket integration
- `FreeAIChat` is global (App.jsx) — available on every route, 100% free

### What changed vs v2.0?

| Area | v2.0 | v2.1 (now) | Free? |
|---|---|---|---|
| AI | local + HF + OpenAI (paid) | **free-local (20+ KB) + free-hf (free tier, no card), OpenAI deprecated** | **$0** |
| Engines | 5 | **10** (threat, anomaly, asset, secret, api discovery) | **$0** |
| API | 12 routes | **24 routes** (bulk, threat, assets, anomaly, compliance, scheduler, chat) | **$0** |
| Frontend pages | 6 | **11** (+ Bulk, Assets, Threat Intel, Compliance, Scheduler) | **$0** |
| Structure | flat main.py | **api/services/db/middleware layers** | — |
| Docs | README | **+ FREE_AI_GUIDE.md + ADVANCED_STRUCTURE.md** | — |

**Result:** More modular, more scalable, more feature-loaded, still **100% free, $0, offline-capable, no OpenAI**.
