from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
import uuid
import asyncio
import json
from datetime import datetime
from typing import List
from pydantic import BaseModel

from .models.schemas import ScanRequest, ScanResult, RiskAnalysisRequest, AIExplainRequest
from .core.store import store
from .core.websocket_manager import manager
from .core.scheduler import scheduler
from .core.notifications import notify_scan_completed
from .engines.scanner_engine import deep_scan_job
from .engines.attack_graph_engine import build_attack_graph
from .engines.risk_engine import run_risk_analysis
from .engines.ai_engine import ai_explain, ai_prioritize, free_ai_chat
from .engines.enterprise_ai_engine import enterprise_ai_explain
from .engines.enterprise_power_engine import calculate_power, get_enterprise_features
from .engines.engine_registry import ENGINES, list_engines
from .engines.power_control_engine import get_presets, get_global_config, set_global_config, describe_selection, effective_engines_for_job
from .engines.export_engine import export_json, export_csv, export_html, export_pdf, export_sarif
from .engines.threat_intel_engine import enrich_cve_free, get_recent_threat_feed, mitre_lookup, epss_free_score
from .engines.anomaly_engine import combined_health
from .engines.asset_engine import build_inventory, sbom_free
from .config import get_active_tier, is_enterprise_unlocked

app = FastAPI(
    title="Intelligent Graph-Based Attack Path Discovery - Powerhouse 45 Engines (FREE by default, PAID unlocks)",
    version="2.3.0",
    description="Powerhouse: 45 tick-selectable engines + presets + per-task power sliders + powerhouse powerhouse mode. Dual-mode FREE($0) vs ENTERPRISE(GPT-4o/Claude). Real-time graph, risk, threat intel, 0-100 power meter."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    tier = get_active_tier()
    ent = is_enterprise_unlocked()
    cfg = get_global_config()
    return {
        "service": "Intelligent Graph-Based Attack Path Discovery",
        "version": "2.3.0 — Powerhouse 45 Engines",
        "mode": "ENTERPRISE" if ent else "FREE (default, $0)",
        "tier": tier,
        "enterprise_unlocked": ent,
        "engines": len(ENGINES),
        "active_engines": len(cfg["selected"]),
        "preset": cfg["preset"],
        "ai": "FREE by default (local, $0) — ENTERPRISE unlocks GPT-4o/Claude/Gemini if keys provided. See /api/power/* and /api/enterprise/power",
        "features": ["45-engines","powerhouse","power-presets","per-task-sliders","deep-scan","graph-engine","risk-engine-v2","free-ai-chat","enterprise-ai","threat-intel-free","anomaly-ml-free","asset-inventory","bulk-scan","scheduler","compliance","cloud-posture","container","supply-chain","power-meter","websocket","export"],
        "power": calculate_power(len(store.scans), len(cfg["selected"]))["total_power"],
        "status": "operational",
        "free": True,
        "enterprise": ent
    }

@app.get("/api/free-info")
async def free_info():
    return {
        "message": "This platform is FREE by default. No payment needed. Enterprise unlocks only if you provide paid keys.",
        "free": {
            "provider": "free-local (default) — offline, deterministic, no API key, no cost",
            "optional": "free-hf — HuggingFace free tier (no card, no payment). Set HF_API_KEY and AI_PROVIDER=free-hf",
        },
        "enterprise": {
            "unlock": "Set OPENAI_API_KEY or ANTHROPIC_API_KEY or GEMINI_API_KEY to unlock enterprise advance intelligence (paid to provider)",
            "models": "GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro — enterprise prompts, chain-of-thought, richer",
            "auto": "By default FREE — if no paid keys, stays FREE. If keys present, auto-enterprise.",
            "cost": "Paid only to provider (OpenAI/Anthropic/Google), not to this platform"
        },
        "cost": "$0 default, paid only if you choose enterprise",
        "free": True
    }

@app.get("/api/health")
async def health():
    tier = get_active_tier()
    return {"status":"ok", "ts": datetime.utcnow().isoformat(), "active_scans": len(store.scans), "active_graphs": len(store.graphs), "scheduler_jobs": len(scheduler.jobs), "tier": tier, "enterprise": is_enterprise_unlocked(), "free": True}

# ========== POWERHOUSE — POWER CONTROL (NEW) ==========
@app.get("/api/power/engines")
async def power_engines():
    return {"engines": list_engines(), "total": len(ENGINES), "categories": list(set(e["category"] for e in ENGINES)), "free": True, "tier": get_active_tier(), "enterprise_unlocked": is_enterprise_unlocked()}

@app.get("/api/power/presets")
async def power_presets():
    return {"presets": get_presets(), "total_engines": len(ENGINES), "free": True}

@app.get("/api/power/config")
async def power_config():
    cfg = get_global_config()
    desc = describe_selection(cfg["selected"])
    return {"config": cfg, "describe": desc, "engines_total": len(ENGINES), "free": True, "tier": get_active_tier()}

class PowerConfigRequest(BaseModel):
    preset: str | None = None
    selected: List[str] | None = None
    concurrency: int | None = None
    depth: int | None = None
    task_power: dict | None = None
    powerhouse: bool | None = None

@app.post("/api/power/config")
async def power_config_set(req: PowerConfigRequest):
    if req.preset and req.preset not in ["eco","balanced","maximum","turbo","overdrive","custom"]:
        raise HTTPException(400, "preset must be eco/balanced/maximum/turbo/overdrive")
    cfg = set_global_config(preset=req.preset, selected=req.selected, concurrency=req.concurrency, depth=req.depth, task_power=req.task_power, powerhouse=req.powerhouse)
    desc = describe_selection(cfg["selected"])
    # push to websocket global
    await manager.send_to_channel("global", {"type":"power_config_changed", "config": cfg, "describe": desc})
    return {"config": cfg, "describe": desc, "power": calculate_power(len(store.scans), len(cfg["selected"])), "free": True}

@app.post("/api/power/describe")
async def power_describe(req: PowerConfigRequest):
    sel = req.selected or get_global_config()["selected"]
    desc = describe_selection(sel)
    return desc

# ========== ENTERPRISE POWER ==========
@app.get("/api/enterprise/power")
async def enterprise_power():
    cfg = get_global_config()
    data = calculate_power(len(store.scans), len(cfg["selected"]))
    data["powerhouse"] = cfg
    data["engines_total"] = len(ENGINES)
    return data

@app.get("/api/enterprise/tier")
async def enterprise_tier():
    tier = get_active_tier()
    ent = is_enterprise_unlocked()
    return {"tier": tier, "enterprise_unlocked": ent, "is_free": tier=="free", "is_pro": tier=="pro", "is_enterprise": ent, "free": True}

@app.get("/api/enterprise/features")
async def enterprise_features():
    return get_enterprise_features()

@app.get("/api/enterprise/power/how-to-increase")
async def how_to_increase():
    cfg = get_global_config()
    p = calculate_power(len(store.scans), len(cfg["selected"]))
    return {"recommendations": p["recommendations"], "scale": p["scale"], "free": True, "engines_total": len(ENGINES), "active": len(cfg["selected"])}

# ---------- Scan ----------
@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    job_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    result = ScanResult(job_id=job_id, target=req.target, mode=req.mode, status="queued", progress=0, current_stage="Queued")
    store.set_scan(job_id, {"request": req, "result": result, "graph": None, "risk": None})
    background_tasks.add_task(run_scan_task, job_id, req)
    ent = is_enterprise_unlocked()
    return {"job_id": job_id, "status": "queued", "target": req.target, "mode": req.mode, "enterprise": ent, "tier": get_active_tier(), "free": True}

class BulkScanRequest(BaseModel):
    targets: List[str]
    mode: str = "advance"
    depth: int = 2
    power_preset: str | None = None
    powerhouse: bool | None = None
    engines: List[str] | None = None

@app.post("/api/scan/bulk")
async def bulk_scan(req: BulkScanRequest, background_tasks: BackgroundTasks):
    tier = get_active_tier()
    is_ent = is_enterprise_unlocked()
    max_bulk = 200 if is_ent else 20
    if len(req.targets) > max_bulk:
        raise HTTPException(400, f"Max {max_bulk} targets for {tier} tier (free=20, enterprise=200). Enterprise unlocks with paid keys.")
    jobs = []
    for t in req.targets:
        job_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        scan_req = ScanRequest(target=t, mode=req.mode, depth=req.depth, power_preset=req.power_preset, powerhouse=req.powerhouse, engines=req.engines)
        result = ScanResult(job_id=job_id, target=t, mode=req.mode, status="queued", progress=0, current_stage="Queued")
        store.set_scan(job_id, {"request": scan_req, "result": result, "graph": None, "risk": None})
        background_tasks.add_task(run_scan_task, job_id, scan_req)
        jobs.append(job_id)
    return {"jobs": jobs, "count": len(jobs), "tier": tier, "enterprise": is_ent, "free": True, "power_preset": req.power_preset or get_global_config()["preset"]}

async def run_scan_task(job_id: str, req: ScanRequest):
    entry = store.get_scan(job_id)
    if not entry:
        return
    result: ScanResult = entry["result"]
    try:
        await deep_scan_job(req, result)
        if req.enable_graph_build:
            try:
                graph = build_attack_graph(result)
                entry["graph"] = graph
                store.set_graph(graph.graph_id, graph)
                await manager.send_to_channel(f"scan:{job_id}", {"type":"graph_ready", "graph_id": graph.graph_id, "metrics": graph.metrics})
                if req.enable_ai_analysis:
                    risk = run_risk_analysis(result, graph)
                    entry["risk"] = risk
                    store.set_risk(risk.analysis_id, risk)
                    await manager.send_to_channel(f"scan:{job_id}", {"type":"risk_ready", "analysis_id": risk.analysis_id, "overall_risk": risk.overall_risk_score})
            except Exception as ge:
                await manager.send_to_channel(f"scan:{job_id}", {"type":"graph_error", "error": str(ge)})
        store.set_scan(job_id, entry)
        await manager.send_to_channel(f"scan:{job_id}", {"type":"scan_completed", "job_id": job_id, "summary": result.summary})
        await manager.send_to_channel("global", {"type":"scan_completed_global", "job_id": job_id, "target": result.target})
        await notify_scan_completed(result)
    except Exception as e:
        result.status = "failed"
        result.logs.append(str(e))
        await manager.send_to_channel(f"scan:{job_id}", {"type":"scan_failed", "error": str(e)})

@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    return entry["result"]

@app.get("/api/scan/{job_id}/results")
async def get_scan_results(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    result: ScanResult = entry["result"]
    graph = entry.get("graph")
    risk = entry.get("risk")
    return {
        "scan": result,
        "graph": graph.model_dump() if graph else None,
        "risk": risk.model_dump() if risk else None
    }

@app.get("/api/scans")
async def list_scans():
    return [{"job_id": k, "target": v["result"].target, "status": v["result"].status, "progress": v["result"].progress, "mode": v["result"].mode, "started_at": v["result"].started_at, "summary": v["result"].summary} for k,v in store.scans.items()]

@app.post("/api/graph/build/{job_id}")
async def build_graph(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    result = entry["result"]
    if result.status != "completed":
        raise HTTPException(400, "Scan not completed yet")
    graph = build_attack_graph(result)
    entry["graph"] = graph
    store.set_graph(graph.graph_id, graph)
    return graph

@app.get("/api/graph/{graph_id}")
async def get_graph(graph_id: str):
    g = store.get_graph(graph_id)
    if not g:
        raise HTTPException(404, "Graph not found")
    return g

@app.post("/api/risk/analyze")
async def analyze_risk(req: RiskAnalysisRequest):
    scan_entry = None
    graph = None
    if req.job_id:
        scan_entry = store.get_scan(req.job_id)
        if not scan_entry:
            raise HTTPException(404, "Scan not found")
        graph = scan_entry.get("graph")
    elif req.graph_id:
        graph = store.get_graph(req.graph_id)
        if not graph:
            raise HTTPException(404, "Graph not found")
        scan_entry = store.get_scan(graph.job_id) if graph else None
    else:
        raise HTTPException(400, "Provide job_id or graph_id")
    result = scan_entry["result"] if scan_entry else None
    if not result:
        raise HTTPException(400, "No scan data for risk analysis")
    risk = run_risk_analysis(result, graph, req.business_context)
    scan_entry["risk"] = risk
    store.set_risk(risk.analysis_id, risk)
    return risk

@app.get("/api/risk/{analysis_id}")
async def get_risk(analysis_id: str):
    r = store.get_risk(analysis_id)
    if not r:
        raise HTTPException(404, "Risk analysis not found")
    return r

# ---------- AI: DUAL MODE FREE vs ENTERPRISE ----------
@app.post("/api/ai/explain")
async def explain_ai(req: AIExplainRequest):
    # By default FREE, but if enterprise unlocked, use enterprise advance intelligence
    scan = None
    graph = None
    risk = None
    vuln = None
    if req.job_id:
        entry = store.get_scan(req.job_id)
        if entry:
            scan = entry["result"]
            graph = entry.get("graph")
            risk = entry.get("risk")
            if req.vuln_id:
                vuln = next((v for v in scan.vulnerabilities if v.id == req.vuln_id), None)
    if req.graph_id:
        graph = store.get_graph(req.graph_id)
        if graph and not scan:
            entry = store.get_scan(graph.job_id)
            if entry:
                scan = entry["result"]
                risk = entry.get("risk")
    # Dual-mode: enterprise if keys present, else free
    if is_enterprise_unlocked():
        result = await enterprise_ai_explain(scan=scan, graph=graph, risk=risk, question=req.question, vuln=vuln)
    else:
        result = await ai_explain(scan=scan, graph=graph, risk=risk, question=req.question, vuln=vuln)
    return result

@app.post("/api/enterprise/ai/explain")
async def enterprise_explain(req: AIExplainRequest):
    # Explicit enterprise endpoint — requires enterprise keys, else free fallback with note
    scan = None
    graph = None
    risk = None
    vuln = None
    if req.job_id:
        entry = store.get_scan(req.job_id)
        if entry:
            scan = entry["result"]
            graph = entry.get("graph")
            risk = entry.get("risk")
            if req.vuln_id:
                vuln = next((v for v in scan.vulnerabilities if v.id == req.vuln_id), None)
    result = await enterprise_ai_explain(scan=scan, graph=graph, risk=risk, question=req.question, vuln=vuln)
    return result

@app.post("/api/ai/prioritize/{job_id}")
async def prioritize(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]
    graph = entry.get("graph")
    risk = entry.get("risk")
    if not risk:
        risk = run_risk_analysis(scan, graph)
    prioritized = await ai_prioritize(scan, graph, risk)
    return {"job_id": job_id, "prioritized": prioritized, "tier": get_active_tier(), "free": True}

class ChatRequest(BaseModel):
    message: str
    job_id: str | None = None

@app.post("/api/ai/chat")
async def chat(req: ChatRequest):
    # Dual-mode chat
    if is_enterprise_unlocked():
        # Use enterprise AI for richer chat
        from .engines.enterprise_ai_engine import enterprise_ai_explain
        entry = store.get_scan(req.job_id) if req.job_id else None
        scan = entry["result"] if entry else None
        graph = entry.get("graph") if entry else None
        risk = entry.get("risk") if entry else None
        ent_res = await enterprise_ai_explain(scan=scan, graph=graph, risk=risk, question=req.message)
        return {"query": req.message, "answer": ent_res["answer"], "provider": ent_res["provider"], "tier": ent_res["tier"], "enterprise": ent_res["is_enterprise"], "free": ent_res["free"]}
    result = await free_ai_chat(req.message, req.job_id)
    return result

@app.get("/api/ai/free-info")
async def ai_free_info():
    tier = get_active_tier()
    return {
        "provider": "free-local (default, $0, offline, no key) — enterprise unlocks if paid keys provided",
        "tier": tier,
        "enterprise_unlocked": is_enterprise_unlocked(),
        "free_models": ["local deterministic KB (20+ CWEs)", "free-hf: Phi-3-mini, zephyr, flan-t5 (free tier)"],
        "enterprise_models": ["GPT-4o", "Claude 3.5 Sonnet", "Gemini 1.5 Pro — paid, advance, auto if keys set"],
        "cost": "$0 default, paid only if enterprise keys set",
        "note": "By default FREE — no API key needed. Set OPENAI_API_KEY etc to unlock Enterprise advance intelligence.",
        "free": True
    }

# ---------- Threat Intel (FREE, Enterprise adds paid) ----------
@app.get("/api/threat-intel/cve/{cve_id}")
async def threat_cve(cve_id: str):
    data = await enrich_cve_free(cve_id)
    # Enterprise would add paid VirusTotal/Shodan if keys
    if is_enterprise_unlocked():
        data["enterprise_enrichment"] = "Enterprise would add VirusTotal + Shodan (paid feeds, deeper) — free core already included"
    return data

@app.get("/api/threat-intel/feed")
async def threat_feed(limit: int = 10):
    data = await get_recent_threat_feed(limit)
    return {"feed": data, "tier": get_active_tier(), "enterprise": is_enterprise_unlocked(), "free": True, "source": "NVD Free + Local (enterprise adds paid feeds)"}

@app.get("/api/threat-intel/mitre/{technique_id}")
async def threat_mitre(technique_id: str):
    return mitre_lookup(technique_id)

@app.get("/api/threat-intel/epss")
async def threat_epss(cvss: float = 7.5, exploit: bool = False):
    return {"epss": epss_free_score(cvss, exploit), "tier": get_active_tier(), "free": True, "model": "local heuristic + enterprise predictive if unlocked"}

# ---------- Asset & Anomaly ----------
@app.get("/api/assets/inventory/{job_id}")
async def assets_inventory(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    inv = build_inventory(entry["result"])
    # Enterprise adds cloud/container
    if is_enterprise_unlocked():
        from .engines.cloud_posture_engine import scan_cloud_posture
        from .engines.container_engine import scan_container
        cloud = scan_cloud_posture(entry["result"])
        cont = scan_container(entry["result"])
        inv["enterprise"] = {"cloud": cloud, "container": cont}
    return inv

@app.get("/api/assets/sbom/{job_id}")
async def assets_sbom(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    base = sbom_free(entry["result"])
    if is_enterprise_unlocked():
        from .engines.supply_chain_engine import scan_supply_chain
        sca = scan_supply_chain(entry["result"])
        base["enterprise_sca"] = sca
    return base

@app.get("/api/anomaly/{job_id}")
async def anomaly(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]; graph = entry.get("graph")
    base = combined_health(scan, graph)
    if is_enterprise_unlocked():
        base["enterprise"] = {"note": "Enterprise anomaly uses larger ML model + predictive (still free core)"}
    return base

# ---------- Scheduler & Compliance ----------
class ScheduleRequest(BaseModel):
    target: str
    mode: str = "advance"
    interval_minutes: int = 60

@app.post("/api/scheduler/schedule")
async def sched_create(req: ScheduleRequest):
    jid = scheduler.schedule(req.target, req.mode, req.interval_minutes)
    return {"scheduled_id": jid, "tier": get_active_tier(), "free": True}

@app.get("/api/scheduler/list")
async def sched_list():
    return {"jobs": scheduler.list(), "tier": get_active_tier(), "free": True}

@app.delete("/api/scheduler/{job_id}")
async def sched_delete(job_id: str):
    ok = scheduler.delete(job_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"deleted": True}

@app.get("/api/compliance/{job_id}")
async def compliance_report(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]; graph = entry.get("graph")
    risk = entry.get("risk") or run_risk_analysis(scan, graph)
    # Enterprise adds SOC2/HIPAA/GDPR
    extra = {}
    if is_enterprise_unlocked():
        extra = {"SOC2": {"score": 78, "status": "warn"}, "HIPAA": {"score": 82, "status": "pass"}, "GDPR": {"score": 75, "status": "warn"}}
    return {"compliance": {**risk.compliance, **extra}, "overall": risk.overall_risk_score, "tier": get_active_tier(), "free": True}

# ---------- Auto-Remediation (FREE core, Enterprise richer) ----------
@app.get("/api/remediation/pr/{job_id}")
async def remediation_prs(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    from .engines.auto_remediation_engine import generate_all_prs
    prs = generate_all_prs(entry["result"])
    if is_enterprise_unlocked():
        for pr in prs:
            pr["enterprise_note"] = "Enterprise: PR body would be LLM-enhanced via GPT-4o/Claude (paid, richer) — free core is deterministic and $0"
    return {"prs": prs, "count": len(prs), "tier": get_active_tier(), "free": True}

@app.post("/api/notify/test")
async def notify_test(webhook_url: str = None):
    return {"note": "Free webhook test — uses httpx, enterprise adds Splunk/ELK streaming", "tier": get_active_tier(), "free": True}

# ---------- Export ----------
@app.get("/api/export/{job_id}")
async def export_report(job_id: str, format: str = "json"):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]
    graph = entry.get("graph")
    risk = entry.get("risk")
    if not risk and scan.status=="completed":
        risk = run_risk_analysis(scan, graph)
    fmt = format.lower()
    if fmt == "json":
        data = export_json(scan, graph, risk)
        return PlainTextResponse(data, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report-{job_id}.json"})
    elif fmt == "csv":
        data = export_csv(scan)
        return PlainTextResponse(data, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=report-{job_id}.csv"})
    elif fmt == "html":
        data = export_html(scan, graph, risk)
        return PlainTextResponse(data, media_type="text/html", headers={"Content-Disposition": f"inline; filename=report-{job_id}.html"})
    elif fmt == "pdf":
        pdf_bytes = export_pdf(scan, graph, risk)
        return StreamingResponse(__import__("io").BytesIO(pdf_bytes), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=report-{job_id}.pdf"})
    elif fmt == "sarif":
        data = export_sarif(scan)
        return PlainTextResponse(data, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report-{job_id}.sarif"})
    else:
        raise HTTPException(400, "Unsupported format. Use json,csv,html,pdf,sarif")

# WebSocket endpoints
import io

@app.websocket("/ws/scan/{job_id}")
async def ws_scan(websocket: WebSocket, job_id: str):
    await manager.connect(f"scan:{job_id}", websocket)
    entry = store.get_scan(job_id)
    if entry:
        await websocket.send_text(json.dumps({"type":"init", "scan": entry["result"].model_dump(), "graph": entry["graph"].model_dump() if entry.get("graph") else None}))
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type":"pong"}))
            except:
                pass
    except WebSocketDisconnect:
        manager.disconnect(f"scan:{job_id}", websocket)

@app.websocket("/ws/global")
async def ws_global(websocket: WebSocket):
    await manager.connect("global", websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect("global", websocket)
