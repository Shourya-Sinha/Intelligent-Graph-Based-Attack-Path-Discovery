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
from .engines.export_engine import export_json, export_csv, export_html, export_pdf, export_sarif
from .engines.threat_intel_engine import enrich_cve_free, get_recent_threat_feed, mitre_lookup, epss_free_score
from .engines.anomaly_engine import combined_health
from .engines.asset_engine import build_inventory, sbom_free

app = FastAPI(
    title="Intelligent Graph-Based Attack Path Discovery - Advanced Engine (FREE AI)",
    version="2.1.0",
    description="Real-time graph-based attack path discovery with custom risk engine, deep scanner, FREE local AI (no OpenAI payment), threat intel, anomaly detection, and websocket live updates."
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
    return {
        "service": "Intelligent Graph-Based Attack Path Discovery",
        "version": "2.1.0",
        "mode": "ADVANCE - FREE AI",
        "ai": "100% FREE — local advanced intelligence, optional free HuggingFace (no payment, no OpenAI). See /api/ai/free-info",
        "features": ["deep-scan","graph-engine","risk-engine-v2","free-ai-chat","threat-intel-free","anomaly-ml-free","asset-inventory","bulk-scan","scheduler","compliance","websocket","export"],
        "status": "operational",
        "free": True
    }

@app.get("/api/free-info")
async def free_info():
    return {
        "message": "This platform is 100% FREE to run. No OpenAI, no payment.",
        "ai": {
            "provider": "free-local (default) — offline, deterministic, no API key, no cost",
            "optional": "free-hf — HuggingFace free tier (create free token at huggingface.co/settings/tokens — no card, no payment). Set HF_API_KEY and AI_PROVIDER=free-hf",
            "deprecated": "openai — requires payment, disabled by default. Use free-local instead."
        },
        "threat_intel": "NVD CVE API free (no key), OTX free pulses, MITRE local, EPSS local — all free",
        "cost": "$0 to run entire platform",
        "free": True
    }

@app.get("/api/health")
async def health():
    return {"status":"ok", "ts": datetime.utcnow().isoformat(), "active_scans": len(store.scans), "active_graphs": len(store.graphs), "scheduler_jobs": len(scheduler.jobs), "free": True}

# ---------- Scan ----------
@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    job_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    result = ScanResult(job_id=job_id, target=req.target, mode=req.mode, status="queued", progress=0, current_stage="Queued")
    store.set_scan(job_id, {"request": req, "result": result, "graph": None, "risk": None})
    background_tasks.add_task(run_scan_task, job_id, req)
    return {"job_id": job_id, "status": "queued", "target": req.target, "mode": req.mode, "free": True}

class BulkScanRequest(BaseModel):
    targets: List[str]
    mode: str = "advance"
    depth: int = 2

@app.post("/api/scan/bulk")
async def bulk_scan(req: BulkScanRequest, background_tasks: BackgroundTasks):
    if len(req.targets) > 20:
        raise HTTPException(400, "Max 20 targets per bulk request (free tier)")
    jobs = []
    for t in req.targets:
        job_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        scan_req = ScanRequest(target=t, mode=req.mode, depth=req.depth)
        result = ScanResult(job_id=job_id, target=t, mode=req.mode, status="queued", progress=0, current_stage="Queued")
        store.set_scan(job_id, {"request": scan_req, "result": result, "graph": None, "risk": None})
        background_tasks.add_task(run_scan_task, job_id, scan_req)
        jobs.append(job_id)
    return {"jobs": jobs, "count": len(jobs), "free": True}

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
        # free notification (local log)
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

# ---------- FREE AI ----------
@app.post("/api/ai/explain")
async def explain_ai(req: AIExplainRequest):
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
    result = await ai_explain(scan=scan, graph=graph, risk=risk, question=req.question, vuln=vuln)
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
    return {"job_id": job_id, "prioritized": prioritized, "free": True}

class ChatRequest(BaseModel):
    message: str
    job_id: str | None = None

@app.post("/api/ai/chat")
async def chat(req: ChatRequest):
    result = await free_ai_chat(req.message, req.job_id)
    return result

@app.get("/api/ai/free-info")
async def ai_free_info():
    return {
        "provider": "free-local (default) — 100% free, offline, no key",
        "free_models": ["local deterministic KB (20+ CWEs)", "free-hf: microsoft/Phi-3-mini, zephyr-7b-beta, flan-t5-base (free tier)"],
        "paid": "OpenAI disabled — requires payment, not used",
        "cost": "$0",
        "note": "All AI works without any API key. HF free token is optional and free (no card).",
        "free": True
    }

# ---------- FREE Threat Intel ----------
@app.get("/api/threat-intel/cve/{cve_id}")
async def threat_cve(cve_id: str):
    data = await enrich_cve_free(cve_id)
    return data

@app.get("/api/threat-intel/feed")
async def threat_feed(limit: int = 10):
    data = await get_recent_threat_feed(limit)
    return {"feed": data, "free": True, "source": "NVD Free + Local"}

@app.get("/api/threat-intel/mitre/{technique_id}")
async def threat_mitre(technique_id: str):
    return mitre_lookup(technique_id)

@app.get("/api/threat-intel/epss")
async def threat_epss(cvss: float = 7.5, exploit: bool = False):
    return {"epss": epss_free_score(cvss, exploit), "free": True, "model": "local heuristic, no API"}

# ---------- Asset & Anomaly (FREE) ----------
@app.get("/api/assets/inventory/{job_id}")
async def assets_inventory(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    inv = build_inventory(entry["result"])
    return inv

@app.get("/api/assets/sbom/{job_id}")
async def assets_sbom(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    return sbom_free(entry["result"])

@app.get("/api/anomaly/{job_id}")
async def anomaly(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]; graph = entry.get("graph")
    return combined_health(scan, graph)

# ---------- Scheduler (FREE) ----------
class ScheduleRequest(BaseModel):
    target: str
    mode: str = "advance"
    interval_minutes: int = 60

@app.post("/api/scheduler/schedule")
async def sched_create(req: ScheduleRequest):
    jid = scheduler.schedule(req.target, req.mode, req.interval_minutes)
    return {"scheduled_id": jid, "free": True}

@app.get("/api/scheduler/list")
async def sched_list():
    return {"jobs": scheduler.list(), "free": True}

@app.delete("/api/scheduler/{job_id}")
async def sched_delete(job_id: str):
    ok = scheduler.delete(job_id)
    if not ok:
        raise HTTPException(404, "Not found")
    return {"deleted": True}

# ---------- Compliance (FREE) ----------
@app.get("/api/compliance/{job_id}")
async def compliance_report(job_id: str):
    entry = store.get_scan(job_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    scan = entry["result"]; graph = entry.get("graph")
    risk = entry.get("risk") or run_risk_analysis(scan, graph)
    return {"compliance": risk.compliance, "overall": risk.overall_risk_score, "free": True}

@app.post("/api/notify/test")
async def notify_test(webhook_url: str = None):
    # free test
    return {"note": "Free webhook test — no paid service, uses httpx", "free": True}

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
