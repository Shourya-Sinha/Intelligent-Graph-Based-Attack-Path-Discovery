"""
Enterprise Power Engine — calculates how powerful the system is, enterprise readiness,
and how to increase power. Shows FREE vs ENTERPRISE power.
"""
import os
try:
    import psutil
except ImportError:
    psutil = None
import time
from typing import Dict, Any, List
from ..config import get_active_tier, is_enterprise_unlocked, SCAN_CONCURRENCY, HF_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY

def calculate_power(scan_count: int = 0, active_engines: int = 10) -> Dict[str, Any]:
    tier = get_active_tier()
    is_ent = is_enterprise_unlocked()
    
    # Base power components (0-100)
    components = {}
    
    # 1. AI Power (0-25)
    if tier == "enterprise":
        if OPENAI_API_KEY and ("gpt-4" in os.getenv("OPENAI_MODEL","gpt-4o") or len(OPENAI_API_KEY)>20):
            ai_power = 25
            ai_label = "Enterprise GPT-4o (paid, max intelligence)"
        elif ANTHROPIC_API_KEY:
            ai_power = 24
            ai_label = "Enterprise Claude 3.5 Sonnet (paid)"
        elif GEMINI_API_KEY:
            ai_power = 23
            ai_label = "Enterprise Gemini 1.5 Pro (paid)"
        else:
            ai_power = 22
            ai_label = "Enterprise (keys detected, advance model)"
    elif tier == "pro":
        ai_power = 16
        ai_label = "Pro — Free HF (Phi-3/ Zephyr, free, no payment)"
    else:
        ai_power = 12
        ai_label = "FREE — Local 20+ CWE KB (offline, $0, no key)"
    components["ai"] = {"score": ai_power, "max": 25, "label": ai_label, "tier": tier}

    # 2. Scanner Power (0-20)
    scanner_power = min(20, 8 + SCAN_CONCURRENCY*0.4 + active_engines*0.6)
    # enterprise gets distribution + higher concurrency
    if is_ent:
        scanner_power = min(20, scanner_power + 4)
    components["scanner"] = {"score": round(scanner_power,1), "max": 20, "label": f"{active_engines} engines × {SCAN_CONCURRENCY} concurrency", "detail": f"Engines: recon, ports, vuln, secrets, API, cloud, container, SCA, threat, anomaly"}

    # 3. Graph Power (0-20)
    # enterprise can handle 10k nodes, free up to 500
    graph_power = 18 if is_ent else 14
    if scan_count > 50:
        graph_power = 20 if is_ent else 15
    components["graph"] = {"score": graph_power, "max": 20, "label": "NetworkX Dijkstra + PageRank + Betweenness" + (" + Distributed (enterprise)" if is_ent else ""), "nodes_capacity": "10k+ nodes" if is_ent else "500 nodes (free)"}

    # 4. Risk Power (0-15)
    risk_power = 15 if is_ent else 12
    components["risk"] = {"score": risk_power, "max": 15, "label": "FAIR + Monte Carlo 4k + Compliance + Anomaly ML" + (" + Predictive (enterprise)" if is_ent else "")}

    # 5. Enterprise Features Power (0-10)
    ent_features = 0
    ent_details = []
    if is_ent:
        ent_features = 10
        ent_details = ["Bulk 200 targets", "Scheduler", "SIEM (Splunk/ELK)", "SSO/RBAC", "Audit logs", "Auto-remediation PRs"]
    else:
        # free still has many
        ent_features = 6
        ent_details = ["Bulk 20 (free)", "Scheduler (free)", "SIEM export (SARIF)", "RBAC basic"]
    components["enterprise"] = {"score": ent_features, "max": 10, "label": f"{'Enterprise unlock' if is_ent else 'Free tier'}", "features": ent_details}

    # 6. Infra Power (0-10)
    try:
        if psutil:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            infra_power = max(0, 10 - (cpu+mem)/30)
            if os.getenv("POWER_GPU_ENABLED","false").lower()=="true":
                infra_power = min(10, infra_power+3)
            components["infra"] = {"score": round(infra_power,1), "max": 10, "label": f"CPU {cpu:.0f}% MEM {mem:.0f}%", "gpu": os.getenv("POWER_GPU_ENABLED","false")}
        else:
            components["infra"] = {"score": 7, "max": 10, "label": "Infra (free, single node — install psutil for live CPU/MEM)"}
    except:
        components["infra"] = {"score": 7, "max": 10, "label": "Infra (free, single node)"}

    total = sum(v["score"] for v in components.values())
    total = min(100, round(total,1))
    
    # Tier thresholds
    if total >= 85:
        level = "ENTERPRISE"
        color = "#22c55e"
    elif total >= 60:
        level = "PRO"
        color = "#3b82f6"
    else:
        level = "FREE"
        color = "#eab308"

    # Recommendations to increase power
    recommendations = []
    if tier == "free":
        recommendations.append({"action": "Set HF_API_KEY (free, no card) → AI +4 power", "cost": "$0", "gain": "+4", "free": True})
        recommendations.append({"action": "Increase SCAN_CONCURRENCY=50 → Scanner +5", "cost": "$0", "gain": "+5", "free": True})
    if not is_ent:
        recommendations.append({"action": "Add OPENAI_API_KEY (GPT-4o) → Enterprise AI +13, unlocks auto-remediation PRs", "cost": "Paid to OpenAI", "gain": "+13", "free": False, "enterprise": True})
        recommendations.append({"action": "Add ANTHROPIC_API_KEY (Claude) or GEMINI_API_KEY → Enterprise +12", "cost": "Paid", "gain": "+12", "enterprise": True})
        recommendations.append({"action": "Set POWER_GPU_ENABLED=true → Infra +3 (enterprise GPU)", "cost": "Infra", "gain": "+3", "enterprise": True})
        recommendations.append({"action": "Set POWER_DISTRIBUTED=true + Redis → Graph 10k nodes +4", "cost": "Infra", "gain": "+4", "enterprise": True})
        recommendations.append({"action": "Enterprise license → Bulk 200, SIEM, SSO, Audit +4", "cost": "License", "gain": "+4", "enterprise": True})
    if SCAN_CONCURRENCY < 50:
        recommendations.append({"action": f"Raise concurrency {SCAN_CONCURRENCY}→100 → +4 scanner power", "cost": "$0", "gain": "+4"})

    return {
        "total_power": total,
        "level": level,
        "color": color,
        "tier": tier,
        "is_enterprise": is_ent,
        "components": components,
        "recommendations": recommendations[:5],
        "enterprise_unlock": is_ent,
        "free_power": 62 if not is_ent else total,  # free alone is ~62
        "enterprise_power": total if is_ent else min(100, total+18),
        "scale": {
            "free_capacity": "500 nodes, 20 bulk, 4k Monte Carlo, single node",
            "enterprise_capacity": "10k+ nodes, 200 bulk, 20k Monte Carlo, distributed, GPU",
            "how_to_scale": "Set paid keys + POWER_GPU_ENABLED=true + SCAN_CONCURRENCY=100 + POWER_DISTRIBUTED=true"
        },
        "free": True
    }

def get_enterprise_features() -> Dict[str, Any]:
    is_ent = is_enterprise_unlocked()
    tier = get_active_tier()
    return {
        "tier": tier,
        "is_enterprise": is_ent,
        "features": [
            {"name": "Deep Scanner (11 ports, 25 paths, XSS/SQLi/SSRF/IDOR)", "free": True, "enterprise": True, "power": 10},
            {"name": "Secret Scan (AWS/GH/Slack/JWT)", "free": True, "enterprise": True, "power": 8},
            {"name": "API Discovery (OpenAPI/GraphQL)", "free": True, "enterprise": True, "power": 8},
            {"name": "Cloud Posture (AWS/GCP/Azure)", "free": "basic", "enterprise": "full (with keys)", "power": 9},
            {"name": "Container/K8s Scan", "free": "basic", "enterprise": "full (image + k8s manifest)", "power": 9},
            {"name": "Supply Chain (SCA) + SBOM", "free": True, "enterprise": True, "power": 7},
            {"name": "Attack Graph (Dijkstra + PageRank)", "free": "500 nodes", "enterprise": "10k+ distributed", "power": 10},
            {"name": "Risk (FAIR + Monte Carlo 4k)", "free": True, "enterprise": "20k + predictive", "power": 9},
            {"name": "FREE AI (20+ CWE KB, offline)", "free": True, "enterprise": True, "power": 12},
            {"name": "Enterprise AI (GPT-4o/Claude/Gemini)", "free": False, "enterprise": True, "power": 25},
            {"name": "Threat Intel (NVD free)", "free": True, "enterprise": True, "power": 6},
            {"name": "Threat Intel (Paid feeds: VirusTotal, Shodan)", "free": False, "enterprise": True, "power": 7},
            {"name": "Bulk Scan", "free": "20 targets", "enterprise": "200 targets", "power": 8},
            {"name": "Scheduler + Notifications", "free": True, "enterprise": True, "power": 5},
            {"name": "Compliance (OWASP/NIST/PCI/ISO/SOC2/HIPAA/GDPR)", "free": "5 frameworks", "enterprise": "10+ enterprise", "power": 8},
            {"name": "Export (JSON/CSV/HTML/PDF/SARIF)", "free": True, "enterprise": True, "power": 6},
            {"name": "SIEM (SARIF)", "free": "SARIF export", "enterprise": "Splunk/ELK/Sentinel streaming", "power": 7},
            {"name": "RBAC/SSO/Audit", "free": "basic", "enterprise": "SSO, RBAC, immutable audit", "power": 6},
            {"name": "Auto-Remediation PRs", "free": False, "enterprise": True, "power": 10},
            {"name": "WebSocket Realtime", "free": True, "enterprise": True, "power": 5},
        ],
        "free": True
    }
