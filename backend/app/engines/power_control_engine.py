"""
Power Control Engine — lets user choose how much power to use.
Presets + custom engine selection + per-task sliders.
"""
from typing import List, Dict, Any
from .engine_registry import ENGINES, get_engine, power_for_selection, total_engines, max_power_sum
from ..config import get_active_tier, is_enterprise_unlocked

# Presets — each is a set of engine ids
PRESETS = {
    "eco": {
        "name":"Eco (Fast, $0)",
        "desc":"12 lightest engines — quick triage, lowest cost, ~40% power",
        "engines":["tech_fingerprint","port_scan","header_audit","xss_engine","sqli_engine","open_redirect","cors_deep","secrets_deep","api_discovery","threat_intel","anomaly_ml","compliance"],
        "concurrency": 10,
        "depth": 1,
        "cost": "$0",
        "speed": "fastest"
    },
    "balanced": {
        "name":"Balanced (Recommended)",
        "desc":"24 engines — best signal/noise for most projects, ~68% power",
        "engines":["tech_fingerprint","subdomain_enum","dns_deep","port_scan","service_detect","tls_deep","waf_detect","header_audit","xss_engine","sqli_engine","ssrf_engine","lfi_rfi_engine","open_redirect","clickjacking","cors_deep","idor_engine","api_discovery","cloud_posture","k8s_deep","container_cis","secrets_deep","sca_deep","dir_brute","threat_intel","anomaly_ml"],
        "concurrency": 20,
        "depth": 2,
        "cost": "$0",
        "speed": "balanced"
    },
    "maximum": {
        "name":"Maximum ($0, all free)",
        "desc":"33 free engines — deepest free, no paid keys, ~82% power",
        "engines": [e["id"] for e in ENGINES if not e["enterprise"]][:33],  # first 33 free
        "concurrency": 30,
        "depth": 2,
        "cost": "$0",
        "speed": "thorough"
    },
    "turbo": {
        "name":"Turbo (All 44 engines)",
        "desc":"All engines inc. enterprise — powerhouse, needs keys for 5 enterprise engines, ~95% power",
        "engines": [e["id"] for e in ENGINES],
        "concurrency": 50,
        "depth": 3,
        "cost": "$0 + enterprise keys if want 5 paid engines",
        "speed": "deep"
    },
    "overdrive": {
        "name":"Overdrive — Enterprise Powerhouse",
        "desc":"Turbo + GPU + distributed + 200 bulk + paid AI — 100/100 power",
        "engines": [e["id"] for e in ENGINES],
        "concurrency": 100,
        "depth": 3,
        "cost": "enterprise keys + GPU",
        "speed": "enterprise",
        "requires_enterprise": True
    }
}

# Global in-memory power config (per server, user can change)
_global_cfg = {
    "preset": "balanced",
    "selected": PRESETS["balanced"]["engines"],
    "concurrency": 20,
    "depth": 2,
    "task_power": {"scanner": 80, "graph": 75, "risk": 80, "ai": 70},
    "powerhouse": False
}

def get_presets() -> Dict[str, Any]:
    tier = get_active_tier()
    is_ent = is_enterprise_unlocked()
    out={}
    for k,v in PRESETS.items():
        allowed = True
        note = ""
        if k=="overdrive" and not is_ent:
            allowed=False
            note="Needs ENTERPRISE keys (OPENAI/ANTHROPIC/GEMINI)"
        # turbo allowed but 5 enterprise engines will be skipped if free
        power = power_for_selection(v["engines"])
        max_pow = max_power_sum()
        pct = round(power / max_pow * 100)
        out[k] = {**v, "power_pct": pct, "power_sum": power, "allowed": allowed, "note": note, "is_enterprise": v.get("requires_enterprise", False)}
    return out

def get_global_config() -> Dict[str, Any]:
    return _global_cfg.copy()

def set_global_config(preset: str = None, selected: List[str] = None, concurrency: int = None, depth: int = None, task_power: Dict[str,int] = None, powerhouse: bool = None) -> Dict[str, Any]:
    global _global_cfg
    if preset and preset in PRESETS:
        _global_cfg["preset"] = preset
        # if selected not provided, switch to preset engines
        if selected is None:
            selected = PRESETS[preset]["engines"]
        if concurrency is None:
            concurrency = PRESETS[preset]["concurrency"]
        if depth is None:
            depth = PRESETS[preset]["depth"]
    if selected is not None:
        # filter invalid + handle enterprise lock
        is_ent = is_enterprise_unlocked()
        valid_ids = {e["id"] for e in ENGINES}
        filtered=[]
        skipped=[]
        for eid in selected:
            if eid not in valid_ids:
                skipped.append(eid)
                continue
            eng = get_engine(eid)
            if eng["enterprise"] and not is_ent:
                skipped.append(eid)
                continue
            filtered.append(eid)
        _global_cfg["selected"] = filtered
        _global_cfg["_skipped"] = skipped
        if filtered:
            # auto preset = custom if not matching preset
            matches = None
            for pk,pv in PRESETS.items():
                if set(pv["engines"])== set(filtered):
                    matches=pk
                    break
            _global_cfg["preset"] = matches or "custom"
    if concurrency is not None:
        _global_cfg["concurrency"] = max(1, min(100, concurrency))
    if depth is not None:
        _global_cfg["depth"] = max(1, min(3, depth))
    if task_power is not None:
        for k in ["scanner","graph","risk","ai"]:
            if k in task_power:
                _global_cfg["task_power"][k] = max(0, min(100, int(task_power[k])))
    if powerhouse is not None:
        _global_cfg["powerhouse"] = bool(powerhouse)
        if powerhouse:
            # when powerhouse toggled, ensure turbo/overdrive — use already imported ENGINES
            all_ids = [e["id"] for e in ENGINES if not e["enterprise"] or is_enterprise_unlocked()]
            _global_cfg["selected"] = all_ids
            _global_cfg["preset"] = "overdrive" if is_enterprise_unlocked() else "turbo"
    return get_global_config()

def describe_selection(selected: List[str]) -> Dict[str, Any]:
    is_ent = is_enterprise_unlocked()
    power_sum = power_for_selection(selected)
    max_sum = max_power_sum()
    pct = round(power_sum / max_sum * 100) if max_sum else 0
    allowed = []
    skipped=[]
    for eid in selected:
        eng = get_engine(eid)
        if not eng:
            skipped.append({"id": eid, "reason":"unknown"})
            continue
        if eng["enterprise"] and not is_ent:
            skipped.append({"id": eid, "reason":"enterprise locked — add paid keys", "name": eng["name"]})
            continue
        allowed.append(eng)
    # categories breakdown
    cats={}
    for e in allowed:
        cats[e["category"]] = cats.get(e["category"], 0) + e["power"]
    return {
        "selected_count": len(allowed),
        "requested_count": len(selected),
        "skipped": skipped,
        "power_sum": power_sum,
        "power_pct": pct,
        "categories": cats,
        "allowed": allowed,
        "is_enterprise": is_ent,
        "tier": get_active_tier(),
        "can_reach_100": is_ent and (len(allowed) >= len(ENGINES)-1)
    }

def effective_engines_for_job(job_selected: List[str] | None) -> List[str]:
    cfg = get_global_config()
    chosen = job_selected if job_selected is not None else cfg["selected"]
    # filter enterprise if locked (again)
    is_ent = is_enterprise_unlocked()
    if not is_ent:
        chosen = [eid for eid in chosen if not get_engine(eid)["enterprise"]]
    return chosen
