"""
Free Asset Engine — inventories subdomains, ports, techs, dirs into asset graph.
No external keys, 100% free, builds on scan data.
"""
from typing import Dict, Any, List
from collections import Counter
from ..models.schemas import ScanResult, Technology

def build_inventory(scan: ScanResult) -> Dict[str, Any]:
    # Count assets
    ports_by_service = Counter([p.service for p in scan.ports])
    tech_by_cat = Counter([t.category for t in scan.technologies])
    # Risk per asset heuristically
    assets = []
    for p in scan.ports:
        risk = "high" if p.port in [22,3306,6379,27017,9200] else "medium" if p.port in [8080,8443,3000] else "low"
        assets.append({"type":"port","id":f"port-{p.port}","label":f"{p.service}:{p.port}","risk":risk,"state":p.state,"banner":p.banner})
    for sub in scan.subdomains:
        assets.append({"type":"subdomain","id":f"sub-{sub}","label":sub,"risk":"medium"})
    for d in scan.directories:
        risk = "critical" if "/.env" in d or "/.git" in d else "high" if "/admin" in d else "medium"
        assets.append({"type":"path","id":f"path-{d}","label":d,"risk":risk})
    # Tech risk
    risky_techs = [t for t in scan.technologies if t.name.lower() in ["jenkins","grafana","kibana","elasticsearch","wordpress"]]
    return {
        "total_assets": len(assets),
        "by_type": {"ports": len(scan.ports), "subdomains": len(scan.subdomains), "paths": len(scan.directories), "techs": len(scan.technologies)},
        "ports_by_service": dict(ports_by_service),
        "tech_by_category": dict(tech_by_cat),
        "assets": assets[:50],
        "risky_techs": [t.model_dump() for t in risky_techs],
        "shadow_it_hint": len(assets) > 15,
        "free": True
    }

def sbom_free(scan: ScanResult) -> Dict[str, Any]:
    """Free SBOM-like inventory from tech fingerprint."""
    components = []
    for t in scan.technologies:
        components.append({"name": t.name, "version": t.version or "unknown", "type": t.category, "supplier": "detected", "risk": "medium" if t.name.lower() in ["jquery","wordpress"] else "low"})
    return {
        "bomFormat": "CycloneDX-free",
        "specVersion": "1.4",
        "components": components,
        "free": True,
        "note": "Generated free from fingerprint — no external SBOM tool needed, 100% free"
    }
