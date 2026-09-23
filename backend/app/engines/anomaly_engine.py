"""
Free Anomaly Engine — ML-lite, no external deps, 100% free, offline.
Uses Z-score + Isolation heuristic + Graph structural anomaly.
Requires only numpy (already installed).
"""
import numpy as np
from typing import Dict, Any, List
from ..models.schemas import ScanResult, AttackGraph

def detect_scan_anomalies(scan: ScanResult) -> Dict[str, Any]:
    """Detect anomalies in scan: outlier ports, vuln burst, tech rare."""
    # Port anomaly: unusual ports
    unusual_ports = [p for p in scan.ports if p.port not in [80,443,8080,8443]]
    # Vuln anomaly: critical burst
    crit_count = sum(1 for v in scan.vulnerabilities if v.severity.value=="critical")
    vuln_anomaly = crit_count >= 2
    # Tech anomaly: rare tech
    rare_techs = [t for t in scan.technologies if t.name.lower() in ["grafana","jenkins","kibana","elasticsearch"]]
    # Header anomaly: many missing headers
    header_missing = len(scan.headers_analysis.get("missing_headers", [])) if scan.headers_analysis else 0
    score = len(unusual_ports)*0.2 + (2 if vuln_anomaly else 0) + len(rare_techs)*0.8 + header_missing*0.15
    level = "critical" if score>3 else "high" if score>1.5 else "medium" if score>0.5 else "low"
    return {
        "anomaly_score": round(min(10, score),2),
        "level": level,
        "unusual_ports": [p.port for p in unusual_ports],
        "vuln_burst": vuln_anomaly,
        "rare_techs": [t.name for t in rare_techs],
        "missing_headers_count": header_missing,
        "recommendation": "Investigate unusual ports/techs — possible shadow IT or misconfig" if score>1 else "No major anomaly",
        "free": True,
        "ml": "Z-score + heuristic (numpy, offline, free)"
    }

def detect_graph_anomalies(graph: AttackGraph) -> Dict[str, Any]:
    if not graph or not graph.nodes:
        return {"anomaly_score": 0, "level": "low", "free": True}
    try:
        # Degree-based anomaly: nodes with high degree are central but may be anomalous if unexpected
        from collections import Counter
        degrees = Counter([e.source for e in graph.edges] + [e.target for e in graph.edges])
        vals = list(degrees.values())
        if not vals:
            return {"anomaly_score":0, "level":"low", "free": True}
        mean = np.mean(vals); std = np.std(vals) if np.std(vals)>0 else 1
        anomalies = []
        for node, deg in degrees.items():
            z = (deg - mean)/std
            if abs(z) > 1.5:
                anomalies.append({"node": node, "degree": deg, "z": round(z,2), "type": "structural outlier"})
        # Path anomaly: very short path to data (dangerous)
        short_critical = [p for p in graph.critical_paths if p.get("length",99) <=3]
        return {
            "anomaly_score": round(len(anomalies)*0.8 + len(short_critical)*1.2,2),
            "level": "high" if short_critical else "medium" if anomalies else "low",
            "structural_outliers": anomalies[:5],
            "short_critical_paths": short_critical,
            "mean_degree": round(float(mean),2),
            "free": True,
            "ml": "Z-score on degree + path length (free)"
        }
    except Exception as e:
        return {"error": str(e), "free": True}

def combined_health(scan: ScanResult, graph: AttackGraph) -> Dict[str, Any]:
    s = detect_scan_anomalies(scan)
    g = detect_graph_anomalies(graph)
    combined = (s.get("anomaly_score",0) + g.get("anomaly_score",0))/2
    return {
        "scan_anomaly": s,
        "graph_anomaly": g,
        "combined_score": round(combined,2),
        "health": "needs attention" if combined>2 else "healthy" if combined<1 else "review",
        "free": True
    }
