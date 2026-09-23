import random
import math
import uuid
from datetime import datetime
from typing import Dict, Any, List
import numpy as np
import networkx as nx

from ..models.schemas import ScanResult, AttackGraph, RiskAnalysisResult, Severity

# --- Custom Risk Engine ---
# Combines: CVSS, EPSS, graph centrality, business impact, FAIR-inspired financial quantification, Monte Carlo

SEVERITY_SCORE = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 7, Severity.LOW: 3, Severity.INFO: 1}

COMPLIANCE_MAP = {
    "OWASP Top 10": ["A01:2021","A03:2021","A05:2021","A06:2021","A10:2021"],
    "NIST CSF": ["PR.AC","PR.DS","DE.CM","RS.CO"],
    "MITRE ATT&CK": ["T1190","T1059","T1078","T1590"],
    "PCI DSS": ["6.5","8.2","2.2"],
    "ISO 27001": ["A.14.2","A.12.6","A.9.4"]
}

def monte_carlo_simulation(base_likelihood: float, impact_low: float, impact_high: float, iterations: int = 5000) -> Dict[str, Any]:
    # Vectorized simulation
    likelihoods = np.random.beta(2, 5, iterations) * base_likelihood * 1.5  # skewed low
    likelihoods = np.clip(likelihoods, 0, 1)
    impacts = np.random.triangular(impact_low*0.6, (impact_low+impact_high)/2, impact_high*1.2, iterations)
    losses = likelihoods * impacts
    # percentiles
    return {
        "iterations": iterations,
        "expected_loss": float(np.mean(losses)),
        "median_loss": float(np.median(losses)),
        "p90_loss": float(np.percentile(losses, 90)),
        "p95_loss": float(np.percentile(losses, 95)),
        "max_loss": float(np.max(losses)),
        "likelihood_mean": float(np.mean(likelihoods)),
        "histogram": np.histogram(losses, bins=10)[0].tolist()
    }

def calculate_business_impact(scan: ScanResult, graph: AttackGraph = None) -> Dict[str, float]:
    # Heuristic based on critical vulns, tech stack, data sensitivity
    crit_count = sum(1 for v in scan.vulnerabilities if v.severity == Severity.CRITICAL)
    high_count = sum(1 for v in scan.vulnerabilities if v.severity == Severity.HIGH)
    base = 50000  # base financial impact
    multiplier = 1 + crit_count*2.5 + high_count*1.2 + len(scan.ports)*0.15
    # if DB tech present
    tech_names = [t.name.lower() for t in scan.technologies]
    if any(db in tech_names for db in ["mysql","postgresql","mongodb","oracle","mssql"]):
        multiplier *= 1.4
    # Graph critical paths increase impact
    if graph and graph.critical_paths:
        max_risk = max((p["risk_score"] for p in graph.critical_paths), default=50)
        multiplier *= (1 + max_risk/100)
    single_loss = base * multiplier
    annualized_low = single_loss * 0.7
    annualized_high = single_loss * 2.8
    return {
        "single_loss_expectancy_usd": round(single_loss,2),
        "annualized_low_usd": round(annualized_low,2),
        "annualized_high_usd": round(annualized_high,2),
        "reputation_impact_usd": round(single_loss*0.6,2),
        "regulatory_fine_risk_usd": round(single_loss*0.4 if crit_count>0 else single_loss*0.1,2)
    }

def analyze_compliance(scan: ScanResult) -> Dict[str, Any]:
    owasp_hits = {}
    for v in scan.vulnerabilities:
        if v.owasp:
            owasp_hits[v.owasp] = owasp_hits.get(v.owasp, 0) + 1
    # Build compliance scores
    compliance = {}
    for framework, controls in COMPLIANCE_MAP.items():
        # score 0-100 inverse of hits
        hits = sum(1 for v in scan.vulnerabilities if v.owasp and any(c.split(":")[0] in v.owasp for c in controls))
        score = max(0, 100 - hits*18 - len(scan.vulnerabilities)*3)
        compliance[framework] = {
            "score": round(score,1),
            "status": "fail" if score<60 else "warn" if score<80 else "pass",
            "hit_count": hits,
            "controls": controls
        }
    return compliance

def run_risk_analysis(scan: ScanResult, graph: AttackGraph = None, business_context: Dict[str, Any] = None) -> RiskAnalysisResult:
    analysis_id = f"RISK-{uuid.uuid4().hex[:8].upper()}"
    # 1. Node criticality via PageRank/Betweenness if graph exists, else vuln scoring
    node_criticality = []
    if graph:
        try:
            G = nx.DiGraph()
            for n in graph.nodes:
                G.add_node(n.id)
            for e in graph.edges:
                G.add_edge(e.source, e.target, weight=e.weight)
            pr = nx.pagerank(G, weight="weight")
            bet = nx.betweenness_centrality(G, weight="weight")
            for node in graph.nodes:
                score = pr.get(node.id,0)*50 + bet.get(node.id,0)*50
                # boost if vulnerability with high cvss
                if node.type=="vulnerability" and node.cvss:
                    score += node.cvss*5
                if node.type=="data":
                    score += 30
                node_criticality.append({
                    "id": node.id,
                    "label": node.label,
                    "type": node.type,
                    "pagerank": round(pr.get(node.id,0),4),
                    "betweenness": round(bet.get(node.id,0),4),
                    "criticality_score": round(min(100, score),1),
                    "severity": node.severity.value if node.severity else "info"
                })
            node_criticality.sort(key=lambda x: -x["criticality_score"])
        except Exception as e:
            node_criticality = [{"error": str(e)}]
    else:
        # fallback from vulns
        for v in scan.vulnerabilities:
            node_criticality.append({
                "id": v.id,
                "label": v.title,
                "type": "vulnerability",
                "criticality_score": round(min(100, v.cvss*10 + (8 if v.exploit_available else 0)),1),
                "severity": v.severity.value
            })
        node_criticality.sort(key=lambda x: -x["criticality_score"])

    # 2. Path risks
    path_risks = []
    if graph and graph.critical_paths:
        for p in graph.critical_paths:
            # FAIR-inspired: Likelihood = exploitability * exposure; Impact = financial
            likelihood = p["exploitability"]
            # impact tier mapping
            impact_tier = {"critical": 500000, "high": 150000, "medium": 50000, "low": 10000}
            impact = impact_tier.get(p["severity"], 50000)
            risk = likelihood * impact / 1000  # normalized
            path_risks.append({
                "target": p["target"],
                "target_label": p["target_label"],
                "path": p["path_labels"],
                "risk_score": p["risk_score"],
                "exploitability": p["exploitability"],
                "likelihood": round(likelihood,3),
                "impact_usd": impact,
                "risk_usd": round(risk*1000,2),
                "severity": p["severity"],
                "mitre": "T1190 -> T1078 -> T1005" if p["severity"]=="critical" else "T1590 -> T1190"
            })
    else:
        # synthetic from vulns
        for v in scan.vulnerabilities[:3]:
            path_risks.append({
                "target": v.title,
                "target_label": v.title,
                "path": ["Internet", scan.target, v.title],
                "risk_score": round(v.cvss*10,1),
                "exploitability": round(v.epss or v.cvss/10,3),
                "likelihood": round((v.epss or v.cvss/10),3),
                "impact_usd": 75000 if v.severity==Severity.CRITICAL else 30000,
                "risk_usd": round(v.cvss*8000,2),
                "severity": v.severity.value,
                "mitre": v.mitre_technique or "T1190"
            })

    # 3. Overall risk score (weighted)
    total_weight = sum(SEVERITY_SCORE.get(v.severity, 1) * (v.cvss/5) for v in scan.vulnerabilities)
    exposure_factor = len(scan.ports) * 2 + len(scan.subdomains) *1.5 + len(scan.directories)*1
    graph_factor = len(path_risks) * 8 if path_risks else 0
    raw_score = total_weight * 3 + exposure_factor + graph_factor
    # normalize 0-100
    overall = min(100, raw_score)
    # tweak using node criticality
    if node_criticality and node_criticality[0].get("criticality_score",0) > 80:
        overall = min(100, overall*1.15)
    overall = round(overall,1)

    if overall >= 85:
        level = "critical"
    elif overall >= 65:
        level = "high"
    elif overall >= 40:
        level = "medium"
    elif overall >= 20:
        level = "low"
    else:
        level = "minimal"

    exposure_score = min(100, round( (len(scan.ports)*6 + len(scan.vulnerabilities)*7 + len(scan.subdomains)*3 + (0 if not scan.headers_analysis.get("missing_headers") else len(scan.headers_analysis["missing_headers"])*4) ),1))

    # 4. Financial impact
    financial = calculate_business_impact(scan, graph)

    # 5. Compliance
    compliance = analyze_compliance(scan)

    # 6. Monte Carlo
    base_likelihood = min(0.85, overall/100 * 0.9 + 0.1)
    mc = monte_carlo_simulation(base_likelihood, financial["annualized_low_usd"], financial["annualized_high_usd"], iterations=4000)

    # 7. Recommendations (prioritized)
    recommendations = []
    # sort vulns by risk
    sorted_vulns = sorted(scan.vulnerabilities, key=lambda v: (v.cvss, v.epss), reverse=True)
    for v in sorted_vulns[:5]:
        effort = "low" if "Header" in v.title else "medium" if v.severity==Severity.MEDIUM else "high"
        priority = "P0 - Fix Immediately" if v.severity==Severity.CRITICAL else "P1 - Fix within 7 days" if v.severity==Severity.HIGH else "P2 - Fix within 30 days"
        recommendations.append({
            "vuln_id": v.id,
            "title": v.title,
            "priority": priority,
            "effort": effort,
            "action": v.remediation,
            "code": v.remediation_code,
            "estimated_risk_reduction": round(v.cvss*2.5,1),
            "cost_benefit": "High" if v.cvss>7 and effort!="high" else "Medium"
        })
    # Add graph-based recommendations
    if graph and graph.critical_paths:
        cp = graph.critical_paths[0]
        recommendations.append({
            "title": f"Break critical attack path to {cp['target_label']}",
            "priority": "P0 - Strategic",
            "effort": "medium",
            "action": f"Isolate {cp['path_labels'][1] if len(cp['path_labels'])>1 else 'host'} via network segmentation, apply WAF rule for {cp['target_label']}, enforce MFA on next hop.",
            "code": "# WAF example (ModSecurity)\nSecRule REQUEST_URI \"@contains /api/user/\" \"id:1001,phase:1,deny,status:403,msg:'Block IDOR probe'\"",
            "estimated_risk_reduction": 22.0,
            "cost_benefit": "High"
        })

    # Business context override
    if business_context:
        # adjust financial by revenue
        revenue = business_context.get("annual_revenue_usd")
        if revenue:
            factor = min(5, max(0.5, revenue / 1_000_000))
            for k in financial:
                financial[k] = round(financial[k] * factor, 2)

    return RiskAnalysisResult(
        analysis_id=analysis_id,
        job_id=scan.job_id,
        graph_id=graph.graph_id if graph else None,
        overall_risk_score=overall,
        risk_level=level,
        exposure_score=exposure_score,
        financial_impact_usd=financial,
        compliance=compliance,
        node_criticality=node_criticality[:12],
        path_risks=path_risks,
        monte_carlo=mc,
        recommendations=recommendations
    )
