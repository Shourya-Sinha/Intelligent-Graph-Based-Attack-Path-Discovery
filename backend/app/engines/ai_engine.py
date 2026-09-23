import os
import random
import httpx
import json
from typing import Dict, Any, List, Optional
from ..config import AI_PROVIDER, HF_API_KEY, OPENAI_API_KEY
from ..models.schemas import Vulnerability, ScanResult, AttackGraph, RiskAnalysisResult

# Local AI knowledge base for free enhancement without external keys
LOCAL_KB = {
    "xss": "Cross-Site Scripting occurs when untrusted data is included in HTML without encoding. Modern defense is layered: 1) Context-aware output encoding, 2) Content-Security-Policy with nonce, 3) Framework auto-escaping like React.",
    "sqli": "SQL Injection is mitigated by parameterized queries. The engine detected error-based patterns. Use ORM and principle of least privilege.",
    "ssrf": "SSRF can pivot to cloud metadata at 169.254.169.254. Block private IPs and use allowlists.",
}

async def call_huggingface(prompt: str) -> str:
    if not HF_API_KEY:
        return ""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Use free inference endpoint - mistral or llama
            resp = await client.post(
                "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": prompt, "parameters": {"max_new_tokens": 512, "temperature": 0.3}}
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    return data[0].get("generated_text","")[:1200]
                if isinstance(data, dict):
                    return data.get("generated_text","")[:1200]
    except Exception as e:
        print(f"HF error: {e}")
    return ""

async def call_openai(prompt: str) -> str:
    if not OPENAI_API_KEY:
        return ""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role":"user","content": prompt}],
                    "max_tokens": 700
                }
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"OpenAI error: {e}")
    return ""

def local_explain_vuln(vuln: Vulnerability) -> str:
    title_low = vuln.title.lower()
    kb_hint = ""
    for k, v in LOCAL_KB.items():
        if k in title_low:
            kb_hint = v
            break
    return f"""
**{vuln.title}** [{vuln.severity.value.upper()} | CVSS {vuln.cvss} | {vuln.cwe or 'N/A'}]

**What happened?**
{vuln.description}

**Why it matters:**
{vuln.impact} This weakness maps to {vuln.owasp or 'OWASP'} and MITRE {vuln.mitre_technique or 'T1190'}.

**Evidence:**
`{vuln.evidence or 'See request/response logs'}`

**Local AI Insight:**
{kb_hint or 'This vulnerability increases attack graph centrality. Prioritize if on critical path.'}

**Exploitability:** EPSS {vuln.epss} | Confidence {vuln.confidence:.0%} | Exploit available: {vuln.exploit_available}
"""

def local_explain_path(path: Dict[str, Any]) -> str:
    return f"""
**Critical Attack Path: {' → '.join(path['path_labels'] if 'path_labels' in path else path.get('path',[]))}**

Risk Score: **{path.get('risk_score','?')}/100** | Exploitability: **{path.get('exploitability',0):.2f}**

**TTP Chain (MITRE):** {path.get('mitre','T1590 Recon → T1190 Exploit Public Facing → T1078 Valid Accounts → T1005 Data from Local System')}

**What attacker does:**
1. Starts from Internet, discovers exposed service.
2. Exploits {path['target_label'] if 'target_label' in path else 'vulnerability'} to gain foothold.
3. Moves laterally / escalates privilege along path nodes.
4. Reaches high-value asset.

**Business impact:** If traversed, attacker achieves {path.get('severity','high')} impact → estimated loss ${path.get('impact_usd',50000):,}

**Fix the choke point:** Patch the earliest vuln in path, enable WAF virtual patch, segment network to break edge between {path['path_labels'][1] if len(path.get('path_labels',[]))>1 else '?'} and {path['path_labels'][2] if len(path.get('path_labels',[]))>2 else '?'}.
"""

async def ai_explain(scan: ScanResult = None, graph: AttackGraph = None, risk: RiskAnalysisResult = None, question: str = None, vuln: Vulnerability = None) -> Dict[str, Any]:
    # Build prompt
    ctx_parts = []
    if scan:
        ctx_parts.append(f"Target: {scan.target} Mode: {scan.mode} Vulns: {len(scan.vulnerabilities)} Tech: {[t.name for t in scan.technologies]}")
        if scan.vulnerabilities:
            ctx_parts.append("Top vulns: " + "; ".join([f"{v.title} ({v.severity.value} {v.cvss})" for v in scan.vulnerabilities[:3]]))
    if graph and graph.critical_paths:
        ctx_parts.append(f"Critical path: {' -> '.join(graph.critical_paths[0]['path_labels'])} Risk {graph.critical_paths[0]['risk_score']}")
    if risk:
        ctx_parts.append(f"Overall risk {risk.overall_risk_score} level {risk.risk_level} Financial SLA ${risk.financial_impact_usd['single_loss_expectancy_usd']:,}")
    if question:
        ctx_parts.append(f"User question: {question}")

    local_answer = ""
    if vuln:
        local_answer = local_explain_vuln(vuln)
    elif graph and graph.critical_paths:
        local_answer = local_explain_path(graph.critical_paths[0])
    elif scan and scan.vulnerabilities:
        local_answer = local_explain_vuln(scan.vulnerabilities[0])
    else:
        local_answer = "This is an Intelligent Graph-Based Attack Path Discovery analysis. The system correlates vulnerabilities into a graph, finds shortest exploit paths via weighted Dijkstra, and quantifies risk with Monte Carlo and FAIR."

    # Try external AI if configured
    external = ""
    if AI_PROVIDER == "huggingface" and HF_API_KEY:
        prompt = f"You are a senior AppSec engineer. Context: {' | '.join(ctx_parts)}\nProvide executive summary + technical fix in 250 words. Be concise, actionable."
        external = await call_huggingface(prompt)
    elif AI_PROVIDER == "openai" and OPENAI_API_KEY:
        prompt = f"As a senior AppSec engineer, explain:\n{' | '.join(ctx_parts)}\nProvide: 1) Executive summary 2) Technical root cause 3) Fix with code 4) Prevention."
        external = await call_openai(prompt)

    # Combine
    final = external.strip() if external else local_answer

    # Generate suggestions autonomously
    suggestions = []
    if scan:
        if any("header" in v.title.lower() for v in scan.vulnerabilities):
            suggestions.append({"type":"quick_win","title":"Enable security headers in 5 min","action":"Add CSP + HSTS via reverse proxy","effort":"low","risk_reduction": "Medium"})
        if any(v.severity.value=="critical" for v in scan.vulnerabilities):
            suggestions.append({"type":"critical","title":"Virtual patch critical vuln via WAF now","action":"Deploy ModSecurity rule while dev fix builds","effort":"low","risk_reduction":"High"})
        if scan.headers_analysis.get("missing_headers"):
            suggestions.append({"type":"hardening","title":"Harden TLS & cookie flags","action":"Set Secure, HttpOnly, SameSite=Strict","effort":"low","risk_reduction":"Medium"})

    # Auto-generate fix code snippets for top vuln
    fix_snippets = {}
    if vuln and vuln.remediation_code:
        fix_snippets[vuln.title] = vuln.remediation_code
    elif scan and scan.vulnerabilities and scan.vulnerabilities[0].remediation_code:
        fix_snippets[scan.vulnerabilities[0].title] = scan.vulnerabilities[0].remediation_code

    return {
        "answer": final,
        "local_kb_used": not bool(external),
        "provider": AI_PROVIDER if external else "local-intelligence",
        "suggestions": suggestions,
        "fix_snippets": fix_snippets,
        "follow_ups": [
            "Show me the cheapest fix that cuts risk by 50%",
            "Explain this path for a non-technical executive",
            "Generate WAF rule to block this exploit",
            "What if we segment network between web and DB?"
        ]
    }

async def ai_prioritize(scan: ScanResult, graph: AttackGraph, risk: RiskAnalysisResult) -> List[Dict[str, Any]]:
    # AI heuristic ranking combining graph criticality + exploitability + business impact
    prioritized = []
    for v in scan.vulnerabilities:
        # centrality boost
        centrality = 0
        if graph:
            # find node for vuln
            nid = next((n.id for n in graph.nodes if v.title in n.label), None)
            if nid and risk:
                centrality = next((c["criticality_score"] for c in risk.node_criticality if c["id"]==nid), 0)
        score = v.cvss*3 + v.epss*20 + (10 if v.exploit_available else 0) + centrality*0.2
        # on critical path boost
        on_path = False
        if graph and graph.critical_paths:
            on_path = any(v.title in str(p["path_labels"]) for p in graph.critical_paths)
            if on_path:
                score *= 1.4
        prioritized.append({
            "vuln_id": v.id,
            "title": v.title,
            "severity": v.severity.value,
            "cvss": v.cvss,
            "epss": v.epss,
            "centrality": round(centrality,1),
            "on_critical_path": on_path,
            "ai_score": round(score,1),
            "reason": "On critical path + exploit available" if on_path and v.exploit_available else "High CVSS + high EPSS" if v.cvss>8 else "Graph centrality high"
        })
    prioritized.sort(key=lambda x: -x["ai_score"])
    return prioritized
