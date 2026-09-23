"""
Enterprise AI Engine — Dual Mode (FREE vs PAID/Enterprise)
- FREE (default, $0, no keys): uses free-local 20+ KB deterministic, offline
- PAID/Enterprise (only if keys provided): uses GPT-4o / Claude / Gemini with enterprise prompts, chain-of-thought, auto-remediation
Auto-switches: if no paid keys → FREE, if keys present → ENTERPRISE advance intelligence.
"""
import os
import httpx
import json
from typing import Dict, Any, Optional
from ..config import AI_PROVIDER, HF_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, get_active_tier, is_enterprise_unlocked
from ..models.schemas import Vulnerability, ScanResult, AttackGraph, RiskAnalysisResult
from .ai_engine import local_explain_vuln, local_explain_path, local_chat_answer, call_free_huggingface

# Enterprise prompts — more advanced than free
ENTERPRISE_SYSTEM_PROMPT = """You are an Enterprise AppSec AI — staff-level engineer (10+ years) for Fortune 500.
You combine CVE/CWE/OWASP/MITRE evidence with business risk (FAIR) and graph centrality.
You produce: executive 3-bullet, technical root cause, exploitability (EPSS), fix with code + WAF + IaC + test, and prevention.
You NEVER hallucinate — you ground every claim in scan evidence.
Tone: concise, actionable, enterprise-grade."""

async def call_openai_enterprise(prompt: str) -> str:
    if not OPENAI_API_KEY:
        return ""
    try:
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # default enterprise cost-effective, but can be gpt-4o
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": ENTERPRISE_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2,
                    "max_tokens": 900
                }
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"][:1800]
            else:
                print(f"OpenAI enterprise error {resp.status_code}: {resp.text[:300]}")
    except Exception as e:
        print(f"OpenAI enterprise exception: {e}")
    return ""

async def call_anthropic_enterprise(prompt: str) -> str:
    if not ANTHROPIC_API_KEY:
        return ""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
                    "max_tokens": 1000,
                    "system": ENTERPRISE_SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                # Anthropic returns content list
                if "content" in data and data["content"]:
                    return data["content"][0].get("text","")[:1800]
    except Exception as e:
        print(f"Anthropic error: {e}")
    return ""

async def call_gemini_enterprise(prompt: str) -> str:
    if not GEMINI_API_KEY:
        return ""
    try:
        model = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": ENTERPRISE_SYSTEM_PROMPT + "\n\n" + prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 900}
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                cands = data.get("candidates", [])
                if cands:
                    parts = cands[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text","")[:1800]
    except Exception as e:
        print(f"Gemini error: {e}")
    return ""

async def enterprise_ai_explain(scan: ScanResult = None, graph: AttackGraph = None, risk: RiskAnalysisResult = None, question: str = None, vuln: Vulnerability = None) -> Dict[str, Any]:
    """
    Dual mode: FREE by default, ENTERPRISE if paid keys provided.
    Enterprise uses advance intelligence model with richer context, chain-of-thought.
    """
    tier = get_active_tier()
    is_ent = is_enterprise_unlocked()

    # Build enterprise-grade context (more detailed than free)
    ctx_parts = []
    if scan:
        ctx_parts.append(f"TARGET: {scan.target} MODE: {scan.mode} Vulns: {len(scan.vulnerabilities)} Tech: {[t.name for t in scan.technologies]} Ports: {len(scan.ports)}")
        if scan.vulnerabilities:
            top = "; ".join([f"{v.title} ({v.severity.value} CVSS {v.cvss} CWE {v.cwe} EPSS {v.epss}) evidence: {v.evidence[:80]}" for v in scan.vulnerabilities[:3]])
            ctx_parts.append(f"TOP VULNS: {top}")
        if scan.headers_analysis:
            ctx_parts.append(f"HEADERS: missing {scan.headers_analysis.get('missing_headers',[])}")
    if graph and graph.critical_paths:
        cp = graph.critical_paths[0]
        ctx_parts.append(f"CRITICAL PATH: {' -> '.join(cp['path_labels'])} Risk {cp['risk_score']} Exploit {cp['exploitability']} Length {cp['length']}")
        ctx_parts.append(f"GRAPH: nodes {graph.metrics.get('node_count')} edges {graph.metrics.get('edge_count')} betweenness {graph.metrics.get('betweenness')}")
    if risk:
        ctx_parts.append(f"RISK: {risk.overall_risk_score}/100 {risk.risk_level} Exposure {risk.exposure_score} SLE ${risk.financial_impact_usd['single_loss_expectancy_usd']:,} P95 ${risk.monte_carlo['p95_loss']:,}")
        ctx_parts.append(f"COMPLIANCE: { {k: v['score'] for k,v in risk.compliance.items()} }")
    if question:
        ctx_parts.append(f"QUESTION: {question}")

    prompt_base = " | ".join(ctx_parts)
    enterprise_prompt = f"""{ENTERPRISE_SYSTEM_PROMPT}

CONTEXT (enterprise scan):
{prompt_base}

TASK: Provide:
1) Executive 3-bullet (risk, financial, next 7 days)
2) Technical root cause (CWE + graph edge)
3) Exploitability (EPSS + on critical path?)
4) Fix: code + WAF + IaC + test (copy-paste)
5) Prevention: CI gate

Be concise, enterprise-grade, no hallucination. Use evidence.
"""

    # Try enterprise paid models in priority order: OpenAI -> Anthropic -> Gemini -> Free HF -> Free Local
    external = ""
    provider_used = ""
    # FREE default: local
    if not is_ent:
        # FREE mode — use local deterministic (no payment)
        if vuln:
            local_ans = local_explain_vuln(vuln)
        elif question:
            local_ans = local_chat_answer(question, scan, graph, risk) + "\n\n---\n" + (local_explain_path(graph.critical_paths[0]) if graph and graph.critical_paths else "")
        elif graph and graph.critical_paths:
            local_ans = local_explain_path(graph.critical_paths[0])
        elif scan and scan.vulnerabilities:
            local_ans = local_explain_vuln(scan.vulnerabilities[0])
        else:
            local_ans = "FREE AI: Intelligent Graph analysis — Dijkstra + FAIR + Monte Carlo, 100% free, offline."
        # Try free HF if requested
        if AI_PROVIDER == "free-hf":
            hf = await call_free_huggingface(prompt_base[:1200])
            if hf:
                external = hf
                provider_used = "Pro — Free HF (Phi-3/Zephyr, free tier, no payment)"
            else:
                external = local_ans
                provider_used = "FREE — Local 20+ CWE KB (offline, $0, no key) — HF unavailable, fallback"
        else:
            external = local_ans
            provider_used = "FREE — Local 20+ CWE KB (offline, $0, no key, default)"
        # Return free
        return {
            "answer": external,
            "provider": provider_used,
            "tier": "free",
            "is_enterprise": False,
            "free": True,
            "enterprise": False,
            "cost": "$0",
            "note": "FREE mode — no OpenAI, no payment. Set paid keys to unlock Enterprise advance intelligence."
        }

    # ENTERPRISE mode — try paid advance models
    # Priority: OpenAI GPT-4o > Anthropic Claude > Gemini > Free HF > Local
    for caller, name in [
        (call_openai_enterprise, "Enterprise — OpenAI GPT-4o (paid, advance)"),
        (call_anthropic_enterprise, "Enterprise — Anthropic Claude 3.5 Sonnet (paid, advance)"),
        (call_gemini_enterprise, "Enterprise — Google Gemini 1.5 Pro (paid, advance)"),
    ]:
        res = await caller(enterprise_prompt)
        if res and len(res.strip()) > 50:
            return {
                "answer": res,
                "provider": name,
                "tier": "enterprise",
                "is_enterprise": True,
                "free": False,
                "enterprise": True,
                "cost": "Paid to provider (enterprise)",
                "note": "Enterprise advance intelligence — paid model, richer reasoning, grounded in scan evidence."
            }
    # Fallback to free HF or local even in enterprise if paid fails
    hf = await call_free_huggingface(prompt_base[:1200])
    if hf:
        return {
            "answer": hf,
            "provider": "Enterprise fallback — Free HF (paid keys failed, using free)",
            "tier": "enterprise",
            "is_enterprise": True,
            "free": True,
            "enterprise": True,
            "cost": "$0 fallback",
            "note": "Paid keys present but call failed — fell back to free HF (still enterprise tier)."
        }
    # Final fallback: local but marked enterprise
    if vuln:
        ans = local_explain_vuln(vuln)
    else:
        ans = local_chat_answer(question or "enterprise", scan, graph, risk)
    return {
        "answer": ans + "\n\n[Enterprise tier — paid keys detected but external call failed, used FREE local fallback (still enterprise unlocked)]",
        "provider": "FREE Local Fallback (enterprise tier, paid keys present)",
        "tier": "enterprise",
        "is_enterprise": True,
        "free": True,
        "enterprise": True,
        "cost": "$0 fallback",
        "note": "Enterprise unlocked, but external LLM unavailable — used local free fallback."
    }
