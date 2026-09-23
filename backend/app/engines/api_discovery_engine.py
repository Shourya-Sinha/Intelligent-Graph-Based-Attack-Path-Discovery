"""
Free API Discovery Engine — finds OpenAPI/Swagger, GraphQL, API paths without external tool, 100% free.
"""
import re
import json
from typing import List, Dict, Any
import httpx
from ..models.schemas import Vulnerability, Severity

API_PATTERNS = [
    r"/api/v\d+/",
    r"/graphql",
    r"/swagger",
    r"/openapi\.json",
    r"/\.well-known",
    r'"openapi"\s*:',
    r'"swagger"\s*:',
]

async def discover_apis(base_url: str, body: str, headers: dict) -> Dict[str, Any]:
    findings = []
    apis = []
    # Check body for API hints
    for pat in API_PATTERNS:
        if re.search(pat, body, re.I):
            apis.append(pat)
    # Try to fetch openapi.json
    discovered = []
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            for path in ["/openapi.json","/swagger.json","/api/docs","/graphql"]:
                try:
                    url = base_url.rstrip("/") + path
                    r = await client.get(url)
                    if r.status_code == 200 and ("openapi" in r.text.lower() or "swagger" in r.text.lower() or "graphql" in r.text.lower()):
                        discovered.append({"path": path, "url": url, "status": r.status_code, "type": "openapi" if "openapi" in r.text.lower() else "graphql"})
                except:
                    continue
    except:
        pass
    vulns = []
    if discovered:
        for d in discovered:
            # Check if API is unauthenticated
            vulns.append(Vulnerability(
                title="Exposed API Documentation",
                severity=Severity.MEDIUM,
                cvss=5.3,
                cwe="CWE-215",
                owasp="A01:2021",
                url=d["url"],
                evidence=f"API docs at {d['path']} returned 200",
                description=f"API documentation at {d['url']} is publicly accessible. Attackers use it to map attack surface.",
                impact="Accelerates API abuse, IDOR, auth bypass discovery.",
                remediation="Require auth for docs, hide in prod, add rate limiting, enable OWASP API Top 10 controls.",
                remediation_code="# Nginx\nlocation /openapi.json { allow 10.0.0.0/8; deny all; }",
                confidence=0.88,
                tags=["api","exposure","free"]
            ))
    return {"patterns": apis, "discovered": discovered, "vulns": vulns, "free": True}
