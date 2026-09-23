"""
Supply Chain (SCA) Engine — SBOM + dependency risk, 100% free.
Enterprise adds paid feeds (Snyk, GitHub Advanced) but core is free.
"""
from typing import Dict, Any, List
import re
from ..models.schemas import ScanResult, Technology, Vulnerability, Severity

RISKY_DEPS = {
    "jquery": {"risk": "high", "note": "1.x has XSS CVE-2020-11022, upgrade to 3.7+", "cvss": 6.5},
    "bootstrap": {"risk": "low", "note": "Generally safe, keep 5.3+", "cvss": 3.0},
    "wordpress": {"risk": "high", "note": "High CVE density, keep core + plugins updated", "cvss": 7.5},
    "react": {"risk": "low", "note": "React 18+ safe, check 16 CVEs", "cvss": 2.0},
}

def scan_supply_chain(scan: ScanResult, body: str = "") -> Dict[str, Any]:
    components = []
    vulns: List[Vulnerability] = []
    for t in scan.technologies:
        info = RISKY_DEPS.get(t.name.lower(), {"risk": "unknown", "note": "No known high CVE", "cvss": 3.0})
        components.append({
            "name": t.name,
            "version": t.version or "unknown",
            "category": t.category,
            "supply_risk": info["risk"],
            "note": info["note"],
            "cvss": info["cvss"]
        })
        if info["risk"] == "high":
            vulns.append(Vulnerability(
                title=f"Supply Chain Risk — {t.name} ({info['risk']})",
                severity=Severity.MEDIUM if info["cvss"]<7 else Severity.HIGH,
                cvss=info["cvss"],
                cwe="CWE-937",
                owasp="A06:2021 - Vulnerable Components",
                evidence=f"Detected {t.name} {t.version or ''} — {info['note']}",
                description=info["note"],
                impact="Supply chain RCE via vulnerable dependency.",
                remediation="Pin version, enable Dependabot (free), Snyk free, npm audit / yarn audit.",
                remediation_code="npm audit fix\n# or\npip list --outdated",
                confidence=0.7,
                tags=["supply-chain","sca","free"]
            ))
    # Check body for cdnjs version hints
    if body and "jquery" in body.lower():
        # Try to extract version
        m = re.search(r"jquery[^\"]*?(\d+\.\d+\.\d+)", body, re.I)
        if m:
            ver = m.group(1)
            if ver.startswith("1.") or ver.startswith("2."):
                vulns.append(Vulnerability(
                    title="Supply Chain — jQuery 1.x/2.x End-of-Life",
                    severity=Severity.MEDIUM,
                    cvss=6.1,
                    cwe="CWE-937",
                    owasp="A06:2021",
                    evidence=f"jQuery {ver} detected in body",
                    description="jQuery 1.x/2.x unsupported, known XSS.",
                    impact="XSS.",
                    remediation="Upgrade to jQuery 3.7+ or remove jQuery (modern browsers).",
                    remediation_code="<script src=\"https://code.jquery.com/jquery-3.7.1.min.js\"></script>",
                    confidence=0.88,
                    tags=["supply-chain"]
                ))

    return {
        "components": components,
        "vulns": vulns,
        "score": 90 if not vulns else 60,
        "sbom_format": "CycloneDX-free + SCA",
        "enterprise_note": "Free: tech fingerprint + regex. Enterprise: Snyk/GitHub Advanced + transitive deps (paid, deeper).",
        "free": True
    }
