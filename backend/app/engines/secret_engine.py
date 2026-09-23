"""
Free Secret Scanner — regex for leaked secrets, 100% free, offline.
Detects AWS keys, private keys, tokens without external API.
"""
import re
from typing import List, Dict
from ..models.schemas import Vulnerability, Severity

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Severity.CRITICAL, "CWE-798", 9.1),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key", Severity.CRITICAL, "CWE-798", 9.1),
    (r"-----BEGIN (RSA )?PRIVATE KEY-----", "Private Key Exposure", Severity.CRITICAL, "CWE-798", 9.3),
    (r"ghp_[A-Za-z0-9_]{36,}", "GitHub Token", Severity.HIGH, "CWE-798", 7.5),
    (r"xox[bprs]-[0-9A-Za-z-]{10,}", "Slack Token", Severity.HIGH, "CWE-798", 7.5),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", Severity.MEDIUM, "CWE-200", 6.5),
]

def scan_secrets(text: str, url: str = "") -> List[Vulnerability]:
    vulns = []
    for pat, title, sev, cwe, cvss in SECRET_PATTERNS:
        if re.search(pat, text):
            vulns.append(Vulnerability(
                title=f"Secret Exposure — {title}",
                severity=sev,
                cvss=cvss,
                cwe=cwe,
                owasp="A07:2021 - Identification & Authentication Failures",
                mitre_technique="T1552",
                url=url,
                evidence=f"Matched pattern {pat[:30]}...",
                description=f"Leaked secret detected: {title} found in response/body. Secrets should never be exposed client-side.",
                impact="Account takeover, supply chain compromise, cost explosion.",
                remediation="Rotate secret immediately, remove from code, use vault (HashiCorp Vault, AWS Secrets Manager), enable secret scanning in CI.",
                remediation_code="# Use env vault\nimport os\nsecret = os.getenv('SECRET') # never hardcode\n# .gitignore .env",
                confidence=0.92,
                exploit_available=True,
                tags=["secret","exposure","free"]
            ))
    return vulns
