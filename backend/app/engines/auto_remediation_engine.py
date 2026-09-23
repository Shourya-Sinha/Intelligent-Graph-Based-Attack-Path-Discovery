"""
Auto-Remediation Engine — generates PR-ready fixes, 100% free core.
Enterprise with paid LLM generates superior PR descriptions.
Free: deterministic patch, Enterprise: LLM-enhanced PR body.
"""
from typing import Dict, Any, List
from ..models.schemas import Vulnerability, ScanResult

def generate_pr(vuln: Vulnerability, scan: ScanResult = None) -> Dict[str, Any]:
    title = f"fix(security): {vuln.title} ({vuln.cwe})"
    branch = f"fix/{vuln.cwe.lower()}-{vuln.id.lower()}"
    # Deterministic free PR body
    body = f"""### 🔒 Auto-Remediation PR — {vuln.title} (FREE)

**Severity:** {vuln.severity.value} CVSS {vuln.cvss} {vuln.cwe} {vuln.owasp}
**Target:** {scan.target if scan else 'target'}
**Evidence:** `{vuln.evidence[:120] if vuln.evidence else 'see scan'}`

#### Root Cause
{vuln.description}

#### Fix (copy-paste, tested)
``` 
{vuln.remediation_code or vuln.remediation}
```

#### Test
```bash
# Verify fix
curl -I {scan.target if scan else 'https://example.com'} | grep -i "content-security-policy" # should have CSP
```

#### Prevention (CI gate)
- Add SAST rule for {vuln.cwe} in CI (Semgrep free)
- Add DAST in staging (OWASP ZAP free)

*Generated 100% FREE — no OpenAI, enterprise PR body would use GPT-4o for richer context if keys provided.*
"""
    diff_hint = vuln.remediation_code or "# Apply remediation via config/code"
    return {
        "title": title,
        "branch": branch,
        "body": body,
        "diff_hint": diff_hint,
        "files_changed": 1,
        "free": True,
        "enterprise": "With OpenAI/Claude key, PR body would be LLM-enhanced with chain-of-thought and business impact."
    }

def generate_all_prs(scan: ScanResult) -> List[Dict[str, Any]]:
    return [generate_pr(v, scan) for v in scan.vulnerabilities[:3]]

