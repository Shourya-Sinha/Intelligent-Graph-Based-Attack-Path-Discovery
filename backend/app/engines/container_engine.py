"""
Container & K8s Engine — simulates Docker/K8s scan, 100% free core.
Enterprise with Docker API would do deep image scan (Trivy free).
"""
from typing import Dict, Any, List
from ..models.schemas import ScanResult, Vulnerability, Severity

def scan_container(scan: ScanResult) -> Dict[str, Any]:
    vulns: List[Vulnerability] = []
    findings = []

    techs = [t.name.lower() for t in scan.technologies]
    # Check for container hints
    if any(p.port in [2375,2376] for p in scan.ports):  # Docker daemon
        vulns.append(Vulnerability(
            title="Exposed Docker Daemon (port 2375)",
            severity=Severity.CRITICAL,
            cvss=9.8,
            cwe="CWE-306",
            owasp="A01:2021",
            evidence="Port 2375 open — Docker daemon unauthenticated",
            description="Docker daemon exposed without TLS/auth — attacker can spawn privileged containers, escape to host.",
            impact="Full host takeover, cluster compromise.",
            remediation="Bind Docker to 127.0.0.1 + TLS, enable Docker Bench (free), scan images with Trivy (free).",
            remediation_code="# Docker\nDOCKER_OPTS=\"--tlsverify --tlscert=/certs\"",
            confidence=0.95,
            exploit_available=True,
            tags=["container","critical","free"]
        ))
    else:
        findings.append({"check": "Docker daemon", "status": "pass", "detail": "No exposed Docker daemon port"})

    # K8s API server
    if any(p.port in [6443,8443] and "http" in p.service for p in scan.ports):
        findings.append({"check": "K8s API", "status": "warn", "detail": "K8s-like port open — check RBAC, enterprise would run kube-bench (free)"})

    # Image vulnerabilities simulation
    if "nginx" in techs:
        findings.append({"check": "Base image", "status": "info", "detail": "Nginx base — enterprise would Trivy scan for CVEs (free Trivy: trivy image nginx)"})
    if "wordpress" in techs:
        vulns.append(Vulnerability(
            title="Container Base Risk — WordPress (high CVE density)",
            severity=Severity.MEDIUM,
            cvss=6.5,
            cwe="CWE-937",
            owasp="A06:2021",
            evidence="WordPress detected — historically high CVE",
            description="WordPress base images have frequent CVEs. Scan with Trivy/Grype (free) and pin digest.",
            impact="Supply chain RCE.",
            remediation="Use distroless, pin SHA256, Trivy in CI, update weekly.",
            remediation_code="FROM wordpress@sha256:abc... # pin digest\nRUN trivy image --severity HIGH,CRITICAL wordpress",
            confidence=0.65,
            tags=["container","sca"]
        ))

    return {
        "findings": findings,
        "vulns": vulns,
        "score": 80 if not vulns else 50,
        "enterprise_note": "Free: simulated. Enterprise: Trivy/Grype full image scan, K8s CIS benchmark (free tools, enterprise orchestration).",
        "free": True
    }
