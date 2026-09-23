"""
Cloud Posture Engine — checks AWS/GCP/Azure misconfigs, 100% free core, enterprise with keys does deep.
Free: checks headers, exposed .env, permissive CORS, etc. as proxy for cloud hygiene.
Enterprise: with AWS keys would call Config, but simulation is free.
"""
from typing import Dict, Any, List
from ..models.schemas import ScanResult, Vulnerability, Severity

def scan_cloud_posture(scan: ScanResult) -> Dict[str, Any]:
    findings = []
    vulns: List[Vulnerability] = []

    # Free checks that proxy cloud posture
    tech_names = [t.name.lower() for t in scan.technologies]
    if any("cloudflare" in t for t in tech_names):
        findings.append({"check": "CDN", "status": "pass", "detail": "Cloudflare detected — DDoS protection likely"})
    else:
        findings.append({"check": "CDN", "status": "warn", "detail": "No CDN detected — consider Cloudflare/AWS CloudFront (free tier)"})

    # S3-like exposure via /.env or /backup
    if any("/.env" in d or "/backup" in d for d in scan.directories):
        vulns.append(Vulnerability(
            title="Cloud Storage Exposure — Simulated S3 Bucket Public",
            severity=Severity.HIGH,
            cvss=7.5,
            cwe="CWE-200",
            owasp="A01:2021",
            mitre_technique="T1530",
            evidence="Public path /.env or /backup suggests cloud storage misconfig",
            description="Simulated cloud posture: public storage bucket or secrets in env. In real AWS, check S3 Block Public Access, IAM.",
            impact="Data leak, cryptojacking, compliance fail (SOC2).",
            remediation="Enable S3 Block Public Access, least privilege IAM, secrets in Secrets Manager, scan IaC with Checkov (free).",
            remediation_code="# Terraform (free Checkov)\nresource \"aws_s3_bucket_public_access_block\" \"p\" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = true\n}",
            confidence=0.7,
            tags=["cloud","enterprise-free"]
        ))

    # CORS wildcard = cloud API Gateway misconfig
    if any("cors" in v.title.lower() for v in scan.vulnerabilities):
        findings.append({"check": "API Gateway CORS", "status": "fail", "detail": "Wildcard CORS — API Gateway misconfig, enterprise would flag AWS API Gateway CORS"})

    # Enterprise would check with keys
    enterprise_note = "Free mode: simulated checks. Enterprise with AWS keys would call AWS Config, Security Hub (paid, deeper)."

    return {
        "findings": findings,
        "vulns": vulns,
        "score": 85 if not vulns else 45,
        "enterprise_note": enterprise_note,
        "free": True,
        "checks": len(findings)
    }
