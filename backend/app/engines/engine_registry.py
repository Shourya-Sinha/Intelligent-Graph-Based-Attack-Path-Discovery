"""
Powerhouse Engine Registry — 45 engines, selectable by user.
Each engine is a unit of power. User ticks what to run.
Power controls how deep each engine runs.
"""
from typing import Dict, List, Any

# Categories
CATEGORIES = ["Recon", "Network", "Web Exploits", "API & Cloud", "Secrets & Crypto", "Supply Chain", "Intelligence", "Posture"]

ENGINES: List[Dict[str, Any]] = [
    # Recon (5)
    {"id":"tech_fingerprint","name":"Tech Fingerprint","category":"Recon","power":2,"tier":"free","desc":"HTTP header + body tech detection (Nginx, React, WordPress etc)","default":True,"enterprise":False},
    {"id":"subdomain_enum","name":"Subdomain Enumeration","category":"Recon","power":2,"tier":"free","desc":"Dictionary + CT + DNS brute (25 subs)","default":True,"enterprise":False},
    {"id":"dns_deep","name":"DNS Deep Dive","category":"Recon","power":2,"tier":"free","desc":"A/AAAA/MX/TXT/SPF/DMARC/zone-transfer checks","default":True,"enterprise":False},
    {"id":"osint","name":"OSINT Harvest","category":"Recon","power":1,"tier":"free","desc":"Emails, OSINT leaks, WHOIS, cert transparency","default":False,"enterprise":False},
    {"id":"shodan_enrich","name":"Shodan / Censys Enrich","category":"Recon","power":3,"tier":"enterprise","desc":"Paid Shodan/Censys host enrich (open ports, vulns)","default":False,"enterprise":True},
    # Network (6)
    {"id":"port_scan","name":"Port Scan (11-19 ports)","category":"Network","power":3,"tier":"free","desc":"TCP SYN simulation, banner grab","default":True,"enterprise":False},
    {"id":"service_detect","name":"Service & Version Detect","category":"Network","power":1,"tier":"free","desc":"Refine service via banners","default":True,"enterprise":False},
    {"id":"tls_deep","name":"TLS Deep Audit","category":"Network","power":2,"tier":"free","desc":"TLS 1.0/1.1, cipher suites, HSTS, cert expiry (SSL Labs logic)","default":True,"enterprise":False},
    {"id":"waf_detect","name":"WAF / CDN Detect","category":"Network","power":2,"tier":"free","desc":"Cloudflare, Akamai, WAF fingerprint + bypass hints","default":True,"enterprise":False},
    {"id":"topology_mapper","name":"Topology Mapper","category":"Network","power":1,"tier":"free","desc":"Infer network topology from subdomains & ports","default":False,"enterprise":False},
    {"id":"firewall_rules","name":"Firewall / Harden Check","category":"Network","power":1,"tier":"free","desc":"Open port risk scoring vs expected profile","default":False,"enterprise":False},
    # Web Exploits (14) — powerhouse core
    {"id":"header_audit","name":"Security Headers Audit","category":"Web Exploits","power":2,"tier":"free","desc":"CSP/HSTS/X-Frame etc 6 headers","default":True,"enterprise":False},
    {"id":"xss_engine","name":"XSS Engine (Ref/Stor/DOM)","category":"Web Exploits","power":3,"tier":"free","desc":"Reflected probe + DOM heuristic","default":True,"enterprise":False},
    {"id":"sqli_engine","name":"SQLi Engine","category":"Web Exploits","power":3,"tier":"free","desc":"Error/union/time blind patterns","default":True,"enterprise":False},
    {"id":"ssrf_engine","name":"SSRF Probe","category":"Web Exploits","power":3,"tier":"free","desc":"url=,param fetch internal, cloud metadata 169.254.169.254","default":True,"enterprise":False},
    {"id":"xxe_engine","name":"XXE Engine","category":"Web Exploits","power":2,"tier":"free","desc":"XML external entity payload check","default":False,"enterprise":False},
    {"id":"ssti_engine","name":"SSTI Engine","category":"Web Exploits","power":2,"tier":"free","desc":"Template injection {{7*7}} probes","default":False,"enterprise":False},
    {"id":"lfi_rfi_engine","name":"LFI/RFI Engine","category":"Web Exploits","power":2,"tier":"free","desc":"../../../../etc/passwd & RFI http://evil","default":True,"enterprise":False},
    {"id":"rce_engine","name":"RCE / Command Inj","category":"Web Exploits","power":3,"tier":"free","desc":"; id, `whoami`, ${jndi:ldap:","default":False,"enterprise":False},
    {"id":"open_redirect","name":"Open Redirect","category":"Web Exploits","power":1,"tier":"free","desc":"next=https://evil.com check","default":True,"enterprise":False},
    {"id":"csrf_engine","name":"CSRF Check","category":"Web Exploits","power":1,"tier":"free","desc":"Forms without anti-CSRF token","default":False,"enterprise":False},
    {"id":"clickjacking","name":"Clickjacking","category":"Web Exploits","power":1,"tier":"free","desc":"X-Frame-Options / CSP frame-ancestors","default":True,"enterprise":False},
    {"id":"cors_deep","name":"CORS Deep","category":"Web Exploits","power":1,"tier":"free","desc":"Origin:* + Credentials, preflight","default":True,"enterprise":False},
    {"id":"proto_pollution","name":"Prototype Pollution","category":"Web Exploits","power":1,"tier":"free","desc":"__proto__ / constructor pollution check","default":False,"enterprise":False},
    {"id":"idor_engine","name":"IDOR Heuristic","category":"Web Exploits","power":2,"tier":"free","desc":"Sequential ID /api/user/123 without authZ","default":True,"enterprise":False},
    {"id":"file_upload","name":"File Upload Bypass","category":"Web Exploits","power":1,"tier":"free","desc":"MIME & extension bypass heuristics","default":False,"enterprise":False},
    # API & Cloud (9)
    {"id":"api_discovery","name":"API Discovery","category":"API & Cloud","power":2,"tier":"free","desc":"OpenAPI / Swagger / GraphQL introspection","default":True,"enterprise":False},
    {"id":"graphql_engine","name":"GraphQL Deep","category":"API & Cloud","power":2,"tier":"free","desc":"Introspection query, batching, depth","default":False,"enterprise":False},
    {"id":"cloud_posture","name":"Cloud Posture","category":"API & Cloud","power":3,"tier":"free","desc":"CDN, S3/.env, CORS - basic free, full with keys","default":True,"enterprise":False},
    {"id":"iam_analyzer","name":"IAM Analyzer","category":"API & Cloud","power":2,"tier":"enterprise","desc":"AWS IAM privilege escalation paths","default":False,"enterprise":True},
    {"id":"k8s_deep","name":"K8s Deep","category":"API & Cloud","power":2,"tier":"free","desc":"6443/8443 + RBAC, podSecurity","default":True,"enterprise":False},
    {"id":"container_cis","name":"Container CIS","category":"API & Cloud","power":2,"tier":"free","desc":"Docker 2375/2376 + base image harden","default":True,"enterprise":False},
    {"id":"serverless_scan","name":"Serverless Audit","category":"API & Cloud","power":1,"tier":"enterprise","desc":"Lambda env, IAM role, URL public","default":False,"enterprise":True},
    {"id":"iac_scan","name":"IaC (Terraform) Scan","category":"API & Cloud","power":1,"tier":"enterprise","desc":"Terraform/K8s manifest misconfig","default":False,"enterprise":True},
    # Secrets & Crypto (5)
    {"id":"secrets_deep","name":"Secrets + Git History","category":"Secrets & Crypto","power":3,"tier":"free","desc":"AWS/GH/Slack/JWT + .git leakage","default":True,"enterprise":False},
    {"id":"jwt_engine","name":"JWT Audit","category":"Secrets & Crypto","power":2,"tier":"free","desc":"none alg, weak secret, exp","default":False,"enterprise":False},
    {"id":"crypto_weak","name":"Weak Crypto","category":"Secrets & Crypto","power":1,"tier":"free","desc":"MD5/SHA1/RC4, weak ciphers","default":False,"enterprise":False},
    {"id":"password_policy","name":"Password Policy","category":"Secrets & Crypto","power":1,"tier":"free","desc":"Login form policy infer","default":False,"enterprise":False},
    {"id":"dir_brute","name":"Dir / File Brute (25)","category":"Secrets & Crypto","power":2,"tier":"free","desc":"/.git/.env/backup.zip etc","default":True,"enterprise":False},
    # Supply Chain (4)
    {"id":"sca_deep","name":"SCA Deep (SBOM)","category":"Supply Chain","power":2,"tier":"free","desc":"jQuery/Bootstrap/React EOL risk","default":True,"enterprise":False},
    {"id":"sast_lite","name":"SAST Lite","category":"Supply Chain","power":2,"tier":"free","desc":"Inline JS static patterns (eval, innerHTML)","default":False,"enterprise":False},
    {"id":"license_audit","name":"License Audit","category":"Supply Chain","power":1,"tier":"free","desc":"Copyleft/GPL risk in SBOM","default":False,"enterprise":False},
    {"id":"cicd_audit","name":"CI/CD Pipeline Audit","category":"Supply Chain","power":1,"tier":"enterprise","desc":"/.github/workflows, Jenkinsfile secrets","default":False,"enterprise":True},
    # Intelligence (4)
    {"id":"threat_intel","name":"Threat Intel (NVD free)","category":"Intelligence","power":2,"tier":"free","desc":"CVE/CWE/EPSS enrich","default":True,"enterprise":False},
    {"id":"exploit_predict","name":"Exploit Predictor (EPSS)","category":"Intelligence","power":1,"tier":"free","desc":"EPSS + exploit available flag","default":True,"enterprise":False},
    {"id":"anomaly_ml","name":"Anomaly ML","category":"Intelligence","power":2,"tier":"free","desc":"Unsupervised anomaly + health 0-100","default":True,"enterprise":False},
    {"id":"compliance","name":"Compliance Mapper","category":"Intelligence","power":2,"tier":"free","desc":"OWASP/NIST/PCI/ISO - 5 free, 10 ent","default":True,"enterprise":False},
]

# Helpers
def get_engine(eid: str) -> dict | None:
    for e in ENGINES:
        if e["id"]==eid:
            return e
    return None

def list_engines() -> List[dict]:
    return ENGINES

def total_engines() -> int:
    return len(ENGINES)

def max_power_sum() -> int:
    return sum(e["power"] for e in ENGINES)

def power_for_selection(selected: List[str]) -> int:
    s = set(selected)
    return sum(e["power"] for e in ENGINES if e["id"] in s)

def enterprise_engines() -> List[dict]:
    return [e for e in ENGINES if e["enterprise"]]

def free_engines() -> List[dict]:
    return [e for e in ENGINES if not e["enterprise"]]
