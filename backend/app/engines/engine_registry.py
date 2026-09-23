"""
Powerhouse Engine Registry — 112 engines, selectable by user.
Each engine is a unit of power. User ticks what to run.
Power controls how deep each engine runs.
112 engines total — every task has max strength, autonomous 100+ powerhouse.
"""
from typing import Dict, List, Any

CATEGORIES = ["Recon", "Network", "Web Exploits", "API & Cloud", "Secrets & Crypto", "Supply Chain", "Intelligence", "Auto-Fix & Autonomous", "Compliance Deep", "Posture"]

ENGINES: List[Dict[str, Any]] = [
    # Recon (10)
    {"id":"tech_fingerprint","name":"Tech Fingerprint","category":"Recon","power":2,"tier":"free","desc":"HTTP header + body tech detection (Nginx, React, WordPress etc)","default":True,"enterprise":False},
    {"id":"subdomain_enum","name":"Subdomain Enumeration","category":"Recon","power":2,"tier":"free","desc":"Dictionary + CT + DNS brute (25 subs)","default":True,"enterprise":False},
    {"id":"dns_deep","name":"DNS Deep Dive","category":"Recon","power":2,"tier":"free","desc":"A/AAAA/MX/TXT/SPF/DMARC/zone-transfer checks","default":True,"enterprise":False},
    {"id":"osint","name":"OSINT Harvest","category":"Recon","power":1,"tier":"free","desc":"Emails, OSINT leaks, WHOIS, cert transparency","default":False,"enterprise":False},
    {"id":"shodan_enrich","name":"Shodan / Censys Enrich","category":"Recon","power":3,"tier":"enterprise","desc":"Paid Shodan/Censys host enrich (open ports, vulns)","default":False,"enterprise":True},
    {"id":"cert_transparency","name":"Cert Transparency Miner","category":"Recon","power":1,"tier":"free","desc":"CT logs brute for shadow subdomains","default":False,"enterprise":False},
    {"id":"whois_lookup","name":"WHOIS / ASN Lookup","category":"Recon","power":1,"tier":"free","desc":"WHOIS, ASN, org, creation date, expiry","default":False,"enterprise":False},
    {"id":"email_harvest","name":"Email Harvest & Leak Check","category":"Recon","power":1,"tier":"free","desc":"Extract emails, check haveibeenpwned pattern (free)","default":False,"enterprise":False},
    {"id":"asset_discovery","name":"Asset Discovery+","category":"Recon","power":2,"tier":"free","desc":"Favicon hash, JARM, cert SAN, sitemap","default":False,"enterprise":False},
    {"id":"cdn_mapper","name":"CDN Mapper","category":"Recon","power":1,"tier":"free","desc":"Map CDN edges, origin IP hint","default":False,"enterprise":False},
    # Network (16)
    {"id":"port_scan","name":"Port Scan (11-19 ports)","category":"Network","power":3,"tier":"free","desc":"TCP SYN simulation, banner grab","default":True,"enterprise":False},
    {"id":"service_detect","name":"Service & Version Detect","category":"Network","power":1,"tier":"free","desc":"Refine service via banners","default":True,"enterprise":False},
    {"id":"tls_deep","name":"TLS Deep Audit","category":"Network","power":2,"tier":"free","desc":"TLS 1.0/1.1, cipher suites, HSTS, cert expiry (SSL Labs logic)","default":True,"enterprise":False},
    {"id":"waf_detect","name":"WAF / CDN Detect","category":"Network","power":2,"tier":"free","desc":"Cloudflare, Akamai, WAF fingerprint + bypass hints","default":True,"enterprise":False},
    {"id":"topology_mapper","name":"Topology Mapper","category":"Network","power":1,"tier":"free","desc":"Infer network topology from subdomains & ports","default":False,"enterprise":False},
    {"id":"firewall_rules","name":"Firewall / Harden Check","category":"Network","power":1,"tier":"free","desc":"Open port risk scoring vs expected profile","default":False,"enterprise":False},
    {"id":"ipv6_scan","name":"IPv6 Surface","category":"Network","power":1,"tier":"free","desc":"AAAA record + IPv6 reachability","default":False,"enterprise":False},
    {"id":"udp_scan","name":"UDP Scan (DNS/SNMP)","category":"Network","power":2,"tier":"free","desc":"UDP 53/123/161 probe (light)","default":False,"enterprise":False},
    {"id":"banner_grab_plus","name":"Banner Grab+","category":"Network","power":1,"tier":"free","desc":"Extended banner + CPE guess","default":False,"enterprise":False},
    {"id":"ssl_lab_grading","name":"SSL Labs Grading","category":"Network","power":2,"tier":"free","desc":"Grade A-F via cipher + proto + HSTS (free heuristic)","default":False,"enterprise":False},
    {"id":"hsts_preload","name":"HSTS Preload Check","category":"Network","power":1,"tier":"free","desc":"hstspreload.org eligibility","default":False,"enterprise":False},
    {"id":"http2_push","name":"HTTP/2 & Push Audit","category":"Network","power":1,"tier":"free","desc":"ALPN h2, server push misconfig","default":False,"enterprise":False},
    {"id":"rate_limit_test","name":"Rate Limit Probe","category":"Network","power":1,"tier":"free","desc":"429/Retry-After, bruteforce window","default":False,"enterprise":False},
    {"id":"http_methods_audit","name":"HTTP Methods Audit","category":"Network","power":1,"tier":"free","desc":"TRACE/PUT/DELETE enabled → risky","default":False,"enterprise":False},
    {"id":"http_headers_entropy","name":"Header Entropy & Leaks","category":"Network","power":1,"tier":"free","desc":"Server/X-Powered-By leak & entropy","default":False,"enterprise":False},
    {"id":"network_segmentation","name":"Network Segmentation Heuristic","category":"Network","power":1,"tier":"free","desc":"DMZ vs internal via subdomain naming","default":False,"enterprise":False},
    # Web Exploits (26)
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
    {"id":"xpath_injection","name":"XPath Injection","category":"Web Exploits","power":1,"tier":"free","desc":"XPath ' or '1'='1 payloads","default":False,"enterprise":False},
    {"id":"ldap_injection","name":"LDAP Injection","category":"Web Exploits","power":1,"tier":"free","desc":"LDAP )(cn=* pattern","default":False,"enterprise":False},
    {"id":"host_header_injection","name":"Host Header Injection","category":"Web Exploits","power":1,"tier":"free","desc":"Host: evil.com cache poison","default":False,"enterprise":False},
    {"id":"cache_poisoning","name":"Cache Poisoning","category":"Web Exploits","power":1,"tier":"free","desc":"X-Forwarded-Host poison probe","default":False,"enterprise":False},
    {"id":"http_request_smuggling_plus","name":"HTTP Smuggling+","category":"Web Exploits","power":1,"tier":"free","desc":"CL vs TE desync probe","default":False,"enterprise":False},
    {"id":"deserialization_java","name":"Deserialization (Java)","category":"Web Exploits","power":2,"tier":"free","desc":"Java rO0AB... + CommonsCollections","default":False,"enterprise":False},
    {"id":"deserialization_php","name":"Deserialization (PHP)","category":"Web Exploits","power":1,"tier":"free","desc":"PHP O:4:\"Test\": pattern","default":False,"enterprise":False},
    {"id":"dom_clobbering","name":"DOM Clobbering","category":"Web Exploits","power":1,"tier":"free","desc":"DOM id=name clobber vector","default":False,"enterprise":False},
    {"id":"json_injection","name":"JSON Injection","category":"Web Exploits","power":1,"tier":"free","desc":"JSON }`, ` break + prototype","default":False,"enterprise":False},
    {"id":"crlf_injection","name":"CRLF Injection","category":"Web Exploits","power":1,"tier":"free","desc":"%0d%0a Set-Cookie inject","default":False,"enterprise":False},
    # API & Cloud (14)
    {"id":"api_discovery","name":"API Discovery","category":"API & Cloud","power":2,"tier":"free","desc":"OpenAPI / Swagger / GraphQL introspection","default":True,"enterprise":False},
    {"id":"graphql_engine","name":"GraphQL Deep","category":"API & Cloud","power":2,"tier":"free","desc":"Introspection query, batching, depth","default":False,"enterprise":False},
    {"id":"cloud_posture","name":"Cloud Posture","category":"API & Cloud","power":3,"tier":"free","desc":"CDN, S3/.env, CORS - basic free, full with keys","default":True,"enterprise":False},
    {"id":"iam_analyzer","name":"IAM Analyzer","category":"API & Cloud","power":2,"tier":"enterprise","desc":"AWS IAM privilege escalation paths","default":False,"enterprise":True},
    {"id":"k8s_deep","name":"K8s Deep","category":"API & Cloud","power":2,"tier":"free","desc":"6443/8443 + RBAC, podSecurity","default":True,"enterprise":False},
    {"id":"container_cis","name":"Container CIS","category":"API & Cloud","power":2,"tier":"free","desc":"Docker 2375/2376 + base image harden","default":True,"enterprise":False},
    {"id":"serverless_scan","name":"Serverless Audit","category":"API & Cloud","power":1,"tier":"enterprise","desc":"Lambda env, IAM role, URL public","default":False,"enterprise":True},
    {"id":"iac_scan","name":"IaC (Terraform) Scan","category":"API & Cloud","power":1,"tier":"enterprise","desc":"Terraform/K8s manifest misconfig","default":False,"enterprise":True},
    {"id":"rest_fuzzing","name":"REST Fuzzing","category":"API & Cloud","power":2,"tier":"free","desc":"Param fuzz: price=-1, role=admin","default":False,"enterprise":False},
    {"id":"openapi_schema_validate","name":"OpenAPI Schema Validate","category":"API & Cloud","power":1,"tier":"free","desc":"Schema mismatch vs traffic","default":False,"enterprise":False},
    {"id":"soap_scan","name":"SOAP / XML API","category":"API & Cloud","power":1,"tier":"free","desc":"WSDL enum + XXE via SOAP","default":False,"enterprise":False},
    {"id":"grpc_scan","name":"gRPC Probe","category":"API & Cloud","power":1,"tier":"free","desc":"gRPC reflection + proto enum","default":False,"enterprise":False},
    {"id":"websocket_fuzz","name":"WebSocket Fuzz","category":"API & Cloud","power":1,"tier":"free","desc":"ws:// cross-origin + frame inject","default":False,"enterprise":False},
    {"id":"api_rate_limit","name":"API Rate Limit","category":"API & Cloud","power":1,"tier":"free","desc":"API 429 missing → bruteforce","default":False,"enterprise":False},
    # Secrets & Crypto (10)
    {"id":"secrets_deep","name":"Secrets + Git History","category":"Secrets & Crypto","power":3,"tier":"free","desc":"AWS/GH/Slack/JWT + .git leakage","default":True,"enterprise":False},
    {"id":"jwt_engine","name":"JWT Audit","category":"Secrets & Crypto","power":2,"tier":"free","desc":"none alg, weak secret, exp","default":False,"enterprise":False},
    {"id":"crypto_weak","name":"Weak Crypto","category":"Secrets & Crypto","power":1,"tier":"free","desc":"MD5/SHA1/RC4, weak ciphers","default":False,"enterprise":False},
    {"id":"password_policy","name":"Password Policy","category":"Secrets & Crypto","power":1,"tier":"free","desc":"Login form policy infer","default":False,"enterprise":False},
    {"id":"dir_brute","name":"Dir / File Brute (25)","category":"Secrets & Crypto","power":2,"tier":"free","desc":"/.git/.env/backup.zip etc","default":True,"enterprise":False},
    {"id":"tls_cert_transparency","name":"TLS CT & Pins","category":"Secrets & Crypto","power":1,"tier":"free","desc":"CT log + HPKP audit","default":False,"enterprise":False},
    {"id":"hpkp_audit","name":"HPKP Audit (deprecated check)","category":"Secrets & Crypto","power":1,"tier":"free","desc":"HPKP header misuse","default":False,"enterprise":False},
    {"id":"cookie_secure_audit","name":"Cookie Secure Audit","category":"Secrets & Crypto","power":1,"tier":"free","desc":"Secure/HttpOnly/SameSite missing","default":False,"enterprise":False},
    {"id":"session_token_entropy","name":"Session Entropy","category":"Secrets & Crypto","power":1,"tier":"free","desc":"Session token randomness heuristic","default":False,"enterprise":False},
    {"id":"crypto_poodle_beast","name":"POODLE/BEAST/CRIME","category":"Secrets & Crypto","power":1,"tier":"free","desc":"Legacy TLS vuln heap","default":False,"enterprise":False},
    # Supply Chain (9)
    {"id":"sca_deep","name":"SCA Deep (SBOM)","category":"Supply Chain","power":2,"tier":"free","desc":"jQuery/Bootstrap/React EOL risk","default":True,"enterprise":False},
    {"id":"sast_lite","name":"SAST Lite","category":"Supply Chain","power":2,"tier":"free","desc":"Inline JS static patterns (eval, innerHTML)","default":False,"enterprise":False},
    {"id":"license_audit","name":"License Audit","category":"Supply Chain","power":1,"tier":"free","desc":"Copyleft/GPL risk in SBOM","default":False,"enterprise":False},
    {"id":"cicd_audit","name":"CI/CD Pipeline Audit","category":"Supply Chain","power":1,"tier":"enterprise","desc":"/.github/workflows, Jenkinsfile secrets","default":False,"enterprise":True},
    {"id":"container_image_scan_plus","name":"Image Scan+","category":"Supply Chain","power":2,"tier":"free","desc":"Trivy-like image layer CVE (heuristic)","default":False,"enterprise":False},
    {"id":"helm_chart_audit","name":"Helm Chart Audit","category":"Supply Chain","power":1,"tier":"free","desc":"Helm values secrets + RBAC","default":False,"enterprise":False},
    {"id":"sbom_license_plus","name":"SBOM License+","category":"Supply Chain","power":1,"tier":"free","desc":"SPDX license drift","default":False,"enterprise":False},
    {"id":"dependency_confusion_plus","name":"Dependency Confusion+","category":"Supply Chain","power":1,"tier":"free","desc":"Private pkg name collide public","default":False,"enterprise":False},
    {"id":"typo_squat","name":"TypoSquat Detector","category":"Supply Chain","power":1,"tier":"free","desc":"npm/pip typo-squat heuristic","default":False,"enterprise":False},
    # Intelligence (9)
    {"id":"threat_intel","name":"Threat Intel (NVD free)","category":"Intelligence","power":2,"tier":"free","desc":"CVE/CWE/EPSS enrich","default":True,"enterprise":False},
    {"id":"exploit_predict","name":"Exploit Predictor (EPSS)","category":"Intelligence","power":1,"tier":"free","desc":"EPSS + exploit available flag","default":True,"enterprise":False},
    {"id":"anomaly_ml","name":"Anomaly ML","category":"Intelligence","power":2,"tier":"free","desc":"Unsupervised anomaly + health 0-100","default":True,"enterprise":False},
    {"id":"compliance","name":"Compliance Mapper","category":"Intelligence","power":2,"tier":"free","desc":"OWASP/NIST/PCI/ISO - 5 free, 10 ent","default":True,"enterprise":False},
    {"id":"threat_feed_otx","name":"OTX Feed Enrich","category":"Intelligence","power":1,"tier":"free","desc":"AlienVault OTX pulse match (free)","default":False,"enterprise":False},
    {"id":"mitre_attack_map","name":"MITRE ATT&CK Map","category":"Intelligence","power":1,"tier":"free","desc":"Technique → tactic mapping","default":False,"enterprise":False},
    {"id":"ioc_enrich","name":"IoC Enrich","category":"Intelligence","power":1,"tier":"free","desc":"IP/domain hash vs feed","default":False,"enterprise":False},
    {"id":"dark_web_monitor_stub","name":"Dark Web Stub (heuristic)","category":"Intelligence","power":1,"tier":"free","desc":"Email/domain dark-web exposure heuristic (free stub)","default":False,"enterprise":False},
    {"id":"phishing_kit_detect","name":"Phishing Kit Detect","category":"Intelligence","power":1,"tier":"free","desc":"Phishing kit fingerprint","default":False,"enterprise":False},
    # Auto-Fix & Autonomous (20)
    {"id":"auto_fix_xss","name":"Auto-Fix: XSS","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Generate CSP + encode fix PR immediately","default":False,"enterprise":False},
    {"id":"auto_fix_sqli","name":"Auto-Fix: SQLi","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Parametrized query patch PR","default":False,"enterprise":False},
    {"id":"auto_fix_headers","name":"Auto-Fix: Headers","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Nginx/Express header fix snippet","default":False,"enterprise":False},
    {"id":"auto_fix_tls","name":"Auto-Fix: TLS","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"TLS 1.2+ cipher hardening config","default":False,"enterprise":False},
    {"id":"auto_fix_cors","name":"Auto-Fix: CORS","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Whitelist origin patch","default":False,"enterprise":False},
    {"id":"auto_fix_secrets","name":"Auto-Fix: Secrets","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Rotate + git history clean guide PR","default":False,"enterprise":False},
    {"id":"auto_fix_sca","name":"Auto-Fix: SCA","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Bump jQuery/Bootstrap to safe version PR","default":False,"enterprise":False},
    {"id":"auto_fix_iac","name":"Auto-Fix: IaC","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Terraform S3 public → private patch","default":False,"enterprise":False},
    {"id":"auto_fix_container","name":"Auto-Fix: Container","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Dockerfile CIS hardening patch","default":False,"enterprise":False},
    {"id":"auto_fix_cloud","name":"Auto-Fix: Cloud","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"S3 ACL + IAM least-privilege PR","default":False,"enterprise":False},
    {"id":"auto_fix_wordpress","name":"Auto-Fix: WordPress","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"WP version bump + plugin patch","default":False,"enterprise":False},
    {"id":"auto_fix_nginx","name":"Auto-Fix: Nginx/Apache","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Server header + conf harden","default":False,"enterprise":False},
    {"id":"auto_patch_generator","name":"Patch Generator","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Unified diff per vuln, apply-ready","default":False,"enterprise":False},
    {"id":"auto_pr_creator","name":"PR Creator","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Create GitHub/GitLab PR via webhook (free stub, enterprise API)","default":False,"enterprise":False},
    {"id":"auto_rollback","name":"Auto-Rollback Guard","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"Test fix → rollback on break","default":False,"enterprise":False},
    {"id":"autonomous_scheduler","name":"Autonomous Scheduler","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Cron: every 15m/1h/daily auto-scan","default":True,"enterprise":False},
    {"id":"autonomous_notifier","name":"Autonomous Notifier","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Sound tune + browser + Slack/Discord + email","default":True,"enterprise":False},
    {"id":"autonomous_healer","name":"Autonomous Healer","category":"Auto-Fix & Autonomous","power":3,"tier":"free","desc":"Continuously scans + auto-fixes, no human needed","default":False,"enterprise":False},
    {"id":"continuous_monitor","name":"Continuous Monitor","category":"Auto-Fix & Autonomous","power":2,"tier":"free","desc":"Every-time scan loop, zero lapse","default":False,"enterprise":False},
    {"id":"manual_override","name":"Manual Override Gate","category":"Auto-Fix & Autonomous","power":1,"tier":"free","desc":"User toggles auto vs manual per task","default":True,"enterprise":False},
    # Compliance Deep (6)
    {"id":"gdpr_audit","name":"GDPR Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"GDPR 6-principles check","default":False,"enterprise":False},
    {"id":"hipaa_audit","name":"HIPAA Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"HIPAA 18 PHI identifiers","default":False,"enterprise":False},
    {"id":"pci_dss_audit","name":"PCI-DSS Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"PCI 12 req + SAQ hint","default":False,"enterprise":False},
    {"id":"soc2_audit","name":"SOC 2 Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"SOC2 CC1-CC8 heuristics","default":False,"enterprise":False},
    {"id":"iso27001_audit","name":"ISO 27001 Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"ISO 114 controls gap","default":False,"enterprise":False},
    {"id":"nist_audit","name":"NIST 800-53 Audit","category":"Compliance Deep","power":2,"tier":"free","desc":"NIST 20 families check","default":False,"enterprise":False},
    # Posture (2)
    {"id":"security_score","name":"Security Score 0-100","category":"Posture","power":1,"tier":"free","desc":"Weighted score + trend","default":True,"enterprise":False},
    {"id":"remediation_priority","name":"Remediation Priority","category":"Posture","power":1,"tier":"free","desc":"Risk × effort sorter, top 3 fix order","default":True,"enterprise":False},
]

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
