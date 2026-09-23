"""
Notification Engine — powerful admin notifications with tune (audio), browser, Slack/Discord/email.
No problem left unnotified. Every bug tells how to remove.
"""
import asyncio
from typing import Dict, Any, List
from datetime import datetime

_notifications: List[Dict[str,Any]] = []
_config = {
    "tune": True,
    "tune_url": "/sounds/notify.mp3",
    "browser": True,
    "webhook_url": "",
    "slack_url": "",
    "discord_url": "",
    "email": "",
    "severity_filter": ["critical","high","medium","low","info"],
    "sound_volume": 0.8,
    "vibrate": True
}

def get_config() -> Dict[str,Any]:
    return _config.copy()

def set_config(**kwargs) -> Dict[str,Any]:
    global _config
    for k,v in kwargs.items():
        if k in _config:
            _config[k]=v
    return get_config()

def add_notification(title: str, message: str, severity: str = "high", how_to_fix: str = "", vuln: Any = None, scan_id: str = None, target: str = None, sound: bool = True) -> Dict[str,Any]:
    n = {
        "id": f"NTF-{len(_notifications)+1:04d}",
        "title": title,
        "message": message,
        "severity": severity,
        "how_to_fix": how_to_fix or "See remediation_code and test command in fix tab",
        "vuln": getattr(vuln, 'title', None) if vuln else None,
        "scan_id": scan_id,
        "target": target,
        "ts": datetime.utcnow().isoformat(),
        "read": False,
        "sound": sound and _config["tune"],
        "tune_url": _config["tune_url"],
        "browser": _config["browser"],
        "channels": []
    }
    _notifications.append(n)
    if len(_notifications)>200:
        _notifications.pop(0)
    return n

def list_notifications(limit: int = 50) -> List[Dict[str,Any]]:
    return list(reversed(_notifications))[-limit:]

def mark_read(nid: str) -> bool:
    for n in _notifications:
        if n["id"]==nid:
            n["read"]=True
            return True
    return False

def mark_all_read() -> int:
    c=0
    for n in _notifications:
        if not n["read"]:
            n["read"]=True; c+=1
    return c

async def notify_scan_completed_with_tune(scan_result, auto_fix_result: Dict[str,Any] = None) -> Dict[str,Any]:
    sev = scan_result.summary.get("risk_hint","high") if hasattr(scan_result,'summary') else "high"
    vuln_count = len(scan_result.vulnerabilities)
    title = f"🛡️ Scan Complete: {scan_result.target}"
    msg = f"Found {vuln_count} vulns ({sev}). {len(auto_fix_result['fixes']) if auto_fix_result else 0} fixes auto-generated."
    how = "\n".join([f"- {v.title}: {v.remediation[:80]}" for v in scan_result.vulnerabilities[:3]]) or "No vulns — stay vigilant, continuous monitor still runs."
    n = add_notification(title=title, message=msg, severity=sev, how_to_fix=how, scan_id=scan_result.job_id, target=scan_result.target, sound=True)
    for v in scan_result.vulnerabilities:
        if v.severity.value in ["critical","high"]:
            add_notification(
                title=f"🚨 {v.severity.value.upper()}: {v.title}",
                message=f"{v.description[:120]} ... on {scan_result.target}",
                severity=v.severity.value,
                how_to_fix=v.remediation + f"\n\nTest: {v.remediation_code[:120] if v.remediation_code else 'see fix tab'}",
                vuln=v, scan_id=scan_result.job_id, target=scan_result.target, sound=True
            )
    return n

async def notify_fix_ready(fix: Dict[str,Any], scan_target: str) -> Dict[str,Any]:
    return add_notification(
        title=f"🔧 Fix Ready: {fix['vuln_title']}",
        message=fix["notification"],
        severity=fix["severity"],
        how_to_fix=fix["how_to_remove"],
        scan_id=fix.get("scan_id"), target=scan_target, sound=True
    )
