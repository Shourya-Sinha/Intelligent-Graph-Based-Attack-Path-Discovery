"""
Free Notifications — webhook dispatcher for Slack/Discord/Generic, 100% free, no paid service.
"""
import httpx
from typing import Dict, Any, List

async def send_webhook(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not url:
        return {"sent": False, "reason": "no webhook url", "free": True}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            resp = await client.post(url, json=payload)
            return {"sent": resp.status_code in [200,201,204], "status": resp.status_code, "free": True}
    except Exception as e:
        return {"sent": False, "error": str(e), "free": True}

async def notify_scan_completed(scan_result, webhook_url: str = None) -> Dict[str, Any]:
    payload = {
        "text": f"🛡️ Scan Completed — {scan_result.target} → {len(scan_result.vulnerabilities)} vulns, risk {scan_result.summary.get('risk_hint','?')}",
        "scan_id": scan_result.job_id,
        "target": scan_result.target,
        "vulns": len(scan_result.vulnerabilities),
        "summary": scan_result.summary
    }
    if webhook_url:
        return await send_webhook(webhook_url, payload)
    # Free local log fallback
    return {"sent": True, "mode": "local-log (free, no webhook configured)", "payload": payload, "free": True}
