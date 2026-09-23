"""
Free Scheduler — in-memory periodic scan scheduling, no Celery/Redis needed, 100% free.
For production, swap with APScheduler or Celery.
"""
import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import random

class InMemoryScheduler:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.logs: List[str] = []

    def schedule(self, target: str, mode: str = "advance", interval_minutes: int = 60, enabled: bool = True) -> str:
        job_id = f"SCHED-{uuid.uuid4().hex[:6].upper()}"
        self.jobs[job_id] = {
            "id": job_id,
            "target": target,
            "mode": mode,
            "interval_minutes": interval_minutes,
            "enabled": enabled,
            "created_at": datetime.utcnow().isoformat(),
            "next_run": (datetime.utcnow() + timedelta(minutes=interval_minutes)).isoformat(),
            "runs": 0,
            "last_scan_id": None
        }
        self.logs.append(f"Scheduled {target} every {interval_minutes}m")
        return job_id

    def list(self) -> List[Dict[str, Any]]:
        return list(self.jobs.values())

    def delete(self, job_id: str) -> bool:
        if job_id in self.jobs:
            del self.jobs[job_id]
            return True
        return False

    def due_jobs(self) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        due = []
        for j in self.jobs.values():
            if not j["enabled"]:
                continue
            try:
                nxt = datetime.fromisoformat(j["next_run"])
                if now >= nxt:
                    due.append(j)
            except:
                continue
        return due

scheduler = InMemoryScheduler()
