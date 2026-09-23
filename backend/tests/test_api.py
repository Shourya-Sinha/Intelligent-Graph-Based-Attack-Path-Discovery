"""
Minimal production tests — 100% free, no external deps, pytest + FastAPI TestClient
Run: pytest -q
Covers: health, power, auto, hunt, scan lifecycle, no single error
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "ok"
    assert "store" in j
    assert j["free"] is True

def test_root_121():
    r = client.get("/")
    assert r.status_code == 200
    j = r.json()
    assert j["engines"] == 121
    assert "121" in j["version"]
    assert "hunting" in j["features"]

def test_power_engines():
    r = client.get("/api/power/engines")
    assert r.status_code == 200
    assert r.json()["total"] == 121

def test_metrics():
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert r.json()["engines_total"] == 121

def test_auto_config():
    r = client.get("/api/auto/config")
    assert r.status_code == 200
    assert "config" in r.json()
    # set auto
    r2 = client.post("/api/auto/config", json={"scan_mode":"auto","fix_mode":"auto"})
    assert r2.status_code == 200
    assert r2.json()["config"]["scan_mode"] == "auto"

def test_hunt_queries():
    r = client.get("/api/hunt/queries")
    assert r.status_code == 200
    assert len(r.json()["queries"]) >= 6

def test_scan_lifecycle():
    # start
    r = client.post("/api/scan/start", json={"target":"example.com","mode":"advance","depth":2,"power_preset":"eco"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    # poll quickly (eco is fast)
    import time
    for _ in range(10):
        time.sleep(0.5)
        s = client.get(f"/api/scan/{job_id}")
        if s.json()["status"] == "completed":
            break
    s = client.get(f"/api/scan/{job_id}")
    assert s.json()["status"] in ["completed","running","queued"]
    # fix list should work even if not completed
    # if completed, check fix
    if s.json()["status"] == "completed":
        f = client.get(f"/api/fix/{job_id}")
        assert f.status_code == 200
        assert f.json()["count"] >= 1
        # hunt
        h = client.post(f"/api/hunt/run/{job_id}?query_id=HUNT-001")
        assert h.status_code == 200
        assert "hits" in h.json()

def test_notifications():
    r = client.post("/api/notifications/test")
    assert r.status_code == 200
    assert r.json()["sound"] is True
    n = client.get("/api/notifications?limit=5")
    assert n.status_code == 200
    assert "notifications" in n.json()
