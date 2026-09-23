"""
Autonomous Manager — auto vs manual mode for scanning/fixing/schedule.
User can toggle auto mode per task: scan, fix, schedule.
When auto, system continuously monitors, scans on schedule, auto-fixes, notifies with tune.
Manual: user approves each step.
Powerhouse: uses 100+ engines when autonomous_healer selected.
"""
from typing import Dict, Any
from datetime import datetime

_config = {
    "mode": "manual",
    "scan_mode": "manual",
    "fix_mode": "manual",
    "schedule_enabled": False,
    "schedule_interval_minutes": 60,
    "schedule_cron": "0 * * * *",
    "continuous": False,
    "auto_targets": [],
    "notify_tune": True,
    "power_preset": "balanced",
    "powerhouse": False,
    "use_100_engines": False,
    "last_run": None,
    "runs": 0
}

def get_config() -> Dict[str,Any]:
    return _config.copy()

def set_config(**kwargs) -> Dict[str,Any]:
    global _config
    allowed = ["mode","scan_mode","fix_mode","schedule_enabled","schedule_interval_minutes","schedule_cron","continuous","auto_targets","notify_tune","power_preset","powerhouse","use_100_engines"]
    for k,v in kwargs.items():
        if k in allowed:
            _config[k]=v
    if _config["scan_mode"]=="auto" and _config["fix_mode"]=="auto":
        _config["mode"]="auto"
    elif _config["scan_mode"]=="schedule" or _config["fix_mode"]=="schedule":
        _config["mode"]="schedule"
    elif _config["scan_mode"]=="manual" and _config["fix_mode"]=="manual":
        _config["mode"]="manual"
    else:
        _config["mode"]="hybrid"
    return get_config()

def should_auto_scan() -> bool:
    return _config["scan_mode"] in ["auto","schedule"] or _config["continuous"]

def should_auto_fix() -> bool:
    return _config["fix_mode"] in ["auto","schedule"] or _config["continuous"]

def should_notify() -> bool:
    return _config["notify_tune"]

def enable_continuous(targets: list, interval: int = 15):
    set_config(continuous=True, schedule_enabled=True, schedule_interval_minutes=interval, auto_targets=targets, scan_mode="auto", fix_mode="auto", use_100_engines=True, powerhouse=True)
    return get_config()

def disable_continuous():
    set_config(continuous=False)
    return get_config()
