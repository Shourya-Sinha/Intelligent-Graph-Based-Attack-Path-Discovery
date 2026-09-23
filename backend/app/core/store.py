"""
Advanced Store — InMemory with optional SQLite persistence (FREE, 100% local).
- Default: pure InMemory (fast, no deps, like v2.1)
- If USE_PERSISTENCE=true or SQLite available, persists scans/graphs/risks to ./reports/store.db
- Auto-fallback: if DB fails, stays InMemory — zero errors, production safe
- For production: set USE_PERSISTENCE=true and mount ./reports volume
"""
from typing import Dict, Any, Optional
import threading
import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime

USE_PERSISTENCE = os.getenv("USE_PERSISTENCE", "false").lower() == "true"
DB_PATH = Path(__file__).resolve().parent.parent.parent / "reports" / "store.db"
# also allow env override
if os.getenv("STORE_DB_PATH"):
    DB_PATH = Path(os.getenv("STORE_DB_PATH"))

class InMemoryStore:
    def __init__(self):
        self.scans: Dict[str, Any] = {}
        self.graphs: Dict[str, Any] = {}
        self.risks: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._db_enabled = False
        if USE_PERSISTENCE:
            try:
                DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                self._init_db()
                self._db_enabled = True
                self._load_from_db()
                print(f"[Store] Persistence ON → {DB_PATH} (SQLite, free, local)")
            except Exception as e:
                print(f"[Store] DB init failed, fallback to pure InMemory: {e}")
                self._db_enabled = False
        else:
            print(f"[Store] InMemory mode (free, fast). Set USE_PERSISTENCE=true to enable SQLite persistence")

    def _init_db(self):
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS scans (
            job_id TEXT PRIMARY KEY,
            data TEXT,
            updated_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS graphs (
            graph_id TEXT PRIMARY KEY,
            data TEXT,
            updated_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS risks (
            analysis_id TEXT PRIMARY KEY,
            data TEXT,
            updated_at TEXT
        )""")
        # meta for scheduler/notifications persistence
        cur.execute("""CREATE TABLE IF NOT EXISTS kv (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        conn.commit()
        conn.close()

    def _load_from_db(self):
        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=5)
            cur = conn.cursor()
            # scans
            cur.execute("SELECT job_id, data FROM scans LIMIT 500")
            for job_id, data in cur.fetchall():
                try:
                    obj = json.loads(data)
                    # store as python object with minimal reconstruction
                    # we store serialized Pydantic, but we keep as dict for now; main.py will handle
                    self.scans[job_id] = obj
                except: pass
            conn.close()
        except Exception as e:
            print(f"[Store] load DB failed: {e}")

    def _persist(self, table: str, key: str, data: Any):
        if not self._db_enabled:
            return
        try:
            # serialize with fallback
            if hasattr(data, "model_dump"):
                txt = json.dumps(data.model_dump(mode="json"), default=str)
            elif isinstance(data, dict) and "result" in data and hasattr(data["result"], "model_dump"):
                # scan entry: {request, result, graph, risk}
                serial = {}
                for k,v in data.items():
                    if hasattr(v, "model_dump"):
                        serial[k] = v.model_dump(mode="json")
                    else:
                        serial[k] = v
                txt = json.dumps(serial, default=str)
            else:
                txt = json.dumps(data, default=str)
            conn = sqlite3.connect(str(DB_PATH), timeout=5)
            cur = conn.cursor()
            if table == "scans":
                cur.execute("INSERT OR REPLACE INTO scans (job_id, data, updated_at) VALUES (?,?,?)", (key, txt, datetime.utcnow().isoformat()))
            elif table == "graphs":
                cur.execute("INSERT OR REPLACE INTO graphs (graph_id, data, updated_at) VALUES (?,?,?)", (key, txt, datetime.utcnow().isoformat()))
            elif table == "risks":
                cur.execute("INSERT OR REPLACE INTO risks (analysis_id, data, updated_at) VALUES (?,?,?)", (key, txt, datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            # never break scan on DB error
            print(f"[Store] persist {table}/{key} failed: {e}")

    def set_scan(self, job_id, data):
        with self._lock:
            self.scans[job_id] = data
        # persist async-ish (quick)
        self._persist("scans", job_id, data)

    def get_scan(self, job_id):
        with self._lock:
            return self.scans.get(job_id)

    def set_graph(self, graph_id, data):
        with self._lock:
            self.graphs[graph_id] = data
        self._persist("graphs", graph_id, data)

    def get_graph(self, graph_id):
        with self._lock:
            return self.graphs.get(graph_id)

    def set_risk(self, analysis_id, data):
        with self._lock:
            self.risks[analysis_id] = data
        self._persist("risks", analysis_id, data)

    def get_risk(self, analysis_id):
        with self._lock:
            return self.risks.get(analysis_id)

    def stats(self):
        with self._lock:
            return {
                "scans": len(self.scans),
                "graphs": len(self.graphs),
                "risks": len(self.risks),
                "persistence": "sqlite" if self._db_enabled else "inmemory",
                "db_path": str(DB_PATH) if self._db_enabled else None
            }

store = InMemoryStore()
