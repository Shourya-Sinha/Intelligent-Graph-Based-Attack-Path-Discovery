from typing import Dict, Any
import threading

class InMemoryStore:
    def __init__(self):
        self.scans: Dict[str, Any] = {}
        self.graphs: Dict[str, Any] = {}
        self.risks: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def set_scan(self, job_id, data):
        with self._lock:
            self.scans[job_id] = data

    def get_scan(self, job_id):
        with self._lock:
            return self.scans.get(job_id)

    def set_graph(self, graph_id, data):
        with self._lock:
            self.graphs[graph_id] = data

    def get_graph(self, graph_id):
        with self._lock:
            return self.graphs.get(graph_id)

    def set_risk(self, analysis_id, data):
        with self._lock:
            self.risks[analysis_id] = data

    def get_risk(self, analysis_id):
        with self._lock:
            return self.risks.get(analysis_id)

store = InMemoryStore()
