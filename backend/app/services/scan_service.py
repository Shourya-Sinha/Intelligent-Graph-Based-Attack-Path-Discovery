"""
Scan Service — orchestrates engines, free, testable.
Keeps main.py thin (advanced clean architecture).
"""
from ..engines.scanner_engine import deep_scan_job
from ..engines.attack_graph_engine import build_attack_graph
from ..engines.risk_engine import run_risk_analysis

# This service layer is ready to inject DB, queue, etc. — currently uses InMemoryStore (free)
