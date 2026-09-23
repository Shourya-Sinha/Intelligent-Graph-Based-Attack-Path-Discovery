import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "20"))
MAX_SCAN_DEPTH = int(os.getenv("MAX_SCAN_DEPTH", "3"))
AI_PROVIDER = os.getenv("AI_PROVIDER", "local")  # local | huggingface | openai
HF_API_KEY = os.getenv("HF_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ENABLE_REAL_NETWORK_SCAN = os.getenv("ENABLE_REAL_NETWORK_SCAN", "true").lower() == "true"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
