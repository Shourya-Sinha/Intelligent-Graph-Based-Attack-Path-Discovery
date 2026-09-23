import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "20"))
MAX_SCAN_DEPTH = int(os.getenv("MAX_SCAN_DEPTH", "3"))

# --- FREE AI CONFIGURATION ---
# This project is 100% FREE to run. No paid APIs required.
# - "free-local"  : Advanced local intelligence (default, zero cost, offline, no key)
# - "free-hf"     : Free HuggingFace Inference (free tier, create free token at huggingface.co, no payment ever)
# - "openai"      : OPTIONAL paid (disabled by default, requires payment — not recommended)
AI_PROVIDER = os.getenv("AI_PROVIDER", "free-local")  # free-local | free-hf | openai (paid, optional)
HF_API_KEY = os.getenv("HF_API_KEY", "")  # FREE token from huggingface.co/settings/tokens (free account, no card)
# OPENAI_API_KEY is intentionally deprecated — OpenAI requires payment, so we use 100% free alternatives instead.
# If you still want OpenAI, set OPENAI_API_KEY, but you will be charged by OpenAI — not needed.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # kept for backwards compat, but not used in free mode

ENABLE_REAL_NETWORK_SCAN = os.getenv("ENABLE_REAL_NETWORK_SCAN", "true").lower() == "true"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Free Threat Intel (no keys needed)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OTX_API_URL = "https://otx.alienvault.com/api/v1"  # free, no key for public pulses

# Scheduler & bulk
MAX_BULK_TARGETS = int(os.getenv("MAX_BULK_TARGETS", "20"))
ENABLE_SCHEDULER = os.getenv("ENABLE_SCHEDULER", "true").lower() == "true"
