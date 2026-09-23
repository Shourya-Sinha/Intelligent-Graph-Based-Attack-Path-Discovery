import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "20"))
MAX_SCAN_DEPTH = int(os.getenv("MAX_SCAN_DEPTH", "3"))

# ========== DUAL MODE: FREE vs PAID (ENTERPRISE) ==========
# Default is FREE — 100% free, offline, no keys, no payment.
# PAID (Enterprise) unlocks automatically ONLY if you provide API keys — otherwise stays FREE.
# FREE:  local advanced intelligence, NVD free, no external billing
# PAID:  OpenAI GPT-4o, Anthropic Claude, Google Gemini, HuggingFace Pro — advanced intelligence

AI_PROVIDER = os.getenv("AI_PROVIDER", "free-local")  # free-local | free-hf | enterprise-auto | openai | anthropic | gemini

# FREE keys (no payment, optional)
HF_API_KEY = os.getenv("HF_API_KEY", "")  # FREE token from huggingface.co (no card)

# PAID keys (only if you want enterprise advance intelligence — requires payment to provider)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # OpenAI — paid, enterprise only
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")  # Anthropic Claude — paid, enterprise
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")  # Google Gemini — paid, enterprise
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY", "")  # Azure OpenAI enterprise

# Enterprise feature flags (auto-detected from keys, or manual)
ENTERPRISE_LICENSE_KEY = os.getenv("ENTERPRISE_LICENSE_KEY", "")  # optional enterprise license
ENABLE_ENTERPRISE_ENGINES = os.getenv("ENABLE_ENTERPRISE_ENGINES", "true").lower() == "true"

def is_enterprise_unlocked() -> bool:
    """Enterprise unlocks ONLY if paid keys provided — otherwise FREE."""
    return bool(OPENAI_API_KEY or ANTHROPIC_API_KEY or GEMINI_API_KEY or AZURE_OPENAI_KEY or ENTERPRISE_LICENSE_KEY)

def get_active_tier() -> str:
    if is_enterprise_unlocked():
        return "enterprise"
    if HF_API_KEY:
        return "pro"  # free-hf is pro tier (still $0, but higher power)
    return "free"

# Threat Intel (free, no keys) — enterprise also adds paid feeds if keys
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OTX_API_URL = "https://otx.alienvault.com/api/v1"

# Scan & enterprise scale
MAX_BULK_TARGETS = int(os.getenv("MAX_BULK_TARGETS", "20"))
ENABLE_SCHEDULER = os.getenv("ENABLE_SCHEDULER", "true").lower() == "true"
ENTERPRISE_MAX_BULK = int(os.getenv("ENTERPRISE_MAX_BULK", "200"))  # enterprise can handle 10x
ENTERPRISE_MAX_CONCURRENCY = int(os.getenv("ENTERPRISE_MAX_CONCURRENCY", "100"))
ENABLE_REAL_NETWORK_SCAN = os.getenv("ENABLE_REAL_NETWORK_SCAN", "true").lower() == "true"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Power scaling
POWER_WORKERS = int(os.getenv("POWER_WORKERS", SCAN_CONCURRENCY))
POWER_GPU_ENABLED = os.getenv("POWER_GPU_ENABLED", "false").lower() == "true"
POWER_DISTRIBUTED = os.getenv("POWER_DISTRIBUTED", "false").lower() == "true"
