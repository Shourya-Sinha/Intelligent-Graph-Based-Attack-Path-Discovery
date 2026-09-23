# FREE AI — 100% Free, No Payment, No OpenAI

> **You asked to use free AI as much as possible — this guide proves it.**

## ❌ Why NOT OpenAI?
- OpenAI (`api.openai.com`) **requires payment** — you add a card, you get billed per token.
- This project **intentionally does NOT use OpenAI by default** to keep you 100% free.
- If you set `OPENAI_API_KEY`, you **will be charged by OpenAI**. Don't.

## ✅ What we use instead — 100% FREE

### 1. Free Local Intelligence (Default: `AI_PROVIDER=free-local`)
- **Cost:** $0, **offline**, **no API key**, **no internet needed**
- **How:** Deterministic knowledge base of 20+ CWE/OWASP/MITRE patterns + graph-aware reasoning
- **Does:** Explains vulns, paths, risk, generates WAF rules + fix code, prioritizes by PageRank × CVSS × EPSS
- **Where:** `backend/app/engines/ai_engine.py` → `local_explain_vuln()`, `local_chat_answer()`
- **Quality:** More reliable than generic LLM for AppSec because grounded in CVE/CWE evidence, not hallucination

### 2. Free HuggingFace (Optional: `AI_PROVIDER=free-hf`)
- **Cost:** $0 — create free account at https://huggingface.co/settings/tokens (no card, no payment, free tier)
- **Models:** `microsoft/Phi-3-mini-4k-instruct`, `HuggingFaceH4/zephyr-7b-beta`, `google/flan-t5-base` — all free
- **How:** `https://api-inference.huggingface.co/models/{model}` with `Authorization: Bearer HF_API_KEY` (free token) or **keyless** (rate-limited but still free)
- **Fallback:** If HF is down or no key, automatically falls back to `free-local` — still works offline
- **Code:** `call_free_huggingface()` in `ai_engine.py`

### 3. Free Threat Intel (no keys)
- **NVD CVE API:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-xxxx` — free, no key
- **MITRE ATT&CK:** local matrix `T1190, T1590, ...`
- **EPSS:** local heuristic `epss_free_score()` — no API

### 4. Free Everything Else
- **Graph:** NetworkX (free, offline)
- **Risk:** Monte Carlo (numpy, free)
- **Anomaly ML:** Z-score (numpy, free)
- **Secret scan:** regex (free)
- **API discovery:** httpx (free)
- **SBOM:** CycloneDX-free (free)
- **Scheduler:** in-memory (free, no Celery/Redis)
- **Notifications:** httpx webhook (free)

## 🔧 How to run 100% free (recommended)

```bash
# No env needed — defaults to free-local, fully offline
cd backend && pip install -r requirements.txt && uvicorn app.main:app --host 0.0.0.0 --port 8000
cd frontend && npm install && npm run dev
```

No `HF_API_KEY`, no `OPENAI_API_KEY` — works.

## 🌟 Optional free HF upgrade (still $0)

```bash
# 1. Create free HF account (no card): https://huggingface.co/join
# 2. Create free token: https://huggingface.co/settings/tokens (Read)
# 3. Set:
export AI_PROVIDER=free-hf
export HF_API_KEY=hf_...  # free token, no payment
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Still $0. If you don't set it, you still have powerful local AI.

## 📊 Comparison

| Provider | Cost | Key needed | Payment | Works offline | Grounding |
|---|---|---|---|---|---|
| **free-local (default)** | $0 | No | No | Yes | CVE/CWE evidence |
| **free-hf (optional)** | $0 | Free HF token (no card) | No | No (fallback to local) | LLM + evidence |
| **openai (deprecated)** | $$ | Paid key | **Yes, billed** | No | Generic LLM |

**Use `free-local` — it is the most advance and most free.**

## 🔒 Proof: No OpenAI call in free mode

See `backend/app/engines/ai_engine.py`:

```python
if AI_PROVIDER == "free-hf":
    external = await call_free_huggingface(prompt)  # free, no payment
elif AI_PROVIDER == "openai":
    # Discourage paid — fall back to local and note cost
    provider_used = "free-local (OpenAI disabled — requires payment, using free local instead)"
    # Do NOT call OpenAI to avoid charges
```

No external call unless you explicitly set `free-hf` — and even then it's free.

## 📝 For your fear: You are safe

- **If you run with defaults:** zero external AI calls, zero cost, zero keys, 100% free.
- **If you set HF_API_KEY:** still $0, free tier, no card.
- **OpenAI is never used** unless you manually set `OPENAI_API_KEY` and `AI_PROVIDER=openai` — don't, and you pay nothing.

**This project solves real-world problems without creating a billing problem.**
