# Production-hardened Dockerfile — multi-stage, no --reload, healthcheck, non-root
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# deps
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

# app
COPY . .

# create non-root + reports dir (for SQLite persistence)
RUN useradd -m appuser && mkdir -p /app/reports && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# healthcheck: hit /api/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=12s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

# prod: no --reload, workers 2 (free), log-level info
# for dev, override command with --reload via docker-compose
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info"]
