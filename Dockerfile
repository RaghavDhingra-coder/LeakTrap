# LeakTrace public ingest service: health checks + POST /ingest/email only.
# Accounts, the extension API and the dashboard are not served by this image.
# Configuration comes from the platform's environment variables (see
# render.yaml); no .env file is copied in. Migrations are never run here.
FROM python:3.11.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LEAKTRACE_ENV=production \
    LEAKTRACE_APP_MODE=ingest \
    LEAKTRACE_DASHBOARD_ENABLED=false \
    PORT=8000

WORKDIR /app
COPY requirements-runtime.txt .
RUN pip install -r requirements-runtime.txt
COPY backend/ backend/

RUN useradd --system --uid 10001 --no-create-home leaktrace
USER leaktrace

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health', timeout=4)"

# No --proxy-headers: the ingest service makes no decisions from client IPs.
CMD ["sh", "-c", "exec uvicorn backend.main:app --host 0.0.0.0 --port \"$PORT\" --workers 1 --no-server-header --timeout-keep-alive 5"]
