# Patchwise web demo. Runs on any container host (Fly.io, Cloud Run, Nebius Serverless endpoints, …).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
# Non-root user: sandboxed test runs of the demo project execute as this user.
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --chown=app:app . .
RUN uv pip install --system --no-cache -e .
USER app
# Python used for sandboxed test runs (the demo pins packages from 2021).
ENV UV_PYTHON_INSTALL_DIR=/home/app/.uv-python UV_CACHE_DIR=/tmp/uv-cache
RUN uv python install 3.11
ENV PORT=8080 PATCHWISE_CLEAN_SANDBOX=1 PATCHWISE_WEB_MAX_COST=0.40 PATCHWISE_DAILY_BUDGET=0.50 \
    PATCHWISE_MAX_CONCURRENT=1 PATCHWISE_RUN_TIMEOUT=600
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % __import__('os').environ.get('PORT','8080'))"
# NEBIUS_API_KEY (and optionally TAVILY_API_KEY) are injected as secrets at deploy time, never baked in.
# One worker: jobs, rate limits and the concurrency guard live in process memory.
CMD ["sh", "-c", "exec uvicorn patchwise.web:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --timeout-keep-alive 75"]
