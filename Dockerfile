# Container for Nebius Serverless Endpoints (or any container host).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
WORKDIR /app
COPY . .
RUN uv pip install --system -e . && uv python install 3.11
ENV PORT=8080
EXPOSE 8080
# NEBIUS_API_KEY (and optionally TAVILY_API_KEY) are injected as environment variables at deploy time.
CMD ["sh", "-c", "uvicorn patchwise.web:app --host 0.0.0.0 --port ${PORT}"]
