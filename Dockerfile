# syntax=docker/dockerfile:1.7
# ---- web UI build -------------------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- python wheel -------------------------------------------------------------------------
FROM python:3.12-slim AS wheel
WORKDIR /src
RUN pip install --no-cache-dir build
COPY backend/ ./backend/
RUN python -m build --wheel --outdir /dist ./backend

# ---- runtime ------------------------------------------------------------------------------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SCRADAR_DATA_DIR=/data SCRADAR_CACHE_DIR=/data/cache \
    SCRADAR_STATIC_DIR=/app/ui SCRADAR_EXAMPLES_DIR=/app \
    SCRADAR_ALLOWED_HOSTS=localhost,127.0.0.1
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin scradar \
 && mkdir -p /data /app && chown scradar /data
COPY --from=wheel /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
COPY --from=ui /ui/dist /app/ui
COPY examples /app/examples
COPY fixtures /app/fixtures
USER 10001
WORKDIR /app
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status==200 else 1)"
# 0.0.0.0 is the in-container address; compose publishes the port on 127.0.0.1 only.
CMD ["supplychain-radar", "serve", "--host", "0.0.0.0", "--port", "8000"]
