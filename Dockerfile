# ── Stage 1: Build frontend ──────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ .

ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ── Stage 2: Runtime (Python + Node) ────────────────────────────────
FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Python venv + dependencies
RUN python3 -m venv /app/venv
COPY backend/requirements.txt /tmp/requirements.txt
RUN /app/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Backend source
COPY backend/ /app/backend/

# Frontend standalone build
COPY --from=frontend-build /app/.next/standalone /app/frontend/
COPY --from=frontend-build /app/.next/static     /app/frontend/.next/static
COPY --from=frontend-build /app/public            /app/frontend/public

# Data directory for SQLite
RUN mkdir -p /data

# Startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

ENV DATABASE_URL=sqlite:////data/honeyos.db
ENV FLASK_ENV=production
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

EXPOSE 7777 7778

HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=10 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:7778/health')" || exit 1

CMD ["/app/start.sh"]
