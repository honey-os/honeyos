# ── Stage 1: Build frontend ──────────────────────────────────────────
FROM node:26-alpine AS frontend-build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ .

ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ── Stage 2: the node binary for the runtime ─────────────────────────────────────
FROM node:26-slim AS node-runtime

# ── Stage 3: Runtime (Caddy + Python + Node) ────────────────────────
# The base is the Python image, not the Node one: no official node image
# ships a current Python (they carry whatever Debian has), while the runtime
# only needs the `node` binary to run the standalone Next.js server. Both
# images are built on the same Debian release, so the binary copies across.
FROM python:3.15-slim

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node

ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev curl openssl libstdc++6 libatomic1 \
    && node --version \
    && CADDY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") \
    && curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=${CADDY_ARCH}" -o /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy \
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

# Data directory for SQLite + certs
RUN mkdir -p /data /data/certs

# Startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

ENV DATABASE_URL=sqlite:////data/honeyos.db
ENV FLASK_ENV=production
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

EXPOSE 7777 7778

HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=10 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["/app/start.sh"]
