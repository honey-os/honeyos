#!/bin/sh
set -e

# ── Generate Caddyfile based on TLS config ───────────────────────────
TLS_CERT="${TLS_CERT:-internal}"
TLS_KEY="${TLS_KEY:-}"
CERT_DIR="/data/certs"

if [ "$TLS_CERT" = "off" ] || [ -z "$TLS_CERT" ]; then
    cat > /tmp/Caddyfile <<'EOF'
:7777 {
	reverse_proxy localhost:3000
}
:7778 {
	reverse_proxy localhost:8000
}
EOF

elif [ "$TLS_CERT" = "internal" ]; then
    if [ ! -f "$CERT_DIR/honeyos-selfsigned.pem" ] || [ ! -f "$CERT_DIR/honeyos-selfsigned.key" ]; then
        mkdir -p "$CERT_DIR"
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$CERT_DIR/honeyos-selfsigned.key" \
            -out "$CERT_DIR/honeyos-selfsigned.pem" \
            -days 3650 -nodes \
            -subj '/O=HoneyOS/CN=HoneyOS Dashboard' \
            -addext 'subjectAltName=DNS:localhost,DNS:honeyos,DNS:honeyos.local,IP:127.0.0.1'
    fi

    cat > /tmp/Caddyfile <<'EOF'
:7777 {
	tls /data/certs/honeyos-selfsigned.pem /data/certs/honeyos-selfsigned.key
	reverse_proxy localhost:3000
}
:7778 {
	tls /data/certs/honeyos-selfsigned.pem /data/certs/honeyos-selfsigned.key
	reverse_proxy localhost:8000
}
EOF

else
    cat > /tmp/Caddyfile <<EOF
:7777 {
	tls ${TLS_CERT} ${TLS_KEY}
	reverse_proxy localhost:3000
}
:7778 {
	tls ${TLS_CERT} ${TLS_KEY}
	reverse_proxy localhost:8000
}
EOF
fi

# ── Start services ───────────────────────────────────────────────────

# Backend (gunicorn) in background
cd /app/backend
/app/venv/bin/gunicorn --bind 127.0.0.1:8000 --worker-class gthread \
    --workers 1 --threads 4 --timeout 120 --access-logfile - app:app &

# Frontend (Next.js standalone) in background
cd /app/frontend
HOSTNAME=127.0.0.1 PORT=3000 node server.js &

# Caddy in foreground
exec caddy run --config /tmp/Caddyfile --adapter caddyfile
