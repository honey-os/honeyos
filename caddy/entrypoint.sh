#!/bin/sh
set -e

TLS_CERT="${TLS_CERT:-off}"
TLS_KEY="${TLS_KEY:-}"

CERT_DIR="/data/certs"

if [ "$TLS_CERT" = "off" ] || [ -z "$TLS_CERT" ]; then
    # Plain HTTP mode
    cat > /tmp/Caddyfile <<'EOF'
:7777 {
	reverse_proxy /health backend:7778
	reverse_proxy /api/* backend:7778
	reverse_proxy frontend:7777
}
EOF

elif [ "$TLS_CERT" = "internal" ]; then
    # Generate self-signed cert if not already present
    if [ ! -f "$CERT_DIR/honeyos-selfsigned.pem" ] || [ ! -f "$CERT_DIR/honeyos-selfsigned.key" ]; then
        apk add --no-cache openssl >/dev/null 2>&1 || true
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
	reverse_proxy /health backend:7778
	reverse_proxy /api/* backend:7778
	reverse_proxy frontend:7777
}
EOF

else
    # Custom certificate files
    cat > /tmp/Caddyfile <<EOF
:7777 {
	tls ${TLS_CERT} ${TLS_KEY}
	reverse_proxy /health backend:7778
	reverse_proxy /api/* backend:7778
	reverse_proxy frontend:7777
}
EOF
fi

exec caddy run --config /tmp/Caddyfile --adapter caddyfile
