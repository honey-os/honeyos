#!/bin/sh
set -e

TLS_CERT="${TLS_CERT:-off}"
TLS_KEY="${TLS_KEY:-}"

if [ "$TLS_CERT" = "off" ] || [ -z "$TLS_CERT" ]; then
    # Plain HTTP mode (default)
    cat > /tmp/Caddyfile <<'EOF'
:7777 {
	reverse_proxy /health backend:7778
	reverse_proxy /api/* backend:7778
	reverse_proxy frontend:7777
}
EOF
elif [ "$TLS_CERT" = "internal" ]; then
    # Self-signed certificate
    cat > /tmp/Caddyfile <<'EOF'
:7777 {
	tls internal
	reverse_proxy /health backend:7778
	reverse_proxy /api/* backend:7778
	reverse_proxy frontend:7777
}
EOF
else
    # Custom certificate files or domain name
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
