#!/usr/bin/env bash
set -euo pipefail

# HoneyOS Installer
# Pulls images from Docker Hub and starts the stack.
# Usage: curl -sSL https://honeyos.io/setup-docker.sh | bash

HONEYOS_DIR="${HONEYOS_DIR:-/opt/honeyos}"
IMAGE_PREFIX="honeyos"
TAG="${HONEYOS_VERSION:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[HoneyOS]${NC} $*"; }
ok()    { echo -e "${GREEN}[HoneyOS]${NC} $*"; }
warn()  { echo -e "${YELLOW}[HoneyOS]${NC} $*"; }
err()   { echo -e "${RED}[HoneyOS]${NC} $*" >&2; }

# -------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------
check_deps() {
    local missing=()
    for cmd in docker; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing required tools: ${missing[*]}"
        err "Install Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Require Docker Compose V2 plugin (docker-compose v1 has known bugs with modern Docker)
    if docker compose version &>/dev/null; then
        COMPOSE="docker compose"
    else
        err "Docker Compose V2 plugin not found."
        err "Install it:  apt-get install docker-compose-plugin"
        err "Or see:      https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# -------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------
setup_dir() {
    info "Setting up HoneyOS in ${HONEYOS_DIR}"
    mkdir -p "$HONEYOS_DIR"
    mkdir -p "$HONEYOS_DIR/data"
    mkdir -p "$HONEYOS_DIR/data/certs"
    cd "$HONEYOS_DIR"
}

generate_secret() {
    # Portable random secret generation
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    fi
}

write_env() {
    if [ -f .env ]; then
        warn ".env already exists, keeping existing configuration"
        return
    fi

    local secret
    secret=$(generate_secret)

    info "Generating .env configuration"
    cat > .env <<EOF
# HoneyOS Configuration
FLASK_ENV=production
SECRET_KEY=${secret}
DEBUG=false
DATABASE_URL=sqlite:////data/honeyos.db
NETWORK_INTERFACE=eth0
LOG_LEVEL=INFO
RETENTION_DAYS=365

# TLS Configuration (default is self-signed HTTPS)
# For plain HTTP:    TLS_CERT=off
# For custom certs:  TLS_CERT=/data/certs/honeyos.pem  TLS_KEY=/data/certs/honeyos.key
# For Let's Encrypt: TLS_CERT=honeyos.example.com
TLS_CERT=internal
TLS_KEY=

# Alert Configuration (optional -- fill in to enable)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=
# SMTP_PASSWORD=
# SLACK_WEBHOOK_URL=
# WEBHOOK_URL=
EOF
}

write_compose() {
    if [ -f docker-compose.yml ]; then
        info "Updating docker-compose.yml"
    else
        info "Writing docker-compose.yml"
    fi

    cat > docker-compose.yml <<EOF
services:
  honeyos:
    image: ${IMAGE_PREFIX}/honeyos:${TAG}
    container_name: honeyos
    restart: unless-stopped
    ports:
      - "7777:7777"
      - "7778:7778"
      - "22:2222"
      - "80:8080"
      - "443:8443"
      - "23:2323"
      - "21:2121"
      - "3306:3307"
      - "5432:5433"
      - "53:5353/udp"
      - "53:5353/tcp"
      - "445:4450"
      - "3389:3390"
      - "40000-40049:40000-40049"
    volumes:
      - ./data:/data
    env_file:
      - .env
    environment:
      - DATABASE_URL=sqlite:////data/honeyos.db
      - TLS_CERT=\${TLS_CERT:-internal}
      - TLS_KEY=\${TLS_KEY:-}
EOF
}

# -------------------------------------------------------------------
# Pull & run
# -------------------------------------------------------------------
pull_images() {
    info "Pulling images (${TAG})..."
    $COMPOSE pull
}

start_stack() {
    info "Starting HoneyOS..."
    $COMPOSE up -d --force-recreate
}

wait_healthy() {
    info "Waiting for services to become healthy..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if docker inspect --format='{{.State.Health.Status}}' honeyos 2>/dev/null | grep -q healthy; then
            break
        fi
        retries=$((retries - 1))
        sleep 2
    done

    if [ $retries -eq 0 ]; then
        warn "Backend didn't report healthy in time, but may still be starting"
    fi
}

# -------------------------------------------------------------------
# Port conflict check
# -------------------------------------------------------------------
check_ports() {
    local ports=(22 23 80 443 21 3306 5432 53 445 3389 7777)
    local conflicts=()
    for port in "${ports[@]}"; do
        if ss -tulnp 2>/dev/null | grep -q ":${port} " || \
           netstat -tulnp 2>/dev/null | grep -q ":${port} " 2>/dev/null; then
            conflicts+=("$port")
        fi
    done
    if [ ${#conflicts[@]} -gt 0 ]; then
        warn "Ports already in use: ${conflicts[*]}"
        warn "HoneyOS needs these ports for honeypot services."
        warn "Stop conflicting services or edit docker-compose.yml to change port mappings."
        if [[ " ${conflicts[*]} " == *" 53 "* ]]; then
            warn "Port 53: see README Troubleshooting section to disable systemd-resolved stub listener."
        fi
        echo ""
        read -r -p "Continue anyway? [y/N] " answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            err "Aborted."
            exit 1
        fi
    fi
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ${GREEN}HoneyOS Installer${CYAN}               ║${NC}"
    echo -e "${CYAN}║  ${NC}Network Deception & Intrusion Detection${CYAN} ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_deps
    setup_dir
    write_env
    write_compose
    check_ports
    pull_images
    start_stack
    wait_healthy

    echo ""
    ok "HoneyOS is running!"
    echo ""
    echo -e "  Dashboard:  ${GREEN}https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):7777${NC}"
    echo -e "  Config:     ${CYAN}${HONEYOS_DIR}/.env${NC}"
    echo ""
    echo -e "  TLS:        Self-signed certificate (accept browser warning)"
    echo -e "              Custom certs: place in ${CYAN}${HONEYOS_DIR}/data/certs/${NC} and update .env"
    echo ""
    echo -e "  Honeypots listening on ports: ${YELLOW}22 (SSH)  80 (HTTP)  443 (HTTPS)  23 (Telnet)  21 (FTP)  3306 (MySQL)  5432 (PostgreSQL)  53 (DNS)  445 (SMB)  3389 (RDP)${NC}"
    echo ""
    echo -e "  Manage:     ${CYAN}cd ${HONEYOS_DIR} && docker compose logs -f${NC}"
    echo -e "  Stop:       ${CYAN}cd ${HONEYOS_DIR} && docker compose down${NC}"
    echo -e "  Update:     ${CYAN}cd ${HONEYOS_DIR} && docker compose pull && docker compose up -d${NC}"
    echo ""
}

main "$@"
