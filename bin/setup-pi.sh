#!/bin/bash
# HoneyOS Raspberry Pi Setup Script
# Run this on a fresh Raspberry Pi OS Lite installation
# Usage: curl -sSL https://raw.githubusercontent.com/your-repo/honeyos/main/bin/setup-pi.sh | bash

set -euo pipefail

echo "============================================"
echo "  HoneyOS - Raspberry Pi Setup"
echo "  Network Deception & Intrusion Detection"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash setup-pi.sh"
    exit 1
fi

# Check architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" && "$ARCH" != "armv7l" ]]; then
    echo "Warning: This script is designed for Raspberry Pi (ARM). Detected: $ARCH"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[1/6] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

echo "[2/6] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker pi 2>/dev/null || usermod -aG docker "$SUDO_USER" 2>/dev/null || true
else
    echo "Docker already installed"
fi

echo "[3/6] Installing Docker Compose..."
if ! command -v docker compose &> /dev/null; then
    apt-get install -y -qq docker-compose-plugin
else
    echo "Docker Compose already installed"
fi

echo "[4/6] Setting up Avahi/mDNS for honeyos.local..."
apt-get install -y -qq avahi-daemon
# Configure hostname
hostnamectl set-hostname honeyos
echo "honeyos" > /etc/hostname
sed -i 's/127\.0\.1\.1.*/127.0.1.1\thoneyos/' /etc/hosts

echo "[5/6] Installing HoneyOS..."
INSTALL_DIR="/opt/honeyos"
mkdir -p "$INSTALL_DIR"

# Clone or download HoneyOS
if command -v git &> /dev/null; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR" && git pull
    else
        rm -rf "$INSTALL_DIR"
        git clone https://github.com/your-repo/honeyos.git "$INSTALL_DIR"
    fi
else
    apt-get install -y -qq git
    git clone https://github.com/your-repo/honeyos.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Setup environment
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random secret key
    SECRET=$(openssl rand -hex 32)
    sed -i "s/change-this-to-a-random-secret-key/$SECRET/" .env
    # Set default network interface
    DEFAULT_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    sed -i "s/NETWORK_INTERFACE=eth0/NETWORK_INTERFACE=${DEFAULT_IF:-eth0}/" .env
fi

echo "[6/6] Creating systemd service..."
cat > /etc/systemd/system/honeyos.service << 'SYSTEMD'
[Unit]
Description=HoneyOS - Network Deception System
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/honeyos
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable honeyos.service

# Start HoneyOS
echo ""
echo "Starting HoneyOS..."
docker compose up -d --build

echo ""
echo "============================================"
echo "  HoneyOS Setup Complete!"
echo "============================================"
echo ""
echo "  Dashboard:  http://honeyos.local:7777"
echo "  API:        http://honeyos.local:7778"
echo ""
echo "  Honeypot ports active (standard ports):"
echo "    SSH:    22"
echo "    HTTP:   80"
echo "    Telnet: 23"
echo "    FTP:    21"
echo "    MySQL:  3306"
echo ""
echo "  To view logs: cd /opt/honeyos && make logs"
echo "  To stop:      cd /opt/honeyos && make stop"
echo "============================================"
