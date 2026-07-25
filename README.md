# HoneyOS

**Network Deception & Intrusion Detection System**

HoneyOS deploys silent decoy devices on your local network to detect internal threats, catch attackers during lateral movement, and record malicious activities — with zero false positives.

An open-source, self-hosted alternative to commercial honeypot appliances. No cloud. No accounts. No cost.

---

## What It Does

When an attacker compromises a device on your network, they scan for other targets — file servers, databases, admin panels. HoneyOS creates convincing fake versions of these services that no legitimate user would ever touch. Any interaction is an immediate indicator of compromise.

**Supported Protocols**: SSH, HTTP, HTTPS, Telnet, FTP, MySQL, PostgreSQL, DNS, SMB, RDP

**Key Capabilities**:
- Catches ransomware, lateral movement, and insider threats
- Records attacker keystrokes and commands (HackerCam)
- Sends instant alerts via email, Slack, webhooks, or SMS
- Monitors WAN ports for newly exposed services
- Zero false positives — no real services, no real users

## Quick Start

### Docker (any Linux host)

```bash
git clone https://github.com/honey-os/honeyos.git
cd honeyos
make setup    # creates .env from template
make prod     # builds and starts everything
```

Open `https://localhost:7777` in your browser (accept the self-signed certificate warning).

### Raspberry Pi

```bash
curl -sSL https://raw.githubusercontent.com/honey-os/honeyos/main/bin/setup-pi.sh | sudo bash
```

Access at `https://honeyos.local:7777` after setup completes (accept the self-signed certificate warning).

## Architecture

```
┌──────────────────────────────────────────────────┐
│                    Your Network                  │
│                                                  │
│  ┌──────────┐  ┌─────────┐  ┌─────────┐          │
│  │ Attacker │  │ Devices │  │  Users  │          │
│  └────┬─────┘  └─────────┘  └─────────┘          │
│       │                                          │
│       ▼                                          │
│  ┌────────────────────────────────────────────┐  │
│  │              HoneyOS                       │  │
│  │                                            │  │
│  │  ┌──────┐ ┌──────┐ ┌────────┐ ┌─────┐      │  │
│  │  │ SSH  │ │ HTTP │ │ Telnet │ │ FTP │ ...  │  │
│  │  │:2222 │ │:8080 │ │ :2323  │ │:2121│      │  │
│  │  └──┬───┘ └──┬───┘ └───┬────┘ └──┬──┘      │  │
│  │     └────┬───┴────┬────┘         │         │  │
│  │          ▼        ▼              ▼         │  │
│  │  ┌─────────────────────────────────┐       │  │
│  │  │     Event Processor             │       │  │
│  │  │  → Session Recording            │       │  │
│  │  │  → Alert Engine                 │       │  │
│  │  │  → SQLite Database              │       │  │
│  │  └─────────────────────────────────┘       │  │
│  │          │                                 │  │
│  │          ▼                                 │  │
│  │  ┌─────────────┐  ┌─────────────────┐      │  │
│  │  │  Dashboard  │  │    Alerts       │      │  │
│  │  │  :7777      │  │ Email/Slack/etc │      │  │
│  │  └─────────────┘  └─────────────────┘      │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Dashboard

The web dashboard at port 7777 provides:

- **Real-time event feed** — live stream of all honeypot interactions
- **Session replay** — watch attacker keystrokes in a terminal player
- **Threat analytics** — top attackers, protocol breakdown, timeline charts
- **Honeypot management** — enable/disable services, configure ports
- **Alert configuration** — set up email, Slack, webhook notifications
- **WAN monitoring** — scan and track public-facing open ports

## Configuration

Copy `.env.example` to `.env` and customize. See [Environment Variables](#environment-variables) for the full list of options and their defaults.

## Environment Variables

All settings are configured via environment variables in `.env`. Copy `.env.example` to get started.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `honeyos-default-secret-change-me` | Flask secret key. Generate with `openssl rand -hex 32` |
| `DEBUG` | `false` | Enable Flask debug mode |
| `READ_ONLY` | `false` | Lock dashboard to read-only mode. Login/logout still works; manage honeypots via `*_HONEYPOT_ENABLED` env vars instead |
| `READ_ONLY_PASSWORD` | *(empty)* | When `READ_ONLY` is true, display this password on the login screen so visitors can log in |
| `DATABASE_URL` | `sqlite:///honeyos.db` | SQLAlchemy database URI |
| `BIND_HOST` | `0.0.0.0` | Address the backend binds to |
| `API_PORT` | `7778` | Backend API port |
| `NETWORK_INTERFACE` | `eth0` | Primary network interface for scanning |
| `SSH_HONEYPOT_PORT` | `2222` | Internal SSH honeypot port |
| `HTTP_HONEYPOT_PORT` | `8080` | Internal HTTP honeypot port |
| `HTTPS_HONEYPOT_PORT` | `8443` | Internal HTTPS honeypot port |
| `TELNET_HONEYPOT_PORT` | `2323` | Internal Telnet honeypot port |
| `FTP_HONEYPOT_PORT` | `2121` | Internal FTP honeypot port |
| `MYSQL_HONEYPOT_PORT` | `3307` | Internal MySQL honeypot port |
| `POSTGRESQL_HONEYPOT_PORT` | `5433` | Internal PostgreSQL honeypot port |
| `DNS_HONEYPOT_PORT` | `5353` | Internal DNS honeypot port |
| `SMB_HONEYPOT_PORT` | `4450` | Internal SMB honeypot port |
| `RDP_HONEYPOT_PORT` | `3390` | Internal RDP honeypot port |
| `SSH_EXTERNAL_PORT` | `22` | External-facing SSH port (after Docker/firewall NAT) |
| `HTTP_EXTERNAL_PORT` | `80` | External-facing HTTP port |
| `HTTPS_EXTERNAL_PORT` | `443` | External-facing HTTPS port |
| `TELNET_EXTERNAL_PORT` | `23` | External-facing Telnet port |
| `FTP_EXTERNAL_PORT` | `21` | External-facing FTP port |
| `MYSQL_EXTERNAL_PORT` | `3306` | External-facing MySQL port |
| `POSTGRESQL_EXTERNAL_PORT` | `5432` | External-facing PostgreSQL port |
| `DNS_EXTERNAL_PORT` | `53` | External-facing DNS port |
| `SMB_EXTERNAL_PORT` | `445` | External-facing SMB port |
| `RDP_EXTERNAL_PORT` | `3389` | External-facing RDP port |
| `SSH_HONEYPOT_ENABLED` | `true` | Enable SSH honeypot on startup |
| `HTTP_HONEYPOT_ENABLED` | `true` | Enable HTTP honeypot on startup |
| `HTTPS_HONEYPOT_ENABLED` | `true` | Enable HTTPS honeypot on startup |
| `TELNET_HONEYPOT_ENABLED` | `true` | Enable Telnet honeypot on startup |
| `FTP_HONEYPOT_ENABLED` | `true` | Enable FTP honeypot on startup |
| `MYSQL_HONEYPOT_ENABLED` | `true` | Enable MySQL honeypot on startup |
| `POSTGRESQL_HONEYPOT_ENABLED` | `true` | Enable PostgreSQL honeypot on startup |
| `DNS_HONEYPOT_ENABLED` | `true` | Enable DNS honeypot on startup |
| `SMB_HONEYPOT_ENABLED` | `true` | Enable SMB honeypot on startup |
| `RDP_HONEYPOT_ENABLED` | `true` | Enable RDP honeypot on startup |
| `ABUSECH_API_KEY` | *(empty)* | abuse.ch API key for ThreatFox/URLhaus threat intelligence lookups |
| `CENSYS_API_TOKEN` | *(empty)* | Censys API personal access token for perimeter monitoring |
| `PUBLIC_IP` | *(empty)* | Override public IP detection (auto-detected if empty) |
| `GEOIP_ENABLED` | `true` | Enable GeoIP lookups via ip-api.com (free, no key needed) |
| `RETENTION_DAYS` | `90` | Days to retain event data |
| `ALERT_COOLDOWN_SECONDS` | `300` | Minimum seconds between repeated alerts |
| `THROTTLE_EVENT_THRESHOLD` | `5000` | Events from one IP on one protocol before blocking new connections |
| `THROTTLE_BLOCK_SECONDS` | `3600` | Duration (seconds) to block an IP after threshold is exceeded |
| `MAX_CONNECTIONS_PER_IP` | `100` | Max concurrent connections from a single IP before blocking |
| `LOG_LEVEL` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `SMTP_HOST` | *(empty)* | SMTP server for email alerts |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | *(empty)* | SMTP username |
| `SMTP_PASSWORD` | *(empty)* | SMTP password |
| `SMTP_USE_TLS` | `true` | Use TLS for SMTP |
| `SMTP_FROM_ADDRESS` | `honeyos@localhost` | From address for alert emails |
| `SLACK_WEBHOOK_URL` | *(empty)* | Slack incoming webhook URL for alerts |
| `WEBHOOK_URL` | *(empty)* | Generic webhook URL for alerts (receives JSON POST) |
| `WEBHOOK_ENABLED` | `true` | Run the inbound canarytokens.org webhook listener |
| `WEBHOOK_PORT` | `7779` | Port for the canarytokens webhook listener (separate from the API and all honeypots) |
| `WEBHOOK_PUBLIC_URL` | *(empty)* | Public URL canarytokens.org should POST to. Set when a proxy fronts the host; otherwise derived from `host:WEBHOOK_PORT` |
| `CANARY_AWS_ACCESS_KEY_ID` | *(empty)* | canarytokens.org AWS access key ID to plant in the bait `.env` |
| `CANARY_AWS_SECRET_ACCESS_KEY` | *(empty)* | canarytokens.org AWS secret key to plant in the bait `.env` |
| `SESSION_TIMEOUT_HOURS` | `168` | Hours before admin session expires (default 7 days) |
| `FRONTEND_PORT` | `7777` | Port the web dashboard listens on |
| `API_URL` | *(auto-detected)* | Backend API URL the browser uses. Runtime — no rebuild needed. Only set if the default `https://<hostname>:7778` doesn't work |
| `TLS_CERT` | `internal` | TLS certificate: `internal` (self-signed), a file path, or a domain for Let's Encrypt |
| `TLS_KEY` | *(empty)* | TLS private key file path (used with custom certs only) |
| `FTP_PASV_ADDRESS` | *(empty)* | IP to advertise in FTP PASV responses (set to host/public IP in Docker) |

## Default Honeypot Ports

In production (Docker/Pi), honeypots bind to standard ports so they look real to attackers. Internally the containers use high ports to avoid running as root.

| Protocol | External Port | Internal Port | Mimics |
|----------|--------------|---------------|--------|
| SSH | 22 | 2222 | OpenSSH 8.9 file server |
| HTTP | 80 | 8080 | Apache admin portal |
| HTTPS | 443 | 8443 | Apache admin portal (TLS) |
| Telnet | 23 | 2323 | Network router |
| FTP | 21 | 2121 | ProFTPD NAS |
| MySQL | 3306 | 3307 | MySQL 8.0 database |
| PostgreSQL | 5432 | 5433 | PostgreSQL 14.5 database |
| DNS | 53 | 5353 | Misconfigured DNS server (UDP + TCP) |
| SMB | 445 | 4450 | Windows file server |
| RDP | 3389 | 3390 | Windows Remote Desktop |

In development, the high ports are exposed directly (2222, 8080, etc.) to avoid conflicts with host services. All ports are configurable through the dashboard or API.

When enabled, the canarytokens webhook listener additionally binds port `7779` — separate from the API and every honeypot port. See [Canarytokens Integration](#canarytokens-integration-optional).

## API

Full REST API available at port 7778:

```
GET  /health                    # Health check
GET  /api/events                # List events (with filters)
GET  /api/sessions              # List recorded sessions
GET  /api/sessions/{id}/replay  # Session replay data
GET  /api/honeypots             # List honeypot services
GET  /api/dashboard/summary     # Dashboard analytics
GET  /api/dashboard/timeline    # Event timeline data
GET  /api/network-scans         # WAN scan results
GET  /api/config                # System configuration
```

## Development

```bash
make dev          # Start with hot-reload
make logs         # Tail all logs
make test         # Run all tests
make status       # Check service status
```

### Manual development (without Docker):

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

## Tech Stack

- **Backend**: Python 3.11, Flask, SQLAlchemy, SQLite, Paramiko
- **Frontend**: Next.js 14, React 18, Tailwind CSS, Zustand, Recharts
- **Infrastructure**: Docker Compose, GitHub Actions, multi-arch builds (amd64 + arm64)

## Use Cases

- **Home labs**: Detect compromised IoT devices or malware
- **Small businesses**: Internal threat detection without enterprise costs
- **Schools**: Catch unauthorized network activity
- **MSPs**: Add honeypot monitoring to client networks
- **Security research**: Study attacker behavior and techniques

## TLS / HTTPS

The dashboard is served over HTTPS on port 7777 with a self-signed certificate by default. A Caddy reverse proxy handles TLS termination automatically.

### Custom Certificates

Place your cert and key in the data directory and set env vars in `.env`:

```
TLS_CERT=/data/certs/honeyos.pem
TLS_KEY=/data/certs/honeyos.key
```

Restart HoneyOS to apply: `docker compose up -d`

### Automatic Let's Encrypt

If your server has a public domain and ports 80/443 available for ACME challenges, set:

```
TLS_CERT=honeyos.example.com
```

Caddy will automatically provision and renew a certificate.

### Plain HTTP (no TLS)

To disable TLS entirely, set in `.env`:

```
TLS_CERT=off
```

### Development Mode

`make dev` bypasses Caddy entirely and serves plain HTTP on ports 7777/7778 directly.

## Censys Integration (Optional)

HoneyOS can check your public IP against [Censys](https://search.censys.io) to detect perimeter drift — ports that are unexpectedly open or missing compared to what you've declared. This is optional; without it the Network page still tracks declared ports but can't compare them against what's actually visible externally.

### Setup

1. Create a free account at [search.censys.io](https://search.censys.io)
2. Go to [Account > API](https://app.censys.io/account/api) and copy your **Personal Access Token**
3. Add it to your `.env` file:

```
CENSYS_API_TOKEN=your-token-here
```

4. Optionally set your public IP if auto-detection doesn't work:

```
PUBLIC_IP=203.0.113.50
```

5. Restart HoneyOS:

```bash
docker compose up -d
```

6. Open the Network page and click **Check Now** to run your first scan

### What it checks

- **Drift detection** — compares your declared honeypot ports against what Censys sees externally. Unexpected ports may indicate unauthorized services; missing ports may indicate firewall misconfiguration.
- **Host overview** — shows your IP's organization, ISP, OS, and hostnames as seen by Censys.
- **Banner comparison** — checks whether the banners Censys captured match what your honeypots are configured to send. Mismatches may mean your honeypots are being fingerprinted.
- **Honeypot flagging** — warns you if Censys has tagged your IP as a known honeypot.

## Canarytokens Integration (Optional)

HoneyOS can plant a [Canarytokens](https://canarytokens.org) AWS credential in the bait files its HTTP/HTTPS honeypots serve (the fake `.env`, `config.php`, and `.git/config`). When an attacker who scraped those files tries the AWS key against AWS — from anywhere in the world — Thinkst detects the use and notifies HoneyOS via a webhook, which records it as a **critical** event on your dashboard. Because the key belongs to Thinkst's trap account, you don't provision any AWS infrastructure yourself; you only plant the key.

This complements HoneyOS's built-in honeytokens: the bait `.env` also contains locally-generated database credentials that point at this host's own MySQL honeypot, so credentials read from the bait and replayed against **any** honeypot protocol are flagged as `honeytoken` events. The Canarytokens AWS key extends that reach beyond your own box.

### The webhook listener

Triggers arrive on a standalone listener on `WEBHOOK_PORT` (default `7779`), deliberately separate from the admin API and every honeypot port so inbound notifications never touch admin authentication. It authenticates callers with a per-install random path secret. Disable it entirely with `WEBHOOK_ENABLED=false`.

### Setup

1. At [canarytokens.org](https://canarytokens.org), create an **AWS keys** token (the simple, free one — *not* the "AWS decoys" Terraform wizard). It hands you a fake access key ID and secret immediately.

2. In the HoneyOS dashboard, open **Settings → Canarytokens Webhook** and copy the webhook URL (it embeds the per-install secret). Set that URL as the token's notification/webhook target on canarytokens.org.

3. Add the generated key pair to your `.env`:

```
CANARY_AWS_ACCESS_KEY_ID=AKIA...
CANARY_AWS_SECRET_ACCESS_KEY=...
```

4. Restart HoneyOS so the honeypots rebuild their bait files with the planted key:

```bash
docker compose up -d
```

**Reachability:** canarytokens.org must be able to POST to the webhook from the public internet. If a reverse proxy or CDN fronts your host, expose the listener through it and set `WEBHOOK_PUBLIC_URL` to the externally-reachable URL (e.g. `https://honeyos.example.com/canary`); otherwise the dashboard advertises `http://<host>:7779` and port `7779` must be open inbound.

### What you'll see

A trigger appears as a `canary` protocol event at **critical** severity, carrying the token's memo, source IP, and user agent. Filter to it on the **Events** page (the `CANARY` protocol option) — it renders with a distinct yellow badge. Since the planted key is random per install, a trigger is high-confidence proof that someone read your bait and tried the credentials.

## Troubleshooting

### Port 53 conflict (DNS honeypot)

On Ubuntu/Debian, `systemd-resolved` listens on port 53 by default. Docker cannot bind the DNS honeypot to port 53 until this is disabled.

To free port 53:

```bash
# Disable the stub listener
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/no-stub.conf > /dev/null <<EOF
[Resolve]
DNSStubListener=no
EOF

# Point resolv.conf to the full resolver (DNS still works)
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# Restart resolved
sudo systemctl restart systemd-resolved
```

Verify port 53 is free:

```bash
ss -tlnp | grep :53
```

Then restart HoneyOS (`docker compose up -d`). To undo this later, remove the conf file and restore the symlink:

```bash
sudo rm /etc/systemd/resolved.conf.d/no-stub.conf
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

## License

AGPL — see [LICENSE](LICENSE) for details.
