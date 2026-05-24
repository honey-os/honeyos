# HoneyOS

**Network Deception & Intrusion Detection System**

HoneyOS deploys silent decoy devices on your local network to detect internal threats, catch attackers during lateral movement, and record malicious activities — with zero false positives.

An open-source, self-hosted alternative to commercial honeypot appliances. No cloud. No accounts. No cost.

---

## What It Does

When an attacker compromises a device on your network, they scan for other targets — file servers, databases, admin panels. HoneyOS creates convincing fake versions of these services that no legitimate user would ever touch. Any interaction is an immediate indicator of compromise.

**Supported Protocols**: SSH, HTTP, Telnet, FTP, MySQL (with SMB and RDP planned)

**Key Capabilities**:
- Catches ransomware, lateral movement, and insider threats
- Records attacker keystrokes and commands (HackerCam)
- Sends instant alerts via email, Slack, webhooks, or SMS
- Monitors WAN ports for newly exposed services
- Zero false positives — no real services, no real users

## Quick Start

### Docker (any Linux host)

```bash
git clone https://github.com/your-repo/honeyos.git
cd honeyos
make setup    # creates .env from template
make prod     # builds and starts everything
```

Open `http://localhost:7777` in your browser.

### Raspberry Pi

```bash
curl -sSL https://raw.githubusercontent.com/your-repo/honeyos/main/bin/setup-pi.sh | sudo bash
```

Access at `http://honeyos.local:7777` after setup completes.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Your Network                       │
│                                                       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐              │
│  │ Attacker │  │ Devices │  │  Users  │              │
│  └────┬─────┘  └─────────┘  └─────────┘              │
│       │                                               │
│       ▼                                               │
│  ┌────────────────────────────────────────────┐       │
│  │              HoneyOS                       │       │
│  │                                            │       │
│  │  ┌──────┐ ┌──────┐ ┌────────┐ ┌─────┐    │       │
│  │  │ SSH  │ │ HTTP │ │ Telnet │ │ FTP │ ...│       │
│  │  │:2222 │ │:8080 │ │ :2323  │ │:2121│    │       │
│  │  └──┬───┘ └──┬───┘ └───┬────┘ └──┬──┘    │       │
│  │     └────┬───┴────┬────┘         │        │       │
│  │          ▼        ▼              ▼        │       │
│  │  ┌─────────────────────────────────┐      │       │
│  │  │     Event Processor             │      │       │
│  │  │  → Session Recording            │      │       │
│  │  │  → Alert Engine                 │      │       │
│  │  │  → SQLite Database              │      │       │
│  │  └─────────────────────────────────┘      │       │
│  │          │                                │       │
│  │          ▼                                │       │
│  │  ┌─────────────┐  ┌────────────────┐     │       │
│  │  │  Dashboard  │  │    Alerts       │     │       │
│  │  │  :7777      │  │ Email/Slack/etc │     │       │
│  │  └─────────────┘  └────────────────┘     │       │
│  └────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────┘
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
| `DATABASE_URL` | `sqlite:///honeyos.db` | SQLAlchemy database URI |
| `BIND_HOST` | `0.0.0.0` | Address the backend binds to |
| `API_PORT` | `7778` | Backend API port |
| `NETWORK_INTERFACE` | `eth0` | Primary network interface for scanning |
| `SSH_HONEYPOT_PORT` | `2222` | Internal SSH honeypot port |
| `HTTP_HONEYPOT_PORT` | `8080` | Internal HTTP honeypot port |
| `TELNET_HONEYPOT_PORT` | `2323` | Internal Telnet honeypot port |
| `FTP_HONEYPOT_PORT` | `2121` | Internal FTP honeypot port |
| `MYSQL_HONEYPOT_PORT` | `3307` | Internal MySQL honeypot port |
| `GEOIP_ENABLED` | `true` | Enable GeoIP lookups via ip-api.com (free, no key needed) |
| `RETENTION_DAYS` | `90` | Days to retain event data |
| `ALERT_COOLDOWN_SECONDS` | `300` | Minimum seconds between repeated alerts |
| `LOG_LEVEL` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `SMTP_HOST` | *(empty)* | SMTP server for email alerts |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | *(empty)* | SMTP username |
| `SMTP_PASSWORD` | *(empty)* | SMTP password |
| `SMTP_USE_TLS` | `true` | Use TLS for SMTP |
| `SMTP_FROM_ADDRESS` | `honeyos@localhost` | From address for alert emails |
| `SLACK_WEBHOOK_URL` | *(empty)* | Slack incoming webhook URL for alerts |
| `SESSION_TIMEOUT_HOURS` | `168` | Hours before admin session expires (default 7 days) |
| `FRONTEND_PORT` | `7777` | Port the web dashboard listens on |
| `NEXT_PUBLIC_API_URL` | `http://localhost:7778` | API URL used by the frontend |

## Default Honeypot Ports

In production (Docker/Pi), honeypots bind to standard ports so they look real to attackers. Internally the containers use high ports to avoid running as root.

| Protocol | External Port | Internal Port | Mimics |
|----------|--------------|---------------|--------|
| SSH | 22 | 2222 | OpenSSH 8.9 file server |
| HTTP | 80 | 8080 | Apache admin portal |
| Telnet | 23 | 2323 | Network router |
| FTP | 21 | 2121 | ProFTPD NAS |
| MySQL | 3306 | 3307 | MySQL 8.0 database |

In development, the high ports are exposed directly (2222, 8080, etc.) to avoid conflicts with host services. All ports are configurable through the dashboard or API.

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

## License

MIT — see [LICENSE](LICENSE) for details.
