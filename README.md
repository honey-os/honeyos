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

Open `http://localhost:3000` in your browser.

### Raspberry Pi

```bash
curl -sSL https://raw.githubusercontent.com/your-repo/honeyos/main/bin/setup-pi.sh | sudo bash
```

Access at `http://honeyos.local:3000` after setup completes.

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
│  │  │  :3000      │  │ Email/Slack/etc │     │       │
│  │  └─────────────┘  └────────────────┘     │       │
│  └────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────┘
```

## Dashboard

The web dashboard at port 3000 provides:

- **Real-time event feed** — live stream of all honeypot interactions
- **Session replay** — watch attacker keystrokes in a terminal player
- **Threat analytics** — top attackers, protocol breakdown, timeline charts
- **Honeypot management** — enable/disable services, configure ports
- **Alert configuration** — set up email, Slack, webhook notifications
- **WAN monitoring** — scan and track public-facing open ports

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Core
SECRET_KEY=your-random-secret       # Generate with: openssl rand -hex 32
NETWORK_INTERFACE=eth0              # Your network interface

# Alerts (optional)
SMTP_HOST=smtp.gmail.com            # Email alerts
SLACK_WEBHOOK_URL=https://hooks...  # Slack alerts
WEBHOOK_URL=https://your-endpoint   # Webhook alerts

# Tuning
RETENTION_DAYS=365                  # How long to keep event data
LOG_LEVEL=INFO                      # DEBUG, INFO, WARNING, ERROR
```

## Default Honeypot Ports

| Protocol | Port | Mimics |
|----------|------|--------|
| SSH | 2222 | OpenSSH 8.9 file server |
| HTTP | 8080 | Apache admin portal |
| Telnet | 2323 | Network router |
| FTP | 2121 | ProFTPD NAS |
| MySQL | 3307 | MySQL 8.0 database |

All ports are configurable through the dashboard or API.

## API

Full REST API available at port 5000:

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
