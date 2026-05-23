# HoneyOS - Network Deception and Intrusion Detection System

## Project Overview

**Application Name**: HoneyOS
**Domain**: honeyos.io
**Type**: Self-hosted SaaS Application

HoneyOS is an open-source, zero-cost alternative to commercial honeypot appliances that brings enterprise-grade internal threat detection to home labs, small businesses, schools, and MSP-managed environments. It works by mimicking attractive targets (file servers, SSH servers, RDP endpoints) that attackers look for when they're already inside a network.

### Core Features
- **Internal threat detection**: Catches attackers, ransomware, and compromised devices during lateral movement
- **Zero false positives**: No legitimate traffic should ever interact with HoneyOS
- **Session recording**: Logs and replays attacker keystrokes ("HackerCam" functionality)
- **Multi-protocol deception**: SSH, Telnet, HTTP, FTP, SMB, RDP, MySQL emulation
- **Instant alerts**: Email, webhooks, Slack, SMS notifications
- **WAN port monitoring**: Scans public-facing network for newly opened ports
- **Clean web dashboard**: Local browser-based UI for event management
- **Fully local**: No cloud dependency, no external accounts required

### Deployment Formats
- **Raspberry Pi Image**: Flash-and-run .img file accessible at http://honeyos.local
- **Docker Image**: Single `docker compose up -d` command for any Linux host

## Technical Architecture

### Core Stack
- **Backend**: Python 3.11+ with Flask
- **Database**: SQLite (with SQLAlchemy ORM)
- **Frontend**: Next.js 14+ with React 18+
- **Styling**: Tailwind CSS with modern design system
- **State Management**: Zustand
- **Authentication**: None (local deployment only)
- **Runtime**: Node.js 20 LTS

### Infrastructure
- **Deployment**: Kubernetes + Docker
- **Container Registry**: GitHub Container Registry (ghcr.io)
- **Database Pooling**: PgBouncer (when scaling beyond SQLite)
- **Timeline**: Sprint delivery (1-2 weeks)

## Project Structure

```
honeyos/
├── README.md
├── CLAUDE.md
├── Makefile
├── .env.example
├── docker-compose.yml
├── docker-compose.dev.yml
├── .github/
│   └── workflows/
│       └── deploy.yml
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py
│   ├── config.py
│   ├── models/
│   ├── services/
│   ├── api/
│   └── utils/
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── next.config.js
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── stores/
│   │   └── utils/
├── database/
│   └── migrations/
├── pgbouncer/
│   ├── Dockerfile
│   └── entrypoint.sh
├── k8s/
│   └── production/
└── bin/
```

## Database Schema

### Tables (SQLite with migration support)

#### `events` - Security Events
```sql
CREATE TABLE events (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    event_type TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity TEXT DEFAULT 'medium',
    details TEXT,
    session_id TEXT,
    user_agent TEXT,
    raw_payload TEXT,
    geolocation TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_source_ip ON events(source_ip);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_protocol ON events(protocol);
```

#### `sessions` - Attack Session Recordings
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    source_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    duration_seconds INTEGER,
    commands_count INTEGER DEFAULT 0,
    keystrokes TEXT,
    commands TEXT,
    file_transfers TEXT,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX idx_sessions_start_time ON sessions(start_time);
CREATE INDEX idx_sessions_protocol ON sessions(protocol);
```

#### `honeypots` - Active Decoy Services
```sql
CREATE TABLE honeypots (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    enabled BOOLEAN DEFAULT true,
    description TEXT,
    config TEXT,
    last_activity DATETIME,
    total_interactions INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_honeypots_port ON honeypots(port);
CREATE INDEX idx_honeypots_protocol ON honeypots(protocol);
```

#### `alerts` - Alert Configurations
```sql
CREATE TABLE alerts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    alert_type TEXT NOT NULL,
    config TEXT NOT NULL,
    conditions TEXT,
    last_sent DATETIME,
    send_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### `network_scans` - WAN Port Monitoring
```sql
CREATE TABLE network_scans (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    target_host TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    discovered_ports TEXT,
    scan_duration_ms INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    changes_detected BOOLEAN DEFAULT false,
    previous_scan_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_network_scans_target_host ON network_scans(target_host);
CREATE INDEX idx_network_scans_timestamp ON network_scans(timestamp);
```

#### `system_config` - Application Configuration
```sql
CREATE TABLE system_config (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,
    config_type TEXT DEFAULT 'string',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## API Endpoints

### Core API Routes

#### Health Check
```
GET /health
Response: { "status": "ok", "timestamp": "2024-01-01T00:00:00Z" }
```

#### Events Management
```
GET /api/events
Query Parameters:
- limit (default: 50)
- offset (default: 0)
- event_type (optional filter)
- protocol (optional filter)
- severity (optional filter)
- start_date, end_date (optional date range)

POST /api/events
Body: { "event_type", "protocol", "source_ip", "destination_port", "details", "severity" }

GET /api/events/{id}
Response: Full event details with related session data
```

#### Session Recordings
```
GET /api/sessions
Query Parameters: limit, offset, protocol, active_only

GET /api/sessions/{id}
Response: Full session with keystroke/command timeline

GET /api/sessions/{id}/replay
Response: Formatted replay data for frontend player
```

#### Honeypot Management
```
GET /api/honeypots
Response: List of all configured decoy services

POST /api/honeypots
Body: { "name", "protocol", "port", "enabled", "description", "config" }

PUT /api/honeypots/{id}
Body: Updated honeypot configuration

DELETE /api/honeypots/{id}
```

#### Alert Configuration
```
GET /api/alerts
Response: List of alert configurations

POST /api/alerts
Body: { "name", "alert_type", "config", "conditions", "enabled" }

PUT /api/alerts/{id}
Body: Updated alert configuration

POST /api/alerts/{id}/test
Action: Send test alert to verify configuration
```

#### Network Scanning
```
GET /api/network-scans
Query Parameters: limit, offset, target_host

POST /api/network-scans
Body: { "target_host", "scan_type" }
Action: Initiate new network scan

GET /api/network-scans/{id}/changes
Response: Comparison with previous scan results
```

#### Dashboard Analytics
```
GET /api/dashboard/summary
Response: {
  "total_events": number,
  "active_sessions": number,
  "top_attackers": [{"ip", "event_count"}],
  "protocol_breakdown": [{"protocol", "count"}],
  "recent_activity": [events],
  "threat_level": "low|medium|high"
}

GET /api/dashboard/timeline
Query Parameters: hours (default: 24)
Response: Time-series data for event visualization
```

#### System Configuration
```
GET /api/config
Response: Current system configuration

PUT /api/config
Body: { "key": "value" } pairs for bulk configuration update

GET /api/config/export
Response: Complete system configuration for backup

POST /api/config/import
Body: Configuration backup for restoration
```

## Frontend Components

### Core Pages and Components

#### Landing Page (`/`)
- Hero section with value proposition
- Feature highlights with icons/screenshots
- "How It Works" explanation
- Deployment options (Raspberry Pi vs Docker)
- Open source emphasis (zero cost, no cloud)
- Download/Get Started CTAs
- Technical specifications
- Community/documentation links

#### Dashboard (`/dashboard`)
- Threat level indicator
- Live event feed
- Active sessions monitor
- Geographic attack map (if geolocation enabled)
- Protocol activity charts
- Top attackers list
- Quick actions (enable/disable honeypots)

#### Events Page (`/events`)
- Filterable/sortable event table
- Event type/protocol/severity filters
- Date range picker
- Event detail modal with full context
- Bulk actions (mark as reviewed, export)
- Search functionality
- Export to CSV/JSON

#### Session Replay (`/sessions`)
- Session list with duration/command count
- Session replay player (terminal emulation)
- Keystroke timeline with timestamps
- Command history analysis
- File transfer detection
- Session export functionality

#### Honeypots Configuration (`/honeypots`)
- Service grid showing all protocols
- Enable/disable toggles
- Port configuration
- Service-specific settings (SSH banners, HTTP responses)
- Health status indicators
- Performance metrics

#### Alerts Configuration (`/alerts`)
- Alert method configuration (email, Slack, webhook, SMS)
- Test alert functionality
- Alert history and delivery status
- Condition-based triggers
- Rate limiting settings

#### Network Monitoring (`/network`)
- Target host configuration
- Scan schedule settings
- Port change detection
- Historical scan results
- Alert integration for new open ports

#### System Settings (`/settings`)
- General settings
- Network interface selection
- Logging levels
- Data retention policies
- Backup/restore functionality
- System information

### Shared Components
- EventFeed: Live-updating event stream
- ThreatMap: Geographic visualization
- MetricsCard: Key statistics display
- AlertBadge: Notification indicators
- SessionPlayer: Terminal replay component
- DataTable: Sortable/filterable tables
- DateRangePicker: Time range selection
- ProtocolBadge: Colored protocol indicators
- SeverityIndicator: Threat level visualization
- ConfigForm: Dynamic configuration forms

## Backend Services

### Core Services Architecture

#### Event Processing Service
- Ingests events from honeypot listeners
- Enriches events with geolocation/threat intel
- Triggers alert conditions
- Manages session correlation
- Handles event persistence

#### Honeypot Orchestrator
- Manages lifecycle of decoy services
- Handles protocol-specific implementations
- Monitors service health
- Configures service responses/behavior
- Collects interaction data

#### Alert Engine
- Processes alert conditions
- Manages notification delivery
- Handles rate limiting/deduplication
- Supports multiple delivery channels
- Tracks delivery status

#### Network Scanner
- Performs WAN port scanning
- Detects service changes
- Integrates with threat intelligence
- Manages scan schedules
- Compares historical results

#### Session Recorder
- Captures interactive sessions
- Records keystrokes/commands
- Handles session persistence
- Manages session lifecycle
- Provides replay functionality

### Protocol Implementations
- SSH Honeypot (Paramiko-based)
- HTTP/HTTPS Honeypot (Flask-based)
- Telnet Honeypot
- FTP Honeypot
- SMB Honeypot
- RDP Honeypot
- MySQL Honeypot

## Environment Configuration

### Environment Variables

```bash
# Application
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DEBUG=false

# Database
DATABASE_URL=sqlite:///honeyos.db
USE_PGBOUNCER=false

# Network Configuration
NETWORK_INTERFACE=eth0
DEFAULT_HONEYPOT_IP=192.168.1.100
PORT_RANGE_START=2000
PORT_RANGE_END=9999

# Alert Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@honeyos.io
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_EMAIL=HoneyOS Alerts <alerts@honeyos.io>

# External Services (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
GEOLOCATION_API_KEY=your-geolocation-api-key

# Security
SESSION_TIMEOUT_HOURS=24
MAX_EVENTS_PER_IP_PER_MINUTE=100
ENABLE_IP_BLOCKING=true

# Monitoring
LOG_LEVEL=INFO
METRICS_ENABLED=true
RETENTION_DAYS=365
```

## Deployment Instructions

### Docker Development Setup
```bash
git clone <repository>
cd honeyos
make setup
cp .env.example .env
make dev
# Frontend: http://localhost:3000
# Backend API: http://localhost:5000
```

### Production Deployment
```bash
make prod
# Or with Kubernetes:
kubectl apply -f k8s/production/
```

## Testing Strategy

### Backend Tests
- API endpoint testing
- Database model testing
- Event processing validation
- Alert delivery testing
- Honeypot service testing
- Protocol implementation tests
- Session recording validation
- Network scanning tests

### Frontend Tests
- Component unit tests (Jest/React Testing Library)
- User interaction testing
- Real-time updates validation
- Dashboard functionality
- API integration tests

## Development Best Practices

### Required Conventions
- **Latest Versions**: Use current stable releases (Node.js 20 LTS, Python 3.11+, React 18+)
- **Database**: SQLAlchemy for all operations, migration-based schema
- **Docker**: Production and development configurations with health checks
- **Documentation**: Comprehensive README.md and technical CLAUDE.md
- **CI/CD**: GitHub Actions with parallel builds and GHCR registry
- **Kubernetes**: Production-ready manifests with TLS and monitoring

### Security Considerations
- Input validation and sanitization
- Rate limiting for API endpoints
- Secure session handling
- SQL injection prevention (via ORM)
- XSS protection in frontend
