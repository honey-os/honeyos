-- HoneyOS Initial Schema Migration
-- Created: 2024-01-01

-- Events table - Security Events
CREATE TABLE IF NOT EXISTS events (
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

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

-- Sessions table - Attack Session Recordings
CREATE TABLE IF NOT EXISTS sessions (
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

CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- Honeypots table - Active Decoy Services
CREATE TABLE IF NOT EXISTS honeypots (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    enabled BOOLEAN DEFAULT 1,
    description TEXT,
    config TEXT,
    last_activity DATETIME,
    total_interactions INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_honeypots_port ON honeypots(port);
CREATE INDEX IF NOT EXISTS idx_honeypots_protocol ON honeypots(protocol);

-- Alerts table - Alert Configurations
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    enabled BOOLEAN DEFAULT 1,
    alert_type TEXT NOT NULL,
    config TEXT NOT NULL,
    conditions TEXT,
    last_sent DATETIME,
    send_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Network Scans table - WAN Port Monitoring
CREATE TABLE IF NOT EXISTS network_scans (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    target_host TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    discovered_ports TEXT,
    scan_duration_ms INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    changes_detected BOOLEAN DEFAULT 0,
    previous_scan_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_network_scans_target_host ON network_scans(target_host);
CREATE INDEX IF NOT EXISTS idx_network_scans_timestamp ON network_scans(timestamp);

-- System Config table - Application Configuration
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,
    config_type TEXT DEFAULT 'string',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Default system configuration
INSERT OR IGNORE INTO system_config (key, value, description, config_type) VALUES
    ('network_interface', 'eth0', 'Network interface for honeypot services', 'string'),
    ('log_level', 'INFO', 'Application log level', 'string'),
    ('retention_days', '365', 'Days to retain event data', 'integer'),
    ('max_events_per_ip_per_minute', '100', 'Rate limit per source IP', 'integer'),
    ('enable_ip_blocking', 'true', 'Enable automatic IP blocking', 'boolean'),
    ('session_timeout_hours', '24', 'Session timeout in hours', 'integer'),
    ('alert_cooldown_seconds', '300', 'Minimum seconds between duplicate alerts', 'integer');

-- Default honeypot configurations
INSERT OR IGNORE INTO honeypots (id, name, protocol, port, enabled, description, config) VALUES
    ('ssh-default', 'SSH Server', 'ssh', 2222, 1, 'SSH honeypot mimicking an OpenSSH server', '{"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "hostname": "fileserver"}'),
    ('http-default', 'Web Server', 'http', 8080, 1, 'HTTP honeypot serving fake login pages', '{"server_header": "Apache/2.4.57", "title": "Admin Portal"}'),
    ('telnet-default', 'Telnet Server', 'telnet', 2323, 1, 'Telnet honeypot with fake login prompt', '{"banner": "Ubuntu 22.04 LTS", "hostname": "router"}'),
    ('ftp-default', 'FTP Server', 'ftp', 2121, 1, 'FTP honeypot capturing file transfer attempts', '{"banner": "220 ProFTPD 1.3.8 Server ready.", "hostname": "nas"}'),
    ('mysql-default', 'MySQL Server', 'mysql', 3307, 1, 'MySQL honeypot capturing query attempts', '{"version": "8.0.36-0ubuntu0.22.04.1", "hostname": "dbserver"}');
