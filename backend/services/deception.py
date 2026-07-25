"""
Deception content service.

Generates per-install planted credentials (honeytokens), renders the bait
files the HTTP/HTTPS honeypots serve, and detects when planted credentials
are replayed against any honeypot protocol.

The planted DB credentials deliberately point at this box's own MySQL
honeypot (via its external port), so an attacker who reads the bait ``.env``
and tries the credentials walks straight into another honeypot.  Seeing the
planted password arrive on any protocol is close to certain proof that this
source read the bait -- those events are flagged ``honeytoken`` and escalated
to critical severity.

Secrets are generated once per install and persisted in ``system_config`` so
every worker and restart serves identical content, while different installs
serve different content (identical bait across the internet would make the
honeypot trivially fingerprintable).
"""

import base64
import json
import logging
import secrets
import threading

from config import Config
from models import SystemConfig, db

logger = logging.getLogger(__name__)

SECRETS_CONFIG_KEY = "deception_secrets"

# Optional canarytokens.org AWS credential pair, planted verbatim in the
# bait .env when configured.  Unlike the locally-generated DB creds, these
# fire (via the canarytokens webhook) even when tried from another machine.
CANARY_AWS_KEY_ID_CONFIG = "canary_aws_access_key_id"
CANARY_AWS_SECRET_CONFIG = "canary_aws_secret_access_key"

# Paths that only an intruder rummaging for secrets would request.
SENSITIVE_PATHS = frozenset({
    "/.env",
    "/config.php",
    "/wp-config.php",
    "/.git/config",
    "/backup",
    "/backup/",
    "/backup/db_backup.sql",
})

_DB_USERNAMES = ("webapp", "appuser", "portal", "www_prod")
_DB_NAMES = ("customer_portal", "webapp_prod", "portal_db", "appdata")

_cache: dict | None = None
_cache_lock = threading.Lock()


def reset_cache() -> None:
    """Forget cached secrets (test isolation)."""
    global _cache
    with _cache_lock:
        _cache = None


def _generate_secrets() -> dict:
    return {
        "db_username": secrets.choice(_DB_USERNAMES),
        "db_password": secrets.token_urlsafe(12),
        "db_name": secrets.choice(_DB_NAMES),
        "app_key": "base64:" + base64.b64encode(secrets.token_bytes(32)).decode(),
    }


def get_secrets() -> dict:
    """Return this install's planted secrets, generating and persisting them
    on first use.  Requires an app context."""
    global _cache
    if _cache is not None:
        return _cache
    with _cache_lock:
        if _cache is not None:
            return _cache
        row = db.session.get(SystemConfig, SECRETS_CONFIG_KEY)
        if row is None:
            row = SystemConfig(
                key=SECRETS_CONFIG_KEY,
                value=json.dumps(_generate_secrets()),
                description="Planted honeytoken credentials served as HTTP bait",
                config_type="json",
            )
            db.session.add(row)
            try:
                db.session.commit()
                logger.info("Deception: generated planted credentials for this install")
            except Exception:
                # Another worker won the race -- use theirs.
                db.session.rollback()
                row = db.session.get(SystemConfig, SECRETS_CONFIG_KEY)
        _cache = json.loads(row.value)
        return _cache


# ---------------------------------------------------------------------------
# Bait content
# ---------------------------------------------------------------------------

def get_canary_aws_creds() -> dict | None:
    """Return configured canarytokens.org AWS creds, or None.

    Env vars (Config) take precedence; the system_config table is a fallback
    so the creds can also be set from the dashboard.  Requires an app context
    only if falling through to the DB.
    """
    key_id = (Config.CANARY_AWS_ACCESS_KEY_ID or "").strip()
    secret_key = (Config.CANARY_AWS_SECRET_ACCESS_KEY or "").strip()
    if not (key_id and secret_key):
        try:
            key_row = db.session.get(SystemConfig, CANARY_AWS_KEY_ID_CONFIG)
            secret_row = db.session.get(SystemConfig, CANARY_AWS_SECRET_CONFIG)
        except Exception:
            return None
        key_id = key_row.value.strip() if key_row and key_row.value else ""
        secret_key = secret_row.value.strip() if secret_row and secret_row.value else ""
    if key_id and secret_key:
        return {"access_key_id": key_id, "secret_access_key": secret_key}
    return None


def _env_file(s: dict, mysql_port: int, canary_aws: dict | None = None) -> str:
    aws_block = ""
    if canary_aws:
        aws_block = f"""
AWS_ACCESS_KEY_ID={canary_aws['access_key_id']}
AWS_SECRET_ACCESS_KEY={canary_aws['secret_access_key']}
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET={s['db_name']}-uploads
"""
    return f"""APP_NAME=CustomerPortal
APP_ENV=production
APP_KEY={s['app_key']}
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT={mysql_port}
DB_DATABASE={s['db_name']}
DB_USERNAME={s['db_username']}
DB_PASSWORD={s['db_password']}

CACHE_DRIVER=file
QUEUE_CONNECTION=sync
SESSION_DRIVER=file
SESSION_LIFETIME=120
{aws_block}"""


def _wp_config(s: dict, mysql_port: int) -> str:
    return f"""<?php
define( 'DB_NAME', '{s['db_name']}' );
define( 'DB_USER', '{s['db_username']}' );
define( 'DB_PASSWORD', '{s['db_password']}' );
define( 'DB_HOST', '127.0.0.1:{mysql_port}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {{
\tdefine( 'ABSPATH', __DIR__ . '/' );
}}

require_once ABSPATH . 'wp-settings.php';
"""


def _git_config(s: dict) -> str:
    return f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = http://gitlab.internal:8080/ops/{s['db_name']}.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""


def _sql_backup(s: dict) -> str:
    return f"""-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
--
-- Host: 127.0.0.1    Database: {s['db_name']}
-- ------------------------------------------------------
-- Server version\t8.0.32-0ubuntu0.22.04.2

CREATE DATABASE IF NOT EXISTS `{s['db_name']}`;
USE `{s['db_name']}`;

-- Application user grant (restore before importing):
-- GRANT ALL PRIVILEGES ON `{s['db_name']}`.* TO '{s['db_username']}'@'%' IDENTIFIED BY '{s['db_password']}';

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `email` varchar(128) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dump truncated. Full backup available on the NAS: \\\\fileserver01\\backups\\
"""


def _index_listing() -> str:
    return """<!DOCTYPE html>
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<hr>
<pre>
<a href="docs/">docs/</a>                  2024-01-15 08:30    -
<a href="images/">images/</a>                2024-01-14 12:00    -
<a href="backup/">backup/</a>                2024-01-10 03:15    -
<a href="config.php">config.php</a>             2024-01-12 09:45    2.1K
<a href=".env">.env</a>                    2024-01-11 14:22    512
</pre>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body>
</html>
"""


def _sub_listing(name: str, entries: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head><title>Index of /{name}</title></head>
<body>
<h1>Index of /{name}</h1>
<hr>
<pre>
<a href="/">Parent Directory</a>                             -
{entries}</pre>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body>
</html>
"""


_ROBOTS_TXT = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"


def build_site_for(app) -> dict:
    """build_site() wrapper for honeypot startup: loads persisted secrets
    under the given app's context, falling back to unpersisted random
    secrets if that fails (pages stay realistic; replay detection just
    won't match until the DB is reachable again)."""
    try:
        if app is not None:
            with app.app_context():
                return build_site()
    except Exception:
        logger.warning(
            "Deception: could not load persisted secrets; serving unpersisted bait",
            exc_info=True,
        )
    return build_site(_generate_secrets())


def build_site(planted: dict | None = None) -> dict:
    """Return {path: (content, content_type)} for every bait GET route.

    ``planted`` defaults to this install's persisted secrets; pass a dict
    explicitly when no app context is available.
    """
    if planted is not None:
        s = planted
        canary_aws = None
    else:
        s = get_secrets()
        canary_aws = get_canary_aws_creds()
    mysql_port = Config.EXTERNAL_PORT.get("mysql", 3306)

    env = _env_file(s, mysql_port, canary_aws)
    wp = _wp_config(s, mysql_port)
    backup_listing = _sub_listing(
        "backup",
        '<a href="/backup/db_backup.sql">db_backup.sql</a>          '
        "2024-01-10 03:15   48K\n",
    )

    html = "text/html"
    plain = "text/plain"
    return {
        "/": (_index_listing(), html),
        "/index.html": (_index_listing(), html),
        "/robots.txt": (_ROBOTS_TXT, plain),
        "/.env": (env, plain),
        # A hardened-but-leaky server returning PHP source as text is a
        # classic misconfiguration; serving identical creds in every file
        # keeps the fiction consistent.
        "/config.php": (wp, plain),
        "/wp-config.php": (wp, plain),
        "/.git/config": (_git_config(s), plain),
        "/backup": (backup_listing, html),
        "/backup/": (backup_listing, html),
        "/backup/db_backup.sql": (_sql_backup(s), plain),
        "/docs/": (_sub_listing("docs", ""), html),
        "/images/": (_sub_listing("images", ""), html),
    }


# ---------------------------------------------------------------------------
# Honeytoken replay detection
# ---------------------------------------------------------------------------

def check_event_for_honeytoken(details: dict | None,
                               raw_payload: str | None = None) -> bool:
    """True if the event carries this install's planted password.

    The password is random per install, so a match can't be a coincidence:
    the source must have read the bait files.  Matching is by password only
    -- usernames like "webapp" are guessable and would false-positive.
    """
    try:
        planted_password = get_secrets().get("db_password")
    except Exception:
        logger.debug("Honeytoken check skipped: secrets unavailable", exc_info=True)
        return False
    if not planted_password:
        return False

    if details:
        if details.get("password") == planted_password:
            return True
        body = details.get("body")
        if isinstance(body, str) and planted_password in body:
            return True
    if raw_payload and planted_password in raw_payload:
        return True
    return False
