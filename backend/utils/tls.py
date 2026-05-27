"""Shared TLS certificate utilities for honeypot services."""

import logging
import os
import subprocess
import tempfile

logger = logging.getLogger(__name__)

# Persistent cert directory inside the data volume
CERT_DIR = os.environ.get("HONEYOS_DATA_DIR", "/data")
CERT_FILE = os.path.join(CERT_DIR, "honeyos-selfsigned.pem")
KEY_FILE = os.path.join(CERT_DIR, "honeyos-selfsigned.key")


def ensure_self_signed_cert() -> tuple[str, str]:
    """Generate a self-signed certificate if one doesn't already exist.

    Returns (cert_path, key_path).
    """
    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        return CERT_FILE, KEY_FILE

    # Try the persistent data directory first, fall back to a temp dir
    cert_dir = CERT_DIR
    cert_path = CERT_FILE
    key_path = KEY_FILE
    try:
        os.makedirs(cert_dir, exist_ok=True)
    except OSError:
        cert_dir = tempfile.mkdtemp(prefix="honeyos-certs-")
        cert_path = os.path.join(cert_dir, "honeyos-selfsigned.pem")
        key_path = os.path.join(cert_dir, "honeyos-selfsigned.key")

    logger.info("Generating self-signed TLS certificate")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "3650", "-nodes",
                "-subj", "/CN=localhost",
            ],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.error("Failed to generate TLS cert: %s", exc)
        raise

    return cert_path, key_path
