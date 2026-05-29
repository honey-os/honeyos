"""Shared TLS certificate utilities."""

import logging
import os

logger = logging.getLogger(__name__)

CERT_DIR = os.path.join(os.environ.get("HONEYOS_DATA_DIR", "/data"), "certs")
CERT_FILE = os.path.join(CERT_DIR, "honeyos-selfsigned.pem")
KEY_FILE = os.path.join(CERT_DIR, "honeyos-selfsigned.key")


def ensure_self_signed_cert() -> tuple[str, str]:
    """Generate a self-signed certificate if one doesn't already exist.

    Returns (cert_path, key_path).  Uses the ``cryptography`` library
    (already a transitive dependency via paramiko) so we don't need
    the openssl CLI in the container.
    """
    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        return CERT_FILE, KEY_FILE

    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(CERT_DIR, exist_ok=True)
    logger.info("Generating self-signed TLS certificate in %s", CERT_DIR)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HoneyOS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "HoneyOS"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("honeyos"),
                x509.DNSName("honeyos.local"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    return CERT_FILE, KEY_FILE
