"""Tests for backend/services/honeypot_manager.py"""

from services.honeypot_manager import HoneypotManager


class TestResolveClass:
    """Test _resolve_class() returns the correct class for all 10 protocols."""

    def test_ssh(self):
        cls = HoneypotManager._resolve_class("ssh")
        assert cls is not None
        assert cls.__name__ == "SSHHoneypot"

    def test_http(self):
        cls = HoneypotManager._resolve_class("http")
        assert cls is not None
        assert cls.__name__ == "HTTPHoneypot"

    def test_https(self):
        cls = HoneypotManager._resolve_class("https")
        assert cls is not None
        assert cls.__name__ == "HTTPSHoneypot"

    def test_telnet(self):
        cls = HoneypotManager._resolve_class("telnet")
        assert cls is not None
        assert cls.__name__ == "TelnetHoneypot"

    def test_ftp(self):
        cls = HoneypotManager._resolve_class("ftp")
        assert cls is not None
        assert cls.__name__ == "FTPHoneypot"

    def test_mysql(self):
        cls = HoneypotManager._resolve_class("mysql")
        assert cls is not None
        assert cls.__name__ == "MySQLHoneypot"

    def test_postgresql(self):
        cls = HoneypotManager._resolve_class("postgresql")
        assert cls is not None
        assert cls.__name__ == "PostgreSQLHoneypot"

    def test_dns(self):
        cls = HoneypotManager._resolve_class("dns")
        assert cls is not None
        assert cls.__name__ == "DNSHoneypot"

    def test_smb(self):
        cls = HoneypotManager._resolve_class("smb")
        assert cls is not None
        assert cls.__name__ == "SMBHoneypot"

    def test_rdp(self):
        cls = HoneypotManager._resolve_class("rdp")
        assert cls is not None
        assert cls.__name__ == "RDPHoneypot"

    def test_unknown_returns_none(self):
        assert HoneypotManager._resolve_class("unknown_protocol") is None

    def test_empty_string_returns_none(self):
        assert HoneypotManager._resolve_class("") is None
