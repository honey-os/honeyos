"""Tests for backend/services/protocols/ftp_honeypot.py"""

from services.protocols.ftp_honeypot import FTPHoneypot, _DIR_LISTING


class TestBanner:
    def test_banner_contains_vsftpd(self):
        assert "vsFTPd" in FTPHoneypot.BANNER

    def test_banner_starts_with_220(self):
        assert FTPHoneypot.BANNER.startswith("220")

    def test_banner_ends_with_crlf(self):
        assert FTPHoneypot.BANNER.endswith("\r\n")


class TestDirectoryListing:
    def test_contains_files(self):
        assert "backups" in _DIR_LISTING
        assert "config" in _DIR_LISTING
        assert "readme.txt" in _DIR_LISTING
        assert "database.sql" in _DIR_LISTING

    def test_unix_format(self):
        lines = _DIR_LISTING.strip().split("\r\n")
        assert len(lines) == 4
        # Each line should start with permissions
        for line in lines:
            assert line[0] in ("d", "-")


class TestFTPHoneypotInit:
    def test_default_port(self):
        hp = FTPHoneypot(port=2121)
        assert hp.port == 2121

    def test_pasv_port_range(self):
        hp = FTPHoneypot(port=2121, config={"pasv_port_min": 5000, "pasv_port_max": 5010})
        assert hp._pasv_port_min == 5000
        assert hp._pasv_port_max == 5010

    def test_default_pasv_range(self):
        hp = FTPHoneypot(port=2121)
        assert hp._pasv_port_min == 4400
        assert hp._pasv_port_max == 4404
