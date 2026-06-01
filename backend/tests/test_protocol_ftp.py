"""Tests for backend/services/protocols/ftp_honeypot.py"""

import os
from unittest.mock import patch

from services.protocols.ftp_honeypot import (
    FTPHoneypot,
    _FAKE_FS,
    _fake_file_content,
    _format_listing,
    _format_nlst,
    _get_node,
    _resolve_path,
)


class TestBanner:
    def test_banner_contains_vsftpd(self):
        assert "vsFTPd" in FTPHoneypot.BANNER

    def test_banner_starts_with_220(self):
        assert FTPHoneypot.BANNER.startswith("220")

    def test_banner_ends_with_crlf(self):
        assert FTPHoneypot.BANNER.endswith("\r\n")


class TestResolvePath:
    def test_absolute_path(self):
        assert _resolve_path("/foo", "/backups") == "/backups"

    def test_relative_path(self):
        assert _resolve_path("/", "backups") == "/backups"

    def test_relative_from_subdir(self):
        assert _resolve_path("/config", "app.conf") == "/config/app.conf"

    def test_dot_returns_cwd(self):
        assert _resolve_path("/backups", ".") == "/backups"

    def test_empty_arg_returns_cwd(self):
        assert _resolve_path("/backups", "") == "/backups"

    def test_dotdot_goes_up(self):
        assert _resolve_path("/backups", "..") == "/"

    def test_dotdot_at_root_stays_root(self):
        assert _resolve_path("/", "..") == "/"

    def test_complex_relative(self):
        assert _resolve_path("/www/upload", "../index.html") == "/www/index.html"

    def test_traversal_clamped_to_root(self):
        result = _resolve_path("/", "../../..")
        assert result == "/"

    def test_trailing_slash_normalized(self):
        result = _resolve_path("/", "backups/")
        assert result == "/backups"


class TestGetNode:
    def test_root_returns_root(self):
        node = _get_node("/")
        assert node is not None
        assert node["type"] == "dir"
        assert "children" in node

    def test_valid_file(self):
        node = _get_node("/readme.txt")
        assert node is not None
        assert node["type"] == "file"
        assert node["size"] == 2048

    def test_valid_directory(self):
        node = _get_node("/backups")
        assert node is not None
        assert node["type"] == "dir"

    def test_nested_file(self):
        node = _get_node("/config/credentials.txt")
        assert node is not None
        assert node["type"] == "file"
        assert node["size"] == 512

    def test_nonexistent_returns_none(self):
        assert _get_node("/does/not/exist") is None

    def test_file_as_dir_returns_none(self):
        assert _get_node("/readme.txt/child") is None

    def test_empty_subdir(self):
        node = _get_node("/www/upload")
        assert node is not None
        assert node["type"] == "dir"
        assert node["children"] == {}


class TestFormatListing:
    def test_root_listing_contains_expected_files(self):
        listing = _format_listing("/")
        assert "backups" in listing
        assert "config" in listing
        assert "readme.txt" in listing
        assert "database.sql" in listing
        assert "www" in listing

    def test_root_listing_has_dir_markers(self):
        listing = _format_listing("/")
        for line in listing.strip().split("\r\n"):
            name = line.split()[-1]
            node = _get_node(f"/{name}")
            if node and node["type"] == "dir":
                assert line.startswith("d")
            elif node and node["type"] == "file":
                assert line.startswith("-")

    def test_subdirectory_listing(self):
        listing = _format_listing("/backups")
        assert "db-2026-05-28.sql.gz" in listing
        assert "db-2026-05-30.sql.gz" in listing
        # Should not contain root-level files
        assert "readme.txt" not in listing

    def test_empty_dir_returns_empty(self):
        listing = _format_listing("/www/upload")
        assert listing == ""

    def test_nonexistent_dir_returns_empty(self):
        listing = _format_listing("/nonexistent")
        assert listing == ""

    def test_file_path_returns_empty(self):
        listing = _format_listing("/readme.txt")
        assert listing == ""


class TestFormatNlst:
    def test_root_nlst(self):
        nlst = _format_nlst("/")
        names = nlst.strip().split("\r\n")
        assert "backups" in names
        assert "config" in names
        assert "readme.txt" in names
        assert "database.sql" in names

    def test_empty_dir_returns_empty(self):
        assert _format_nlst("/www/upload") == ""


class TestFakeFileContent:
    def test_returns_bytes(self):
        content = _fake_file_content("readme.txt", 2048)
        assert isinstance(content, bytes)
        assert len(content) > 0

    def test_sql_file(self):
        content = _fake_file_content("database.sql", 15360)
        assert b"CREATE TABLE" in content

    def test_conf_file(self):
        content = _fake_file_content("app.conf", 1024)
        assert b"[server]" in content

    def test_html_file(self):
        content = _fake_file_content("index.html", 4096)
        assert b"<html>" in content

    def test_credentials_file(self):
        content = _fake_file_content("credentials.txt", 512)
        assert b"admin" in content
        assert b"pass" in content.lower()

    def test_different_extensions_different_content(self):
        sql = _fake_file_content("test.sql", 100)
        conf = _fake_file_content("test.conf", 100)
        assert sql != conf

    def test_gz_file_treated_as_sql(self):
        content = _fake_file_content("backup.sql.gz", 1000)
        assert b"CREATE TABLE" in content


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
        assert hp._pasv_port_min == 40000
        assert hp._pasv_port_max == 40004


class TestPasvAddress:
    def test_config_pasv_address_takes_priority(self):
        hp = FTPHoneypot(port=2121, config={"pasv_address": "1.2.3.4"})
        assert hp._pasv_address == "1.2.3.4"

    @patch.dict(os.environ, {"FTP_PASV_ADDRESS": "5.6.7.8", "PUBLIC_IP": "9.9.9.9"})
    def test_ftp_pasv_env_over_public_ip(self):
        hp = FTPHoneypot(port=2121)
        assert hp._pasv_address == "5.6.7.8"

    @patch.dict(os.environ, {"FTP_PASV_ADDRESS": "", "PUBLIC_IP": "10.20.30.40"}, clear=False)
    def test_public_ip_fallback(self):
        hp = FTPHoneypot(port=2121)
        assert hp._pasv_address == "10.20.30.40"

    @patch.dict(os.environ, {"FTP_PASV_ADDRESS": "", "PUBLIC_IP": ""}, clear=False)
    @patch.object(FTPHoneypot, "_detect_public_ip", return_value="99.88.77.66")
    def test_ipify_fallback(self, mock_detect):
        hp = FTPHoneypot(port=2121)
        assert hp._pasv_address == "99.88.77.66"
        mock_detect.assert_called_once()

    @patch.dict(os.environ, {"FTP_PASV_ADDRESS": "", "PUBLIC_IP": ""}, clear=False)
    @patch.object(FTPHoneypot, "_detect_public_ip", return_value="")
    def test_empty_when_all_fail(self, mock_detect):
        hp = FTPHoneypot(port=2121)
        # Will be empty — PASV handler falls back to socket local address
        assert hp._pasv_address == ""


class TestFakeFilesystem:
    def test_root_has_children(self):
        root = _FAKE_FS["/"]
        assert root["type"] == "dir"
        assert len(root["children"]) > 0

    def test_all_nodes_have_type(self):
        """Every node in the tree has a 'type' field."""
        def check(node):
            assert "type" in node
            if node["type"] == "dir":
                for child in node.get("children", {}).values():
                    check(child)
        check(_FAKE_FS["/"])

    def test_file_nodes_have_size(self):
        """Every file node has a 'size' field."""
        def check(node):
            if node["type"] == "file":
                assert "size" in node
                assert isinstance(node["size"], int)
            elif node["type"] == "dir":
                for child in node.get("children", {}).values():
                    check(child)
        check(_FAKE_FS["/"])
