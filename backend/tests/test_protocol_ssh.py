"""Tests for backend/services/protocols/ssh_honeypot.py"""

from unittest.mock import MagicMock

import paramiko

from services.protocols.ssh_honeypot import SSHHoneypot, _ServerInterface


class TestServerInterfaceAuth:
    def _make_interface(self, event_processor=None, app=None):
        return _ServerInterface(
            event_processor=event_processor,
            session_recorder=None,
            client_addr=("10.0.0.1", 12345),
            app=app,
            port=2222,
        )

    def test_check_auth_password_always_succeeds(self):
        iface = self._make_interface()
        result = iface.check_auth_password("root", "password123")
        assert result == paramiko.AUTH_SUCCESSFUL

    def test_stores_credentials(self):
        iface = self._make_interface()
        iface.check_auth_password("admin", "secret")
        assert iface.username == "admin"
        assert iface.password == "secret"

    def test_check_channel_request_session(self):
        iface = self._make_interface()
        assert iface.check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED

    def test_check_channel_request_other(self):
        iface = self._make_interface()
        assert iface.check_channel_request("direct-tcpip", 0) == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def test_check_channel_shell_request(self):
        iface = self._make_interface()
        assert iface.check_channel_shell_request(None) is True

    def test_check_channel_pty_request(self):
        iface = self._make_interface()
        assert iface.check_channel_pty_request(
            None, "xterm", 80, 24, 640, 480, b""
        ) is True

    def test_get_allowed_auths(self):
        iface = self._make_interface()
        assert iface.get_allowed_auths("anything") == "password"

    def test_logs_event_when_processor_and_app(self):
        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock()
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)
        mock_processor = MagicMock()

        iface = self._make_interface(
            event_processor=mock_processor,
            app=mock_app,
        )
        iface.check_auth_password("root", "toor")
        mock_processor.process_event.assert_called_once()
        call_data = mock_processor.process_event.call_args[0][0]
        assert call_data["protocol"] == "ssh"
        assert call_data["details"]["username"] == "root"
        assert call_data["details"]["password"] == "toor"


class TestCommandResponses:
    def test_whoami(self):
        assert SSHHoneypot.COMMAND_RESPONSES["whoami"] == "root\n"

    def test_hostname(self):
        assert SSHHoneypot.COMMAND_RESPONSES["hostname"] == "server01\n"

    def test_id_contains_root(self):
        assert "root" in SSHHoneypot.COMMAND_RESPONSES["id"]

    def test_uname_a(self):
        response = SSHHoneypot.COMMAND_RESPONSES["uname -a"]
        assert "Linux" in response
        assert "server01" in response

    def test_all_responses_end_with_newline(self):
        for cmd, response in SSHHoneypot.COMMAND_RESPONSES.items():
            assert response.endswith("\n"), f"Response for '{cmd}' missing trailing newline"


class TestSSHHoneypotInit:
    def test_port(self):
        hp = SSHHoneypot(port=2222)
        assert hp.port == 2222

    def test_fake_banner(self):
        assert "Ubuntu" in SSHHoneypot.FAKE_BANNER

    def test_fake_hostname(self):
        assert SSHHoneypot.FAKE_HOSTNAME == "server01"
