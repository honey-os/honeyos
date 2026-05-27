"""
SSHHoneypot -- Paramiko-based SSH honeypot that records credentials,
commands, and keystrokes.
"""

import json
import logging
import socket
import threading
from datetime import datetime, timezone

import paramiko

logger = logging.getLogger(__name__)

# Generate a persistent host key once at module load.
_HOST_KEY = paramiko.RSAKey.generate(2048)


class _ServerInterface(paramiko.ServerInterface):
    """Paramiko ServerInterface that accepts any credentials."""

    def __init__(self, event_processor, session_recorder, client_addr, app, port):
        super().__init__()
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.client_addr = client_addr
        self.app = app
        self.port = port
        self.username = ""
        self.password = ""

    # -- auth callbacks ---------------------------------------------------

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        logger.info("SSH auth  user=%s  pass=%s  from=%s", username, password, self.client_addr[0])

        if self.event_processor and self.app:
            with self.app.app_context():
                self.event_processor.process_event({
                    "event_type": "authentication",
                    "protocol": "ssh",
                    "source_ip": self.client_addr[0],
                    "source_port": self.client_addr[1],
                    "destination_port": self.port,
                    "severity": "high",
                    "details": {"username": username, "password": password},
                })

        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


class SSHHoneypot:
    """
    Listens on a TCP port and presents a fake SSH server.

    Each connection gets its own thread with a minimal interactive shell
    that records every keystroke and command.
    """

    FAKE_BANNER = "Ubuntu 22.04 LTS"
    FAKE_HOSTNAME = "server01"

    # Fake command responses
    COMMAND_RESPONSES = {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname -a": "Linux server01 5.15.0-72-generic #79-Ubuntu SMP x86_64 GNU/Linux\n",
        "hostname": "server01\n",
        "pwd": "/root\n",
        "ls": "Desktop  Documents  Downloads\n",
        "ls -la": (
            "total 32\n"
            "drwx------  5 root root 4096 Jan  3 08:12 .\n"
            "drwxr-xr-x 19 root root 4096 Jan  3 08:12 ..\n"
            "-rw-------  1 root root  220 Jan  3 08:12 .bash_logout\n"
            "-rw-------  1 root root 3526 Jan  3 08:12 .bashrc\n"
            "drwxr-xr-x  2 root root 4096 Jan  3 08:12 Desktop\n"
            "drwxr-xr-x  2 root root 4096 Jan  3 08:12 Documents\n"
            "drwxr-xr-x  2 root root 4096 Jan  3 08:12 Downloads\n"
        ),
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        ),
        "ifconfig": (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
        ),
        "uptime": " 08:12:01 up 42 days,  3:17,  1 user,  load average: 0.08, 0.03, 0.01\n",
    }

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Bind and accept connections until stopped."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        try:
            self._server_socket.bind(("0.0.0.0", self.port))
            self._server_socket.listen(5)
            logger.info("SSH honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("SSH honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("SSH accept error")
                break

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        from models import db as _db
        transport = None
        session_id = None
        ctx = self.app.app_context() if self.app else None
        if ctx:
            ctx.push()
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(_HOST_KEY)
            server = _ServerInterface(
                self.event_processor, self.session_recorder, addr, self.app, self.port
            )
            transport.start_server(server=server)

            channel = transport.accept(timeout=20)
            if channel is None:
                return

            # Start a session record
            if self.session_recorder:
                sess = self.session_recorder.start_session(addr[0], "ssh")
                session_id = sess.id

            # Send banner
            channel.send(f"Welcome to {self.FAKE_BANNER}\r\n")
            prompt = f"root@{self.FAKE_HOSTNAME}:~# "
            channel.send(prompt)

            command_buffer = ""
            while transport.is_active():
                try:
                    data = channel.recv(1024)
                except socket.timeout:
                    continue
                if not data:
                    break

                for byte in data:
                    char = chr(byte)

                    # Record keystroke
                    if self.session_recorder and session_id:
                        self.session_recorder.record_keystroke(
                            session_id, char, datetime.now(timezone.utc)
                        )

                    if char in ("\r", "\n"):
                        channel.send("\r\n")
                        cmd = command_buffer.strip()
                        if cmd:
                            self._execute_fake_command(channel, cmd, addr, session_id)
                        command_buffer = ""
                        channel.send(prompt)
                    elif char == "\x7f" or char == "\x08":  # backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send("\x08 \x08")
                    elif char == "\x03":  # Ctrl-C
                        channel.send("^C\r\n")
                        command_buffer = ""
                        channel.send(prompt)
                    elif char == "\x04":  # Ctrl-D / EOF
                        break
                    else:
                        command_buffer += char
                        channel.send(char)

        except Exception:
            logger.exception("SSH handler error for %s", addr)
        finally:
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            if ctx:
                _db.session.remove()
                ctx.pop()

    def _execute_fake_command(self, channel, command: str, addr: tuple, session_id: str | None) -> None:
        """Process a command and send a fake response."""
        logger.info("SSH command from %s: %s", addr[0], command)

        # Record the command
        if self.session_recorder and session_id:
            self.session_recorder.record_command(
                session_id, command, datetime.now(timezone.utc)
            )

        # Log as event
        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "command",
                "protocol": "ssh",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": "medium",
                "session_id": session_id,
                "details": {"command": command},
            })

        if command in ("exit", "quit", "logout"):
            channel.send("logout\r\n")
            channel.close()
            return

        response = self.COMMAND_RESPONSES.get(command)
        if response is None:
            # Try prefix match (e.g., "ls /tmp")
            base_cmd = command.split()[0] if command.split() else command
            if base_cmd in ("cd",):
                response = ""
            elif base_cmd in ("cat", "less", "more"):
                response = f"cat: {command.split()[-1] if len(command.split()) > 1 else ''}: No such file or directory\n"
            elif base_cmd in ("wget", "curl"):
                response = f"bash: {base_cmd}: command not found\n"
            else:
                response = f"bash: {command}: command not found\n"

        channel.send(response.replace("\n", "\r\n"))
