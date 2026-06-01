"""Tests for backend/services/session_recorder.py"""

import json
from datetime import datetime, timedelta, timezone

from models import Session, db
from services.session_recorder import SessionRecorder
from utils.helpers import generate_id


class TestStartSession:
    def test_creates_session(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            assert session.id is not None
            assert session.source_ip == "10.0.0.1"
            assert session.protocol == "ssh"
            assert session.status == "active"
            assert session.commands_count == 0

    def test_persisted_in_db(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "telnet")
            found = Session.query.get(session.id)
            assert found is not None
            assert found.protocol == "telnet"


class TestEndSession:
    def test_marks_completed_with_commands(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            recorder.record_command(session.id, "ls")
            result = recorder.end_session(session.id)
            assert result is not None
            assert result.status == "completed"
            assert result.end_time is not None
            assert result.duration_seconds is not None
            assert result.duration_seconds >= 0

    def test_deletes_session_with_zero_commands(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            sid = session.id
            result = recorder.end_session(sid)
            assert result is None
            assert Session.query.get(sid) is None

    def test_unknown_session_returns_none(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            result = recorder.end_session("nonexistent-id")
            assert result is None


class TestRecordCommand:
    def test_appends_command(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            assert recorder.record_command(session.id, "whoami") is True
            assert recorder.record_command(session.id, "ls -la") is True

            db.session.refresh(session)
            assert session.commands_count == 2
            cmds = json.loads(session.commands)
            assert len(cmds) == 2
            assert cmds[0]["command"] == "whoami"
            assert cmds[1]["command"] == "ls -la"

    def test_stores_output(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            recorder.record_command(session.id, "id", output="uid=0(root)")

            db.session.refresh(session)
            cmds = json.loads(session.commands)
            assert cmds[0]["output"] == "uid=0(root)"

    def test_unknown_session_returns_false(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            assert recorder.record_command("bad-id", "ls") is False


class TestRecordKeystroke:
    def test_appends_keystroke(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            assert recorder.record_keystroke(session.id, "a") is True
            assert recorder.record_keystroke(session.id, "b") is True

            db.session.refresh(session)
            keystrokes = json.loads(session.keystrokes)
            assert len(keystrokes) == 2
            assert keystrokes[0]["key"] == "a"

    def test_unknown_session_returns_false(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            assert recorder.record_keystroke("bad-id", "x") is False


class TestRecordFileTransfer:
    def test_appends_transfer(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ftp")
            assert recorder.record_file_transfer(
                session.id, "malware.bin", "upload", 1024
            ) is True

            db.session.refresh(session)
            transfers = json.loads(session.file_transfers)
            assert len(transfers) == 1
            assert transfers[0]["filename"] == "malware.bin"
            assert transfers[0]["direction"] == "upload"
            assert transfers[0]["size"] == 1024


class TestGetReplayData:
    def test_returns_none_for_unknown(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            assert recorder.get_replay_data("nonexistent") is None

    def test_returns_replay_structure(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session = recorder.start_session("10.0.0.1", "ssh")
            recorder.record_keystroke(session.id, "l")
            recorder.record_keystroke(session.id, "s")
            recorder.record_command(session.id, "ls", output="Desktop Documents")

            replay = recorder.get_replay_data(session.id)
            assert replay is not None
            assert replay["session_id"] == session.id
            assert replay["source_ip"] == "10.0.0.1"
            assert replay["protocol"] == "ssh"
            assert len(replay["entries"]) == 3
            # Entries should be sorted by timestamp
            types = [e["type"] for e in replay["entries"]]
            assert "keystroke" in types
            assert "command" in types


class TestGetOrStartSession:
    def test_reuses_active_session(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            s1 = recorder.start_session("10.0.0.1", "mysql")
            s2, created = recorder.get_or_start_session("10.0.0.1", "mysql")
            assert s2.id == s1.id
            assert created is False

    def test_creates_new_when_none_exists(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            session, created = recorder.get_or_start_session("10.0.0.1", "ssh")
            assert session is not None
            assert created is True

    def test_ends_stale_session(self, app):
        with app.app_context():
            recorder = SessionRecorder()
            old_session = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="ssh",
                status="active",
                start_time=datetime.now(timezone.utc) - timedelta(seconds=600),
                commands_count=0,
                commands=json.dumps([]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(old_session)
            db.session.commit()

            new_session, created = recorder.get_or_start_session(
                "10.0.0.1", "ssh", max_idle_seconds=300
            )
            assert created is True
            assert new_session.id != old_session.id


class TestReapStaleSessions:
    def test_reaps_old_active_sessions_with_commands(self, app):
        with app.app_context():
            s = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="ssh",
                status="active",
                start_time=datetime.now(timezone.utc) - timedelta(seconds=600),
                commands_count=3,
                commands=json.dumps([{"command": "ls"}]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(s)
            db.session.commit()

            count = SessionRecorder.reap_stale_sessions(max_age_seconds=300)
            assert count == 1
            refreshed = Session.query.get(s.id)
            assert refreshed.status == "completed"

    def test_deletes_old_sessions_with_zero_commands(self, app):
        with app.app_context():
            s = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="mysql",
                status="active",
                start_time=datetime.now(timezone.utc) - timedelta(seconds=600),
                commands_count=0,
                commands=json.dumps([]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(s)
            db.session.commit()
            sid = s.id

            count = SessionRecorder.reap_stale_sessions(max_age_seconds=300)
            assert count == 1
            assert Session.query.get(sid) is None

    def test_does_not_reap_recent_sessions(self, app):
        with app.app_context():
            s = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="ssh",
                status="active",
                start_time=datetime.now(timezone.utc) - timedelta(seconds=60),
                commands_count=1,
                commands=json.dumps([{"command": "ls"}]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(s)
            db.session.commit()

            count = SessionRecorder.reap_stale_sessions(max_age_seconds=300)
            assert count == 0
            assert Session.query.get(s.id).status == "active"
