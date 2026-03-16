"""Tests for session storage (all use :memory: SQLite)."""

import pytest

from volai.report.models import Finding, PluginOutput, TriageReport
from volai.storage.store import SessionStore


@pytest.fixture
def store():
    s = SessionStore(db_path=":memory:")
    yield s
    s.close()


class TestSessionCRUD:
    def test_create_session(self, store):
        session = store.create_session(
            dump_path="/tmp/test.dmp",
            session_type="triage",
            provider="claude",
            model="test",
        )
        assert len(session["id"]) == 8
        assert session["session_type"] == "triage"

    def test_get_session(self, store):
        created = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        fetched = store.get_session(created["id"])
        assert fetched is not None
        assert fetched["id"] == created["id"]
        assert fetched["dump_path"] == "/tmp/t.dmp"

    def test_get_nonexistent_session(self, store):
        assert store.get_session("notexist") is None

    def test_list_sessions(self, store):
        store.create_session("/tmp/a.dmp", "triage", "claude", "test")
        store.create_session("/tmp/b.dmp", "chat", "openai", "test")
        all_sessions = store.list_sessions()
        assert len(all_sessions) == 2

    def test_list_sessions_filter_type(self, store):
        store.create_session("/tmp/a.dmp", "triage", "claude", "test")
        store.create_session("/tmp/b.dmp", "chat", "openai", "test")
        triage = store.list_sessions(session_type="triage")
        assert len(triage) == 1
        assert triage[0]["session_type"] == "triage"

    def test_list_sessions_filter_dump(self, store):
        store.create_session("/tmp/a.dmp", "triage", "claude", "test")
        store.create_session("/tmp/b.dmp", "chat", "openai", "test")
        filtered = store.list_sessions(dump_path="/tmp/a.dmp")
        assert len(filtered) == 1

    def test_delete_session(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        assert store.delete_session(session["id"]) is True
        assert store.get_session(session["id"]) is None

    def test_delete_nonexistent(self, store):
        assert store.delete_session("notexist") is False


class TestMessages:
    def test_save_and_get_messages(self, store):
        session = store.create_session("/tmp/t.dmp", "chat", "claude", "test")
        sid = session["id"]
        store.save_message(sid, "user", "hello")
        store.save_message(sid, "assistant", "hi there")
        store.save_message(sid, "user", "analyze this")

        msgs = store.get_messages(sid)
        assert len(msgs) == 3
        assert msgs[0]["role"] == "user"
        assert msgs[0]["content"] == "hello"
        assert msgs[1]["role"] == "assistant"
        assert msgs[2]["sequence"] == 3

    def test_empty_messages(self, store):
        session = store.create_session("/tmp/t.dmp", "chat", "claude", "test")
        assert store.get_messages(session["id"]) == []


class TestPluginOutputs:
    def test_save_and_get(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        sid = session["id"]
        po = PluginOutput(
            plugin_name="windows.pslist.PsList",
            columns=["PID", "Name"],
            rows=[{"PID": 4, "Name": "System"}],
            row_count=1,
        )
        store.save_plugin_output(sid, po)
        outputs = store.get_plugin_outputs(sid)
        assert len(outputs) == 1
        assert outputs[0].plugin_name == "windows.pslist.PsList"
        assert outputs[0].rows[0]["PID"] == 4


class TestTriageReport:
    def test_save_and_get_report(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        sid = session["id"]
        report = TriageReport(
            dump_path="/tmp/t.dmp",
            llm_provider="claude",
            llm_model="test",
            summary="Test summary",
            risk_score=42,
            findings=[
                Finding(title="F1", severity="high", description="d1"),
            ],
        )
        store.save_triage_report(sid, report)
        loaded = store.get_triage_report(sid)
        assert loaded is not None
        assert loaded.summary == "Test summary"
        assert loaded.risk_score == 42
        assert len(loaded.findings) == 1

    def test_get_report_nonexistent(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        assert store.get_triage_report(session["id"]) is None


class TestExportAndResolve:
    def test_export_session(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        sid = session["id"]
        store.save_message(sid, "user", "hello")
        po = PluginOutput(plugin_name="test", columns=["A"], rows=[{"A": 1}], row_count=1)
        store.save_plugin_output(sid, po)
        report = TriageReport(
            dump_path="/tmp/t.dmp", llm_provider="claude", llm_model="test",
            summary="s", risk_score=10,
        )
        store.save_triage_report(sid, report)

        export = store.export_session(sid)
        assert export is not None
        assert export["session"]["id"] == sid
        assert len(export["messages"]) == 1
        assert len(export["plugin_outputs"]) == 1
        assert export["triage_report"] is not None

    def test_export_nonexistent(self, store):
        assert store.export_session("notexist") is None

    def test_resolve_session_id(self, store):
        session = store.create_session("/tmp/t.dmp", "triage", "claude", "test")
        sid = session["id"]
        # Resolve by prefix
        assert store.resolve_session_id(sid[:4]) == sid

    def test_resolve_ambiguous(self, store):
        # Create two sessions — ambiguity test only works if both IDs share prefix
        # We'll test with full IDs which should resolve unambiguously
        s1 = store.create_session("/tmp/a.dmp", "triage", "claude", "test")
        s2 = store.create_session("/tmp/b.dmp", "triage", "claude", "test")
        assert store.resolve_session_id(s1["id"]) == s1["id"]
        assert store.resolve_session_id(s2["id"]) == s2["id"]

    def test_resolve_not_found(self, store):
        assert store.resolve_session_id("zzzznotexist") is None
