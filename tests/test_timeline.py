"""Tests for timeline extraction."""

from volai.analysis.timeline import extract_timeline
from volai.report.models import PluginOutput


def _po(name, columns, rows):
    return PluginOutput(
        plugin_name=name, columns=columns, rows=rows, row_count=len(rows)
    )


class TestExtractTimeline:
    def test_pslist_creates_events(self):
        po = _po("windows.pslist.PsList", ["PID", "ImageFileName", "CreateTime", "ExitTime"], [
            {"PID": 4, "ImageFileName": "System", "CreateTime": "2024-01-01 00:00:00", "ExitTime": "N/A"},
            {"PID": 100, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-01 00:01:00", "ExitTime": "2024-01-01 01:00:00"},
        ])
        tl = extract_timeline([po], "/tmp/test.dmp")
        assert tl.event_count >= 2
        # Should have process_created events
        created = [e for e in tl.events if e.event_type == "process_created"]
        assert len(created) == 2
        # ExitTime N/A should be skipped
        exited = [e for e in tl.events if e.event_type == "process_exited"]
        assert len(exited) == 1

    def test_netscan_creates_events(self):
        po = _po("windows.netscan.NetScan",
            ["PID", "ForeignAddr", "ForeignPort", "Created"],
            [{"PID": 100, "ForeignAddr": "10.0.0.1", "ForeignPort": 443,
              "Created": "2024-01-01 12:00:00"}],
        )
        tl = extract_timeline([po])
        conns = [e for e in tl.events if e.event_type == "network_connection"]
        assert len(conns) == 1

    def test_bash_creates_events(self):
        po = _po("linux.bash.Bash",
            ["PID", "Process", "Timestamp", "Command"],
            [{"PID": 1000, "Process": "bash", "Timestamp": "2024-06-15 10:30:00",
              "Command": "ls -la"}],
        )
        tl = extract_timeline([po])
        bash = [e for e in tl.events if e.event_type == "bash_command"]
        assert len(bash) == 1

    def test_empty_plugin_outputs(self):
        tl = extract_timeline([])
        assert tl.event_count == 0
        assert tl.events == []
        assert tl.earliest is None
        assert tl.latest is None

    def test_plugin_with_error_skipped(self):
        po = PluginOutput(plugin_name="bad", error="Failed")
        tl = extract_timeline([po])
        assert tl.event_count == 0

    def test_events_sorted_by_timestamp(self):
        po = _po("windows.pslist.PsList", ["PID", "ImageFileName", "CreateTime"], [
            {"PID": 1, "ImageFileName": "b.exe", "CreateTime": "2024-01-01 12:00:00"},
            {"PID": 2, "ImageFileName": "a.exe", "CreateTime": "2024-01-01 06:00:00"},
        ])
        tl = extract_timeline([po])
        assert tl.events[0].timestamp < tl.events[1].timestamp

    def test_earliest_and_latest(self):
        po = _po("windows.pslist.PsList", ["PID", "ImageFileName", "CreateTime"], [
            {"PID": 1, "ImageFileName": "a.exe", "CreateTime": "2024-01-01 01:00:00"},
            {"PID": 2, "ImageFileName": "b.exe", "CreateTime": "2024-06-15 23:59:59"},
        ])
        tl = extract_timeline([po])
        assert tl.earliest == "2024-01-01 01:00:00"
        assert tl.latest == "2024-06-15 23:59:59"

    def test_generic_timestamp_column_fallback(self):
        po = _po("custom.plugin", ["ID", "EventTime", "Data"], [
            {"ID": 1, "EventTime": "2024-03-15 08:00:00", "Data": "test"},
        ])
        tl = extract_timeline([po])
        assert tl.event_count == 1
        assert tl.events[0].event_type == "event"

    def test_dump_path_preserved(self):
        tl = extract_timeline([], "/my/dump.dmp")
        assert tl.dump_path == "/my/dump.dmp"

    def test_invalid_timestamp_skipped(self):
        po = _po("windows.pslist.PsList", ["PID", "ImageFileName", "CreateTime"], [
            {"PID": 1, "ImageFileName": "a.exe", "CreateTime": "N/A"},
            {"PID": 2, "ImageFileName": "b.exe", "CreateTime": ""},
            {"PID": 3, "ImageFileName": "c.exe", "CreateTime": None},
            {"PID": 4, "ImageFileName": "d.exe", "CreateTime": "2024-01-01 00:00:00"},
        ])
        tl = extract_timeline([po])
        assert tl.event_count == 1
