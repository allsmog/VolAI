"""Tests for report diffing."""

from volai.analysis.diff import diff_reports
from volai.report.models import Finding, PluginOutput, TriageReport


def _report(risk_score=50, findings=None, plugin_outputs=None):
    return TriageReport(
        dump_path="/tmp/test.dmp",
        llm_provider="test",
        llm_model="test",
        summary="Test",
        risk_score=risk_score,
        findings=findings or [],
        plugin_outputs=plugin_outputs or [],
    )


def _finding(title="F1", severity="high", description="d", evidence=None, mitre=None):
    return Finding(
        title=title, severity=severity, description=description,
        evidence=evidence or [], mitre_attack=mitre or [],
    )


def _pslist_po(pids):
    return PluginOutput(
        plugin_name="windows.pslist.PsList",
        columns=["PID", "Name"],
        rows=[{"PID": pid, "Name": f"proc_{pid}"} for pid in pids],
        row_count=len(pids),
    )


def _netscan_po(connections):
    return PluginOutput(
        plugin_name="windows.netscan.NetScan",
        columns=["ForeignAddr", "ForeignPort"],
        rows=[{"ForeignAddr": addr, "ForeignPort": port} for addr, port in connections],
        row_count=len(connections),
    )


class TestDiffReports:
    def test_identical_reports(self):
        f = _finding("Injection", "high", "Code injection")
        a = _report(50, [f])
        b = _report(50, [f])
        result = diff_reports(a, b)
        assert result.risk_score_delta == 0
        assert len(result.finding_diffs) == 1
        assert result.finding_diffs[0].status == "unchanged"

    def test_risk_score_delta(self):
        a = _report(30)
        b = _report(70)
        result = diff_reports(a, b)
        assert result.risk_score_delta == 40

    def test_new_finding(self):
        a = _report(30, [])
        b = _report(50, [_finding("New issue")])
        result = diff_reports(a, b)
        new = [d for d in result.finding_diffs if d.status == "new"]
        assert len(new) == 1
        assert new[0].finding_b.title == "New issue"

    def test_resolved_finding(self):
        a = _report(50, [_finding("Old issue")])
        b = _report(30, [])
        result = diff_reports(a, b)
        resolved = [d for d in result.finding_diffs if d.status == "resolved"]
        assert len(resolved) == 1
        assert resolved[0].finding_a.title == "Old issue"

    def test_modified_finding(self):
        fa = _finding("Injection", "high", "version 1", evidence=["PID 100"])
        fb = _finding("Injection", "high", "version 2", evidence=["PID 200"])
        a = _report(50, [fa])
        b = _report(50, [fb])
        result = diff_reports(a, b)
        modified = [d for d in result.finding_diffs if d.status == "modified"]
        assert len(modified) == 1

    def test_process_diffs(self):
        a = _report(50, plugin_outputs=[_pslist_po([4, 100, 200])])
        b = _report(50, plugin_outputs=[_pslist_po([4, 200, 300])])
        result = diff_reports(a, b)
        assert 300 in result.process_diffs["added"]
        assert 100 in result.process_diffs["removed"]
        assert result.process_diffs["common"] == 2

    def test_network_diffs(self):
        a = _report(50, plugin_outputs=[_netscan_po([("10.0.0.1", 443)])])
        b = _report(50, plugin_outputs=[_netscan_po([("10.0.0.1", 443), ("1.2.3.4", 4444)])])
        result = diff_reports(a, b)
        assert "1.2.3.4:4444" in result.network_diffs["added"]
        assert result.network_diffs["common"] == 1

    def test_empty_reports(self):
        a = _report(0)
        b = _report(0)
        result = diff_reports(a, b)
        assert result.risk_score_delta == 0
        assert len(result.finding_diffs) == 0

    def test_summary_contains_delta(self):
        a = _report(20, [_finding("F1")])
        b = _report(80, [_finding("F1"), _finding(title="New")])
        result = diff_reports(a, b)
        assert "+60" in result.summary
        assert "new" in result.summary.lower()

    def test_fuzzy_match_by_evidence(self):
        # Same evidence but different title — should match via Jaccard
        fa = _finding("Issue A", "medium", "d", evidence=["PID 100", "PID 200", "svchost.exe"])
        fb = _finding("Issue B", "high", "d", evidence=["PID 100", "PID 200", "svchost.exe"])
        a = _report(50, [fa])
        b = _report(50, [fb])
        result = diff_reports(a, b)
        # Should be "modified" via fuzzy match, not "resolved" + "new"
        modified = [d for d in result.finding_diffs if d.status == "modified"]
        assert len(modified) == 1
