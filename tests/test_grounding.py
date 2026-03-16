"""Tests for grounding and validation of LLM findings."""

from volai.analysis.grounding import (
    ArtifactIndex,
    MitreValidator,
    annotate_report,
    ground_findings,
)
from volai.report.models import Finding, PluginOutput, TriageReport


def _make_plugin_output(name, columns, rows):
    return PluginOutput(
        plugin_name=name, columns=columns, rows=rows, row_count=len(rows)
    )


def _pslist_output():
    return _make_plugin_output(
        "windows.pslist.PsList",
        ["PID", "PPID", "ImageFileName", "CreateTime"],
        [
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-01"},
            {"PID": 456, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2024-01-01"},
            {"PID": 1234, "PPID": 456, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-01"},
            {"PID": 5678, "PPID": 1234, "ImageFileName": "suspicious.exe", "CreateTime": "2024-01-01"},
        ],
    )


def _netscan_output():
    return _make_plugin_output(
        "windows.netscan.NetScan",
        ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"],
        [
            {"Offset": "0x1000", "Proto": "TCPv4", "LocalAddr": "192.168.1.100",
             "LocalPort": 49152, "ForeignAddr": "10.0.0.1", "ForeignPort": 443,
             "State": "ESTABLISHED", "PID": 1234},
            {"Offset": "0x2000", "Proto": "TCPv4", "LocalAddr": "192.168.1.100",
             "LocalPort": 49153, "ForeignAddr": "203.0.113.50", "ForeignPort": 4444,
             "State": "ESTABLISHED", "PID": 5678},
        ],
    )


def _cmdline_output():
    return _make_plugin_output(
        "windows.cmdline.CmdLine",
        ["PID", "Process", "Args"],
        [
            {"PID": 5678, "Process": "suspicious.exe",
             "Args": r"C:\Users\admin\AppData\Local\Temp\suspicious.exe --payload"},
        ],
    )


class TestArtifactIndex:
    def test_extracts_pids(self):
        idx = ArtifactIndex([_pslist_output()])
        assert 4 in idx.pids
        assert 1234 in idx.pids
        assert 5678 in idx.pids
        assert 9999 not in idx.pids

    def test_extracts_process_names(self):
        idx = ArtifactIndex([_pslist_output()])
        assert "system" in idx.process_names
        assert "svchost.exe" in idx.process_names
        assert "suspicious.exe" in idx.process_names

    def test_extracts_ips(self):
        idx = ArtifactIndex([_netscan_output()])
        assert "192.168.1.100" in idx.ips
        assert "10.0.0.1" in idx.ips
        assert "203.0.113.50" in idx.ips
        assert "1.2.3.4" not in idx.ips

    def test_extracts_file_paths(self):
        idx = ArtifactIndex([_cmdline_output()])
        assert any("temp" in p for p in idx.file_paths)

    def test_contains_pid(self):
        idx = ArtifactIndex([_pslist_output()])
        matched, mtype = idx.contains("PID 1234")
        assert matched is True
        assert mtype == "pid"

    def test_contains_process_name(self):
        idx = ArtifactIndex([_pslist_output()])
        matched, mtype = idx.contains("Process svchost.exe is running")
        assert matched is True
        assert mtype == "process"

    def test_contains_ip(self):
        idx = ArtifactIndex([_netscan_output()])
        matched, mtype = idx.contains("Connection to 203.0.113.50 on port 4444")
        assert matched is True
        assert mtype == "ip"

    def test_contains_no_match(self):
        idx = ArtifactIndex([_pslist_output()])
        matched, mtype = idx.contains("completely fabricated artifact xyz123")
        assert matched is False
        assert mtype == "none"

    def test_empty_plugin_outputs(self):
        idx = ArtifactIndex([])
        assert len(idx.pids) == 0
        assert len(idx.process_names) == 0
        matched, mtype = idx.contains("anything")
        assert matched is False

    def test_contains_token_fallback(self):
        idx = ArtifactIndex([_pslist_output()])
        # "2024-01-01" should be in tokens
        matched, mtype = idx.contains("Created at 2024-01-01")
        assert matched is True
        assert mtype == "token"

    def test_plugin_with_error_skipped(self):
        po = PluginOutput(plugin_name="bad", error="Failed")
        idx = ArtifactIndex([po])
        assert len(idx.pids) == 0


class TestMitreValidator:
    def test_valid_known_id(self):
        assert MitreValidator.validate("T1055") == "valid"

    def test_valid_known_subtechnique(self):
        assert MitreValidator.validate("T1055.001") == "valid"

    def test_valid_format_unknown_id(self):
        assert MitreValidator.validate("T9999") == "valid_format_unknown_id"

    def test_invalid_format_no_prefix(self):
        assert MitreValidator.validate("1055") == "invalid_format"

    def test_invalid_format_wrong_pattern(self):
        assert MitreValidator.validate("TXYZ") == "invalid_format"

    def test_invalid_format_empty(self):
        assert MitreValidator.validate("") == "invalid_format"

    def test_invalid_format_too_many_digits(self):
        assert MitreValidator.validate("T12345") == "invalid_format"

    def test_valid_format_t_prefix(self):
        assert MitreValidator.validate("T1036.005") == "valid"


class TestGroundFindings:
    def test_all_evidence_grounded(self):
        outputs = [_pslist_output(), _netscan_output()]
        findings = [
            Finding(
                title="Suspicious process",
                severity="high",
                description="suspicious.exe communicating with external IP",
                evidence=["PID 5678", "Connection to 203.0.113.50"],
                mitre_attack=["T1055"],
            )
        ]
        results = ground_findings(findings, outputs)
        assert len(results) == 1
        assert results[0].grounded is True
        assert results[0].confidence == 1.0

    def test_no_evidence_grounded(self):
        outputs = [_pslist_output()]
        findings = [
            Finding(
                title="Fabricated",
                severity="high",
                description="Totally made up",
                evidence=["PID 99999", "notreal.exe"],
                mitre_attack=["TXYZ"],
            )
        ]
        results = ground_findings(findings, outputs)
        assert results[0].grounded is False
        assert results[0].confidence == 0.0

    def test_partial_grounding(self):
        outputs = [_pslist_output()]
        findings = [
            Finding(
                title="Mixed",
                severity="medium",
                description="Some real, some fake",
                evidence=["PID 1234", "PID 99999"],
                mitre_attack=["T1055"],
            )
        ]
        results = ground_findings(findings, outputs)
        # 1 grounded ev + 1 valid mitre = 2, total = 3
        assert results[0].confidence == round(2 / 3, 2)
        assert results[0].grounded is True  # 0.67 >= 0.5

    def test_empty_findings(self):
        results = ground_findings([], [_pslist_output()])
        assert results == []

    def test_finding_with_no_evidence_or_mitre(self):
        findings = [
            Finding(
                title="Generic",
                severity="low",
                description="No specifics",
                evidence=[],
                mitre_attack=[],
            )
        ]
        results = ground_findings(findings, [_pslist_output()])
        assert results[0].confidence == 1.0
        assert results[0].grounded is True

    def test_invalid_mitre_lowers_confidence(self):
        outputs = [_pslist_output()]
        findings = [
            Finding(
                title="Bad MITRE",
                severity="medium",
                description="Invalid technique",
                evidence=["PID 1234"],
                mitre_attack=["NOTVALID"],
            )
        ]
        results = ground_findings(findings, outputs)
        # 1 grounded + 0 valid mitre = 1, total = 2
        assert results[0].confidence == 0.5
        assert results[0].grounded is True


class TestAnnotateReport:
    def test_annotates_findings(self):
        report = TriageReport(
            dump_path="/tmp/test.dmp",
            llm_provider="test",
            llm_model="test",
            summary="Test",
            risk_score=50,
            findings=[
                Finding(title="F1", severity="high", description="d1",
                        evidence=["PID 1234"], mitre_attack=["T1055"]),
            ],
            plugin_outputs=[_pslist_output()],
        )
        results = ground_findings(report.findings, report.plugin_outputs)
        annotate_report(report, results)

        assert report.findings[0].grounded is True
        assert report.findings[0].confidence is not None
        assert report.findings[0].grounding_details is not None
        assert report.grounding_summary is not None
        assert report.grounding_summary["total_findings"] == 1
        assert report.grounding_summary["grounded_findings"] == 1

    def test_annotate_empty_report(self):
        report = TriageReport(
            dump_path="/tmp/test.dmp",
            llm_provider="test",
            llm_model="test",
            summary="Clean",
            risk_score=0,
        )
        results = ground_findings(report.findings, report.plugin_outputs)
        annotate_report(report, results)

        assert report.grounding_summary is not None
        assert report.grounding_summary["total_findings"] == 0
        assert report.grounding_summary["grounding_rate"] == 1.0

    def test_grounding_details_structure(self):
        report = TriageReport(
            dump_path="/tmp/test.dmp",
            llm_provider="test",
            llm_model="test",
            summary="Test",
            risk_score=50,
            findings=[
                Finding(title="F1", severity="high", description="d1",
                        evidence=["PID 1234", "fake_thing"],
                        mitre_attack=["T1055", "TXYZ"]),
            ],
            plugin_outputs=[_pslist_output()],
        )
        results = ground_findings(report.findings, report.plugin_outputs)
        annotate_report(report, results)

        details = report.findings[0].grounding_details
        assert len(details["evidence"]) == 2
        assert details["evidence"][0]["grounded"] is True
        assert len(details["mitre"]) == 2
        assert details["mitre"][0]["status"] == "valid"
        assert details["mitre"][1]["status"] == "invalid_format"
