import json

import pytest
from pydantic import ValidationError

from volai.report.models import Finding, PluginOutput, TriageReport


class TestPluginOutput:
    def test_minimal(self):
        po = PluginOutput(plugin_name="windows.pslist.PsList")
        assert po.plugin_name == "windows.pslist.PsList"
        assert po.columns == []
        assert po.rows == []
        assert po.row_count == 0
        assert po.error is None

    def test_with_data(self):
        po = PluginOutput(
            plugin_name="windows.pslist.PsList",
            columns=["PID", "Name"],
            rows=[{"PID": 4, "Name": "System"}],
            row_count=1,
        )
        assert po.row_count == 1
        assert po.rows[0]["Name"] == "System"

    def test_with_error(self):
        po = PluginOutput(
            plugin_name="windows.malfind.Malfind",
            error="Unsatisfied requirements",
        )
        assert po.error == "Unsatisfied requirements"


class TestFinding:
    def test_minimal(self):
        f = Finding(
            title="Test finding",
            severity="high",
            description="Something bad",
        )
        assert f.title == "Test finding"
        assert f.evidence == []
        assert f.mitre_attack == []

    def test_full(self):
        f = Finding(
            title="Process injection",
            severity="critical",
            description="Malfind detected code injection",
            evidence=["PID 1234", "svchost.exe"],
            mitre_attack=["T1055", "T1055.001"],
        )
        assert len(f.evidence) == 2
        assert "T1055" in f.mitre_attack


class TestTriageReport:
    def test_minimal(self):
        report = TriageReport(
            dump_path="/tmp/test.dmp",
            llm_provider="claude",
            llm_model="claude-sonnet-4-20250514",
            summary="No issues found.",
            risk_score=0,
        )
        assert report.dump_path == "/tmp/test.dmp"
        assert report.findings == []
        assert report.errors == []
        assert report.analysis_timestamp is not None

    def test_risk_score_bounds(self):
        # Valid boundary values
        TriageReport(
            dump_path="x", llm_provider="x", llm_model="x",
            summary="x", risk_score=0,
        )
        TriageReport(
            dump_path="x", llm_provider="x", llm_model="x",
            summary="x", risk_score=100,
        )

    def test_risk_score_too_low(self):
        with pytest.raises(ValidationError):
            TriageReport(
                dump_path="x", llm_provider="x", llm_model="x",
                summary="x", risk_score=-1,
            )

    def test_risk_score_too_high(self):
        with pytest.raises(ValidationError):
            TriageReport(
                dump_path="x", llm_provider="x", llm_model="x",
                summary="x", risk_score=101,
            )

    def test_json_serialization_roundtrip(self):
        report = TriageReport(
            dump_path="/tmp/test.dmp",
            llm_provider="openai",
            llm_model="gpt-4o",
            summary="Test summary",
            risk_score=42,
            findings=[
                Finding(
                    title="Test",
                    severity="low",
                    description="desc",
                    evidence=["PID 1"],
                    mitre_attack=["T1059"],
                )
            ],
            recommendations=["Investigate further"],
        )
        json_str = report.model_dump_json()
        data = json.loads(json_str)
        restored = TriageReport.model_validate(data)
        assert restored.risk_score == 42
        assert restored.findings[0].title == "Test"
        assert restored.recommendations == ["Investigate further"]

    def test_model_validate_from_llm_json(self):
        """Simulate parsing a JSON blob like an LLM would return."""
        llm_json = {
            "summary": "Analysis complete. Suspicious activity detected.",
            "findings": [
                {
                    "title": "Suspicious svchost",
                    "severity": "high",
                    "description": "svchost.exe spawned from unusual parent",
                    "evidence": ["PID 2048", "PPID 1024"],
                    "mitre_attack": ["T1055"],
                }
            ],
            "risk_score": 75,
            "os_detected": "Windows 10 x64",
            "recommendations": ["Memory dump the process", "Check network logs"],
            # These would be injected by our code
            "dump_path": "/evidence/case1.dmp",
            "llm_provider": "claude",
            "llm_model": "claude-sonnet-4-20250514",
        }
        report = TriageReport.model_validate(llm_json)
        assert report.risk_score == 75
        assert report.os_detected == "Windows 10 x64"
        assert len(report.findings) == 1
        assert report.findings[0].severity == "high"
