import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from volai.analysis.triage import _coerce_evidence, _parse_report, _try_repair_json, run_triage
from volai.config import VolAIConfig
from volai.llm.base import LLMResponse
from volai.report.models import TriageReport
from volai.volatility.runner import PluginResult


class TestParseReport:
    def _make_backend(self, name="claude"):
        backend = MagicMock()
        backend.name.return_value = name
        return backend

    def _make_config(self, model="test-model"):
        return VolAIConfig(
            provider="claude", model=model, api_key="x", base_url=None
        )

    def test_valid_json(self):
        llm_json = json.dumps({
            "summary": "Test summary",
            "findings": [],
            "risk_score": 25,
            "os_detected": "Windows 10",
            "recommendations": [],
        })
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert isinstance(report, TriageReport)
        assert report.summary == "Test summary"
        assert report.risk_score == 25
        assert report.os_detected == "Windows 10"
        assert report.llm_provider == "claude"
        assert report.llm_model == "test-model"

    def test_json_with_markdown_fencing(self):
        llm_json = '```json\n{"summary": "Fenced", "findings": [], "risk_score": 10, "recommendations": []}\n```'
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.summary == "Fenced"
        assert report.risk_score == 10

    def test_json_with_plain_fencing(self):
        llm_json = '```\n{"summary": "Plain fence", "findings": [], "risk_score": 5, "recommendations": []}\n```'
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.summary == "Plain fence"

    def test_invalid_json_falls_back(self):
        report = _parse_report(
            "This is not JSON at all, just narrative text.",
            self._make_config(),
            self._make_backend(),
            Path("/tmp/x"),
        )
        assert report.risk_score == 0
        assert "not JSON" in report.summary

    def test_json_with_invalid_risk_score_falls_back(self):
        bad_json = json.dumps({
            "summary": "x",
            "findings": [],
            "risk_score": 999,  # out of bounds
            "recommendations": [],
        })
        report = _parse_report(
            bad_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        # Should fallback gracefully since Pydantic validation will fail
        assert report.risk_score == 0

    def test_json_with_findings(self):
        llm_json = json.dumps({
            "summary": "Bad stuff found",
            "findings": [
                {
                    "title": "Injection",
                    "severity": "critical",
                    "description": "Code injection detected",
                    "evidence": ["PID 1234"],
                    "mitre_attack": ["T1055"],
                }
            ],
            "risk_score": 90,
            "recommendations": ["Isolate host"],
        })
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert len(report.findings) == 1
        assert report.findings[0].title == "Injection"
        assert report.findings[0].severity == "critical"


class TestCoerceEvidence:
    def test_dict_evidence_coerced_to_string(self):
        data = {
            "findings": [
                {
                    "title": "Suspicious process",
                    "evidence": [
                        {"type": "memory_region", "process_name": "svchost.exe"}
                    ],
                }
            ]
        }
        result = _coerce_evidence(data)
        assert result["findings"][0]["evidence"] == [
            "type=memory_region process_name=svchost.exe"
        ]

    def test_string_evidence_unchanged(self):
        data = {
            "findings": [
                {
                    "title": "Clean",
                    "evidence": ["PID 2048", "Normal behavior"],
                }
            ]
        }
        result = _coerce_evidence(data)
        assert result["findings"][0]["evidence"] == ["PID 2048", "Normal behavior"]

    def test_mixed_evidence(self):
        data = {
            "findings": [
                {
                    "title": "Mixed",
                    "evidence": [
                        "PID 1234",
                        {"type": "injection", "target": "explorer.exe"},
                        42,
                    ],
                }
            ]
        }
        result = _coerce_evidence(data)
        ev = result["findings"][0]["evidence"]
        assert ev[0] == "PID 1234"
        assert ev[1] == "type=injection target=explorer.exe"
        assert ev[2] == "42"

    def test_no_findings_key(self):
        data = {"summary": "No findings"}
        result = _coerce_evidence(data)
        assert result == {"summary": "No findings"}

    def test_finding_without_evidence(self):
        data = {"findings": [{"title": "No evidence field"}]}
        result = _coerce_evidence(data)
        assert result["findings"][0] == {"title": "No evidence field"}

    def test_non_dict_finding_skipped(self):
        data = {"findings": ["not a dict", {"title": "Valid", "evidence": ["ok"]}]}
        result = _coerce_evidence(data)
        assert result["findings"][0] == "not a dict"
        assert result["findings"][1]["evidence"] == ["ok"]

    def test_evidence_not_a_list(self):
        data = {"findings": [{"title": "Bad", "evidence": "single string"}]}
        result = _coerce_evidence(data)
        assert result["findings"][0]["evidence"] == "single string"


class TestParseReportEvidenceCoercion:
    def _make_backend(self, name="local"):
        backend = MagicMock()
        backend.name.return_value = name
        return backend

    def _make_config(self, model="test-model"):
        return VolAIConfig(
            provider="local", model=model, api_key=None, base_url=None
        )

    def test_object_evidence_parsed_successfully(self):
        llm_json = json.dumps({
            "summary": "Suspicious activity",
            "findings": [
                {
                    "title": "Injection",
                    "severity": "high",
                    "description": "Code injection detected",
                    "evidence": [
                        {"type": "memory_region", "process_name": "svchost.exe"},
                    ],
                    "mitre_attack": ["T1055"],
                }
            ],
            "risk_score": 75,
            "recommendations": ["Investigate"],
        })
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.risk_score == 75
        assert len(report.findings) == 1
        assert "process_name=svchost.exe" in report.findings[0].evidence[0]


class TestTryRepairJson:
    def test_fix_unescaped_backslashes(self):
        text = r'{"path": "C:\Users\admin\file.exe"}'
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data["path"] == "C:\\Users\\admin\\file.exe"

    def test_preserves_already_escaped_backslashes(self):
        text = r'{"path": "C:\\Users\\admin"}'
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data["path"] == "C:\\Users\\admin"

    def test_fix_trailing_commas(self):
        text = '{"a": 1, "b": 2, }'
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data == {"a": 1, "b": 2}

    def test_fix_trailing_comma_in_array(self):
        text = '{"items": [1, 2, 3, ]}'
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data == {"items": [1, 2, 3]}

    def test_close_unclosed_braces(self):
        text = '{"summary": "truncated", "findings": ['
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data["summary"] == "truncated"

    def test_combined_repairs(self):
        text = r'{"path": "C:\Windows\System32", "items": [1, 2,'
        repaired = _try_repair_json(text)
        data = json.loads(repaired)
        assert data["path"] == "C:\\Windows\\System32"
        assert data["items"] == [1, 2]


class TestParseReportRepair:
    def _make_backend(self, name="local"):
        backend = MagicMock()
        backend.name.return_value = name
        return backend

    def _make_config(self, model="test-model"):
        return VolAIConfig(
            provider="local", model=model, api_key=None, base_url=None
        )

    def test_backslash_json_parses_successfully(self):
        llm_json = r'{"summary": "Found C:\Users\admin\malware.exe", "findings": [], "risk_score": 50, "recommendations": []}'
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.risk_score == 50
        assert "malware.exe" in report.summary

    def test_trailing_comma_json_parses_successfully(self):
        llm_json = '{"summary": "Clean", "findings": [], "risk_score": 5, "recommendations": [], }'
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.summary == "Clean"
        assert report.risk_score == 5

    def test_truncated_json_parses_with_fallback(self):
        llm_json = '{"summary": "Truncated output", "findings": [], "risk_score": 30, "recommendations": ['
        report = _parse_report(
            llm_json, self._make_config(), self._make_backend(), Path("/tmp/x")
        )
        assert report.summary == "Truncated output"
        assert report.risk_score == 30


@pytest.mark.asyncio
class TestRunTriage:
    @patch("volai.analysis.triage.VolatilityRunner")
    @patch("volai.analysis.triage.get_backend")
    async def test_all_plugins_fail(self, mock_get_backend, mock_runner_cls):
        config = VolAIConfig(
            provider="local", model="llama3", api_key=None, base_url=None
        )

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(
            return_value=[
                PluginResult(plugin_name="p1", error="Failed"),
                PluginResult(plugin_name="p2", error="Also failed"),
            ]
        )

        mock_backend = MagicMock()
        mock_backend.name.return_value = "local"
        mock_get_backend.return_value = mock_backend

        report = await run_triage(
            config, Path("/tmp/fake.dmp"), custom_plugins=["p1", "p2"]
        )
        assert "All plugins failed" in report.summary
        assert len(report.errors) == 2
        # LLM should NOT have been called
        mock_backend.send.assert_not_called()

    @patch("volai.analysis.triage.VolatilityRunner")
    @patch("volai.analysis.triage.get_backend")
    async def test_successful_triage(self, mock_get_backend, mock_runner_cls):
        config = VolAIConfig(
            provider="local", model="llama3", api_key=None, base_url=None
        )

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(
            return_value=[
                PluginResult(
                    plugin_name="windows.pslist.PsList",
                    columns=["PID", "Name"],
                    rows=[{"PID": 4, "Name": "System"}],
                    row_count=1,
                ),
            ]
        )

        llm_response = json.dumps({
            "summary": "Clean system",
            "findings": [],
            "risk_score": 5,
            "recommendations": [],
        })
        mock_backend = MagicMock()
        mock_backend.name.return_value = "local"
        mock_backend.send = AsyncMock(
            return_value=LLMResponse(content=llm_response, model="llama3")
        )
        mock_get_backend.return_value = mock_backend

        report = await run_triage(
            config, Path("/tmp/fake.dmp"), custom_plugins=["windows.pslist.PsList"]
        )
        assert report.summary == "Clean system"
        assert report.risk_score == 5
        assert len(report.plugin_outputs) == 1
        assert report.plugin_outputs[0].plugin_name == "windows.pslist.PsList"
        mock_backend.send.assert_called_once()

    @patch("volai.analysis.triage.VolatilityRunner")
    @patch("volai.analysis.triage.get_backend")
    async def test_llm_send_raises_error(self, mock_get_backend, mock_runner_cls):
        config = VolAIConfig(
            provider="local", model="llama3", api_key=None, base_url=None
        )

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(
            return_value=[
                PluginResult(
                    plugin_name="windows.pslist.PsList",
                    columns=["PID", "Name"],
                    rows=[{"PID": 4, "Name": "System"}],
                    row_count=1,
                ),
            ]
        )

        mock_backend = MagicMock()
        mock_backend.name.return_value = "local"
        mock_backend.send = AsyncMock(side_effect=ConnectionError("Connection refused"))
        mock_get_backend.return_value = mock_backend

        report = await run_triage(
            config, Path("/tmp/fake.dmp"), custom_plugins=["windows.pslist.PsList"]
        )
        assert "LLM analysis failed" in report.summary
        assert report.risk_score == 0
        assert any("LLM analysis failed" in e for e in report.errors)
        # Plugin outputs should still be attached
        assert len(report.plugin_outputs) == 1
        assert report.plugin_outputs[0].plugin_name == "windows.pslist.PsList"

    @patch("volai.analysis.triage.VolatilityRunner")
    @patch("volai.analysis.triage.get_backend")
    async def test_mixed_success_and_failure(self, mock_get_backend, mock_runner_cls):
        config = VolAIConfig(
            provider="local", model="llama3", api_key=None, base_url=None
        )

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(
            return_value=[
                PluginResult(
                    plugin_name="windows.pslist.PsList",
                    columns=["PID"],
                    rows=[{"PID": 4}],
                    row_count=1,
                ),
                PluginResult(
                    plugin_name="windows.malfind.Malfind",
                    error="Failed to construct",
                ),
            ]
        )

        llm_response = json.dumps({
            "summary": "Partial analysis",
            "findings": [],
            "risk_score": 10,
            "recommendations": [],
        })
        mock_backend = MagicMock()
        mock_backend.name.return_value = "local"
        mock_backend.send = AsyncMock(
            return_value=LLMResponse(content=llm_response, model="llama3")
        )
        mock_get_backend.return_value = mock_backend

        report = await run_triage(
            config, Path("/tmp/fake.dmp"), custom_plugins=["windows.pslist.PsList", "windows.malfind.Malfind"]
        )
        assert report.summary == "Partial analysis"
        assert len(report.errors) == 1
        assert "malfind" in report.errors[0].lower()
        assert len(report.plugin_outputs) == 2
