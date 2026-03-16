import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from volai.analysis.triage import _parse_report, run_triage
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
