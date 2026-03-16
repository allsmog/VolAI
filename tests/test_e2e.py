"""End-to-end integration tests.

These test the full pipeline: CLI -> VolatilityRunner -> LLM -> JSON report.
Volatility is mocked (we don't need a real memory dump), but the LLM
communication goes through a real HTTP server (fake_llm_server).
"""

import json
import threading
from http.server import HTTPServer
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from click.testing import CliRunner

from volai.cli import cli
from volai.volatility.runner import PluginResult


# --- Fake OpenAI server fixture ---

CANNED_LLM_RESPONSE = {
    "summary": "E2E test: suspicious activity detected in memory dump.",
    "findings": [
        {
            "title": "Suspicious Process",
            "severity": "high",
            "description": "svchost.exe spawned from cmd.exe",
            "evidence": ["PID 2048", "PPID 1024"],
            "mitre_attack": ["T1055"],
        }
    ],
    "risk_score": 72,
    "os_detected": "Windows 10 x64",
    "recommendations": ["Isolate the host"],
}


def _make_handler(response_json):
    """Create a handler class that returns the given JSON."""
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(content_length)  # consume body

            response = {
                "id": "test-123",
                "object": "chat.completion",
                "model": "fake-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(response_json),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 50,
                    "total_tokens": 150,
                },
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

        def log_message(self, format, *args):
            pass  # silence logs

    return Handler


@pytest.fixture
def fake_llm_server():
    """Start a fake OpenAI-compatible server on a random port."""
    handler = _make_handler(CANNED_LLM_RESPONSE)
    server = HTTPServer(("localhost", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{port}/v1"
    server.shutdown()


# --- Realistic mock Volatility data ---

MOCK_PSLIST = PluginResult(
    plugin_name="windows.pslist.PsList",
    columns=["PID", "PPID", "ImageFileName", "CreateTime"],
    rows=[
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-10T08:00:00", "__depth": 0},
        {"PID": 400, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2024-01-10T08:00:01", "__depth": 0},
        {"PID": 500, "PPID": 400, "ImageFileName": "csrss.exe", "CreateTime": "2024-01-10T08:00:02", "__depth": 0},
        {"PID": 600, "PPID": 500, "ImageFileName": "services.exe", "CreateTime": "2024-01-10T08:00:03", "__depth": 0},
        {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-10T08:00:04", "__depth": 0},
        {"PID": 1024, "PPID": 500, "ImageFileName": "cmd.exe", "CreateTime": "2024-01-10T12:30:00", "__depth": 0},
        {"PID": 2048, "PPID": 1024, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-10T12:31:00", "__depth": 0},
    ],
    row_count=7,
)

MOCK_NETSCAN = PluginResult(
    plugin_name="windows.netscan.NetScan",
    columns=["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"],
    rows=[
        {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152, "ForeignAddr": "185.220.101.42", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 2048, "__depth": 0},
        {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 80, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 4, "__depth": 0},
    ],
    row_count=2,
)

MOCK_MALFIND = PluginResult(
    plugin_name="windows.malfind.Malfind",
    columns=["PID", "Process", "StartVPN", "EndVPN", "Protection", "Hexdump", "Disasm"],
    rows=[
        {"PID": 2048, "Process": "svchost.exe", "StartVPN": "0x1a0000", "EndVPN": "0x1a1000", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d5a9000...", "Disasm": "dec ebp; pop edx", "__depth": 0},
    ],
    row_count=1,
)

MOCK_FAILED_PLUGIN = PluginResult(
    plugin_name="windows.handles.Handles",
    error="VolatilityException: Unsatisfied requirement for handles",
)

ALL_MOCK_RESULTS = [MOCK_PSLIST, MOCK_NETSCAN, MOCK_MALFIND, MOCK_FAILED_PLUGIN]


# --- Tests ---

class TestE2EAnalyze:
    """End-to-end tests for the analyze command."""

    @patch("volai.analysis.triage.VolatilityRunner")
    def test_full_pipeline_json_report(self, mock_runner_cls, fake_llm_server, tmp_path):
        """Test the full analyze pipeline: CLI -> mock Vol3 -> real HTTP -> JSON report."""
        # Create a fake dump file
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 1024)

        # Mock the VolatilityRunner to return realistic data
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=ALL_MOCK_RESULTS)

        output_file = tmp_path / "report.json"

        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze", str(dump),
            "--provider", "local",
            "--base-url", fake_llm_server,
            "--model", "fake-model",
            "--plugins", "windows.pslist.PsList,windows.netscan.NetScan,windows.malfind.Malfind,windows.handles.Handles",
            "-o", str(output_file),
        ])

        assert result.exit_code == 0, f"CLI failed: {result.output}\n{result.exception}"
        assert output_file.exists()

        # Parse and validate the report
        report = json.loads(output_file.read_text())

        assert "summary" in report
        assert "findings" in report
        assert "risk_score" in report
        assert 0 <= report["risk_score"] <= 100
        assert report["llm_provider"] == "local"
        assert report["llm_model"] == "fake-model"
        assert report["os_detected"] == "Windows 10 x64"
        assert len(report["findings"]) == 1
        assert report["findings"][0]["severity"] == "high"
        assert "T1055" in report["findings"][0]["mitre_attack"]

        # Plugin outputs should be attached
        assert len(report["plugin_outputs"]) == 4
        plugin_names = [p["plugin_name"] for p in report["plugin_outputs"]]
        assert "windows.pslist.PsList" in plugin_names
        assert "windows.netscan.NetScan" in plugin_names
        assert "windows.malfind.Malfind" in plugin_names

        # Errors for failed plugins
        assert len(report["errors"]) == 1
        assert "handles" in report["errors"][0].lower()

    @patch("volai.analysis.triage.VolatilityRunner")
    def test_stdout_output(self, mock_runner_cls, fake_llm_server, tmp_path):
        """Test that output goes to stdout when no -o flag is given."""
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 1024)

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=[MOCK_PSLIST])

        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze", str(dump),
            "--provider", "local",
            "--base-url", fake_llm_server,
            "--model", "fake-model",
            "--plugins", "windows.pslist.PsList",
        ])

        assert result.exit_code == 0, f"CLI failed: {result.output}\n{result.exception}"

        # stdout should contain valid JSON
        # Find the JSON portion (skip the progress messages)
        lines = result.output.strip().split("\n")
        # Find start of JSON
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("{"):
                json_start = i
                break
        assert json_start is not None, f"No JSON found in output:\n{result.output}"

        json_text = "\n".join(lines[json_start:])
        report = json.loads(json_text)
        assert "summary" in report
        assert "risk_score" in report

    @patch("volai.analysis.triage.VolatilityRunner")
    def test_all_plugins_fail_no_llm_call(self, mock_runner_cls, fake_llm_server, tmp_path):
        """When all plugins fail, we should get a report without calling the LLM."""
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 1024)

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=[
            PluginResult(plugin_name="p1", error="Failed"),
            PluginResult(plugin_name="p2", error="Also failed"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, [
            "analyze", str(dump),
            "--provider", "local",
            "--base-url", fake_llm_server,
            "--model", "fake-model",
            "--plugins", "p1,p2",
        ])

        assert result.exit_code == 0
        # Should still get valid JSON
        lines = result.output.strip().split("\n")
        json_start = next(i for i, line in enumerate(lines) if line.strip().startswith("{"))
        report = json.loads("\n".join(lines[json_start:]))
        assert "All plugins failed" in report["summary"]
        assert len(report["errors"]) == 2


class TestE2EPromptContent:
    """Verify that the LLM actually receives the plugin data."""

    @patch("volai.analysis.triage.VolatilityRunner")
    def test_llm_receives_plugin_output(self, mock_runner_cls, fake_llm_server, tmp_path):
        """Capture what gets sent to the LLM and verify it contains plugin data."""
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 1024)

        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=[MOCK_PSLIST, MOCK_NETSCAN])

        sent_messages = []

        from volai.llm import get_backend as _orig_get_backend

        def capturing_get_backend(*args, **kwargs):
            backend = _orig_get_backend(*args, **kwargs)
            original_send = backend.send

            async def capturing_send(messages, **kw):
                sent_messages.extend(messages)
                return await original_send(messages, **kw)

            backend.send = capturing_send
            return backend

        with patch("volai.analysis.triage.get_backend", side_effect=capturing_get_backend):
            runner = CliRunner()
            result = runner.invoke(cli, [
                "analyze", str(dump),
                "--provider", "local",
                "--base-url", fake_llm_server,
                "--model", "fake-model",
                "--plugins", "windows.pslist.PsList,windows.netscan.NetScan",
            ])

        assert result.exit_code == 0, f"Failed: {result.output}"

        # Check that the LLM received system + user messages
        assert len(sent_messages) == 2
        system_msg = sent_messages[0]
        user_msg = sent_messages[1]

        assert system_msg.role == "system"
        assert "forensics" in system_msg.content.lower()
        assert "JSON" in system_msg.content

        assert user_msg.role == "user"
        assert "windows.pslist.PsList" in user_msg.content
        assert "svchost.exe" in user_msg.content
        assert "185.220.101.42" in user_msg.content
        assert "ESTABLISHED" in user_msg.content
