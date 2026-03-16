"""
End-to-end demo: shows the full VolAI pipeline with mock Volatility data
hitting a real fake LLM HTTP server.

Run:  python tests/demo_e2e.py
"""

import json
import threading
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from tests.fake_llm_server import FakeOpenAIHandler
from volai.cli import cli
from volai.volatility.runner import PluginResult

# Start fake LLM server
server = HTTPServer(("localhost", 0), FakeOpenAIHandler)
port = server.server_address[1]
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
print(f"Fake LLM server on port {port}\n")

# Create fake dump file
dump = Path("/tmp/volai_demo.dmp")
dump.write_bytes(b"\x00" * 1024)

# Realistic mock Volatility plugin output
mock_results = [
    PluginResult(
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
    ),
    PluginResult(
        plugin_name="windows.netscan.NetScan",
        columns=["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"],
        rows=[
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152, "ForeignAddr": "185.220.101.42", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 2048, "__depth": 0},
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 80, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 4, "__depth": 0},
        ],
        row_count=2,
    ),
    PluginResult(
        plugin_name="windows.malfind.Malfind",
        columns=["PID", "Process", "StartVPN", "EndVPN", "Protection"],
        rows=[
            {"PID": 2048, "Process": "svchost.exe", "StartVPN": "0x1a0000", "EndVPN": "0x1a1000", "Protection": "PAGE_EXECUTE_READWRITE", "__depth": 0},
        ],
        row_count=1,
    ),
    PluginResult(
        plugin_name="windows.handles.Handles",
        error="VolatilityException: Unsatisfied requirement",
    ),
]

# Patch VolatilityRunner to return mock data, then run the real CLI
with patch("volai.analysis.triage.VolatilityRunner") as mock_cls:
    mock_runner = MagicMock()
    mock_cls.return_value = mock_runner
    mock_runner.run_plugins_async = AsyncMock(return_value=mock_results)

    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(cli, [
        "analyze", str(dump),
        "--provider", "local",
        "--base-url", f"http://localhost:{port}/v1",
        "--model", "fake-forensic-model",
        "--plugins", "windows.pslist.PsList,windows.netscan.NetScan,windows.malfind.Malfind,windows.handles.Handles",
    ])

    print(result.output)

# Cleanup
server.shutdown()
dump.unlink()
