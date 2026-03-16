"""
End-to-end demo with real Ollama LLM.
Volatility is mocked (no real memory dump needed), but the LLM call is real.

Run:  python -m tests.demo_ollama
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from click.testing import CliRunner

from volai.cli import cli
from volai.volatility.runner import PluginResult

# Realistic mock Volatility plugin output (simulates a compromised Windows host)
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
            {"PID": 3000, "PPID": 2048, "ImageFileName": "powershell.exe", "CreateTime": "2024-01-10T12:32:00", "__depth": 0},
        ],
        row_count=8,
    ),
    PluginResult(
        plugin_name="windows.netscan.NetScan",
        columns=["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"],
        rows=[
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152, "ForeignAddr": "185.220.101.42", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 2048, "__depth": 0},
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49200, "ForeignAddr": "91.215.85.200", "ForeignPort": 8080, "State": "ESTABLISHED", "PID": 3000, "__depth": 0},
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 80, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 4, "__depth": 0},
        ],
        row_count=3,
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
        plugin_name="windows.cmdline.CmdLine",
        columns=["PID", "Process", "Args"],
        rows=[
            {"PID": 1024, "Process": "cmd.exe", "Args": "cmd.exe /c whoami", "__depth": 0},
            {"PID": 2048, "Process": "svchost.exe", "Args": "svchost.exe -k netsvcs", "__depth": 0},
            {"PID": 3000, "Process": "powershell.exe", "Args": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...", "__depth": 0},
        ],
        row_count=3,
    ),
]

# Create fake dump file
dump = Path("/tmp/volai_ollama_demo.dmp")
dump.write_bytes(b"\x00" * 1024)

print("=" * 70)
print("VolAI E2E Demo — Real Ollama LLM (smollm2:135m)")
print("=" * 70)
print()

with patch("volai.analysis.triage.VolatilityRunner") as mock_cls:
    mock_runner = MagicMock()
    mock_cls.return_value = mock_runner
    mock_runner.run_plugins_async = AsyncMock(return_value=mock_results)

    runner = CliRunner()
    result = runner.invoke(cli, [
        "analyze", str(dump),
        "--provider", "local",
        "--model", "smollm2:135m",
        "--plugins", "windows.pslist.PsList,windows.netscan.NetScan,windows.malfind.Malfind,windows.cmdline.CmdLine",
    ])

    print(result.output)
    if result.exception:
        import traceback
        traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)

dump.unlink()
