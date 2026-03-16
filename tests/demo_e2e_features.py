"""
End-to-end demo exercising ALL new features:
  - Behavioral rules (10 rules)
  - Grounding & validation
  - Storage (session persistence)
  - Timeline extraction
  - Report diffing

Uses a fake OpenAI-compatible HTTP server (fast) + mock Volatility data.
Run:  python -m tests.demo_e2e_features
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from click.testing import CliRunner

from volai.cli import cli
from volai.volatility.runner import PluginResult

# --- Fake LLM that returns a forensic report ---

CANNED_RESPONSE = {
    "summary": "Significant compromise detected. svchost.exe (PID 2048) spawned "
               "from cmd.exe with suspicious parent chain. Malfind detected code "
               "injection. C2 connection to 91.215.85.200:4444 via powershell.exe.",
    "findings": [
        {
            "title": "Code Injection in svchost.exe",
            "severity": "critical",
            "description": "Malfind detected PAGE_EXECUTE_READWRITE memory in PID 2048",
            "evidence": ["PID 2048", "svchost.exe", "PAGE_EXECUTE_READWRITE"],
            "mitre_attack": ["T1055", "T1055.001"],
        },
        {
            "title": "Suspicious Parent Chain",
            "severity": "high",
            "description": "svchost.exe spawned by cmd.exe instead of services.exe",
            "evidence": ["PID 2048", "PPID 1024", "cmd.exe"],
            "mitre_attack": ["T1036.005"],
        },
        {
            "title": "C2 Communication on Port 4444",
            "severity": "high",
            "description": "powershell.exe connected to 91.215.85.200:4444",
            "evidence": ["PID 3000", "91.215.85.200:4444"],
            "mitre_attack": ["T1571"],
        },
        {
            "title": "Fabricated Finding",
            "severity": "medium",
            "description": "This finding has fake evidence the LLM hallucinated",
            "evidence": ["PID 99999", "totally_fake_process.exe"],
            "mitre_attack": ["TXYZ", "T1055"],
        },
    ],
    "risk_score": 85,
    "os_detected": "Windows 10 x64",
    "recommendations": [
        "Isolate the host immediately",
        "Collect disk image for further analysis",
        "Block 91.215.85.200 at the firewall",
    ],
}


class FakeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        response = {
            "id": "test",
            "object": "chat.completion",
            "model": "fake",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": json.dumps(CANNED_RESPONSE)},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass


# --- Mock Volatility data (compromised host) ---

MOCK_RESULTS = [
    PluginResult(
        plugin_name="windows.pslist.PsList",
        columns=["PID", "PPID", "ImageFileName", "CreateTime"],
        rows=[
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-10T08:00:00"},
            {"PID": 400, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2024-01-10T08:00:01"},
            {"PID": 500, "PPID": 400, "ImageFileName": "csrss.exe", "CreateTime": "2024-01-10T08:00:02"},
            {"PID": 600, "PPID": 500, "ImageFileName": "services.exe", "CreateTime": "2024-01-10T08:00:03"},
            {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-10T08:00:04"},
            {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe", "CreateTime": "2024-01-10T08:01:00"},
            {"PID": 1024, "PPID": 500, "ImageFileName": "cmd.exe", "CreateTime": "2024-01-10T12:30:00"},
            {"PID": 2048, "PPID": 1024, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-10T12:31:00"},
            {"PID": 3000, "PPID": 2048, "ImageFileName": "powershell.exe", "CreateTime": "2024-01-10T12:32:00"},
        ],
        row_count=9,
    ),
    PluginResult(
        plugin_name="windows.pstree.PsTree",
        columns=["PID", "PPID", "ImageFileName"],
        rows=[
            {"PID": 4, "PPID": 0, "ImageFileName": "System"},
            {"PID": 400, "PPID": 4, "ImageFileName": "smss.exe"},
            {"PID": 500, "PPID": 400, "ImageFileName": "csrss.exe"},
            {"PID": 600, "PPID": 500, "ImageFileName": "services.exe"},
            {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe"},
            {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe"},
            {"PID": 1024, "PPID": 500, "ImageFileName": "cmd.exe"},
            {"PID": 2048, "PPID": 1024, "ImageFileName": "svchost.exe"},
            {"PID": 3000, "PPID": 2048, "ImageFileName": "powershell.exe"},
        ],
        row_count=9,
    ),
    PluginResult(
        plugin_name="windows.netscan.NetScan",
        columns=["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID"],
        rows=[
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49152,
             "ForeignAddr": "185.220.101.42", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 2048},
            {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49200,
             "ForeignAddr": "91.215.85.200", "ForeignPort": 4444, "State": "ESTABLISHED", "PID": 3000},
        ],
        row_count=2,
    ),
    PluginResult(
        plugin_name="windows.malfind.Malfind",
        columns=["PID", "Process", "StartVPN", "EndVPN", "Protection"],
        rows=[
            {"PID": 2048, "Process": "svchost.exe", "StartVPN": "0x1a0000",
             "EndVPN": "0x1a1000", "Protection": "PAGE_EXECUTE_READWRITE"},
        ],
        row_count=1,
    ),
    PluginResult(
        plugin_name="windows.cmdline.CmdLine",
        columns=["PID", "Process", "Args"],
        rows=[
            {"PID": 1024, "Process": "cmd.exe", "Args": "cmd.exe /c whoami"},
            {"PID": 2048, "Process": "svchost.exe", "Args": "svchost.exe -k netsvcs"},
            {"PID": 3000, "Process": "powershell.exe",
             "Args": r"C:\Users\admin\AppData\Local\Temp\payload.ps1"},
        ],
        row_count=3,
    ),
]


def section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def main():
    # Start fake server
    server = HTTPServer(("localhost", 0), FakeHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    dump = Path("/tmp/volai_e2e_demo.dmp")
    dump.write_bytes(b"\x00" * 1024)
    db_path = "/tmp/volai_e2e_test.db"

    runner = CliRunner()
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  PASS: {name}")
            passed += 1
        else:
            print(f"  FAIL: {name}")
            failed += 1

    # =========================================================================
    section("1. ANALYZE — Full pipeline with rules + grounding + storage")
    # =========================================================================

    import os
    os.environ["VOLAI_DB_PATH"] = db_path

    with patch("volai.analysis.triage.VolatilityRunner") as mock_cls:
        mock_runner = MagicMock()
        mock_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=MOCK_RESULTS)

        result = runner.invoke(cli, [
            "analyze", str(dump),
            "--provider", "local",
            "--base-url", f"http://localhost:{port}/v1",
            "--model", "fake-model",
            "--plugins", ",".join(r.plugin_name for r in MOCK_RESULTS),
            "-o", "/tmp/volai_e2e_report1.json",
        ])

    check("CLI exits 0", result.exit_code == 0)
    if result.exit_code != 0:
        print(f"  Output: {result.output}")
        if result.exception:
            import traceback
            traceback.print_exception(type(result.exception), result.exception, result.exception.__traceback__)

    report = json.loads(Path("/tmp/volai_e2e_report1.json").read_text())

    check("Has summary", len(report.get("summary", "")) > 20)
    check("Risk score present", 0 <= report.get("risk_score", -1) <= 100)
    check("OS detected", report.get("os_detected") == "Windows 10 x64")

    # --- Grounding ---
    section("2. GROUNDING — Evidence validated against plugin data")
    findings = report.get("findings", [])
    check("Has findings", len(findings) >= 1)
    check("Grounding summary present", report.get("grounding_summary") is not None)

    gs = report.get("grounding_summary", {})
    print(f"  Grounding rate: {gs.get('grounding_rate', 'N/A')}")
    print(f"  Grounded: {gs.get('grounded_findings')}/{gs.get('total_findings')}")

    grounded_findings = [f for f in findings if f.get("grounded") is True]
    ungrounded = [f for f in findings if f.get("grounded") is False]
    check("Some findings grounded", len(grounded_findings) >= 1)
    check("Fabricated finding NOT grounded", any(
        "Fabricated" in f.get("title", "") and f.get("grounded") is False
        for f in findings
    ))

    for f in findings:
        status = "GROUNDED" if f.get("grounded") else "UNGROUNDED"
        print(f"  [{status}] {f['title']} (confidence={f.get('confidence')})")
        if f.get("grounding_details"):
            for ev in f["grounding_details"].get("evidence", []):
                mark = "ok" if ev["grounded"] else "XX"
                print(f"    [{mark}] {ev['value'][:50]} ({ev['match_type']})")
            for m in f["grounding_details"].get("mitre", []):
                print(f"    MITRE {m['id']}: {m['status']}")

    # --- Behavioral Rules ---
    section("3. BEHAVIORAL RULES — Deterministic findings")
    rule_findings = report.get("rule_findings", [])
    print(f"  Rule findings count: {len(rule_findings)}")
    check("Has rule findings", len(rule_findings) >= 1)

    expected_rules = {"VOLAI-B001", "VOLAI-B005", "VOLAI-B006", "VOLAI-B007"}
    found_rules = set()
    for rf in rule_findings:
        # Extract rule ID from title "[VOLAI-B001] ..."
        rid = rf["title"].split("]")[0].lstrip("[")
        found_rules.add(rid)
        print(f"  {rf['title']} ({rf['severity']})")
        if rf.get("evidence"):
            print(f"    Evidence: {rf['evidence'][:3]}")

    check("B001 (bad svchost parent) fired", "VOLAI-B001" in found_rules)
    check("B005 (C2 port) fired", "VOLAI-B005" in found_rules)
    check("B006 (malfind) fired", "VOLAI-B006" in found_rules)
    check("B007 (unusual shell parent) fired", "VOLAI-B007" in found_rules)

    # Risk floor: malfind is high -> floor 60, B001 also high -> 60
    check("Risk score >= 60 (rule floor)", report.get("risk_score", 0) >= 60)

    # --- Storage ---
    section("4. STORAGE — Session persisted to SQLite")

    from volai.storage.store import SessionStore
    store = SessionStore(db_path)
    sessions = store.list_sessions()
    check("Session saved", len(sessions) >= 1)

    if sessions:
        sid = sessions[0]["id"]
        print(f"  Session ID: {sid}")
        print(f"  Type: {sessions[0]['session_type']}")
        print(f"  Provider: {sessions[0]['provider']}")

        saved_report = store.get_triage_report(sid)
        check("Report retrievable", saved_report is not None)
        if saved_report:
            check("Saved risk_score matches", saved_report.risk_score == report["risk_score"])

        outputs = store.get_plugin_outputs(sid)
        check("Plugin outputs saved", len(outputs) >= 1)
        print(f"  Plugin outputs: {[o.plugin_name for o in outputs]}")

        # Export
        export = store.export_session(sid)
        check("Export works", export is not None and "session" in export)

    # --- Timeline ---
    section("5. TIMELINE — Temporal event extraction")

    from volai.analysis.timeline import extract_timeline
    from volai.report.models import PluginOutput
    plugin_outputs = [
        PluginOutput(
            plugin_name=r.plugin_name, columns=r.columns,
            rows=r.rows, row_count=r.row_count, error=r.error,
        ) for r in MOCK_RESULTS
    ]
    tl = extract_timeline(plugin_outputs, str(dump))
    print(f"  Events: {tl.event_count}")
    print(f"  Earliest: {tl.earliest}")
    print(f"  Latest: {tl.latest}")
    check("Timeline has events", tl.event_count > 0)
    check("Events sorted", all(
        tl.events[i].timestamp <= tl.events[i+1].timestamp
        for i in range(len(tl.events)-1)
    ))
    for ev in tl.events[:5]:
        print(f"  [{ev.timestamp}] {ev.event_type}: {ev.description}")
    if tl.event_count > 5:
        print(f"  ... and {tl.event_count - 5} more")

    # --- Diff ---
    section("6. DIFF — Report comparison")

    # Run a second analysis with slightly different mock data
    MOCK_RESULTS_2 = list(MOCK_RESULTS)
    # Add a new process
    MOCK_RESULTS_2[0] = PluginResult(
        plugin_name="windows.pslist.PsList",
        columns=["PID", "PPID", "ImageFileName", "CreateTime"],
        rows=MOCK_RESULTS[0].rows + [
            {"PID": 4000, "PPID": 800, "ImageFileName": "malware2.exe",
             "CreateTime": "2024-01-10T13:00:00"},
        ],
        row_count=MOCK_RESULTS[0].row_count + 1,
    )

    with patch("volai.analysis.triage.VolatilityRunner") as mock_cls:
        mock_runner = MagicMock()
        mock_cls.return_value = mock_runner
        mock_runner.run_plugins_async = AsyncMock(return_value=MOCK_RESULTS_2)

        result2 = runner.invoke(cli, [
            "analyze", str(dump),
            "--provider", "local",
            "--base-url", f"http://localhost:{port}/v1",
            "--model", "fake-model",
            "--plugins", ",".join(r.plugin_name for r in MOCK_RESULTS),
            "-o", "/tmp/volai_e2e_report2.json",
        ])

    check("Second analysis exits 0", result2.exit_code == 0)

    sessions2 = store.list_sessions()
    check("Two sessions saved", len(sessions2) >= 2)

    if len(sessions2) >= 2:
        sid_a = sessions2[1]["id"]  # older
        sid_b = sessions2[0]["id"]  # newer

        from volai.analysis.diff import diff_reports
        report_a = store.get_triage_report(sid_a)
        report_b = store.get_triage_report(sid_b)

        if report_a and report_b:
            diff = diff_reports(report_a, report_b, sid_a, sid_b)
            print(f"  {diff.summary}")
            print(f"  Finding diffs: {len(diff.finding_diffs)}")
            for d in diff.finding_diffs:
                title = (d.finding_a or d.finding_b).title
                print(f"    [{d.status.upper()}] {title}")
            check("Diff has finding diffs", len(diff.finding_diffs) >= 1)
            check("Process diffs detected", diff.process_diffs.get("added") is not None)
            if diff.process_diffs.get("added"):
                print(f"  New PIDs: {diff.process_diffs['added']}")
                check("PID 4000 is new", 4000 in diff.process_diffs["added"])

    # --- Sessions CLI ---
    section("7. CLI COMMANDS — sessions list/show/export")

    result_list = runner.invoke(cli, ["sessions", "list"])
    check("sessions list works", result_list.exit_code == 0)
    print(f"  {result_list.output.strip()}")

    if sessions:
        result_show = runner.invoke(cli, ["sessions", "show", sessions[0]["id"]])
        check("sessions show works", result_show.exit_code == 0)

    # =========================================================================
    section("SUMMARY")
    # =========================================================================
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total:  {passed + failed}")
    print()

    if failed == 0:
        print("  ALL E2E CHECKS PASSED!")
    else:
        print(f"  {failed} CHECK(S) FAILED")

    # Cleanup
    server.shutdown()
    dump.unlink(missing_ok=True)
    Path("/tmp/volai_e2e_report1.json").unlink(missing_ok=True)
    Path("/tmp/volai_e2e_report2.json").unlink(missing_ok=True)
    Path(db_path).unlink(missing_ok=True)
    store.close()


if __name__ == "__main__":
    main()
