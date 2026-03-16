from volai.prompts.system import CHAT_SYSTEM_PROMPT, TRIAGE_SYSTEM_PROMPT
from volai.prompts.templates import build_triage_prompt
from volai.volatility.runner import PluginResult


class TestSystemPrompts:
    def test_triage_prompt_mentions_json(self):
        assert "JSON" in TRIAGE_SYSTEM_PROMPT

    def test_triage_prompt_mentions_findings(self):
        assert "findings" in TRIAGE_SYSTEM_PROMPT

    def test_triage_prompt_mentions_mitre(self):
        assert "MITRE" in TRIAGE_SYSTEM_PROMPT

    def test_chat_prompt_has_plugin_placeholder(self):
        assert "{plugin_list}" in CHAT_SYSTEM_PROMPT

    def test_chat_prompt_can_be_formatted(self):
        result = CHAT_SYSTEM_PROMPT.format(plugin_list="  - windows.pslist.PsList")
        assert "windows.pslist.PsList" in result
        assert "{plugin_list}" not in result


class TestBuildTriagePrompt:
    def test_with_successful_results(self):
        results = [
            PluginResult(
                plugin_name="windows.pslist.PsList",
                columns=["PID", "Name"],
                rows=[
                    {"PID": 4, "Name": "System", "__depth": 0},
                    {"PID": 100, "Name": "svchost.exe", "__depth": 0},
                ],
                row_count=2,
            ),
        ]
        prompt = build_triage_prompt(results, "/tmp/test.dmp")
        assert "Memory dump: /tmp/test.dmp" in prompt
        assert "windows.pslist.PsList" in prompt
        assert "PID | Name" in prompt
        assert "System" in prompt
        assert "svchost.exe" in prompt

    def test_with_error_result(self):
        results = [
            PluginResult(
                plugin_name="windows.malfind.Malfind",
                error="Unsatisfied requirements",
            ),
        ]
        prompt = build_triage_prompt(results, "/tmp/test.dmp")
        assert "windows.malfind.Malfind" in prompt
        assert "ERROR: Unsatisfied requirements" in prompt

    def test_with_empty_result(self):
        results = [
            PluginResult(
                plugin_name="windows.netscan.NetScan",
                columns=["LocalAddr", "RemoteAddr"],
                rows=[],
                row_count=0,
            ),
        ]
        prompt = build_triage_prompt(results, "/tmp/test.dmp")
        assert "No output (0 rows)" in prompt

    def test_truncation_over_200_rows(self):
        rows = [{"PID": i, "Name": f"proc{i}", "__depth": 0} for i in range(250)]
        results = [
            PluginResult(
                plugin_name="windows.pslist.PsList",
                columns=["PID", "Name"],
                rows=rows,
                row_count=250,
            ),
        ]
        prompt = build_triage_prompt(results, "/tmp/test.dmp")
        assert "50 more rows truncated" in prompt
        # Should not contain row 200+
        assert "proc249" not in prompt
        # Should contain row 199 (0-indexed)
        assert "proc199" in prompt

    def test_mixed_results(self):
        results = [
            PluginResult(
                plugin_name="windows.pslist.PsList",
                columns=["PID", "Name"],
                rows=[{"PID": 4, "Name": "System", "__depth": 0}],
                row_count=1,
            ),
            PluginResult(
                plugin_name="windows.malfind.Malfind",
                error="Plugin failed",
            ),
            PluginResult(
                plugin_name="windows.netscan.NetScan",
                columns=["Addr"],
                rows=[],
                row_count=0,
            ),
        ]
        prompt = build_triage_prompt(results, "/tmp/dump.raw")
        assert "System" in prompt
        assert "ERROR: Plugin failed" in prompt
        assert "No output (0 rows)" in prompt
