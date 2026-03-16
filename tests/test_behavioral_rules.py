"""Tests for behavioral detection rules."""

from volai.report.models import PluginOutput
from volai.rules.behavioral import (
    BehavioralRule,
    compute_risk_floor,
    get_all_rules,
    rule_finding_to_finding,
    run_behavioral_rules,
)
from volai.rules.models import RuleFinding


def _po(name, columns, rows):
    return PluginOutput(
        plugin_name=name, columns=columns, rows=rows, row_count=len(rows)
    )


# ---- Helper data builders ----

def _pslist_normal():
    return _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 600, "PPID": 500, "ImageFileName": "services.exe"},
        {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe"},
        {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe"},
    ])


def _pslist_bad_svchost():
    return _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 600, "PPID": 4, "ImageFileName": "services.exe"},
        {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe"},
        {"PID": 999, "PPID": 800, "ImageFileName": "svchost.exe"},  # Bad parent
        {"PID": 800, "PPID": 4, "ImageFileName": "malware.exe"},
    ])


def _pstree_matching():
    return _po("windows.pstree.PsTree", ["PID", "PPID", "ImageFileName"], [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 600, "PPID": 500, "ImageFileName": "services.exe"},
        {"PID": 700, "PPID": 600, "ImageFileName": "svchost.exe"},
        {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe"},
    ])


def _pstree_missing_pid():
    """pstree missing PID 700 that's in pslist."""
    return _po("windows.pstree.PsTree", ["PID", "PPID", "ImageFileName"], [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 600, "PPID": 500, "ImageFileName": "services.exe"},
        {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe"},
    ])


class TestRuleRegistry:
    def test_has_10_rules(self):
        rules = get_all_rules()
        assert len(rules) == 10

    def test_rule_ids_unique(self):
        rules = get_all_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_required_fields(self):
        for rule in get_all_rules():
            assert rule.id.startswith("VOLAI-B")
            assert rule.title
            assert rule.severity in ("critical", "high", "medium", "low")
            assert len(rule.required_plugins) > 0
            assert callable(rule.check)


class TestB001SvchostParent:
    def test_normal_svchost(self):
        plugins = {"windows.pslist.PsList": _pslist_normal()}
        findings = run_behavioral_rules(plugins)
        b001 = [f for f in findings if f.rule_id == "VOLAI-B001"]
        assert len(b001) == 0

    def test_bad_svchost_parent(self):
        plugins = {"windows.pslist.PsList": _pslist_bad_svchost()}
        findings = run_behavioral_rules(plugins)
        b001 = [f for f in findings if f.rule_id == "VOLAI-B001"]
        assert len(b001) == 1
        assert "999" in b001[0].evidence[0]


class TestB002TempProcess:
    def test_no_temp_process(self):
        cmdline = _po("windows.cmdline.CmdLine", ["PID", "Process", "Args"], [
            {"PID": 700, "Process": "svchost.exe", "Args": r"C:\Windows\System32\svchost.exe"},
        ])
        findings = run_behavioral_rules({"windows.cmdline.CmdLine": cmdline})
        b002 = [f for f in findings if f.rule_id == "VOLAI-B002"]
        assert len(b002) == 0

    def test_temp_process(self):
        cmdline = _po("windows.cmdline.CmdLine", ["PID", "Process", "Args"], [
            {"PID": 999, "Process": "evil.exe",
             "Args": r"C:\Users\admin\AppData\Local\Temp\evil.exe"},
        ])
        findings = run_behavioral_rules({"windows.cmdline.CmdLine": cmdline})
        b002 = [f for f in findings if f.rule_id == "VOLAI-B002"]
        assert len(b002) == 1


class TestB003Typosquatting:
    def test_normal_names(self):
        plugins = {"windows.pslist.PsList": _pslist_normal()}
        findings = run_behavioral_rules(plugins)
        b003 = [f for f in findings if f.rule_id == "VOLAI-B003"]
        assert len(b003) == 0

    def test_typosquat_detected(self):
        pslist = _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
            {"PID": 100, "PPID": 4, "ImageFileName": "scvhost.exe"},
        ])
        findings = run_behavioral_rules({"windows.pslist.PsList": pslist})
        b003 = [f for f in findings if f.rule_id == "VOLAI-B003"]
        assert len(b003) == 1
        assert "scvhost" in b003[0].description


class TestB004HiddenProcess:
    def test_matching_lists(self):
        plugins = {
            "windows.pslist.PsList": _pslist_normal(),
            "windows.pstree.PsTree": _pstree_matching(),
        }
        findings = run_behavioral_rules(plugins)
        b004 = [f for f in findings if f.rule_id == "VOLAI-B004"]
        assert len(b004) == 0

    def test_hidden_process_detected(self):
        plugins = {
            "windows.pslist.PsList": _pslist_normal(),
            "windows.pstree.PsTree": _pstree_missing_pid(),
        }
        findings = run_behavioral_rules(plugins)
        b004 = [f for f in findings if f.rule_id == "VOLAI-B004"]
        assert len(b004) == 1
        assert "700" in b004[0].description


class TestB005C2Port:
    def test_normal_port(self):
        netscan = _po("windows.netscan.NetScan",
            ["PID", "ForeignAddr", "ForeignPort", "State"],
            [{"PID": 100, "ForeignAddr": "10.0.0.1", "ForeignPort": 443, "State": "ESTABLISHED"}],
        )
        findings = run_behavioral_rules({"windows.netscan.NetScan": netscan})
        b005 = [f for f in findings if f.rule_id == "VOLAI-B005"]
        assert len(b005) == 0

    def test_c2_port_detected(self):
        netscan = _po("windows.netscan.NetScan",
            ["PID", "ForeignAddr", "ForeignPort", "State"],
            [{"PID": 100, "ForeignAddr": "203.0.113.50", "ForeignPort": 4444, "State": "ESTABLISHED"}],
        )
        findings = run_behavioral_rules({"windows.netscan.NetScan": netscan})
        b005 = [f for f in findings if f.rule_id == "VOLAI-B005"]
        assert len(b005) == 1


class TestB006Malfind:
    def test_malfind_hit(self):
        malfind = _po("windows.malfind.Malfind",
            ["PID", "Process", "Start VPN", "End VPN"],
            [{"PID": 100, "Process": "evil.exe", "Start VPN": "0x1000", "End VPN": "0x2000"}],
        )
        findings = run_behavioral_rules({"windows.malfind.Malfind": malfind})
        b006 = [f for f in findings if f.rule_id == "VOLAI-B006"]
        assert len(b006) == 1

    def test_no_malfind(self):
        malfind = _po("windows.malfind.Malfind", ["PID", "Process"], [])
        findings = run_behavioral_rules({"windows.malfind.Malfind": malfind})
        b006 = [f for f in findings if f.rule_id == "VOLAI-B006"]
        assert len(b006) == 0


class TestB007ShellParent:
    def test_normal_shell_parent(self):
        pslist = _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
            {"PID": 800, "PPID": 700, "ImageFileName": "explorer.exe"},
            {"PID": 900, "PPID": 800, "ImageFileName": "cmd.exe"},
        ])
        findings = run_behavioral_rules({"windows.pslist.PsList": pslist})
        b007 = [f for f in findings if f.rule_id == "VOLAI-B007"]
        assert len(b007) == 0

    def test_unusual_shell_parent(self):
        pslist = _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
            {"PID": 100, "PPID": 4, "ImageFileName": "malware.exe"},
            {"PID": 200, "PPID": 100, "ImageFileName": "powershell.exe"},
        ])
        findings = run_behavioral_rules({"windows.pslist.PsList": pslist})
        b007 = [f for f in findings if f.rule_id == "VOLAI-B007"]
        assert len(b007) == 1
        assert "malware.exe" in b007[0].description


class TestB008KernelModule:
    def test_normal_module(self):
        modules = _po("windows.modules.Modules", ["Name", "FullDllName"], [
            {"Name": "ntoskrnl.exe", "FullDllName": r"\SystemRoot\system32\ntoskrnl.exe"},
        ])
        findings = run_behavioral_rules({"windows.modules.Modules": modules})
        b008 = [f for f in findings if f.rule_id == "VOLAI-B008"]
        assert len(b008) == 0

    def test_unusual_module_path(self):
        modules = _po("windows.modules.Modules", ["Name", "FullDllName"], [
            {"Name": "rootkit.sys", "FullDllName": r"C:\Users\admin\rootkit.sys"},
        ])
        findings = run_behavioral_rules({"windows.modules.Modules": modules})
        b008 = [f for f in findings if f.rule_id == "VOLAI-B008"]
        assert len(b008) == 1


class TestB009DuplicateProcesses:
    def test_no_duplicates(self):
        plugins = {"windows.pslist.PsList": _pslist_normal()}
        findings = run_behavioral_rules(plugins)
        b009 = [f for f in findings if f.rule_id == "VOLAI-B009"]
        assert len(b009) == 0

    def test_duplicates_detected(self):
        pslist = _po("windows.pslist.PsList", ["PID", "PPID", "ImageFileName"], [
            {"PID": 100, "PPID": 4, "ImageFileName": "notepad.exe"},
            {"PID": 200, "PPID": 4, "ImageFileName": "notepad.exe"},
            {"PID": 300, "PPID": 4, "ImageFileName": "notepad.exe"},
        ])
        findings = run_behavioral_rules({"windows.pslist.PsList": pslist})
        b009 = [f for f in findings if f.rule_id == "VOLAI-B009"]
        assert len(b009) == 1


class TestB010ServicePath:
    def test_normal_service(self):
        svcscan = _po("windows.svcscan.SvcScan", ["Name", "Binary"], [
            {"Name": "wuauserv", "Binary": r"C:\Windows\System32\svchost.exe"},
        ])
        findings = run_behavioral_rules({"windows.svcscan.SvcScan": svcscan})
        b010 = [f for f in findings if f.rule_id == "VOLAI-B010"]
        assert len(b010) == 0

    def test_suspicious_service_path(self):
        svcscan = _po("windows.svcscan.SvcScan", ["Name", "Binary"], [
            {"Name": "evilsvc", "Binary": r"C:\Users\admin\AppData\Local\Temp\evil.exe"},
        ])
        findings = run_behavioral_rules({"windows.svcscan.SvcScan": svcscan})
        b010 = [f for f in findings if f.rule_id == "VOLAI-B010"]
        assert len(b010) == 1


class TestEngineEdgeCases:
    def test_missing_required_plugin_skips_rule(self):
        # No plugins at all
        findings = run_behavioral_rules({})
        assert findings == []

    def test_plugin_with_error_skips_rule(self):
        po = PluginOutput(plugin_name="windows.pslist.PsList", error="Failed")
        findings = run_behavioral_rules({"windows.pslist.PsList": po})
        # All rules requiring pslist should be skipped
        assert findings == []

    def test_rule_exception_handled(self):
        def bad_check(plugins):
            raise RuntimeError("Intentional failure")

        bad_rule = BehavioralRule(
            id="VOLAI-TEST", title="Bad rule", description="Fails",
            severity="high", required_plugins=["windows.pslist.PsList"],
            mitre_attack=[], check=bad_check,
        )
        plugins = {"windows.pslist.PsList": _pslist_normal()}
        # Should not raise
        findings = run_behavioral_rules(plugins, rules=[bad_rule])
        assert findings == []


class TestConversions:
    def test_rule_finding_to_finding(self):
        rf = RuleFinding(
            rule_id="VOLAI-B001", title="Test", severity="high",
            description="desc", evidence=["PID 1"], mitre_attack=["T1055"],
        )
        f = rule_finding_to_finding(rf)
        assert f.title == "[VOLAI-B001] Test"
        assert f.severity == "high"
        assert f.mitre_attack == ["T1055"]

    def test_compute_risk_floor_empty(self):
        assert compute_risk_floor([]) == 0

    def test_compute_risk_floor_critical(self):
        rf = RuleFinding(
            rule_id="X", title="X", severity="critical", description="X",
        )
        assert compute_risk_floor([rf]) == 80

    def test_compute_risk_floor_highest_wins(self):
        rfs = [
            RuleFinding(rule_id="X", title="X", severity="low", description="X"),
            RuleFinding(rule_id="Y", title="Y", severity="high", description="Y"),
        ]
        assert compute_risk_floor(rfs) == 60
