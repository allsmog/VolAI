"""Behavioral detection rule engine with 10 bundled Windows-focused rules."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from volai.report.models import Finding, PluginOutput
from volai.rules.models import RuleFinding

logger = logging.getLogger(__name__)

PluginDict = dict[str, PluginOutput]
RuleCheck = Callable[[PluginDict], list[RuleFinding]]


@dataclass
class BehavioralRule:
    id: str
    title: str
    description: str
    severity: str
    required_plugins: list[str]
    mitre_attack: list[str]
    check: RuleCheck


_REGISTRY: list[BehavioralRule] = []


def register(rule: BehavioralRule) -> BehavioralRule:
    """Register a behavioral rule."""
    _REGISTRY.append(rule)
    return rule


def get_all_rules() -> list[BehavioralRule]:
    """Return all registered rules."""
    return list(_REGISTRY)


def run_behavioral_rules(
    plugin_results: PluginDict,
    rules: list[BehavioralRule] | None = None,
) -> list[RuleFinding]:
    """Run behavioral rules against collected plugin output.

    Skips rules whose required plugins are missing or have no rows.
    Catches exceptions per rule and logs warnings.
    """
    rules = rules if rules is not None else get_all_rules()
    findings: list[RuleFinding] = []

    for rule in rules:
        # Check required plugins are present and have data
        skip = False
        for req in rule.required_plugins:
            po = plugin_results.get(req)
            if po is None or po.error is not None or not po.rows:
                skip = True
                break
        if skip:
            continue

        try:
            rule_findings = rule.check(plugin_results)
            findings.extend(rule_findings)
        except Exception:
            logger.warning("Rule %s (%s) failed", rule.id, rule.title, exc_info=True)

    return findings


def rule_finding_to_finding(rf: RuleFinding) -> Finding:
    """Convert a RuleFinding to a report Finding."""
    return Finding(
        title=f"[{rf.rule_id}] {rf.title}",
        severity=rf.severity,
        description=rf.description,
        evidence=rf.evidence,
        mitre_attack=rf.mitre_attack,
    )


RULE_SEVERITY_FLOOR = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}


def compute_risk_floor(rule_findings: list[RuleFinding]) -> int:
    """Compute minimum risk score from rule findings."""
    if not rule_findings:
        return 0
    return max(
        RULE_SEVERITY_FLOOR.get(rf.severity, 0) for rf in rule_findings
    )


# --- Helper to get rows from a plugin ---

def _get_rows(plugins: PluginDict, name: str) -> list[dict]:
    po = plugins.get(name)
    if po and not po.error:
        return po.rows
    return []


def _get_col(row: dict, *candidates: str) -> str | None:
    """Get value from row trying multiple column name candidates."""
    for c in candidates:
        if c in row:
            val = row[c]
            return str(val) if val is not None else None
    return None


def _build_pid_name_map(rows: list[dict]) -> dict[int, str]:
    """Build PID -> process name map from pslist-like rows."""
    m: dict[int, str] = {}
    for row in rows:
        pid = _get_col(row, "PID")
        name = _get_col(row, "ImageFileName", "Name", "Process")
        if pid is not None and name is not None:
            try:
                m[int(pid)] = name
            except (ValueError, TypeError):
                pass
    return m


# ============================================================================
# 10 Bundled Rules
# ============================================================================

# B001: Suspicious svchost parent
def _check_svchost_parent(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.pslist.PsList")
    pid_name = _build_pid_name_map(rows)

    # Find services.exe PID
    services_pids = {pid for pid, name in pid_name.items() if name.lower() == "services.exe"}

    for row in rows:
        name = _get_col(row, "ImageFileName", "Name")
        if name and name.lower() == "svchost.exe":
            ppid_str = _get_col(row, "PPID")
            pid_str = _get_col(row, "PID")
            if ppid_str:
                try:
                    ppid = int(ppid_str)
                    if ppid not in services_pids:
                        parent_name = pid_name.get(ppid, "unknown")
                        findings.append(RuleFinding(
                            rule_id="VOLAI-B001",
                            title="Suspicious svchost parent",
                            severity="high",
                            description=f"svchost.exe (PID {pid_str}) has parent "
                                        f"{parent_name} (PID {ppid}) instead of services.exe",
                            evidence=[f"PID {pid_str}", f"PPID {ppid}"],
                            mitre_attack=["T1036.005"],
                        ))
                except (ValueError, TypeError):
                    pass
    return findings


register(BehavioralRule(
    id="VOLAI-B001", title="Suspicious svchost parent",
    description="svchost.exe should be spawned by services.exe",
    severity="high", required_plugins=["windows.pslist.PsList"],
    mitre_attack=["T1036.005"], check=_check_svchost_parent,
))


# B002: Process in temp directory
def _check_temp_process(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.cmdline.CmdLine")
    temp_patterns = [r"\temp\\", r"\appdata\local\temp"]

    for row in rows:
        args = _get_col(row, "Args", "CommandLine")
        pid = _get_col(row, "PID")
        name = _get_col(row, "Process", "Name", "ImageFileName")
        if args:
            args_lower = args.lower()
            for pat in temp_patterns:
                if pat in args_lower:
                    findings.append(RuleFinding(
                        rule_id="VOLAI-B002",
                        title="Process in temp directory",
                        severity="medium",
                        description=f"Process {name} (PID {pid}) running from temp directory",
                        evidence=[f"PID {pid}", args],
                        mitre_attack=["T1204"],
                    ))
                    break
    return findings


register(BehavioralRule(
    id="VOLAI-B002", title="Process in temp directory",
    description="Processes running from temp directories are suspicious",
    severity="medium", required_plugins=["windows.cmdline.CmdLine"],
    mitre_attack=["T1204"], check=_check_temp_process,
))


# B003: Process name typosquatting
_TYPOSQUAT_NAMES = frozenset({
    "scvhost", "svch0st", "svchosl", "svchosts",
    "csrsss", "cssrs", "cssrss",
    "lssas", "lsas", "lsasss",
    "winIogon", "winlog0n",
    "expl0rer", "exploer",
    "spoolsvc", "sp00lsv",
    "taskh0st",
})


def _check_typosquatting(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.pslist.PsList")

    for row in rows:
        name = _get_col(row, "ImageFileName", "Name")
        pid = _get_col(row, "PID")
        if name:
            name_base = name.lower().replace(".exe", "")
            if name_base in _TYPOSQUAT_NAMES:
                findings.append(RuleFinding(
                    rule_id="VOLAI-B003",
                    title="Process name typosquatting",
                    severity="high",
                    description=f"Process '{name}' (PID {pid}) resembles a "
                                f"system process name typosquat",
                    evidence=[f"PID {pid}", name],
                    mitre_attack=["T1036.005"],
                ))
    return findings


register(BehavioralRule(
    id="VOLAI-B003", title="Process name typosquatting",
    description="Detect process names that mimic legitimate system processes",
    severity="high", required_plugins=["windows.pslist.PsList"],
    mitre_attack=["T1036.005"], check=_check_typosquatting,
))


# B004: Hidden process (in pslist but not pstree, or vice versa)
def _check_hidden_process(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    pslist_rows = _get_rows(plugins, "windows.pslist.PsList")
    pstree_rows = _get_rows(plugins, "windows.pstree.PsTree")

    pslist_pids: set[int] = set()
    for row in pslist_rows:
        pid = _get_col(row, "PID")
        if pid:
            try:
                pslist_pids.add(int(pid))
            except (ValueError, TypeError):
                pass

    pstree_pids: set[int] = set()
    for row in pstree_rows:
        pid = _get_col(row, "PID")
        if pid:
            try:
                pstree_pids.add(int(pid))
            except (ValueError, TypeError):
                pass

    # PIDs in pslist but not pstree
    hidden = pslist_pids - pstree_pids
    for pid in hidden:
        findings.append(RuleFinding(
            rule_id="VOLAI-B004",
            title="Hidden process detected",
            severity="critical",
            description=f"PID {pid} found in pslist but not in pstree — "
                        f"possible DKOM or process hiding",
            evidence=[f"PID {pid}"],
            mitre_attack=["T1564.001"],
        ))

    # PIDs in pstree but not pslist
    for pid in pstree_pids - pslist_pids:
        findings.append(RuleFinding(
            rule_id="VOLAI-B004",
            title="Hidden process detected",
            severity="critical",
            description=f"PID {pid} found in pstree but not in pslist — "
                        f"possible process hiding",
            evidence=[f"PID {pid}"],
            mitre_attack=["T1564.001"],
        ))

    return findings


register(BehavioralRule(
    id="VOLAI-B004", title="Hidden process detected",
    description="Process visible in one listing but not the other",
    severity="critical",
    required_plugins=["windows.pslist.PsList", "windows.pstree.PsTree"],
    mitre_attack=["T1564.001"], check=_check_hidden_process,
))


# B005: C2 port connection
_C2_PORTS = frozenset({4444, 5555, 8888, 1337, 1234, 6666, 7777, 9999,
                       31337, 12345, 54321})


def _check_c2_ports(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.netscan.NetScan")

    for row in rows:
        foreign_port = _get_col(row, "ForeignPort")
        foreign_addr = _get_col(row, "ForeignAddr")
        pid = _get_col(row, "PID")
        state = _get_col(row, "State")
        if foreign_port:
            try:
                port = int(foreign_port)
                if port in _C2_PORTS:
                    findings.append(RuleFinding(
                        rule_id="VOLAI-B005",
                        title="Possible C2 port connection",
                        severity="medium",
                        description=f"PID {pid} connected to {foreign_addr}:{port} "
                                    f"(state: {state}) — common C2 port",
                        evidence=[f"PID {pid}", f"{foreign_addr}:{port}"],
                        mitre_attack=["T1571"],
                    ))
            except (ValueError, TypeError):
                pass
    return findings


register(BehavioralRule(
    id="VOLAI-B005", title="Possible C2 port connection",
    description="Connection to commonly used C2 framework ports",
    severity="medium", required_plugins=["windows.netscan.NetScan"],
    mitre_attack=["T1571"], check=_check_c2_ports,
))


# B006: Malfind hit present
def _check_malfind(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.malfind.Malfind")

    seen_pids: set[str] = set()
    for row in rows:
        pid = _get_col(row, "PID")
        name = _get_col(row, "Process", "Name", "ImageFileName")
        if pid and pid not in seen_pids:
            seen_pids.add(pid)
            findings.append(RuleFinding(
                rule_id="VOLAI-B006",
                title="Code injection indicator (malfind)",
                severity="high",
                description=f"Malfind detected suspicious memory region in "
                            f"{name} (PID {pid})",
                evidence=[f"PID {pid}"],
                mitre_attack=["T1055"],
            ))
    return findings


register(BehavioralRule(
    id="VOLAI-B006", title="Code injection indicator (malfind)",
    description="Any malfind hit indicates possible code injection",
    severity="high", required_plugins=["windows.malfind.Malfind"],
    mitre_attack=["T1055"], check=_check_malfind,
))


# B007: Unusual cmd/powershell parent
_SHELL_NAMES = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe"})
_NORMAL_SHELL_PARENTS = frozenset({"explorer.exe", "services.exe", "svchost.exe",
                                   "cmd.exe", "powershell.exe", "pwsh.exe",
                                   "windowsterminal.exe", "conhost.exe"})


def _check_shell_parent(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.pslist.PsList")
    pid_name = _build_pid_name_map(rows)

    for row in rows:
        name = _get_col(row, "ImageFileName", "Name")
        if name and name.lower() in _SHELL_NAMES:
            ppid_str = _get_col(row, "PPID")
            pid_str = _get_col(row, "PID")
            if ppid_str:
                try:
                    ppid = int(ppid_str)
                    parent_name = pid_name.get(ppid, "unknown")
                    if parent_name.lower() not in _NORMAL_SHELL_PARENTS:
                        findings.append(RuleFinding(
                            rule_id="VOLAI-B007",
                            title="Unusual shell parent process",
                            severity="medium",
                            description=f"{name} (PID {pid_str}) spawned by "
                                        f"{parent_name} (PID {ppid}) — unusual parent",
                            evidence=[f"PID {pid_str}", f"PPID {ppid}", parent_name],
                            mitre_attack=["T1059"],
                        ))
                except (ValueError, TypeError):
                    pass
    return findings


register(BehavioralRule(
    id="VOLAI-B007", title="Unusual shell parent process",
    description="cmd.exe/powershell.exe spawned by unexpected parent",
    severity="medium", required_plugins=["windows.pslist.PsList"],
    mitre_attack=["T1059"], check=_check_shell_parent,
))


# B008: Unusual kernel module path
def _check_kernel_module_path(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.modules.Modules")

    for row in rows:
        path = _get_col(row, "FullDllName", "Path", "Name")
        if path:
            path_lower = path.lower()
            if path_lower and "\\systemroot\\system32\\" not in path_lower \
                    and "\\windows\\system32\\" not in path_lower \
                    and path_lower not in ("", "none"):
                findings.append(RuleFinding(
                    rule_id="VOLAI-B008",
                    title="Kernel module in unusual path",
                    severity="medium",
                    description=f"Kernel module loaded from unusual path: {path}",
                    evidence=[path],
                    mitre_attack=["T1547.006"],
                ))
    return findings


register(BehavioralRule(
    id="VOLAI-B008", title="Kernel module in unusual path",
    description="Kernel module not in standard system32 directory",
    severity="medium", required_plugins=["windows.modules.Modules"],
    mitre_attack=["T1547.006"], check=_check_kernel_module_path,
))


# B009: Duplicate process names (≥3 with same name)
_NORMAL_DUPLICATES = frozenset({
    "svchost.exe", "runtimebroker.exe", "conhost.exe",
    "dllhost.exe", "taskhostw.exe", "backgroundtaskhost.exe",
    "searchprotocolhost.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "explorer.exe",
})


def _check_duplicate_processes(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.pslist.PsList")

    name_counts: dict[str, list[str]] = {}
    for row in rows:
        name = _get_col(row, "ImageFileName", "Name")
        pid = _get_col(row, "PID")
        if name:
            name_lower = name.lower()
            if name_lower not in _NORMAL_DUPLICATES:
                name_counts.setdefault(name_lower, []).append(pid or "?")

    for name, pids in name_counts.items():
        if len(pids) >= 3:
            findings.append(RuleFinding(
                rule_id="VOLAI-B009",
                title="Duplicate process names",
                severity="low",
                description=f"Process '{name}' found {len(pids)} times — "
                            f"possible process hollowing",
                evidence=[f"PIDs: {', '.join(pids)}"],
                mitre_attack=["T1055.012"],
            ))
    return findings


register(BehavioralRule(
    id="VOLAI-B009", title="Duplicate process names",
    description="Multiple processes with the same name (excluding common ones)",
    severity="low", required_plugins=["windows.pslist.PsList"],
    mitre_attack=["T1055.012"], check=_check_duplicate_processes,
))


# B010: Service in unusual path
_SVC_SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\users\\", "\\downloads\\"]


def _check_service_path(plugins: PluginDict) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    rows = _get_rows(plugins, "windows.svcscan.SvcScan")

    for row in rows:
        binary = _get_col(row, "Binary", "BinaryPath", "Path")
        svc_name = _get_col(row, "Name", "ServiceName")
        if binary:
            binary_lower = binary.lower()
            for pat in _SVC_SUSPICIOUS_PATHS:
                if pat in binary_lower:
                    findings.append(RuleFinding(
                        rule_id="VOLAI-B010",
                        title="Service in unusual path",
                        severity="high",
                        description=f"Service '{svc_name}' binary path in "
                                    f"suspicious location: {binary}",
                        evidence=[binary],
                        mitre_attack=["T1543.003"],
                    ))
                    break
    return findings


register(BehavioralRule(
    id="VOLAI-B010", title="Service in unusual path",
    description="Service binary in temp/user profile directory",
    severity="high", required_plugins=["windows.svcscan.SvcScan"],
    mitre_attack=["T1543.003"], check=_check_service_path,
))
