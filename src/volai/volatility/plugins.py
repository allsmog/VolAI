"""Triage plugin sets per OS profile."""

WINDOWS_TRIAGE_PLUGINS = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.malfind.Malfind",
    "windows.dlllist.DllList",
    "windows.handles.Handles",
    "windows.filescan.FileScan",
    "windows.svcscan.SvcScan",
    "windows.modules.Modules",
]

LINUX_TRIAGE_PLUGINS = [
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.bash.Bash",
    "linux.lsof.Lsof",
    "linux.lsmod.Lsmod",
    "linux.malfind.Malfind",
    "linux.sockstat.Sockstat",
    "linux.elfs.Elfs",
    "linux.proc.Maps",
]

MAC_TRIAGE_PLUGINS = [
    "mac.pslist.PsList",
    "mac.pstree.PsTree",
    "mac.bash.Bash",
    "mac.lsof.Lsof",
    "mac.lsmod.Lsmod",
    "mac.malfind.Malfind",
    "mac.netstat.Netstat",
    "mac.mount.Mount",
]

ALL_TRIAGE_PLUGINS = {
    "windows": WINDOWS_TRIAGE_PLUGINS,
    "linux": LINUX_TRIAGE_PLUGINS,
    "mac": MAC_TRIAGE_PLUGINS,
}


def get_triage_plugins(os_type: str | None = None) -> list[str]:
    """Return triage plugin list for a given OS.

    If os_type is None, returns a combined superset — the runner will
    skip plugins that fail for the wrong OS.
    """
    if os_type:
        return ALL_TRIAGE_PLUGINS.get(os_type, WINDOWS_TRIAGE_PLUGINS)
    combined: list[str] = []
    for plugins in ALL_TRIAGE_PLUGINS.values():
        combined.extend(plugins)
    return list(dict.fromkeys(combined))  # deduplicate preserving order
