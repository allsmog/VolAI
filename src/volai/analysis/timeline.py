"""Timeline extraction from plugin output — no LLM needed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from volai.report.models import PluginOutput

# Columns that contain timestamps
_TIME_COL_PATTERNS = re.compile(r"(?i)(time|date|created|timestamp)")

# Known timestamp column mappings: (plugin_name_substring, column, event_type)
_KNOWN_COLUMNS: list[tuple[str, str, str]] = [
    ("pslist", "CreateTime", "process_created"),
    ("pslist", "ExitTime", "process_exited"),
    ("pstree", "CreateTime", "process_created"),
    ("pstree", "ExitTime", "process_exited"),
    ("netscan", "Created", "network_connection"),
    ("bash", "Timestamp", "bash_command"),
]


@dataclass
class TimelineEvent:
    """A single event extracted from plugin data."""

    timestamp: str
    event_type: str
    source_plugin: str
    description: str
    details: dict = field(default_factory=dict)


@dataclass
class Timeline:
    """Collection of timeline events."""

    dump_path: str
    event_count: int = 0
    earliest: str | None = None
    latest: str | None = None
    events: list[TimelineEvent] = field(default_factory=list)


def _is_valid_timestamp(value: str) -> bool:
    """Check if a string looks like a timestamp (not empty/N/A/0)."""
    if not value or value.strip() in ("", "N/A", "0", "None", "-"):
        return False
    # Must contain at least a digit
    return any(c.isdigit() for c in value)


def _build_description(row: dict, col_name: str, plugin_name: str) -> str:
    """Build a human-readable description from row data."""
    parts = []
    # Try to find a name/process/PID for context
    for key in ("ImageFileName", "Name", "Process", "PID", "Command"):
        val = row.get(key)
        if val is not None and str(val).strip():
            parts.append(f"{key}={val}")
    if not parts:
        # Use first few non-timestamp columns
        for k, v in list(row.items())[:3]:
            if k != col_name and v is not None:
                parts.append(f"{k}={v}")
    return ", ".join(parts) if parts else plugin_name


def extract_timeline(
    plugin_outputs: list[PluginOutput],
    dump_path: str = "",
) -> Timeline:
    """Extract timeline events from plugin output data."""
    events: list[TimelineEvent] = []

    for po in plugin_outputs:
        if po.error or not po.rows:
            continue

        # Find timestamp columns for this plugin
        ts_columns: list[tuple[str, str]] = []  # (column_name, event_type)

        # Check known columns first
        for plugin_substr, col_name, event_type in _KNOWN_COLUMNS:
            if plugin_substr in po.plugin_name.lower() and col_name in po.columns:
                ts_columns.append((col_name, event_type))

        # Fallback: scan for generic timestamp-like columns
        if not ts_columns:
            for col in po.columns:
                if _TIME_COL_PATTERNS.search(col):
                    ts_columns.append((col, "event"))

        # Extract events
        for row in po.rows:
            for col_name, event_type in ts_columns:
                val = row.get(col_name)
                if val is None:
                    continue
                val_str = str(val).strip()
                if not _is_valid_timestamp(val_str):
                    continue

                desc = _build_description(row, col_name, po.plugin_name)
                details = {k: str(v) for k, v in row.items() if v is not None}

                events.append(TimelineEvent(
                    timestamp=val_str,
                    event_type=event_type,
                    source_plugin=po.plugin_name,
                    description=desc,
                    details=details,
                ))

    # Sort by timestamp string (ISO 8601 sorts lexicographically)
    events.sort(key=lambda e: e.timestamp)

    earliest = events[0].timestamp if events else None
    latest = events[-1].timestamp if events else None

    return Timeline(
        dump_path=dump_path,
        event_count=len(events),
        earliest=earliest,
        latest=latest,
        events=events,
    )
