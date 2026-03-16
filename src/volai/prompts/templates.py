from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from volai.volatility.runner import PluginResult


def build_triage_prompt(
    plugin_results: list[PluginResult],
    dump_path: str,
) -> str:
    """Build the user message containing all plugin output for triage analysis."""
    sections: list[str] = []

    for result in plugin_results:
        if result.error:
            sections.append(
                f"## {result.plugin_name}\nERROR: {result.error}\n"
            )
            continue
        if not result.rows:
            sections.append(
                f"## {result.plugin_name}\nNo output (0 rows)\n"
            )
            continue

        rows = result.rows
        truncated = False
        if len(rows) > 200:
            rows = rows[:200]
            truncated = True

        header = " | ".join(result.columns)
        lines = [header, "-" * len(header)]
        for row in rows:
            line = " | ".join(
                str(row.get(col, "")) for col in result.columns
            )
            lines.append(line)
        if truncated:
            lines.append(
                f"... ({result.row_count - 200} more rows truncated)"
            )

        sections.append(
            f"## {result.plugin_name}\n" + "\n".join(lines) + "\n"
        )

    return (
        f"Memory dump: {dump_path}\n\n"
        "Below are the outputs from Volatility3 plugins.\n"
        "Analyze these results and provide a forensic triage report.\n\n"
        + "\n".join(sections)
    )
