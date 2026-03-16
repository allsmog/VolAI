from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from volai.rules.models import RuleFinding
    from volai.volatility.runner import PluginResult


def format_rule_findings(rule_findings: list[RuleFinding]) -> str:
    """Format rule findings as a text section for the LLM prompt."""
    lines = [
        "## Deterministic Rule-Based Findings",
        "The following were identified by automated detection rules.",
        "Treat these as confirmed matches — correlate with plugin data.",
        "",
    ]
    for rf in rule_findings:
        lines.append(f"### [{rf.rule_id}] {rf.title} (severity: {rf.severity})")
        lines.append(rf.description)
        if rf.evidence:
            lines.append(f"  Evidence: {', '.join(rf.evidence)}")
        if rf.mitre_attack:
            lines.append(f"  MITRE: {', '.join(rf.mitre_attack)}")
        lines.append("")
    return "\n".join(lines)


def build_triage_prompt(
    plugin_results: list[PluginResult],
    dump_path: str,
    rule_findings: list[RuleFinding] | None = None,
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

    preamble = (
        f"Memory dump: {dump_path}\n\n"
        "Below are the outputs from Volatility3 plugins.\n"
        "Analyze these results and provide a forensic triage report.\n\n"
    )

    if rule_findings:
        preamble += format_rule_findings(rule_findings) + "\n"

    return preamble + "\n".join(sections)
