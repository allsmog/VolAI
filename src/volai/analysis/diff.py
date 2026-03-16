"""Report diffing — compare two triage reports."""

from __future__ import annotations

from dataclasses import dataclass, field

from volai.report.models import Finding, TriageReport


@dataclass
class FindingDiff:
    """Comparison result for a single finding."""

    status: str  # new, resolved, modified, unchanged
    finding_a: Finding | None = None
    finding_b: Finding | None = None


@dataclass
class DiffReport:
    """Result of comparing two triage reports."""

    session_id_a: str
    session_id_b: str
    risk_score_delta: int = 0
    finding_diffs: list[FindingDiff] = field(default_factory=list)
    process_diffs: dict = field(default_factory=dict)
    network_diffs: dict = field(default_factory=dict)
    summary: str = ""


def _finding_key(f: Finding) -> tuple[str, str]:
    """Key for matching findings."""
    return (f.title.lower(), f.severity.lower())


def _jaccard(a: list[str], b: list[str]) -> float:
    """Jaccard similarity between two string lists."""
    set_a = {s.lower() for s in a}
    set_b = {s.lower() for s in b}
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def _extract_pids(report: TriageReport) -> set[int]:
    """Extract PIDs from pslist plugin output."""
    pids: set[int] = set()
    for po in report.plugin_outputs:
        if "pslist" in po.plugin_name.lower():
            for row in po.rows:
                pid = row.get("PID")
                if pid is not None:
                    try:
                        pids.add(int(pid))
                    except (ValueError, TypeError):
                        pass
    return pids


def _extract_connections(report: TriageReport) -> set[str]:
    """Extract network connections from netscan plugin output."""
    conns: set[str] = set()
    for po in report.plugin_outputs:
        if "netscan" in po.plugin_name.lower():
            for row in po.rows:
                foreign = row.get("ForeignAddr", "")
                port = row.get("ForeignPort", "")
                if foreign and port:
                    conns.add(f"{foreign}:{port}")
    return conns


def diff_reports(
    report_a: TriageReport,
    report_b: TriageReport,
    session_id_a: str = "a",
    session_id_b: str = "b",
) -> DiffReport:
    """Compare two triage reports and produce a diff."""
    finding_diffs: list[FindingDiff] = []

    # Index findings from B by key
    b_by_key: dict[tuple[str, str], Finding] = {}
    b_matched: set[int] = set()
    for i, f in enumerate(report_b.findings):
        b_by_key[_finding_key(f)] = (i, f)

    # Match findings from A to B
    for fa in report_a.findings:
        key = _finding_key(fa)
        if key in b_by_key:
            idx, fb = b_by_key[key]
            b_matched.add(idx)
            # Check if modified (different evidence)
            if fa.evidence == fb.evidence and fa.description == fb.description:
                finding_diffs.append(FindingDiff(
                    status="unchanged", finding_a=fa, finding_b=fb,
                ))
            else:
                finding_diffs.append(FindingDiff(
                    status="modified", finding_a=fa, finding_b=fb,
                ))
        else:
            # Try fuzzy match by evidence similarity
            best_idx = None
            best_sim = 0.0
            for i, fb in enumerate(report_b.findings):
                if i in b_matched:
                    continue
                sim = _jaccard(fa.evidence, fb.evidence)
                if sim > best_sim:
                    best_sim = sim
                    best_idx = i

            if best_sim > 0.6 and best_idx is not None:
                b_matched.add(best_idx)
                finding_diffs.append(FindingDiff(
                    status="modified", finding_a=fa,
                    finding_b=report_b.findings[best_idx],
                ))
            else:
                finding_diffs.append(FindingDiff(
                    status="resolved", finding_a=fa,
                ))

    # Remaining unmatched B findings are "new"
    for i, fb in enumerate(report_b.findings):
        if i not in b_matched:
            finding_diffs.append(FindingDiff(
                status="new", finding_b=fb,
            ))

    # Process diffs
    pids_a = _extract_pids(report_a)
    pids_b = _extract_pids(report_b)
    process_diffs = {
        "added": sorted(pids_b - pids_a),
        "removed": sorted(pids_a - pids_b),
        "common": len(pids_a & pids_b),
    }

    # Network diffs
    conns_a = _extract_connections(report_a)
    conns_b = _extract_connections(report_b)
    network_diffs = {
        "added": sorted(conns_b - conns_a),
        "removed": sorted(conns_a - conns_b),
        "common": len(conns_a & conns_b),
    }

    # Build summary
    risk_delta = report_b.risk_score - report_a.risk_score
    new_count = sum(1 for d in finding_diffs if d.status == "new")
    resolved_count = sum(1 for d in finding_diffs if d.status == "resolved")
    modified_count = sum(1 for d in finding_diffs if d.status == "modified")
    unchanged_count = sum(1 for d in finding_diffs if d.status == "unchanged")

    summary_parts = [
        f"Risk score: {report_a.risk_score} -> {report_b.risk_score} (delta: {risk_delta:+d})",
    ]
    if new_count:
        summary_parts.append(f"{new_count} new finding(s)")
    if resolved_count:
        summary_parts.append(f"{resolved_count} resolved finding(s)")
    if modified_count:
        summary_parts.append(f"{modified_count} modified finding(s)")
    if unchanged_count:
        summary_parts.append(f"{unchanged_count} unchanged finding(s)")

    return DiffReport(
        session_id_a=session_id_a,
        session_id_b=session_id_b,
        risk_score_delta=risk_delta,
        finding_diffs=finding_diffs,
        process_diffs=process_diffs,
        network_diffs=network_diffs,
        summary=". ".join(summary_parts),
    )
