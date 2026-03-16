"""Grounding and validation for LLM-generated findings.

Validates evidence references against actual plugin data and MITRE ATT&CK IDs
against a static lookup. Annotates each finding with grounded/confidence scores.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from volai.analysis.mitre_data import MITRE_TECHNIQUE_IDS
from volai.report.models import Finding, PluginOutput, TriageReport

_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[\w\\.\-\s]+")
_UNIX_PATH_RE = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]+")


class ArtifactIndex:
    """Extracts and indexes artifacts from plugin output for evidence lookup."""

    def __init__(self, plugin_outputs: list[PluginOutput]) -> None:
        self.pids: set[int] = set()
        self.process_names: set[str] = set()
        self.ips: set[str] = set()
        self.file_paths: set[str] = set()
        self.tokens: set[str] = set()
        self._build(plugin_outputs)

    def _build(self, plugin_outputs: list[PluginOutput]) -> None:
        for po in plugin_outputs:
            for col_idx, col_name in enumerate(po.columns):
                col_upper = col_name.upper()
                for row in po.rows:
                    val = row.get(col_name)
                    if val is None:
                        continue
                    val_str = str(val)

                    if col_upper in ("PID", "PPID"):
                        try:
                            self.pids.add(int(val))
                        except (ValueError, TypeError):
                            pass

                    if any(k in col_upper for k in ("NAME", "PROCESS", "IMAGEFILENAME")):
                        self.process_names.add(val_str.lower())

                    # Extract IPs from any column
                    for ip_match in _IP_RE.findall(val_str):
                        self.ips.add(ip_match)

                    # Extract file paths from any column
                    for path_match in _WIN_PATH_RE.findall(val_str):
                        self.file_paths.add(path_match.lower())
                    for path_match in _UNIX_PATH_RE.findall(val_str):
                        self.file_paths.add(path_match.lower())

                    # General tokens for fuzzy fallback
                    self.tokens.add(val_str.lower())

    def contains(self, evidence_str: str) -> tuple[bool, str]:
        """Check if evidence string matches any known artifact.

        Returns (matched, match_type) where match_type is one of:
        'pid', 'process', 'ip', 'path', 'token', or 'none'.
        """
        ev_lower = evidence_str.lower()

        # Check PID references
        pid_matches = re.findall(r"\b\d+\b", evidence_str)
        for pid_str in pid_matches:
            try:
                if int(pid_str) in self.pids:
                    return True, "pid"
            except (ValueError, TypeError):
                pass

        # Check process names
        for pname in self.process_names:
            if pname in ev_lower:
                return True, "process"

        # Check IPs
        for ip_match in _IP_RE.findall(evidence_str):
            if ip_match in self.ips:
                return True, "ip"

        # Check paths
        for path_match in _WIN_PATH_RE.findall(evidence_str):
            if path_match.lower() in self.file_paths:
                return True, "path"
        for path_match in _UNIX_PATH_RE.findall(evidence_str):
            if path_match.lower() in self.file_paths:
                return True, "path"

        # Token fallback: check if any token is a substring of the evidence
        for token in self.tokens:
            if len(token) >= 3 and token in ev_lower:
                return True, "token"

        return False, "none"


class MitreValidator:
    """Validates MITRE ATT&CK technique IDs."""

    @staticmethod
    def validate(technique_id: str) -> str:
        """Validate a MITRE technique ID.

        Returns:
            'valid' — correct format and known ID
            'valid_format_unknown_id' — correct format but not in our set
            'invalid_format' — doesn't match T####(.###)? pattern
        """
        if not _MITRE_RE.match(technique_id):
            return "invalid_format"
        if technique_id in MITRE_TECHNIQUE_IDS:
            return "valid"
        return "valid_format_unknown_id"


@dataclass
class EvidenceResult:
    """Validation result for a single piece of evidence."""

    evidence: str
    grounded: bool
    match_type: str


@dataclass
class MitreResult:
    """Validation result for a single MITRE ID."""

    technique_id: str
    status: str  # valid, valid_format_unknown_id, invalid_format


@dataclass
class FindingGroundingResult:
    """Grounding result for a single finding."""

    finding_index: int
    evidence_results: list[EvidenceResult] = field(default_factory=list)
    mitre_results: list[MitreResult] = field(default_factory=list)
    confidence: float = 1.0
    grounded: bool = True


def ground_findings(
    findings: list[Finding],
    plugin_outputs: list[PluginOutput],
) -> list[FindingGroundingResult]:
    """Validate all findings against actual plugin data and MITRE IDs.

    Returns a FindingGroundingResult per finding.
    """
    index = ArtifactIndex(plugin_outputs)
    validator = MitreValidator()
    results: list[FindingGroundingResult] = []

    for i, finding in enumerate(findings):
        ev_results: list[EvidenceResult] = []
        for ev in finding.evidence:
            matched, match_type = index.contains(ev)
            ev_results.append(EvidenceResult(
                evidence=ev, grounded=matched, match_type=match_type,
            ))

        mitre_results: list[MitreResult] = []
        for tid in finding.mitre_attack:
            status = validator.validate(tid)
            mitre_results.append(MitreResult(
                technique_id=tid, status=status,
            ))

        # Compute confidence
        grounded_ev = sum(1 for e in ev_results if e.grounded)
        valid_mitre = sum(1 for m in mitre_results if m.status != "invalid_format")
        total = len(ev_results) + len(mitre_results)

        if total == 0:
            confidence = 1.0
        else:
            confidence = (grounded_ev + valid_mitre) / total

        results.append(FindingGroundingResult(
            finding_index=i,
            evidence_results=ev_results,
            mitre_results=mitre_results,
            confidence=round(confidence, 2),
            grounded=confidence >= 0.5,
        ))

    return results


def annotate_report(
    report: TriageReport,
    ground_results: list[FindingGroundingResult],
) -> None:
    """Annotate report findings with grounding data and add summary."""
    total_findings = len(ground_results)
    grounded_count = sum(1 for r in ground_results if r.grounded)

    for gr in ground_results:
        if gr.finding_index < len(report.findings):
            finding = report.findings[gr.finding_index]
            finding.grounded = gr.grounded
            finding.confidence = gr.confidence
            finding.grounding_details = {
                "evidence": [
                    {"value": er.evidence, "grounded": er.grounded, "match_type": er.match_type}
                    for er in gr.evidence_results
                ],
                "mitre": [
                    {"id": mr.technique_id, "status": mr.status}
                    for mr in gr.mitre_results
                ],
            }

    report.grounding_summary = {
        "total_findings": total_findings,
        "grounded_findings": grounded_count,
        "ungrounded_findings": total_findings - grounded_count,
        "grounding_rate": round(grounded_count / total_findings, 2) if total_findings > 0 else 1.0,
    }
