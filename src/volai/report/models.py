from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class PluginOutput(BaseModel):
    """Output from a single Volatility3 plugin."""

    plugin_name: str
    columns: list[str] = Field(default_factory=list)
    rows: list[dict] = Field(default_factory=list)
    row_count: int = 0
    error: str | None = None


class Finding(BaseModel):
    """A single forensic finding identified by the LLM."""

    title: str
    severity: str = Field(
        description="critical, high, medium, low, informational"
    )
    description: str
    evidence: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    grounded: bool | None = Field(default=None)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    grounding_details: dict | None = Field(default=None)


class TriageReport(BaseModel):
    """Top-level report for the analyze command."""

    dump_path: str
    analysis_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    os_detected: str | None = None
    llm_provider: str
    llm_model: str
    summary: str = Field(description="Executive summary of findings")
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=100)
    plugin_outputs: list[PluginOutput] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    grounding_summary: dict | None = Field(default=None)
    rule_findings: list[Finding] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """A single event in a forensic timeline."""

    timestamp: str
    event_type: str
    source_plugin: str
    description: str
    details: dict = Field(default_factory=dict)


class Timeline(BaseModel):
    """Collection of timeline events."""

    dump_path: str
    event_count: int = 0
    earliest: str | None = None
    latest: str | None = None
    events: list[TimelineEvent] = Field(default_factory=list)


class FindingDiff(BaseModel):
    """Comparison result for a single finding."""

    status: str  # new, resolved, modified, unchanged
    finding_a: Finding | None = None
    finding_b: Finding | None = None


class DiffReport(BaseModel):
    """Result of comparing two triage reports."""

    session_id_a: str
    session_id_b: str
    risk_score_delta: int = 0
    finding_diffs: list[FindingDiff] = Field(default_factory=list)
    process_diffs: dict = Field(default_factory=dict)
    network_diffs: dict = Field(default_factory=dict)
    summary: str = ""
