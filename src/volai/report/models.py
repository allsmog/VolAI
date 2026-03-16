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
