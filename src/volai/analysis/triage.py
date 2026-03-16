from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from volai.config import VolAIConfig
from volai.llm import get_backend
from volai.llm.base import Message
from volai.prompts.system import TRIAGE_SYSTEM_PROMPT
from volai.prompts.templates import build_triage_prompt
from volai.report.models import PluginOutput, TriageReport
from volai.volatility.plugins import get_triage_plugins
from volai.volatility.runner import VolatilityRunner

logger = logging.getLogger(__name__)


async def run_triage(
    config: VolAIConfig,
    dump_path: Path,
    os_profile: str | None = None,
    custom_plugins: list[str] | None = None,
    verbose: bool = False,
) -> TriageReport:
    """Run automated triage analysis on a memory dump."""
    backend = get_backend(
        provider=config.provider,
        model=config.model,
        api_key=config.api_key,
        base_url=config.base_url,
    )

    runner = VolatilityRunner(dump_path)
    runner.initialize()

    plugin_names = custom_plugins or get_triage_plugins(os_profile)

    click.echo(f"Running {len(plugin_names)} plugins in parallel...")
    results = await runner.run_plugins_async(plugin_names)

    successful = [r for r in results if r.error is None]
    failed = [r for r in results if r.error is not None]

    click.echo(
        f"Completed: {len(successful)} succeeded, {len(failed)} failed"
    )

    if not successful:
        return TriageReport(
            dump_path=str(dump_path),
            llm_provider=backend.name(),
            llm_model=config.model or "unknown",
            summary="All plugins failed. Unable to perform analysis.",
            risk_score=0,
            errors=[f"{r.plugin_name}: {r.error}" for r in failed],
        )

    prompt_text = build_triage_prompt(results, str(dump_path))
    messages = [
        Message(role="system", content=TRIAGE_SYSTEM_PROMPT),
        Message(role="user", content=prompt_text),
    ]

    click.echo("Sending results to LLM for analysis...")
    response = await backend.send(messages)

    report = _parse_report(response.content, config, backend, dump_path)

    report.plugin_outputs = [
        PluginOutput(
            plugin_name=r.plugin_name,
            columns=r.columns,
            rows=r.rows,
            row_count=r.row_count,
            error=r.error,
        )
        for r in results
    ]
    report.errors = [f"{r.plugin_name}: {r.error}" for r in failed]

    return report


def _parse_report(
    llm_response: str,
    config: VolAIConfig,
    backend,
    dump_path: Path,
) -> TriageReport:
    """Parse the LLM JSON response into a TriageReport."""
    # Strip markdown fencing if present
    text = llm_response.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]  # remove opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        data = json.loads(text)
        data["dump_path"] = str(dump_path)
        data["llm_provider"] = backend.name()
        data["llm_model"] = config.model or "unknown"
        return TriageReport.model_validate(data)
    except (json.JSONDecodeError, Exception) as e:
        logger.warning("Failed to parse LLM response as JSON: %s", e)
        return TriageReport(
            dump_path=str(dump_path),
            llm_provider=backend.name(),
            llm_model=config.model or "unknown",
            summary=llm_response,
            risk_score=0,
        )
