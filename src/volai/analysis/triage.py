from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import click
from pydantic import ValidationError

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
    enable_rules: bool = True,
    store: object | None = None,
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

    # Run behavioral rules before LLM call
    rule_findings_list = []
    if enable_rules:
        from volai.rules.behavioral import run_behavioral_rules
        plugin_results_dict = {r.plugin_name: PluginOutput(
            plugin_name=r.plugin_name, columns=r.columns,
            rows=r.rows, row_count=r.row_count, error=r.error,
        ) for r in results}
        rule_findings_list = run_behavioral_rules(plugin_results_dict)
        if rule_findings_list:
            click.echo(f"Behavioral rules: {len(rule_findings_list)} findings")

    prompt_text = build_triage_prompt(
        results, str(dump_path),
        rule_findings=rule_findings_list if rule_findings_list else None,
    )
    messages = [
        Message(role="system", content=TRIAGE_SYSTEM_PROMPT),
        Message(role="user", content=prompt_text),
    ]

    click.echo("Sending results to LLM for analysis...")
    try:
        use_json_mode = config.json_mode if config.json_mode is not None else backend.supports_json_mode
        send_kwargs: dict = {"json_mode": use_json_mode}
        if config.temperature is not None:
            send_kwargs["temperature"] = config.temperature
        if config.max_tokens is not None:
            send_kwargs["max_tokens"] = config.max_tokens
        response = await backend.send(messages, **send_kwargs)
    except Exception as e:
        logger.warning("LLM request failed: %s", e)
        plugin_outputs = [
            PluginOutput(
                plugin_name=r.plugin_name,
                columns=r.columns,
                rows=r.rows,
                row_count=r.row_count,
                error=r.error,
            )
            for r in results
        ]
        errors = [f"{r.plugin_name}: {r.error}" for r in failed]
        errors.append(f"LLM analysis failed: {e}")
        return TriageReport(
            dump_path=str(dump_path),
            llm_provider=backend.name(),
            llm_model=config.model or "unknown",
            summary=f"LLM analysis failed: {e}",
            risk_score=0,
            plugin_outputs=plugin_outputs,
            errors=errors,
        )

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

    # Grounding: validate findings against actual plugin data
    from volai.analysis.grounding import ground_findings, annotate_report

    ground_results = ground_findings(report.findings, report.plugin_outputs)
    annotate_report(report, ground_results)

    # Attach rule findings and apply risk score floor
    if rule_findings_list:
        from volai.rules.behavioral import (
            compute_risk_floor,
            rule_finding_to_finding,
        )

        report.rule_findings = [
            rule_finding_to_finding(rf) for rf in rule_findings_list
        ]
        risk_floor = compute_risk_floor(rule_findings_list)
        report.risk_score = max(report.risk_score, risk_floor)

    # Persist session if store provided
    if store is not None:
        try:
            from volai.storage.store import SessionStore
            if isinstance(store, SessionStore):
                session = store.create_session(
                    dump_path=str(dump_path),
                    session_type="triage",
                    provider=config.provider,
                    model=config.model or "unknown",
                )
                for po in report.plugin_outputs:
                    store.save_plugin_output(session["id"], po)
                store.save_triage_report(session["id"], report)
                click.echo(f"Session saved: {session['id']}")
        except Exception as e:
            logger.warning("Failed to save session: %s", e)

    return report


def _coerce_evidence(data: dict) -> dict:
    """Coerce non-string evidence items to strings.

    Small LLMs sometimes return evidence as objects instead of strings.
    """
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence")
        if not isinstance(evidence, list):
            continue
        finding["evidence"] = [
            " ".join(f"{k}={v}" for k, v in item.items())
            if isinstance(item, dict)
            else str(item)
            for item in evidence
        ]
    return data


def _try_repair_json(text: str) -> str:
    """Fix common JSON errors from small LLMs.

    Only called after json.loads() already failed, so aggressive fixes are safe.
    """
    # Fix unescaped backslashes (escape any \ not already part of \\ or \")
    text = re.sub(r'(?<!\\)\\(?![\\"])', r'\\\\', text)
    # Close unclosed brackets then braces (order matters for nested structures)
    opens = text.count('[') - text.count(']')
    if opens > 0:
        text += ']' * opens
    opens = text.count('{') - text.count('}')
    if opens > 0:
        text += '}' * opens
    # Remove trailing commas before } or ] (after closing, so truncated commas are caught)
    text = re.sub(r',\s*([}\]])', r'\1', text)
    return text


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
    except json.JSONDecodeError:
        try:
            repaired = _try_repair_json(text)
            data = json.loads(repaired)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse LLM response as JSON: %s", e)
            return TriageReport(
                dump_path=str(dump_path),
                llm_provider=backend.name(),
                llm_model=config.model or "unknown",
                summary=llm_response,
                risk_score=0,
            )

    try:
        data = _coerce_evidence(data)
        data["dump_path"] = str(dump_path)
        data["llm_provider"] = backend.name()
        data["llm_model"] = config.model or "unknown"
        return TriageReport.model_validate(data)
    except ValidationError as e:
        logger.warning("Failed to validate LLM response: %s", e)
        return TriageReport(
            dump_path=str(dump_path),
            llm_provider=backend.name(),
            llm_model=config.model or "unknown",
            summary=llm_response,
            risk_score=0,
        )
