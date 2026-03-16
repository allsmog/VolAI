from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from volai.config import resolve_config


@click.group()
@click.version_option(package_name="volai")
def cli() -> None:
    """VolAI - AI-powered memory forensics companion for Volatility3."""


@cli.command()
@click.argument("dump", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["claude", "openai", "local"]),
    envvar="VOLAI_PROVIDER",
    required=True,
    help="LLM provider (or set VOLAI_PROVIDER).",
)
@click.option(
    "--model",
    "-m",
    envvar="VOLAI_MODEL",
    default=None,
    help="Model name/ID. Provider-specific defaults if omitted.",
)
@click.option(
    "--api-key",
    envvar="VOLAI_API_KEY",
    default=None,
    help="API key (or set VOLAI_API_KEY / provider-specific env var).",
)
@click.option(
    "--base-url",
    envvar="VOLAI_BASE_URL",
    default=None,
    help="Base URL for local/custom endpoint.",
)
@click.option(
    "--os-profile",
    type=click.Choice(["windows", "linux", "mac"]),
    default=None,
    help="OS profile for triage plugins. Auto-detected if omitted.",
)
@click.option(
    "--plugins",
    default=None,
    help="Comma-separated plugin names to run instead of default triage set.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write JSON report to file instead of stdout.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.option("--no-rules", is_flag=True, help="Disable behavioral detection rules.")
@click.option("--no-save", is_flag=True, help="Don't persist session to database.")
def analyze(
    dump: Path,
    provider: str,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
    os_profile: str | None,
    plugins: str | None,
    output: Path | None,
    verbose: bool,
    no_rules: bool,
    no_save: bool,
) -> None:
    """Automated triage analysis of a memory dump."""
    _setup_logging(verbose)

    config = resolve_config(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )
    plugin_list = plugins.split(",") if plugins else None

    from volai.analysis.triage import run_triage

    store = None
    if not no_save:
        try:
            from volai.storage.store import SessionStore
            store = SessionStore()
        except Exception:
            pass

    report = asyncio.run(
        run_triage(
            config, dump, os_profile, plugin_list, verbose,
            enable_rules=not no_rules, store=store,
        )
    )
    report_json = report.model_dump_json(indent=2)

    if output:
        output.write_text(report_json)
        click.echo(f"Report written to {output}")
    else:
        click.echo(report_json)


@cli.command()
@click.argument("dump", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["claude", "openai", "local"]),
    envvar="VOLAI_PROVIDER",
    required=True,
    help="LLM provider (or set VOLAI_PROVIDER).",
)
@click.option(
    "--model",
    "-m",
    envvar="VOLAI_MODEL",
    default=None,
    help="Model name/ID.",
)
@click.option(
    "--api-key",
    envvar="VOLAI_API_KEY",
    default=None,
    help="API key.",
)
@click.option(
    "--base-url",
    envvar="VOLAI_BASE_URL",
    default=None,
    help="Base URL for local/custom endpoint.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.option("--resume", "resume_id", default=None, help="Resume a previous chat session by ID.")
@click.option("--no-save", is_flag=True, help="Don't persist session to database.")
def chat(
    dump: Path,
    provider: str,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
    verbose: bool,
    resume_id: str | None,
    no_save: bool,
) -> None:
    """Interactive forensic investigation chat session."""
    _setup_logging(verbose)

    config = resolve_config(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )

    store = None
    if not no_save:
        try:
            from volai.storage.store import SessionStore
            store = SessionStore()
        except Exception:
            pass

    from volai.analysis.chat import run_chat

    asyncio.run(run_chat(config, dump, verbose, store=store, resume_session_id=resume_id))


@cli.group()
def sessions() -> None:
    """Manage saved analysis sessions."""


@sessions.command("list")
@click.option("--type", "session_type", type=click.Choice(["triage", "chat"]), default=None)
@click.option("--dump", default=None, help="Filter by dump path.")
def sessions_list(session_type: str | None, dump: str | None) -> None:
    """List saved sessions."""
    from volai.storage.store import SessionStore

    store = SessionStore()
    items = store.list_sessions(session_type=session_type, dump_path=dump)
    if not items:
        click.echo("No sessions found.")
        return
    for s in items:
        click.echo(
            f"{s['id']}  {s['session_type']:7}  {s['provider']:8}  "
            f"{s['created_at'][:19]}  {s['dump_path']}"
        )


@sessions.command("show")
@click.argument("session_id")
@click.option("--messages", is_flag=True, help="Show chat messages.")
def sessions_show(session_id: str, messages: bool) -> None:
    """Show session details."""
    from volai.storage.store import SessionStore

    store = SessionStore()
    resolved = store.resolve_session_id(session_id)
    if not resolved:
        click.echo(f"Session '{session_id}' not found (or ambiguous).")
        return

    session = store.get_session(resolved)
    for k, v in session.items():
        click.echo(f"  {k}: {v}")

    report = store.get_triage_report(resolved)
    if report:
        click.echo(f"\n  Risk Score: {report.risk_score}")
        click.echo(f"  Findings: {len(report.findings)}")
        click.echo(f"  Summary: {report.summary[:200]}")

    if messages:
        msgs = store.get_messages(resolved)
        click.echo(f"\n  Messages ({len(msgs)}):")
        for m in msgs:
            preview = m["content"][:100].replace("\n", " ")
            click.echo(f"    [{m['role']}] {preview}")


@sessions.command("delete")
@click.argument("session_id")
@click.option("--force", is_flag=True, help="Skip confirmation.")
def sessions_delete(session_id: str, force: bool) -> None:
    """Delete a session."""
    from volai.storage.store import SessionStore

    store = SessionStore()
    resolved = store.resolve_session_id(session_id)
    if not resolved:
        click.echo(f"Session '{session_id}' not found (or ambiguous).")
        return

    if not force:
        click.confirm(f"Delete session {resolved}?", abort=True)

    if store.delete_session(resolved):
        click.echo(f"Session {resolved} deleted.")
    else:
        click.echo("Delete failed.")


@sessions.command("export")
@click.argument("session_id")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def sessions_export(session_id: str, output: Path | None) -> None:
    """Export a session as JSON."""
    import json as json_mod

    from volai.storage.store import SessionStore

    store = SessionStore()
    resolved = store.resolve_session_id(session_id)
    if not resolved:
        click.echo(f"Session '{session_id}' not found (or ambiguous).")
        return

    data = store.export_session(resolved)
    if not data:
        click.echo("Export failed.")
        return

    json_str = json_mod.dumps(data, indent=2, default=str)
    if output:
        output.write_text(json_str)
        click.echo(f"Exported to {output}")
    else:
        click.echo(json_str)


@cli.command()
@click.argument("dump", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--provider", "-p",
    type=click.Choice(["claude", "openai", "local"]),
    envvar="VOLAI_PROVIDER", required=True,
)
@click.option("--model", "-m", envvar="VOLAI_MODEL", default=None)
@click.option("--api-key", envvar="VOLAI_API_KEY", default=None)
@click.option("--base-url", envvar="VOLAI_BASE_URL", default=None)
@click.option("--os-profile", type=click.Choice(["windows", "linux", "mac"]), default=None)
@click.option("--plugins", default=None, help="Comma-separated plugin names.")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "csv"]), default="text")
def timeline(
    dump: Path, provider: str, model: str | None, api_key: str | None,
    base_url: str | None, os_profile: str | None, plugins: str | None,
    fmt: str,
) -> None:
    """Extract a forensic timeline from a memory dump."""
    _setup_logging(False)
    import json as json_mod

    from volai.analysis.timeline import extract_timeline
    from volai.report.models import PluginOutput
    from volai.volatility.plugins import get_triage_plugins
    from volai.volatility.runner import VolatilityRunner

    plugin_names = plugins.split(",") if plugins else get_triage_plugins(os_profile)
    runner = VolatilityRunner(dump)
    runner.initialize()

    click.echo(f"Running {len(plugin_names)} plugins...")
    results = asyncio.run(runner.run_plugins_async(plugin_names))
    outputs = [
        PluginOutput(
            plugin_name=r.plugin_name, columns=r.columns,
            rows=r.rows, row_count=r.row_count, error=r.error,
        ) for r in results
    ]

    tl = extract_timeline(outputs, str(dump))
    click.echo(f"Extracted {tl.event_count} events")

    if fmt == "json":
        # Use dataclass-style dict manually
        events_data = [
            {"timestamp": e.timestamp, "event_type": e.event_type,
             "source_plugin": e.source_plugin, "description": e.description}
            for e in tl.events
        ]
        click.echo(json_mod.dumps({
            "dump_path": tl.dump_path, "event_count": tl.event_count,
            "earliest": tl.earliest, "latest": tl.latest, "events": events_data,
        }, indent=2))
    elif fmt == "csv":
        click.echo("timestamp,event_type,source_plugin,description")
        for e in tl.events:
            desc = e.description.replace(",", ";").replace("\n", " ")
            click.echo(f"{e.timestamp},{e.event_type},{e.source_plugin},{desc}")
    else:
        if not tl.events:
            click.echo("No timeline events found.")
        else:
            click.echo(f"\nTimeline ({tl.earliest} to {tl.latest}):\n")
            for e in tl.events:
                click.echo(f"  [{e.timestamp}] {e.event_type}: {e.description}")


@cli.command("diff")
@click.argument("id1")
@click.argument("id2")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def diff_cmd(id1: str, id2: str, fmt: str) -> None:
    """Compare two triage reports by session ID."""
    import json as json_mod

    from volai.analysis.diff import diff_reports
    from volai.storage.store import SessionStore

    store = SessionStore()
    resolved_a = store.resolve_session_id(id1)
    resolved_b = store.resolve_session_id(id2)

    if not resolved_a:
        click.echo(f"Session '{id1}' not found.")
        return
    if not resolved_b:
        click.echo(f"Session '{id2}' not found.")
        return

    report_a = store.get_triage_report(resolved_a)
    report_b = store.get_triage_report(resolved_b)

    if not report_a:
        click.echo(f"No triage report found for session {resolved_a}")
        return
    if not report_b:
        click.echo(f"No triage report found for session {resolved_b}")
        return

    result = diff_reports(report_a, report_b, resolved_a, resolved_b)

    if fmt == "json":
        click.echo(json_mod.dumps({
            "session_id_a": result.session_id_a,
            "session_id_b": result.session_id_b,
            "risk_score_delta": result.risk_score_delta,
            "finding_diffs": [
                {"status": d.status,
                 "finding_a": d.finding_a.title if d.finding_a else None,
                 "finding_b": d.finding_b.title if d.finding_b else None}
                for d in result.finding_diffs
            ],
            "process_diffs": result.process_diffs,
            "network_diffs": result.network_diffs,
            "summary": result.summary,
        }, indent=2))
    else:
        click.echo(f"\nDiff: {resolved_a} vs {resolved_b}\n")
        click.echo(f"  {result.summary}\n")
        for d in result.finding_diffs:
            title = (d.finding_a or d.finding_b).title
            click.echo(f"  [{d.status.upper():10}] {title}")
        if result.process_diffs.get("added"):
            click.echo(f"\n  New PIDs: {result.process_diffs['added']}")
        if result.process_diffs.get("removed"):
            click.echo(f"  Removed PIDs: {result.process_diffs['removed']}")
        if result.network_diffs.get("added"):
            click.echo(f"  New connections: {result.network_diffs['added']}")
        if result.network_diffs.get("removed"):
            click.echo(f"  Removed connections: {result.network_diffs['removed']}")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
