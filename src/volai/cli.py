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

    report = asyncio.run(
        run_triage(config, dump, os_profile, plugin_list, verbose)
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
def chat(
    dump: Path,
    provider: str,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
    verbose: bool,
) -> None:
    """Interactive forensic investigation chat session."""
    _setup_logging(verbose)

    config = resolve_config(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )

    from volai.analysis.chat import run_chat

    asyncio.run(run_chat(config, dump, verbose))


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
