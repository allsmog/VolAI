from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click

from volai.config import VolAIConfig
from volai.llm import get_backend
from volai.llm.base import Message
from volai.prompts.system import CHAT_SYSTEM_PROMPT
from volai.report.models import PluginOutput
from volai.volatility.runner import VolatilityRunner

logger = logging.getLogger(__name__)

HELP_TEXT = """\
Available commands:
  /run <plugin>  - Run a Volatility3 plugin and add output to context
  /plugins       - List available plugins
  /rules         - Run behavioral detection rules against collected data
  /timeline      - Extract timeline from collected plugin data
  /report        - Generate a summary report of this session
  /sessions      - Show current session ID
  /save          - Manually save session checkpoint
  /help          - Show this help message
  /quit          - Exit the chat session"""


async def run_chat(
    config: VolAIConfig,
    dump_path: Path,
    verbose: bool = False,
    store: object | None = None,
    resume_session_id: str | None = None,
) -> None:
    """Run an interactive forensic investigation chat session."""
    backend = get_backend(
        provider=config.provider,
        model=config.model,
        api_key=config.api_key,
        base_url=config.base_url,
    )

    runner = VolatilityRunner(dump_path)
    runner.initialize()

    available_plugins = runner.list_available_plugins()
    plugin_list_str = "\n".join(f"  - {p}" for p in available_plugins)

    system_prompt = CHAT_SYSTEM_PROMPT.format(plugin_list=plugin_list_str)
    conversation: list[Message] = [
        Message(role="system", content=system_prompt)
    ]
    collected_plugins: dict[str, PluginOutput] = {}

    # Session management
    session_id: str | None = None
    if store is not None:
        try:
            from volai.storage.store import SessionStore
            if isinstance(store, SessionStore):
                if resume_session_id:
                    resolved = store.resolve_session_id(resume_session_id)
                    if resolved:
                        session_id = resolved
                        messages = store.get_messages(session_id)
                        for msg in messages:
                            conversation.append(Message(role=msg["role"], content=msg["content"]))
                        click.echo(f"Resumed session: {session_id} ({len(messages)} messages)")
                    else:
                        click.echo(f"Session '{resume_session_id}' not found, starting new session")
                if not session_id:
                    session = store.create_session(
                        dump_path=str(dump_path),
                        session_type="chat",
                        provider=config.provider,
                        model=config.model or "unknown",
                    )
                    session_id = session["id"]
        except Exception as e:
            logger.warning("Session init failed: %s", e)

    click.echo(f"VolAI Chat - investigating: {dump_path}")
    click.echo(f"LLM: {config.provider} ({config.model or 'default'})")
    click.echo(f"Plugins available: {len(available_plugins)}")
    if session_id:
        click.echo(f"Session: {session_id}")
    click.echo('Type /help for commands, /quit to exit.\n')

    while True:
        try:
            user_input = click.prompt("volai", prompt_suffix="> ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("\nGoodbye.")
            break

        if not user_input:
            continue

        if user_input in ("/quit", "/exit"):
            click.echo("Goodbye.")
            break

        if user_input == "/help":
            click.echo(HELP_TEXT)
            continue

        if user_input == "/plugins":
            click.echo("Available plugins:")
            for p in available_plugins:
                click.echo(f"  {p}")
            continue

        if user_input.startswith("/run "):
            plugin_name = user_input[5:].strip()
            await _run_plugin_in_chat(runner, plugin_name, conversation, collected_plugins)
            continue

        if user_input == "/rules":
            if not collected_plugins:
                click.echo("No plugin data collected yet. Run some plugins first.")
            else:
                from volai.rules.behavioral import run_behavioral_rules
                rule_findings = run_behavioral_rules(collected_plugins)
                if not rule_findings:
                    click.echo("No behavioral rule findings.")
                else:
                    click.echo(f"\nBehavioral Rules: {len(rule_findings)} findings\n")
                    for rf in rule_findings:
                        click.echo(f"  [{rf.rule_id}] {rf.title} ({rf.severity})")
                        click.echo(f"    {rf.description}")
                    click.echo()
            continue

        if user_input == "/timeline":
            if not collected_plugins:
                click.echo("No plugin data collected yet. Run some plugins first.")
            else:
                from volai.analysis.timeline import extract_timeline
                outputs = list(collected_plugins.values())
                timeline = extract_timeline(outputs, str(dump_path))
                if not timeline.events:
                    click.echo("No timeline events extracted.")
                else:
                    click.echo(f"\nTimeline: {timeline.event_count} events\n")
                    for ev in timeline.events[:50]:
                        click.echo(f"  [{ev.timestamp}] {ev.event_type}: {ev.description}")
                    if timeline.event_count > 50:
                        click.echo(f"  ... ({timeline.event_count - 50} more events)")
                    click.echo()
            continue

        if user_input == "/sessions":
            if session_id:
                click.echo(f"Current session: {session_id}")
            else:
                click.echo("No active session (persistence disabled)")
            continue

        if user_input == "/save":
            if store is not None and session_id:
                click.echo(f"Session {session_id} saved.")
            else:
                click.echo("Persistence not enabled.")
            continue

        if user_input == "/report":
            conversation.append(
                Message(
                    role="user",
                    content="Please generate a comprehensive summary report "
                    "of our investigation so far, including all findings, "
                    "indicators of compromise, and recommended next steps.",
                )
            )
            try:
                response = await backend.send(conversation)
                click.echo(f"\n{response.content}\n")
                conversation.append(
                    Message(role="assistant", content=response.content)
                )
            except Exception as e:
                click.echo(f"Error: {e}")
                conversation.pop()  # remove the failed user message
            continue

        # Regular chat message
        conversation.append(Message(role="user", content=user_input))

        try:
            response = await backend.send(conversation)
            click.echo(f"\n{response.content}\n")
            conversation.append(
                Message(role="assistant", content=response.content)
            )
        except Exception as e:
            click.echo(f"Error: {e}")
            conversation.pop()  # remove the failed user message


async def _run_plugin_in_chat(
    runner: VolatilityRunner,
    plugin_name: str,
    conversation: list[Message],
    collected_plugins: dict[str, PluginOutput] | None = None,
) -> None:
    """Run a plugin and add its output to the conversation."""
    click.echo(f"Running {plugin_name}...")
    result = await asyncio.to_thread(runner.run_plugin, plugin_name)

    if result.error:
        click.echo(f"Error: {result.error}")
        conversation.append(
            Message(role="user", content=f"I ran plugin {plugin_name} but it failed: {result.error}")
        )
        return

    if not result.rows:
        click.echo(f"{plugin_name}: No output (0 rows)")
        conversation.append(
            Message(role="user", content=f"I ran plugin {plugin_name} but it returned no output (0 rows).")
        )
        return

    click.echo(f"{plugin_name}: {result.row_count} rows returned")

    # Track collected plugin output
    if collected_plugins is not None:
        collected_plugins[plugin_name] = PluginOutput(
            plugin_name=result.plugin_name,
            columns=result.columns,
            rows=result.rows,
            row_count=result.row_count,
            error=result.error,
        )

    # Format output for the conversation
    header = " | ".join(result.columns)
    lines = [header, "-" * len(header)]
    rows = result.rows[:200]
    for row in rows:
        line = " | ".join(
            str(row.get(col, "")) for col in result.columns
        )
        lines.append(line)
    if result.row_count > 200:
        lines.append(f"... ({result.row_count - 200} more rows truncated)")

    output_text = (
        f"Plugin output for {plugin_name} "
        f"({result.row_count} rows):\n\n" + "\n".join(lines)
    )
    conversation.append(Message(role="user", content=output_text))
