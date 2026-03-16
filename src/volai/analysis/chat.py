from __future__ import annotations

import logging
from pathlib import Path

import click

from volai.config import VolAIConfig
from volai.llm import get_backend
from volai.llm.base import Message
from volai.prompts.system import CHAT_SYSTEM_PROMPT
from volai.volatility.runner import VolatilityRunner

logger = logging.getLogger(__name__)

HELP_TEXT = """\
Available commands:
  /run <plugin>  - Run a Volatility3 plugin and add output to context
  /plugins       - List available plugins
  /report        - Generate a summary report of this session
  /help          - Show this help message
  /quit          - Exit the chat session"""


async def run_chat(
    config: VolAIConfig,
    dump_path: Path,
    verbose: bool = False,
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

    click.echo(f"VolAI Chat - investigating: {dump_path}")
    click.echo(f"LLM: {config.provider} ({config.model or 'default'})")
    click.echo(f"Plugins available: {len(available_plugins)}")
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
            await _run_plugin_in_chat(runner, plugin_name, conversation)
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
            response = await backend.send(conversation)
            click.echo(f"\n{response.content}\n")
            conversation.append(
                Message(role="assistant", content=response.content)
            )
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
) -> None:
    """Run a plugin and add its output to the conversation."""
    click.echo(f"Running {plugin_name}...")
    result = runner.run_plugin(plugin_name)

    if result.error:
        click.echo(f"Error: {result.error}")
        return

    if not result.rows:
        click.echo(f"{plugin_name}: No output (0 rows)")
        return

    click.echo(f"{plugin_name}: {result.row_count} rows returned")

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
