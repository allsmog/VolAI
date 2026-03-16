from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from volai.analysis.chat import run_chat, _run_plugin_in_chat, HELP_TEXT
from volai.config import VolAIConfig
from volai.llm.base import LLMResponse
from volai.volatility.runner import PluginResult


def _make_config():
    return VolAIConfig(
        provider="local", model="llama3", api_key=None, base_url=None
    )


def _make_runner(plugins=None):
    runner = MagicMock()
    runner.list_available_plugins.return_value = plugins or ["windows.pslist.PsList", "windows.netscan.NetScan"]
    return runner


def _make_backend():
    backend = MagicMock()
    backend.name.return_value = "local"
    backend.send = AsyncMock(
        return_value=LLMResponse(content="LLM response text", model="llama3")
    )
    return backend


@pytest.mark.asyncio
class TestRunChat:
    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_quit_exits_cleanly(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        mock_runner_cls.return_value = _make_runner()
        mock_get_backend.return_value = _make_backend()
        mock_prompt.return_value = "/quit"

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        echo_calls = [str(c) for c in mock_echo.call_args_list]
        assert any("Goodbye" in c for c in echo_calls)

    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_help_shows_commands(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        mock_runner_cls.return_value = _make_runner()
        mock_get_backend.return_value = _make_backend()
        mock_prompt.side_effect = ["/help", "/quit"]

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        mock_echo.assert_any_call(HELP_TEXT)

    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_plugins_lists_available(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        plugins = ["windows.pslist.PsList", "windows.netscan.NetScan"]
        mock_runner_cls.return_value = _make_runner(plugins)
        mock_get_backend.return_value = _make_backend()
        mock_prompt.side_effect = ["/plugins", "/quit"]

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        echo_calls = [str(c) for c in mock_echo.call_args_list]
        assert any("windows.pslist.PsList" in c for c in echo_calls)
        assert any("windows.netscan.NetScan" in c for c in echo_calls)

    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_chat_message_sends_to_llm(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        mock_runner_cls.return_value = _make_runner()
        backend = _make_backend()
        mock_get_backend.return_value = backend
        mock_prompt.side_effect = ["What processes are suspicious?", "/quit"]

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        backend.send.assert_called_once()
        echo_calls = [str(c) for c in mock_echo.call_args_list]
        assert any("LLM response text" in c for c in echo_calls)

    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_llm_error_doesnt_crash(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        mock_runner_cls.return_value = _make_runner()
        backend = _make_backend()
        backend.send = AsyncMock(side_effect=ConnectionError("Network down"))
        mock_get_backend.return_value = backend
        mock_prompt.side_effect = ["hello", "/quit"]

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        echo_calls = [str(c) for c in mock_echo.call_args_list]
        assert any("Network down" in c for c in echo_calls)
        # Should still exit cleanly via /quit
        assert any("Goodbye" in c for c in echo_calls)

    @patch("volai.analysis.chat.VolatilityRunner")
    @patch("volai.analysis.chat.get_backend")
    @patch("click.prompt")
    @patch("click.echo")
    async def test_report_command(self, mock_echo, mock_prompt, mock_get_backend, mock_runner_cls):
        mock_runner_cls.return_value = _make_runner()
        backend = _make_backend()
        backend.send = AsyncMock(
            return_value=LLMResponse(content="Summary report here", model="llama3")
        )
        mock_get_backend.return_value = backend
        mock_prompt.side_effect = ["/report", "/quit"]

        await run_chat(_make_config(), Path("/tmp/fake.dmp"))

        backend.send.assert_called_once()
        echo_calls = [str(c) for c in mock_echo.call_args_list]
        assert any("Summary report here" in c for c in echo_calls)


@pytest.mark.asyncio
class TestRunPluginInChat:
    @patch("click.echo")
    async def test_run_plugin_adds_to_context(self, mock_echo):
        runner = _make_runner()
        runner.run_plugin.return_value = PluginResult(
            plugin_name="windows.pslist.PsList",
            columns=["PID", "Name"],
            rows=[{"PID": 4, "Name": "System"}],
            row_count=1,
        )
        conversation = []

        await _run_plugin_in_chat(runner, "windows.pslist.PsList", conversation)

        assert len(conversation) == 1
        assert conversation[0].role == "user"
        assert "windows.pslist.PsList" in conversation[0].content
        assert "1 rows" in conversation[0].content

    @patch("click.echo")
    async def test_run_plugin_failure_in_context(self, mock_echo):
        runner = _make_runner()
        runner.run_plugin.return_value = PluginResult(
            plugin_name="windows.malfind.Malfind",
            error="Unsatisfied requirements",
        )
        conversation = []

        await _run_plugin_in_chat(runner, "windows.malfind.Malfind", conversation)

        assert len(conversation) == 1
        assert conversation[0].role == "user"
        assert "failed" in conversation[0].content
        assert "Unsatisfied requirements" in conversation[0].content

    @patch("click.echo")
    async def test_run_plugin_empty_results_in_context(self, mock_echo):
        runner = _make_runner()
        runner.run_plugin.return_value = PluginResult(
            plugin_name="windows.malfind.Malfind",
            columns=["PID"],
            rows=[],
            row_count=0,
        )
        conversation = []

        await _run_plugin_in_chat(runner, "windows.malfind.Malfind", conversation)

        assert len(conversation) == 1
        assert conversation[0].role == "user"
        assert "no output" in conversation[0].content.lower()
