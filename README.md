# VolAI

**AI-Powered Memory Forensics Companion for Volatility3**

VolAI combines the power of [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics with LLMs to automate triage analysis and enable interactive investigation of memory dumps.

## Features

- **Automated Triage** (`volai analyze`) — runs Volatility3 plugins in parallel, sends results to an LLM, and produces a structured JSON forensic report with findings, severity ratings, MITRE ATT&CK mappings, and recommendations
- **Interactive Chat** (`volai chat`) — REPL-based investigation session where you can run plugins on-the-fly and discuss findings with an AI forensic analyst
- **Pluggable LLM Backends** — Claude (Anthropic), OpenAI, or any OpenAI-compatible endpoint (Ollama, vLLM, llama.cpp, etc.)
- **Async Plugin Execution** — runs multiple Volatility3 plugins concurrently for faster triage
- **Structured JSON Reports** — Pydantic-validated output with findings, evidence, risk scores, and MITRE ATT&CK technique IDs

## Installation

Requires **Python 3.11+**.

```bash
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Automated Triage

```bash
# Using Claude
volai analyze memory.dmp --provider claude

# Using OpenAI
volai analyze memory.dmp --provider openai --model gpt-4o

# Using a local model (Ollama)
volai analyze memory.dmp --provider local --model llama3

# Save report to file
volai analyze memory.dmp --provider claude -o report.json

# Specify OS profile and custom plugins
volai analyze memory.dmp --provider openai --os-profile windows \
  --plugins "windows.pslist.PsList,windows.netscan.NetScan,windows.malfind.Malfind"
```

### Interactive Chat

```bash
volai chat memory.dmp --provider claude
```

Chat commands:

| Command | Description |
|---|---|
| `/run <plugin>` | Run a Volatility3 plugin and add output to context |
| `/plugins` | List all available Volatility3 plugins |
| `/report` | Generate a summary report of the current session |
| `/help` | Show available commands |
| `/quit` | Exit the chat session |

## Configuration

### LLM Provider (required)

Set via CLI flag or environment variable — no default provider, you must choose one:

| Method | Example |
|---|---|
| CLI flag | `--provider claude` |
| Env var | `VOLAI_PROVIDER=claude` |

### API Keys

Keys are resolved in this order: `--api-key` flag > `VOLAI_API_KEY` env var > provider-specific env var.

| Provider | Provider-specific env var |
|---|---|
| `claude` | `ANTHROPIC_API_KEY` |
| `openai` | `OPENAI_API_KEY` |
| `local` | Not required (most local servers don't need one) |

### Local Models

For local models, point `--base-url` at any OpenAI-compatible endpoint:

```bash
# Ollama (default: http://localhost:11434/v1)
volai analyze memory.dmp --provider local --model llama3

# Custom endpoint
volai analyze memory.dmp --provider local \
  --base-url http://localhost:8080/v1 --model my-model
```

### All Environment Variables

| Variable | Description |
|---|---|
| `VOLAI_PROVIDER` | LLM provider (`claude`, `openai`, `local`) |
| `VOLAI_MODEL` | Model name/ID |
| `VOLAI_API_KEY` | API key (overrides provider-specific vars) |
| `VOLAI_BASE_URL` | Base URL for local/custom endpoints |

## How It Works

### Analyze Mode

```
Memory Dump
    |
    v
VolatilityRunner.run_plugins_async()
    |  (runs plugins in parallel via asyncio.to_thread)
    v
Plugin Results (structured dicts)
    |
    v
build_triage_prompt() -> formatted text
    |
    v
LLM Backend.send() -> JSON response
    |
    v
TriageReport (Pydantic-validated JSON)
```

1. Volatility3 plugins run concurrently against the memory dump
2. Results are formatted into a prompt with table-style output per plugin
3. The LLM analyzes the data and returns a structured JSON report
4. The report includes findings with severity, evidence references, MITRE ATT&CK mappings, risk score, and recommendations

### Chat Mode

An interactive REPL where you direct the investigation. Run plugins with `/run`, ask questions about the output, and the LLM maintains full conversation context. Plugin output is automatically added to the conversation so the LLM can reference it.

## Report Schema

The `analyze` command outputs a JSON report with this structure:

```json
{
  "dump_path": "/path/to/memory.dmp",
  "analysis_timestamp": "2025-01-15T10:30:00Z",
  "os_detected": "Windows 10 x64",
  "llm_provider": "claude",
  "llm_model": "claude-sonnet-4-20250514",
  "summary": "Executive summary of findings...",
  "findings": [
    {
      "title": "Suspicious Process Injection",
      "severity": "critical",
      "description": "Detailed explanation...",
      "evidence": ["PID 1234", "svchost.exe"],
      "mitre_attack": ["T1055"]
    }
  ],
  "risk_score": 85,
  "recommendations": ["Isolate the host", "Capture network logs"],
  "plugin_outputs": [...],
  "errors": [...]
}
```

## Project Structure

```
src/volai/
├── cli.py                    # Click CLI (analyze + chat commands)
├── config.py                 # Configuration resolution
├── llm/
│   ├── base.py               # LLMBackend ABC
│   ├── claude.py             # Anthropic SDK backend
│   ├── openai.py             # OpenAI SDK backend
│   └── local.py              # Generic OpenAI-compatible backend
├── volatility/
│   ├── runner.py             # Plugin execution + async parallel
│   ├── plugins.py            # Triage plugin sets per OS
│   └── formatter.py          # TreeGrid -> dict conversion
├── analysis/
│   ├── triage.py             # Automated triage orchestrator
│   └── chat.py               # Interactive chat REPL
├── prompts/
│   ├── system.py             # System prompt constants
│   └── templates.py          # Prompt formatting
└── report/
    └── models.py             # Pydantic report models
```

## Default Triage Plugins

Plugins are selected by OS profile. If no profile is specified, all are attempted (failures for wrong OS are handled gracefully).

**Windows:** `Info`, `PsList`, `PsTree`, `CmdLine`, `NetScan`, `Malfind`, `DllList`, `Handles`, `FileScan`, `SvcScan`, `Modules`

**Linux:** `PsList`, `PsTree`, `Bash`, `Lsof`, `Lsmod`, `Malfind`, `Sockstat`, `Elfs`, `Maps`

**macOS:** `PsList`, `PsTree`, `Bash`, `Lsof`, `Lsmod`, `Malfind`, `Netstat`, `Mount`

## License

MIT
