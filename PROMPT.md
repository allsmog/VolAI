# VolAI — Implementation Prompt

Build VolAI — an AI-powered memory forensics companion for Volatility3. The project should have:

1. **Python CLI (`volai`)** with two modes:
   - `volai analyze <dump>` for automated triage
   - `volai chat <dump>` for interactive investigation

2. **Pluggable LLM backend system** supporting Claude, OpenAI, and local models via a common interface

3. **Volatility3 integration** that runs plugins (pslist, netscan, malfind, etc.) and feeds structured output to the LLM

4. **Structured JSON reporting**

Use Python 3.11+, Click for CLI, and a clean package layout under `src/volai/`.
