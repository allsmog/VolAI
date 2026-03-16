from volai.llm.base import LLMBackend, LLMResponse, Message
from volai.llm.claude import ClaudeBackend
from volai.llm.openai import OpenAIBackend
from volai.llm.local import LocalBackend

__all__ = ["LLMBackend", "LLMResponse", "Message", "get_backend"]

_BACKENDS: dict[str, type[LLMBackend]] = {
    "claude": ClaudeBackend,
    "openai": OpenAIBackend,
    "local": LocalBackend,
}


def get_backend(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLMBackend:
    """Instantiate an LLM backend by provider name."""
    if provider not in _BACKENDS:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. "
            f"Choose from: {', '.join(_BACKENDS)}"
        )
    return _BACKENDS[provider](model=model, api_key=api_key, base_url=base_url)
