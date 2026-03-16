from volai.llm.base import LLMBackend, LLMResponse, Message, _BACKEND_REGISTRY, get_registered_providers
# These imports trigger __init_subclass__ registration:
from volai.llm.claude import ClaudeBackend
from volai.llm.openai import OpenAIBackend
from volai.llm.local import LocalBackend

__all__ = [
    "ClaudeBackend",
    "LocalBackend",
    "LLMBackend",
    "LLMResponse",
    "Message",
    "OpenAIBackend",
    "get_backend",
    "get_registered_providers",
]


def get_backend(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLMBackend:
    """Instantiate an LLM backend by provider name."""
    if provider not in _BACKEND_REGISTRY:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. "
            f"Choose from: {', '.join(get_registered_providers())}"
        )
    return _BACKEND_REGISTRY[provider](model=model, api_key=api_key, base_url=base_url)
