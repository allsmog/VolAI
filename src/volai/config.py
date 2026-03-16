from dataclasses import dataclass
import os


@dataclass
class VolAIConfig:
    """Resolved configuration for a VolAI session."""

    provider: str
    model: str | None
    api_key: str | None
    base_url: str | None


_PROVIDER_KEY_ENV = {
    "claude": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "local": None,
}


def resolve_config(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> VolAIConfig:
    """Resolve configuration from explicit args and environment variables.

    Priority: explicit arg > VOLAI_* env var > provider-specific env var.
    """
    if api_key is None:
        provider_env = _PROVIDER_KEY_ENV.get(provider)
        if provider_env:
            api_key = os.environ.get(provider_env)

    return VolAIConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )
