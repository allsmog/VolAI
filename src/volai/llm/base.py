from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Message:
    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: dict | None = None


_BACKEND_REGISTRY: dict[str, type["LLMBackend"]] = {}


class LLMBackend(ABC):
    """Abstract base class for all LLM backends."""

    provider: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.provider:
            _BACKEND_REGISTRY[cls.provider] = cls

    @property
    def supports_json_mode(self) -> bool:
        """Whether this backend supports constrained JSON output."""
        return False

    @abstractmethod
    def __init__(self, model: str | None = None, **kwargs) -> None: ...

    @abstractmethod
    async def send(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send messages and return the LLM response."""
        ...

    @abstractmethod
    def name(self) -> str:
        """Return a human-readable backend name."""
        ...


def get_registered_providers() -> list[str]:
    """Return sorted list of registered provider names."""
    return sorted(_BACKEND_REGISTRY)
