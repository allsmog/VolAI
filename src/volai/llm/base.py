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


class LLMBackend(ABC):
    """Abstract base class for all LLM backends."""

    @abstractmethod
    def __init__(self, model: str | None = None, **kwargs) -> None: ...

    @abstractmethod
    async def send(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send messages and return the LLM response."""
        ...

    @abstractmethod
    def name(self) -> str:
        """Return a human-readable backend name."""
        ...
