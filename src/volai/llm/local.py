import openai

from volai.llm.base import LLMBackend, LLMResponse, Message

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "llama3"


class LocalBackend(LLMBackend):
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        **kwargs,
    ) -> None:
        self._model = model or DEFAULT_MODEL
        self._client = openai.AsyncOpenAI(
            api_key=api_key or "not-needed",
            base_url=base_url or DEFAULT_BASE_URL,
        )

    async def send(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        formatted = [{"role": m.role, "content": m.content} for m in messages]
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=formatted,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        choice = response.choices[0]
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model or self._model,
            usage={
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }
            if response.usage
            else None,
        )

    def name(self) -> str:
        return "local"
