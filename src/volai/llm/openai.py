import openai

from volai.llm.base import LLMBackend, LLMResponse, Message

DEFAULT_MODEL = "gpt-4o"


class OpenAIBackend(LLMBackend):
    provider = "openai"

    @property
    def supports_json_mode(self) -> bool:
        return True

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        **kwargs,
    ) -> None:
        self._model = model or DEFAULT_MODEL
        self._client = openai.AsyncOpenAI(api_key=api_key)

    async def send(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> LLMResponse:
        formatted = [{"role": m.role, "content": m.content} for m in messages]
        kwargs = {}
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=formatted,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
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
        return "openai"
