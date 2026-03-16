import anthropic

from volai.llm.base import LLMBackend, LLMResponse, Message

DEFAULT_MODEL = "claude-sonnet-4-20250514"


class ClaudeBackend(LLMBackend):
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        **kwargs,
    ) -> None:
        self._model = model or DEFAULT_MODEL
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def send(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        system_text = None
        conversation = []
        for msg in messages:
            if msg.role == "system":
                system_text = msg.content
            else:
                conversation.append({"role": msg.role, "content": msg.content})

        kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": conversation,
        }
        if system_text:
            kwargs["system"] = system_text

        response = await self._client.messages.create(**kwargs)
        return LLMResponse(
            content=response.content[0].text,
            model=response.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )

    def name(self) -> str:
        return "claude"
