import pytest

from volai.llm import get_backend, get_registered_providers
from volai.llm.base import LLMBackend, LLMResponse, Message, _BACKEND_REGISTRY
from volai.llm.claude import ClaudeBackend
from volai.llm.openai import OpenAIBackend
from volai.llm.local import LocalBackend


class TestMessage:
    def test_creation(self):
        msg = Message(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"

    def test_equality(self):
        a = Message(role="system", content="prompt")
        b = Message(role="system", content="prompt")
        assert a == b


class TestLLMResponse:
    def test_creation_with_usage(self):
        resp = LLMResponse(
            content="analysis",
            model="gpt-4o",
            usage={"input_tokens": 100, "output_tokens": 50},
        )
        assert resp.content == "analysis"
        assert resp.model == "gpt-4o"
        assert resp.usage["input_tokens"] == 100

    def test_creation_without_usage(self):
        resp = LLMResponse(content="test", model="llama3")
        assert resp.usage is None


class TestBackendRegistry:
    def test_all_providers_registered(self):
        assert "claude" in _BACKEND_REGISTRY
        assert "openai" in _BACKEND_REGISTRY
        assert "local" in _BACKEND_REGISTRY

    def test_registry_maps_to_correct_classes(self):
        assert _BACKEND_REGISTRY["claude"] is ClaudeBackend
        assert _BACKEND_REGISTRY["openai"] is OpenAIBackend
        assert _BACKEND_REGISTRY["local"] is LocalBackend

    def test_get_registered_providers_returns_sorted(self):
        providers = get_registered_providers()
        assert providers == ["claude", "local", "openai"]

    def test_get_registered_providers_returns_list(self):
        providers = get_registered_providers()
        assert isinstance(providers, list)


class TestSupportsJsonMode:
    def test_local_supports_json_mode(self):
        backend = get_backend("local")
        assert backend.supports_json_mode is True

    def test_openai_supports_json_mode(self):
        backend = get_backend("openai", api_key="test")
        assert backend.supports_json_mode is True

    def test_claude_does_not_support_json_mode(self):
        backend = get_backend("claude", api_key="test")
        assert backend.supports_json_mode is False


class TestGetBackend:
    def test_claude_backend(self):
        backend = get_backend("claude", api_key="test")
        assert isinstance(backend, ClaudeBackend)
        assert backend.name() == "claude"

    def test_openai_backend(self):
        backend = get_backend("openai", api_key="test")
        assert isinstance(backend, OpenAIBackend)
        assert backend.name() == "openai"

    def test_local_backend(self):
        backend = get_backend("local")
        assert isinstance(backend, LocalBackend)
        assert backend.name() == "local"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown LLM provider 'bogus'"):
            get_backend("bogus")

    def test_custom_model(self):
        backend = get_backend("local", model="mistral")
        assert backend._model == "mistral"

    def test_claude_default_model(self):
        backend = get_backend("claude", api_key="test")
        assert backend._model == "claude-sonnet-4-20250514"

    def test_openai_default_model(self):
        backend = get_backend("openai", api_key="test")
        assert backend._model == "gpt-4o"

    def test_local_default_model(self):
        backend = get_backend("local")
        assert backend._model == "llama3"

    def test_local_custom_base_url(self):
        backend = get_backend(
            "local", base_url="http://myserver:8080/v1"
        )
        assert backend._client.base_url.host == "myserver"

    def test_local_default_base_url(self):
        backend = get_backend("local")
        # Ollama default
        assert "11434" in str(backend._client.base_url)

    def test_all_backends_are_llm_backend(self):
        for provider in ["claude", "openai", "local"]:
            kwargs = {"api_key": "test"} if provider != "local" else {}
            backend = get_backend(provider, **kwargs)
            assert isinstance(backend, LLMBackend)
