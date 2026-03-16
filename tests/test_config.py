import os
from unittest.mock import patch

from volai.config import resolve_config


class TestResolveConfig:
    def test_explicit_args_passed_through(self):
        cfg = resolve_config(
            provider="claude",
            model="claude-opus-4-20250514",
            api_key="sk-test",
            base_url="https://custom.api",
        )
        assert cfg.provider == "claude"
        assert cfg.model == "claude-opus-4-20250514"
        assert cfg.api_key == "sk-test"
        assert cfg.base_url == "https://custom.api"

    def test_none_defaults(self):
        cfg = resolve_config(provider="local")
        assert cfg.provider == "local"
        assert cfg.model is None
        assert cfg.api_key is None
        assert cfg.base_url is None

    def test_claude_falls_back_to_anthropic_env(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            cfg = resolve_config(provider="claude")
            assert cfg.api_key == "sk-ant-test"

    def test_openai_falls_back_to_openai_env(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-oai-test"}):
            cfg = resolve_config(provider="openai")
            assert cfg.api_key == "sk-oai-test"

    def test_local_no_env_fallback(self):
        cfg = resolve_config(provider="local")
        assert cfg.api_key is None

    def test_explicit_key_overrides_env(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "from-env"}):
            cfg = resolve_config(provider="claude", api_key="from-arg")
            assert cfg.api_key == "from-arg"

    def test_unknown_provider_no_crash(self):
        # resolve_config doesn't validate provider, that's get_backend's job
        cfg = resolve_config(provider="unknown-provider")
        assert cfg.provider == "unknown-provider"
