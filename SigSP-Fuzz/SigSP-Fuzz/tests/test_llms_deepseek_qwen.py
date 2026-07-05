"""
Tests for DeepSeek and Qwen LLM provider integration.

Tests provider routing, API key resolution, model info validation,
and fallback chain integrity. Uses mocked API calls — no real keys needed.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from fuzzingbrain.llms import (
    LLMClient,
    LLMConfig,
    Provider,
    DEEPSEEK_V4_PRO,
    QWEN3_6_PLUS,
    DEEPSEEK_MODELS,
    QWEN_MODELS,
    get_model_by_id,
    get_fallback_chain,
    get_recommended_model,
    TaskType,
    LLMError,
    LLMAuthError,
)


class TestProviderEnum:
    """Tests for new Provider enum values."""

    def test_deepseek_provider_exists(self):
        assert hasattr(Provider, "DEEPSEEK")
        assert Provider.DEEPSEEK.value == "deepseek"

    def test_qwen_provider_exists(self):
        assert hasattr(Provider, "QWEN")
        assert Provider.QWEN.value == "qwen"


class TestModelInfo:
    """Tests for new ModelInfo definitions."""

    def test_deepseek_v4_pro_info(self):
        model = DEEPSEEK_V4_PRO
        assert model.id == "deepseek-v4-pro"
        assert model.alias == "deepseek-v4-pro"
        assert model.provider == Provider.DEEPSEEK
        assert model.context_window == 128_000
        assert model.max_output == 32_768
        assert model.supports_tools is True
        assert model.supports_vision is False

    def test_qwen3_6_plus_info(self):
        model = QWEN3_6_PLUS
        assert model.id == "qwen3.6-plus"
        assert model.alias == "qwen3.6-plus"
        assert model.provider == Provider.QWEN
        assert model.context_window == 128_000
        assert model.max_output == 32_768
        assert model.supports_tools is True

    def test_get_model_by_id_deepseek(self):
        model = get_model_by_id("deepseek-v4-pro")
        assert model is not None
        assert model.alias == "deepseek-v4-pro"

    def test_get_model_by_id_qwen(self):
        model = get_model_by_id("qwen3.6-plus")
        assert model is not None
        assert model.alias == "qwen3.6-plus"

    def test_model_collections_include_new(self):
        from fuzzingbrain.llms.models import ALL_MODELS
        model_ids = [m.id for m in ALL_MODELS]
        assert "deepseek-v4-pro" in model_ids
        assert "qwen3.6-plus" in model_ids
        assert len(DEEPSEEK_MODELS) == 1
        assert len(QWEN_MODELS) >= 1  # qwen3.6-plus, qwen3.7-plus, etc.


class TestAPIKeyResolution:
    """Tests for API key resolution for new providers."""

    def test_deepseek_api_key_from_env(self):
        os.environ["DEEPSEEK_API_KEY"] = "sk-test-deepseek-123"
        config = LLMConfig()
        key = config.get_api_key(Provider.DEEPSEEK)
        assert key == "sk-test-deepseek-123"
        assert config.has_api_key(Provider.DEEPSEEK) is True
        del os.environ["DEEPSEEK_API_KEY"]

    def test_qwen_api_key_from_env(self):
        os.environ["DASHSCOPE_API_KEY"] = "sk-test-qwen-456"
        config = LLMConfig()
        key = config.get_api_key(Provider.QWEN)
        assert key == "sk-test-qwen-456"
        assert config.has_api_key(Provider.QWEN) is True
        del os.environ["DASHSCOPE_API_KEY"]

    def test_deepseek_api_key_from_config_dict(self):
        config = LLMConfig()
        config.api_keys = {"deepseek": "sk-config-deepseek"}
        key = config.get_api_key(Provider.DEEPSEEK)
        assert key == "sk-config-deepseek"

    def test_qwen_api_key_from_config_dict(self):
        config = LLMConfig()
        config.api_keys = {"qwen": "sk-config-qwen"}
        key = config.get_api_key(Provider.QWEN)
        assert key == "sk-config-qwen"

    def test_missing_keys_return_none(self):
        config = LLMConfig()
        config.api_keys = {}
        # Clear env to ensure no leakage
        for var in ["DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY"]:
            os.environ.pop(var, None)
        assert config.get_api_key(Provider.DEEPSEEK) is None
        assert config.get_api_key(Provider.QWEN) is None
        assert config.has_api_key(Provider.DEEPSEEK) is False
        assert config.has_api_key(Provider.QWEN) is False


class TestFallbackChains:
    """Tests for cross-provider fallback chains."""

    def test_deepseek_falls_back_to_claude(self):
        chain = get_fallback_chain(DEEPSEEK_V4_PRO)
        chain_ids = [m.alias for m in chain]
        # Qwen removed from chain (broken model ID for litellm)
        assert "claude-sonnet-4-5" in chain_ids

    def test_qwen_falls_back_to_claude_directly(self):
        """Qwen now falls back to Claude directly (DeepSeek native API hangs)."""
        chain = get_fallback_chain(QWEN3_6_PLUS)
        chain_ids = [m.alias for m in chain]
        assert "claude-sonnet-4-6" in chain_ids
        assert "claude-sonnet-4-5" in chain_ids

    def test_claude_sonnet_is_recommended_for_code_analysis(self):
        """Claude Sonnet (Anthropic provider) is now primary for code analysis."""
        model = get_recommended_model(TaskType.CODE_ANALYSIS)
        assert model.alias == "claude-sonnet-4-6"

    def test_qwen_is_recommended_for_fast_judgment(self):
        model = get_recommended_model(TaskType.FAST_JUDGMENT)
        assert model.alias == "qwen3.6-plus"


class TestLLMClientProviderRouting:
    """Tests for LLMClient provider routing with new providers."""

    def setup_method(self):
        # Create client with clean config (no custom base URLs)
        # so native provider routing is tested, not openai/ fallback
        from fuzzingbrain.llms.config import LLMConfig
        clean_config = LLMConfig(fallback_enabled=False)
        self.client = LLMClient(config=clean_config)

    def test_get_model_id_deepseek(self):
        result = self.client._get_model_id(DEEPSEEK_V4_PRO)
        assert result == "deepseek/deepseek-v4-pro"

    def test_get_model_id_qwen(self):
        result = self.client._get_model_id(QWEN3_6_PLUS)
        assert result == "qwen/qwen3.6-plus"

    def test_get_model_id_deepseek_with_custom_base(self):
        """When api_bases is set, models route via openai/ provider."""
        from fuzzingbrain.llms.config import LLMConfig
        config = LLMConfig(
            fallback_enabled=False,
            api_bases={"deepseek": "https://custom.endpoint/v1"},
        )
        client = LLMClient(config=config)
        result = client._get_model_id(DEEPSEEK_V4_PRO)
        assert result == "openai/deepseek-v4-pro"

    def test_get_model_id_qwen_with_custom_base(self):
        """When api_bases is set, models route via openai/ provider."""
        from fuzzingbrain.llms.config import LLMConfig
        config = LLMConfig(
            fallback_enabled=False,
            api_bases={"qwen": "https://custom.endpoint/v1"},
        )
        client = LLMClient(config=config)
        result = client._get_model_id(QWEN3_6_PLUS)
        assert result == "openai/qwen3.6-plus"

    def test_get_provider_deepseek(self):
        result = self.client._get_provider(DEEPSEEK_V4_PRO)
        assert result == Provider.DEEPSEEK

    def test_get_provider_qwen(self):
        result = self.client._get_provider(QWEN3_6_PLUS)
        assert result == Provider.QWEN

    def test_get_provider_guess_deepseek(self):
        result = self.client._get_provider("deepseek-v4-pro")
        assert result == Provider.DEEPSEEK

    def test_get_provider_guess_qwen(self):
        result = self.client._get_provider("qwen3.6-plus")
        assert result == Provider.QWEN

    @patch("fuzzingbrain.llms.client.litellm.completion")
    def test_parse_response_detects_deepseek_provider(self, mock_completion):
        """Verify _parse_response sets provider='deepseek' for DeepSeek models."""
        mock_choice = MagicMock()
        mock_choice.message.content = "test response"
        mock_choice.message.tool_calls = None
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15
        mock_completion.return_value = mock_response

        import time
        result = self.client._parse_response(
            mock_response,
            "deepseek/deepseek-v4-pro",
            time.time(),
        )
        assert result.provider == "deepseek"

    @patch("fuzzingbrain.llms.client.litellm.completion")
    def test_parse_response_detects_qwen_provider(self, mock_completion):
        """Verify _parse_response sets provider='qwen' for Qwen models."""
        mock_choice = MagicMock()
        mock_choice.message.content = "test response"
        mock_choice.message.tool_calls = None
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15
        mock_completion.return_value = mock_response

        import time
        result = self.client._parse_response(
            mock_response,
            "qwen/qwen3.6-plus",
            time.time(),
        )
        assert result.provider == "qwen"
