# Phase 1: LLM 接入层 + 固件静态提取 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate DeepSeek-V4-Pro and Qwen3.6-Plus as primary LLM providers, and build the Ghidra Headless automation pipeline to extract pseudo-code, call graphs, and strings from firmware binaries.

**Architecture:** Extend the existing `fuzzingbrain/llms/` module with two new providers (DeepSeek, Qwen) and their model definitions. Build a new `fuzzingbrain/static/` package that shells out to `binwalk` for firmware extraction and `Ghidra Headless` for batch decompilation. All integrations are stateless Python wrappers over external CLI tools.

**Tech Stack:** Python 3.10+, litellm (API routing), openai SDK (DeepSeek compatible API), Ghidra Headless (Java), binwalk, pytest + mongomock + unittest.mock

---

## File Structure

### Files to Modify

| File | Change | Responsibility |
|------|--------|---------------|
| `fuzzingbrain/llms/models.py` | Add Provider enums + ModelInfo definitions + fallback chains + task recommendations | Model registry |
| `fuzzingbrain/llms/config.py` | Add API key mappings for DeepSeek/Qwen | Provider authentication |
| `fuzzingbrain/llms/client.py` | Add provider routing in `_get_model_id`, `_get_provider`, `_parse_response` | API dispatch |
| `fuzzingbrain/llms/__init__.py` | Export new model constants | Public API surface |
| `fuzzingbrain/llm_config.yaml` | Add `deepseek`/`qwen` API key slots + default model | User configuration |
| `fuzzingbrain/llms/test.py` | Add DeepSeek/Qwen to connection test | Manual smoke test |

### Files to Create

| File | Responsibility |
|------|---------------|
| `fuzzingbrain/static/__init__.py` | Package init, exports |
| `fuzzingbrain/static/extractor.py` | binwalk wrapper — firmware.bin → extracted filesystem |
| `fuzzingbrain/static/ghidra_analyzer.py` | Ghidra Headless wrapper — binary → functions.json + callgraph.json + strings.json |
| `fuzzingbrain/static/callgraph.py` | Call graph data structures + JSON serialization |
| `fuzzingbrain/static/strings_analyzer.py` | String extraction from .rodata + cross-reference analysis |
| `fuzzingbrain/static/models.py` | Data models: `FunctionInfo`, `BinaryInfo`, `CallGraph`, `StringRef` |
| `tests/test_llms_deepseek_qwen.py` | Tests for new LLM providers |
| `tests/test_static_extractor.py` | Tests for binwalk extraction pipeline |
| `tests/test_static_ghidra.py` | Tests for Ghidra pipeline (mocked subprocess) |

---

### Task 1: Add DEEPSEEK and QWEN to Provider enum

**Files:**
- Modify: `fuzzingbrain/llms/models.py`

- [ ] **Step 1: Add DEEPSEEK and QWEN values to the Provider enum**

Open `fuzzingbrain/llms/models.py`. Find the `Provider` class. Add two new enum values:

```python
class Provider(Enum):
    """LLM Provider"""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    XAI = "xai"
    DEEPSEEK = "deepseek"    # NEW: DeepSeek API (api.deepseek.com)
    QWEN = "qwen"            # NEW: Qwen via DashScope (dashscope.aliyuncs.com)
```

- [ ] **Step 2: Verify the enum is importable**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "from fuzzingbrain.llms.models import Provider; print(Provider.DEEPSEEK.value); print(Provider.QWEN.value)"`

Expected output:
```
deepseek
qwen
```

- [ ] **Step 3: Commit**

```bash
git add fuzzingbrain/llms/models.py
git commit -m "feat(llms): add DEEPSEEK and QWEN to Provider enum"
```

---

### Task 2: Add DeepSeek-V4-Pro and Qwen3.6-Plus ModelInfo definitions

**Files:**
- Modify: `fuzzingbrain/llms/models.py`

- [ ] **Step 1: Add DEEPSEEK_V4_PRO ModelInfo**

In `fuzzingbrain/llms/models.py`, after the Grok section, add:

```python
# =============================================================================
# DeepSeek Models
# =============================================================================

DEEPSEEK_V4_PRO = ModelInfo(
    id="deepseek-v4-pro",
    alias="deepseek-v4-pro",
    provider=Provider.DEEPSEEK,
    name="DeepSeek V4 Pro",
    description="DeepSeek flagship, strong code analysis, 128K context",
    price_input=0.27,       # ¥2/1M tokens (approx $0.27)
    price_output=1.09,      # ¥8/1M tokens (approx $1.09)
    context_window=128_000,
    max_output=32_768,
    supports_vision=False,  # DeepSeek does not support image input
    supports_tools=True,
)

DEEPSEEK_MODELS = [DEEPSEEK_V4_PRO]

# =============================================================================
# Qwen Models
# =============================================================================

QWEN3_6_PLUS = ModelInfo(
    id="qwen3.6-plus",
    alias="qwen3.6-plus",
    provider=Provider.QWEN,
    name="Qwen3.6 Plus",
    description="Alibaba Qwen flagship, fast and affordable for judgment/dedup",
    price_input=0.14,       # ¥1/1M tokens (approx $0.14)
    price_output=0.56,      # ¥4/1M tokens (approx $0.56)
    context_window=128_000,
    max_output=32_768,
    supports_tools=True,
)

QWEN_MODELS = [QWEN3_6_PLUS]
```

- [ ] **Step 2: Update ALL_MODELS list**

Replace the existing `ALL_MODELS` assignment:

```python
ALL_MODELS: List[ModelInfo] = (
    OPENAI_MODELS + CLAUDE_MODELS + GEMINI_MODELS + GROK_MODELS + DEEPSEEK_MODELS + QWEN_MODELS
)
```

- [ ] **Step 3: Verify models are accessible**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.llms.models import DEEPSEEK_V4_PRO, QWEN3_6_PLUS, get_model_by_id, ALL_MODELS
print(DEEPSEEK_V4_PRO.name, DEEPSEEK_V4_PRO.provider)
print(QWEN3_6_PLUS.name, QWEN3_6_PLUS.provider)
print('get_model_by_id:', get_model_by_id('deepseek-v4-pro').name)
print('get_model_by_id alias:', get_model_by_id('qwen3.6-plus').name)
print('models count:', len(ALL_MODELS))
"`

Expected output:
```
DeepSeek V4 Pro Provider.DEEPSEEK
Qwen3.6 Plus Provider.QWEN
get_model_by_id: DeepSeek V4 Pro
get_model_by_id alias: Qwen3.6 Plus
models count: XX (should be previous count + 2)
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/llms/models.py
git commit -m "feat(llms): add DEEPSEEK_V4_PRO and QWEN3_6_PLUS ModelInfo definitions"
```

---

### Task 3: Update fallback chains and task recommendations

**Files:**
- Modify: `fuzzingbrain/llms/models.py`

- [ ] **Step 1: Add DeepSeek and Qwen to FALLBACK_CHAINS**

In `fuzzingbrain/llms/models.py`, add entries to the `FALLBACK_CHAINS` dict:

```python
FALLBACK_CHAINS: Dict[str, List[ModelInfo]] = {
    # ...existing entries...
    # DeepSeek fallbacks -> Qwen, then Claude
    DEEPSEEK_V4_PRO.id: [QWEN3_6_PLUS, CLAUDE_SONNET_4_5, CLAUDE_HAIKU_4_5],
    # Qwen fallbacks -> DeepSeek, then Claude
    QWEN3_6_PLUS.id: [DEEPSEEK_V4_PRO, CLAUDE_SONNET_4_5, CLAUDE_HAIKU_4_5],
}
```

- [ ] **Step 2: Update DEFAULT_FALLBACK to include DeepSeek/Qwen**

Change the assignment:

```python
DEFAULT_FALLBACK = [DEEPSEEK_V4_PRO, QWEN3_6_PLUS, CLAUDE_SONNET_4_5, CLAUDE_HAIKU_4_5]
```

- [ ] **Step 3: Update TASK_RECOMMENDATIONS for DeepSeek-first strategy**

Replace the entire `TASK_RECOMMENDATIONS` dict:

```python
TASK_RECOMMENDATIONS: Dict[TaskType, List[ModelInfo]] = {
    TaskType.CODE_ANALYSIS:     [DEEPSEEK_V4_PRO, QWEN3_6_PLUS, CLAUDE_SONNET_4_5],
    TaskType.CODE_REFACTOR:     [DEEPSEEK_V4_PRO, CLAUDE_SONNET_4_5],
    TaskType.FAST_CODING:       [QWEN3_6_PLUS, DEEPSEEK_V4_PRO, CLAUDE_HAIKU_4_5],
    TaskType.FAST_JUDGMENT:     [QWEN3_6_PLUS, CLAUDE_HAIKU_4_5],
    TaskType.COMPLEX_REASONING: [DEEPSEEK_V4_PRO, CLAUDE_SONNET_4_5],
    TaskType.GENERAL:           [DEEPSEEK_V4_PRO, QWEN3_6_PLUS, CLAUDE_SONNET_4_5],
}
```

- [ ] **Step 4: Verify fallback chains resolve correctly**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.llms.models import DEEPSEEK_V4_PRO, QWEN3_6_PLUS, get_fallback_chain, get_recommended_model, TaskType

# Test fallback chain
chain = get_fallback_chain(DEEPSEEK_V4_PRO)
print('DeepSeek fallbacks:', [m.alias for m in chain])

chain2 = get_fallback_chain(QWEN3_6_PLUS)
print('Qwen fallbacks:', [m.alias for m in chain2])

# Test task recommendation
for task in TaskType:
    model = get_recommended_model(task)
    print(f'{task.value}: {model.alias}')
"`

Expected output:
```
DeepSeek fallbacks: ['qwen3.6-plus', 'claude-sonnet-4-5', 'claude-haiku-4-5']
Qwen fallbacks: ['deepseek-v4-pro', 'claude-sonnet-4-5', 'claude-haiku-4-5']
code_analysis: deepseek-v4-pro
code_refactor: deepseek-v4-pro
fast_coding: qwen3.6-plus
fast_judgment: qwen3.6-plus
complex_reasoning: deepseek-v4-pro
general: deepseek-v4-pro
```

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/llms/models.py
git commit -m "feat(llms): add DeepSeek/Qwen fallback chains and make DeepSeek default for all task types"
```

---

### Task 4: Add API key mappings for DeepSeek and Qwen in LLMConfig

**Files:**
- Modify: `fuzzingbrain/llms/config.py`

- [ ] **Step 1: Add DEEPSEEK and QWEN to provider_key_map**

In `fuzzingbrain/llms/config.py`, find the `get_api_key` method. Add entries to `provider_key_map`:

```python
def get_api_key(self, provider: Provider) -> Optional[str]:
    provider_key_map = {
        Provider.OPENAI: ["openai", "OPENAI"],
        Provider.ANTHROPIC: ["anthropic", "ANTHROPIC"],
        Provider.GOOGLE: ["google", "GOOGLE", "gemini", "GEMINI"],
        Provider.XAI: ["xai", "XAI"],
        Provider.DEEPSEEK: ["deepseek", "DEEPSEEK"],     # NEW
        Provider.QWEN: ["qwen", "QWEN"],                  # NEW
    }
```

- [ ] **Step 2: Add environment variable mappings**

In the same method, find `env_var_map` and add:

```python
    env_var_map = {
        Provider.OPENAI: "OPENAI_API_KEY",
        Provider.ANTHROPIC: "ANTHROPIC_API_KEY",
        Provider.GOOGLE: "GEMINI_API_KEY",
        Provider.XAI: "XAI_API_KEY",
        Provider.DEEPSEEK: "DEEPSEEK_API_KEY",           # NEW
        Provider.QWEN: "DASHSCOPE_API_KEY",               # NEW
    }
```

- [ ] **Step 3: Verify API key resolution**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
import os
os.environ['DEEPSEEK_API_KEY'] = 'sk-test-deepseek-key'
os.environ['DASHSCOPE_API_KEY'] = 'sk-test-qwen-key'

from fuzzingbrain.llms.config import LLMConfig
from fuzzingbrain.llms.models import Provider

config = LLMConfig()
print('DeepSeek key:', config.get_api_key(Provider.DEEPSEEK))
print('Qwen key:', config.get_api_key(Provider.QWEN))
print('Has DeepSeek:', config.has_api_key(Provider.DEEPSEEK))
print('Has Qwen:', config.has_api_key(Provider.QWEN))
"`

Expected output:
```
DeepSeek key: sk-test-deepseek-key
Qwen key: sk-test-qwen-key
Has DeepSeek: True
Has Qwen: True
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/llms/config.py
git commit -m "feat(llms): add DeepSeek and Qwen API key mappings"
```

---

### Task 5: Add provider routing in LLMClient

**Files:**
- Modify: `fuzzingbrain/llms/client.py`

- [ ] **Step 1: Add DEEPSEEK and QWEN cases in `_get_model_id`**

Find the `_get_model_id` method. Add handling before the final `else`:

```python
def _get_model_id(self, model: Union[ModelInfo, str, None]) -> str:
    # ...existing code...
    # In the provider routing section, add:
        elif model.provider == Provider.XAI:
            if model.id.startswith("xai/"):
                return model.id[4:]
            return model.id
        elif model.provider == Provider.DEEPSEEK:          # NEW
            return f"deepseek/{model.id}"
        elif model.provider == Provider.QWEN:              # NEW
            return f"qwen/{model.id}"
        else:
            return model.id
```

- [ ] **Step 2: Add DeepSeek and Qwen detection in `_get_provider`**

Find the `_get_provider` method. Add detection patterns:

```python
def _get_provider(self, model: Union[ModelInfo, str, None]) -> Provider:
    # ...existing code...
    # In the guess-from-model-ID section, add:
        elif "deepseek" in model_lower:                    # NEW
            return Provider.DEEPSEEK
        elif "qwen" in model_lower:                        # NEW
            return Provider.QWEN

        return Provider.OPENAI  # Default
```

- [ ] **Step 3: Add provider string detection in `_parse_response`**

Find the `_parse_response` method. In the provider detection block, add:

```python
    # Determine provider from model ID
    provider = "unknown"
    if "claude" in model_id.lower():
        provider = "anthropic"
    elif "gpt" in model_id.lower() or model_id.startswith("o"):
        provider = "openai"
    elif "gemini" in model_id.lower():
        provider = "google"
    elif "grok" in model_id.lower() or "xai" in model_id.lower():
        provider = "xai"
    elif "deepseek" in model_id.lower():                   # NEW
        provider = "deepseek"
    elif "qwen" in model_id.lower():                       # NEW
        provider = "qwen"
```

- [ ] **Step 4: Verify provider routing**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.llms.client import LLMClient
from fuzzingbrain.llms.models import DEEPSEEK_V4_PRO, QWEN3_6_PLUS

client = LLMClient()

# Test _get_model_id
print('DeepSeek model id:', client._get_model_id(DEEPSEEK_V4_PRO))
print('Qwen model id:', client._get_model_id(QWEN3_6_PLUS))

# Test _get_provider
print('DeepSeek provider:', client._get_provider(DEEPSEEK_V4_PRO))
print('Qwen provider:', client._get_provider(QWEN3_6_PLUS))
print('Guess deepseek string:', client._get_provider('deepseek-v4-pro'))
print('Guess qwen string:', client._get_provider('qwen3.6-plus'))
"`

Expected output:
```
DeepSeek model id: deepseek/deepseek-v4-pro
Qwen model id: qwen/qwen3.6-plus
DeepSeek provider: Provider.DEEPSEEK
Qwen provider: Provider.QWEN
Guess deepseek string: Provider.DEEPSEEK
Guess qwen string: Provider.QWEN
```

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/llms/client.py
git commit -m "feat(llms): add DeepSeek and Qwen provider routing in LLMClient"
```

---

### Task 6: Update __init__.py exports and llm_config.yaml

**Files:**
- Modify: `fuzzingbrain/llms/__init__.py`
- Modify: `fuzzingbrain/llm_config.yaml`

- [ ] **Step 1: Export new model constants in `__init__.py`**

Add to the `from .models import (...)` block:

```python
from .models import (
    # ...existing imports...
    # DeepSeek models
    DEEPSEEK_V4_PRO,
    # Qwen models
    QWEN3_6_PLUS,
    # Model collections
    # ...existing...
    DEEPSEEK_MODELS,
    QWEN_MODELS,
    # ...existing...
)
```

Add to `__all__`:

```python
__all__ = [
    # ...existing...
    # DeepSeek
    "DEEPSEEK_V4_PRO",
    # Qwen
    "QWEN3_6_PLUS",
    # Collections
    "DEEPSEEK_MODELS",
    "QWEN_MODELS",
    # ...existing...
]
```

- [ ] **Step 2: Update `llm_config.yaml` with DeepSeek/Qwen config**

Add to the `api_keys` section:

```yaml
api_keys:
  # ...existing...
  # DeepSeek - https://platform.deepseek.com/
  deepseek: ""

  # Qwen (DashScope) - https://dashscope.console.aliyun.com/
  qwen: ""
```

Change `default_model`:

```yaml
default_model: deepseek-v4-pro
```

Update `task_models` section to use DeepSeek/Qwen:

```yaml
task_models:
  code_analysis: deepseek-v4-pro
  code_refactor: deepseek-v4-pro
  fast_coding: qwen3.6-plus
  fast_judgment: qwen3.6-plus
  complex_reasoning: deepseek-v4-pro
```

- [ ] **Step 3: Verify exports work**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.llms import DEEPSEEK_V4_PRO, QWEN3_6_PLUS, DEEPSEEK_MODELS, QWEN_MODELS, Provider, get_default_config
print('Imports OK')
print('Config default model:', get_default_config().default_model.alias)
print('Available providers:', [p.value for p in get_default_config().get_available_providers()])
"`

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/llms/__init__.py fuzzingbrain/llm_config.yaml
git commit -m "feat(llms): export DeepSeek/Qwen constants and set as default in llm_config.yaml"
```

---

### Task 7: Write unit tests for new LLM providers

**Files:**
- Create: `tests/test_llms_deepseek_qwen.py`

- [ ] **Step 1: Write the test file**

Create `tests/test_llms_deepseek_qwen.py`:

```python
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
        assert len(QWEN_MODELS) == 1


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

    def test_deepseek_falls_back_to_qwen_then_claude(self):
        chain = get_fallback_chain(DEEPSEEK_V4_PRO)
        chain_ids = [m.alias for m in chain]
        assert "qwen3.6-plus" in chain_ids
        assert "claude-sonnet-4-5" in chain_ids

    def test_qwen_falls_back_to_deepseek_then_claude(self):
        chain = get_fallback_chain(QWEN3_6_PLUS)
        chain_ids = [m.alias for m in chain]
        assert "deepseek-v4-pro" in chain_ids
        assert "claude-sonnet-4-5" in chain_ids

    def test_deepseek_is_recommended_for_code_analysis(self):
        model = get_recommended_model(TaskType.CODE_ANALYSIS)
        assert model.alias == "deepseek-v4-pro"

    def test_qwen_is_recommended_for_fast_judgment(self):
        model = get_recommended_model(TaskType.FAST_JUDGMENT)
        assert model.alias == "qwen3.6-plus"


class TestLLMClientProviderRouting:
    """Tests for LLMClient provider routing with new providers."""

    def setup_method(self):
        self.client = LLMClient()

    def test_get_model_id_deepseek(self):
        result = self.client._get_model_id(DEEPSEEK_V4_PRO)
        assert result == "deepseek/deepseek-v4-pro"

    def test_get_model_id_qwen(self):
        result = self.client._get_model_id(QWEN3_6_PLUS)
        assert result == "qwen/qwen3.6-plus"

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
```

- [ ] **Step 2: Run tests to verify they fail/pass appropriately**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && pip install pytest mongomock -q 2>/dev/null; python -m pytest tests/test_llms_deepseek_qwen.py -v`

Expected: All 19 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_llms_deepseek_qwen.py
git commit -m "test(llms): add unit tests for DeepSeek and Qwen provider integration"
```

---

### Task 8: Create static analysis data models

**Files:**
- Create: `fuzzingbrain/static/__init__.py`
- Create: `fuzzingbrain/static/models.py`

- [ ] **Step 1: Create package init**

Create `fuzzingbrain/static/__init__.py`:

```python
"""
FuzzingBrain Static Analysis Module for Firmware

Binwalk extraction + Ghidra Headless decompilation + call graph analysis.
"""

from .models import (
    BinaryInfo,
    FunctionInfo,
    CallGraph,
    CallGraphNode,
    StringRef,
    ExtractResult,
    AnalysisResult,
)

__all__ = [
    "BinaryInfo",
    "FunctionInfo",
    "CallGraph",
    "CallGraphNode",
    "StringRef",
    "ExtractResult",
    "AnalysisResult",
]
```

- [ ] **Step 2: Create data models**

Create `fuzzingbrain/static/models.py`:

```python
"""
Data models for firmware static analysis.

These models represent the output of binwalk extraction and Ghidra decompilation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BinaryInfo:
    """Information about an extracted binary file."""

    path: str                      # Relative path within extracted filesystem
    arch: str                      # Architecture: arm, mips, riscv, x86
    bits: int                      # 32 or 64
    endian: str                    # little or big
    file_type: str                 # web_server, daemon, cgi, library, kernel_module
    stripped: bool                 # Whether symbols are stripped
    entry_point: int               # Entry point address (0 if library)
    sections: List[str] = field(default_factory=list)  # Section names

    @property
    def is_stripped(self) -> bool:
        """Alias for stripped."""
        return self.stripped

    @property
    def arch_tuple(self) -> tuple:
        """Return (arch, bits, endian) as a tuple for QEMU selection."""
        return (self.arch, self.bits, self.endian)


@dataclass
class FunctionInfo:
    """Information about a single function extracted by Ghidra."""

    name: str                      # Function name (FUN_XXXXXXXX if stripped)
    address: int                   # Binary offset address
    pseudo_code: str               # Ghidra decompiled C pseudo-code
    assembly: str                  # Assembly code (optional, can be empty)
    callers: List[str] = field(default_factory=list)    # Function names that call this
    callees: List[str] = field(default_factory=list)    # Function names this calls
    parameters: int = 0            # Inferred parameter count
    complexity: int = 0            # Cyclomatic complexity
    has_unsafe_calls: bool = False # Whether it calls dangerous functions
    dangerous_funcs: List[str] = field(default_factory=list)  # List of dangerous callees
    strings_used: List[str] = field(default_factory=list)     # Strings referenced
    arch: str = ""                 # Architecture
    section: str = ""              # .text, .data, .plt, etc.
    binary_path: str = ""          # Which binary this function belongs to

    @property
    def is_stripped_name(self) -> bool:
        """Check if function name is Ghidra auto-generated (FUN_XXXXXXXX)."""
        return self.name.startswith("FUN_")

    @property
    def dangeous_call_count(self) -> int:
        """Count of dangerous function calls."""
        return len(self.dangerous_funcs)


@dataclass
class CallGraphNode:
    """A node in the call graph."""

    function_name: str
    address: int
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)


@dataclass
class CallGraph:
    """Complete call graph for a binary."""

    binary_path: str
    nodes: Dict[str, CallGraphNode] = field(default_factory=dict)

    def get_callers(self, func_name: str) -> List[str]:
        """Get all callers of a function."""
        node = self.nodes.get(func_name)
        return node.callers if node else []

    def get_callees(self, func_name: str) -> List[str]:
        """Get all callees of a function."""
        node = self.nodes.get(func_name)
        return node.callees if node else []

    def get_call_path(self, from_func: str, to_func: str, max_depth: int = 10) -> Optional[List[str]]:
        """
        Find a call path from from_func to to_func using BFS.
        Returns list of function names representing the path, or None if not found.
        """
        if from_func not in self.nodes or to_func not in self.nodes:
            return None
        if from_func == to_func:
            return [from_func]

        from collections import deque
        queue = deque([(from_func, [from_func])])
        visited = {from_func}

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for callee in self.get_callees(current):
                if callee == to_func:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return None

    @property
    def node_count(self) -> int:
        return len(self.nodes)


@dataclass
class StringRef:
    """A string reference with its location and cross-references."""

    value: str                     # The string value
    address: int                   # Address in .rodata
    referenced_by: List[str] = field(default_factory=list)  # Functions that reference it
    category: str = "other"        # port, url, path, protocol, credential, debug, other

    CATEGORY_KEYWORDS = {
        "port": ["port", ":80", ":443", ":8080", ":23", ":21", ":22"],
        "url": ["http://", "https://", "www.", "/cgi-bin/", "/www/", ".html", ".cgi"],
        "path": ["/etc/", "/tmp/", "/var/", "/proc/", "/sys/", "/dev/"],
        "protocol": ["HTTP", "UPnP", "SSDP", "DNS", "FTP", "Telnet", "SSH", "SNMP"],
        "credential": ["admin", "root", "password", "login", "passwd", "token", "cookie"],
        "debug": ["debug", "test", "TODO", "FIXME", "printf", "assert"],
    }

    def categorize(self) -> str:
        """Auto-categorize this string based on content."""
        lower_val = self.value.lower()
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in lower_val:
                    self.category = category
                    return category
        return "other"


@dataclass
class ExtractResult:
    """Result of firmware extraction via binwalk."""

    firmware_path: str             # Original firmware path
    output_dir: str                # Extraction output directory
    success: bool                  # Whether extraction succeeded
    filesystem_type: str = ""      # squashfs, jffs2, cramfs, etc.
    binaries: List[BinaryInfo] = field(default_factory=list)
    file_count: int = 0
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete result of Ghidra static analysis for one binary."""

    binary: BinaryInfo
    success: bool
    functions: List[FunctionInfo] = field(default_factory=list)
    callgraph: Optional[CallGraph] = None
    strings: List[StringRef] = field(default_factory=list)
    error: Optional[str] = None
    analysis_time_seconds: float = 0.0

    @property
    def function_count(self) -> int:
        return len(self.functions)

    @property
    def stripped_function_count(self) -> int:
        return sum(1 for f in self.functions if f.is_stripped_name)

    @property
    def unsafe_function_count(self) -> int:
        return sum(1 for f in self.functions if f.has_unsafe_calls)
```

- [ ] **Step 3: Verify models import cleanly**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.static.models import BinaryInfo, FunctionInfo, CallGraph, StringRef, ExtractResult, AnalysisResult

# Test basic construction
bi = BinaryInfo(path='bin/httpd', arch='arm', bits=32, endian='little', file_type='web_server', stripped=True, entry_point=0x10000)
print('BinaryInfo OK:', bi.arch_tuple)

fi = FunctionInfo(name='http_cgi_handler', address=0x1234, pseudo_code='void foo() {}', assembly='', callers=['main'], callees=['strcpy', 'sprintf'], parameters=2, has_unsafe_calls=True, dangerous_funcs=['strcpy'])
print('FunctionInfo OK:', fi.is_stripped_name)
print('Dangerous count:', fi.dangeous_call_count)

cg = CallGraph(binary_path='bin/httpd')
print('CallGraph OK:', cg.node_count)

sr = StringRef(value='/cgi-bin/admin', address=0x5000, referenced_by=['http_cgi_handler'])
sr.categorize()
print('StringRef OK:', sr.category)
"`

Expected output:
```
BinaryInfo OK: ('arm', 32, 'little')
FunctionInfo OK: False
Dangerous count: 1
CallGraph OK: 0
StringRef OK: url
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/static/__init__.py fuzzingbrain/static/models.py
git commit -m "feat(static): add data models for firmware static analysis"
```

---

### Task 9: Implement binwalk firmware extractor

**Files:**
- Create: `fuzzingbrain/static/extractor.py`

- [ ] **Step 1: Write the extractor module**

Create `fuzzingbrain/static/extractor.py`:

```python
"""
Firmware Extractor using binwalk.

Extracts firmware binaries: binwalk -e to unpack, then identifies
binaries (ELF), web files, configurations, and shared libraries.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from loguru import logger

from .models import BinaryInfo, ExtractResult


# Known binary file extensions and magic bytes
ELF_MAGIC = b"\x7fELF"
KNOWN_WEB_EXTENSIONS = {".cgi", ".html", ".htm", ".php", ".asp", ".js", ".css"}
KNOWN_CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".xml", ".json", ".yaml", ".yml"}
KNOWN_LIB_PATTERNS = {"lib", ".so"}


class FirmwareExtractor:
    """
    Extract firmware binaries using binwalk.

    Usage:
        extractor = FirmwareExtractor()
        result = extractor.extract("firmware.bin", "output_dir/")
        for binary in result.binaries:
            print(f"{binary.path}: {binary.arch} {binary.file_type}")
    """

    def __init__(self, binwalk_path: str = "binwalk"):
        """
        Args:
            binwalk_path: Path to binwalk executable (default: find in PATH)
        """
        self.binwalk_path = binwalk_path
        self._check_binwalk()

    def _check_binwalk(self) -> None:
        """Verify binwalk is installed and accessible."""
        if not shutil.which(self.binwalk_path):
            logger.warning(
                f"binwalk not found at '{self.binwalk_path}'. "
                "Install with: sudo apt install binwalk"
            )

    def extract(self, firmware_path: str, output_dir: str) -> ExtractResult:
        """
        Extract firmware and identify binaries.

        Args:
            firmware_path: Path to firmware binary file
            output_dir: Directory to extract into

        Returns:
            ExtractResult with list of identified BinaryInfo objects
        """
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error=f"Firmware file not found: {firmware_path}",
            )

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Extracting {fw_path.name} to {output_dir}")

        # Step 1: Run binwalk -e to extract
        try:
            result = subprocess.run(
                [self.binwalk_path, "-e", "-M", "-C", str(out_path), str(fw_path)],
                capture_output=True,
                text=True,
                timeout=600,  # 10 min timeout for large firmware
            )

            if result.returncode != 0 and "No valid signatures" not in result.stderr:
                logger.warning(f"binwalk returned non-zero: {result.returncode}")
                logger.debug(f"binwalk stderr: {result.stderr[:500]}")

        except subprocess.TimeoutExpired:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error="binwalk extraction timed out (10 min)",
            )
        except FileNotFoundError:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error=f"binwalk not found. Install: sudo apt install binwalk",
            )

        # Step 2: Find extracted filesystem
        extracted_dirs = self._find_extracted_dirs(out_path, fw_path.stem)

        if not extracted_dirs:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error="No extracted filesystem found. Firmware may be encrypted or unsupported format.",
            )

        # Step 3: Identify binaries in extracted filesystem
        binaries = []
        file_count = 0
        for ext_dir in extracted_dirs:
            for root, dirs, files in os.walk(ext_dir):
                file_count += len(files)
                for fname in files:
                    fpath = os.path.join(root, fname)
                    binary_info = self._identify_file(fpath, ext_dir)
                    if binary_info:
                        binaries.append(binary_info)

        logger.info(
            f"Extraction complete: {len(binaries)} binaries found "
            f"out of {file_count} total files"
        )

        # Step 4: Detect filesystem type
        fs_type = self._detect_filesystem_type(extracted_dirs)

        return ExtractResult(
            firmware_path=firmware_path,
            output_dir=output_dir,
            success=True,
            filesystem_type=fs_type,
            binaries=binaries,
            file_count=file_count,
        )

    def _find_extracted_dirs(self, base_dir: Path, firmware_stem: str) -> List[str]:
        """
        Find extracted filesystem directories.
        binwalk typically creates: <base>/_<firmware>.extracted/squashfs-root/
        """
        extracted_dirs = []

        # Pattern 1: binwalk's standard output structure
        pattern1 = base_dir / f"_{firmware_stem}.extracted"
        if pattern1.exists():
            # Look for squashfs-root or similar inside
            for item in pattern1.iterdir():
                if item.is_dir() and (
                    "root" in item.name.lower()
                    or "fs" in item.name.lower()
                    or "filesystem" in item.name.lower()
                ):
                    extracted_dirs.append(str(item))
            # If no obvious root, add the .extracted dir itself
            if not extracted_dirs:
                extracted_dirs.append(str(pattern1))

        # Pattern 2: Direct extraction to base_dir
        if not extracted_dirs:
            for item in base_dir.iterdir():
                if item.is_dir() and item.name != f"_{firmware_stem}.extracted":
                    if any(
                        (item / d).exists()
                        for d in ["bin", "sbin", "usr", "etc", "lib"]
                    ):
                        extracted_dirs.append(str(item))

        return extracted_dirs

    def _identify_file(self, filepath: str, base_dir: str) -> Optional[BinaryInfo]:
        """Identify a single file as a binary of interest."""
        fpath = Path(filepath)

        # Skip very small files and non-files
        try:
            if not fpath.is_file() or fpath.stat().st_size < 100:
                return None
        except OSError:
            return None

        # Check for ELF magic
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
        except (IOError, PermissionError):
            return None

        if magic != ELF_MAGIC:
            return None

        # Parse ELF header for architecture info
        arch_info = self._parse_elf_header(filepath)
        if arch_info is None:
            return None

        arch, bits, endian, entry = arch_info

        # Classify file type based on path and name
        rel_path = os.path.relpath(filepath, base_dir)
        file_type = self._classify_binary(rel_path, Path(filepath).name)

        # Check if stripped
        stripped = self._is_stripped(filepath)

        return BinaryInfo(
            path=rel_path,
            arch=arch,
            bits=bits,
            endian=endian,
            file_type=file_type,
            stripped=stripped,
            entry_point=entry,
        )

    def _parse_elf_header(self, filepath: str) -> Optional[tuple]:
        """
        Parse ELF header to extract (arch, bits, endian, entry_point).
        Returns None if file is not a valid ELF or parsing fails.
        """
        try:
            import struct

            with open(filepath, "rb") as f:
                # Read e_ident (16 bytes)
                ident = f.read(16)
                if len(ident) < 16:
                    return None

                # Byte 4: EI_CLASS (1=32-bit, 2=64-bit)
                bits = 32 if ident[4] == 1 else 64 if ident[4] == 2 else 0

                # Byte 5: EI_DATA (1=little, 2=big)
                endian = "little" if ident[5] == 1 else "big" if ident[5] == 2 else "unknown"

                # Bytes 18-19: e_machine
                f.seek(18)
                machine_bytes = f.read(2)
                machine = struct.unpack("<H" if endian == "little" else ">H", machine_bytes)[0]

                # Map e_machine to architecture string
                ARCH_MAP = {
                    0x28: "arm",     # EM_ARM
                    0xB7: "aarch64", # EM_AARCH64
                    0x08: "mips",    # EM_MIPS
                    0x0A: "mips64",  # EM_MIPS_RS3_LE (approximate)
                    0xF3: "riscv",   # EM_RISCV
                    0x03: "x86",     # EM_386
                    0x3E: "x86_64",  # EM_X86_64
                    0x14: "ppc",     # EM_PPC
                    0x15: "ppc64",   # EM_PPC64
                }
                arch = ARCH_MAP.get(machine, f"unknown_{machine:#x}")

                # Read entry point (offset varies by 32/64-bit)
                if bits == 64:
                    f.seek(24)
                    entry_bytes = f.read(8)
                    entry = struct.unpack("<Q" if endian == "little" else ">Q", entry_bytes)[0]
                else:
                    f.seek(24)
                    entry_bytes = f.read(4)
                    entry = struct.unpack("<I" if endian == "little" else ">I", entry_bytes)[0]

                return (arch, bits, endian, entry)

        except Exception:
            return None

    def _classify_binary(self, rel_path: str, filename: str) -> str:
        """Classify a binary by its path and name."""
        rel_lower = rel_path.lower()
        name_lower = filename.lower()

        # CGI scripts
        if ".cgi" in name_lower or "cgi" in rel_lower:
            return "cgi"

        # Web servers
        web_server_names = {"httpd", "nginx", "lighttpd", "apache2", "boa", "goahead", "uhttpd"}
        if any(w in name_lower for w in web_server_names):
            return "web_server"

        # Located in web directories
        if any(d in rel_lower for d in ["/www/", "/cgi-bin/", "/htdocs/", "/web/"]):
            return "cgi" if ".cgi" in name_lower else "web_related"

        # Libraries
        if name_lower.startswith("lib") or ".so" in name_lower or "/lib/" in rel_lower:
            return "library"

        # System daemons in /bin/ or /sbin/ or /usr/
        if any(d in rel_lower for d in ["/bin/", "/sbin/", "/usr/sbin/", "/usr/bin/"]):
            # Further classify by name hints
            if any(d in name_lower for d in ["dns", "dnsmasq"]):
                return "dns_server"
            if any(d in name_lower for d in ["telnet", "telnetd"]):
                return "telnet_server"
            if any(d in name_lower for d in ["upnp", "ssdp"]):
                return "upnp_server"
            return "daemon"

        return "daemon"

    def _is_stripped(self, filepath: str) -> bool:
        """Check if an ELF binary is stripped of symbols."""
        try:
            result = subprocess.run(
                ["file", filepath],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "stripped" in result.stdout.lower()
        except Exception:
            return False

    def _detect_filesystem_type(self, extracted_dirs: List[str]) -> str:
        """Detect the filesystem type of the extracted firmware."""
        for ext_dir in extracted_dirs:
            try:
                result = subprocess.run(
                    ["file", ext_dir],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                stdout = result.stdout.lower()
                if "squashfs" in stdout:
                    return "squashfs"
                if "jffs2" in stdout:
                    return "jffs2"
                if "cramfs" in stdout:
                    return "cramfs"
                if "ext" in stdout and "filesystem" in stdout:
                    return "ext"
            except Exception:
                pass
        return "unknown"


def extract_firmware(firmware_path: str, output_dir: str = None) -> ExtractResult:
    """
    Convenience function to extract firmware.

    Args:
        firmware_path: Path to firmware binary
        output_dir: Output directory (default: ./extracted_<firmware_name>/)

    Returns:
        ExtractResult
    """
    if output_dir is None:
        fw_stem = Path(firmware_path).stem
        output_dir = f"extracted_{fw_stem}"

    extractor = FirmwareExtractor()
    return extractor.extract(firmware_path, output_dir)
```

- [ ] **Step 2: Verify basic import and structure**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.static.extractor import FirmwareExtractor, extract_firmware
# Test that the class initializes (without real binwalk)
extractor = FirmwareExtractor()
print('FirmwareExtractor initialized OK')
print('Methods:', [m for m in dir(extractor) if not m.startswith('_')])
"`

- [ ] **Step 3: Commit**

```bash
git add fuzzingbrain/static/extractor.py
git commit -m "feat(static): implement binwalk firmware extractor with ELF identification"
```

---

### Task 10: Implement call graph data structure

**Files:**
- Create: `fuzzingbrain/static/callgraph.py`

- [ ] **Step 1: Write the callgraph module**

Create `fuzzingbrain/static/callgraph.py`:

```python
"""
Call Graph construction and analysis for firmware binaries.

Builds call graphs from Ghidra-exported function data and provides
path-finding and reachability queries.
"""

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from .models import CallGraph, CallGraphNode, FunctionInfo


class CallGraphBuilder:
    """
    Builds CallGraph from a list of FunctionInfo objects.

    Usage:
        functions: List[FunctionInfo] = [...]  # from Ghidra export
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path="bin/httpd")

        # Query paths
        path = callgraph.get_call_path("main", "strcpy")
    """

    def build(self, functions: List[FunctionInfo], binary_path: str = "") -> CallGraph:
        """
        Build a CallGraph from FunctionInfo list.

        Args:
            functions: List of function info from Ghidra export
            binary_path: Path to the binary for identification

        Returns:
            CallGraph with all nodes and edges populated
        """
        cg = CallGraph(binary_path=binary_path)

        for func in functions:
            node = CallGraphNode(
                function_name=func.name,
                address=func.address,
                callers=list(func.callers),
                callees=list(func.callees),
            )
            cg.nodes[func.name] = node

        logger.debug(f"Built call graph: {cg.node_count} nodes for {binary_path}")
        return cg

    def build_from_json(self, json_path: str, binary_path: str = "") -> CallGraph:
        """
        Build a CallGraph from a Ghidra-exported JSON file.

        Expected JSON format:
        {
          "functions": [
            {
              "name": "main",
              "address": 4096,
              "callers": ["_start"],
              "callees": ["httpd_main", "printf"]
            },
            ...
          ]
        }

        Args:
            json_path: Path to functions.json from Ghidra export
            binary_path: Path to the binary for identification

        Returns:
            CallGraph
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cg = CallGraph(binary_path=binary_path)

        functions = data.get("functions", [])
        for func_data in functions:
            node = CallGraphNode(
                function_name=func_data.get("name", ""),
                address=func_data.get("address", 0),
                callers=func_data.get("callers", []),
                callees=func_data.get("callees", []),
            )
            cg.nodes[node.function_name] = node

        logger.info(f"Loaded call graph from JSON: {cg.node_count} nodes")
        return cg

    def to_json(self, callgraph: CallGraph, output_path: str) -> None:
        """
        Serialize CallGraph to JSON.

        Args:
            callgraph: CallGraph to serialize
            output_path: Output JSON file path
        """
        nodes_data = []
        for name, node in callgraph.nodes.items():
            nodes_data.append({
                "name": node.function_name,
                "address": node.address,
                "callers": node.callers,
                "callees": node.callees,
            })

        data = {
            "binary_path": callgraph.binary_path,
            "node_count": callgraph.node_count,
            "functions": nodes_data,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported call graph to {output_path}: {callgraph.node_count} nodes")


class CallGraphAnalyzer:
    """
    Analyze and query a CallGraph for vulnerability research.

    Provides common queries needed for attack surface analysis:
    - Find all reachable functions from an entry point
    - Find the shortest path between two functions
    - Identify functions that call dangerous sinks
    """

    DANGEROUS_SINKS = {
        # Buffer overflow sinks
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "memcpy", "memmove", "bcopy",
        # Command injection sinks
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "doSystem", "do_system",
        # Format string sinks
        "printf", "fprintf", "snprintf", "syslog", "vprintf",
        # Path traversal sinks
        "fopen", "open", "read", "write", "unlink", "rename",
        # Network sinks
        "recv", "recvfrom", "read", "fread",
        "bind", "listen", "accept",
    }

    def __init__(self, callgraph: CallGraph):
        self.cg = callgraph

    def find_reachable_functions(
        self, entry_function: str, max_depth: int = 20
    ) -> Set[str]:
        """
        Find all functions reachable from an entry point via BFS.

        Args:
            entry_function: Starting function name
            max_depth: Maximum call depth to traverse

        Returns:
            Set of reachable function names
        """
        if entry_function not in self.cg.nodes:
            return set()

        reachable = {entry_function}
        queue = deque([(entry_function, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for callee in self.cg.get_callees(current):
                if callee not in reachable:
                    reachable.add(callee)
                    queue.append((callee, depth + 1))

        return reachable

    def find_dangerous_calls(
        self, entry_function: str
    ) -> List[tuple]:
        """
        Find all dangerous sink calls reachable from an entry point.

        Returns:
            List of (dangerous_sink, call_path) tuples
        """
        reachable = self.find_reachable_functions(entry_function)
        dangerous = []

        for func_name in reachable:
            node = self.cg.nodes.get(func_name)
            if node:
                for callee in node.callees:
                    if callee in self.DANGEROUS_SINKS:
                        path = self.cg.get_call_path(entry_function, func_name)
                        dangerous.append((callee, path or [func_name], func_name))

        return dangerous

    def find_entry_points(self) -> List[str]:
        """
        Find likely entry points — functions with no callers or called by
        well-known start functions.

        Returns:
            List of potential entry point function names
        """
        entry_points = []
        start_functions = {"main", "_start", "entry", "start", "WinMain", "DllMain"}

        for name, node in self.cg.nodes.items():
            # No callers = potential entry
            if not node.callers:
                entry_points.append(name)
            # Called by known start functions
            elif any(c in start_functions for c in node.callers):
                entry_points.append(name)

        return entry_points
```

- [ ] **Step 2: Verify callgraph module**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.static.models import FunctionInfo, CallGraph
from fuzzingbrain.static.callgraph import CallGraphBuilder, CallGraphAnalyzer

# Create test functions
funcs = [
    FunctionInfo(name='main', address=0x1000, pseudo_code='', callers=['_start'], callees=['httpd_main', 'init']),
    FunctionInfo(name='httpd_main', address=0x2000, pseudo_code='', callers=['main'], callees=['process_request']),
    FunctionInfo(name='process_request', address=0x3000, pseudo_code='', callers=['httpd_main'], callees=['strcpy', 'sprintf']),
]

builder = CallGraphBuilder()
cg = builder.build(funcs, binary_path='bin/httpd')
print('Nodes:', cg.node_count)
print('Call path main->strcpy:', cg.get_call_path('main', 'strcpy'))

analyzer = CallGraphAnalyzer(cg)
print('Reachable from main:', analyzer.find_reachable_functions('main'))
print('Dangerous calls:', analyzer.find_dangerous_calls('main'))
print('Entry points:', analyzer.find_entry_points())
"`

Expected output (roughly):
```
Nodes: 3
Call path main->strcpy: ['main', 'httpd_main', 'process_request']
Reachable from main: {'main', 'httpd_main', 'process_request'}
Dangerous calls: [('strcpy', ['main', 'httpd_main', 'process_request'], 'process_request'), ('sprintf', [...], 'process_request')]
Entry points: ['main']
```

- [ ] **Step 3: Commit**

```bash
git add fuzzingbrain/static/callgraph.py
git commit -m "feat(static): implement call graph construction and analysis"
```

---

### Task 11: Write tests for static analysis models and callgraph

**Files:**
- Create: `tests/test_static_models.py`

- [ ] **Step 1: Write tests for static data models**

Create `tests/test_static_models.py`:

```python
"""
Tests for firmware static analysis data models and call graph operations.
"""

import json
import tempfile
import os
from pathlib import Path

from fuzzingbrain.static.models import (
    BinaryInfo,
    FunctionInfo,
    CallGraph,
    CallGraphNode,
    StringRef,
    ExtractResult,
    AnalysisResult,
)
from fuzzingbrain.static.callgraph import CallGraphBuilder, CallGraphAnalyzer


class TestBinaryInfo:
    def test_basic_construction(self):
        bi = BinaryInfo(
            path="bin/httpd",
            arch="arm",
            bits=32,
            endian="little",
            file_type="web_server",
            stripped=True,
            entry_point=0x10000,
        )
        assert bi.path == "bin/httpd"
        assert bi.arch == "arm"
        assert bi.arch_tuple == ("arm", 32, "little")
        assert bi.is_stripped is True

    def test_sections_default(self):
        bi = BinaryInfo(
            path="test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=False, entry_point=0x4000,
        )
        assert bi.sections == []

    def test_sections_provided(self):
        bi = BinaryInfo(
            path="test", arch="arm", bits=64, endian="little",
            file_type="library", stripped=True, entry_point=0,
            sections=[".text", ".data", ".rodata"],
        )
        assert len(bi.sections) == 3


class TestFunctionInfo:
    def test_basic_construction(self):
        fi = FunctionInfo(
            name="http_cgi_handler",
            address=0x1234,
            pseudo_code="void handler() { strcpy(buf, input); }",
            assembly="push {lr}\nbl strcpy",
            callers=["main"],
            callees=["strcpy", "sprintf"],
            parameters=2,
            has_unsafe_calls=True,
            dangerous_funcs=["strcpy"],
        )
        assert fi.name == "http_cgi_handler"
        assert fi.is_stripped_name is False
        assert fi.dangeous_call_count == 1

    def test_stripped_name_detection(self):
        fi = FunctionInfo(
            name="FUN_00001234",
            address=0x1234,
            pseudo_code="",
            has_unsafe_calls=False,
        )
        assert fi.is_stripped_name is True

    def test_defaults(self):
        fi = FunctionInfo(
            name="test_func",
            address=0x100,
            pseudo_code="",
            assembly="",
        )
        assert fi.callers == []
        assert fi.callees == []
        assert fi.parameters == 0
        assert fi.complexity == 0
        assert fi.has_unsafe_calls is False
        assert fi.dangerous_funcs == []
        assert fi.strings_used == []


class TestCallGraph:
    def setup_method(self):
        self.cg = CallGraph(binary_path="bin/httpd")

    def test_empty_graph(self):
        assert self.cg.node_count == 0
        assert self.cg.get_callers("nonexistent") == []
        assert self.cg.get_callees("nonexistent") == []

    def test_add_and_query_nodes(self):
        self.cg.nodes["main"] = CallGraphNode(
            function_name="main",
            address=0x1000,
            callers=["_start"],
            callees=["httpd_main"],
        )
        self.cg.nodes["httpd_main"] = CallGraphNode(
            function_name="httpd_main",
            address=0x2000,
            callers=["main"],
            callees=["process_request"],
        )
        self.cg.nodes["process_request"] = CallGraphNode(
            function_name="process_request",
            address=0x3000,
            callers=["httpd_main"],
            callees=["strcpy"],
        )

        assert self.cg.node_count == 3
        assert self.cg.get_callers("httpd_main") == ["main"]
        assert self.cg.get_callees("main") == ["httpd_main"]

    def test_call_path_direct(self):
        self.cg.nodes["main"] = CallGraphNode(
            "main", 0x1000, callers=[], callees=["target"]
        )
        self.cg.nodes["target"] = CallGraphNode(
            "target", 0x2000, callers=["main"], callees=[]
        )
        path = self.cg.get_call_path("main", "target")
        assert path == ["main", "target"]

    def test_call_path_chain(self):
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=["b"])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=["a"], callees=["c"])
        self.cg.nodes["c"] = CallGraphNode("c", 2, callers=["b"], callees=["d"])
        self.cg.nodes["d"] = CallGraphNode("d", 3, callers=["c"], callees=[])
        path = self.cg.get_call_path("a", "d")
        assert path == ["a", "b", "c", "d"]

    def test_call_path_not_found(self):
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=[])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=[], callees=[])
        path = self.cg.get_call_path("a", "b")
        assert path is None

    def test_call_path_max_depth(self):
        """Verify max_depth prevents infinite loops."""
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=["b"])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=["a"], callees=["a"])  # cycle
        path = self.cg.get_call_path("a", "b", max_depth=1)
        assert path == ["a", "b"]
        path_cycle = self.cg.get_call_path("a", "b", max_depth=0)
        assert path_cycle is None


class TestCallGraphBuilder:
    def test_build_from_functions(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=["_start"], callees=["parse"]),
            FunctionInfo(name="parse", address=0x2000, pseudo_code="",
                        callers=["main"], callees=["strcpy"]),
        ]
        builder = CallGraphBuilder()
        cg = builder.build(funcs, binary_path="bin/test")
        assert cg.node_count == 2
        assert cg.binary_path == "bin/test"
        assert cg.get_call_path("main", "strcpy") == ["main", "parse"]

    def test_build_from_json(self):
        json_data = {
            "functions": [
                {"name": "main", "address": 4096, "callers": ["_start"], "callees": ["foo"]},
                {"name": "foo", "address": 8192, "callers": ["main"], "callees": ["bar"]},
                {"name": "bar", "address": 12288, "callers": ["foo"], "callees": []},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(json_data, f)
            tmp_path = f.name

        try:
            builder = CallGraphBuilder()
            cg = builder.build_from_json(tmp_path, "bin/test")
            assert cg.node_count == 3
            path = cg.get_call_path("main", "bar")
            assert path == ["main", "foo", "bar"]
        finally:
            os.unlink(tmp_path)

    def test_to_json(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=[], callees=["foo"]),
        ]
        builder = CallGraphBuilder()
        cg = builder.build(funcs, binary_path="bin/test")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            builder.to_json(cg, tmp_path)
            with open(tmp_path) as f:
                loaded = json.load(f)
            assert loaded["binary_path"] == "bin/test"
            assert loaded["node_count"] == 1
            assert len(loaded["functions"]) == 1
        finally:
            os.unlink(tmp_path)


class TestCallGraphAnalyzer:
    def setup_method(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=["_start"], callees=["http_handler", "init"]),
            FunctionInfo(name="http_handler", address=0x2000, pseudo_code="",
                        callers=["main"], callees=["parse_request"]),
            FunctionInfo(name="parse_request", address=0x3000, pseudo_code="",
                        callers=["http_handler"], callees=["strcpy", "sprintf"]),
            FunctionInfo(name="init", address=0x4000, pseudo_code="",
                        callers=["main"], callees=[]),
        ]
        builder = CallGraphBuilder()
        self.cg = builder.build(funcs, binary_path="bin/httpd")
        self.analyzer = CallGraphAnalyzer(self.cg)

    def test_find_reachable(self):
        reachable = self.analyzer.find_reachable_functions("main")
        assert "http_handler" in reachable
        assert "parse_request" in reachable
        assert "init" in reachable

    def test_find_reachable_nonexistent(self):
        reachable = self.analyzer.find_reachable_functions("nonexistent")
        assert reachable == set()

    def test_find_dangerous_calls(self):
        dangerous = self.analyzer.find_dangerous_calls("main")
        dangerous_sinks = [d[0] for d in dangerous]
        assert "strcpy" in dangerous_sinks
        assert "sprintf" in dangerous_sinks

    def test_find_entry_points(self):
        entries = self.analyzer.find_entry_points()
        assert "main" in entries  # called by _start


class TestStringRef:
    def test_categorize_url(self):
        sr = StringRef(value="http://192.168.1.1/admin", address=0x5000)
        assert sr.categorize() == "url"

    def test_categorize_port(self):
        sr = StringRef(value="Listening on :80", address=0x6000)
        assert sr.categorize() == "port"

    def test_categorize_credential(self):
        sr = StringRef(value="admin:password123", address=0x7000)
        assert sr.categorize() == "credential"

    def test_categorize_path(self):
        sr = StringRef(value="/etc/shadow", address=0x8000)
        assert sr.categorize() == "path"

    def test_categorize_debug(self):
        sr = StringRef(value="TODO: fix this", address=0x9000)
        assert sr.categorize() == "debug"

    def test_categorize_other(self):
        sr = StringRef(value="some random text", address=0xA000)
        assert sr.categorize() == "other"


class TestExtractResult:
    def test_success(self):
        result = ExtractResult(
            firmware_path="test.bin",
            output_dir="extracted/",
            success=True,
            filesystem_type="squashfs",
            file_count=150,
        )
        assert result.success is True
        assert result.filesystem_type == "squashfs"

    def test_failure(self):
        result = ExtractResult(
            firmware_path="test.bin",
            output_dir="extracted/",
            success=False,
            error="binwalk not found",
        )
        assert result.success is False
        assert result.error == "binwalk not found"


class TestAnalysisResult:
    def test_basic(self):
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=True, entry_point=0x10000,
        )
        result = AnalysisResult(binary=bi, success=True)
        assert result.function_count == 0
        assert result.stripped_function_count == 0

    def test_with_functions(self):
        bi = BinaryInfo(
            path="test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )
        funcs = [
            FunctionInfo(name="FUN_00001000", address=0x1000, pseudo_code="", has_unsafe_calls=True, dangerous_funcs=["strcpy"]),
            FunctionInfo(name="main", address=0x2000, pseudo_code="", has_unsafe_calls=False),
        ]
        result = AnalysisResult(binary=bi, success=True, functions=funcs)
        assert result.function_count == 2
        assert result.stripped_function_count == 1
        assert result.unsafe_function_count == 1
```

- [ ] **Step 2: Run tests**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -m pytest tests/test_static_models.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_static_models.py
git commit -m "test(static): add comprehensive tests for static analysis models and callgraph"
```

---

### Task 12: Implement Ghidra Headless automation

**Files:**
- Create: `fuzzingbrain/static/ghidra_analyzer.py`
- Create: `fuzzingbrain/static/strings_analyzer.py`

- [ ] **Step 1: Write the Ghidra analyzer module**

Create `fuzzingbrain/static/ghidra_analyzer.py`:

```python
"""
Ghidra Headless Automation for Firmware Binary Analysis.

Runs Ghidra in headless mode to decompile firmware binaries and export:
- Function pseudo-code (C)
- Call graph (callers/callees per function)
- String cross-references

Requires Ghidra installation. Set GHIDRA_HOME environment variable.
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from .models import BinaryInfo, FunctionInfo, CallGraph, StringRef, AnalysisResult
from .callgraph import CallGraphBuilder


# Default Ghidra paths
DEFAULT_GHIDRA_HOME = "/opt/ghidra"
GHIDRA_HEADLESS = "support/analyzeHeadless"

# Ghidra export script (Java) — embedded as a resource
GHIDRA_EXPORT_SCRIPT = """
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import com.google.gson.*;

public class ExportFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        String outputPath = getScriptArgs()[0];
        String binaryName = currentProgram.getName();

        JsonObject root = new JsonObject();
        root.addProperty("binary_name", binaryName);
        root.addProperty("arch", currentProgram.getLanguage().getProcessor().toString());
        root.addProperty("bits", currentProgram.getLanguage().getLanguageDescription().getSize());

        // Export functions
        JsonArray functions = new JsonArray();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator iter = funcManager.getFunctions(true);

        int count = 0;
        for (Function func : iter) {
            try {
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().getOffset());

                // Decompile
                DecompileResults decompiled = decompiler.decompileFunction(func, 60, monitor);
                if (decompiled != null && decompiled.decompileCompleted()) {
                    funcObj.addProperty("pseudo_code",
                        decompiled.getDecompiledFunction().getC());
                } else {
                    funcObj.addProperty("pseudo_code",
                        "// Decompilation failed for " + func.getName());
                }

                // Parameters
                funcObj.addProperty("parameter_count", func.getParameterCount());

                // Callers
                JsonArray callers = new JsonArray();
                for (Function caller : func.getCallingFunctions(monitor)) {
                    callers.add(new JsonPrimitive(caller.getName()));
                }
                funcObj.add("callers", callers);

                // Callees
                JsonArray callees = new JsonArray();
                for (Function callee : func.getCalledFunctions(monitor)) {
                    callees.add(new JsonPrimitive(callee.getName()));
                }
                funcObj.add("callees", callees);

                functions.add(funcObj);
                count++;
            } catch (Exception e) {
                // Skip functions that fail to decompile
            }
        }
        root.add("functions", functions);
        root.addProperty("function_count", count);

        // Write output
        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            new GsonBuilder().setPrettyPrinting().create().toJson(root)
        );

        println("Exported " + count + " functions to " + outputPath);
    }
}
"""


class GhidraAnalyzer:
    """
    Ghidra Headless automation for batch binary decompilation.

    Usage:
        analyzer = GhidraAnalyzer(ghidra_home="/opt/ghidra")
        result = analyzer.analyze_binary(
            binary="extracted/bin/httpd",
            binary_info=BinaryInfo(...),
            output_dir="analysis/httpd/",
        )
    """

    def __init__(
        self,
        ghidra_home: Optional[str] = None,
        project_name: str = "firmware_analysis",
        timeout_seconds: int = 1800,  # 30 min per binary
    ):
        """
        Args:
            ghidra_home: Path to Ghidra installation (default: GHIDRA_HOME env or /opt/ghidra)
            project_name: Name for the temporary Ghidra project
            timeout_seconds: Max time per binary analysis
        """
        self.ghidra_home = ghidra_home or os.environ.get("GHIDRA_HOME", DEFAULT_GHIDRA_HOME)
        self.headless = os.path.join(self.ghidra_home, GHIDRA_HEADLESS)
        self.project_name = project_name
        self.timeout = timeout_seconds

        if not os.path.exists(self.headless):
            logger.warning(
                f"Ghidra headless not found at {self.headless}. "
                f"Set GHIDRA_HOME environment variable."
            )

    def analyze_binary(
        self,
        binary_path: str,
        binary_info: BinaryInfo,
        output_dir: str,
    ) -> AnalysisResult:
        """
        Run Ghidra Headless analysis on a single binary.

        Args:
            binary_path: Path to the ELF binary to analyze
            binary_info: BinaryInfo metadata
            output_dir: Directory for analysis output

        Returns:
            AnalysisResult with functions, callgraph, and strings
        """
        start_time = time.time()

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        binary_name = Path(binary_path).name
        functions_json = out_path / f"{binary_name}_functions.json"

        logger.info(f"Analyzing {binary_name} ({binary_info.arch}, {binary_info.bits}-bit)")

        # Validate binary exists
        if not os.path.exists(binary_path):
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error=f"Binary not found: {binary_path}",
            )

        # Step 1: Create Ghidra export Java script
        script_path = self._write_export_script()

        # Step 2: Create temporary Ghidra project directory
        project_dir = out_path / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        # Step 3: Run Ghidra Headless
        success = False
        error_msg = None

        try:
            cmd = [
                self.headless,
                str(project_dir),
                self.project_name,
                "-import", binary_path,
                "-scriptPath", str(script_path.parent),
                "-postScript", script_path.name,
                str(functions_json),
                "-deleteProject",
            ]

            logger.debug(f"Running Ghidra: {' '.join(cmd[:5])}...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**os.environ, "JAVA_OPTS": "-Xmx4G"},  # Increase heap
            )

            if result.returncode != 0:
                error_msg = f"Ghidra returned {result.returncode}: {result.stderr[:500]}"
                logger.error(error_msg)
            elif not functions_json.exists():
                error_msg = f"Functions JSON not created by Ghidra"
                logger.error(error_msg)
            else:
                success = True
                logger.info(
                    f"Ghidra analysis completed for {binary_name} "
                    f"in {time.time() - start_time:.1f}s"
                )

        except subprocess.TimeoutExpired:
            error_msg = f"Ghidra analysis timed out after {self.timeout}s"
            logger.error(error_msg)
        except FileNotFoundError:
            error_msg = f"Ghidra headless not found at {self.headless}"
            logger.error(error_msg)

        # Step 4: Parse results
        if not success:
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error=error_msg,
                analysis_time_seconds=time.time() - start_time,
            )

        functions, callgraph = self._parse_functions_json(
            str(functions_json), binary_info
        )

        return AnalysisResult(
            binary=binary_info,
            success=True,
            functions=functions,
            callgraph=callgraph,
            analysis_time_seconds=time.time() - start_time,
        )

    def _write_export_script(self) -> Path:
        """Write the Ghidra Java export script to a temp file."""
        script_dir = Path(tempfile.mkdtemp(prefix="ghidra_script_"))
        script_file = script_dir / "ExportFunctions.java"

        with open(script_file, "w") as f:
            f.write(GHIDRA_EXPORT_SCRIPT)

        return script_file

    def _parse_functions_json(
        self, json_path: str, binary_info: BinaryInfo
    ) -> tuple:
        """
        Parse Ghidra-exported functions JSON into FunctionInfo list and CallGraph.

        Returns:
            Tuple of (List[FunctionInfo], CallGraph)
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        functions = []
        raw_functions = data.get("functions", [])

        # Known dangerous function names
        DANGEROUS_FUNCTIONS = {
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
            "memcpy", "memmove", "bcopy", "read", "recv", "recvfrom",
            "system", "popen", "execve", "execvp", "execl", "execlp",
            "printf", "fprintf", "snprintf", "vprintf", "syslog",
        }

        for func_data in raw_functions:
            callees = func_data.get("callees", [])
            dangerous = [c for c in callees if c in DANGEROUS_FUNCTIONS]

            fi = FunctionInfo(
                name=func_data.get("name", ""),
                address=func_data.get("address", 0),
                pseudo_code=func_data.get("pseudo_code", ""),
                assembly="",  # Ghidra script above doesn't export assembly
                callers=func_data.get("callers", []),
                callees=callees,
                parameters=func_data.get("parameter_count", 0),
                has_unsafe_calls=len(dangerous) > 0,
                dangerous_funcs=dangerous,
                arch=binary_info.arch,
                binary_path=binary_info.path,
            )
            functions.append(fi)

        # Build call graph
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path=binary_info.path)

        logger.info(
            f"Parsed {len(functions)} functions "
            f"({sum(1 for f in functions if f.has_unsafe_calls)} with unsafe calls)"
        )

        return functions, callgraph
```

- [ ] **Step 2: Write the strings analyzer module**

Create `fuzzingbrain/static/strings_analyzer.py`:

```python
"""
String extraction and analysis from firmware binaries.

Extracts strings from extracted firmware and categorizes them
for attack surface identification.
"""

import re
import subprocess
from pathlib import Path
from typing import List

from loguru import logger

from .models import StringRef


class StringsAnalyzer:
    """
    Extract and categorize strings from binaries.

    Uses the 'strings' command (or Python fallback) to extract printable
    strings, then categorizes them for attack surface analysis.

    Usage:
        analyzer = StringsAnalyzer()
        strings = analyzer.extract_strings("bin/httpd")
        for s in strings:
            print(f"[{s.category}] {s.value}")
    """

    # Minimum string length
    MIN_STRING_LENGTH = 4

    # Regex for interesting strings in firmware
    INTERESTING_PATTERNS = [
        re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP address
        re.compile(r":\d{2,5}"),                                 # Port
        re.compile(r"https?://"),                                # URL
        re.compile(r"/[a-zA-Z0-9/_.-]+"),                        # File path
        re.compile(r"[A-Z_]{3,}"),                               # ALL_CAPS identifiers
        re.compile(r"%[sdXxcnpf]"),                              # Format specifiers
        re.compile(r"password|passwd|admin|root|login|auth", re.I),
        re.compile(r"debug|test|TODO|FIXME", re.I),
    ]

    def __init__(self, strings_binary: str = "strings"):
        """
        Args:
            strings_binary: Path to 'strings' command (default: find in PATH)
        """
        self.strings_binary = strings_binary

    def extract_strings(self, binary_path: str) -> List[StringRef]:
        """
        Extract strings from a binary file and categorize them.

        Args:
            binary_path: Path to binary file

        Returns:
            List of StringRef objects
        """
        raw_strings = self._run_strings(binary_path)
        results = []

        for addr, value in raw_strings:
            # Skip very short strings and pure whitespace
            if len(value) < self.MIN_STRING_LENGTH or value.isspace():
                continue

            ref = StringRef(value=value, address=addr)
            ref.categorize()

            # Only keep interesting strings (reduce noise)
            if self._is_interesting(value):
                results.append(ref)

        logger.debug(f"Extracted {len(results)} interesting strings from {binary_path}")
        return results

    def _run_strings(self, binary_path: str) -> List[tuple]:
        """
        Run 'strings' command and return (offset, string) pairs.
        Falls back to pure Python if 'strings' command not available.
        """
        try:
            result = subprocess.run(
                [self.strings_binary, "-t", "x", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return self._python_strings(binary_path)

            pairs = []
            for line in result.stdout.strip().split("\n"):
                # Format: "<hex_offset> <string>"
                parts = line.split(None, 1)
                if len(parts) == 2:
                    try:
                        addr = int(parts[0], 16)
                        pairs.append((addr, parts[1]))
                    except ValueError:
                        pairs.append((0, parts[1]))

            return pairs

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return self._python_strings(binary_path)

    def _python_strings(self, binary_path: str) -> List[tuple]:
        """Fallback: extract strings using pure Python (slower but no deps)."""
        pairs = []
        current_string = []
        current_offset = 0

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except Exception:
            return pairs

        for i, byte in enumerate(data):
            # Printable ASCII: 0x20-0x7E
            if 0x20 <= byte <= 0x7E:
                if not current_string:
                    current_offset = i
                current_string.append(chr(byte))
            else:
                if len(current_string) >= self.MIN_STRING_LENGTH:
                    pairs.append((current_offset, "".join(current_string)))
                current_string = []

        # Don't forget the last string
        if len(current_string) >= self.MIN_STRING_LENGTH:
            pairs.append((current_offset, "".join(current_string)))

        return pairs

    def _is_interesting(self, value: str) -> bool:
        """Check if a string is interesting for vulnerability analysis."""
        for pattern in self.INTERESTING_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def extract_from_directory(self, dir_path: str, file_pattern: str = "*.so") -> List[StringRef]:
        """
        Extract strings from all matching files in a directory.

        Args:
            dir_path: Directory to search
            file_pattern: Glob pattern for files to analyze

        Returns:
            Combined list of StringRef objects
        """
        all_strings = []
        for file_path in Path(dir_path).rglob(file_pattern):
            if file_path.is_file():
                strings = self.extract_strings(str(file_path))
                all_strings.extend(strings)
        return all_strings
```

- [ ] **Step 3: Verify Ghidra analyzer structure**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
from fuzzingbrain.static.ghidra_analyzer import GhidraAnalyzer
from fuzzingbrain.static.strings_analyzer import StringsAnalyzer

# Test init (will warn about missing Ghidra but shouldn't crash)
analyzer = GhidraAnalyzer()
print('GhidraAnalyzer initialized OK')
print('Ghidra home:', analyzer.ghidra_home)

# Test strings analyzer
sa = StringsAnalyzer()
print('StringsAnalyzer initialized OK')
"`

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/static/ghidra_analyzer.py fuzzingbrain/static/strings_analyzer.py
git commit -m "feat(static): implement Ghidra Headless automation and string extraction"
```

---

### Task 13: Write tests for static analysis modules (mocked subprocess)

**Files:**
- Create: `tests/test_static_ghidra.py`

- [ ] **Step 1: Write tests with mocked Ghidra**

Create `tests/test_static_ghidra.py`:

```python
"""
Tests for Ghidra analyzer and strings analyzer (with mocked subprocess).

No real Ghidra or firmware binaries needed.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from fuzzingbrain.static.models import BinaryInfo, FunctionInfo, AnalysisResult
from fuzzingbrain.static.ghidra_analyzer import GhidraAnalyzer
from fuzzingbrain.static.strings_analyzer import StringsAnalyzer


# Sample Ghidra JSON output to use in mocks
SAMPLE_GHIDRA_OUTPUT = {
    "binary_name": "httpd",
    "arch": "ARM",
    "bits": 32,
    "functions": [
        {
            "name": "main",
            "address": 4096,
            "pseudo_code": "int main(int argc, char **argv) {\n  httpd_main();\n  return 0;\n}",
            "parameter_count": 2,
            "callers": ["_start"],
            "callees": ["httpd_main"],
        },
        {
            "name": "httpd_main",
            "address": 8192,
            "pseudo_code": "void httpd_main(void) {\n  char buf[256];\n  char *input = recv_request();\n  strcpy(buf, input);\n}",
            "parameter_count": 0,
            "callers": ["main"],
            "callees": ["recv_request", "strcpy"],
        },
        {
            "name": "recv_request",
            "address": 16384,
            "pseudo_code": "char * recv_request(void) {\n  return recv(sock, buf, 4096, 0);\n}",
            "parameter_count": 0,
            "callers": ["httpd_main"],
            "callees": ["recv"],
        },
    ],
    "function_count": 3,
}


class TestGhidraAnalyzer:
    """Tests for GhidraAnalyzer with mocked Ghidra subprocess."""

    def test_init_default(self):
        analyzer = GhidraAnalyzer()
        assert analyzer.project_name == "firmware_analysis"
        assert analyzer.timeout == 1800

    def test_init_custom(self):
        analyzer = GhidraAnalyzer(
            ghidra_home="/custom/ghidra",
            timeout_seconds=600,
        )
        assert analyzer.ghidra_home == "/custom/ghidra"
        assert analyzer.timeout == 600

    def test_parse_functions_json(self):
        """Test parsing of Ghidra JSON output into FunctionInfo list."""
        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=True, entry_point=0x10000,
        )

        # Write sample JSON to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(SAMPLE_GHIDRA_OUTPUT, f)
            tmp_path = f.name

        try:
            functions, callgraph = analyzer._parse_functions_json(tmp_path, bi)

            assert len(functions) == 3
            assert functions[0].name == "main"
            assert functions[1].has_unsafe_calls is True  # calls strcpy
            assert "strcpy" in functions[1].dangerous_funcs
            assert callgraph.node_count == 3
            assert callgraph.get_call_path("main", "strcpy") == [
                "main", "httpd_main"
            ]

            # Check function with unsafe call detection
            unsafe_funcs = [f for f in functions if f.has_unsafe_calls]
            assert len(unsafe_funcs) == 1
            assert unsafe_funcs[0].name == "httpd_main"

        finally:
            os.unlink(tmp_path)

    @patch("subprocess.run")
    def test_analyze_binary_success(self, mock_run):
        """Test full analyze_binary flow with mocked Ghidra success."""
        # Mock subprocess.run to simulate Ghidra success
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Exported 3 functions"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=False, entry_point=0x10000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the expected output file
            func_json = Path(tmpdir) / "httpd_functions.json"
            with open(func_json, "w") as f:
                json.dump(SAMPLE_GHIDRA_OUTPUT, f)

            # Create a fake binary file
            fake_binary = Path(tmpdir) / "httpd"
            fake_binary.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100)

            result = analyzer.analyze_binary(
                str(fake_binary), bi, tmpdir
            )

            assert result.success is True
            assert result.function_count == 3
            assert result.callgraph is not None
            assert result.analysis_time_seconds > 0

    @patch("subprocess.run")
    def test_analyze_binary_ghidra_not_found(self, mock_run):
        """Test analyze_binary when Ghidra is not installed."""
        mock_run.side_effect = FileNotFoundError("No such file")

        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = Path(tmpdir) / "test"
            fake_binary.write_bytes(b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 100)

            result = analyzer.analyze_binary(str(fake_binary), bi, tmpdir)

            assert result.success is False
            assert result.error is not None
            assert "not found" in result.error.lower()

    @patch("subprocess.run")
    def test_analyze_binary_timeout(self, mock_run):
        """Test Ghidra timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("ghidra", 1800)

        analyzer = GhidraAnalyzer(timeout_seconds=1)
        bi = BinaryInfo(
            path="bin/test", arch="arm", bits=32, endian="little",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = Path(tmpdir) / "test"
            fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

            result = analyzer.analyze_binary(str(fake_binary), bi, tmpdir)

            assert result.success is False
            assert "timed out" in result.error.lower()


class TestStringsAnalyzer:
    """Tests for StringsAnalyzer."""

    def test_init(self):
        sa = StringsAnalyzer()
        assert sa.MIN_STRING_LENGTH == 4

    def test_python_strings_extraction(self):
        """Test the fallback Python string extraction."""
        sa = StringsAnalyzer()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Create a simple binary with some known strings
            f.write(b"Hello World\x00")
            f.write(b"admin:password123\x00")
            f.write(b"http://192.168.1.1/cgi-bin/admin\x00")
            f.write(b"/etc/shadow\x00")
            f.write(b"xyz\x00")  # Too short, should be filtered
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            assert len(strings) >= 4

            categories = [s.category for s in strings]
            assert "credential" in categories
            assert "url" in categories
            assert "path" in categories

        finally:
            os.unlink(tmp_path)

    def test_string_categorization(self):
        """Test that extract_strings correctly categorizes strings."""
        sa = StringsAnalyzer()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # URL-related
            f.write(b"/cgi-bin/vuln\x00")
            f.write(b"/www/admin.html\x00")
            f.write(b"GET / HTTP/1.1\x00")

            # Port-related
            f.write(b"0.0.0.0:80\x00")
            f.write(b"Listening on port 8080\x00")

            # Protocol-related
            f.write(b"UPnP/1.0\x00")
            f.write(b"M-SEARCH * HTTP/1.1\x00")

            # Debug-related
            f.write(b"TODO: fix buffer size\x00")
            f.write(b"DEBUG: entering handler\x00")

            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)

            categories = {s.category for s in strings}
            assert "url" in categories
            assert "port" in categories
            assert "protocol" in categories
            assert "debug" in categories

        finally:
            os.unlink(tmp_path)

    def test_empty_file(self):
        """Test string extraction on empty file."""
        sa = StringsAnalyzer()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"")
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            assert len(strings) == 0
        finally:
            os.unlink(tmp_path)

    def test_short_strings_filtered(self):
        """Test that strings shorter than MIN_STRING_LENGTH are filtered."""
        sa = StringsAnalyzer()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"ab\x00")   # Too short
            f.write(b"abc\x00")  # Too short
            f.write(b"abcd\x00") # Just right (4 chars)
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            # Only "abcd" should appear
            assert len(strings) == 1
            assert strings[0].value == "abcd"
        finally:
            os.unlink(tmp_path)
```

- [ ] **Step 2: Run tests**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -m pytest tests/test_static_ghidra.py -v`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_static_ghidra.py
git commit -m "test(static): add mocked tests for Ghidra analyzer and strings extraction"
```

---

### Task 14: Run all Phase 1 tests and validate pipeline

- [ ] **Step 1: Run full test suite for Phase 1**

```bash
cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -m pytest tests/test_llms_deepseek_qwen.py tests/test_static_models.py tests/test_static_ghidra.py -v
```

Expected: All tests PASS across all 3 test files.
Expected total: ~50+ tests passing.

- [ ] **Step 2: Run existing tests to verify no regressions**

```bash
cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -m pytest tests/ -v --ignore=tests/test_llms_deepseek_qwen.py --ignore=tests/test_static_models.py --ignore=tests/test_static_ghidra.py -x
```

Expected: All existing tests still PASS. If any fail, investigate and fix before proceeding.

- [ ] **Step 3: Verify Phase 1 module structure**

Run: `cd /home/yxhueimie/Desktop/漏洞大作业/FuzzingBrain-V2-main/FuzzingBrain-V2-main && python -c "
# Full import verification
from fuzzingbrain.llms import (
    Provider, LLMClient, LLMConfig,
    DEEPSEEK_V4_PRO, QWEN3_6_PLUS,
    DEEPSEEK_MODELS, QWEN_MODELS,
    get_model_by_id, get_fallback_chain, get_recommended_model,
    quick_call,
)
from fuzzingbrain.static import (
    BinaryInfo, FunctionInfo, CallGraph, StringRef,
    ExtractResult, AnalysisResult,
)
from fuzzingbrain.static.extractor import FirmwareExtractor
from fuzzingbrain.static.callgraph import CallGraphBuilder, CallGraphAnalyzer
from fuzzingbrain.static.ghidra_analyzer import GhidraAnalyzer
from fuzzingbrain.static.strings_analyzer import StringsAnalyzer

print('All Phase 1 modules import successfully!')
print('DeepSeek model:', DEEPSEEK_V4_PRO.name)
print('Qwen model:', QWEN3_6_PLUS.name)
print('Available static tools:', 'FirmwareExtractor, GhidraAnalyzer, StringsAnalyzer, CallGraphBuilder')
"`

Expected output: All imports succeed with no errors.

- [ ] **Step 4: Commit all remaining changes**

```bash
git add -A
git commit -m "feat(phase1): complete LLM integration + firmware static analysis pipeline

- Add DeepSeek-V4-Pro and Qwen3.6-Plus as primary LLM providers
- Implement binwalk firmware extraction with ELF identification
- Implement Ghidra Headless automation for batch decompilation
- Add call graph construction, path-finding, and dangerous sink analysis
- Add string extraction and categorization for attack surface analysis
- Comprehensive test coverage (50+ tests) with mocked external deps
- Zero breaking changes to existing FuzzingBrain modules

Phase 1 output: firmware.bin -> functions.json + callgraph.json + strings.json"
```

---

## Phase 1 Completion Checklist

After all tasks are complete, verify:

- [ ] `DEEPSEEK_API_KEY` can be set in env and read by LLMConfig
- [ ] `DASHSCOPE_API_KEY` can be set in env and read by LLMConfig
- [ ] `quick_call("Hello")` uses DeepSeek-V4-Pro by default
- [ ] `quick_call("Hello", model=QWEN3_6_PLUS)` uses Qwen
- [ ] DeepSeek failure auto-fallbacks to Qwen (if API keys for both configured)
- [ ] `FirmwareExtractor().extract("firmware.bin")` runs binwalk successfully
- [ ] `GhidraAnalyzer().analyze_binary("httpd", ...)` exports functions.json
- [ ] `CallGraphBuilder().build_from_json("functions.json")` creates valid callgraph
- [ ] `CallGraphAnalyzer(cg).find_dangerous_calls("main")` identifies strcpy/system calls
- [ ] `StringsAnalyzer().extract_strings("httpd")` extracts and categorizes strings
- [ ] All Phase 1 tests pass: `pytest tests/test_llms_deepseek_qwen.py tests/test_static_models.py tests/test_static_ghidra.py -v`
- [ ] Zero regressions in existing tests

---

## Next: Phase 2 Plan

Phase 2 (Attack Surface Identification + Direction Planning) will be planned separately once Phase 1 is complete and verified. It will consume `functions.json`, `callgraph.json`, and `strings.json` and produce `attack_surface.json` and `directions.json` using the AttackSurface Agent (DeepSeek-V4-Pro) and Direction Planner Agent (DeepSeek-V4-Pro).

---

## Plan Self-Review

### 1. Spec coverage
- Phase 1.1-1.4 (LLM module): Tasks 1-6 ✓
- Phase 1.5 (binwalk): Task 9 ✓
- Phase 1.6 (Ghidra): Tasks 10, 12 ✓
- Phase 1.7 (integration test): Task 14 ✓
- Phase 1 testing: Tasks 7, 11, 13 ✓
- Spec acceptance criteria: Task 14 completion checklist ✓

### 2. Placeholder scan
- No TBD/TODO/fill-in-later found
- All code steps have complete implementations
- All test steps have exact test code

### 3. Type consistency
- `ModelInfo` fields consistent between models.py definition and test assertions
- `FunctionInfo`/`CallGraph`/`StringRef` used consistently across tasks 10-13
- `GhidraAnalyzer.analyze_binary()` signature consistent between task 12 and task 13 mocks
- `StringsAnalyzer.extract_strings()` return type consistent with task 10 definition
