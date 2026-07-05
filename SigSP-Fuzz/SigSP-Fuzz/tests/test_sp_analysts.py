"""Tests for AnalystAgent (sp_analysts.py)."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.static.models import FunctionInfo
from fuzzingbrain.attack_surface.models import AttackSurface, Direction, PortInfo
from fuzzingbrain.agents.firmware.sp_models import FirmwareSP, ExploitabilityAssessment


# ── Helper ─────────────────────────────────────────────────────────────

def make_function(name, address=0x1000, callees=None, strings=None, dangerous=None,
                  pseudo_code=None, callers=None):
    """Helper to create FunctionInfo for tests."""
    return FunctionInfo(
        name=name, address=address,
        pseudo_code=pseudo_code or f"void {name}(void) {{ }}",
        callees=callees or [], strings_used=strings or [],
        dangerous_funcs=dangerous or [], has_unsafe_calls=bool(dangerous),
        callers=callers or [],
    )


# ── Sample data ────────────────────────────────────────────────────────

SAMPLE_DIRECTION = Direction(
    name="HTTP Processing",
    description="HTTP request handling and CGI dispatch",
    category="http_processing",
    entry_functions=["httpd_init", "httpd_handle_request"],
    core_functions=["httpd_handle_request", "cgi_login"],
    big_pool=["httpd_handle_request", "cgi_login", "do_system_cmd"],
    primary_attack_types=["buffer_overflow", "command_injection"],
    priority=5,
)

SAMPLE_ATTACK_SURFACES = [
    AttackSurface(
        name="HTTP Management Interface",
        category="network_service",
        entry_functions=["httpd_init", "httpd_handle_request"],
        protocol="HTTP",
        port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
        risks=["buffer_overflow", "command_injection"],
    ),
    AttackSurface(
        name="Login CGI Handler",
        category="cgi_endpoint",
        entry_functions=["cgi_login"],
        protocol="HTTP",
        risks=["command_injection", "auth_bypass"],
    ),
]

SAMPLE_FUNCTIONS = [
    make_function("httpd_handle_request", 0x2100,
                  callees=["recv", "strcpy", "system", "send"],
                  strings=["GET ", "POST ", "/cgi-bin/"],
                  dangerous=["strcpy", "system"],
                  callers=["httpd_init"]),
    make_function("cgi_login", 0x2200,
                  callees=["recv", "sprintf", "strcmp", "system"],
                  strings=["admin", "password"],
                  dangerous=["sprintf", "system"],
                  callers=["httpd_handle_request"]),
]

# Sample LLM responses
SINGLE_SP_RESPONSE = json.dumps({
    "analyst_type": "memory_corruption",
    "findings": [{
        "cwe": "CWE-121",
        "title": "Stack Buffer Overflow in HTTP parameter parsing",
        "description": "strcpy copies user-controlled request into fixed 256-byte stack buffer",
        "vulnerable_function": "httpd_handle_request",
        "vulnerable_code_snippet": "char buf[256]; strcpy(buf, param);",
        "control_flow": "recv() → get_param() → strcpy()",
        "trigger_condition": "URL parameter longer than 256 bytes",
        "root_cause": "Missing bounds check before strcpy",
        "exploitability_initial": {
            "attack_vector": "network",
            "difficulty": "trivial",
            "reliability": "reliable",
            "impact": "RCE"
        },
        "confidence": 0.85,
        "severity": "critical",
        "supporting_evidence": ["param comes from HTTP request"],
        "potential_false_positive_triggers": [
            "Check if callee internally validates length"
        ]
    }]
})

MULTI_SP_RESPONSE = json.dumps({
    "analyst_type": "memory_corruption",
    "findings": [
        {
            "cwe": "CWE-121",
            "title": "Stack Buffer Overflow in HTTP parameter parsing",
            "description": "strcpy copies user-controlled request into fixed 256-byte stack buffer",
            "vulnerable_function": "httpd_handle_request",
            "vulnerable_code_snippet": "char buf[256]; strcpy(buf, param);",
            "control_flow": "recv() → get_param() → strcpy()",
            "trigger_condition": "URL parameter longer than 256 bytes",
            "root_cause": "Missing bounds check before strcpy",
            "exploitability_initial": {
                "attack_vector": "network", "difficulty": "trivial",
                "reliability": "reliable", "impact": "RCE"
            },
            "confidence": 0.85,
            "severity": "critical",
            "supporting_evidence": ["param comes from HTTP request"],
            "potential_false_positive_triggers": []
        },
        {
            "cwe": "CWE-190",
            "title": "Integer Overflow in size calculation",
            "description": "Multiplication of user-controlled size could overflow",
            "vulnerable_function": "httpd_handle_request",
            "vulnerable_code_snippet": "malloc(count * sizeof(struct))",
            "control_flow": "recv() → malloc()",
            "trigger_condition": "count > 0xFFFFFFFF/sizeof(struct)",
            "root_cause": "Missing overflow check before multiplication",
            "exploitability_initial": {
                "attack_vector": "network", "difficulty": "moderate",
                "reliability": "fragile", "impact": "RCE"
            },
            "confidence": 0.65,
            "severity": "high",
            "supporting_evidence": ["count is user-controlled"],
            "potential_false_positive_triggers": []
        }
    ]
})

EMPTY_FINDINGS_RESPONSE = json.dumps({
    "analyst_type": "memory_corruption",
    "findings": []
})

LOW_CONFIDENCE_RESPONSE = json.dumps({
    "analyst_type": "memory_corruption",
    "findings": [
        {
            "cwe": "CWE-121",
            "title": "Possible buffer overflow",
            "description": "Some description",
            "vulnerable_function": "httpd_handle_request",
            "vulnerable_code_snippet": "strcpy(buf, param)",
            "control_flow": "recv → strcpy",
            "trigger_condition": "long input",
            "root_cause": "no check",
            "confidence": 0.25,
            "severity": "low",
            "supporting_evidence": [],
            "potential_false_positive_triggers": []
        },
        {
            "cwe": "CWE-121",
            "title": "Real buffer overflow",
            "description": "Better description",
            "vulnerable_function": "httpd_handle_request",
            "vulnerable_code_snippet": "strcpy(buf, param)",
            "control_flow": "recv → strcpy",
            "trigger_condition": "long input",
            "root_cause": "no check",
            "confidence": 0.75,
            "severity": "high",
            "supporting_evidence": [],
            "potential_false_positive_triggers": []
        }
    ]
})

MARKDOWN_FENCED_RESPONSE = "```json\n" + SINGLE_SP_RESPONSE + "\n```"


# ── Analyst tests ─────────────────────────────────────────────────────

class TestAnalystAgentInitialization:
    """Tests for AnalystAgent constructor."""

    def test_analyst_a_loads_memory_corruption_prompt(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        prompt = agent._get_system_prompt()
        assert "memory corruption" in prompt.lower() or "Memory Corruption" in prompt
        assert "CWE-121" in prompt or "CWE-122" in prompt

    def test_analyst_b_loads_logic_flaw_prompt(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="logic_flaw")
        prompt = agent._get_system_prompt()
        assert "logic" in prompt.lower()
        assert "CWE-287" in prompt

    def test_analyst_c_loads_injection_prompt(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="injection")
        prompt = agent._get_system_prompt()
        assert "injection" in prompt.lower()
        assert "CWE-78" in prompt

    def test_analyst_a_default_model_is_deepseek(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO, LLMClient, LLMConfig
        # Use clean config so hardcoded fallback is tested, not agent_routing
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        agent = AnalystAgent(llm_client=client, analyst_type="memory_corruption")
        model = agent._get_default_model()
        assert model.id == DEEPSEEK_V4_PRO.id

    def test_analyst_c_default_model_is_deepseek(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO, LLMClient, LLMConfig
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        agent = AnalystAgent(llm_client=client, analyst_type="injection")
        model = agent._get_default_model()
        assert model.id == DEEPSEEK_V4_PRO.id  # was QWEN (broken model ID)

    def test_invalid_analyst_type_raises_error(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        with pytest.raises(ValueError, match="Invalid analyst_type"):
            AnalystAgent(analyst_type="invalid_type")

    def test_custom_model_override(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        from fuzzingbrain.llms import QWEN3_6_PLUS
        agent = AnalystAgent(analyst_type="memory_corruption", model=QWEN3_6_PLUS)
        assert agent.model.id == QWEN3_6_PLUS.id


class TestGenerateSPId:
    """Tests for _generate_sp_id static method."""

    def test_memory_corruption_prefix(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        sp_id = AnalystAgent._generate_sp_id("memory_corruption", "httpd_handler", "CWE-121", 1)
        assert sp_id == "mc-httpd_handler-CWE-121-0001"

    def test_logic_flaw_prefix(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        sp_id = AnalystAgent._generate_sp_id("logic_flaw", "check_auth", "CWE-287", 3)
        assert sp_id == "lf-check_auth-CWE-287-0003"

    def test_injection_prefix(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        sp_id = AnalystAgent._generate_sp_id("injection", "do_system_cmd", "CWE-78", 42)
        assert sp_id == "inj-do_system_cmd-CWE-78-0042"

    def test_handles_cwe_lowercase(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        sp_id = AnalystAgent._generate_sp_id("memory_corruption", "func", "cwe-121", 1)
        assert sp_id == "mc-func-CWE-121-0001"


class TestParseResponse:
    """Tests for _parse_response method."""

    def test_parse_valid_sp_response(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(SINGLE_SP_RESPONSE, "httpd_handle_request")
        assert len(sps) == 1
        sp = sps[0]
        assert isinstance(sp, FirmwareSP)
        assert sp.function_name == "httpd_handle_request"
        assert sp.cwe == "CWE-121"
        assert sp.confidence == 0.85
        assert sp.severity == "critical"
        assert sp.analyst_type == "memory_corruption"
        assert sp.sp_id.startswith("mc-")
        assert sp.exploitability is not None
        assert sp.exploitability.attack_vector == "network"
        assert sp.exploitability.impact == "RCE"

    def test_parse_multiple_sps(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(MULTI_SP_RESPONSE, "httpd_handle_request")
        assert len(sps) == 2
        assert sps[0].sp_id != sps[1].sp_id
        assert sps[0].cwe == "CWE-121"
        assert sps[1].cwe == "CWE-190"

    def test_parse_response_filters_low_confidence(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(LOW_CONFIDENCE_RESPONSE, "httpd_handle_request")
        assert len(sps) == 1
        assert sps[0].confidence == 0.75

    def test_parse_response_with_markdown_fence(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(MARKDOWN_FENCED_RESPONSE, "httpd_handle_request")
        assert len(sps) == 1
        assert sps[0].confidence == 0.85

    def test_parse_empty_findings(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(EMPTY_FINDINGS_RESPONSE, "httpd_handle_request")
        assert len(sps) == 0

    def test_parse_response_without_exploitability(self):
        """SP without exploitability should still parse with exploitability=None."""
        response = json.dumps({
            "analyst_type": "memory_corruption",
            "findings": [{
                "cwe": "CWE-121",
                "title": "Buffer overflow",
                "description": "Some overflow",
                "vulnerable_function": "httpd_handle_request",
                "vulnerable_code_snippet": "strcpy(buf, param)",
                "control_flow": "recv → strcpy",
                "trigger_condition": "long input",
                "root_cause": "no check",
                "confidence": 0.75,
                "severity": "high",
                "supporting_evidence": [],
                "potential_false_positive_triggers": []
            }]
        })
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response(response, "httpd_handle_request")
        assert len(sps) == 1
        assert sps[0].exploitability is None

    def test_parse_response_invalid_json_returns_empty(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent._parse_response("not valid json {{{", "some_func")
        assert len(sps) == 0


class TestBuildFunctionPrompt:
    """Tests for _build_function_prompt."""

    def test_build_function_prompt_includes_context(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        func = SAMPLE_FUNCTIONS[0]
        prompt = agent._build_function_prompt(func, SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)

        assert func.name in prompt
        assert "httpd_handle_request" in prompt
        assert SAMPLE_DIRECTION.name in prompt
        assert "HTTP Processing" in prompt
        assert "strcpy" in prompt or "recv" in prompt

    def test_build_function_prompt_includes_attack_surface_info(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        func = SAMPLE_FUNCTIONS[1]  # cgi_login
        prompt = agent._build_function_prompt(func, SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)

        # Should include attack surfaces that reference cgi_login
        assert "cgi_login" in prompt
        assert "Login CGI Handler" in prompt or "HTTP Management Interface" in prompt
        assert "CGI" in prompt


class TestAnalyze:
    """Tests for the main analyze method."""

    @pytest.fixture
    def mock_llm_response(self):
        resp = MagicMock()
        resp.content = SINGLE_SP_RESPONSE
        return resp

    def test_analyze_with_mocked_llm(self, mock_llm_response):
        with patch("fuzzingbrain.agents.firmware.sp_analysts.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
            agent = AnalystAgent(analyst_type="memory_corruption")
            sps = agent.analyze(SAMPLE_FUNCTIONS, SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)

        # One function returns one SP -> 2 functions = 2 SPs (one per function call)
        assert len(sps) == len(SAMPLE_FUNCTIONS)
        for sp in sps:
            assert isinstance(sp, FirmwareSP)
            assert sp.sp_id.startswith("mc-")
            assert sp.confidence >= 0.3

    def test_analyze_llm_called_with_correct_messages(self, mock_llm_response):
        with patch("fuzzingbrain.agents.firmware.sp_analysts.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
            agent = AnalystAgent(analyst_type="memory_corruption")
            agent.analyze([SAMPLE_FUNCTIONS[0]], SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)

            # Verify the call was made
            assert mock_client.call.called

            # Check messages structure
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            assert len(messages) == 2
            assert messages[0]["role"] == "system"
            assert messages[1]["role"] == "user"
            assert "httpd_handle_request" in messages[1]["content"]

    def test_analyze_passes_model_and_temperature(self, mock_llm_response):
        with patch("fuzzingbrain.agents.firmware.sp_analysts.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
            from fuzzingbrain.llms import DEEPSEEK_V4_PRO
            agent = AnalystAgent(analyst_type="memory_corruption", model=DEEPSEEK_V4_PRO, temperature=0.5)
            agent.analyze([SAMPLE_FUNCTIONS[0]], SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)

            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"].id == DEEPSEEK_V4_PRO.id
            assert call_kwargs["temperature"] == 0.5

    def test_analyze_empty_functions(self):
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        agent = AnalystAgent(analyst_type="memory_corruption")
        sps = agent.analyze([], SAMPLE_DIRECTION, SAMPLE_ATTACK_SURFACES)
        assert len(sps) == 0
