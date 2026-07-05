"""Tests for PoCAgent."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.verifier.poc_agent import PoCAgent
from fuzzingbrain.verifier.models import PoC, PoCTarget, ExpectedBehavior
from fuzzingbrain.agents.firmware.sp_models import (
    VerifiedSP, AnalystConsensus, ExploitabilityAssessment,
)
from fuzzingbrain.attack_surface.models import AttackSurface, PortInfo
from fuzzingbrain.static.models import FunctionInfo


# -- Mock data helpers -------------------------------------------------------

def make_p0_sp(sp_id="mc-httpd-CWE-121-0001", confidence=0.85,
               function_name="httpd_handler", priority="P0"):
    ea = ExploitabilityAssessment(
        attack_vector="network", difficulty="trivial",
        reliability="reliable", impact="RCE",
    )
    consensus = AnalystConsensus(
        analyst_a="confirmed", analyst_b="confirmed", analyst_c="confirmed",
        votes_confirmed=3, votes_refuted=0, votes_uncertain=0,
        final_vote="confirmed",
    )
    return VerifiedSP(
        sp_id=sp_id, cwe="CWE-121",
        title="Stack Buffer Overflow in HTTP handler",
        description="strcpy without bounds check on user-supplied parameter",
        function_name=function_name,
        vulnerable_code_snippet="char buf[256]; strcpy(buf, user_param);",
        control_flow="httpd_handle_request -> get_param -> strcpy",
        trigger_condition="Send HTTP request with param > 256 bytes",
        root_cause="Missing bounds check before strcpy",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority=priority,
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_p1_sp():
    return make_p0_sp(sp_id="inj-login-CWE-78-0001", priority="P1",
                       function_name="cgi_login", confidence=0.75)


def make_attack_surface():
    return AttackSurface(
        name="HTTP Management Interface",
        category="network_service",
        entry_functions=["httpd_init", "httpd_handle_request"],
        protocol="HTTP",
        port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
        strings_evidence=[":80", "GET ", "POST ", "/cgi-bin/"],
        risks=["buffer_overflow", "command_injection"],
    )


def make_function_info():
    """Ghidra-style FunctionInfo with C pseudo-code."""
    return FunctionInfo(
        name="httpd_handler", address=0x2100,
        pseudo_code="void httpd_handler(int sock) {\n"
                     "  char buf[256];\n"
                     "  char *param = get_param(request, \"url\");\n"
                     "  strcpy(buf, param);\n"
                     "}",
        assembly="",  # Ghidra script doesn't export assembly separately
        callees=["get_param", "strcpy"],
        callers=["httpd_init"],
        strings_used=["GET ", "POST ", "url"],
        dangerous_funcs=["strcpy"],
        has_unsafe_calls=True,
        arch="arm",
    )


def make_function_info_objdump():
    """ObjdumpAnalyzer-style FunctionInfo with MIPS disassembly as pseudo_code."""
    mips_disasm = (
        "004007e0 <main>:\n"
        "  4007e0:       3c1c0005        lui     gp,0x5\n"
        "  4007e4:       279c84f0        addiu   gp,gp,-31504\n"
        "  4007e8:       0399e021        addu    gp,gp,t9\n"
        "  4007ec:       27bdff18        addiu   sp,sp,-232\n"
        "  4007f0:       afbf00e4        sw      ra,228(sp)\n"
        "  4007f4:       afbe00e0        sw      s8,224(sp)\n"
        "  4007f8:       03a0f021        move    s8,sp\n"
        "  4007fc:       afbc0010        sw      gp,16(sp)\n"
        "  400800:       afc400e8        sw      a0,232(s8)\n"
        "  400804:       afc500ec        sw      a1,236(s8)\n"
        "  ...\n"
        "  400830:       8f998040        lw      t9,-32704(gp)\n"
        "  400838:       0320f809        jalr    t9            # strcpy\n"
        "  40083c:       00000000        nop\n"
        "  ...\n"
        "  400884:       0320f809        jalr    t9            # system\n"
    )
    return FunctionInfo(
        name="main", address=0x4007e0,
        pseudo_code=mips_disasm,
        assembly="",  # ObjdumpAnalyzer: pseudo_code IS the disassembly
        callees=["strcpy", "system", "puts", "printf", "memset"],
        callers=["_start"],
        strings_used=["Usage: stack_bof_01 <argument>"],
        dangerous_funcs=["strcpy", "system"],
        has_unsafe_calls=True,
        arch="mips",
    )


def make_function_info_with_assembly():
    """Ghidra-style with separate assembly excerpt (future enhancement)."""
    return FunctionInfo(
        name="httpd_handler", address=0x2100,
        pseudo_code="void httpd_handler(int sock) {\n"
                     "  char buf[256];\n"
                     "  strcpy(buf, param);\n"
                     "}",
        assembly="00402100 <httpd_handler>:\n"
                 "  402100:  addiu  sp,sp,-0x120\n"
                 "  402104:  sw     ra,0x11c(sp)\n"
                 "  402108:  jal    400a30 <strcpy>\n",
        callees=["strcpy"],
        callers=["httpd_init"],
        strings_used=["GET "],
        dangerous_funcs=["strcpy"],
        has_unsafe_calls=True,
        arch="mips",
    )


# -- Mock LLM response ------------------------------------------------------

MOCK_POC_RESPONSE = json.dumps({
    "sp_id": "mc-httpd-CWE-121-0001",
    "poc_type": "http_request",
    "poc_target": {
        "host": "192.168.1.1",
        "port": 80,
        "path": "/cgi-bin/login",
        "method": "POST",
    },
    "poc_content": "POST /cgi-bin/login HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Length: 300\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nurl=AAAA...<300 bytes>",
    "poc_content_hex": "50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 6c 6f 67 69 6e ...",
    "poc_explanation": "The url parameter is copied via strcpy without bounds check. Sending 300 bytes overflows the 256-byte stack buffer, overwriting the return address.",
    "expected_behavior": {
        "expected_crash_type": "SIGSEGV",
        "expected_register_state": "PC=0x41414141",
        "success_indicator": "QEMU exits with signal 11 (SIGSEGV) after processing the POST request",
    },
    "alternate_payloads": [
        {
            "description": "Longer overflow with cyclical pattern for offset detection",
            "poc_content": "POST /cgi-bin/login HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Length: 400\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nurl=AAAABBBBCCCC...<400 bytes cyclical>",
            "poc_content_hex": "",
        },
    ],
})


# -- Tests ------------------------------------------------------------------

class TestPoCAgentInit:
    def test_default_model_is_deepseek(self):
        from fuzzingbrain.llms import CLAUDE_SONNET_4_6, LLMClient, LLMConfig
        # Use clean config so hardcoded fallback is tested, not agent_routing
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        agent = PoCAgent(llm_client=client)
        assert agent.model == CLAUDE_SONNET_4_6

    def test_model_override(self):
        from fuzzingbrain.llms import QWEN3_6_PLUS
        agent = PoCAgent(model=QWEN3_6_PLUS)
        assert agent.model == QWEN3_6_PLUS

    def test_custom_temperature(self):
        agent = PoCAgent(temperature=0.1)
        assert agent.temperature == 0.1


class TestPoCAgentFilterP0:
    def test_filter_p0_only(self):
        agent = PoCAgent()
        sps = [make_p0_sp(), make_p1_sp(), make_p0_sp(sp_id="sp-3")]
        filtered = agent._filter_p0(sps)
        assert len(filtered) == 2
        assert all(sp.priority == "P0" for sp in filtered)

    def test_filter_empty(self):
        agent = PoCAgent()
        assert agent._filter_p0([]) == []

    def test_filter_no_p0(self):
        agent = PoCAgent()
        sps = [make_p1_sp()]
        assert agent._filter_p0(sps) == []


class TestPoCAgentGenerate:
    @pytest.fixture
    def mock_response(self):
        resp = MagicMock()
        resp.content = MOCK_POC_RESPONSE
        return resp

    def test_generate_returns_poc(self, mock_response):
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_response
            agent = PoCAgent()
            poc = agent.generate(
                sp=make_p0_sp(),
                attack_surface=make_attack_surface(),
                function_info=make_function_info(),
            )
        assert isinstance(poc, PoC)
        assert poc.sp_id == "mc-httpd-CWE-121-0001"
        assert poc.poc_type == "http_request"
        assert poc.poc_target.port == 80
        assert len(poc.alternate_payloads) == 1

    def test_generate_prompt_includes_sp_info(self, mock_response):
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            agent = PoCAgent()
            agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            assert "CWE-121" in user_msg or any("CWE-121" in str(m) for m in messages)

    def test_generate_prompt_includes_pseudo_code(self, mock_response):
        """Pseudo-code from FunctionInfo must appear in the LLM prompt."""
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            agent = PoCAgent()
            fi = make_function_info()
            agent.generate(make_p0_sp(), make_attack_surface(), fi)
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            # Verify C pseudo-code is sent to LLM
            assert "void httpd_handler(int sock)" in user_msg
            assert "char buf[256]" in user_msg
            assert "strcpy(buf, param)" in user_msg
            assert "Pseudo-code / Disassembly" in user_msg

    def test_generate_prompt_includes_mips_disasm(self, mock_response):
        """MIPS disassembly from ObjdumpAnalyzer must be sent to LLM."""
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            agent = PoCAgent()
            fi = make_function_info_objdump()
            agent.generate(make_p0_sp(), make_attack_surface(), fi)
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            # Verify MIPS disasm is sent to LLM
            assert "4007e0" in user_msg
            assert "jalr    t9" in user_msg
            assert "addiu   sp,sp,-232" in user_msg
            assert "Pseudo-code / Disassembly" in user_msg
            # ObjdumpAnalyzer doesn't set assembly, so no "Assembly Excerpt"
            assert "Assembly Excerpt" not in user_msg

    def test_generate_prompt_includes_assembly_when_available(self, mock_response):
        """Assembly excerpt should be included when FunctionInfo.assembly is set."""
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            agent = PoCAgent()
            fi = make_function_info_with_assembly()
            agent.generate(make_p0_sp(), make_attack_surface(), fi)
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            # C pseudo-code present
            assert "void httpd_handler(int sock)" in user_msg
            # Assembly excerpt present (separate section)
            assert "Assembly Excerpt" in user_msg
            assert "402100:" in user_msg
            assert "addiu  sp,sp,-0x120" in user_msg

    def test_generate_prompt_no_assembly_when_empty(self, mock_response):
        """When FunctionInfo.assembly is empty, 'Assembly Excerpt' must NOT appear."""
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            agent = PoCAgent()
            fi = make_function_info()  # assembly=""
            agent.generate(make_p0_sp(), make_attack_surface(), fi)
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            # Pseudo-code section exists
            assert "Pseudo-code / Disassembly" in user_msg
            # Assembly excerpt must NOT appear when assembly is empty
            assert "Assembly Excerpt" not in user_msg

    def test_generate_uses_model_kwarg(self, mock_response):
        from fuzzingbrain.llms import CLAUDE_SONNET_4_6
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response
            # config.get_agent_model() returns None with clean mock → hardcoded fallback
            mock_client.config.get_agent_model.return_value = None
            agent = PoCAgent(llm_client=mock_client)
            agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())
            call_kwargs = mock_client.call.call_args[1]
            assert "model" in call_kwargs
            assert call_kwargs["model"] == CLAUDE_SONNET_4_6

    def test_generate_json_parse_error(self):
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            bad_response = MagicMock()
            bad_response.content = "This is not JSON {{{"
            mock_client.call.return_value = bad_response
            agent = PoCAgent()
            with pytest.raises(ValueError, match="Failed to parse"):
                agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())

    def test_generate_with_markdown_fence(self):
        response = MagicMock()
        response.content = '```json\n' + MOCK_POC_RESPONSE + '\n```'
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = response
            agent = PoCAgent()
            poc = agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())
        assert poc.sp_id == "mc-httpd-CWE-121-0001"


class TestPoCAgentGenerateBatch:
    @pytest.fixture
    def mock_response(self):
        resp = MagicMock()
        resp.content = MOCK_POC_RESPONSE
        return resp

    def test_generate_batch_filters_non_p0(self, mock_response):
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_response
            agent = PoCAgent()
            sps = [make_p0_sp(), make_p1_sp()]
            pocs = agent.generate_batch(
                sps,
                [make_attack_surface()],
                {"httpd_handler": make_function_info()},
            )
        assert len(pocs) == 1  # Only P0 generated


class TestPoCAgentFileIO:
    def test_save_and_load(self, tmp_path):
        poc = PoC(sp_id="test-1", poc_type="http_request",
                  poc_target=PoCTarget(port=8080),
                  poc_content="AAAA", poc_explanation="Test overflow")
        agent = PoCAgent()
        output_path = tmp_path / "poc.json"
        agent.save(poc, output_path)
        assert output_path.exists()
        loaded = agent.load(output_path)
        assert loaded.sp_id == "test-1"
        assert loaded.poc_target.port == 8080
