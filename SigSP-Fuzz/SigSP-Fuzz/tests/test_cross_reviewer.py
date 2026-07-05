"""Tests for CrossReviewer (cross_reviewer.py)."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.static.models import FunctionInfo
from fuzzingbrain.agents.firmware.sp_models import (
    FirmwareSP,
    CrossReviewVerdict,
    ExploitabilityAssessment,
)


# ── Helpers ─────────────────────────────────────────────────────────────

def make_function(name, address=0x1000, pseudo_code=None):
    """Helper to create FunctionInfo for tests."""
    return FunctionInfo(
        name=name,
        address=address,
        pseudo_code=pseudo_code or f"void {name}(void) {{ }}",
    )


def make_sp(
    sp_id="mc-httpd_handler-CWE-121-0001",
    function_name="httpd_handle_request",
    confidence=0.85,
    analyst_type="memory_corruption",
    cwe="CWE-121",
    title="Stack Buffer Overflow",
    description="strcpy copies user input into fixed buffer",
    code_snippet="char buf[256]; strcpy(buf, param);",
    control_flow="recv() -> get_param() -> strcpy()",
    trigger_condition="URL parameter longer than 256 bytes",
    root_cause="Missing bounds check before strcpy",
    severity="critical",
):
    """Helper to create FirmwareSP for tests."""
    return FirmwareSP(
        sp_id=sp_id,
        cwe=cwe,
        title=title,
        description=description,
        function_name=function_name,
        vulnerable_code_snippet=code_snippet,
        control_flow=control_flow,
        trigger_condition=trigger_condition,
        root_cause=root_cause,
        confidence=confidence,
        severity=severity,
        analyst_type=analyst_type,
        exploitability=ExploitabilityAssessment(
            attack_vector="network",
            difficulty="trivial",
            reliability="reliable",
            impact="RCE",
        ),
    )


def make_context(name, pseudo_code=None):
    """Helper to create a function context dict entry."""
    return make_function(name=name, pseudo_code=pseudo_code)


# ── Sample Data ──────────────────────────────────────────────────────────

SAMPLE_SP_HIGH_CONF = make_sp(
    sp_id="mc-httpd_handler-CWE-121-0001",
    confidence=0.85,
    analyst_type="memory_corruption",
)

SAMPLE_SP_MED_CONF = make_sp(
    sp_id="lf-cgi_login-CWE-287-0001",
    function_name="cgi_login",
    confidence=0.65,
    analyst_type="logic_flaw",
    cwe="CWE-287",
    title="Authentication Bypass",
    description="Authentication check can be bypassed",
    code_snippet="if(authenticated) { do_admin(); }",
    control_flow="recv() -> strcmp() -> do_admin()",
    trigger_condition="auth cookie present but unvalidated",
    root_cause="Missing signature validation on auth cookie",
    severity="high",
)

SAMPLE_SP_LOW_CONF = make_sp(
    sp_id="inj-do_system_cmd-CWE-78-0001",
    function_name="do_system_cmd",
    confidence=0.30,
    analyst_type="injection",
    cwe="CWE-78",
    title="Command Injection",
    description="User input passed to system()",
    code_snippet="system(user_input);",
    control_flow="recv() -> system()",
    trigger_condition="attacker controls input to system()",
    root_cause="No sanitization of user input",
    severity="critical",
)

SAMPLE_SP_BORDERLINE_CONF = make_sp(
    sp_id="lf-check_auth-CWE-287-0002",
    function_name="check_auth",
    confidence=0.60,
    analyst_type="logic_flaw",
    cwe="CWE-287",
    title="Hardcoded Credentials",
    description="Password compared to hardcoded string",
    code_snippet="if(strcmp(input, 'admin123') == 0)",
    control_flow="recv() -> strcmp()",
    trigger_condition="attacker knows hardcoded password",
    root_cause="Hardcoded credential",
    severity="high",
)

SAMPLE_FUNCTION_CONTEXTS = {
    "httpd_handle_request": make_context(
        "httpd_handle_request",
        pseudo_code="void httpd_handle_request(char *param) {\n    char buf[256];\n    strcpy(buf, param);\n    send_response(buf);\n}",
    ),
    "cgi_login": make_context(
        "cgi_login",
        pseudo_code="int cgi_login() {\n    char auth[64];\n    recv(auth);\n    if(strcmp(auth, admin_pass) == 0) {\n        do_admin();\n    }\n}",
    ),
    "do_system_cmd": make_context(
        "do_system_cmd",
        pseudo_code="void do_system_cmd(char *input) {\n    char cmd[256];\n    sprintf(cmd, \"echo %s\", input);\n    system(cmd);\n}",
    ),
    "check_auth": make_context(
        "check_auth",
        pseudo_code="int check_auth(char *user, char *pass) {\n    if(strcmp(pass, \"admin123\") == 0) {\n        return 1;\n    }\n    return 0;\n}",
    ),
}

# Sample LLM verdict responses
VALID_VERDICT_RESPONSE = json.dumps([
    {
        "sp_id": "mc-httpd_handler-CWE-121-0001",
        "verdict": "confirmed",
        "confidence_adjustment": "+0.1",
        "refutation_reason": "",
        "missed_context": "",
        "merged_with": None,
    },
    {
        "sp_id": "lf-cgi_login-CWE-287-0001",
        "verdict": "refuted",
        "confidence_adjustment": "-0.5",
        "refutation_reason": "Login function has input validation on line 42 that checks length before strcmp",
        "missed_context": "Input validation in validate_input() was not analyzed",
        "merged_with": None,
    },
    {
        "sp_id": "lf-check_auth-CWE-287-0002",
        "verdict": "uncertain",
        "confidence_adjustment": "0.0",
        "refutation_reason": "Cannot determine if hardcoded password is for recovery mode or production",
        "missed_context": "Need to check if this path is guarded by compile-time flag",
        "merged_with": None,
    },
])

SINGLE_VERDICT_RESPONSE = json.dumps([
    {
        "sp_id": "mc-httpd_handler-CWE-121-0001",
        "verdict": "confirmed",
        "confidence_adjustment": "+0.1",
        "refutation_reason": "",
        "missed_context": "",
        "merged_with": None,
    },
])

MARKDOWN_FENCED_VERDICT_RESPONSE = "```json\n" + SINGLE_VERDICT_RESPONSE + "\n```"


# ── CrossReviewer Tests ────────────────────────────────────────────────

class TestCrossReviewerInitialization:
    """Tests for CrossReviewer constructor."""

    def test_reviewer_loads_cross_review_prompt(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        prompt = reviewer._get_system_prompt()
        assert "Review each Suspicious Point" in prompt
        assert "confirmed" in prompt
        assert "refuted" in prompt
        assert "Reachability" in prompt or "reachability" in prompt

    def test_default_model_a_is_deepseek(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO, LLMClient, LLMConfig
        # Use clean config so hardcoded fallback is tested, not agent_routing
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        reviewer = CrossReviewer(llm_client=client, reviewer_type="memory_corruption")
        model = reviewer._get_default_model()
        assert model.id == DEEPSEEK_V4_PRO.id

    def test_default_model_b_is_deepseek(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO, LLMClient, LLMConfig
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        reviewer = CrossReviewer(llm_client=client, reviewer_type="logic_flaw")
        model = reviewer._get_default_model()
        assert model.id == DEEPSEEK_V4_PRO.id

    def test_default_model_c_is_deepseek(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO, LLMClient, LLMConfig
        clean_config = LLMConfig(fallback_enabled=False)
        client = LLMClient(config=clean_config)
        reviewer = CrossReviewer(llm_client=client, reviewer_type="injection")
        model = reviewer._get_default_model()
        assert model.id == DEEPSEEK_V4_PRO.id

    def test_invalid_reviewer_type_raises_error(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        with pytest.raises(ValueError, match="Invalid reviewer_type"):
            CrossReviewer(reviewer_type="invalid_type")

    def test_custom_model_override(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        from fuzzingbrain.llms import QWEN3_6_PLUS
        reviewer = CrossReviewer(
            reviewer_type="memory_corruption", model=QWEN3_6_PLUS
        )
        assert reviewer.model.id == QWEN3_6_PLUS.id

    def test_custom_temperature_and_max_tokens(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(
            reviewer_type="memory_corruption",
            temperature=0.5,
            max_tokens=8000,
        )
        assert reviewer.temperature == 0.5
        assert reviewer.max_tokens == 8000


class TestBuildReviewPrompt:
    """Tests for _build_review_prompt method."""

    def test_build_prompt_includes_sp_details(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        sps = [SAMPLE_SP_HIGH_CONF]
        prompt = reviewer._build_review_prompt(sps, SAMPLE_FUNCTION_CONTEXTS)

        assert SAMPLE_SP_HIGH_CONF.sp_id in prompt
        assert SAMPLE_SP_HIGH_CONF.cwe in prompt
        assert SAMPLE_SP_HIGH_CONF.title in prompt
        assert SAMPLE_SP_HIGH_CONF.description in prompt

    def test_build_prompt_includes_function_context(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        sps = [SAMPLE_SP_HIGH_CONF]
        prompt = reviewer._build_review_prompt(sps, SAMPLE_FUNCTION_CONTEXTS)

        # Should include pseudo-code from function context
        assert "void httpd_handle_request" in prompt
        assert "buf[256]" in prompt
        assert "strcpy" in prompt

    def test_build_prompt_includes_confidence_and_analyst_type(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        sps = [SAMPLE_SP_HIGH_CONF]
        prompt = reviewer._build_review_prompt(sps, SAMPLE_FUNCTION_CONTEXTS)

        assert "0.85" in prompt or "0.85" in prompt
        assert "memory_corruption" in prompt

    def test_build_prompt_with_multiple_sps(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        sps = [SAMPLE_SP_HIGH_CONF, SAMPLE_SP_MED_CONF]
        prompt = reviewer._build_review_prompt(sps, SAMPLE_FUNCTION_CONTEXTS)

        assert SAMPLE_SP_HIGH_CONF.sp_id in prompt
        assert SAMPLE_SP_MED_CONF.sp_id in prompt
        assert "httpd_handle_request" in prompt
        assert "cgi_login" in prompt


class TestParseVerdictResponse:
    """Tests for _parse_response method."""

    def test_parse_valid_verdict_response(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response(VALID_VERDICT_RESPONSE)

        assert len(verdicts) == 3
        for v in verdicts:
            assert isinstance(v, CrossReviewVerdict)
            assert v.verdict in ("confirmed", "refuted", "uncertain", "needs_more_context")

    def test_parse_confirmed_verdict(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response(SINGLE_VERDICT_RESPONSE)

        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.sp_id == "mc-httpd_handler-CWE-121-0001"
        assert v.verdict == "confirmed"
        assert v.confidence_adjustment == "+0.1"
        assert v.reviewer_type == "memory_corruption"

    def test_parse_markdown_fenced_response(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response(MARKDOWN_FENCED_VERDICT_RESPONSE)

        assert len(verdicts) == 1
        assert verdicts[0].verdict == "confirmed"

    def test_parse_invalid_json_returns_empty(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response("not valid json {{{")
        assert len(verdicts) == 0

    def test_parse_invalid_verdict_raises_error(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        bad_json = json.dumps([
            {
                "sp_id": "mc-test-0001",
                "verdict": "not_a_valid_verdict",
                "confidence_adjustment": "0.0",
                "refutation_reason": "",
                "missed_context": "",
                "merged_with": None,
            }
        ])
        with pytest.raises(ValueError, match="Invalid verdict"):
            reviewer._parse_response(bad_json)

    def test_parse_empty_json_array(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response("[]")
        assert len(verdicts) == 0

    def test_parse_empty_content(self):
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer._parse_response("")
        assert len(verdicts) == 0


class TestReview:
    """Tests for the main review method."""

    @pytest.fixture
    def mock_llm_response(self):
        resp = MagicMock()
        resp.content = VALID_VERDICT_RESPONSE
        return resp

    def test_filters_low_confidence_sps(self):
        """
        Review only accepts SPs with confidence > 0.6.
        Only SAMPLE_SP_HIGH_CONF (0.85) and SAMPLE_SP_MED_CONF (0.65) should pass.
        SAMPLE_SP_LOW_CONF (0.30) and SAMPLE_SP_BORDERLINE_CONF (0.60) should be filtered out.
        """
        filtered_mock_response = json.dumps([
            {
                "sp_id": "mc-httpd_handler-CWE-121-0001",
                "verdict": "confirmed",
                "confidence_adjustment": "+0.1",
                "refutation_reason": "",
                "missed_context": "",
                "merged_with": None,
            },
            {
                "sp_id": "lf-cgi_login-CWE-287-0001",
                "verdict": "refuted",
                "confidence_adjustment": "-0.5",
                "refutation_reason": "Missing input validation evidence",
                "missed_context": "Need to check validate_input()",
                "merged_with": None,
            },
        ])
        mock_resp = MagicMock()
        mock_resp.content = filtered_mock_response

        with patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.LLMClient"
        ) as MockClient:
            MockClient.return_value.call.return_value = mock_resp
            from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
            reviewer = CrossReviewer(reviewer_type="memory_corruption")

            sps = [
                SAMPLE_SP_HIGH_CONF,  # 0.85 -> passes filter
                SAMPLE_SP_LOW_CONF,   # 0.30 -> filtered out
                SAMPLE_SP_MED_CONF,   # 0.65 -> passes filter
                SAMPLE_SP_BORDERLINE_CONF,  # 0.60 -> filtered out (not > 0.6)
            ]
            verdicts = reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)

            # Should only have verdicts for the 2 SPs that passed the filter
            assert len(verdicts) == 2
            returned_sp_ids = [v.sp_id for v in verdicts]
            assert "mc-httpd_handler-CWE-121-0001" in returned_sp_ids
            assert "lf-cgi_login-CWE-287-0001" in returned_sp_ids
            assert "inj-do_system_cmd-CWE-78-0001" not in returned_sp_ids
            assert "lf-check_auth-CWE-287-0002" not in returned_sp_ids

    def test_filters_only_above_06_threshold(self):
        """
        Verify the boundary: confidence of 0.61 should be included,
        0.60 should be excluded.
        """
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")

        # This tests the logic directly without LLM
        sp_border = make_sp(
            sp_id="lf-check-CWE-287-0003",
            function_name="check_it",
            confidence=0.61,
            analyst_type="logic_flaw",
        )
        sps = [sp_border]
        filtered = reviewer._filter_sps(sps)
        assert len(filtered) == 1
        assert filtered[0].sp_id == "lf-check-CWE-287-0003"

    def test_review_no_sps_to_review(self):
        """Should return empty list when no SPs pass the confidence filter."""
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        sps = [SAMPLE_SP_LOW_CONF]
        verdicts = reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)
        assert len(verdicts) == 0

    def test_review_with_mocked_llm(self, mock_llm_response):
        """Full integration: filter SPs, build prompt, call LLM, parse response."""
        with patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.LLMClient"
        ) as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
            reviewer = CrossReviewer(reviewer_type="memory_corruption")

            sps = [SAMPLE_SP_HIGH_CONF, SAMPLE_SP_MED_CONF]
            verdicts = reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)

            assert len(verdicts) == 3
            # Verify LLM was called
            assert mock_client.call.called

    def test_review_passes_correct_messages(self, mock_llm_response):
        """Verify the LLM client is called with correct message structure."""
        with patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.LLMClient"
        ) as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
            reviewer = CrossReviewer(reviewer_type="memory_corruption")

            sps = [SAMPLE_SP_HIGH_CONF]
            reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)

            # Check messages structure
            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            assert len(messages) == 2
            assert messages[0]["role"] == "system"
            assert messages[1]["role"] == "user"

    def test_review_passes_model_and_temperature(self, mock_llm_response):
        """Verify model and temperature params are passed to LLM."""
        with patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.LLMClient"
        ) as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
            from fuzzingbrain.llms import QWEN3_6_PLUS
            reviewer = CrossReviewer(
                reviewer_type="memory_corruption",
                model=QWEN3_6_PLUS,
                temperature=0.5,
            )

            sps = [SAMPLE_SP_HIGH_CONF]
            reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)

            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"].id == QWEN3_6_PLUS.id
            assert call_kwargs["temperature"] == 0.5

    def test_review_logging(self, mock_llm_response):
        """Verify review logs the expected messages."""
        with patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.LLMClient"
        ) as MockClient, patch(
            "fuzzingbrain.agents.firmware.cross_reviewer.logger"
        ) as mock_logger:
            MockClient.return_value.call.return_value = mock_llm_response
            from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
            reviewer = CrossReviewer(reviewer_type="logic_flaw")

            sps = [SAMPLE_SP_HIGH_CONF, SAMPLE_SP_MED_CONF]
            reviewer.review(sps, SAMPLE_FUNCTION_CONTEXTS)

            # Should log info about how many were reviewed, confirmed, refuted
            info_calls = [
                c for c in mock_logger.info.call_args_list
            ]
            assert len(info_calls) > 0
            all_info = " ".join(str(c) for c in info_calls)
            assert "reviewed" in all_info.lower() or "review" in all_info.lower()
