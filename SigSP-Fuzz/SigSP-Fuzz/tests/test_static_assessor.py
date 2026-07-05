"""Tests for StaticAssessor."""

import pytest
from fuzzingbrain.verifier.static_assessor import StaticAssessor
from fuzzingbrain.verifier.models import VerificationResult
from fuzzingbrain.agents.firmware.sp_models import (
    VerifiedSP, AnalystConsensus, ExploitabilityAssessment,
)
from fuzzingbrain.static.models import CallGraph, CallGraphNode


def make_sp(sp_id="sp-1", confidence=0.90, function_name="httpd_handler"):
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
        sp_id=sp_id, cwe="CWE-121", title="Test SP",
        description="Test description", function_name=function_name,
        vulnerable_code_snippet="strcpy(buf, input);",
        control_flow="httpd_init -> httpd_handler -> get_param -> strcpy",
        trigger_condition="Send oversized input",
        root_cause="No bounds check",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority="P0",
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_callgraph():
    nodes = {
        "httpd_init": CallGraphNode(
            function_name="httpd_init", address=0x2000,
            callees=["httpd_handler", "socket", "bind", "listen"],
        ),
        "httpd_handler": CallGraphNode(
            function_name="httpd_handler", address=0x2100,
            callees=["get_param", "strcpy"],
            callers=["httpd_init"],
        ),
        "get_param": CallGraphNode(
            function_name="get_param", address=0x2200,
            callees=[],
            callers=["httpd_handler"],
        ),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


def make_incomplete_callgraph():
    nodes = {
        "httpd_init": CallGraphNode(
            function_name="httpd_init", address=0x2000,
            callees=["socket", "bind", "listen"],
        ),
        "httpd_handler": CallGraphNode(
            function_name="httpd_handler", address=0x2100,
            callees=["get_param", "strcpy"],
            callers=[],
        ),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


class TestStaticAssessorAssess:
    def test_high_confidence_complete_chain_returns_static_high(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert isinstance(result, VerificationResult)
        assert result.verification_level == "static_high"
        assert result.crashed is False

    def test_high_confidence_incomplete_chain_returns_static_low(self):
        """Incomplete chain: function has no callers AND no SP metadata evidence."""
        assessor = StaticAssessor()
        # Use a non-network input_vector + empty control_flow so SP metadata
        # fallback does NOT mark it as complete
        sp = make_sp(confidence=0.90, function_name="httpd_handler")
        sp.input_vector = "local_file"  # NOT network-facing
        sp.control_flow = ""            # no chain evidence
        cg = make_incomplete_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_low_confidence_returns_static_low(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.50)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_boundary_confidence_at_threshold_static_high(self):
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.85)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_high"

    def test_boundary_confidence_below_threshold_discarded(self):
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.849)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_assess_without_callgraph(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        result = assessor.assess(sp, callgraph=None)
        assert result.verification_level == "static_high"

    def test_output_message_includes_reasoning(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert "confidence=0.9" in result.output
        assert "complete" in result.output.lower()

    def test_custom_threshold(self):
        assessor = StaticAssessor(high_confidence_threshold=0.90)
        sp = make_sp(confidence=0.85, function_name="httpd_handler")
        sp.input_vector = "local_file"  # not network-facing
        sp.control_flow = ""            # no chain evidence
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_no_callers_but_network_input_vector_passes(self):
        """SP with empty callers but network input_vector → chain inferred."""
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.90, function_name="httpd_handler")
        sp.input_vector = "http_post"  # network-facing
        sp.control_flow = "httpd_init → httpd_handler → get_param → strcpy"
        cg = make_incomplete_callgraph()  # httpd_handler has callers=[]
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_high"

    def test_no_callers_no_metadata_fails(self):
        """SP with empty callers AND no metadata evidence → incomplete."""
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.90, function_name="httpd_handler")
        sp.input_vector = "local_file"   # NOT network-facing
        sp.control_flow = ""             # no evidence
        cg = make_incomplete_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_no_callers_but_control_flow_keywords_passes(self):
        """SP with no callers but control_flow has chain keywords → passes."""
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.90, function_name="formSetSpeedWan")
        sp.input_vector = "http_post"
        sp.control_flow = (
            "HTTP request arrives at CGI endpoint 'formSetSpeedWan'. "
            "The handler invokes GetValue and dispatches to strcpy."
        )
        cg = make_incomplete_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_high"

    def test_not_in_callgraph_no_metadata_fails(self):
        """SP function not in callgraph at all AND no metadata → fails."""
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90, function_name="completely_missing_func")
        sp.input_vector = "local_file"
        sp.control_flow = ""
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"
