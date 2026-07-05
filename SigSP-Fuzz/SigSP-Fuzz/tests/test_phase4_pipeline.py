"""Tests for Phase4Pipeline integration."""

import json
from unittest.mock import MagicMock, patch

from fuzzingbrain.verifier.pipeline import Phase4Pipeline
from fuzzingbrain.verifier.models import (
    Phase4Result, Phase4Statistics, VerificationResult, CrashInfo,
    PoC, PoCTarget,
)
from fuzzingbrain.agents.firmware.sp_models import (
    VerifiedSP, AnalystConsensus, ExploitabilityAssessment,
)
from fuzzingbrain.attack_surface.models import AttackSurface, PortInfo
from fuzzingbrain.static.models import FunctionInfo, CallGraph, CallGraphNode


def make_p0_sp(sp_id="mc-func-CWE-121-0001", confidence=0.85, function_name="httpd_handler", priority="P0"):
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
        sp_id=sp_id, cwe="CWE-121", title="Stack Buffer Overflow",
        description="strcpy without bounds check",
        function_name=function_name,
        vulnerable_code_snippet="char buf[256]; strcpy(buf, input);",
        control_flow="entry -> handler -> strcpy",
        trigger_condition="Oversized input",
        root_cause="Missing bounds check",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority=priority,
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_functions():
    return [
        FunctionInfo(
            name="httpd_handler", address=0x2100,
            pseudo_code="void httpd_handler() { char buf[256]; strcpy(buf, input); }",
            callees=["strcpy"], callers=["httpd_init"],
            strings_used=["GET"], dangerous_funcs=["strcpy"],
            has_unsafe_calls=True, arch="arm",
        ),
    ]


def make_attack_surfaces():
    return [
        AttackSurface(
            name="HTTP Server", category="network_service",
            entry_functions=["httpd_init", "httpd_handler"],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
        ),
    ]


def make_callgraph():
    nodes = {
        "httpd_init": CallGraphNode(function_name="httpd_init", address=0x2000,
                                     callees=["httpd_handler"]),
        "httpd_handler": CallGraphNode(function_name="httpd_handler", address=0x2100,
                                        callees=["strcpy"], callers=["httpd_init"]),
    }
    return CallGraph(binary_path="/bin/test", nodes=nodes)


MOCK_POC_JSON = json.dumps({
    "sp_id": "mc-func-CWE-121-0001",
    "poc_type": "http_request",
    "poc_target": {"host": "192.168.1.1", "port": 80, "path": "/cgi-bin/test", "method": "POST"},
    "poc_content": "POST /cgi-bin/test HTTP/1.1\r\n...AAAA...",
    "poc_content_hex": "",
    "poc_explanation": "Overflows the 256-byte buffer",
    "expected_behavior": {"expected_crash_type": "SIGSEGV", "expected_register_state": "PC=0x41414141", "success_indicator": "SIGSEGV signal 11"},
    "alternate_payloads": [],
})


class TestPhase4PipelineInit:
    def test_default_init(self):
        pipeline = Phase4Pipeline()
        assert pipeline.poc_agent is not None
        assert pipeline.crash_monitor is not None
        assert pipeline.static_assessor is not None

    def test_output_dir_default(self):
        pipeline = Phase4Pipeline()
        assert pipeline.output_dir is not None


class TestPhase4PipelineRun:
    @patch("fuzzingbrain.verifier.pipeline.LLMClient")
    @patch("fuzzingbrain.verifier.pipeline.FirmAERunner")
    @patch("fuzzingbrain.verifier.pipeline.QEMURunner")
    def test_run_with_mocked_runners(self, MockQEMU, MockFirmAE, MockLLM):
        """Full pipeline run with FirmAE -> QEMU -> StaticAssessor fallback."""
        mock_client = MockLLM.return_value
        mock_response = MagicMock()
        mock_response.content = MOCK_POC_JSON
        mock_client.call.return_value = mock_response

        # Mock FirmAE -- fails (returns not_verified)
        mock_firmae = MockFirmAE.return_value
        mock_firmae.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="not_verified", crashed=False,
            output="FirmAE boot failed",
        )

        # Mock QEMU -- succeeds (returns crash)
        mock_qemu = MockQEMU.return_value
        mock_qemu.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="dynamic_user", crashed=True,
            crash_info=CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            output="QEMU: SIGSEGV at 0x41414141",
        )

        pipeline = Phase4Pipeline()
        result = pipeline.run(
            verified_sps=[make_p0_sp()],
            functions=make_functions(),
            attack_surfaces=make_attack_surfaces(),
            callgraph=make_callgraph(),
            firmware_name="test.bin",
        )

        assert isinstance(result, Phase4Result)
        assert result.statistics.total_p0_sps == 1
        assert result.statistics.poc_generated == 1
        assert result.statistics.dynamic_user_verified == 1
        assert len(result.crashes) == 1

    @patch("fuzzingbrain.verifier.pipeline.LLMClient")
    @patch("fuzzingbrain.verifier.pipeline.FirmAERunner")
    @patch("fuzzingbrain.verifier.pipeline.QEMURunner")
    def test_run_firmae_succeeds(self, MockQEMU, MockFirmAE, MockLLM):
        """When FirmAE succeeds, QEMU should not be called."""
        mock_client = MockLLM.return_value
        mock_response = MagicMock()
        mock_response.content = MOCK_POC_JSON
        mock_client.call.return_value = mock_response

        mock_firmae = MockFirmAE.return_value
        mock_firmae.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="dynamic_full", crashed=True,
            crash_info=CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            output="FirmAE: crash confirmed",
        )

        pipeline = Phase4Pipeline(firmae_dir="/opt/FirmAE")
        result = pipeline.run(
            verified_sps=[make_p0_sp()],
            functions=make_functions(),
            attack_surfaces=make_attack_surfaces(),
            firmware_path="test.bin",
            firmware_name="test.bin",
        )

        MockQEMU.return_value.verify.assert_not_called()
        assert result.statistics.dynamic_full_verified == 1

    @patch("fuzzingbrain.verifier.pipeline.LLMClient")
    @patch("fuzzingbrain.verifier.pipeline.FirmAERunner")
    @patch("fuzzingbrain.verifier.pipeline.QEMURunner")
    def test_run_all_fail_falls_to_static(self, MockQEMU, MockFirmAE, MockLLM):
        """When both FirmAE and QEMU fail, StaticAssessor handles it."""
        mock_client = MockLLM.return_value
        mock_response = MagicMock()
        mock_response.content = MOCK_POC_JSON
        mock_client.call.return_value = mock_response

        MockFirmAE.return_value.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="not_verified", crashed=False,
            output="FirmAE failed",
        )
        MockQEMU.return_value.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="not_verified", crashed=False,
            output="QEMU failed",
        )

        pipeline = Phase4Pipeline()
        result = pipeline.run(
            verified_sps=[make_p0_sp(confidence=0.90)],
            functions=make_functions(),
            attack_surfaces=make_attack_surfaces(),
            callgraph=make_callgraph(),
            firmware_name="test.bin",
        )

        assert result.statistics.static_high_reserved >= 0
        assert len(result.verified_results) > 0

    @patch("fuzzingbrain.verifier.pipeline.LLMClient")
    def test_run_filters_non_p0(self, MockLLM):
        """Non-P0 SPs should not have PoCs generated."""
        mock_client = MockLLM.return_value
        mock_response = MagicMock()
        mock_response.content = MOCK_POC_JSON
        mock_client.call.return_value = mock_response

        p1_sp = make_p0_sp(sp_id="mc-func2-CWE-121-0002", priority="P1")

        pipeline = Phase4Pipeline()
        result = pipeline.run(
            verified_sps=[p1_sp],
            functions=make_functions(),
            attack_surfaces=make_attack_surfaces(),
            firmware_name="test.bin",
        )

        assert result.statistics.poc_generated == 0
        assert result.statistics.total_p0_sps == 0


class TestPhase4PipelineFileIO:
    def test_save_and_load(self, tmp_path):
        stats = Phase4Statistics(total_p0_sps=1, poc_generated=1,
                                  dynamic_user_verified=1, unique_crashes=1)
        result = Phase4Result(
            verified_results=[
                VerificationResult(sp_id="sp-1", verification_level="dynamic_user",
                                   crashed=True, crash_info=CrashInfo(crash_type="SIGSEGV", signal_number=11)),
            ],
            crashes=[CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)],
            statistics=stats,
        )
        pipeline = Phase4Pipeline()
        output_path = tmp_path / "phase4_result.json"
        pipeline.save(result, output_path)
        assert output_path.exists()
        loaded = pipeline.load(output_path)
        assert loaded.statistics.total_p0_sps == 1
        assert loaded.statistics.dynamic_user_verified == 1
