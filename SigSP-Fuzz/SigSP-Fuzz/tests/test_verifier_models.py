"""Tests for verifier data models."""

import json
import pytest
from dataclasses import asdict

from fuzzingbrain.verifier.models import (
    PoC,
    PoCTarget,
    ExpectedBehavior,
    AltPayload,
    VerificationResult,
    CrashInfo,
    Phase4Statistics,
    Phase4Result,
    ReportMetadata,
    VulnerabilityEntry,
    FinalReport,
)
from fuzzingbrain.agents.firmware.sp_models import ExploitabilityAssessment


class TestPoCTarget:
    def test_create_default(self):
        t = PoCTarget()
        assert t.host == "127.0.0.1"
        assert t.port == 80
        assert t.path == ""
        assert t.method == "GET"

    def test_create_http_post(self):
        t = PoCTarget(host="192.168.1.1", port=8080, path="/cgi-bin/login", method="POST")
        assert t.host == "192.168.1.1"
        assert t.port == 8080
        assert t.method == "POST"


class TestExpectedBehavior:
    def test_create(self):
        eb = ExpectedBehavior(
            expected_crash_type="SIGSEGV",
            expected_register_state="PC=0x41414141",
            success_indicator="QEMU exits with signal 11",
        )
        assert eb.expected_crash_type == "SIGSEGV"
        assert "0x41414141" in eb.expected_register_state

    def test_defaults(self):
        eb = ExpectedBehavior()
        assert eb.expected_crash_type == ""
        assert eb.expected_register_state == ""
        assert eb.success_indicator == ""


class TestAltPayload:
    def test_create(self):
        ap = AltPayload(description="Longer overflow pattern", poc_content="A" * 512)
        assert ap.description == "Longer overflow pattern"
        assert len(ap.poc_content) == 512
        assert ap.poc_content_hex == ""

    def test_with_hex(self):
        ap = AltPayload(description="Null byte injection", poc_content="\\x00admin", poc_content_hex="00 61 64 6d 69 6e")
        assert ap.poc_content_hex == "00 61 64 6d 69 6e"


class TestPoC:
    def test_create_minimal(self):
        p = PoC(sp_id="mc-func-CWE-121-0001", poc_type="http_request")
        assert p.sp_id == "mc-func-CWE-121-0001"
        assert p.poc_type == "http_request"
        assert p.poc_content == ""
        assert p.poc_target.port == 80

    def test_create_full(self):
        target = PoCTarget(host="10.0.0.1", port=80, path="/cgi-bin/vuln", method="POST")
        eb = ExpectedBehavior(
            expected_crash_type="SIGSEGV",
            expected_register_state="PC=0x41414141",
            success_indicator="Segmentation fault",
        )
        alt = AltPayload(description="Bigger payload", poc_content="B" * 1024)
        p = PoC(
            sp_id="mc-httpd-CWE-121-0001",
            poc_type="http_request",
            poc_target=target,
            poc_content="AAAA" * 100,
            poc_content_hex="41" * 100,
            poc_explanation="Overflows a 256-byte stack buffer",
            expected_behavior=eb,
            alternate_payloads=[alt],
        )
        assert p.sp_id == "mc-httpd-CWE-121-0001"
        assert p.poc_target.port == 80
        assert len(p.alternate_payloads) == 1
        assert "256-byte" in p.poc_explanation

    def test_serialization(self):
        p = PoC(
            sp_id="test-1",
            poc_type="udp_packet",
            poc_content="\\x00" * 64,
            poc_explanation="Sends 64 null bytes to overflow buffer",
        )
        d = p.to_dict()
        assert d["sp_id"] == "test-1"
        assert d["poc_type"] == "udp_packet"
        assert d["poc_explanation"] == "Sends 64 null bytes to overflow buffer"

    def test_json_roundtrip(self):
        p = PoC(
            sp_id="test-2",
            poc_type="tcp_stream",
            poc_target=PoCTarget(port=23),
            poc_content="AAAA",
            poc_explanation="Telnet overflow",
        )
        json_str = json.dumps(p.to_dict())
        loaded = json.loads(json_str)
        p2 = PoC.from_dict(loaded)
        assert p.sp_id == p2.sp_id
        assert p.poc_target.port == p2.poc_target.port

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Invalid poc_type"):
            PoC(sp_id="x", poc_type="invalid")


class TestCrashInfo:
    def test_create_minimal(self):
        ci = CrashInfo(crash_type="SIGSEGV")
        assert ci.crash_type == "SIGSEGV"
        assert ci.crash_address == ""
        assert ci.register_state == {}
        assert ci.backtrace == []
        assert ci.signal_number == 0
        assert ci.crash_signature == "SIGSEGV-"

    def test_create_full(self):
        ci = CrashInfo(
            crash_type="SIGSEGV",
            crash_address="0x41414141",
            register_state={"PC": "0x41414141", "SP": "0xbefffc00"},
            backtrace=["0x41414141", "0x0804a000 in httpd_handler", "0x0804b000 in main"],
            signal_number=11,
        )
        assert ci.crash_address == "0x41414141"
        assert ci.register_state["PC"] == "0x41414141"
        assert len(ci.backtrace) == 3
        assert ci.signal_number == 11
        assert "SIGSEGV-0x41414141" == ci.crash_signature

    def test_serialization(self):
        ci = CrashInfo(crash_type="SIGABRT", crash_address="0xdeadbeef", signal_number=6)
        d = ci.to_dict()
        assert d["crash_type"] == "SIGABRT"
        assert d["crash_address"] == "0xdeadbeef"
        assert d["signal_number"] == 6

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Invalid crash_type"):
            CrashInfo(crash_type="invalid")


class TestVerificationResult:
    def test_create_dynamic_full(self):
        vr = VerificationResult(
            sp_id="test-1",
            verification_level="dynamic_full",
            crashed=True,
            crash_info=CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            output="qemu: uncaught target signal 11",
        )
        assert vr.verification_level == "dynamic_full"
        assert vr.crashed is True
        assert vr.crash_info.crash_type == "SIGSEGV"

    def test_create_static_high(self):
        vr = VerificationResult(
            sp_id="test-2",
            verification_level="static_high",
            crashed=False,
            output="L3 assessment: chain complete, confidence=0.90",
        )
        assert vr.verification_level == "static_high"
        assert vr.crashed is False
        assert vr.crash_info is None
        assert "confidence=0.90" in vr.output

    def test_create_static_low_discarded(self):
        vr = VerificationResult(
            sp_id="test-3",
            verification_level="static_low",
            crashed=False,
            output="Discarded: confidence=0.60 < 0.85 threshold",
        )
        assert vr.verification_level == "static_low"
        assert vr.crashed is False

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="verification_level"):
            VerificationResult(sp_id="t", verification_level="invalid", crashed=False)

    def test_serialization(self):
        vr = VerificationResult(
            sp_id="test-4",
            verification_level="dynamic_user",
            crashed=True,
            crash_info=CrashInfo(crash_type="SIGILL", signal_number=4),
            output="Illegal instruction",
        )
        d = vr.to_dict()
        assert d["verification_level"] == "dynamic_user"
        assert d["crash_info"]["crash_type"] == "SIGILL"


class TestPhase4Statistics:
    def test_create(self):
        stats = Phase4Statistics(
            total_p0_sps=5, poc_generated=5,
            dynamic_full_verified=2, dynamic_user_verified=1,
            static_high_reserved=1, discarded=1,
            unique_crashes=3, verification_rate="60.0%",
        )
        assert stats.total_p0_sps == 5
        assert stats.poc_generated == 5
        assert stats.dynamic_full_verified == 2

    def test_defaults(self):
        stats = Phase4Statistics()
        assert stats.total_p0_sps == 0
        assert stats.poc_generated == 0
        assert stats.verification_rate == ""


class TestPhase4Result:
    def test_create(self):
        results = [
            VerificationResult(sp_id="sp-1", verification_level="dynamic_full", crashed=True),
            VerificationResult(sp_id="sp-2", verification_level="static_high", crashed=False),
        ]
        crashes = [CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)]
        stats = Phase4Statistics(total_p0_sps=2, poc_generated=2, dynamic_full_verified=1,
                                  static_high_reserved=1, unique_crashes=1)
        result = Phase4Result(verified_results=results, crashes=crashes, statistics=stats)
        assert len(result.verified_results) == 2
        assert len(result.crashes) == 1

    def test_json_roundtrip(self):
        stats = Phase4Statistics(total_p0_sps=1, poc_generated=1, dynamic_full_verified=1, unique_crashes=1)
        result = Phase4Result(
            verified_results=[
                VerificationResult(sp_id="sp-1", verification_level="dynamic_full", crashed=True,
                                   crash_info=CrashInfo(crash_type="SIGSEGV", signal_number=11))
            ],
            crashes=[CrashInfo(crash_type="SIGSEGV", signal_number=11)],
            statistics=stats,
        )
        json_str = json.dumps(result.to_dict())
        loaded = json.loads(json_str)
        r2 = Phase4Result.from_dict(loaded)
        assert r2.statistics.total_p0_sps == 1
        assert r2.verified_results[0].verification_level == "dynamic_full"


class TestReportMetadata:
    def test_create(self):
        rm = ReportMetadata(
            firmware_name="test_firmware.bin", firmware_hash="abc123",
            analysis_date="2026-06-04T12:00:00",
            total_functions_analyzed=100, total_attack_surfaces=5, total_directions=3,
        )
        assert rm.firmware_name == "test_firmware.bin"
        assert rm.firmware_hash == "abc123"
        assert rm.total_functions_analyzed == 100


class TestVulnerabilityEntry:
    def test_create_minimal(self):
        ve = VulnerabilityEntry(
            sp_id="sp-1", cwe="CWE-121", title="Stack Buffer Overflow",
            description="strcpy without bounds check", function_name="httpd_handler",
        )
        assert ve.sp_id == "sp-1"
        assert ve.cwe == "CWE-121"
        assert ve.confidence == 0.0
        assert ve.severity == ""

    def test_create_full(self):
        ea = ExploitabilityAssessment(
            attack_vector="network", difficulty="trivial",
            reliability="reliable", impact="RCE"
        )
        poc = PoC(sp_id="sp-1", poc_type="http_request", poc_content="AAAA")
        ci = CrashInfo(crash_type="SIGSEGV", signal_number=11)
        ve = VulnerabilityEntry(
            sp_id="sp-1", cwe="CWE-121", title="Stack Buffer Overflow",
            description="strcpy without bounds check on user input",
            function_name="httpd_handler", binary_offset="0x2100",
            control_flow="httpd_init → httpd_handle_request → strcpy",
            trigger_condition="Send HTTP request with param > 256 bytes",
            confidence=0.85, severity="critical", priority="P0",
            verification_level="dynamic_full",
            exploitability=ea, poc=poc, crash_info=ci,
            fix_suggestion="Replace strcpy with strncpy and add bounds check",
        )
        assert ve.confidence == 0.85
        assert ve.priority == "P0"
        assert ve.verification_level == "dynamic_full"
        assert ve.exploitability.attack_vector == "network"
        assert ve.poc.poc_type == "http_request"
        assert ve.crash_info.crash_type == "SIGSEGV"
        assert "strncpy" in ve.fix_suggestion

    def test_invalid_confidence_raises(self):
        """Confidence must fall within 0.0 <= x <= 1.0, matching FirmwareSP/VerifiedSP patterns."""
        with pytest.raises(ValueError, match="Invalid confidence"):
            VulnerabilityEntry(sp_id="x", cwe="CWE-121", title="t",
                               description="d", function_name="f",
                               confidence=1.5)


class TestFinalReport:
    def test_create(self):
        metadata = ReportMetadata(firmware_name="test.bin")
        entries = [
            VulnerabilityEntry(
                sp_id="sp-1", cwe="CWE-121", title="Stack Overflow",
                description="Buffer overflow in HTTP handler",
                function_name="httpd_handler", confidence=0.85,
                severity="critical", priority="P0",
                verification_level="dynamic_full",
            ),
        ]
        stats = Phase4Statistics(total_p0_sps=1, poc_generated=1, dynamic_full_verified=1,
                                  unique_crashes=1, verification_rate="100%")
        report = FinalReport(metadata=metadata, vulnerabilities=entries, statistics=stats)
        assert report.metadata.firmware_name == "test.bin"
        assert len(report.vulnerabilities) == 1
        assert report.statistics.verification_rate == "100%"
        assert report.count == 1

    def test_confirmed_vulnerabilities(self):
        metadata = ReportMetadata(firmware_name="test.bin")
        entries = [
            VulnerabilityEntry(sp_id="sp-1", cwe="CWE-121", title="Test1",
                               description="d", function_name="f1",
                               verification_level="dynamic_full"),
            VulnerabilityEntry(sp_id="sp-2", cwe="CWE-78", title="Test2",
                               description="d", function_name="f2",
                               verification_level="static_low"),
            VulnerabilityEntry(sp_id="sp-3", cwe="CWE-190", title="Test3",
                               description="d", function_name="f3",
                               verification_level="static_high"),
        ]
        stats = Phase4Statistics()
        report = FinalReport(metadata=metadata, vulnerabilities=entries, statistics=stats)
        confirmed = report.confirmed_vulnerabilities
        assert len(confirmed) == 2  # dynamic_full + static_high
