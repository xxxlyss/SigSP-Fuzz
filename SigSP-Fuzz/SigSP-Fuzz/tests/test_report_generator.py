"""Tests for ReportGenerator."""

import json
from pathlib import Path
from fuzzingbrain.reporter.generator import ReportGenerator
from fuzzingbrain.verifier.models import (
    Phase4Statistics, VerificationResult,
    CrashInfo, PoC, PoCTarget, ReportMetadata, VulnerabilityEntry, FinalReport,
)
from fuzzingbrain.agents.firmware.sp_models import ExploitabilityAssessment


def make_sample_report():
    metadata = ReportMetadata(
        firmware_name="test_firmware.bin", firmware_hash="abc123def456",
        analysis_date="2026-06-04T12:00:00",
        total_functions_analyzed=150, total_attack_surfaces=7, total_directions=4,
    )
    ea = ExploitabilityAssessment(
        attack_vector="network", difficulty="trivial",
        reliability="reliable", impact="RCE",
    )
    poc = PoC(
        sp_id="mc-httpd-CWE-121-0001", poc_type="http_request",
        poc_target=PoCTarget(host="192.168.1.1", port=80, path="/cgi-bin/login", method="POST"),
        poc_content="POST /cgi-bin/login HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Length: 300\r\n\r\nurl=AAAA...",
        poc_explanation="Overflows a 256-byte buffer via strcpy",
    )
    crash = CrashInfo(
        crash_type="SIGSEGV", crash_address="0x41414141",
        register_state={"PC": "0x41414141", "SP": "0xbefffc00"},
        backtrace=["0x41414141", "0x0804a100 in httpd_handler", "0x0804b200 in main"],
        signal_number=11,
    )
    entries = [
        VulnerabilityEntry(
            sp_id="mc-httpd-CWE-121-0001", cwe="CWE-121",
            title="Stack Buffer Overflow in HTTP parameter parsing",
            description="The httpd_handler function copies user-supplied URL parameter "
                        "into a fixed-size 256-byte stack buffer using strcpy without "
                        "any bounds check, allowing remote code execution.",
            function_name="httpd_handler", binary_offset="0x2100",
            control_flow="httpd_init -> httpd_handle_request -> get_param -> strcpy",
            trigger_condition="Send HTTP POST request with url parameter exceeding 256 bytes",
            confidence=0.85, severity="critical", priority="P0",
            verification_level="dynamic_full",
            exploitability=ea, poc=poc, crash_info=crash,
            fix_suggestion="Replace strcpy with strncpy(buf, param, sizeof(buf)-1) and "
                           "ensure null termination.",
        ),
        VulnerabilityEntry(
            sp_id="inj-cgi-CWE-78-0001", cwe="CWE-78",
            title="Command Injection in ping utility handler",
            description="The cgi_ping function concatenates user-supplied IP address "
                        "into a system() command string without sanitization.",
            function_name="cgi_ping", binary_offset="0x3500",
            control_flow="cgi_main -> cgi_ping -> sprintf -> system",
            trigger_condition="Send POST to /cgi-bin/ping with ip=;cat /etc/shadow",
            confidence=0.90, severity="critical", priority="P0",
            verification_level="static_high",
            fix_suggestion="Validate IP address format before passing to system().",
        ),
    ]
    stats = Phase4Statistics(
        total_p0_sps=3, poc_generated=3, dynamic_full_verified=1,
        dynamic_user_verified=0, static_high_reserved=1, discarded=1,
        unique_crashes=1, verification_rate="66.7%",
    )
    return FinalReport(metadata=metadata, vulnerabilities=entries, statistics=stats)


class TestReportGeneratorJSON:
    def test_generates_json(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.json"
        gen.to_json(report, output_path)
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["metadata"]["firmware_name"] == "test_firmware.bin"
        assert len(data["vulnerabilities"]) == 2
        assert data["statistics"]["dynamic_full_verified"] == 1

    def test_json_contains_all_required_fields(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.json"
        gen.to_json(report, output_path)
        data = json.loads(output_path.read_text())
        entry = data["vulnerabilities"][0]
        for field in ["sp_id", "cwe", "title", "description", "function_name",
                       "confidence", "severity", "priority", "verification_level", "fix_suggestion"]:
            assert field in entry, f"Missing field: {field}"

    def test_json_includes_poc(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.json"
        gen.to_json(report, output_path)
        data = json.loads(output_path.read_text())
        entry = data["vulnerabilities"][0]
        assert entry["poc"] is not None
        assert entry["poc"]["poc_type"] == "http_request"

    def test_json_includes_crash_info(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.json"
        gen.to_json(report, output_path)
        data = json.loads(output_path.read_text())
        entry = data["vulnerabilities"][0]
        assert entry["crash_info"] is not None
        assert entry["crash_info"]["crash_type"] == "SIGSEGV"


class TestReportGeneratorMarkdown:
    def test_generates_markdown(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)
        assert output_path.exists()
        content = output_path.read_text()
        assert "# Firmware Vulnerability Analysis Report" in content
        assert "test_firmware.bin" in content

    def test_markdown_contains_executive_summary(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)
        content = output_path.read_text()
        assert "Executive Summary" in content
        assert "66.7%" in content

    def test_markdown_contains_vulnerability_details(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)
        content = output_path.read_text()
        assert "CWE-121" in content
        assert "CWE-78" in content
        assert "Stack Buffer Overflow" in content
        assert "Command Injection" in content

    def test_markdown_contains_fix_suggestions(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)
        content = output_path.read_text()
        assert "strncpy" in content

    def test_generate_complete(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        result = gen.generate(report)
        assert isinstance(result, FinalReport)
        assert result.count == 2


class TestReportGeneratorEmptyReport:
    def test_empty_report_json(self, tmp_path):
        metadata = ReportMetadata(firmware_name="empty.bin")
        stats = Phase4Statistics()
        report = FinalReport(metadata=metadata, vulnerabilities=[], statistics=stats)
        gen = ReportGenerator()
        output_path = tmp_path / "empty_report.json"
        gen.to_json(report, output_path)
        assert output_path.exists()

    def test_empty_report_markdown(self, tmp_path):
        metadata = ReportMetadata(firmware_name="empty.bin")
        stats = Phase4Statistics()
        report = FinalReport(metadata=metadata, vulnerabilities=[], statistics=stats)
        gen = ReportGenerator()
        output_path = tmp_path / "empty_report.md"
        gen.to_markdown(report, output_path)
        content = output_path.read_text()
        assert "No vulnerabilities" in content or "0 vulnerabilities" in content.lower()
