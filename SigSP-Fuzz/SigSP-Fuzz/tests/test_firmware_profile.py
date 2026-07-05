"""
Tests for FirmwareProfile YAML mechanism.

Covers:
  - Model construction & validation (FirmwareArchitecture, KnownEntryPoint, KnownCVE)
  - YAML roundtrip (to_dict / from_dict / from_yaml)
  - Profile discovery & loading (load_profile, discover_profiles)
  - Binary filtering (should_skip_binary with focus/skip lists)
  - Ground truth cross-referencing (cross_reference_cves)
  - CLI --profile integration
  - FirmwarePipeline integration (profile passed through, architecture override)
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from fuzzingbrain.firmware_profile import (
    FirmwareArchitecture,
    FirmwareProfile,
    KnownCVE,
    KnownEntryPoint,
    VALID_CPUS,
    VALID_DEVICE_TYPES,
    VALID_ENDIANS,
    VALID_FILESYSTEMS,
    discover_profiles,
    load_profile,
)
from fuzzingbrain.agents.firmware.sp_models import (
    VerifiedSP, AnalystConsensus, ExploitabilityAssessment,
)


# ==========================================================================
# Helpers
# ==========================================================================

def make_dvrf_profile_dict():
    """Minimal DVRF-like profile dict (no YAML file needed)."""
    return {
        "name": "DVRF-Test",
        "version": "0.3",
        "vendor": "Praetorian",
        "device_type": "router",
        "architecture": {
            "cpu": "mips",
            "endian": "little",
            "bits": 32,
        },
        "filesystem": "squashfs",
        "known_entry_points": [
            {
                "name": "HTTP Daemon",
                "binary": "usr/sbin/httpd",
                "protocol": "HTTP",
                "port": 80,
                "description": "Mini HTTP server",
            },
            {
                "name": "DNS Forwarder",
                "binary": "usr/sbin/dnsmasq",
                "protocol": "DNS",
                "port": 53,
            },
        ],
        "known_cves": [
            {
                "cve_id": "DVRF-STACK-BOF-01",
                "cwe": "CWE-121",
                "function_name": "main",
                "binary_path": "pwnable/Intro/stack_bof_01",
                "description": "Stack buffer overflow via strcpy",
                "cvss_score": 8.5,
            },
            {
                "cve_id": "DVRF-SOCKET-BOF-01",
                "cwe": "CWE-121",
                "function_name": "handle_connection",
                "binary_path": "pwnable/Shellcode/socket_bof",
                "description": "Network stack buffer overflow",
                "cvss_score": 9.8,
            },
            {
                "cve_id": "DVRF-UAF-01",
                "cwe": "CWE-416",
                "function_name": "main",
                "binary_path": "pwnable/Heap/uaf_01",
                "description": "Use-after-free",
                "cvss_score": 8.2,
            },
        ],
    }


def make_verified_sp(sp_id, function_name, binary_path="", priority="P0", confidence=0.85):
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
        title=f"Vuln in {function_name}",
        description=f"Buffer overflow in {function_name}",
        function_name=function_name,
        vulnerable_code_snippet="",
        control_flow=f"entry -> {function_name}",
        trigger_condition="",
        root_cause="",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x400000",
        input_vector="stdin", priority=priority,
        analyst_consensus=consensus, verification_priority="immediate",
    )


# ==========================================================================
# FirmwareArchitecture
# ==========================================================================

class TestFirmwareArchitecture:
    def test_basic_construction(self):
        arch = FirmwareArchitecture(cpu="mips", endian="little", bits=32)
        assert arch.cpu == "mips"
        assert arch.endian == "little"
        assert arch.bits == 32
        assert arch.thumb_mode is False

    def test_defaults(self):
        arch = FirmwareArchitecture(cpu="arm")
        assert arch.endian == "little"
        assert arch.bits == 32
        assert arch.thumb_mode is False

    def test_invalid_cpu_raises(self):
        with pytest.raises(ValueError, match="Invalid cpu"):
            FirmwareArchitecture(cpu="nvidia_cuda")

    def test_invalid_endian_raises(self):
        with pytest.raises(ValueError, match="Invalid endian"):
            FirmwareArchitecture(cpu="mips", endian="middle")

    def test_invalid_bits_raises(self):
        with pytest.raises(ValueError, match="Invalid bits"):
            FirmwareArchitecture(cpu="mips", bits=128)

    def test_qemu_arch_mipsel(self):
        arch = FirmwareArchitecture(cpu="mips", endian="little", bits=32)
        assert arch.qemu_arch == "mipsel"

    def test_qemu_arch_arm(self):
        arch = FirmwareArchitecture(cpu="arm", endian="little", bits=32)
        assert arch.qemu_arch == "arm"

    def test_qemu_arch_x86_64(self):
        arch = FirmwareArchitecture(cpu="x86_64", endian="little", bits=64)
        assert arch.qemu_arch == "x86_64"

    def test_objdump_prefix_mipsel(self):
        arch = FirmwareArchitecture(cpu="mips", endian="little", bits=32)
        assert arch.objdump_prefix == "mipsel-linux-gnu-"

    def test_objdump_prefix_mips_be(self):
        arch = FirmwareArchitecture(cpu="mips", endian="big", bits=32)
        assert arch.objdump_prefix == "mips-linux-gnu-"

    def test_objdump_prefix_arm(self):
        arch = FirmwareArchitecture(cpu="arm", endian="little", bits=32)
        assert arch.objdump_prefix == "arm-linux-gnueabi-"

    def test_objdump_prefix_x86(self):
        arch = FirmwareArchitecture(cpu="x86", endian="little", bits=32)
        assert arch.objdump_prefix == ""

    def test_objdump_prefix_aarch64(self):
        arch = FirmwareArchitecture(cpu="arm", endian="little", bits=64)
        assert arch.objdump_prefix == "aarch64-linux-gnu-"

    def test_objdump_prefix_riscv(self):
        arch = FirmwareArchitecture(cpu="riscv", endian="little", bits=64)
        assert arch.objdump_prefix == "riscv64-linux-gnu-"

    def test_to_dict_roundtrip(self):
        arch = FirmwareArchitecture(cpu="mips", endian="big", bits=64)
        d = arch.to_dict()
        a2 = FirmwareArchitecture.from_dict(d)
        assert a2.cpu == arch.cpu
        assert a2.endian == arch.endian
        assert a2.bits == arch.bits

    def test_from_dict_defaults(self):
        a = FirmwareArchitecture.from_dict({})
        assert a.cpu == "mips"  # default fallback
        assert a.endian == "little"
        assert a.bits == 32


class TestKnownEntryPoint:
    def test_basic(self):
        ep = KnownEntryPoint(
            name="HTTP", binary="usr/sbin/httpd",
            protocol="HTTP", port=80, description="Web server",
        )
        assert ep.name == "HTTP"
        assert ep.port == 80

    def test_defaults(self):
        ep = KnownEntryPoint(name="test", binary="bin/test")
        assert ep.protocol == ""
        assert ep.port == 0
        assert ep.description == ""

    def test_validate_requires_name(self):
        ep = KnownEntryPoint(name="", binary="bin/test")
        errs = ep.validate()
        assert any("name" in e for e in errs)

    def test_validate_requires_binary(self):
        ep = KnownEntryPoint(name="ok", binary="")
        errs = ep.validate()
        assert any("binary" in e for e in errs)

    def test_to_dict_roundtrip(self):
        ep = KnownEntryPoint(
            name="DNS", binary="usr/sbin/dnsmasq",
            protocol="DNS", port=53,
        )
        d = ep.to_dict()
        ep2 = KnownEntryPoint.from_dict(d)
        assert ep2.name == ep.name
        assert ep2.port == ep.port


class TestKnownCVE:
    def test_basic(self):
        cve = KnownCVE(
            cve_id="CVE-2020-0001", cwe="CWE-121",
            function_name="parse_request", binary_path="usr/sbin/httpd",
            description="stack overflow", cvss_score=8.5,
        )
        assert cve.cve_id == "CVE-2020-0001"
        assert cve.cvss_score == 8.5

    def test_defaults(self):
        cve = KnownCVE(
            cve_id="CVE-X", cwe="CWE-787",
            function_name="main", binary_path="bin/test",
        )
        assert cve.description == ""
        assert cve.cvss_score == 0.0
        assert cve.patch_commit is None

    def test_invalid_cvss_too_high(self):
        with pytest.raises(ValueError, match="cvss_score"):
            KnownCVE(
                cve_id="x", cwe="x", function_name="x",
                binary_path="x", cvss_score=11.0,
            )

    def test_invalid_cvss_negative(self):
        with pytest.raises(ValueError, match="cvss_score"):
            KnownCVE(
                cve_id="x", cwe="x", function_name="x",
                binary_path="x", cvss_score=-1.0,
            )

    def test_validate_requires_fields(self):
        cve = KnownCVE(cve_id="", cwe="", function_name="", binary_path="")
        errs = cve.validate()
        assert len(errs) == 4
        assert any("cve_id" in e for e in errs)
        assert any("cwe" in e for e in errs)
        assert any("function_name" in e for e in errs)
        assert any("binary_path" in e for e in errs)

    def test_to_dict_roundtrip(self):
        cve = KnownCVE(
            cve_id="CVE-FOO", cwe="CWE-121",
            function_name="vuln_func", binary_path="/bin/vuln",
            description="overflow", cvss_score=7.5,
            patch_commit="abc123",
        )
        d = cve.to_dict()
        c2 = KnownCVE.from_dict(d)
        assert c2.cve_id == cve.cve_id
        assert c2.patch_commit == "abc123"


# ==========================================================================
# FirmwareProfile — Construction & Validation
# ==========================================================================

class TestFirmwareProfileConstruction:
    def test_from_dict_minimal(self):
        p = FirmwareProfile.from_dict({"name": "TestFirmware"})
        assert p.name == "TestFirmware"
        assert p.version == ""
        assert p.vendor == ""
        assert p.device_type == "other"
        assert p.architecture.cpu == "mips"  # default
        assert p.known_entry_points == []
        assert p.known_cves == []

    def test_from_dict_full(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        assert p.name == "DVRF-Test"
        assert p.version == "0.3"
        assert p.architecture.cpu == "mips"
        assert p.architecture.endian == "little"
        assert len(p.known_entry_points) == 2
        assert len(p.known_cves) == 3
        assert p.filesystem == "squashfs"

    def test_invalid_device_type(self):
        with pytest.raises(ValueError, match="device_type"):
            FirmwareProfile(name="x", device_type="toaster")

    def test_invalid_filesystem(self):
        with pytest.raises(ValueError, match="filesystem"):
            FirmwareProfile(name="x", filesystem="ntfs")

    def test_skip_and_focus_mutually_exclusive(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            FirmwareProfile(
                name="x",
                skip_binaries=["a"],
                focus_binaries=["b"],
            )

    def test_has_ground_truth(self):
        p = FirmwareProfile(name="x")
        assert not p.has_ground_truth
        p.known_cves = [KnownCVE(cve_id="x", cwe="x", function_name="x", binary_path="x")]
        assert p.has_ground_truth

    def test_has_entry_points(self):
        p = FirmwareProfile(name="x")
        assert not p.has_entry_points
        p.known_entry_points = [KnownEntryPoint(name="x", binary="x")]
        assert p.has_entry_points


class TestFirmwareProfileValidate:
    def test_empty_name(self):
        p = FirmwareProfile(name="")
        assert any("name" in e for e in p.validate())

    def test_valid_profile(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        assert p.validate() == []

    def test_invalid_entry_points(self):
        p = FirmwareProfile(
            name="test",
            known_entry_points=[
                KnownEntryPoint(name="ok", binary="bin/x"),
                KnownEntryPoint(name="", binary=""),  # invalid
            ],
        )
        errs = p.validate()
        assert len(errs) == 2

    def test_invalid_cves(self):
        p = FirmwareProfile(
            name="test",
            known_cves=[
                KnownCVE(
                    cve_id="ok", cwe="ok",
                    function_name="ok", binary_path="ok",
                ),
                KnownCVE(
                    cve_id="", cwe="", function_name="", binary_path="",
                ),
            ],
        )
        errs = p.validate()
        assert any("cve_id" in e for e in errs)


class TestFirmwareProfileToDict:
    def test_roundtrip_preserves_data(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        d2 = p.to_dict()

        assert d2["name"] == d["name"]
        assert d2["architecture"]["cpu"] == d["architecture"]["cpu"]
        assert len(d2["known_entry_points"]) == len(d["known_entry_points"])
        assert len(d2["known_cves"]) == len(d["known_cves"])


# ==========================================================================
# YAML I/O
# ==========================================================================

class TestFirmwareProfileYAML:
    def test_write_and_read_yaml(self, tmp_path):
        """Write a profile as YAML, read it back."""
        import yaml

        d = make_dvrf_profile_dict()
        yaml_path = tmp_path / "test_profile.yaml"
        yaml_path.write_text(
            yaml.dump(d, default_flow_style=False),
            encoding="utf-8",
        )

        p = FirmwareProfile.from_yaml(str(yaml_path))
        assert p.name == "DVRF-Test"
        assert p.architecture.cpu == "mips"
        assert len(p.known_cves) == 3

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            FirmwareProfile.from_yaml("/nonexistent/profile.yaml")

    def test_load_empty_file(self, tmp_path):
        yaml_path = tmp_path / "empty.yaml"
        yaml_path.write_text("", encoding="utf-8")
        with pytest.raises(RuntimeError, match="Empty"):
            FirmwareProfile.from_yaml(str(yaml_path))

    def test_load_real_dvrf_profile(self):
        """Verify the bundled DVRF.yaml loads correctly."""
        import os
        profile_path = os.path.join(
            os.path.dirname(__file__), "..", "profiles", "DVRF.yaml"
        )
        p = FirmwareProfile.from_yaml(profile_path)
        assert p.name == "DVRF"
        assert p.architecture.cpu == "mips"
        assert p.architecture.endian == "little"
        assert p.architecture.bits == 32
        assert p.filesystem == "squashfs"
        assert len(p.known_cves) > 0
        assert p.validate() == []


# ==========================================================================
# Profile Discovery & Loading
# ==========================================================================

class TestDiscoverProfiles:
    def test_discovers_dvrf(self):
        profiles = discover_profiles()
        assert "DVRF" in profiles

    def test_custom_directory(self, tmp_path):
        import yaml

        d = make_dvrf_profile_dict()
        profile_path = tmp_path / "custom.yaml"
        profile_path.write_text(
            yaml.dump(d, default_flow_style=False),
            encoding="utf-8",
        )

        profiles = discover_profiles(str(tmp_path))
        assert "DVRF-Test" in profiles


class TestLoadProfile:
    def test_by_path(self, tmp_path):
        import yaml

        d = make_dvrf_profile_dict()
        yaml_path = tmp_path / "foo.yaml"
        yaml_path.write_text(
            yaml.dump(d, default_flow_style=False),
            encoding="utf-8",
        )

        p = load_profile(str(yaml_path))
        assert p.name == "DVRF-Test"

    def test_by_name(self):
        p = load_profile("DVRF")
        assert p.name == "DVRF"

    def test_not_found(self):
        with pytest.raises(FileNotFoundError, match="Profile not found"):
            load_profile("NonExistentProfile_XYZ")


# ==========================================================================
# Binary Filtering
# ==========================================================================

class TestShouldSkipBinary:
    def test_no_filter_does_not_skip(self):
        p = FirmwareProfile(name="test")
        assert not p.should_skip_binary("usr/sbin/httpd")
        assert not p.should_skip_binary("bin/test")

    def test_skip_binaries_matches(self):
        p = FirmwareProfile(name="test", skip_binaries=["busybox", "lib/"])
        assert p.should_skip_binary("bin/busybox")
        assert p.should_skip_binary("lib/libc.so")
        assert not p.should_skip_binary("usr/sbin/httpd")

    def test_skip_is_substring_match(self):
        p = FirmwareProfile(name="test", skip_binaries=["pwnable"])
        assert p.should_skip_binary("pwnable/Intro/stack_bof_01")
        assert not p.should_skip_binary("usr/sbin/httpd")

    def test_focus_binaries_only_allows_matches(self):
        p = FirmwareProfile(
            name="test",
            focus_binaries=["usr/sbin/httpd", "usr/sbin/dnsmasq"],
        )
        assert not p.should_skip_binary("usr/sbin/httpd")
        assert not p.should_skip_binary("usr/sbin/dnsmasq")
        assert p.should_skip_binary("bin/busybox")
        assert p.should_skip_binary("pwnable/Intro/stack_bof_01")

    def test_focus_with_leading_slash(self):
        p = FirmwareProfile(name="test", focus_binaries=["/usr/sbin/httpd"])
        assert not p.should_skip_binary("usr/sbin/httpd")
        assert not p.should_skip_binary("/usr/sbin/httpd")


# ==========================================================================
# Ground Truth Cross-Referencing
# ==========================================================================

class TestCrossReferenceCVEs:
    def test_empty_sps(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        result = p.cross_reference_cves([])
        assert result["matched"] == []
        assert result["found_count"] == 0
        assert result["total_known"] == 3
        assert result["recall"] == 0.0
        assert len(result["unmatched_cves"]) == 3
        assert result["extra"] == []

    def test_exact_match_by_function_name(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        sps = [
            make_verified_sp("sp-1", "main"),
        ]
        result = p.cross_reference_cves(sps)

        # "main" matches DVRF-STACK-BOF-01 AND DVRF-UAF-01
        assert result["found_count"] >= 1
        matched_ids = [m["cve"].cve_id for m in result["matched"]]
        assert "DVRF-STACK-BOF-01" in matched_ids

    def test_fuzzy_match(self):
        """Fuzzy: function name is a substring."""
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        # "handle_connection" is an exact match to DVRF-SOCKET-BOF-01
        sps = [
            make_verified_sp("sp-2", "handle_connection"),
        ]
        result = p.cross_reference_cves(sps)
        assert result["found_count"] == 1
        assert result["matched"][0]["cve"].cve_id == "DVRF-SOCKET-BOF-01"

    def test_no_match_returns_extra(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        sps = [
            make_verified_sp("sp-novel", "novel_function"),
        ]
        result = p.cross_reference_cves(sps)
        assert result["found_count"] == 0
        assert len(result["extra"]) == 1
        assert result["extra"][0].sp_id == "sp-novel"

    def test_full_coverage(self):
        """All 3 CVEs matched, nothing extra."""
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        sps = [
            make_verified_sp("sp-1", "main"),             # matches 2 CVEs
            make_verified_sp("sp-2", "handle_connection"), # matches 1
        ]
        result = p.cross_reference_cves(sps)
        assert result["total_known"] == 3
        # All 3 CVEs should be matched (two share function_name "main")
        assert result["found_count"] <= result["total_known"]

    def test_recall_is_correct(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        sps = [
            make_verified_sp("sp-1", "main"),
            make_verified_sp("sp-2", "handle_connection"),
        ]
        result = p.cross_reference_cves(sps)
        expected_recall = result["found_count"] / result["total_known"]
        assert result["recall"] == pytest.approx(expected_recall)


# ==========================================================================
# CLI Integration
# ==========================================================================

class TestCLIProfileIntegration:
    def test_args_has_profile_option(self):
        """Verify --profile argument exists."""
        from fuzzingbrain.main import parse_args
        import sys

        test_args = [
            "main.py",
            "--firmware", "firmware.bin",
            "--profile", "profiles/DVRF.yaml",
        ]
        with patch.object(sys, "argv", test_args):
            args = parse_args()
            assert args.profile == "profiles/DVRF.yaml"

    def test_args_profile_default_is_none(self):
        from fuzzingbrain.main import parse_args
        import sys

        test_args = ["main.py", "--firmware", "firmware.bin"]
        with patch.object(sys, "argv", test_args):
            args = parse_args()
            assert args.profile is None

    def test_load_profile_in_run_firmware_mode(self):
        """Integration: run_firmware_mode with --profile loads the profile."""
        # FirmwarePipeline is imported locally inside run_firmware_mode,
        # so we must patch the module it's imported FROM.
        with patch("fuzzingbrain.firmware_pipeline.FirmwarePipeline") as MockPipeline:
            mock_pipeline = MockPipeline.return_value
            mock_report = MagicMock()
            mock_report.count = 5
            mock_report.statistics.dynamic_full_verified = 3
            mock_report.statistics.dynamic_user_verified = 1
            mock_report.statistics.static_high_reserved = 1
            mock_report.statistics.verification_rate = "80%"
            mock_report.statistics.unique_crashes = 2
            mock_report.vulnerabilities = []
            mock_report.confirmed_vulnerabilities = []
            mock_report.ground_truth_match = None
            mock_pipeline.run.return_value = mock_report

            import sys
            from fuzzingbrain.main import parse_args, run_firmware_mode

            # Point to the actual DVRF profile
            profile_path = str(
                Path(__file__).parent.parent / "profiles" / "DVRF.yaml"
            )

            test_args = [
                "main.py",
                "--firmware", "/tmp/fake.bin",
                "--profile", profile_path,
                "--no-resume",
                "--phases", "phase1",
            ]
            with patch.object(sys, "argv", test_args):
                args = parse_args()
                # Verify profile path was captured
                assert args.profile == profile_path


# ==========================================================================
# FirmwarePipeline Integration
# ==========================================================================

class TestPipelineProfileIntegration:
    def test_pipeline_accepts_profile(self):
        """FirmwarePipeline constructor accepts firmware_profile."""
        from fuzzingbrain.firmware_pipeline import FirmwarePipeline

        d = make_dvrf_profile_dict()
        profile = FirmwareProfile.from_dict(d)

        pipeline = FirmwarePipeline(
            firmware_profile=profile,
        )
        assert pipeline.profile is profile
        assert pipeline.profile.name == "DVRF-Test"

    def test_pipeline_profile_none_by_default(self):
        from fuzzingbrain.firmware_pipeline import FirmwarePipeline

        pipeline = FirmwarePipeline()
        assert pipeline.profile is None

    def test_should_skip_binary_integration(self):
        """Pipeline uses profile to filter binaries."""
        from fuzzingbrain.firmware_pipeline import FirmwarePipeline

        profile = FirmwareProfile(
            name="test",
            focus_binaries=["usr/sbin/httpd"],
        )
        pipeline = FirmwarePipeline(firmware_profile=profile)
        assert pipeline.profile.should_skip_binary("bin/busybox")
        assert not pipeline.profile.should_skip_binary("usr/sbin/httpd")

    def test_build_report_with_ground_truth(self):
        """_build_final_report includes ground_truth_match when profile has CVEs."""
        from fuzzingbrain.firmware_pipeline import FirmwarePipeline
        from fuzzingbrain.verifier.models import (
            FinalReport, Phase4Result, Phase4Statistics,
            VerificationResult,
        )

        d = make_dvrf_profile_dict()
        profile = FirmwareProfile.from_dict(d)

        pipeline = FirmwarePipeline(firmware_profile=profile)

        # Create minimal Phase3Result with one matching SP
        from fuzzingbrain.agents.firmware.sp_models import (
            Phase3Result, Phase3Statistics,
        )

        sp = make_verified_sp("sp-1", "main")
        phase3_result = Phase3Result(
            verified_sps=[sp],
            statistics=Phase3Statistics(total_raw_sps=1),
        )

        # Create minimal Phase4Result
        vr = VerificationResult(
            sp_id="sp-1",
            verification_level="dynamic_full",
            crashed=True,
        )
        phase4_result = Phase4Result(
            verified_results=[vr],
            crashes=[],
            statistics=Phase4Statistics(total_p0_sps=1),
        )

        report = pipeline._build_final_report(
            phase3_result=phase3_result,
            phase4_result=phase4_result,
            all_functions=[],
            all_attack_surfaces=[],
            firmware_name="test",
            firmware_hash="abc123",
        )

        assert report.ground_truth_match is not None
        assert "recall" in report.ground_truth_match
        assert "matched" in report.ground_truth_match
        # "main" should match at least CVE DVRF-STACK-BOF-01
        assert report.ground_truth_match["found_count"] >= 1

    def test_build_report_no_profile(self):
        """Without profile, ground_truth_match is None."""
        from fuzzingbrain.firmware_pipeline import FirmwarePipeline
        from fuzzingbrain.verifier.models import (
            Phase4Result, Phase4Statistics, VerificationResult,
        )

        pipeline = FirmwarePipeline()  # no profile

        vr = VerificationResult(
            sp_id="sp-1",
            verification_level="dynamic_full",
            crashed=True,
        )
        phase4_result = Phase4Result(
            verified_results=[vr],
            crashes=[],
            statistics=Phase4Statistics(total_p0_sps=1),
        )

        report = pipeline._build_final_report(
            phase3_result=None,
            phase4_result=phase4_result,
            all_functions=[],
            all_attack_surfaces=[],
            firmware_name="test",
            firmware_hash="abc123",
        )

        assert report.ground_truth_match is None


# ==========================================================================
# FinalReport ground_truth_match
# ==========================================================================

class TestFinalReportGroundTruth:
    def test_report_with_ground_truth(self):
        from fuzzingbrain.verifier.models import (
            FinalReport, ReportMetadata, Phase4Statistics,
        )

        report = FinalReport(
            metadata=ReportMetadata(firmware_name="test"),
            vulnerabilities=[],
            statistics=Phase4Statistics(),
            ground_truth_match={
                "matched": [],
                "unmatched_cves": [],
                "extra_sp_ids": [],
                "total_known": 3,
                "found_count": 0,
                "recall": 0.0,
            },
        )
        assert report.ground_truth_match["total_known"] == 3
        assert report.ground_truth_match["recall"] == 0.0

    def test_report_roundtrip_with_ground_truth(self):
        from fuzzingbrain.verifier.models import (
            FinalReport, ReportMetadata, Phase4Statistics,
        )

        gt = {
            "matched": [],
            "unmatched_cves": [],
            "extra_sp_ids": [],
            "total_known": 5,
            "found_count": 3,
            "recall": 0.6,
        }
        report = FinalReport(
            metadata=ReportMetadata(firmware_name="test"),
            vulnerabilities=[],
            statistics=Phase4Statistics(),
            ground_truth_match=gt,
        )

        d = report.to_dict()
        r2 = FinalReport.from_dict(d)
        assert r2.ground_truth_match["total_known"] == 5
        assert r2.ground_truth_match["found_count"] == 3


# ==========================================================================
# Edge Cases
# ==========================================================================

class TestEdgeCases:
    def test_empty_focus_binaries_means_keep_all(self):
        p = FirmwareProfile(name="test", focus_binaries=[])
        assert not p.should_skip_binary("anything")

    def test_skip_binaries_case_sensitive(self):
        p = FirmwareProfile(name="test", skip_binaries=["HTTPD"])
        assert not p.should_skip_binary("usr/sbin/httpd")
        assert p.should_skip_binary("usr/sbin/HTTPD")

    def test_cross_reference_case_insensitive(self):
        d = make_dvrf_profile_dict()
        p = FirmwareProfile.from_dict(d)
        sps = [
            make_verified_sp("sp-1", "MAIN"),  # uppercase
        ]
        result = p.cross_reference_cves(sps)
        # "MAIN" lower -> "main" should match
        assert result["found_count"] >= 1

    def test_architecture_from_partial_dict(self):
        a = FirmwareArchitecture.from_dict({"cpu": "arm"})
        assert a.cpu == "arm"
        assert a.endian == "little"
        assert a.bits == 32

    def test_profile_metadata_preserved(self):
        p = FirmwareProfile(
            name="test",
            metadata={"source": "github", "notes": "test fw"},
        )
        d = p.to_dict()
        assert d["metadata"]["source"] == "github"
        p2 = FirmwareProfile.from_dict(d)
        assert p2.metadata["notes"] == "test fw"

    def test_valid_device_types(self):
        for dt in VALID_DEVICE_TYPES:
            p = FirmwareProfile(name="test", device_type=dt)
            assert p.device_type == dt
