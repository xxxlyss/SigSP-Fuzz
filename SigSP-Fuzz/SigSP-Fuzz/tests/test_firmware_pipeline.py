"""End-to-end integration tests for FirmwarePipeline.

Tests the complete firmware.bin → FinalReport orchestration with all
external dependencies mocked (LLM, binwalk, Ghidra, FirmAE, QEMU).
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from fuzzingbrain.firmware_pipeline import FirmwarePipeline
from fuzzingbrain.verifier.models import (
    CrashInfo,
    FinalReport,
    Phase4Result,
    Phase4Statistics,
    PoC,
    PoCTarget,
    ReportMetadata,
    VerificationResult,
    VulnerabilityEntry,
)
from fuzzingbrain.agents.firmware.sp_models import (
    AnalystConsensus,
    CrossReviewVerdict,
    ExploitabilityAssessment,
    FirmwareSP,
    Phase3Result,
    Phase3Statistics,
    VerifiedSP,
)
from fuzzingbrain.attack_surface.models import (
    AnalysisOrder,
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    PortInfo,
)
from fuzzingbrain.static.models import (
    AnalysisResult,
    BinaryInfo,
    CallGraph,
    CallGraphNode,
    ExtractResult,
    FunctionInfo,
    StringRef,
)


# ============================================================================
# Test Helpers
# ============================================================================


def make_function(name="httpd_handler", address=0x2100, arch="arm"):
    return FunctionInfo(
        name=name,
        address=address,
        pseudo_code=f"void {name}(void) {{ char buf[256]; strcpy(buf, input); }}",
        callees=["strcpy"],
        callers=["main"],
        strings_used=["GET", "/cgi-bin/"],
        dangerous_funcs=["strcpy"],
        has_unsafe_calls=True,
        arch=arch,
        binary_path="/bin/httpd",
    )


def make_p0_sp(sp_id="SP-001", function_name="httpd_handler", priority="P0"):
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
        description="strcpy without bounds check on user input",
        function_name=function_name,
        vulnerable_code_snippet="char buf[256]; strcpy(buf, input);",
        control_flow="main -> httpd_handler -> strcpy",
        trigger_condition="Send oversized HTTP POST body",
        root_cause="Missing bounds check before strcpy",
        exploitability=ea, confidence=0.85, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority=priority,
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_attack_surface():
    return AttackSurface(
        name="HTTP Server", category="network_service",
        entry_functions=["main", "httpd_handler"],
        description="HTTP request processing on port 80",
        protocol="HTTP",
        port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
        strings_evidence=["GET", "/cgi-bin/"],
        risks=["buffer_overflow", "command_injection"],
    )


def make_callgraph():
    nodes = {
        "main": CallGraphNode(function_name="main", address=0x1000,
                             callees=["httpd_handler"]),
        "httpd_handler": CallGraphNode(function_name="httpd_handler",
                                       address=0x2100,
                                       callees=["strcpy"],
                                       callers=["main"]),
        "strcpy": CallGraphNode(function_name="strcpy", address=0x3000,
                                callers=["httpd_handler"]),
    }
    return CallGraph(binary_path="/bin/httpd", nodes=nodes)


def make_direction_result():
    direction = Direction(
        name="HTTP Processing",
        description="HTTP request handling",
        category="http_processing",
        entry_functions=["main"],
        core_functions=["httpd_handler"],
        big_pool=["httpd_handler", "main"],
        primary_attack_types=["buffer_overflow"],
        priority=5,
        estimated_complexity="medium",
        rationale="Network-facing unauthenticated input processing",
    )
    order = AnalysisOrder(
        recommended_sequence=["HTTP Processing"],
        rationale="Highest priority attack surface",
    )
    return DirectionResult(directions=[direction], analysis_order=order)


def make_phase3_result():
    stats = Phase3Statistics(
        total_raw_sps=3,
        after_dedup=2,
        after_verification=1,
        discarded_as_false_positive=1,
        false_positive_rate_estimate=0.33,
        high_confidence_sps=1,
        needs_dynamic_verification=1,
    )
    return Phase3Result(
        verified_sps=[make_p0_sp()],
        statistics=stats,
    )


def make_phase4_result():
    vr = VerificationResult(
        sp_id="SP-001",
        verification_level="dynamic_user",
        crashed=True,
        crash_info=CrashInfo(
            crash_type="SIGSEGV",
            crash_address="0x41414141",
            signal_number=11,
            register_state={"PC": "0x41414141", "SP": "0xbefffc00"},
            backtrace=["0x41414141", "httpd_handler+0x10", "main+0x20"],
        ),
    )
    stats = Phase4Statistics(
        total_p0_sps=1,
        poc_generated=1,
        dynamic_user_verified=1,
        unique_crashes=1,
        verification_rate="100.0%",
    )
    return Phase4Result(
        verified_results=[vr],
        crashes=[vr.crash_info],
        statistics=stats,
    )


# ============================================================================
# Tests: _build_final_report (pure function, no mocking needed)
# ============================================================================


class TestBuildFinalReport:
    """Test the _build_final_report method in isolation."""

    def test_build_from_phase3_phase4(self):
        """Should cross-reference VerifiedSPs with VerificationResults."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        phase3 = make_phase3_result()
        phase4 = make_phase4_result()
        functions = [make_function()]
        attack_surfaces = [make_attack_surface()]

        report = pipeline._build_final_report(
            phase3_result=phase3,
            phase4_result=phase4,
            all_functions=functions,
            all_attack_surfaces=attack_surfaces,
            firmware_name="TestFW",
            firmware_hash="abc123",
        )

        assert isinstance(report, FinalReport)
        assert report.count == 1
        assert report.metadata.firmware_name == "TestFW"
        assert report.metadata.firmware_hash == "abc123"
        assert report.metadata.total_functions_analyzed == 1
        assert report.metadata.total_attack_surfaces == 1

        v = report.vulnerabilities[0]
        assert v.sp_id == "SP-001"
        assert v.cwe == "CWE-121"
        assert v.function_name == "httpd_handler"
        assert v.priority == "P0"
        assert v.confidence == 0.85
        assert v.verification_level == "dynamic_user"
        assert v.crash_info is not None
        assert v.crash_info.crash_type == "SIGSEGV"

    def test_discovered_crashes_included(self):
        """Phase4 discovered crashes (without VerifiedSP) should be in report."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        phase3 = Phase3Result(
            verified_sps=[],
            statistics=Phase3Statistics(),
        )
        vr = VerificationResult(
            sp_id="DISCOVERED-001",
            verification_level="dynamic_full",
            crashed=True,
            crash_info=CrashInfo(
                crash_type="SIGABRT",
                crash_address="0xdeadbeef",
            ),
        )
        stats = Phase4Statistics(
            total_p0_sps=1,
            dynamic_full_verified=1,
            unique_crashes=1,
            verification_rate="100.0%",
        )
        phase4 = Phase4Result(verified_results=[vr], crashes=[], statistics=stats)

        report = pipeline._build_final_report(
            phase3_result=phase3,
            phase4_result=phase4,
            all_functions=[],
            all_attack_surfaces=[],
            firmware_name="TestFW",
            firmware_hash="abc123",
        )

        assert report.count == 1
        assert report.vulnerabilities[0].sp_id == "DISCOVERED-001"
        assert report.vulnerabilities[0].verification_level == "dynamic_full"

    def test_static_low_discarded(self):
        """SPs with verification_level=static_low are excluded from report."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        phase3 = Phase3Result(
            verified_sps=[make_p0_sp("SP-001")],
            statistics=Phase3Statistics(),
        )
        vr = VerificationResult(
            sp_id="SP-001",
            verification_level="static_low",
            crashed=False,
        )
        stats = Phase4Statistics(
            total_p0_sps=1,
            discarded=1,
            verification_rate="0.0%",
        )
        phase4 = Phase4Result(verified_results=[vr], crashes=[], statistics=stats)

        report = pipeline._build_final_report(
            phase3_result=phase3,
            phase4_result=phase4,
            all_functions=[],
            all_attack_surfaces=[],
            firmware_name="TestFW",
            firmware_hash="abc123",
        )

        assert report.count == 0

    def test_vulnerabilities_sorted_by_priority(self):
        """P0 SPs should come before P1, P2, P3."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")

        sps = [
            make_p0_sp("SP-P2", priority="P2"),
            make_p0_sp("SP-P0", priority="P0"),
            make_p0_sp("SP-P1", priority="P1"),
        ]
        phase3 = Phase3Result(verified_sps=sps, statistics=Phase3Statistics())
        vrs = [
            VerificationResult(sp_id="SP-P0", verification_level="dynamic_full", crashed=True),
            VerificationResult(sp_id="SP-P1", verification_level="dynamic_full", crashed=True),
            VerificationResult(sp_id="SP-P2", verification_level="dynamic_full", crashed=True),
        ]
        stats = Phase4Statistics(total_p0_sps=3, dynamic_full_verified=3)
        phase4 = Phase4Result(verified_results=vrs, crashes=[], statistics=stats)

        report = pipeline._build_final_report(
            phase3_result=phase3, phase4_result=phase4,
            all_functions=[], all_attack_surfaces=[],
            firmware_name="TestFW", firmware_hash="abc",
        )

        priorities = [v.priority for v in report.vulnerabilities]
        assert priorities == ["P0", "P1", "P2"]

    def test_empty_phase3_ok(self):
        """None Phase3 should not crash — creates entries without VS metadata."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        vr = VerificationResult(
            sp_id="SP-001",
            verification_level="dynamic_full",
            crashed=True,
        )
        stats = Phase4Statistics(total_p0_sps=1, dynamic_full_verified=1)
        phase4 = Phase4Result(verified_results=[vr], crashes=[], statistics=stats)

        report = pipeline._build_final_report(
            phase3_result=None,
            phase4_result=phase4,
            all_functions=[],
            all_attack_surfaces=[],
            firmware_name="TestFW",
            firmware_hash="abc123",
        )

        assert report.count == 1
        assert report.vulnerabilities[0].cwe == "unknown"


# ============================================================================
# Tests: Checkpoint save/load
# ============================================================================


class TestCheckpointIO:
    """Test Phase 1 checkpoint save/load roundtrip."""

    def test_phase1_save_load_roundtrip(self):
        """Phase 1 checkpoint should survive a save→load cycle."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        functions = [make_function("func_a", 0x1000), make_function("func_b", 0x2000)]
        cg = make_callgraph()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "phase1_result.json"
            pipeline._save_phase1(path, functions, cg, "TestFW")

            assert path.exists()
            loaded_funcs, loaded_cg = pipeline._load_phase1(path)

            assert len(loaded_funcs) == 2
            assert loaded_funcs[0].name == "func_a"
            assert loaded_funcs[0].address == 0x1000
            assert loaded_funcs[0].callees == ["strcpy"]
            assert loaded_cg.node_count == 3
            assert "httpd_handler" in loaded_cg.nodes

    def test_load_nonexistent_checkpoint_raises(self):
        """Loading a nonexistent checkpoint should raise FileNotFoundError."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nonexistent.json"
            with pytest.raises(FileNotFoundError):
                pipeline._load_phase1(path)

    def test_load_empty_functions(self):
        """Checkpoint with empty function list should load correctly."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        cg = CallGraph(binary_path="/bin/test")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "phase1_result.json"
            pipeline._save_phase1(path, [], cg, "TestFW")

            loaded_funcs, loaded_cg = pipeline._load_phase1(path)

            assert len(loaded_funcs) == 0
            assert loaded_cg.node_count == 0


# ============================================================================
# Tests: Firmware hash
# ============================================================================


class TestFirmwareHash:
    """Test firmware hash computation."""

    def test_hash_small_file(self):
        """Small file should be hashed completely."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"A" * 1000)
            f.flush()
            result = pipeline._hash_firmware(f.name)
        Path(f.name).unlink()
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_large_file(self):
        """Large file should be hashed (first 4KB + last 4KB)."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"X" * 20000)
            f.flush()
            result = pipeline._hash_firmware(f.name)
        Path(f.name).unlink()
        assert len(result) == 64

    def test_hash_deterministic(self):
        """Same content → same hash."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test firmware content")
            f.flush()
            h1 = pipeline._hash_firmware(f.name)
            h2 = pipeline._hash_firmware(f.name)
        Path(f.name).unlink()
        assert h1 == h2


# ============================================================================
# Tests: Phase filtering
# ============================================================================


class TestPhaseFiltering:
    """Test selective phase execution."""

    def test_valid_phases_accepted(self):
        """All VALID_PHASES should be accepted."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        assert FirmwarePipeline.VALID_PHASES == {"phase1", "phase2", "phase3", "phase4"}

    def test_invalid_phase_rejected_by_cli_validation(self):
        """Invalid phases should be caught (test the set logic)."""
        invalid = {"phase5", "phaseX"}
        valid = FirmwarePipeline.VALID_PHASES
        assert invalid - valid == {"phase5", "phaseX"}


# ============================================================================
# Tests: Full pipeline with mocked phases
# ============================================================================


class TestFullPipelineMocked:
    """End-to-end tests with all heavy phases mocked."""

    @pytest.fixture
    def mock_phase1(self):
        """Mock binwalk extraction + Ghidra analysis."""
        with patch.object(
            FirmwarePipeline, "_run_phase1",
            return_value=(
                [make_function()],
                make_callgraph(),
            ),
        ) as mock:
            yield mock

    @pytest.fixture
    def mock_phase2(self):
        """Mock attack surface + direction planning."""
        as_result = AttackSurfaceResult(
            attack_surfaces=[make_attack_surface()],
            summary=AttackSurfaceSummary(
                total_attack_surfaces=1,
                primary_exposure="HTTP server on port 80",
            ),
        )
        with patch.object(
            FirmwarePipeline, "_run_phase2",
            return_value=(as_result, make_direction_result()),
        ) as mock:
            yield mock

    @pytest.fixture
    def mock_phase3(self):
        """Mock Phase3Pipeline.run()."""
        with patch(
            "fuzzingbrain.agents.firmware.pipeline.Phase3Pipeline.run",
            return_value=make_phase3_result(),
        ) as mock:
            yield mock

    @pytest.fixture
    def mock_phase4(self):
        """Mock Phase4Pipeline.run()."""
        with patch(
            "fuzzingbrain.verifier.pipeline.Phase4Pipeline.run",
            return_value=make_phase4_result(),
        ) as mock:
            yield mock

    @pytest.fixture
    def mock_llm(self):
        """Mock LLMClient to avoid real API calls."""
        with patch("fuzzingbrain.firmware_pipeline.LLMClient") as mock:
            mock.return_value = MagicMock()
            yield mock

    def test_full_pipeline_all_phases(
        self, mock_llm, mock_phase1, mock_phase2, mock_phase3, mock_phase4, tmp_path
    ):
        """Complete mocked pipeline should produce a FinalReport."""
        # Create a fake firmware file
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        pipeline = FirmwarePipeline(
            output_dir=str(output_dir),
            llm_client=MagicMock(),
        )
        report = pipeline.run(
            str(fw_path),
            firmware_name="TestRouter_v1",
            resume=False,  # Don't try to load from checkpoint
        )

        assert isinstance(report, FinalReport)
        assert report.count == 1
        assert report.metadata.firmware_name == "TestRouter_v1"
        assert report.statistics.dynamic_user_verified == 1
        assert report.statistics.verification_rate == "100.0%"

        # Check that all phases were called
        mock_phase1.assert_called_once()
        mock_phase2.assert_called_once()
        mock_phase3.assert_called_once()
        mock_phase4.assert_called_once()

    def test_full_pipeline_creates_output_files(
        self, mock_llm, mock_phase1, mock_phase2, mock_phase3, mock_phase4, tmp_path
    ):
        """Pipeline should create JSON and Markdown report files."""
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        pipeline = FirmwarePipeline(
            output_dir=str(output_dir),
            llm_client=MagicMock(),
        )
        pipeline.run(str(fw_path), firmware_name="TestRouter", resume=False)

        task_dir = output_dir / "TestRouter"
        assert task_dir.exists()
        assert (task_dir / "final_report.json").exists()
        assert (task_dir / "final_report.md").exists()

        # Verify JSON is valid
        data = json.loads((task_dir / "final_report.json").read_text())
        assert data["metadata"]["firmware_name"] == "TestRouter"
        assert len(data["vulnerabilities"]) == 1

    def test_resume_skips_completed_phases(
        self, mock_llm, mock_phase1, mock_phase2, mock_phase3, mock_phase4, tmp_path
    ):
        """With resume=True, phases with checkpoints should be skipped."""
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        task_dir = output_dir / "TestRouter"
        task_dir.mkdir(parents=True)

        # Pre-create Phase 1-3 checkpoints
        phase3_result = make_phase3_result()
        pipeline = FirmwarePipeline(output_dir=str(output_dir), llm_client=MagicMock())

        # Save Phase 3 checkpoint (this will cause Phase 1-3 to be skipped if
        # they also exist, but Phase 4 doesn't)
        pipeline._phase3.save(phase3_result, task_dir / "phase3_result.json")

        # Save Phase 1 and 2 checkpoints too
        phase1_path = task_dir / "phase1_result.json"
        pipeline._save_phase1(phase1_path, [make_function()], make_callgraph(), "TestRouter")

        as_data = AttackSurfaceResult(
            attack_surfaces=[make_attack_surface()],
            summary=AttackSurfaceSummary(total_attack_surfaces=1, primary_exposure="HTTP"),
        ).to_dict()
        (task_dir / "phase2_attack_surfaces.json").write_text(json.dumps(as_data))
        (task_dir / "phase2_directions.json").write_text(json.dumps(make_direction_result().to_dict()))

        # Now run with resume=True
        pipeline.run(str(fw_path), firmware_name="TestRouter", resume=True)

        # Phase 1-3 should be SKIPPED (checkpoint exists), only Phase 4 runs
        mock_phase1.assert_not_called()
        mock_phase2.assert_not_called()
        # Phase 3 should have been loaded from checkpoint, not run
        mock_phase3.assert_not_called()
        # Phase 4 should still run
        mock_phase4.assert_called_once()

    def test_selective_phases_only_phase3_phase4(
        self, mock_llm, mock_phase1, mock_phase2, mock_phase3, mock_phase4, tmp_path
    ):
        """Running only phase3+phase4 should skip 1 and 2."""
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        task_dir = output_dir / "TestRouter"
        task_dir.mkdir(parents=True)

        # Pre-create Phase 1 and 2 checkpoints (required for Phase 3)
        pipeline = FirmwarePipeline(output_dir=str(output_dir), llm_client=MagicMock())
        phase1_path = task_dir / "phase1_result.json"
        pipeline._save_phase1(phase1_path, [make_function()], make_callgraph(), "TestRouter")

        as_data = AttackSurfaceResult(
            attack_surfaces=[make_attack_surface()],
            summary=AttackSurfaceSummary(total_attack_surfaces=1, primary_exposure="HTTP"),
        ).to_dict()
        (task_dir / "phase2_attack_surfaces.json").write_text(json.dumps(as_data))
        (task_dir / "phase2_directions.json").write_text(json.dumps(make_direction_result().to_dict()))

        pipeline.run(
            str(fw_path),
            firmware_name="TestRouter",
            resume=True,
            phases={"phase3", "phase4"},
        )

        mock_phase1.assert_not_called()
        mock_phase2.assert_not_called()
        mock_phase3.assert_called_once()
        mock_phase4.assert_called_once()

    def test_phase4_requires_phase3(self, mock_llm, tmp_path):
        """Phase 4 without Phase 3 checkpoint should raise RuntimeError."""
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        task_dir = output_dir / "TestRouter"
        task_dir.mkdir(parents=True)

        pipeline = FirmwarePipeline(output_dir=str(output_dir), llm_client=MagicMock())

        # Save Phase 1 and 2 but NOT Phase 3
        phase1_path = task_dir / "phase1_result.json"
        pipeline._save_phase1(phase1_path, [make_function()], make_callgraph(), "TestRouter")

        as_data = AttackSurfaceResult(
            attack_surfaces=[make_attack_surface()],
            summary=AttackSurfaceSummary(total_attack_surfaces=1, primary_exposure="HTTP"),
        ).to_dict()
        (task_dir / "phase2_attack_surfaces.json").write_text(json.dumps(as_data))
        (task_dir / "phase2_directions.json").write_text(json.dumps(make_direction_result().to_dict()))

        with pytest.raises(RuntimeError, match="Phase 4 requires phase3_result"):
            pipeline.run(
                str(fw_path),
                firmware_name="TestRouter",
                resume=True,
                phases={"phase4"},
            )

    def test_firmware_not_found_raises(self):
        """Missing firmware file should raise FileNotFoundError."""
        pipeline = FirmwarePipeline(output_dir="/tmp/test")
        with pytest.raises(FileNotFoundError, match="Firmware not found"):
            pipeline.run("/nonexistent/firmware.bin")

    def test_auto_derive_firmware_name(self, mock_llm, mock_phase1, mock_phase2,
                                        mock_phase3, mock_phase4, tmp_path):
        """Firmware name should be derived from filename if not provided."""
        fw_path = tmp_path / "Netgear_R7000_v1.0.1.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        pipeline = FirmwarePipeline(output_dir=str(output_dir), llm_client=MagicMock())
        report = pipeline.run(str(fw_path), resume=False)

        assert report.metadata.firmware_name == "Netgear_R7000_v1.0.1"

    def test_markdown_report_content(
        self, mock_llm, mock_phase1, mock_phase2, mock_phase3, mock_phase4, tmp_path
    ):
        """Generated Markdown report should contain key sections."""
        fw_path = tmp_path / "test_firmware.bin"
        fw_path.write_bytes(b"\x00" * 4096)

        output_dir = tmp_path / "results"
        pipeline = FirmwarePipeline(output_dir=str(output_dir), llm_client=MagicMock())
        pipeline.run(str(fw_path), firmware_name="TestRouter", resume=False)

        md_path = output_dir / "TestRouter" / "final_report.md"
        content = md_path.read_text()

        assert "# Firmware Vulnerability Analysis Report" in content
        assert "TestRouter" in content
        assert "Executive Summary" in content
        assert "Statistics" in content
        assert "Vulnerability Details" in content
        assert "Methodology" in content
        assert "Ghidra" in content  # methodology mentions it
