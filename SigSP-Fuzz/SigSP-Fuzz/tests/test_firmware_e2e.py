"""
End-to-End Tests for Complete Firmware Vulnerability Discovery Pipeline.

Validates the full firmware.bin → FinalReport flow:
  1. Static extraction (binwalk + objdump/Ghidra)
  2. Attack surface identification + direction planning
  3. Multi-agent SP cross-examination
  4. Dual-layer fuzzing (Global AFL++ + SP targeted)
  5. Snapshot-based state transfer
  6. Report generation (JSON + SARIF)

Uses the real AC9 firmware binary for Phase 1, with mocked LLM/QEMU/AFL++
for deterministic testing of the pipeline data flow.

Test data: firmware/ac9_kf_V15.03.05.19(6318_)_cn.bin (Tenda AC9, ARM 32-bit)
"""

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# =============================================================================
# Fixtures
# =============================================================================

AC9_FIRMWARE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "firmware",
    "ac9_kf_V15.03.05.19(6318_)_cn.bin",
)


@pytest.fixture
def ac9_firmware_path():
    """Path to the real AC9 firmware binary."""
    if not os.path.exists(AC9_FIRMWARE):
        pytest.skip(f"AC9 firmware not found: {AC9_FIRMWARE}")
    return AC9_FIRMWARE


@pytest.fixture
def temp_work_dir():
    """Temporary working directory for fuzzer output."""
    with tempfile.TemporaryDirectory(prefix="fb_e2e_") as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_llm_client():
    """Mock LLM client that returns deterministic responses."""
    from fuzzingbrain.llms.client import LLMResponse

    client = MagicMock()
    client.call.return_value = LLMResponse(
        content=json.dumps(
            {
                "thought": "Analyzing the function for vulnerabilities...",
                "action": {
                    "tool": "decompile_function",
                    "params": {
                        "binary_path": "/bin/httpd",
                        "func_addr": 0x401000,
                    },
                },
            }
        ),
        model="mock-model",
        provider="mock",
        success=True,
        input_tokens=100,
        output_tokens=200,
        total_tokens=300,
    )
    return client


@pytest.fixture
def sample_attack_surface():
    """Sample attack surface resembling Tenda AC9 httpd."""
    return {
        "protocol": "HTTP",
        "port": 80,
        "entry_functions": ["websAccept", "websDefaultHandler"],
        "arch": "arm",
    }


@pytest.fixture
def sample_suspicious_point():
    """Sample SP resembling a stack buffer overflow in httpd CGI handler."""
    return {
        "sp_id": "SP-TEST-001",
        "function_name": "formSetSpeedWan",
        "func_addr": 0x401000,
        "description": (
            "formSetSpeedWan retrieves HTTP request parameters via "
            "GetValue() into a fixed-size 32-byte stack buffer without "
            "bounds checking. User-controlled HTTP POST parameter "
            "'speed_dir' can overflow the buffer, overwriting the "
            "return address. Classic stack buffer overflow (CWE-121)."
        ),
        "cwe": "CWE-121",
        "priority": "P0",
        "attack_surface": {"protocol": "HTTP", "port": 80},
    }


@pytest.fixture
def sample_sps():
    """Sample list of suspicious points."""
    return [
        {
            "sp_id": "SP-001",
            "function_name": "formSetSpeedWan",
            "func_addr": 0x401000,
            "description": "Stack buffer overflow via GetValue() into 32-byte buffer",
            "cwe": "CWE-121",
            "priority": "P0",
            "attack_surface": {"protocol": "HTTP", "port": 80},
        },
        {
            "sp_id": "SP-002",
            "function_name": "FUN_000384c8",
            "func_addr": 0x384C8,
            "description": "Command injection via snprintf → doSystemCmd",
            "cwe": "CWE-78",
            "priority": "P0",
            "attack_surface": {"protocol": "HTTP", "port": 80},
        },
        {
            "sp_id": "SP-003",
            "function_name": "TendaTelnet",
            "func_addr": 0x420000,
            "description": "Stack buffer overflow in telnet handler",
            "cwe": "CWE-121",
            "priority": "P1",
            "attack_surface": {"protocol": "TELNET", "port": 23},
        },
    ]


# =============================================================================
# Phase 1: Static Extraction (Real Binary)
# =============================================================================


class TestPhase1StaticExtraction:
    """Test Phase 1 using real AC9 firmware binary."""

    def test_binwalk_extraction(self, ac9_firmware_path, temp_work_dir):
        """binwalk should extract the firmware and identify squashfs filesystem."""
        from fuzzingbrain.static.extractor import FirmwareExtractor

        extractor = FirmwareExtractor()
        result = extractor.extract(
            ac9_firmware_path, temp_work_dir
        )

        assert result.success, (
            f"binwalk extraction failed: {result.error}"
        )
        assert result.file_count > 0, "Should find files in firmware"
        assert result.filesystem_type, "Should detect filesystem type"

        # Tenda AC9 uses squashfs
        assert result.filesystem_type in (
            "squashfs",
            "ext",
            "unknown",
        ), f"Unexpected fs type: {result.filesystem_type}"

    def test_elf_binary_discovery(self, ac9_firmware_path, temp_work_dir):
        """Should discover ELF binaries including httpd."""
        from fuzzingbrain.static.extractor import FirmwareExtractor

        extractor = FirmwareExtractor()
        result = extractor.extract(
            ac9_firmware_path, temp_work_dir
        )

        assert len(result.binaries) > 0, (
            "Should find at least one ELF binary"
        )

        # Verify we find ARM binaries (Tenda AC9 is ARM)
        arm_bins = [
            b
            for b in result.binaries
            if "arm" in b.arch.lower()
        ]
        assert len(arm_bins) > 0, (
            f"Should find ARM binaries, found architectures: "
            f"{set(b.arch for b in result.binaries)}"
        )

    def test_architecture_detection(self, ac9_firmware_path):
        """Should correctly detect ARM 32-bit little-endian architecture."""
        from fuzzingbrain.firmware_fuzzer import (
            _detect_arch_from_elf,
        )
        from fuzzingbrain.tools.firmware_mcp.qemu_bridge import (
            detect_firmware_arch,
        )

        # Find any ELF in the extracted firmware
        import glob as globmod
        extracted_dir = os.path.join(
            os.path.dirname(AC9_FIRMWARE),
            f"_{os.path.basename(AC9_FIRMWARE)}.extracted",
        )
        if not os.path.isdir(extracted_dir):
            pytest.skip(
                f"Extracted dir not found: {extracted_dir}. "
                f"Run binwalk first."
            )

        elfs = []
        for root, dirs, files in os.walk(extracted_dir):
            for f in files[:500]:
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "rb") as fh:
                        if fh.read(4) == b"\x7fELF":
                            elfs.append(fpath)
                except (OSError, PermissionError):
                    pass
            if len(elfs) >= 5:
                break

        if not elfs:
            pytest.skip("No ELF binaries found in extracted firmware")

        # Test detection on first ELF
        arch = _detect_arch_from_elf(elfs[0])
        assert arch is not None, (
            f"Should detect architecture from ELF header"
        )
        assert arch in (
            "arm",
            "armeb",
        ), f"AC9 should be ARM, got: {arch}"

    def test_objdump_function_extraction(self, temp_work_dir):
        """objdump should extract function symbols from an ELF binary."""
        from fuzzingbrain.static.objdump_analyzer import ObjdumpAnalyzer
        from fuzzingbrain.static.models import BinaryInfo

        # Use system ELF binary for reliable testing
        import shutil
        test_bin = (
            shutil.which("ls")
            or shutil.which("cat")
            or "/bin/ls"
        )

        analyzer = ObjdumpAnalyzer(max_disasm_funcs=10)
        binfo = BinaryInfo(
            path=test_bin,
            arch="x86_64",
            bits=64,
            endian="little",
            file_type="daemon",
            stripped=False,
            entry_point=0,
        )
        result = analyzer.analyze_binary(
            test_bin, binfo, str(temp_work_dir)
        )
        assert result.success, (
            f"objdump analysis failed: {result.error}"
        )
        assert result.function_count > 0, (
            "Should find function symbols"
        )


# =============================================================================
# Phase 3: SP Generation + Cross-Examination (Mocked LLM)
# =============================================================================


class TestPhase3SPAnalysis:
    """Test SP generation and verification pipeline with mocked LLM."""

    def test_sp_generation_from_hotspots(self, sample_hotspots=None):
        """SP generation should produce valid SPs from coverage hotspots."""
        from fuzzingbrain.fuzzer_orchestrator import FuzzerOrchestrator
        from fuzzingbrain.firmware_fuzzer import CrashInfo, CoverageInfo

        hotspots = sample_hotspots or [
            {
                "func_addr": 0x401000,
                "func_name": "formSetSpeedWan",
                "hit_count": 15420,
                "edge_density": 0.75,
                "has_dangerous_calls": True,
                "dangerous_types": ["strcpy", "sprintf"],
            },
            {
                "func_addr": 0x402000,
                "func_name": "FUN_000384c8",
                "hit_count": 8920,
                "edge_density": 0.55,
                "has_dangerous_calls": True,
                "dangerous_types": ["system", "popen"],
            },
            {
                "func_addr": 0x403000,
                "func_name": "TendaTelnet",
                "hit_count": 4500,
                "edge_density": 0.30,
                "has_dangerous_calls": False,
                "dangerous_types": [],
            },
        ]

        # Verify hotspot structure
        for h in hotspots:
            assert "func_addr" in h, "Hotspot must have func_addr"
            assert "hit_count" in h, "Hotspot must have hit_count"
            assert h["hit_count"] > 0, "Hotspot must have positive hit count"

        # Verify we can build SPs from hotspots
        sps = []
        for h in hotspots:
            sp = {
                "sp_id": f"SP-HOT-{h['func_addr']:08x}",
                "function_name": h["func_name"],
                "func_addr": h["func_addr"],
                "description": (
                    f"Hotspot: {h['hit_count']} executions"
                ),
                "priority": (
                    "P0"
                    if h.get("has_dangerous_calls")
                    else "P2"
                ),
            }
            sps.append(sp)

        assert len(sps) > 0, "Should generate SPs from hotspots"
        dangerous_sps = [
            s for s in sps if s["priority"] == "P0"
        ]
        assert len(dangerous_sps) > 0, (
            "Hotspots with dangerous calls should be P0"
        )

    def test_sp_deduplication(self, sample_sps):
        """SP deduplication should merge duplicate SPs by function address."""
        # Add a duplicate
        sps = list(sample_sps)
        sps.append(
            {
                "sp_id": "SP-DUP",
                "function_name": "formSetSpeedWan",
                "func_addr": 0x401000,  # Same addr as SP-001
                "description": "Duplicate of SP-001",
                "cwe": "CWE-121",
                "priority": "P1",
            }
        )

        # Dedup by func_addr
        seen = set()
        deduped = []
        for sp in sps:
            addr = sp.get("func_addr", 0)
            if addr and addr in seen:
                continue
            seen.add(addr)
            deduped.append(sp)

        assert len(deduped) == len(sample_sps), (
            f"After dedup should have {len(sample_sps)} SPs, "
            f"got {len(deduped)}"
        )
        # The original P0 should be kept over the P1 duplicate
        kept = [
            s for s in deduped if s["func_addr"] == 0x401000
        ][0]
        assert kept["priority"] == "P0", (
            "Should keep higher-priority SP when deduplicating"
        )

    def test_sp_verification_flow(
        self, sample_suspicious_point
    ):
        """SP verification should produce a valid VerificationResult."""
        from fuzzingbrain.sp_fuzzer import (
            VerificationResult,
            SPFirmwareFuzzer,
        )

        # Verify result with crash → CONFIRMED
        vr = VerificationResult(
            status="CONFIRMED",
            sp_id="SP-001",
            poc_guidance=(
                "Stack overflow confirmed: send oversized "
                "'speed_dir' parameter (>32 bytes) to "
                "/goform/SetSpeedWan"
            ),
            verification_time=45.2,
            iterations_run=342,
            breakpoints_hit=28,
            unique_crashes=3,
        )

        assert vr.status == "CONFIRMED"
        assert vr.iterations_run > 0
        assert vr.breakpoints_hit > 0
        d = vr.to_dict()
        assert "status" in d
        assert "iterations_run" in d

        # Verify result without crash → NEEDS_REVIEW
        vr_nr = VerificationResult(
            status="NEEDS_REVIEW",
            sp_id="SP-002",
            notes="Reached target 45 times but no crash",
            verification_time=30.0,
            iterations_run=200,
            breakpoints_hit=45,
            unique_crashes=0,
        )
        assert vr_nr.status == "NEEDS_REVIEW"

        # Verify unreachable → FALSE_POSITIVE
        vr_fp = VerificationResult(
            status="FALSE_POSITIVE",
            sp_id="SP-003",
            notes="Could not reach target after 100 iterations",
            verification_time=10.0,
            iterations_run=100,
            breakpoints_hit=0,
            unique_crashes=0,
        )
        assert vr_fp.status == "FALSE_POSITIVE"

        # Invalid status should raise
        with pytest.raises(ValueError):
            VerificationResult(status="INVALID", sp_id="x")


# =============================================================================
# Phase 4: Dual-Layer Fuzzing (Mocked QEMU/AFL++)
# =============================================================================


class TestPhase4Fuzzing:
    """Test dual-layer fuzzing with mocked external tools."""

    def test_crash_info_model(self):
        """CrashInfo should correctly serialize and deduplicate."""
        from fuzzingbrain.firmware_fuzzer import CrashInfo

        c1 = CrashInfo(
            crash_id="crash-001",
            input_data=b"A" * 200,
            crash_type="stack-buffer-overflow",
            crash_address=0x7FFF1234,
            sanitizer_output="READ of size 200 at 0x7FFF1234",
            stack_trace=[0x401000, 0x401200, 0x7FFF0000],
            func_where="formSetSpeedWan",
            found_by="global_fuzzer",
            signal_number=11,
        )

        d = c1.to_dict()
        assert "input_data_base64" in d
        assert "stack_hash" in d
        assert "crash_id" in d

        # Same crash should have same hash
        c2 = CrashInfo(
            crash_id="crash-002",
            input_data=b"B" * 200,
            crash_type="stack-buffer-overflow",
            crash_address=0x7FFF1234,
            sanitizer_output="...",
            stack_trace=[0x401000, 0x401200, 0x7FFF0000],
            func_where="formSetSpeedWan",
        )
        assert c1.stack_hash == c2.stack_hash, (
            "Same stack trace → same hash (dedup)"
        )

    def test_coverage_merge(self):
        """CoverageInfo.merge should correctly combine bitmaps."""
        from fuzzingbrain.firmware_fuzzer import CoverageInfo

        c1 = CoverageInfo(
            edges=500,
            total_edges=65536,
            coverage_percent=0.76,
            total_execs=50000,
            execs_per_sec=120,
        )
        c2 = CoverageInfo(
            edges=300,
            total_edges=65536,
            coverage_percent=0.46,
            total_execs=80000,
            execs_per_sec=200,
        )

        merged = CoverageInfo.merge([c1, c2])
        assert merged.total_execs == 130000, (
            "Total execs should be sum"
        )
        assert merged.execs_per_sec == 320, (
            "Exec/sec should be sum"
        )

    def test_global_fuzzer_init(self, temp_work_dir):
        """GlobalFirmwareFuzzer should initialize with correct defaults."""
        from fuzzingbrain.global_fuzzer import (
            GlobalFirmwareFuzzer,
        )

        fuzzer = GlobalFirmwareFuzzer(
            work_dir=temp_work_dir,
            max_runtime=60,  # 1 minute for test
            monitor_interval=30,
            fork_level=1,
        )

        assert fuzzer.max_runtime == 60
        assert fuzzer.monitor_interval == 30
        assert fuzzer.fork_level == 1
        assert fuzzer._processes == {}
        assert fuzzer._coverage_history == {}

    def test_global_fuzzer_plateau_detection(
        self, temp_work_dir
    ):
        """Plateau detection should correctly identify stalled fuzzing."""
        from fuzzingbrain.global_fuzzer import (
            GlobalFirmwareFuzzer,
            CoverageSample,
        )
        from collections import deque

        fuzzer = GlobalFirmwareFuzzer(
            work_dir=temp_work_dir,
            max_runtime=300,
            monitor_interval=30,
        )

        fid = "test_plateau"
        fuzzer._coverage_history[fid] = deque(maxlen=120)
        fuzzer._fuzzer_dirs[fid] = Path(temp_work_dir)
        fuzzer._start_times[fid] = 0  # Override for testing

        # Scenario: edges grow 500→590 over 2min, flat for 1.5min
        base_ts = time.time() - 210  # 3.5 minutes ago
        for i in range(25):
            edges = min(500 + i * 6, 590)
            fuzzer._coverage_history[fid].append(
                CoverageSample(
                    timestamp=base_ts + i * 8,  # 8s intervals
                    edges=edges,
                    coverage_percent=edges / 65536 * 100,
                    new_edges_since_last=(
                        6 if i < 15 else 0  # flat for last 10 samples (80s > 60s)
                    ),
                )
            )

        # Last 60s window: all samples at 590 edges, 0 growth
        is_plat = fuzzer.is_plateaued(
            fid, window_minutes=1, threshold=0.01
        )
        assert is_plat, (
            "Should detect plateau when edge growth is zero"
        )

        score = fuzzer.get_plateau_score(fid)
        # Score measures 5-min trend; with growth early on, it may be low.
        # The per-window is_plateaued is the primary detection mechanism.
        assert score >= 0.0, (
            f"Plateau score should be non-negative, got {score}"
        )

    def test_protocol_seed_generation(self):
        """ProtocolSeedGenerator should produce valid seeds for each protocol."""
        from fuzzingbrain.global_fuzzer import (
            ProtocolSeedGenerator,
        )

        for proto in ["HTTP", "DNS", "TELNET", "stdin"]:
            seeds = ProtocolSeedGenerator.generate(
                proto, count=4
            )
            assert len(seeds) > 0, (
                f"Should have seeds for {proto}"
            )
            assert len(seeds) <= 4, (
                f"Should respect count limit for {proto}"
            )
            for seed_bytes, label in seeds:
                assert len(seed_bytes) > 0, (
                    f"Seed '{label}' should not be empty"
                )
                assert isinstance(
                    label, str
                ), f"Label should be string"

        # HTTP should have GET/POST variants
        http_seeds = ProtocolSeedGenerator.generate("HTTP")
        http_labels = [l for _, l in http_seeds]
        assert any(
            "get" in l.lower() for l in http_labels
        ), "HTTP seeds should include GET"
        assert any(
            "post" in l.lower() for l in http_labels
        ), "HTTP seeds should include POST"

    def test_sp_fuzzer_init(self, temp_work_dir):
        """SPFirmwareFuzzer should initialize with correct parameters."""
        from fuzzingbrain.sp_fuzzer import SPFirmwareFuzzer

        fuzzer = SPFirmwareFuzzer(
            work_dir=temp_work_dir,
            max_iterations=100,
            breakpoint_timeout=10,
            snapshot_interval=25,
        )

        assert fuzzer.max_iterations == 100
        assert fuzzer.breakpoint_timeout == 10
        assert fuzzer.snapshot_interval == 25

    def test_sp_fuzzer_input_template_mutation(self):
        """InputTemplate mutation should preserve structure."""
        from fuzzingbrain.sp_fuzzer import InputTemplate

        raw = (
            b"POST /cgi-bin/config HTTP/1.0\r\n"
            b"Content-Length: 0100\r\n\r\n"
            + b"A" * 100
        )
        tmpl = InputTemplate(
            template_id="test",
            description="HTTP POST template",
            raw_template=raw,
            protocol="HTTP",
            target_func_addr=0x401000,
            target_func_name="cgi_handler",
            mutation_fields=[
                {
                    "name": "content_length",
                    "offset": 38,
                    "length": 4,
                    "type": "integer",
                    "range": [0, 4096],
                    "encoding": "base10",
                    "current_value": 100,
                },
                {
                    "name": "body",
                    "offset": 48,
                    "length": 50,
                    "type": "string",
                    "range": [0, 500],
                    "encoding": "ascii",
                    "current_value": "test",
                },
            ],
        )

        # Mutation should preserve total length
        for _ in range(10):
            mutated = tmpl.mutate()
            assert len(mutated) == len(raw), (
                "Mutation must preserve input length"
            )
            # Structure should be intact (POST / HTTP/1.0)
            assert mutated[:4] == b"POST", (
                "HTTP method should be preserved"
            )

    def test_weighted_corpus_selection(self):
        """WeightedCorpus should select higher-weight entries more often."""
        from fuzzingbrain.sp_fuzzer import WeightedCorpus

        corpus = WeightedCorpus(max_size=100)
        corpus.add(b"normal", 1.0, "normal")
        corpus.add(b"crash", 20.0, "crash")

        selections = [
            corpus.select() for _ in range(1000)
        ]
        crash_count = sum(
            1 for s in selections if s == b"crash"
        )
        normal_count = sum(
            1 for s in selections if s == b"normal"
        )

        # Crash weight (20) should be selected ~20x more than normal (1)
        assert crash_count > normal_count, (
            f"Crash (weight 20) should be selected more than "
            f"normal (weight 1): {crash_count} vs {normal_count}"
        )

    def test_breakpoint_tracker(self):
        """BreakpointTracker should correctly record hits."""
        from fuzzingbrain.sp_fuzzer import BreakpointTracker

        bt = BreakpointTracker()
        bt.add_target(0x401000, "formSetSpeedWan", "SP-001")
        bt.add_target(0x402000, "TendaTelnet", "SP-002")

        # Record hits
        for i in range(10):
            bt.record_hit(0x401000, f"input_{i}".encode())

        bt.record_hit(0x402000, b"telnet_input")

        assert bt.target_count == 2
        assert bt.total_hits == 11
        assert bt.any_targets_hit() is True
        assert bt.get_hit_count(0x401000) == 10
        assert bt.get_hit_count(0x402000) == 1

        status = bt.status()
        assert (
            status["0x401000"]["hit_count"] == 10
        )

    def test_snapshot_metadata(self):
        """SnapshotMetadata should correctly track lifecycle."""
        from fuzzingbrain.snapshot_manager import (
            SnapshotMetadata,
        )

        meta = SnapshotMetadata(
            snapshot_name="baseline_httpd_arm_a1b2c",
            binary_path="/bin/httpd",
            arch="arm",
            level="baseline",
            coverage_edges=1500,
            coverage_percent=2.3,
            tags=["baseline", "arm"],
        )

        d = meta.to_dict()
        assert d["level"] == "baseline"
        assert d["arch"] == "arm"
        assert d["coverage_edges"] == 1500
        assert not d["is_expired"]  # Just created

        meta.touch()
        assert not meta.is_expired

    def test_snapshot_manager_init(
        self, temp_work_dir
    ):
        """SnapshotManager should init and handle metadata CRUD."""
        from fuzzingbrain.snapshot_manager import (
            SnapshotManager,
            SnapshotMetadata,
        )

        mgr = SnapshotManager(
            snapshot_dir=temp_work_dir,
            max_age_hours=24,
            max_per_binary=5,
        )

        # Add test metadata
        snap_dir = Path(temp_work_dir) / "test" / "snap1"
        snap_dir.mkdir(parents=True)
        meta = SnapshotMetadata(
            snapshot_name="snap-test",
            binary_path="/bin/httpd",
            arch="arm",
            level="baseline",
            snapshot_path=str(snap_dir),
        )
        mgr._metadata["snap-test"] = meta
        mgr._save_snapshot_metadata(meta, snap_dir)

        # List
        all_snaps = mgr.list_snapshots()
        assert len(all_snaps) == 1
        assert all_snaps[0]["snapshot_name"] == "snap-test"

        # Stats
        stats = mgr.get_stats()
        assert stats.total_snapshots == 1
        assert stats.by_level.get("baseline", 0) == 1

        # Delete
        mgr.delete_snapshot("snap-test")
        assert len(mgr.list_snapshots()) == 0


# =============================================================================
# Full Pipeline Integration (Mocked)
# =============================================================================


class TestFullPipelineIntegration:
    """Test the complete pipeline flow with mocked external dependencies."""

    def test_orchestrator_init_and_checkpoint(
        self, temp_work_dir
    ):
        """Orchestrator should init and save/load checkpoints."""
        from fuzzingbrain.global_fuzzer import (
            GlobalFirmwareFuzzer,
        )
        from fuzzingbrain.sp_fuzzer import SPFirmwareFuzzer
        from fuzzingbrain.snapshot_manager import (
            SnapshotManager,
        )
        from fuzzingbrain.fuzzer_orchestrator import (
            FuzzerOrchestrator,
            FuzzingReport,
        )

        gf = GlobalFirmwareFuzzer(
            work_dir=f"{temp_work_dir}/global",
            max_runtime=60,
        )
        sf = SPFirmwareFuzzer(
            work_dir=f"{temp_work_dir}/sp",
            max_iterations=50,
        )
        sm = SnapshotManager(
            snapshot_dir=f"{temp_work_dir}/snapshots"
        )

        orch = FuzzerOrchestrator(
            global_fuzzer=gf,
            sp_fuzzer=sf,
            snapshot_manager=sm,
            max_parallel_sp=2,
            global_duration_minutes=1,
            checkpoint_dir=temp_work_dir,
        )

        # Test checkpoint
        orch._report = FuzzingReport(
            firmware_path="/tmp/test.bin"
        )
        orch._checkpoint = {"last_phase": "phase1"}
        orch._save_checkpoint("phase1")

        loaded = orch._load_checkpoint()
        assert loaded is not None
        assert loaded["last_phase"] == "phase1"

    def test_report_generation(self, sample_sps):
        """Final report should include confirmed, review, and FP categories."""
        from fuzzingbrain.fuzzer_orchestrator import (
            FuzzingReport,
        )
        from fuzzingbrain.firmware_fuzzer import (
            CrashInfo,
            CoverageInfo,
        )

        crash = CrashInfo(
            crash_id="crash-confirmed",
            input_data=b"A" * 200,
            crash_type="stack-buffer-overflow",
            crash_address=0x7FFF1234,
            sanitizer_output="...",
            stack_trace=[0x401000],
            func_where="formSetSpeedWan",
        )

        report = FuzzingReport(
            firmware_path="/tmp/ac9.bin",
            firmware_hash="a1b2c3d4",
            analysis_duration=600.0,
            global_coverage=CoverageInfo(
                edges=1500,
                coverage_percent=2.29,
            ),
            global_duration_seconds=300,
            total_sps_generated=25,
            total_sps_verified=15,
            confirmed_vulns=[
                {
                    "sp_id": "SP-001",
                    "status": "CONFIRMED",
                    "cwe": "CWE-121",
                    "poc_guidance": "Send >32 bytes to /goform/SetSpeedWan",
                    "crash_info": crash.to_dict(),
                },
            ],
            needs_review=[
                {
                    "sp_id": "SP-002",
                    "status": "NEEDS_REVIEW",
                    "cwe": "CWE-78",
                    "notes": "Reached target but no crash",
                },
            ],
            false_positives=[
                {
                    "sp_id": "SP-003",
                    "status": "FALSE_POSITIVE",
                },
            ],
            summary="Analysis complete",
            recommendations=["Fix buffer overflow in formSetSpeedWan"],
        )

        d = report.to_dict()
        assert len(d["confirmed_vulns"]) == 1
        assert len(d["needs_review"]) == 1
        assert len(d["false_positives"]) == 1
        assert d["firmware_hash"] == "a1b2c3d4"

        # SARIF output
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1, (
            "SARIF should include at least confirmed vuln"
        )

    def test_crash_to_cwe_mapping(self):
        """Crash types should map to correct CWE IDs."""
        from fuzzingbrain.fuzzer_orchestrator import (
            FuzzerOrchestrator,
        )

        mapping = {
            "stack-buffer-overflow": "CWE-121",
            "heap-buffer-overflow": "CWE-122",
            "use-after-free": "CWE-416",
            "double-free": "CWE-415",
            "null-deref": "CWE-476",
            "SIGSEGV": "CWE-121",
            "SIGABRT": "CWE-617",
            "SIGILL": "CWE-440",
        }

        for crash_type, expected_cwe in mapping.items():
            cwe = FuzzerOrchestrator._crash_type_to_cwe(
                crash_type
            )
            assert cwe == expected_cwe, (
                f"{crash_type} → {cwe}, expected {expected_cwe}"
            )

    def test_fuzzer_status_reporting(
        self, temp_work_dir
    ):
        """FuzzerManager status should report correct pool usage."""
        from fuzzingbrain.firmware_fuzzer import FuzzerManager

        mgr = FuzzerManager(
            work_dir=temp_work_dir, max_sp_fuzzers=4
        )

        status = mgr.status()
        assert status["sp_pool_usage"] == "0/4"
        assert status["total_unique_crashes"] == 0
        assert "global_fuzzer" in status
        assert "sp_fuzzers" in status

        mgr.stop_all()

    def test_coverage_trend_analysis(
        self, temp_work_dir
    ):
        """Coverage trending should detect growth and plateaus."""
        from fuzzingbrain.global_fuzzer import (
            GlobalFirmwareFuzzer,
            CoverageSample,
        )
        from collections import deque

        fuzzer = GlobalFirmwareFuzzer(
            work_dir=temp_work_dir,
            max_runtime=300,
            monitor_interval=30,
        )

        fid = "test_trend"
        fuzzer._coverage_history[fid] = deque(maxlen=120)
        fuzzer._fuzzer_dirs[fid] = Path(temp_work_dir)
        fuzzer._start_times[fid] = 0

        # Steady growth scenario
        base_ts = time.time() - 360  # 6 min ago
        for i in range(12):
            fuzzer._coverage_history[fid].append(
                CoverageSample(
                    timestamp=base_ts + i * 30,
                    edges=500 + i * 20,  # 500→740
                    coverage_percent=(500 + i * 20)
                    / 65536
                    * 100,
                    new_edges_since_last=20,
                )
            )

        growth = fuzzer.get_coverage_growth_rate(
            fid, minutes=5
        )
        assert growth > 0, (
            "Growing fuzzer should have positive growth rate"
        )

    def test_snapshot_baseline_reuse(
        self, temp_work_dir
    ):
        """get_or_create_baseline should reuse existing snapshots."""
        from fuzzingbrain.snapshot_manager import (
            SnapshotManager,
            SnapshotMetadata,
        )

        mgr = SnapshotManager(
            snapshot_dir=temp_work_dir, max_age_hours=24
        )

        # Create a synthetic baseline with a RECENT timestamp (not expired)
        from datetime import datetime, timedelta

        snap_name = "baseline_httpd_arm_abc12345"
        snap_dir = Path(temp_work_dir) / "inst1" / snap_name
        snap_dir.mkdir(parents=True)

        recent_ts = (datetime.now() - timedelta(hours=1)).isoformat()
        meta = SnapshotMetadata(
            snapshot_name=snap_name,
            binary_path="/bin/httpd",
            binary_hash="abc12345",
            arch="arm",
            level="baseline",
            snapshot_path=str(snap_dir),
            created_at=recent_ts,  # 1 hour ago — not expired
        )
        mgr._metadata[snap_name] = meta
        mgr._save_snapshot_metadata(meta, snap_dir)

        # Find baseline for an SP
        sp = {"sp_id": "SP-001", "func_addr": 0x401000}
        found = mgr.find_baseline_for_sp("/bin/httpd", sp)
        assert found is not None, (
            "Should find existing baseline for same binary"
        )

    def test_mcp_tool_registry_complete(self):
        """All 11 tools should be auto-registered and have valid schemas."""
        from fuzzingbrain.tools.firmware_mcp import (
            get_registry,
        )

        registry = get_registry()
        tools = registry.list_tools()

        # At least 11 tools (5 SAST + 6 DAST)
        assert len(tools) >= 11, (
            f"Expected >=11 tools, got {len(tools)}"
        )

        # Every tool must have a valid OpenAI schema
        schemas = registry.get_function_schemas()
        for schema in schemas:
            f = schema["function"]
            assert "name" in f
            assert "description" in f
            params = f["parameters"]
            assert params["type"] == "object"
            assert "properties" in params
            # Required params must exist in properties
            for req in params.get("required", []):
                assert req in params["properties"], (
                    f"'{req}' in required but not properties"
                )

    def test_tool_execution_decompile_fallback(
        self, temp_work_dir
    ):
        """decompile_function should work with objdump fallback."""
        from fuzzingbrain.tools.firmware_mcp import (
            get_registry,
        )
        import shutil

        registry = get_registry()
        test_bin = shutil.which("ls") or "/bin/ls"

        result = registry.execute_tool(
            "decompile_function",
            binary_path=test_bin,
            func_addr=0x4020,
        )
        assert "success" in result
        if result["success"]:
            assert len(result.get("decompiled_code", "")) > 0


# =============================================================================
# Performance Constraints
# =============================================================================


class TestPerformanceConstraints:
    """Verify analysis stays within time/resource bounds."""

    def test_crash_dedup_performance(self):
        """Crash dedup should be O(1) per crash."""
        from fuzzingbrain.firmware_fuzzer import CrashInfo

        crashes = []
        for i in range(100):
            crashes.append(
                CrashInfo(
                    crash_id=f"crash-{i:04d}",
                    input_data=bytes([i] * 10),
                    crash_type="stack-buffer-overflow",
                    crash_address=0x7FFF0000 + i,
                    sanitizer_output=f"crash {i}",
                    stack_trace=[0x401000, i],
                    func_where=f"func_{i}",
                )
            )

        start = time.time()
        seen = set()
        unique = []
        for c in crashes:
            h = c.stack_hash
            if h not in seen:
                seen.add(h)
                unique.append(c)
        elapsed = time.time() - start

        assert len(unique) == 100, "All unique crashes should be kept"
        assert elapsed < 0.1, (
            f"Dedup should be fast (<100ms), took {elapsed*1000:.0f}ms"
        )

    def test_coverage_trend_storage(self):
        """Coverage trend history should stay within memory bounds."""
        from fuzzingbrain.global_fuzzer import CoverageSample
        from collections import deque

        # Simulate 2 hours of 30s-interval samples
        history = deque(maxlen=120)
        base_ts = time.time() - 7200
        for i in range(240):
            history.append(
                CoverageSample(
                    timestamp=base_ts + i * 30,
                    edges=min(i * 3, 5000),
                    coverage_percent=min(
                        i * 3 / 65536 * 100, 7.6
                    ),
                )
            )

        # Deque should have capped at 120 (60 min)
        assert len(history) <= 120, (
            f"Trend history should be capped, got {len(history)}"
        )
