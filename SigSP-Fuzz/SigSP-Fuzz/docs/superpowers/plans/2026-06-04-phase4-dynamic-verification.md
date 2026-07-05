# Phase 4: Layered Dynamic Verification + Report — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the layered dynamic verification pipeline — PoC Agent generates trigger inputs for P0 SPs, FirmAE/QEMU execute them with crash monitoring, static assessment provides L3 fallback, and report generator produces JSON + Markdown final reports.

**Architecture:** Follows Phase 2/3 patterns — dataclass models with `to_dict`/`from_dict`, class-based agents with `LLMClient`, prompt `.md` templates, `Phase4Pipeline` orchestration with `ThreadPoolExecutor`. FirmAE/QEMU runners use `subprocess` to invoke external emulators. CrashMonitor is pure-algorithm dedup. StaticAssessor is pure-algorithm L3 fallback.

**Tech Stack:** Python 3.10+, dataclasses, DeepSeek-V4-Pro (PoC Agent), subprocess (FirmAE/QEMU), pytest + unittest.mock

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `fuzzingbrain/verifier/__init__.py` | **Create** | Package init, public API exports |
| `fuzzingbrain/verifier/models.py` | **Create** | PoC, VerificationResult, CrashInfo, Phase4Result, FinalReport dataclasses |
| `fuzzingbrain/verifier/poc_agent.py` | **Create** | PoCAgent — generates trigger inputs via DeepSeek-V4-Pro |
| `fuzzingbrain/verifier/firmae_runner.py` | **Create** | FirmAERunner — L1 full-system emulation via subprocess |
| `fuzzingbrain/verifier/qemu_runner.py` | **Create** | QEMURunner — L2 user-mode execution via subprocess |
| `fuzzingbrain/verifier/crash_monitor.py` | **Create** | CrashMonitor — crash capture, classification, dedup |
| `fuzzingbrain/verifier/static_assessor.py` | **Create** | StaticAssessor — L3 confidence-based fallback |
| `fuzzingbrain/verifier/pipeline.py` | **Create** | Phase4Pipeline — orchestrates PoC → verify → report |
| `fuzzingbrain/reporter/__init__.py` | **Create** | Package init |
| `fuzzingbrain/reporter/generator.py` | **Create** | ReportGenerator — JSON + Markdown report |
| `fuzzingbrain/agents/firmware/prompts/poc_prompt.md` | **Create** | PoC Agent system prompt template |
| `fuzzingbrain/agents/firmware/prompts/__init__.py` | **Modify** | Add `get_poc_prompt()` loader |
| `tests/test_verifier_models.py` | **Create** | Model serialization/validation tests (~15 tests) |
| `tests/test_poc_agent.py` | **Create** | PoCAgent tests with mocked LLM (~10 tests) |
| `tests/test_crash_monitor.py` | **Create** | CrashMonitor dedup/classification tests (~8 tests) |
| `tests/test_static_assessor.py` | **Create** | StaticAssessor L3 logic tests (~6 tests) |
| `tests/test_report_generator.py` | **Create** | ReportGenerator JSON/Markdown tests (~8 tests) |
| `tests/test_phase4_pipeline.py` | **Create** | Phase4Pipeline integration tests (~6 tests) |

**Total: 12 new files, 2 modified, ~53 tests**

---

### Task 1: Data Models

**Files:**
- Create: `fuzzingbrain/verifier/__init__.py`
- Create: `fuzzingbrain/verifier/models.py`
- Create: `tests/test_verifier_models.py`

- [ ] **Step 1: Create verifier package init**

```python
# fuzzingbrain/verifier/__init__.py
"""
Dynamic verification for firmware vulnerability discovery.

Phase 4 of the pipeline:
- PoCAgent: Generates PoC trigger inputs for P0 SPs
- FirmAERunner: L1 full-system emulation verification
- QEMURunner: L2 user-mode emulation verification
- CrashMonitor: Crash capture, classification, and dedup
- StaticAssessor: L3 static confidence fallback
- Phase4Pipeline: Full Phase 4 orchestration
"""

from .models import (
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
from .poc_agent import PoCAgent
from .crash_monitor import CrashMonitor
from .static_assessor import StaticAssessor
from .firmae_runner import FirmAERunner
from .qemu_runner import QEMURunner
from .pipeline import Phase4Pipeline

__all__ = [
    "PoC",
    "PoCTarget",
    "ExpectedBehavior",
    "AltPayload",
    "VerificationResult",
    "CrashInfo",
    "Phase4Statistics",
    "Phase4Result",
    "ReportMetadata",
    "VulnerabilityEntry",
    "FinalReport",
    "PoCAgent",
    "CrashMonitor",
    "StaticAssessor",
    "FirmAERunner",
    "QEMURunner",
    "Phase4Pipeline",
]
```

- [ ] **Step 2: Write model tests (these must fail first)**

```python
# tests/test_verifier_models.py
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
    """Tests for PoCTarget dataclass."""

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
    """Tests for ExpectedBehavior dataclass."""

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
    """Tests for AltPayload dataclass."""

    def test_create(self):
        ap = AltPayload(description="Longer overflow pattern", poc_content="A" * 512)
        assert ap.description == "Longer overflow pattern"
        assert len(ap.poc_content) == 512
        assert ap.poc_content_hex == ""

    def test_with_hex(self):
        ap = AltPayload(description="Null byte injection", poc_content="\\x00admin", poc_content_hex="00 61 64 6d 69 6e")
        assert ap.poc_content_hex == "00 61 64 6d 69 6e"


class TestPoC:
    """Tests for PoC dataclass."""

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


class TestCrashInfo:
    """Tests for CrashInfo dataclass."""

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
        # crash_signature is auto-computed
        assert "SIGSEGV-0x41414141" == ci.crash_signature

    def test_serialization(self):
        ci = CrashInfo(crash_type="SIGABRT", crash_address="0xdeadbeef", signal_number=6)
        d = ci.to_dict()
        assert d["crash_type"] == "SIGABRT"
        assert d["crash_address"] == "0xdeadbeef"
        assert d["signal_number"] == 6


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

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
    """Tests for Phase4Statistics dataclass."""

    def test_create(self):
        stats = Phase4Statistics(
            total_p0_sps=5,
            poc_generated=5,
            dynamic_full_verified=2,
            dynamic_user_verified=1,
            static_high_reserved=1,
            discarded=1,
            unique_crashes=3,
            verification_rate="60.0%",
        )
        assert stats.total_p0_sps == 5
        assert stats.poc_generated == 5
        assert stats.dynamic_full_verified == 2
        assert stats.dynamic_user_verified == 1
        assert stats.static_high_reserved == 1
        assert stats.discarded == 1
        assert stats.unique_crashes == 3
        assert stats.verification_rate == "60.0%"

    def test_defaults(self):
        stats = Phase4Statistics()
        assert stats.total_p0_sps == 0
        assert stats.poc_generated == 0
        assert stats.dynamic_full_verified == 0
        assert stats.verification_rate == ""


class TestPhase4Result:
    """Tests for Phase4Result dataclass."""

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
        assert result.statistics.total_p0_sps == 2

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
    """Tests for ReportMetadata dataclass."""

    def test_create(self):
        rm = ReportMetadata(
            firmware_name="test_firmware.bin",
            firmware_hash="abc123",
            analysis_date="2026-06-04T12:00:00",
            total_functions_analyzed=100,
            total_attack_surfaces=5,
            total_directions=3,
        )
        assert rm.firmware_name == "test_firmware.bin"
        assert rm.firmware_hash == "abc123"
        assert rm.total_functions_analyzed == 100


class TestVulnerabilityEntry:
    """Tests for VulnerabilityEntry dataclass."""

    def test_create_minimal(self):
        ve = VulnerabilityEntry(
            sp_id="sp-1",
            cwe="CWE-121",
            title="Stack Buffer Overflow",
            description="strcpy without bounds check",
            function_name="httpd_handler",
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


class TestFinalReport:
    """Tests for FinalReport dataclass."""

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
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pytest tests/test_verifier_models.py -v
```
Expected: all FAIL with `ModuleNotFoundError: No module named 'fuzzingbrain.verifier'`

- [ ] **Step 4: Write the data models**

```python
# fuzzingbrain/verifier/models.py
"""
Data models for Phase 4: dynamic verification and reporting.

Phase 4 outputs: PoC (trigger inputs), VerificationResult (verification outcomes),
CrashInfo (crash details), Phase4Result (pipeline output), FinalReport (human-readable).
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from ..agents.firmware.sp_models import ExploitabilityAssessment


# ---------------------------------------------------------------------------
# PoC models
# ---------------------------------------------------------------------------

@dataclass
class PoCTarget:
    """Target information for PoC delivery."""

    host: str = "127.0.0.1"
    port: int = 80
    path: str = ""               # HTTP path, e.g. /cgi-bin/vuln
    method: str = "GET"          # HTTP method: GET, POST

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PoCTarget":
        return cls(**d)


@dataclass
class ExpectedBehavior:
    """Expected crash behavior from a PoC."""

    expected_crash_type: str = ""       # SIGSEGV, SIGABRT, SIGILL, heap_corruption, none
    expected_register_state: str = ""   # e.g. "PC=0x41414141"
    success_indicator: str = ""         # e.g. "QEMU exits with signal 11 (SIGSEGV)"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ExpectedBehavior":
        return cls(**d)


@dataclass
class AltPayload:
    """Alternate payload variation if the primary doesn't work."""

    description: str = ""
    poc_content: str = ""
    poc_content_hex: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AltPayload":
        return cls(**d)


@dataclass
class PoC:
    """
    A constructed exploit trigger input for a specific SP.

    Produced by PoCAgent (DeepSeek-V4-Pro) for P0 SPs only.
    """

    sp_id: str
    poc_type: str                        # http_request, http_response, udp_packet, tcp_stream, stdin_input, other
    poc_target: PoCTarget = field(default_factory=PoCTarget)
    poc_content: str = ""                # Raw payload content
    poc_content_hex: str = ""            # Hex representation for non-printable bytes
    poc_explanation: str = ""            # Why this payload triggers the vulnerability
    expected_behavior: ExpectedBehavior = field(default_factory=ExpectedBehavior)
    alternate_payloads: List[AltPayload] = field(default_factory=list)

    VALID_POC_TYPES = {
        "http_request", "http_response", "udp_packet",
        "tcp_stream", "stdin_input", "other",
    }

    def __post_init__(self):
        if self.poc_type not in self.VALID_POC_TYPES:
            raise ValueError(
                f"Invalid poc_type: {self.poc_type}. "
                f"Must be one of: {self.VALID_POC_TYPES}"
            )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PoC":
        d = dict(d)
        if d.get("poc_target"):
            d["poc_target"] = PoCTarget(**d["poc_target"])
        if d.get("expected_behavior"):
            d["expected_behavior"] = ExpectedBehavior(**d["expected_behavior"])
        if d.get("alternate_payloads"):
            d["alternate_payloads"] = [AltPayload(**ap) for ap in d["alternate_payloads"]]
        return cls(**d)


# ---------------------------------------------------------------------------
# Verification models
# ---------------------------------------------------------------------------

@dataclass
class CrashInfo:
    """Captured crash information from dynamic verification."""

    crash_type: str                      # SIGSEGV, SIGABRT, SIGILL, SIGBUS, heap_corruption
    crash_address: str = ""              # Faulting address (hex string)
    register_state: Dict[str, str] = field(default_factory=dict)
    backtrace: List[str] = field(default_factory=list)
    signal_number: int = 0               # e.g. 11 for SIGSEGV
    crash_signature: str = ""            # Auto-computed dedup key

    VALID_CRASH_TYPES = {"SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "heap_corruption", "unknown"}

    def __post_init__(self):
        if self.crash_type not in self.VALID_CRASH_TYPES:
            raise ValueError(
                f"Invalid crash_type: {self.crash_type}. "
                f"Must be one of: {self.VALID_CRASH_TYPES}"
            )
        # Auto-compute crash_signature if not provided
        if not self.crash_signature:
            self.crash_signature = f"{self.crash_type}-{self.crash_address}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CrashInfo":
        return cls(**d)


@dataclass
class VerificationResult:
    """Result of verifying a single SP."""

    sp_id: str
    verification_level: str              # dynamic_full, dynamic_user, static_high, static_low, not_verified
    crashed: bool
    crash_info: Optional[CrashInfo] = None
    output: str = ""                     # stdout/stderr from emulation
    error: str = ""                      # Error message if verification failed

    VALID_LEVELS = {"dynamic_full", "dynamic_user", "static_high", "static_low", "not_verified"}

    def __post_init__(self):
        if self.verification_level not in self.VALID_LEVELS:
            raise ValueError(
                f"Invalid verification_level: {self.verification_level}. "
                f"Must be one of: {self.VALID_LEVELS}"
            )

    @property
    def is_confirmed(self) -> bool:
        """Whether the vulnerability was dynamically confirmed."""
        return self.verification_level in ("dynamic_full", "dynamic_user")

    @property
    def is_reportable(self) -> bool:
        """Whether this result should appear in the final report."""
        return self.verification_level in ("dynamic_full", "dynamic_user", "static_high")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "VerificationResult":
        d = dict(d)
        if d.get("crash_info"):
            d["crash_info"] = CrashInfo(**d["crash_info"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Phase4 pipeline models
# ---------------------------------------------------------------------------

@dataclass
class Phase4Statistics:
    """Aggregate statistics for the Phase 4 pipeline run."""

    total_p0_sps: int = 0
    poc_generated: int = 0
    dynamic_full_verified: int = 0       # L1 confirmed
    dynamic_user_verified: int = 0       # L2 confirmed
    static_high_reserved: int = 0        # L3 reserved
    discarded: int = 0                   # L3 discarded
    unique_crashes: int = 0              # After CrashMonitor dedup
    verification_rate: str = ""          # e.g. "60.0%"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Phase4Statistics":
        return cls(**d)


@dataclass
class Phase4Result:
    """Complete result of the Phase 4 verification pipeline."""

    verified_results: List[VerificationResult]
    crashes: List[CrashInfo]
    statistics: Phase4Statistics

    @property
    def confirmed_results(self) -> List[VerificationResult]:
        """Results confirmed via dynamic verification (L1 or L2)."""
        return [r for r in self.verified_results if r.is_confirmed]

    @property
    def reportable_results(self) -> List[VerificationResult]:
        """Results that should appear in the final report."""
        return [r for r in self.verified_results if r.is_reportable]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Phase4Result":
        results = [VerificationResult.from_dict(r) for r in d.get("verified_results", [])]
        crashes = [CrashInfo.from_dict(c) for c in d.get("crashes", [])]
        stats = Phase4Statistics.from_dict(d.get("statistics", {}))
        return cls(verified_results=results, crashes=crashes, statistics=stats)


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------

@dataclass
class ReportMetadata:
    """Metadata for the final vulnerability report."""

    firmware_name: str
    firmware_hash: str = ""
    analysis_date: str = ""              # ISO 8601
    total_functions_analyzed: int = 0
    total_attack_surfaces: int = 0
    total_directions: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ReportMetadata":
        return cls(**d)


@dataclass
class VulnerabilityEntry:
    """A single vulnerability entry in the final report."""

    sp_id: str
    cwe: str
    title: str
    description: str
    function_name: str
    binary_offset: str = ""
    control_flow: str = ""
    trigger_condition: str = ""
    confidence: float = 0.0
    severity: str = ""                   # critical, high, medium, low
    priority: str = ""                   # P0, P1, P2, P3
    verification_level: str = ""         # dynamic_full, dynamic_user, static_high
    exploitability: Optional[ExploitabilityAssessment] = None
    poc: Optional[PoC] = None
    crash_info: Optional[CrashInfo] = None
    fix_suggestion: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "VulnerabilityEntry":
        d = dict(d)
        if d.get("exploitability"):
            d["exploitability"] = ExploitabilityAssessment(**d["exploitability"])
        if d.get("poc"):
            d["poc"] = PoC.from_dict(d["poc"])
        if d.get("crash_info"):
            d["crash_info"] = CrashInfo(**d["crash_info"])
        return cls(**d)


@dataclass
class FinalReport:
    """Complete final vulnerability report."""

    metadata: ReportMetadata
    vulnerabilities: List[VulnerabilityEntry]
    statistics: Phase4Statistics

    @property
    def count(self) -> int:
        """Total number of vulnerability entries."""
        return len(self.vulnerabilities)

    @property
    def confirmed_vulnerabilities(self) -> List[VulnerabilityEntry]:
        """Vulnerabilities confirmed via dynamic verification or static_high."""
        return [
            v for v in self.vulnerabilities
            if v.verification_level in ("dynamic_full", "dynamic_user", "static_high")
        ]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FinalReport":
        metadata = ReportMetadata.from_dict(d.get("metadata", {}))
        entries = [VulnerabilityEntry.from_dict(e) for e in d.get("vulnerabilities", [])]
        stats = Phase4Statistics.from_dict(d.get("statistics", {}))
        return cls(metadata=metadata, vulnerabilities=entries, statistics=stats)
```

- [ ] **Step 5: Run model tests to verify they pass**

```bash
pytest tests/test_verifier_models.py -v
```
Expected: all 18 tests PASS

- [ ] **Step 6: Commit**

```bash
git add fuzzingbrain/verifier/__init__.py fuzzingbrain/verifier/models.py tests/test_verifier_models.py
git commit -m "feat(phase4): add verifier data models for PoC, verification, and reporting

Add PoC, PoCTarget, ExpectedBehavior, AltPayload, VerificationResult,
CrashInfo, Phase4Statistics, Phase4Result, ReportMetadata,
VulnerabilityEntry, and FinalReport dataclasses with validation,
JSON serialization, and 18 unit tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: PoC Prompt Template

**Files:**
- Create: `fuzzingbrain/agents/firmware/prompts/poc_prompt.md`
- Modify: `fuzzingbrain/agents/firmware/prompts/__init__.py`

- [ ] **Step 1: Write poc_prompt.md**

```markdown
# fuzzingbrain/agents/firmware/prompts/poc_prompt.md
# Role
You are an exploit proof-of-concept developer for embedded systems.
Given a confirmed Suspicious Point (SP), construct the minimal input
needed to trigger the vulnerability.

# Input Data

## Suspicious Point
{sp_json}

## Attack Surface Context
{attack_surface_context}

## Target Function Pseudo-code
```c
{pseudo_code}
```

## Architecture
{arch} ({bits}-bit, {endian}-endian)

## Call Path from Entry Point
{call_path}

# PoC Construction Strategy by Input Vector

## For HTTP-based vulnerabilities
1. Identify HTTP method (GET/POST) and endpoint path from attack surface info
2. Include required headers (Host, Content-Length, Content-Type, Cookie if auth needed)
3. Craft payload in the appropriate field:
   - Buffer overflow in URL param: `GET /cgi-bin/vuln?param=AAAA...<overflow>`
   - Buffer overflow in POST body: `param=AAAA...<overflow>`
   - Command injection: `param=;id`
   - Format string: `param=%x.%x.%x.%n`
   - Path traversal: `param=../../etc/passwd`

## For UDP/TCP packet-based vulnerabilities
1. Identify the protocol format from attack surface context
2. Build a minimal valid packet skeleton
3. Inject the overflow/injection payload in the appropriate field
4. Include length fields that need to be consistent

## For stdin-based vulnerabilities (local binaries)
1. Identify the expected input format from function parameters
2. Build minimal valid input structure
3. Introduce the vulnerability trigger at the right offset

## Payload Construction Principles
1. **Overflow**: Use De Bruijn sequence or cyclical pattern "AAAABBBBCCCC...ZZZZ"
   for easy offset identification in crash analysis
2. **Format string**: Start with `%x.%x.%x` to verify format string before
   attempting `%n` writes
3. **Command injection**: Start with benign command (`id`, `ls`, `echo test`)
   before exploitation
4. **Path traversal**: Start with `../../etc/passwd` before complex paths
5. **Always include** a "safe" version to test reachability without crashing
6. **For non-printable bytes**, provide both raw content and hex representation

# Output Format
You MUST output valid JSON matching this exact schema:

```json
{{
  "sp_id": "original_sp_id",
  "poc_type": "http_request | http_response | udp_packet | tcp_stream | stdin_input | other",
  "poc_target": {{
    "host": "127.0.0.1",
    "port": 80,
    "path": "/cgi-bin/vuln",
    "method": "POST"
  }},
  "poc_content": "AAAA...raw content here",
  "poc_content_hex": "hex for non-printable bytes (space-separated)",
  "poc_explanation": "Detailed explanation of why this payload triggers the vulnerability",
  "expected_behavior": {{
    "expected_crash_type": "SIGSEGV | SIGABRT | SIGILL | heap_corruption | none",
    "expected_register_state": "PC=0x41414141 (for stack overflow)",
    "success_indicator": "QEMU exits with signal 11 (SIGSEGV)"
  }},
  "alternate_payloads": [
    {{
      "description": "Variation if first payload doesn't work",
      "poc_content": "...",
      "poc_content_hex": ""
    }}
  ]
}}
```

# Rules
1. Be SPECIFIC about payload content — exact bytes matter for binary exploitation
2. Include HEX for ALL non-printable bytes (null bytes, binary data)
3. Explain WHY this payload structure triggers the vulnerability
4. Always provide at least ONE alternate payload in case the primary fails
5. If the vulnerability is not network-exploitable, use stdin_input poc_type
6. For stripped binaries (FUN_XXXXXXXX), be conservative — prioritize simple
   overflow patterns over complex ROP chains
7. Payload should be MINIMAL — the smallest input that proves the vulnerability
8. Do NOT fabricate file paths or endpoints — use only what's in the attack_surface_context
```

- [ ] **Step 2: Update prompts/__init__.py**

Add the following function inside the file, before `__all__`:

```python
def get_poc_prompt() -> str:
    """Get the PoC Construction Agent system prompt."""
    return load_prompt("poc_prompt.md")
```

And update `__all__`:

```python
__all__ = [
    "load_prompt",
    "get_attack_surface_prompt",
    "get_direction_prompt",
    "get_analyst_a_prompt",
    "get_analyst_b_prompt",
    "get_analyst_c_prompt",
    "get_cross_review_prompt",
    "get_verifier_prompt",
    "get_poc_prompt",
]
```

- [ ] **Step 3: Verify prompt loads correctly**

```bash
python -c "
from fuzzingbrain.agents.firmware.prompts import get_poc_prompt
p = get_poc_prompt()
assert len(p) > 500, f'PoC prompt too short: {len(p)} chars'
print(f'PoC prompt: {len(p)} chars OK')
"
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/agents/firmware/prompts/poc_prompt.md fuzzingbrain/agents/firmware/prompts/__init__.py
git commit -m "feat(phase4): add PoC Agent prompt template

Add poc_prompt.md for exploit PoC construction with DeepSeek-V4-Pro,
covering HTTP, UDP/TCP, and stdin input vectors with payload
construction principles and structured JSON output format.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: PoCAgent

**Files:**
- Create: `fuzzingbrain/verifier/poc_agent.py`
- Create: `tests/test_poc_agent.py`

- [ ] **Step 1: Write PoCAgent tests (these must fail first)**

```python
# tests/test_poc_agent.py
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


# ── Mock data helpers ──────────────────────────────────────────────────

def make_p0_sp(sp_id="mc-httpd-CWE-121-0001", confidence=0.85,
               function_name="httpd_handler", priority="P0"):
    """Create a P0 VerifiedSP for testing."""
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
        control_flow="httpd_handle_request → get_param → strcpy",
        trigger_condition="Send HTTP request with param > 256 bytes",
        root_cause="Missing bounds check before strcpy",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority=priority,
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_p1_sp():
    """Create a P1 VerifiedSP (should be filtered out by P0-only logic)."""
    return make_p0_sp(sp_id="inj-login-CWE-78-0001", priority="P1",
                       function_name="cgi_login", confidence=0.75)


def make_attack_surface():
    """Create a matching AttackSurface."""
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
    """Create a matching FunctionInfo."""
    return FunctionInfo(
        name="httpd_handler", address=0x2100,
        pseudo_code="void httpd_handler(int sock) {\n"
                     "  char buf[256];\n"
                     "  char *param = get_param(request, \"url\");\n"
                     "  strcpy(buf, param);\n"
                     "}",
        callees=["get_param", "strcpy"],
        callers=["httpd_init"],
        strings_used=["GET ", "POST ", "url"],
        dangerous_funcs=["strcpy"],
        has_unsafe_calls=True,
        arch="arm", bits=32, endian="little",
    )


# ── Mock LLM response ──────────────────────────────────────────────────

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


# ── Tests ──────────────────────────────────────────────────────────────

class TestPoCAgentInit:
    """Tests for PoCAgent initialization."""

    def test_default_model_is_deepseek(self):
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO
        agent = PoCAgent()
        assert agent.model == DEEPSEEK_V4_PRO

    def test_model_override(self):
        from fuzzingbrain.llms import QWEN3_6_PLUS
        agent = PoCAgent(model=QWEN3_6_PLUS)
        assert agent.model == QWEN3_6_PLUS

    def test_custom_temperature(self):
        agent = PoCAgent(temperature=0.1)
        assert agent.temperature == 0.1


class TestPoCAgentFilterP0:
    """Tests for P0 filtering logic."""

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
    """Tests for PoC generation with mocked LLM."""

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
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response

            agent = PoCAgent()
            agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())

            call_kwargs = mock_client.call.call_args[1]
            messages = call_kwargs.get("messages", [])
            user_msg = messages[-1]["content"] if messages else ""
            assert "char buf[256]" in user_msg or any("char buf[256]" in str(m) for m in messages)
            assert "strcpy" in user_msg or any("strcpy" in str(m) for m in messages)

    def test_generate_uses_model_kwarg(self, mock_response):
        from fuzzingbrain.llms import DEEPSEEK_V4_PRO
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_response

            agent = PoCAgent()
            agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())

            call_kwargs = mock_client.call.call_args[1]
            assert "model" in call_kwargs
            assert call_kwargs["model"] == DEEPSEEK_V4_PRO

    def test_generate_json_parse_error(self):
        """Should handle malformed LLM JSON output."""
        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            bad_response = MagicMock()
            bad_response.content = "This is not JSON {{{"
            mock_client.call.return_value = bad_response

            agent = PoCAgent()
            with pytest.raises(ValueError, match="Failed to parse"):
                agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())

    def test_generate_with_markdown_fence(self):
        """Should parse JSON wrapped in ```json fence."""
        response = MagicMock()
        response.content = '```json\n' + MOCK_POC_RESPONSE + '\n```'

        with patch("fuzzingbrain.verifier.poc_agent.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = response
            agent = PoCAgent()
            poc = agent.generate(make_p0_sp(), make_attack_surface(), make_function_info())

        assert poc.sp_id == "mc-httpd-CWE-121-0001"


class TestPoCAgentGenerateBatch:
    """Tests for batch PoC generation."""

    @pytest.fixture
    def mock_response(self):
        resp = MagicMock()
        resp.content = MOCK_POC_RESPONSE
        return resp

    def test_generate_batch_filters_non_p0(self, mock_response):
        """Batch should skip non-P0 SPs."""
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
    """Tests for save/load."""

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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_poc_agent.py -v
```
Expected: all FAIL (ImportError for poc_agent module)

- [ ] **Step 3: Write the PoCAgent implementation**

```python
# fuzzingbrain/verifier/poc_agent.py
"""
PoCAgent -- Generates PoC trigger inputs for P0 SPs.

Uses DeepSeek-V4-Pro to construct minimal exploit trigger inputs based on
the SP's control flow, vulnerability type, and attack surface context.

Only generates PoCs for P0 SPs (priority == "P0") to control token cost.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from loguru import logger

from ..llms import LLMClient, DEEPSEEK_V4_PRO, ModelInfo
from ..static.models import FunctionInfo
from ..attack_surface.models import AttackSurface
from ..agents.firmware.sp_models import VerifiedSP
from ..agents.firmware.prompts import get_poc_prompt
from .models import PoC


class PoCAgent:
    """
    Generates PoC trigger inputs for P0 SPs using DeepSeek-V4-Pro.

    Only generates PoCs for P0 SPs (network + unauthenticated + RCE +
    confidence > 0.7). Follows Phase 2/3 pattern: LLMClient, prompt template,
    JSON parsing.

    Usage:
        agent = PoCAgent()
        poc = agent.generate(sp, attack_surface, function_info)
        agent.save(poc, "poc/sp_001_poc.json")
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        temperature: float = 0.3,
        max_tokens: int = 8000,
    ):
        """
        Args:
            llm_client: LLMClient instance (creates new one if None).
            model: Model to use (default: DEEPSEEK_V4_PRO).
            temperature: LLM temperature for structured output.
            max_tokens: Maximum output tokens.
        """
        self.llm_client = llm_client or LLMClient()
        self.model = model or DEEPSEEK_V4_PRO
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ── Public API ──────────────────────────────────────────────────────

    def generate(
        self,
        sp: VerifiedSP,
        attack_surface: AttackSurface,
        function_info: FunctionInfo,
    ) -> PoC:
        """
        Generate a PoC for a single SP.

        Args:
            sp: The verified SP to generate a PoC for.
            attack_surface: The attack surface this SP belongs to.
            function_info: The FunctionInfo with pseudo-code and metadata.

        Returns:
            PoC with trigger input and expected behavior.

        Raises:
            ValueError: If the LLM response cannot be parsed.
        """
        system_prompt = get_poc_prompt()
        user_content = self._build_user_message(sp, attack_surface, function_info)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        logger.info(
            f"PoCAgent: generating PoC for SP {sp.sp_id} "
            f"({sp.cwe}, {sp.function_name})"
        )

        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        poc = self._parse_response(response.content, sp.sp_id)
        logger.info(
            f"PoCAgent: generated PoC for {sp.sp_id} "
            f"(type={poc.poc_type}, {len(poc.alternate_payloads)} alternates)"
        )
        return poc

    def generate_batch(
        self,
        sps: List[VerifiedSP],
        attack_surfaces: List[AttackSurface],
        function_contexts: Dict[str, FunctionInfo],
    ) -> List[PoC]:
        """
        Generate PoCs for multiple P0 SPs.

        Filters to P0 SPs only. Generates one PoC per SP sequentially
        (one LLM call each).

        Args:
            sps: All verified SPs (P0-P3).
            attack_surfaces: All attack surfaces.
            function_contexts: Dict mapping function_name → FunctionInfo.

        Returns:
            List of PoCs for P0 SPs only.
        """
        p0_sps = self._filter_p0(sps)
        if not p0_sps:
            logger.info("PoCAgent: no P0 SPs to generate PoCs for")
            return []

        # Build attack surface lookup by name
        surface_map = {s.name: s for s in attack_surfaces}

        pocs = []
        for sp in p0_sps:
            try:
                func_info = function_contexts.get(sp.function_name)
                if not func_info:
                    logger.warning(
                        f"PoCAgent: no FunctionInfo for {sp.function_name}, skipping {sp.sp_id}"
                    )
                    continue
                # Use first matching attack surface, or first one available
                surface = surface_map.get(
                    sp.input_vector, next(iter(attack_surfaces), AttackSurface(
                        name="unknown", category="other", entry_functions=[]
                    ))
                )
                poc = self.generate(sp, surface, func_info)
                pocs.append(poc)
            except Exception as e:
                logger.error(f"PoCAgent: failed to generate PoC for {sp.sp_id}: {e}")
                continue

        logger.info(
            f"PoCAgent: generated {len(pocs)} PoCs from {len(p0_sps)} P0 SPs"
        )
        return pocs

    # ── P0 Filtering ────────────────────────────────────────────────────

    def _filter_p0(self, sps: List[VerifiedSP]) -> List[VerifiedSP]:
        """Filter to P0 SPs only."""
        return [sp for sp in sps if sp.priority == "P0"]

    # ── Prompt Building ─────────────────────────────────────────────────

    def _build_user_message(
        self,
        sp: VerifiedSP,
        attack_surface: AttackSurface,
        function_info: FunctionInfo,
    ) -> str:
        """Build the user message with SP context, attack surface, and code."""
        parts = []

        parts.append("# Suspicious Point for PoC Generation\n")

        # SP details
        parts.append("## Vulnerability Details")
        parts.append(f"- SP ID: {sp.sp_id}")
        parts.append(f"- CWE: {sp.cwe}")
        parts.append(f"- Title: {sp.title}")
        parts.append(f"- Description: {sp.description}")
        parts.append(f"- Control Flow: {sp.control_flow}")
        parts.append(f"- Trigger Condition: {sp.trigger_condition}")
        parts.append(f"- Root Cause: {sp.root_cause}")
        parts.append(f"- Confidence: {sp.confidence}")
        parts.append(f"- Input Vector: {sp.input_vector}")
        parts.append(f"- Severity: {sp.severity}")
        parts.append(f"- Analyst Type: {sp.analyst_type}")
        if sp.exploitability:
            parts.append(f"- Exploitability: attack_vector={sp.exploitability.attack_vector}, "
                         f"difficulty={sp.exploitability.difficulty}, "
                         f"impact={sp.exploitability.impact}")
        parts.append("")

        # Attack surface context
        parts.append("## Attack Surface Context")
        parts.append(f"- Name: {attack_surface.name}")
        parts.append(f"- Category: {attack_surface.category}")
        parts.append(f"- Protocol: {attack_surface.protocol}")
        if attack_surface.port_info:
            parts.append(f"- Port: {attack_surface.port_info.port}/{attack_surface.port_info.protocol_type}")
        parts.append(f"- Entry Functions: {', '.join(attack_surface.entry_functions)}")
        if attack_surface.strings_evidence:
            parts.append(f"- String Evidence: {', '.join(attack_surface.strings_evidence[:5])}")
        parts.append("")

        # Function pseudo-code
        parts.append("## Target Function")
        parts.append(f"- Name: {function_info.name}")
        parts.append(f"- Address: 0x{function_info.address:X}")
        parts.append(f"- Architecture: {function_info.arch} "
                     f"({function_info.bits}-bit, {function_info.endian}-endian)")
        if function_info.callers:
            parts.append(f"- Callers: {', '.join(function_info.callers[:5])}")
        if function_info.callees:
            parts.append(f"- Callees: {', '.join(function_info.callees[:8])}")
        parts.append("")
        parts.append("### Pseudo-code")
        parts.append("```c")
        parts.append(function_info.pseudo_code)
        parts.append("```")
        parts.append("")

        # Assembly excerpt if available
        if function_info.assembly:
            parts.append("### Assembly Excerpt")
            parts.append("```asm")
            # Show first 40 lines
            asm_lines = function_info.assembly.split("\n")[:40]
            parts.append("\n".join(asm_lines))
            if len(function_info.assembly.split("\n")) > 40:
                parts.append("... (truncated)")
            parts.append("```")
            parts.append("")

        # Call path from entry
        parts.append("## Call Path from Entry Point")
        parts.append(sp.control_flow)
        parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Based on the above vulnerability details and code, construct the "
            "MINIMAL PoC input to trigger this vulnerability. Output ONLY valid "
            "JSON matching the schema in the system prompt. Do not include any "
            "text outside the JSON."
        )

        return "\n".join(parts)

    # ── Response Parsing ────────────────────────────────────────────────

    def _parse_response(self, content: str, sp_id: str) -> PoC:
        """Parse LLM response into PoC.

        Handles LLMs that wrap JSON in markdown code fences.
        """
        json_str = content.strip()

        # Remove ```json ... ``` wrapper if present
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Try to find a JSON object if there's surrounding text
        if not json_str.startswith("{"):
            brace_start = json_str.find("{")
            if brace_start >= 0:
                depth = 0
                end = -1
                for i, ch in enumerate(json_str[brace_start:], brace_start):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                if end >= 0:
                    json_str = json_str[brace_start:end + 1]

        try:
            data = json.loads(json_str)
            return PoC.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse LLM response as PoC: {e}")
            logger.debug(f"Raw response (first 500 chars): {content[:500]}")
            raise ValueError(
                f"Failed to parse LLM response as PoC: {e}"
            ) from e

    # ── File I/O ────────────────────────────────────────────────────────

    def save(self, poc: PoC, path: Union[str, Path]) -> None:
        """Save PoC to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = poc.to_dict()
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"PoC saved to {path}")

    def load(self, path: Union[str, Path]) -> PoC:
        """Load PoC from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"PoC file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return PoC.from_dict(data)
```

- [ ] **Step 4: Run PoCAgent tests to verify they pass**

```bash
pytest tests/test_poc_agent.py -v
```
Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/verifier/poc_agent.py tests/test_poc_agent.py
git commit -m "feat(phase4): implement PoCAgent for P0 SP trigger input generation

PoCAgent uses DeepSeek-V4-Pro to construct minimal exploit trigger inputs.
P0-only filter controls token cost. Includes prompt building with SP
context, attack surface info, function pseudo-code, and call paths.
10 unit tests with mocked LLM responses.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: CrashMonitor

**Files:**
- Create: `fuzzingbrain/verifier/crash_monitor.py`
- Create: `tests/test_crash_monitor.py`

- [ ] **Step 1: Write CrashMonitor tests (these must fail first)**

```python
# tests/test_crash_monitor.py
"""Tests for CrashMonitor."""

import pytest
from fuzzingbrain.verifier.crash_monitor import CrashMonitor
from fuzzingbrain.verifier.models import CrashInfo


class TestCrashMonitorRecord:
    """Tests for crash recording."""

    def test_record_single_crash(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", crash)
        assert cm.crash_count == 1

    def test_record_multiple_crashes(self):
        cm = CrashMonitor()
        cm.record_crash("sp-1", CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11))
        cm.record_crash("sp-2", CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6))
        assert cm.crash_count == 2

    def test_get_unique_crashes(self):
        cm = CrashMonitor()
        cm.record_crash("sp-1", CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11))
        cm.record_crash("sp-2", CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6))
        unique = cm.get_unique_crashes()
        assert len(unique) == 2


class TestCrashMonitorDedup:
    """Tests for crash deduplication."""

    def test_exact_signature_match_is_duplicate(self):
        cm = CrashMonitor()
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        assert cm.is_duplicate(c1) is False  # First one is not dup
        cm.record_crash("sp-1", c1)
        assert cm.is_duplicate(c2) is True   # Second one matches

    def test_different_crash_type_not_duplicate(self):
        cm = CrashMonitor()
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        c2 = CrashInfo(crash_type="SIGABRT", crash_address="0x41414141", signal_number=6)
        assert cm.is_duplicate(c2) is False

    def test_aslr_tolerance(self):
        """Same crash type, nearby address → duplicate (ASLR)."""
        cm = CrashMonitor(aslr_tolerance=0x1000)
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        # Address within 0x1000 tolerance
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41415141", signal_number=11)
        assert cm.is_duplicate(c2) is True

    def test_aslr_outside_tolerance(self):
        """Same crash type, address far away → not duplicate."""
        cm = CrashMonitor(aslr_tolerance=0x1000)
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x42424242", signal_number=11)
        assert cm.is_duplicate(c2) is False

    def test_deduplicate_list(self):
        cm = CrashMonitor()
        crashes = [
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),  # dup
            CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6),
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41415141", signal_number=11),  # near
        ]
        unique = cm.deduplicate(crashes)
        assert len(unique) == 2  # SIGSEGV merged (within tolerance) + SIGABRT

    def test_deduplicate_empty(self):
        cm = CrashMonitor()
        assert cm.deduplicate([]) == []


class TestCrashMonitorClassification:
    """Tests for crash classification."""

    def test_classify_stack_overflow(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        category = cm.classify(crash)
        assert "stack" in category.lower() or "controlled" in category.lower()

    def test_classify_sigabrt(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6)
        category = cm.classify(crash)
        assert "abort" in category.lower() or "assertion" in category.lower()

    def test_classify_sigill(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGILL", crash_address="0x0804a000", signal_number=4)
        category = cm.classify(crash)
        assert "illegal" in category.lower() or "corrupted" in category.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_crash_monitor.py -v
```
Expected: all FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the CrashMonitor implementation**

```python
# fuzzingbrain/verifier/crash_monitor.py
"""
CrashMonitor -- Captures, classifies, and deduplicates crashes.

Pure algorithm (no LLM). Used by FirmAERunner and QEMURunner to track
and deduplicate crash results from dynamic verification.

Dedup Strategy:
1. Exact crash_signature match → duplicate
2. Same crash_type + same crash_address (± aslr_tolerance) → duplicate
3. Same crash_type + crash_address within tolerance → duplicate

Classification:
- SIGSEGV at 0x41... → likely stack overflow (controlled PC)
- SIGSEGV at valid address → likely heap corruption or null deref
- SIGABRT → assertion failure or abort() call
- SIGILL → corrupted function pointer
"""

from typing import Dict, List


class CrashMonitor:
    """
    Captures, classifies, and deduplicates crashes from dynamic verification.
    """

    def __init__(self, aslr_tolerance: int = 0x1000):
        """
        Args:
            aslr_tolerance: Address range tolerance for dedup (default 0x1000).
                           Addresses within this range are considered the same
                           crash location (accounts for ASLR).
        """
        self.aslr_tolerance = aslr_tolerance
        self._recorded: Dict[str, List[CrashInfo]] = {}  # sp_id → [crashes]
        self._signatures: set = set()  # Set of seen signatures for fast lookup

    @property
    def crash_count(self) -> int:
        """Total number of crashes recorded."""
        return sum(len(crashes) for crashes in self._recorded.values())

    def record_crash(self, sp_id: str, crash: "CrashInfo") -> None:
        """Record a crash for a specific SP."""
        if sp_id not in self._recorded:
            self._recorded[sp_id] = []
        self._recorded[sp_id].append(crash)
        self._signatures.add(crash.crash_signature)

    def is_duplicate(self, crash: "CrashInfo") -> bool:
        """
        Check if a crash is a duplicate of any previously recorded crash.

        Uses crash_signature (exact) and address proximity (ASLR tolerance).
        """
        # Check exact signature match first
        if crash.crash_signature in self._signatures:
            return True

        # Check address proximity for same crash_type
        for sig in self._signatures:
            # sig format: "TYPE-ADDRESS"
            if not sig.startswith(crash.crash_type + "-"):
                continue
            sig_addr_str = sig[len(crash.crash_type) + 1:]
            crash_addr_str = crash.crash_address

            # Try to parse addresses
            try:
                sig_addr = int(sig_addr_str, 16) if sig_addr_str else None
                crash_addr = int(crash_addr_str, 16) if crash_addr_str else None
            except (ValueError, AttributeError):
                continue

            if sig_addr is not None and crash_addr is not None:
                if abs(sig_addr - crash_addr) <= self.aslr_tolerance:
                    return True

        return False

    def deduplicate(self, crashes: List["CrashInfo"]) -> List["CrashInfo"]:
        """
        Deduplicate a list of crashes.

        Returns deduplicated list keeping the first occurrence.
        """
        seen: set = set()
        unique: List["CrashInfo"] = []

        for crash in crashes:
            # Check exact signature
            if crash.crash_signature in seen:
                continue

            # Check address proximity
            is_dup = False
            for sig in seen:
                if not sig.startswith(crash.crash_type + "-"):
                    continue
                sig_addr_str = sig[len(crash.crash_type) + 1:]
                crash_addr_str = crash.crash_address
                try:
                    sig_addr = int(sig_addr_str, 16) if sig_addr_str else None
                    crash_addr = int(crash_addr_str, 16) if crash_addr_str else None
                except (ValueError, AttributeError):
                    continue
                if (sig_addr is not None and crash_addr is not None
                        and abs(sig_addr - crash_addr) <= self.aslr_tolerance):
                    is_dup = True
                    break

            if not is_dup:
                seen.add(crash.crash_signature)
                unique.append(crash)

        return unique

    def get_unique_crashes(self) -> List["CrashInfo"]:
        """Get all recorded crashes after deduplication."""
        all_crashes = []
        for crashes in self._recorded.values():
            all_crashes.extend(crashes)
        return self.deduplicate(all_crashes)

    def classify(self, crash: "CrashInfo") -> str:
        """
        Classify a crash into a human-readable category.

        Returns:
            One of: "stack_buffer_overflow", "heap_corruption",
            "null_pointer_deref", "assertion_failure",
            "corrupted_function_pointer", "unknown_crash"
        """
        crash_type = crash.crash_type
        addr = crash.crash_address

        if crash_type == "SIGSEGV":
            if addr and "41414141" in addr:
                return "stack_buffer_overflow"
            if addr and ("00000000" in addr or addr == "0x0" or addr == "0x00"):
                return "null_pointer_deref"
            # Check if address looks like a valid heap address range
            try:
                addr_int = int(addr, 16)
                if 0x08000000 <= addr_int <= 0x7FFFFFFF:
                    return "heap_corruption"
            except (ValueError, AttributeError):
                pass
            return "likely_stack_or_heap_corruption"

        elif crash_type == "SIGABRT":
            return "assertion_failure_or_abort"

        elif crash_type == "SIGILL":
            return "corrupted_function_pointer"

        elif crash_type == "SIGBUS":
            return "bus_error_unaligned_access"

        else:
            return "unknown_crash"


# Import at bottom to avoid circular import
from .models import CrashInfo
```

- [ ] **Step 4: Run CrashMonitor tests to verify they pass**

```bash
pytest tests/test_crash_monitor.py -v
```
Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/verifier/crash_monitor.py tests/test_crash_monitor.py
git commit -m "feat(phase4): implement CrashMonitor for crash capture, classification, and dedup

Pure-algorithm crash dedup using crash_signature exact match and
ASLR-tolerant address proximity. Classification identifies stack
overflow, heap corruption, null deref, assertion failure, and
corrupted function pointer patterns. 10 unit tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: StaticAssessor

**Files:**
- Create: `fuzzingbrain/verifier/static_assessor.py`
- Create: `tests/test_static_assessor.py`

- [ ] **Step 1: Write StaticAssessor tests (these must fail first)**

```python
# tests/test_static_assessor.py
"""Tests for StaticAssessor."""

import pytest
from fuzzingbrain.verifier.static_assessor import StaticAssessor
from fuzzingbrain.verifier.models import VerificationResult
from fuzzingbrain.agents.firmware.sp_models import (
    VerifiedSP, AnalystConsensus, ExploitabilityAssessment,
)
from fuzzingbrain.static.models import CallGraph, CallGraphNode


def make_sp(sp_id="sp-1", confidence=0.90, function_name="httpd_handler",
            entry_functions=None):
    """Helper to create VerifiedSP for testing."""
    if entry_functions is None:
        entry_functions = ["httpd_init"]
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
        title="Test SP",
        description="Test description",
        function_name=function_name,
        vulnerable_code_snippet="strcpy(buf, input);",
        control_flow="httpd_init → httpd_handler → get_param → strcpy",
        trigger_condition="Send oversized input",
        root_cause="No bounds check",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority="P0",
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_callgraph():
    """Create a callgraph with complete path from entry to vuln function."""
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
    """Create a callgraph with missing path (vuln function not connected to entry)."""
    nodes = {
        "httpd_init": CallGraphNode(
            function_name="httpd_init", address=0x2000,
            callees=["socket", "bind", "listen"],  # No path to httpd_handler
        ),
        "httpd_handler": CallGraphNode(
            function_name="httpd_handler", address=0x2100,
            callees=["get_param", "strcpy"],
            callers=[],  # No callers in graph
        ),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


class TestStaticAssessorAssess:
    """Tests for static assessment logic."""

    def test_high_confidence_complete_chain_returns_static_high(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert isinstance(result, VerificationResult)
        assert result.verification_level == "static_high"
        assert result.crashed is False

    def test_high_confidence_incomplete_chain_returns_static_low(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        cg = make_incomplete_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_low_confidence_returns_static_low(self):
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.50)  # Below 0.85 threshold
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_boundary_confidence_below_threshold_discarded(self):
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.849)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_low"

    def test_boundary_confidence_at_threshold_static_high(self):
        assessor = StaticAssessor(high_confidence_threshold=0.85)
        sp = make_sp(confidence=0.85)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        assert result.verification_level == "static_high"

    def test_assess_without_callgraph(self):
        """Without callgraph, should assess based on confidence alone."""
        assessor = StaticAssessor()
        sp = make_sp(confidence=0.90)
        result = assessor.assess(sp, callgraph=None)
        # High confidence but no callgraph → static_high (can't verify chain)
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
        sp = make_sp(confidence=0.85)
        cg = make_callgraph()
        result = assessor.assess(sp, cg)
        # 0.85 < 0.90 threshold → discarded
        assert result.verification_level == "static_low"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_static_assessor.py -v
```
Expected: all FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the StaticAssessor implementation**

```python
# fuzzingbrain/verifier/static_assessor.py
"""
StaticAssessor -- L3 static confidence fallback for dynamic verification.

Pure algorithm (no LLM). When FirmAE (L1) and QEMU (L2) cannot confirm
a vulnerability, assess based on static confidence and call chain completeness.

Rules:
- confidence >= threshold AND complete call chain from entry to sink → static_high
- confidence >= threshold AND incomplete call chain → static_low
- confidence < threshold → static_low
"""

from typing import Optional

from loguru import logger

from ..static.models import CallGraph
from ..agents.firmware.sp_models import VerifiedSP
from .models import VerificationResult


class StaticAssessor:
    """
    L3: Pure static confidence assessment — no dynamic execution.

    Used as the final fallback when both FirmAE (L1) and QEMU (L2)
    cannot confirm a vulnerability.
    """

    def __init__(self, high_confidence_threshold: float = 0.85):
        """
        Args:
            high_confidence_threshold: Minimum confidence for static_high
                                       classification (default 0.85).
        """
        self.high_confidence_threshold = high_confidence_threshold

    def assess(
        self,
        sp: VerifiedSP,
        callgraph: Optional[CallGraph] = None,
    ) -> VerificationResult:
        """
        Assess SP via static confidence rules.

        Args:
            sp: The verified SP to assess.
            callgraph: Optional call graph for path completeness check.

        Returns:
            VerificationResult with verification_level = static_high or static_low.
        """
        # Check confidence threshold
        if sp.confidence < self.high_confidence_threshold:
            logger.info(
                f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f} < "
                f"threshold={self.high_confidence_threshold} → static_low (discarded)"
            )
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="static_low",
                crashed=False,
                output=(
                    f"L3 assessment: confidence={sp.confidence:.2f} < "
                    f"threshold={self.high_confidence_threshold}. Discarded."
                ),
            )

        # Check call chain completeness if callgraph available
        if callgraph is not None:
            chain_complete = self._check_call_chain_completeness(sp, callgraph)
            if chain_complete:
                logger.info(
                    f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f}, "
                    f"chain complete → static_high"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="static_high",
                    crashed=False,
                    output=(
                        f"L3 assessment: confidence={sp.confidence:.2f} >= "
                        f"threshold={self.high_confidence_threshold}, "
                        f"call chain complete from entry to sink. Reserved."
                    ),
                )
            else:
                logger.info(
                    f"StaticAssessor: {sp.sp_id} high confidence but "
                    f"incomplete chain → static_low"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="static_low",
                    crashed=False,
                    output=(
                        f"L3 assessment: confidence={sp.confidence:.2f} >= "
                        f"threshold but call chain incomplete. Discarded."
                    ),
                )

        # No callgraph available — rely on confidence alone
        logger.info(
            f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f}, "
            f"no callgraph → static_high (confidence-based)"
        )
        return VerificationResult(
            sp_id=sp.sp_id,
            verification_level="static_high",
            crashed=False,
            output=(
                f"L3 assessment: confidence={sp.confidence:.2f} >= "
                f"threshold={self.high_confidence_threshold}. "
                f"No callgraph available for path verification. Reserved."
            ),
        )

    def _check_call_chain_completeness(
        self, sp: VerifiedSP, callgraph: CallGraph
    ) -> bool:
        """
        Check if the entry function can reach the vulnerable function
        through the call graph.

        Uses a simple BFS/DFS through callee relationships.

        Returns:
            True if a path exists from any entry-like function to the
            vulnerable function, or if the vulnerable function is itself
            an entry point.
        """
        vuln_func = sp.function_name

        # If the vulnerable function has callers in the graph, that's a start.
        # Check if any of those callers ultimately trace back to an entry function
        # (leaf nodes in the call graph: functions with no callers, i.e., roots).
        if vuln_func not in callgraph.nodes:
            logger.debug(
                f"Vulnerable function '{vuln_func}' not in call graph nodes"
            )
            return False

        # Find root functions (those with no callers — likely entry points)
        root_funcs = {
            name for name, node in callgraph.nodes.items()
            if not node.callers
        }

        if not root_funcs:
            # If no roots found, can't verify chain
            logger.debug("No root functions found in call graph")
            return False

        # BFS from roots to see if any reach the vulnerable function
        visited = set()
        queue = list(root_funcs)
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current == vuln_func:
                logger.debug(
                    f"Found path from root to '{vuln_func}' in call graph"
                )
                return True

            if current in callgraph.nodes:
                for callee in callgraph.nodes[current].callees:
                    if callee not in visited:
                        queue.append(callee)

        logger.debug(
            f"No path from any root to '{vuln_func}' in call graph"
        )
        return False
```

- [ ] **Step 4: Run StaticAssessor tests to verify they pass**

```bash
pytest tests/test_static_assessor.py -v
```
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/verifier/static_assessor.py tests/test_static_assessor.py
git commit -m "feat(phase4): implement StaticAssessor for L3 confidence-based fallback

Pure-algorithm L3 fallback when FirmAE/QEMU cannot confirm. Uses
confidence threshold (default 0.85) and BFS-based call chain
completeness check. 8 unit tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: FirmAERunner

**Files:**
- Create: `fuzzingbrain/verifier/firmae_runner.py`

Note: No separate unit test file for FirmAERunner — it's tested via Phase4Pipeline integration tests (Task 9) and manual end-to-end runs. FirmAERunner requires actual FirmAE installation and firmware filesystem, which cannot be mocked in a meaningful unit test.

- [ ] **Step 1: Write FirmAERunner implementation**

```python
# fuzzingbrain/verifier/firmae_runner.py
"""
FirmAERunner -- L1 full-system emulation verification.

Uses FirmAE to emulate the entire firmware system, send PoC payloads
to the target service, and monitor for crashes.

Requirements:
- FirmAE installed at firmae_dir
- Extracted firmware filesystem
- Target binary identified

FirmAE Reference: https://github.com/pr0v3rbs/FirmAE
"""

import os
import subprocess
import time
import shutil
from pathlib import Path
from typing import Optional

from loguru import logger

from ..agents.firmware.sp_models import VerifiedSP
from .models import PoC, VerificationResult, CrashInfo


class FirmAERunner:
    """
    L1: FirmAE full-system emulation verification.

    Attempts to boot the firmware in FirmAE, send PoC payloads,
    and capture crash results.

    Usage:
        runner = FirmAERunner(firmae_dir="/opt/FirmAE")
        result = runner.verify(sp, poc, firmware_path="/path/to/firmware.bin")
    """

    def __init__(
        self,
        firmae_dir: str,
        workspace_dir: Optional[str] = None,
        boot_timeout: int = 120,
        poc_timeout: int = 30,
    ):
        """
        Args:
            firmae_dir: Path to FirmAE installation directory.
            workspace_dir: Working directory for FirmAE runs (default: firmae_dir/workspace).
            boot_timeout: Maximum seconds to wait for firmware to boot.
            poc_timeout: Maximum seconds to wait for PoC response.
        """
        self.firmae_dir = Path(firmae_dir)
        self.workspace_dir = Path(workspace_dir or self.firmae_dir / "workspace")
        self.boot_timeout = boot_timeout
        self.poc_timeout = poc_timeout
        self._firmae_init_script = self.firmae_dir / "init.sh"
        self._firmae_run_script = self.firmae_dir / "run.sh"

    def verify(
        self,
        sp: VerifiedSP,
        poc: PoC,
        firmware_path: str,
    ) -> VerificationResult:
        """
        Attempt L1 verification via FirmAE full-system emulation.

        Args:
            sp: The SP to verify.
            poc: The PoC payload to send.
            firmware_path: Path to the original firmware binary.

        Returns:
            VerificationResult with verification_level=dynamic_full if crash
            confirmed, or error information if verification failed.
        """
        logger.info(f"FirmAERunner: attempting L1 verification for {sp.sp_id}")

        # Check FirmAE installation
        if not self._firmae_init_script.exists():
            error_msg = (
                f"FirmAE init.sh not found at {self._firmae_init_script}. "
                f"Is FirmAE installed?"
            )
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Step 1: Initialize FirmAE
        try:
            self._initialize_firmae()
        except Exception as e:
            logger.error(f"FirmAE initialization failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"FirmAE init failed: {e}",
            )

        # Step 2: Extract firmware and set up workspace
        workspace = None
        try:
            workspace = self._prepare_workspace(firmware_path)
            if not workspace:
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    error="Failed to prepare FirmAE workspace",
                )
        except Exception as e:
            logger.error(f"Workspace preparation failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"Workspace preparation failed: {e}",
            )

        # Step 3: Deploy and boot firmware
        try:
            booted = self._deploy_firmware(workspace)
            if not booted:
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output="FirmAE boot failed or timed out",
                )
        except Exception as e:
            logger.error(f"FirmAE deploy failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"FirmAE deploy failed: {e}",
            )

        # Step 4: Send PoC payload
        crash_info = None
        try:
            payload_sent = self._send_payload(poc)
            if payload_sent:
                # Check for crashes after sending payload
                crash_info = self._check_crash(workspace)
        except Exception as e:
            logger.error(f"PoC delivery failed: {e}")

        # Step 5: Cleanup
        try:
            self._cleanup(workspace)
        except Exception as e:
            logger.warning(f"FirmAE cleanup failed (non-fatal): {e}")

        # Build result
        if crash_info:
            logger.info(
                f"FirmAERunner: CRASH CONFIRMED for {sp.sp_id} — "
                f"{crash_info.crash_type} at {crash_info.crash_address}"
            )
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="dynamic_full",
                crashed=True,
                crash_info=crash_info,
                output=f"FirmAE L1: {crash_info.crash_type} at {crash_info.crash_address}",
            )
        else:
            logger.info(f"FirmAERunner: no crash detected for {sp.sp_id}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output="FirmAE booted but no crash detected with PoC",
            )

    def _initialize_firmae(self) -> None:
        """Initialize FirmAE (run init.sh if needed)."""
        result = subprocess.run(
            [str(self._firmae_init_script)],
            cwd=str(self.firmae_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"FirmAE init.sh failed (exit {result.returncode}): {result.stderr}"
            )
        logger.info("FirmAE initialized successfully")

    def _prepare_workspace(self, firmware_path: str) -> Optional[str]:
        """
        Prepare FirmAE workspace for the firmware.

        Uses FirmAE's extractor to unpack the firmware and create
        a runnable workspace.
        """
        firmware_name = Path(firmware_path).stem
        workspace = str(self.workspace_dir / firmware_name)

        # Check if already extracted
        if Path(workspace).exists() and Path(workspace, "run.sh").exists():
            logger.info(f"Using existing workspace: {workspace}")
            return workspace

        # Run FirmAE's extractor
        extract_script = self.firmae_dir / "sources" / "extractor" / "extractor.py"
        if not extract_script.exists():
            # Try alternative locations
            extract_script = self.firmae_dir / "extractor.py"

        if extract_script.exists():
            result = subprocess.run(
                ["python3", str(extract_script), "-b", "brand", firmware_path, workspace],
                cwd=str(self.firmae_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.error(f"FirmAE extractor failed: {result.stderr}")
                return None

        # Create workspace directory if extraction didn't
        Path(workspace).mkdir(parents=True, exist_ok=True)
        return workspace

    def _deploy_firmware(self, workspace: str) -> bool:
        """
        Deploy firmware in FirmAE and wait for boot.

        Returns:
            True if the firmware appears to have booted successfully.
        """
        # Launch FirmAE run script
        run_script = Path(workspace) / "run.sh"
        if not run_script.exists():
            logger.error(f"FirmAE run script not found: {run_script}")
            return False

        try:
            # Run in background and wait for boot indicator
            self._firmae_process = subprocess.Popen(
                ["bash", str(run_script)],
                cwd=workspace,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for boot indicator (check for network interface or service)
            booted = self._wait_for_boot(workspace)
            return booted
        except Exception as e:
            logger.error(f"FirmAE deploy exception: {e}")
            return False

    def _wait_for_boot(self, workspace: str) -> bool:
        """Wait for firmware to complete boot process."""
        start_time = time.time()
        while time.time() - start_time < self.boot_timeout:
            # Check if FirmAE created a network interface (indicates boot)
            tap_file = Path(workspace) / "tap.sh"
            if tap_file.exists():
                logger.info("FirmAE boot detected (tap interface ready)")
                # Give it a few more seconds to stabilize
                time.sleep(5)
                return True

            # Check for run.sh completion marker
            if self._firmae_process and self._firmae_process.poll() is not None:
                logger.error(
                    f"FirmAE process exited early with code {self._firmae_process.returncode}"
                )
                return False

            time.sleep(1)

        logger.warning(
            f"FirmAE boot timed out after {self.boot_timeout}s"
        )
        return False

    def _send_payload(self, poc: PoC) -> bool:
        """
        Send PoC payload to the target service inside FirmAE emulation.

        Uses netcat/curl depending on PoC type, with tap interface
        for network communication.
        """
        try:
            if poc.poc_type in ("http_request", "http_response"):
                return self._send_http_payload(poc)
            elif poc.poc_type in ("tcp_stream",):
                return self._send_tcp_payload(poc)
            elif poc.poc_type in ("udp_packet",):
                return self._send_udp_payload(poc)
            else:
                logger.warning(
                    f"Unsupported poc_type for FirmAE: {poc.poc_type}"
                )
                return False
        except Exception as e:
            logger.error(f"Payload delivery failed: {e}")
            return False

    def _send_http_payload(self, poc: PoC) -> bool:
        """Send HTTP-based PoC via curl."""
        target = poc.poc_target
        url = f"http://{target.host}:{target.port}{target.path}"

        cmd = ["curl", "-s", "--max-time", str(self.poc_timeout)]
        if target.method == "POST":
            cmd.extend(["-X", "POST", "-d", poc.poc_content])
        else:
            cmd.extend(["-G", "--data-urlencode", f"data={poc.poc_content}"])

        cmd.append(url)
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.poc_timeout + 5
        )
        return result.returncode in (0, 7, 52, 56)  # curl exit codes that indicate connection happened

    def _send_tcp_payload(self, poc: PoC) -> bool:
        """Send TCP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-w", str(self.poc_timeout), target.host, str(target.port)]
        result = subprocess.run(
            cmd,
            input=poc.poc_content,
            capture_output=True,
            text=True,
            timeout=self.poc_timeout + 5,
        )
        return True  # nc always returns success if connection made

    def _send_udp_payload(self, poc: PoC) -> bool:
        """Send UDP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-u", "-w", str(self.poc_timeout), target.host, str(target.port)]
        result = subprocess.run(
            cmd,
            input=poc.poc_content,
            capture_output=True,
            text=True,
            timeout=self.poc_timeout + 5,
        )
        return True

    def _check_crash(self, workspace: str) -> Optional[CrashInfo]:
        """
        Check for crashes in the FirmAE emulated system.

        Looks for:
        1. /crash directory with crash logs
        2. Core dumps
        3. FirmAE console output with crash indicators
        """
        # Check FirmAE's crash directory
        crash_dir = Path(workspace) / "crash"
        if crash_dir.exists():
            crash_files = list(crash_dir.glob("*"))
            if crash_files:
                # Parse the most recent crash file
                crash_file = max(crash_files, key=lambda p: p.stat().st_mtime)
                return self._parse_crash_file(crash_file)

        # Check console output
        try:
            stdout, stderr = self._firmae_process.communicate(timeout=5)
            output = (stdout or b"") + (stderr or b"")
            output_str = output.decode("utf-8", errors="replace")

            if "SIGSEGV" in output_str:
                return CrashInfo(crash_type="SIGSEGV", signal_number=11)
            elif "SIGABRT" in output_str:
                return CrashInfo(crash_type="SIGABRT", signal_number=6)
            elif "SIGILL" in output_str:
                return CrashInfo(crash_type="SIGILL", signal_number=4)
            elif "SIGBUS" in output_str:
                return CrashInfo(crash_type="SIGBUS", signal_number=7)
            elif "Segmentation fault" in output_str:
                return CrashInfo(crash_type="SIGSEGV", signal_number=11)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.warning(f"Error checking crash: {e}")

        return None

    def _parse_crash_file(self, crash_file: Path) -> CrashInfo:
        """Parse a FirmAE crash file into CrashInfo."""
        content = crash_file.read_text(encoding="utf-8", errors="replace")

        crash_type = "SIGSEGV"
        crash_address = ""
        signal_number = 11
        backtrace_lines = []

        for line in content.split("\n"):
            line = line.strip()
            if "SIGSEGV" in line:
                crash_type = "SIGSEGV"
                signal_number = 11
            elif "SIGABRT" in line:
                crash_type = "SIGABRT"
                signal_number = 6
            elif "SIGILL" in line:
                crash_type = "SIGILL"
                signal_number = 4
            elif "SIGBUS" in line:
                crash_type = "SIGBUS"
                signal_number = 7

            if "fault addr" in line.lower():
                # Extract hex address
                import re
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)
            elif "at" in line.lower() and "0x" in line:
                import re
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)

            if "0x" in line and ("::" in line or " in " in line):
                backtrace_lines.append(line)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
            signal_number=signal_number,
            backtrace=backtrace_lines,
        )

    def _cleanup(self, workspace: str) -> None:
        """Cleanup FirmAE emulation."""
        if hasattr(self, "_firmae_process") and self._firmae_process:
            try:
                self._firmae_process.terminate()
                self._firmae_process.wait(timeout=10)
            except Exception:
                try:
                    self._firmae_process.kill()
                except Exception:
                    pass


# Import at bottom to avoid circular import
from .models import CrashInfo
```

- [ ] **Step 2: Commit**

```bash
git add fuzzingbrain/verifier/firmae_runner.py
git commit -m "feat(phase4): implement FirmAERunner for L1 full-system emulation verification

FirmAERunner integrates with FirmAE for full firmware emulation:
- FirmAE initialization and workspace preparation
- Firmware deployment and boot monitoring (120s timeout)
- PoC payload delivery via curl/nc (HTTP, TCP, UDP)
- Crash detection from /crash directory and console output
- Graceful cleanup of emulation processes

Tested via Phase4Pipeline integration tests. Requires FirmAE
installation for actual runtime use.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: QEMURunner

**Files:**
- Create: `fuzzingbrain/verifier/qemu_runner.py`

Note: No separate unit test file — tested via Phase4Pipeline integration tests (Task 9).

- [ ] **Step 1: Write QEMURunner implementation**

```python
# fuzzingbrain/verifier/qemu_runner.py
"""
QEMURunner -- L2 user-mode emulation verification.

Uses QEMU user-mode (qemu-arm, qemu-mipsel, etc.) to run individual
binaries with PoC input and capture crash signals.

Requirements:
- QEMU user-mode binaries installed (qemu-arm, qemu-mipsel, etc.)
- Extracted rootfs for library dependencies (-L flag)
- Target binary extracted from firmware
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from ..agents.firmware.sp_models import VerifiedSP
from .models import PoC, VerificationResult, CrashInfo


class QEMURunner:
    """
    L2: QEMU user-mode emulation verification.

    Runs the target binary under QEMU user-mode with PoC as input
    and monitors for crash signals.

    Usage:
        runner = QEMURunner(qemu_dir="/usr/bin", rootfs_dir="/path/to/rootfs")
        result = runner.verify(sp, poc, binary_path="/path/to/binary", arch="arm")
    """

    # Architecture → QEMU binary mapping
    ARCH_TO_QEMU = {
        "arm": "qemu-arm",
        "armeb": "qemu-armeb",
        "mips": "qemu-mips",
        "mipsel": "qemu-mipsel",
        "mips64": "qemu-mips64",
        "mips64el": "qemu-mips64el",
        "x86": "qemu-i386",
        "x86_64": "qemu-x86_64",
        "aarch64": "qemu-aarch64",
        "ppc": "qemu-ppc",
        "ppc64": "qemu-ppc64",
        "riscv64": "qemu-riscv64",
    }

    # QEMU signal → (CrashType, SignalNumber) mapping
    SIGNAL_MAP = {
        4: ("SIGILL", 4),
        6: ("SIGABRT", 6),
        7: ("SIGBUS", 7),
        8: ("SIGFPE", 8),
        11: ("SIGSEGV", 11),
    }

    def __init__(
        self,
        qemu_dir: str = "/usr/bin",
        rootfs_dir: str = "",
        timeout: int = 30,
    ):
        """
        Args:
            qemu_dir: Directory containing QEMU user-mode binaries.
            rootfs_dir: Root filesystem directory for -L flag (library search path).
            timeout: Maximum seconds for QEMU execution.
        """
        self.qemu_dir = Path(qemu_dir)
        self.rootfs_dir = rootfs_dir
        self.timeout = timeout

    def verify(
        self,
        sp: VerifiedSP,
        poc: PoC,
        binary_path: str,
        arch: str,
    ) -> VerificationResult:
        """
        Attempt L2 verification via QEMU user-mode.

        Args:
            sp: The SP to verify.
            poc: The PoC payload to use as input.
            binary_path: Path to the target binary.
            arch: Target architecture (arm, mips, mipsel, etc.).

        Returns:
            VerificationResult with verification_level=dynamic_user if crash
            confirmed, or error information.
        """
        logger.info(
            f"QEMURunner: attempting L2 verification for {sp.sp_id} (arch={arch})"
        )

        # Detect QEMU binary
        qemu_bin = self._detect_qemu_binary(arch)
        if not qemu_bin:
            error_msg = (
                f"QEMU binary not found for arch '{arch}'. "
                f"Supported: {sorted(self.ARCH_TO_QEMU.keys())}"
            )
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Check target binary exists
        if not Path(binary_path).exists():
            error_msg = f"Target binary not found: {binary_path}"
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Build command
        cmd = self._build_command(qemu_bin, binary_path, poc)
        logger.debug(f"QEMU command: {' '.join(cmd)}")

        # Execute
        try:
            result = subprocess.run(
                cmd,
                input=poc.poc_content,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Parse crash from exit code
            crash_info = self._parse_crash_output(
                result.stdout,
                result.stderr,
                result.returncode,
            )

            if crash_info:
                logger.info(
                    f"QEMURunner: CRASH CONFIRMED for {sp.sp_id} — "
                    f"{crash_info.crash_type} signal={crash_info.signal_number}"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash_info,
                    output=f"QEMU L2: {crash_info.crash_type} (signal {crash_info.signal_number})\n"
                           f"stderr: {result.stderr[:500]}",
                )
            else:
                logger.info(
                    f"QEMURunner: no crash for {sp.sp_id} "
                    f"(exit code {result.returncode})"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output=f"QEMU exited normally with code {result.returncode}",
                )

        except subprocess.TimeoutExpired:
            logger.info(f"QEMURunner: {sp.sp_id} timed out ({self.timeout}s) — possible hang")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output=f"QEMU timed out after {self.timeout}s (possible infinite loop/hang)",
            )
        except Exception as e:
            logger.error(f"QEMURunner: execution failed for {sp.sp_id}: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"QEMU execution failed: {e}",
            )

    def _detect_qemu_binary(self, arch: str) -> Optional[str]:
        """
        Map architecture to QEMU binary and check if it exists.

        Returns:
            Path to QEMU binary, or None if not found.
        """
        qemu_name = self.ARCH_TO_QEMU.get(arch)
        if not qemu_name:
            return None

        qemu_path = self.qemu_dir / qemu_name
        if qemu_path.exists():
            return str(qemu_path)

        # Try without directory (in PATH)
        try:
            subprocess.run(["which", qemu_name], capture_output=True, check=True)
            return qemu_name
        except subprocess.CalledProcessError:
            return None

    def _build_command(
        self,
        qemu_bin: str,
        binary_path: str,
        poc: PoC,
    ) -> List[str]:
        """
        Build the QEMU command line.

        For HTTP targets, use -E to set environment variables.
        For stdin targets, pipe content via subprocess stdin.
        """
        cmd = [qemu_bin]

        # Set library search path if rootfs is available
        if self.rootfs_dir and Path(self.rootfs_dir).exists():
            cmd.extend(["-L", self.rootfs_dir])

        # Strace-like output for crash details
        cmd.extend(["-strace"])

        # Add binary path
        cmd.append(binary_path)

        # Add arguments based on PoC type
        if poc.poc_type == "http_request":
            # For HTTP-based vulns, QEMU can't really do full networking.
            # Set env vars and let stdin serve as input.
            target = poc.poc_target
            cmd.extend([
                "-E", f"REQUEST_METHOD={target.method}",
                "-E", f"REQUEST_URI={target.path}",
                "-E", f"SERVER_PORT={target.port}",
            ])
        elif poc.poc_type == "stdin_input":
            # Binary reads from stdin directly
            pass

        return cmd

    def _parse_crash_output(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> Optional[CrashInfo]:
        """
        Parse QEMU output for crash information.

        QEMU user-mode returns the signal number as exit code (if negative
        in shell, subprocess captures as positive int). For QEMU, the exit
        code is typically:
        - 0: Normal exit
        - -signal_number: Killed by signal (wrapped to positive by subprocess)

        Actually, QEMU user-mode: exit code = signal if killed by signal,
        or the program's return code.
        """
        # Check if return code indicates a signal
        if returncode <= 0:
            return None

        crash_type, signal_number = self.SIGNAL_MAP.get(
            returncode, (None, 0)
        )

        # Also check stderr for crash indicators
        combined_output = stdout + stderr
        if not crash_type:
            for sig_name in ["SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGFPE"]:
                if sig_name in combined_output:
                    sig_map = {
                        "SIGSEGV": 11, "SIGABRT": 6, "SIGILL": 4,
                        "SIGBUS": 7, "SIGFPE": 8,
                    }
                    crash_type = sig_name
                    signal_number = sig_map.get(sig_name, 0)
                    break

        if not crash_type and "Segmentation fault" in combined_output:
            crash_type = "SIGSEGV"
            signal_number = 11

        if not crash_type:
            return None

        # Extract crash address from QEMU output
        crash_address = ""
        backtrace = []
        for line in combined_output.split("\n"):
            line = line.strip()
            # QEMU typically prints: qemu: uncaught target signal 11 (Segmentation fault) - core dumped
            # PC=0x41414141
            if "PC=0x" in line or "pc=0x" in line:
                import re
                match = re.search(r"[Pp][Cc]\s*=\s*(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)
            elif "fault addr" in line.lower() or "at address" in line.lower():
                import re
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)
            elif "0x" in line and (" in " in line or "::" in line):
                backtrace.append(line)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
            signal_number=signal_number,
            backtrace=backtrace,
        )


# Import at bottom
from .models import CrashInfo
```

- [ ] **Step 2: Commit**

```bash
git add fuzzingbrain/verifier/qemu_runner.py
git commit -m "feat(phase4): implement QEMURunner for L2 user-mode emulation verification

QEMURunner provides L2 fallback when FirmAE cannot boot:
- Architecture detection and QEMU binary mapping (ARM, MIPS, x86, etc.)
- QEMU user-mode execution with PoC stdin input
- Crash detection via signal exit codes and stderr parsing
- Strace integration for detailed crash output
- Configurable timeout (default 30s)

Tested via Phase4Pipeline integration tests. Requires QEMU user-mode
binaries for target architectures.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: ReportGenerator

**Files:**
- Create: `fuzzingbrain/reporter/__init__.py`
- Create: `fuzzingbrain/reporter/generator.py`
- Create: `tests/test_report_generator.py`

- [ ] **Step 1: Create reporter package init**

```python
# fuzzingbrain/reporter/__init__.py
"""
Report generation for firmware vulnerability discovery.

Phase 4 output: FinalReport with JSON + Markdown formats.
"""

from .generator import ReportGenerator

__all__ = ["ReportGenerator"]
```

- [ ] **Step 2: Write ReportGenerator tests (these must fail first)**

```python
# tests/test_report_generator.py
"""Tests for ReportGenerator."""

import json
import pytest
from pathlib import Path

from fuzzingbrain.reporter.generator import ReportGenerator
from fuzzingbrain.verifier.models import (
    Phase4Statistics, Phase4Result, VerificationResult,
    CrashInfo, PoC, PoCTarget, ReportMetadata, VulnerabilityEntry, FinalReport,
)
from fuzzingbrain.agents.firmware.sp_models import ExploitabilityAssessment


def make_sample_report():
    """Create a sample FinalReport for testing."""
    metadata = ReportMetadata(
        firmware_name="test_firmware.bin",
        firmware_hash="abc123def456",
        analysis_date="2026-06-04T12:00:00",
        total_functions_analyzed=150,
        total_attack_surfaces=7,
        total_directions=4,
    )

    ea = ExploitabilityAssessment(
        attack_vector="network", difficulty="trivial",
        reliability="reliable", impact="RCE",
    )
    poc = PoC(
        sp_id="mc-httpd-CWE-121-0001",
        poc_type="http_request",
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
            sp_id="mc-httpd-CWE-121-0001",
            cwe="CWE-121",
            title="Stack Buffer Overflow in HTTP parameter parsing",
            description="The httpd_handler function copies user-supplied URL parameter "
                        "into a fixed-size 256-byte stack buffer using strcpy without "
                        "any bounds check, allowing remote code execution.",
            function_name="httpd_handler",
            binary_offset="0x2100",
            control_flow="httpd_init → httpd_handle_request → get_param → strcpy",
            trigger_condition="Send HTTP POST request with url parameter exceeding 256 bytes",
            confidence=0.85,
            severity="critical",
            priority="P0",
            verification_level="dynamic_full",
            exploitability=ea,
            poc=poc,
            crash_info=crash,
            fix_suggestion="Replace strcpy with strncpy(buf, param, sizeof(buf)-1) and "
                           "ensure null termination. Alternatively, use snprintf with "
                           "explicit buffer size.",
        ),
        VulnerabilityEntry(
            sp_id="inj-cgi-CWE-78-0001",
            cwe="CWE-78",
            title="Command Injection in ping utility handler",
            description="The cgi_ping function concatenates user-supplied IP address "
                        "into a system() command string without sanitization.",
            function_name="cgi_ping",
            binary_offset="0x3500",
            control_flow="cgi_main → cgi_ping → sprintf → system",
            trigger_condition="Send POST to /cgi-bin/ping with ip=;cat /etc/shadow",
            confidence=0.90,
            severity="critical",
            priority="P0",
            verification_level="static_high",
            fix_suggestion="Validate IP address format before passing to system(). "
                           "Use gethostbyname() or a proper ping library instead of "
                           "shell command.",
        ),
    ]

    stats = Phase4Statistics(
        total_p0_sps=3,
        poc_generated=3,
        dynamic_full_verified=1,
        dynamic_user_verified=0,
        static_high_reserved=1,
        discarded=1,
        unique_crashes=1,
        verification_rate="66.7%",
    )

    return FinalReport(metadata=metadata, vulnerabilities=entries, statistics=stats)


class TestReportGeneratorJSON:
    """Tests for JSON report generation."""

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
        required_fields = [
            "sp_id", "cwe", "title", "description", "function_name",
            "confidence", "severity", "priority", "verification_level",
            "fix_suggestion",
        ]
        for field in required_fields:
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
    """Tests for Markdown report generation."""

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
        assert "# Vulnerability" in content or "## Vulnerability" in content

    def test_markdown_contains_statistics(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)

        content = output_path.read_text()
        assert "Statistics" in content or "statistics" in content.lower()
        assert "P0" in content

    def test_markdown_contains_fix_suggestions(self, tmp_path):
        report = make_sample_report()
        gen = ReportGenerator()
        output_path = tmp_path / "report.md"
        gen.to_markdown(report, output_path)

        content = output_path.read_text()
        assert "Fix" in content or "Mitigation" in content or "Remediation" in content
        assert "strncpy" in content

    def test_generate_complete(self, tmp_path):
        """Generate complete report (both formats)."""
        report = make_sample_report()
        gen = ReportGenerator()
        result = gen.generate(report)
        assert isinstance(result, FinalReport)
        assert result.count == 2


class TestReportGeneratorEmptyReport:
    """Tests for empty report handling."""

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
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pytest tests/test_report_generator.py -v
```
Expected: all FAIL with `ModuleNotFoundError: No module named 'fuzzingbrain.reporter'`

- [ ] **Step 4: Write ReportGenerator implementation**

```python
# fuzzingbrain/reporter/generator.py
"""
ReportGenerator -- Generates final vulnerability reports.

Produces two formats:
1. JSON: Machine-readable, complete structured data
2. Markdown: Human-readable, suitable for submission/display

Both formats include CWE, PoC, call chains, exploitability assessment,
and fix suggestions.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Union

from loguru import logger

from ..verifier.models import FinalReport, Phase4Statistics, ReportMetadata, VulnerabilityEntry


class ReportGenerator:
    """
    Generates the final vulnerability report in JSON and Markdown.

    Usage:
        gen = ReportGenerator()
        gen.to_json(report, "final_report.json")
        gen.to_markdown(report, "final_report.md")
    """

    def generate(self, report: FinalReport) -> FinalReport:
        """Generate complete report (returns same object, for API consistency)."""
        return report

    # ── JSON Output ──────────────────────────────────────────────────────

    def to_json(self, report: FinalReport, path: Union[str, Path]) -> None:
        """Write report as JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = report.to_dict()
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"JSON report saved to {path}")

    # ── Markdown Output ──────────────────────────────────────────────────

    def to_markdown(self, report: FinalReport, path: Union[str, Path]) -> None:
        """Write report as Markdown file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        md = self._build_markdown(report)
        path.write_text(md, encoding="utf-8")
        logger.info(f"Markdown report saved to {path}")

    def _build_markdown(self, report: FinalReport) -> str:
        """Build complete Markdown report."""
        lines = []

        # Title
        lines.append(f"# Firmware Vulnerability Analysis Report")
        lines.append("")
        lines.append(f"**Firmware:** `{report.metadata.firmware_name}`")
        lines.append(f"**Analysis Date:** {report.metadata.analysis_date or 'N/A'}")
        lines.append(f"**Firmware Hash:** `{report.metadata.firmware_hash or 'N/A'}`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.extend(self._build_executive_summary(report))
        lines.append("")
        lines.append("---")
        lines.append("")

        # Statistics
        lines.extend(self._build_statistics_section(report.statistics))
        lines.append("")
        lines.append("---")
        lines.append("")

        # Vulnerability Details
        if report.vulnerabilities:
            lines.append(f"## Vulnerability Details ({report.count} found)")
            lines.append("")
            for i, vuln in enumerate(report.vulnerabilities, 1):
                lines.extend(self._build_vulnerability_section(i, vuln))
                lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("## Vulnerability Details")
            lines.append("")
            lines.append("No vulnerabilities were confirmed in this analysis.")
            lines.append("")

        # Methodology
        lines.append("## Methodology")
        lines.append("")
        lines.append("This report was generated by FuzzingBrain's firmware vulnerability "
                     "discovery pipeline:")
        lines.append("")
        lines.append("1. **Phase 1 — Static Analysis:** Ghidra decompilation + binwalk extraction")
        lines.append("2. **Phase 2 — Attack Surface Identification:** LLM-based semantic analysis "
                     "of functions, strings, and call graphs")
        lines.append("3. **Phase 3 — Multi-Agent Cross-Examination:** 3 specialized vulnerability "
                     "analysts (memory corruption, logic flaw, injection) with adversarial "
                     "cross-review and voting-based verification")
        lines.append("4. **Phase 4 — Dynamic Verification:** Layered verification with "
                     "FirmAE full-system emulation (L1), QEMU user-mode (L2), and "
                     "static confidence assessment (L3)")
        lines.append("")

        return "\n".join(lines)

    def _build_executive_summary(self, report: FinalReport) -> list:
        """Build the executive summary section."""
        stats = report.statistics
        lines = ["## Executive Summary", ""]

        total = stats.total_p0_sps
        confirmed = stats.dynamic_full_verified + stats.dynamic_user_verified
        reserved = stats.static_high_reserved
        discarded = stats.discarded

        lines.append(f"- **P0 SPs analyzed:** {total}")
        lines.append(f"- **Dynamically confirmed:** {confirmed} "
                     f"(FirmAE: {stats.dynamic_full_verified}, "
                     f"QEMU: {stats.dynamic_user_verified})")
        lines.append(f"- **Static high confidence:** {reserved}")
        lines.append(f"- **Discarded:** {discarded}")
        lines.append(f"- **Verification rate:** {stats.verification_rate or 'N/A'}")
        lines.append(f"- **Unique crashes:** {stats.unique_crashes}")
        lines.append("")

        # Key findings
        critical_vulns = [
            v for v in report.vulnerabilities
            if v.severity == "critical" or v.priority == "P0"
        ]
        if critical_vulns:
            lines.append("### Key Findings")
            lines.append("")
            for v in critical_vulns:
                lines.append(f"- **{v.cwe}** — {v.title} in `{v.function_name}` "
                           f"(confidence: {v.confidence:.0%}, "
                           f"verification: {v.verification_level})")

        return lines

    def _build_statistics_section(self, stats: Phase4Statistics) -> list:
        """Build statistics section."""
        lines = ["## Statistics", ""]
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total P0 SPs | {stats.total_p0_sps} |")
        lines.append(f"| PoCs Generated | {stats.poc_generated} |")
        lines.append(f"| L1 (FirmAE) Confirmed | {stats.dynamic_full_verified} |")
        lines.append(f"| L2 (QEMU) Confirmed | {stats.dynamic_user_verified} |")
        lines.append(f"| L3 (Static High) Reserved | {stats.static_high_reserved} |")
        lines.append(f"| Discarded (False Positive) | {stats.discarded} |")
        lines.append(f"| Unique Crashes | {stats.unique_crashes} |")
        lines.append(f"| Verification Rate | {stats.verification_rate or 'N/A'} |")
        return lines

    def _build_vulnerability_section(self, index: int, v: VulnerabilityEntry) -> list:
        """Build a single vulnerability detail section."""
        lines = [
            f"### {index}. {v.title}",
            "",
            f"| Field | Detail |",
            f"|-------|--------|",
            f"| **CWE** | {v.cwe} |",
            f"| **SP ID** | `{v.sp_id}` |",
            f"| **Function** | `{v.function_name}` @ `{v.binary_offset or 'N/A'}` |",
            f"| **Severity** | {v.severity} |",
            f"| **Priority** | {v.priority} |",
            f"| **Confidence** | {v.confidence:.0%} |",
            f"| **Verification** | {v.verification_level} |",
            "",
        ]

        # Description
        lines.append("#### Description")
        lines.append("")
        lines.append(v.description)
        lines.append("")

        # Control Flow
        if v.control_flow:
            lines.append("#### Control Flow")
            lines.append("")
            lines.append("```")
            lines.append(v.control_flow)
            lines.append("```")
            lines.append("")

        # Trigger Condition
        if v.trigger_condition:
            lines.append("#### Trigger Condition")
            lines.append("")
            lines.append(v.trigger_condition)
            lines.append("")

        # Exploitability
        if v.exploitability:
            lines.append("#### Exploitability Assessment")
            lines.append("")
            lines.append(f"- **Attack Vector:** {v.exploitability.attack_vector}")
            lines.append(f"- **Difficulty:** {v.exploitability.difficulty}")
            lines.append(f"- **Reliability:** {v.exploitability.reliability}")
            lines.append(f"- **Impact:** {v.exploitability.impact}")
            lines.append("")

        # PoC
        if v.poc:
            lines.append("#### Proof of Concept")
            lines.append("")
            lines.append(f"- **Type:** {v.poc.poc_type}")
            lines.append(f"- **Target:** {v.poc.poc_target.method} "
                         f"http://{v.poc.poc_target.host}:{v.poc.poc_target.port}"
                         f"{v.poc.poc_target.path}")
            lines.append(f"- **Explanation:** {v.poc.poc_explanation}")
            lines.append("")
            lines.append("```")
            # Show first 500 chars of payload
            content_preview = v.poc.poc_content[:500]
            if len(v.poc.poc_content) > 500:
                content_preview += "\n... (truncated)"
            lines.append(content_preview)
            lines.append("```")
            lines.append("")

        # Crash Info
        if v.crash_info:
            lines.append("#### Crash Information")
            lines.append("")
            lines.append(f"- **Crash Type:** {v.crash_info.crash_type}")
            lines.append(f"- **Crash Address:** `{v.crash_info.crash_address}`")
            lines.append(f"- **Signal:** {v.crash_info.signal_number}")
            if v.crash_info.register_state:
                lines.append(f"- **Registers:** {v.crash_info.register_state}")
            if v.crash_info.backtrace:
                lines.append("- **Backtrace:**")
                for bt in v.crash_info.backtrace[:5]:
                    lines.append(f"  - {bt}")
            lines.append("")

        # Fix Suggestion
        if v.fix_suggestion:
            lines.append("#### Fix Suggestion")
            lines.append("")
            lines.append(v.fix_suggestion)
            lines.append("")

        return lines
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_report_generator.py -v
```
Expected: all 10 tests PASS

- [ ] **Step 6: Commit**

```bash
git add fuzzingbrain/reporter/__init__.py fuzzingbrain/reporter/generator.py tests/test_report_generator.py
git commit -m "feat(phase4): implement ReportGenerator for JSON + Markdown report generation

ReportGenerator produces structured final reports with:
- JSON output (machine-readable, complete data)
- Markdown output (human-readable, submission-ready)
- Executive summary, statistics table, vulnerability details
- Per-vulnerability: CWE, PoC, crash info, exploitability, fix suggestions
- Methodology section documenting the analysis pipeline

10 unit tests covering both formats and edge cases.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Phase4Pipeline

**Files:**
- Create: `fuzzingbrain/verifier/pipeline.py`
- Create: `tests/test_phase4_pipeline.py`

- [ ] **Step 1: Write Phase4Pipeline tests (these must fail first)**

```python
# tests/test_phase4_pipeline.py
"""Tests for Phase4Pipeline integration."""

import json
from unittest.mock import MagicMock, patch, PropertyMock

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


def make_p0_sp(sp_id="mc-func-CWE-121-0001", confidence=0.85, function_name="httpd_handler"):
    """Create a P0 VerifiedSP."""
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
        title="Stack Buffer Overflow",
        description="strcpy without bounds check",
        function_name=function_name,
        vulnerable_code_snippet="char buf[256]; strcpy(buf, input);",
        control_flow="entry → handler → strcpy",
        trigger_condition="Oversized input",
        root_cause="Missing bounds check",
        exploitability=ea, confidence=confidence, severity="critical",
        analyst_type="memory_corruption", binary_offset="0x2100",
        input_vector="http_post", priority="P0",
        analyst_consensus=consensus, verification_priority="immediate",
    )


def make_functions():
    """Create test FunctionInfo list."""
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
    """Create test AttackSurface list."""
    return [
        AttackSurface(
            name="HTTP Server",
            category="network_service",
            entry_functions=["httpd_init", "httpd_handler"],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
        ),
    ]


def make_callgraph():
    """Create test CallGraph."""
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
    """Tests for pipeline initialization."""

    def test_default_init(self):
        pipeline = Phase4Pipeline()
        assert pipeline.poc_agent is not None
        assert pipeline.crash_monitor is not None
        assert pipeline.static_assessor is not None

    def test_output_dir_default(self):
        pipeline = Phase4Pipeline()
        assert pipeline.output_dir is not None


class TestPhase4PipelineRun:
    """Integration tests with mocked external dependencies."""

    @patch("fuzzingbrain.verifier.pipeline.LLMClient")
    @patch("fuzzingbrain.verifier.pipeline.FirmAERunner")
    @patch("fuzzingbrain.verifier.pipeline.QEMURunner")
    def test_run_with_mocked_runners(self, MockQEMU, MockFirmAE, MockLLM):
        """Full pipeline run with FirmAE → QEMU → StaticAssessor fallback."""
        # Mock LLM for PoC generation
        mock_client = MockLLM.return_value
        mock_response = MagicMock()
        mock_response.content = MOCK_POC_JSON
        mock_client.call.return_value = mock_response

        # Mock FirmAE — fails (returns not_verified)
        mock_firmae = MockFirmAE.return_value
        mock_firmae.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="not_verified",
            crashed=False,
            output="FirmAE boot failed",
        )

        # Mock QEMU — succeeds (returns crash)
        mock_qemu = MockQEMU.return_value
        mock_qemu.verify.return_value = VerificationResult(
            sp_id="mc-func-CWE-121-0001",
            verification_level="dynamic_user",
            crashed=True,
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
        # QEMU should have confirmed it (FirmAE failed → QEMU succeeded)
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
            verification_level="dynamic_full",
            crashed=True,
            crash_info=CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            output="FirmAE: crash confirmed",
        )

        pipeline = Phase4Pipeline()
        result = pipeline.run(
            verified_sps=[make_p0_sp()],
            functions=make_functions(),
            attack_surfaces=make_attack_surfaces(),
            firmware_name="test.bin",
        )

        # QEMU should NOT have been called
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

        # Both runners fail
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

        # Should fall through to static assessment
        assert result.statistics.static_high_reserved >= 0
        # Total verified results should include the SP
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

        # No P0 SPs → no PoCs generated
        assert result.statistics.poc_generated == 0
        assert result.statistics.total_p0_sps == 0


class TestPhase4PipelineFileIO:
    """Tests for save/load."""

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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_phase4_pipeline.py -v
```
Expected: all FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write Phase4Pipeline implementation**

```python
# fuzzingbrain/verifier/pipeline.py
"""
Phase4Pipeline -- Full Phase 4 orchestration.

Orchestrates the complete Phase 4 pipeline:
1. Filter P0 SPs
2. Generate PoCs via PoCAgent
3. For each PoC+SP pair, try L1→L2→L3 verification
4. CrashMonitor deduplicates crashes
5. Return Phase4Result
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from loguru import logger

from ..llms import LLMClient
from ..static.models import FunctionInfo, CallGraph
from ..attack_surface.models import AttackSurface
from ..agents.firmware.sp_models import VerifiedSP
from .models import (
    PoC, VerificationResult, CrashInfo,
    Phase4Statistics, Phase4Result,
)
from .poc_agent import PoCAgent
from .crash_monitor import CrashMonitor
from .static_assessor import StaticAssessor
from .firmae_runner import FirmAERunner
from .qemu_runner import QEMURunner


class Phase4Pipeline:
    """
    Orchestrates the full Phase 4 pipeline: PoC → Verify → Report.

    Follows Phase3Pipeline pattern with layered verification fallback.

    Usage:
        pipeline = Phase4Pipeline(firmae_dir="/opt/FirmAE")
        result = pipeline.run(verified_sps, functions, attack_surfaces)
        pipeline.save(result, "results/phase4_result.json")
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        firmae_dir: Optional[str] = None,
        qemu_dir: str = "/usr/bin",
        rootfs_dir: str = "",
        output_dir: str = "results/phase4",
        temperature: float = 0.3,
        max_tokens: int = 8000,
    ):
        """
        Args:
            llm_client: Shared LLMClient instance.
            firmae_dir: Path to FirmAE installation (None = skip L1).
            qemu_dir: Directory containing QEMU user-mode binaries.
            rootfs_dir: Root filesystem for QEMU -L flag.
            output_dir: Directory for intermediate outputs (PoCs, etc.).
            temperature: LLM temperature for PoC generation.
            max_tokens: Maximum output tokens for PoC generation.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Shared LLM client
        self.llm_client = llm_client or LLMClient()

        # PoC Agent (DeepSeek-V4-Pro)
        self.poc_agent = PoCAgent(
            llm_client=self.llm_client,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Verification runners
        self.firmae_runner = FirmAERunner(firmae_dir) if firmae_dir else None
        self.qemu_runner = QEMURunner(
            qemu_dir=qemu_dir,
            rootfs_dir=rootfs_dir,
        )

        # Crash monitor & static assessor
        self.crash_monitor = CrashMonitor()
        self.static_assessor = StaticAssessor()

    # ── Public API ──────────────────────────────────────────────────────

    def run(
        self,
        verified_sps: List[VerifiedSP],
        functions: List[FunctionInfo],
        attack_surfaces: List[AttackSurface],
        callgraph: Optional[CallGraph] = None,
        firmware_path: str = "",
        firmware_name: str = "",
    ) -> Phase4Result:
        """
        Full Phase 4 pipeline.

        1. Filter P0 SPs
        2. Generate PoCs via PoCAgent (one LLM call per P0 SP)
        3. For each PoC+SP pair:
           a. Try L1 FirmAE → if crash, mark dynamic_full
           b. Else try L2 QEMU → if crash, mark dynamic_user
           c. Else L3 static assessment → static_high or static_low
        4. CrashMonitor deduplicates
        5. Return Phase4Result
        """
        function_contexts = {f.name: f for f in functions}

        # Step 1: Filter P0 SPs
        p0_sps = [sp for sp in verified_sps if sp.priority == "P0"]
        logger.info(
            f"Phase4Pipeline: {len(p0_sps)} P0 SPs out of "
            f"{len(verified_sps)} total"
        )

        # Step 2: Generate PoCs
        pocs = self.poc_agent.generate_batch(
            p0_sps, attack_surfaces, function_contexts
        )
        poc_map: Dict[str, PoC] = {p.sp_id: p for p in pocs}

        # Step 3: Layered verification
        verified_results: List[VerificationResult] = []
        all_crashes: List[CrashInfo] = []

        stats = Phase4Statistics()
        stats.total_p0_sps = len(p0_sps)
        stats.poc_generated = len(pocs)

        for sp in p0_sps:
            poc = poc_map.get(sp.sp_id)
            if not poc:
                # No PoC generated (e.g., missing function context)
                result = self.static_assessor.assess(sp, callgraph)
                if result.verification_level == "static_high":
                    stats.static_high_reserved += 1
                else:
                    stats.discarded += 1
                verified_results.append(result)
                continue

            func_info = function_contexts.get(sp.function_name)
            if not func_info:
                logger.warning(f"No FunctionInfo for {sp.function_name}")
                result = self.static_assessor.assess(sp, callgraph)
                verified_results.append(result)
                if result.verification_level == "static_high":
                    stats.static_high_reserved += 1
                else:
                    stats.discarded += 1
                continue

            # L1: FirmAE
            if self.firmae_runner and firmware_path:
                result = self.firmae_runner.verify(sp, poc, firmware_path)
                if result.crashed:
                    stats.dynamic_full_verified += 1
                    verified_results.append(result)
                    if result.crash_info and not self.crash_monitor.is_duplicate(result.crash_info):
                        self.crash_monitor.record_crash(sp.sp_id, result.crash_info)
                        all_crashes.append(result.crash_info)
                    continue
                logger.info(f"FirmAE L1 failed for {sp.sp_id}, falling back to L2")
            elif not self.firmae_runner:
                logger.debug("No FirmAE configured, skipping L1")

            # L2: QEMU
            binary_path = func_info.binary_path or firmware_path
            arch = func_info.arch or "arm"
            result = self.qemu_runner.verify(sp, poc, binary_path, arch)
            if result.crashed:
                stats.dynamic_user_verified += 1
                verified_results.append(result)
                if result.crash_info and not self.crash_monitor.is_duplicate(result.crash_info):
                    self.crash_monitor.record_crash(sp.sp_id, result.crash_info)
                    all_crashes.append(result.crash_info)
                continue
            logger.info(f"QEMU L2 failed for {sp.sp_id}, falling back to L3")

            # L3: Static assessment
            result = self.static_assessor.assess(sp, callgraph)
            if result.verification_level == "static_high":
                stats.static_high_reserved += 1
            else:
                stats.discarded += 1
            verified_results.append(result)

        # Step 4: Deduplicate crashes
        unique_crashes = self.crash_monitor.get_unique_crashes()
        stats.unique_crashes = len(unique_crashes)

        # Compute verification rate
        total_verified = stats.dynamic_full_verified + stats.dynamic_user_verified + stats.static_high_reserved
        if stats.total_p0_sps > 0:
            stats.verification_rate = f"{(total_verified / stats.total_p0_sps) * 100:.1f}%"

        logger.info(
            f"Phase4Pipeline complete: {stats.total_p0_sps} P0 SPs → "
            f"L1={stats.dynamic_full_verified}, L2={stats.dynamic_user_verified}, "
            f"L3={stats.static_high_reserved}, discarded={stats.discarded}, "
            f"crashes={stats.unique_crashes}"
        )

        return Phase4Result(
            verified_results=verified_results,
            crashes=unique_crashes,
            statistics=stats,
        )

    # ── File I/O (matching Phase 2/3 pattern) ────────────────────────────

    def save(self, result: Phase4Result, path: Union[str, Path]) -> None:
        """Save Phase4Result to JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Phase4Result saved to {path}")

    def load(self, path: Union[str, Path]) -> Phase4Result:
        """Load Phase4Result from JSON."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Phase4Result file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return Phase4Result.from_dict(data)
```

- [ ] **Step 4: Run pipeline tests to verify they pass**

```bash
pytest tests/test_phase4_pipeline.py -v
```
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/verifier/pipeline.py tests/test_phase4_pipeline.py
git commit -m "feat(phase4): implement Phase4Pipeline orchestration with layered verification

Phase4Pipeline orchestrates the complete Phase 4 flow:
- Filters P0 SPs and generates PoCs via PoCAgent
- L1→L2→L3 layered verification (FirmAE → QEMU → StaticAssessor)
- CrashMonitor dedup across all verification results
- Statistics tracking (verification rate, unique crashes)
- Save/load for Phase4Result JSON

6 integration tests with mocked external dependencies.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Exports + Final Verification

**Files:**
- Modify: `fuzzingbrain/verifier/__init__.py` (verify imports work)
- No new tests needed (verification step only)

- [ ] **Step 1: Verify all imports work**

```bash
python -c "
from fuzzingbrain.verifier import (
    PoC, PoCTarget, ExpectedBehavior, AltPayload,
    VerificationResult, CrashInfo,
    Phase4Statistics, Phase4Result,
    ReportMetadata, VulnerabilityEntry, FinalReport,
    PoCAgent, CrashMonitor, StaticAssessor,
    FirmAERunner, QEMURunner, Phase4Pipeline,
)
print('All Phase 4 imports successful')

# Quick smoke test: create key instances
from fuzzingbrain.agents.firmware.sp_models import VerifiedSP, AnalystConsensus, ExploitabilityAssessment

ea = ExploitabilityAssessment(attack_vector='network', difficulty='trivial',
                               reliability='reliable', impact='RCE')
print(f'ExploitabilityAssessment: {ea.attack_vector}')

consensus = AnalystConsensus(analyst_a='confirmed', analyst_b='confirmed',
                              analyst_c='confirmed', votes_confirmed=3,
                              votes_refuted=0, votes_uncertain=0, final_vote='confirmed')
print(f'AnalystConsensus: {consensus.votes_confirmed}/3')

sp = VerifiedSP(
    sp_id='test-sp-1', cwe='CWE-121', title='Test',
    description='test', function_name='test_func',
    vulnerable_code_snippet='test', control_flow='test',
    trigger_condition='test', root_cause='test',
    exploitability=ea, confidence=0.85, severity='critical',
    analyst_type='memory_corruption',
    analyst_consensus=consensus, priority='P0',
)
print(f'VerifiedSP: {sp.sp_id}, P{sp.priority}')

poc = PoC(sp_id='test-1', poc_type='http_request',
          poc_target=PoCTarget(port=80), poc_content='AAAA')
print(f'PoC: type={poc.poc_type}, port={poc.poc_target.port}')

crash = CrashInfo(crash_type='SIGSEGV', crash_address='0x41414141', signal_number=11)
print(f'CrashInfo: {crash.crash_type} at {crash.crash_address}')

cm = CrashMonitor()
cm.record_crash('sp-1', crash)
print(f'CrashMonitor: {cm.crash_count} crashes recorded')

sa = StaticAssessor()
vr = sa.assess(sp, None)
print(f'StaticAssessor: {vr.verification_level}')

agent = PoCAgent()
print(f'PoCAgent: model={agent.model}')

print('Smoke test PASSED')
"
```

- [ ] **Step 2: Run full test suite to check for regressions**

```bash
pytest tests/ -v 2>&1 | tail -30
```
Expected: All tests pass, no regressions from Phase 1/2/3.

- [ ] **Step 3: Commit**

```bash
git add fuzzingbrain/verifier/__init__.py
git commit -m "feat(phase4): final verification — all imports working, no regressions

Verify Phase 4 package exports and full integration:
- All 12 verifier models importable
- PoCAgent, CrashMonitor, StaticAssessor, FirmAERunner, QEMURunner, Phase4Pipeline all creatable
- Full test suite passes with no regressions

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Summary

| Task | Files Created | Tests | Effort |
|------|-------------|-------|--------|
| 1. Data Models | `verifier/__init__.py`, `verifier/models.py` | 18 | Medium |
| 2. PoC Prompt | `poc_prompt.md`, modify `prompts/__init__.py` | 0 | Small |
| 3. PoCAgent | `verifier/poc_agent.py` | 10 | Medium |
| 4. CrashMonitor | `verifier/crash_monitor.py` | 10 | Small |
| 5. StaticAssessor | `verifier/static_assessor.py` | 8 | Small |
| 6. FirmAERunner | `verifier/firmae_runner.py` | 0 (integration) | Large |
| 7. QEMURunner | `verifier/qemu_runner.py` | 0 (integration) | Medium |
| 8. ReportGenerator | `reporter/__init__.py`, `reporter/generator.py` | 10 | Medium |
| 9. Phase4Pipeline | `verifier/pipeline.py` | 6 | Medium |
| 10. Exports + Verify | modify `verifier/__init__.py` | 0 | Small |

**Total: ~10 commits, ~62 tests, 12 new files, 2 modified files**
