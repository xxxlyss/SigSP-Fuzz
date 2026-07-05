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
    path: str = ""
    method: str = "GET"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PoCTarget":
        return cls(**d)


@dataclass
class ExpectedBehavior:
    """Expected crash behavior from a PoC."""
    expected_crash_type: str = ""
    expected_register_state: str = ""
    success_indicator: str = ""

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
    """A constructed exploit trigger input for a specific SP."""
    sp_id: str
    poc_type: str
    poc_target: PoCTarget = field(default_factory=PoCTarget)
    poc_content: str = ""
    poc_content_hex: str = ""
    poc_explanation: str = ""
    expected_behavior: ExpectedBehavior = field(default_factory=ExpectedBehavior)
    alternate_payloads: List[AltPayload] = field(default_factory=list)

    VALID_POC_TYPES = {
        "http_request", "http_response", "http_post", "http_get",
        "udp_packet", "tcp_stream", "stdin_input", "other",
    }
    # Normalize LLM-generated variants to canonical types
    POC_TYPE_ALIASES = {
        "http_post": "http_request",
        "http_get": "http_request",
    }

    def __post_init__(self):
        # Normalize LLM-generated aliases (e.g. http_post → http_request)
        if self.poc_type in self.POC_TYPE_ALIASES:
            self.poc_type = self.POC_TYPE_ALIASES[self.poc_type]
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
    crash_type: str
    crash_address: str = ""
    register_state: Dict[str, str] = field(default_factory=dict)
    backtrace: List[str] = field(default_factory=list)
    signal_number: int = 0
    crash_signature: str = ""

    VALID_CRASH_TYPES = {"SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "heap_corruption", "unknown"}

    def __post_init__(self):
        if self.crash_type not in self.VALID_CRASH_TYPES:
            raise ValueError(
                f"Invalid crash_type: {self.crash_type}. "
                f"Must be one of: {self.VALID_CRASH_TYPES}"
            )
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
    verification_level: str
    crashed: bool
    crash_info: Optional[CrashInfo] = None
    output: str = ""
    error: str = ""

    VALID_LEVELS = {"dynamic_full", "dynamic_user", "static_high", "static_low", "not_verified"}

    def __post_init__(self):
        if self.verification_level not in self.VALID_LEVELS:
            raise ValueError(
                f"Invalid verification_level: {self.verification_level}. "
                f"Must be one of: {self.VALID_LEVELS}"
            )

    @property
    def is_confirmed(self) -> bool:
        return self.verification_level in ("dynamic_full", "dynamic_user")

    @property
    def is_reportable(self) -> bool:
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
    dynamic_full_verified: int = 0
    dynamic_user_verified: int = 0
    static_high_reserved: int = 0
    discarded: int = 0
    unique_crashes: int = 0
    verification_rate: str = ""

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
        return [r for r in self.verified_results if r.is_confirmed]

    @property
    def reportable_results(self) -> List[VerificationResult]:
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
    analysis_date: str = ""
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
    severity: str = ""
    priority: str = ""
    verification_level: str = ""
    exploitability: Optional[ExploitabilityAssessment] = None
    poc: Optional[PoC] = None
    crash_info: Optional[CrashInfo] = None
    fix_suggestion: str = ""

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"Invalid confidence: {self.confidence}. "
                f"Must be between 0.0 and 1.0 (inclusive)"
            )

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
    ground_truth_match: Optional[dict] = None  # Cross-reference results from FirmwareProfile

    @property
    def count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def confirmed_vulnerabilities(self) -> List[VulnerabilityEntry]:
        return [
            v for v in self.vulnerabilities
            if v.verification_level in ("dynamic_full", "dynamic_user", "static_high")
        ]

    def to_dict(self) -> dict:
        d = asdict(self)
        # ground_truth_match is already a plain dict
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FinalReport":
        metadata = ReportMetadata.from_dict(d.get("metadata", {}))
        entries = [VulnerabilityEntry.from_dict(e) for e in d.get("vulnerabilities", [])]
        stats = Phase4Statistics.from_dict(d.get("statistics", {}))
        return cls(
            metadata=metadata,
            vulnerabilities=entries,
            statistics=stats,
            ground_truth_match=d.get("ground_truth_match"),
        )
