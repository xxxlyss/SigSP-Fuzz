"""
Data models for attack surface identification and direction planning.

Phase 2 outputs: AttackSurface (identified entry points for untrusted data)
and Direction (prioritized analysis groupings).
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Phase 2.1: Attack Surface models
# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    """Network port information associated with an attack surface."""

    port: int
    protocol_type: str = "TCP"          # TCP, UDP
    certainty: str = "inferred"          # confirmed, inferred

    def __post_init__(self):
        # Normalize LLM-generated protocol strings to canonical form
        _proto = self.protocol_type.upper()
        if "TCP" in _proto and "UDP" in _proto:
            self.protocol_type = "TCP"  # Default to TCP when both mentioned
        elif "TCP" in _proto:
            self.protocol_type = "TCP"
        elif "UDP" in _proto:
            self.protocol_type = "UDP"
        # Accept any value from LLM; just warn if unusual
        if self.certainty not in ("confirmed", "inferred"):
            self.certainty = "inferred"


@dataclass
class AttackSurface:
    """
    An identified attack surface — a code path where external, untrusted
    data enters the firmware.
    """

    name: str                            # Human-readable short name
    category: str                        # network_service, cgi_endpoint, protocol_parser,
                                         # auth_module, file_operation, command_execution, other
    entry_functions: List[str]           # Functions that receive external input
    description: str = ""                # Detailed description
    supporting_functions: List[str] = field(default_factory=list)
    protocol: str = "N/A"                # HTTP, Telnet, DNS, UPnP, SSH, Custom, N/A
    port_info: Optional[PortInfo] = None
    strings_evidence: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)

    VALID_CATEGORIES = {
        "network_service", "cgi_endpoint", "protocol_parser",
        "auth_module", "file_operation", "command_execution", "other",
    }

    def __post_init__(self):
        if self.category not in self.VALID_CATEGORIES:
            raise ValueError(
                f"Invalid attack surface category: {self.category}. "
                f"Must be one of: {self.VALID_CATEGORIES}"
            )

    @property
    def has_port(self) -> bool:
        """Whether this attack surface has known port information."""
        return self.port_info is not None

    @property
    def risk_count(self) -> int:
        """Number of identified risk types."""
        return len(self.risks)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AttackSurface":
        """Create from dict (with nested PortInfo handling)."""
        if d.get("port_info") is not None:
            d = dict(d)
            d["port_info"] = PortInfo(**d["port_info"])
        return cls(**d)


@dataclass
class AttackSurfaceSummary:
    """Summary of attack surface analysis."""

    total_attack_surfaces: int
    primary_exposure: str              # Brief assessment of most dangerous entry point
    secondary_exposures: List[str] = field(default_factory=list)


@dataclass
class AttackSurfaceResult:
    """Complete result of attack surface identification."""

    attack_surfaces: List[AttackSurface]
    summary: AttackSurfaceSummary

    @property
    def count(self) -> int:
        return len(self.attack_surfaces)

    @property
    def high_risk_surfaces(self) -> List[AttackSurface]:
        """Attack surfaces that are network-facing with high-risk indicators."""
        return [
            s for s in self.attack_surfaces
            if s.category in ("network_service", "cgi_endpoint", "protocol_parser")
            and s.risk_count > 0
        ]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AttackSurfaceResult":
        surfaces = [AttackSurface.from_dict(s) for s in d.get("attack_surfaces", [])]
        summary = AttackSurfaceSummary(**d.get("summary", {}))
        return cls(attack_surfaces=surfaces, summary=summary)


# ---------------------------------------------------------------------------
# Phase 2.2: Direction models
# ---------------------------------------------------------------------------

@dataclass
class Direction:
    """
    A logical partition of the attack surface for prioritized analysis.

    Each direction groups related functions with functional cohesion, assigned
    a priority 1-5 for analysis ordering.
    """

    name: str                            # Short descriptive name
    description: str                     # What this direction covers
    category: str                        # http_processing, protocol_parsing, auth_management,
                                         # file_handling, command_execution, network_service, other
    entry_functions: List[str]           # External entry points
    core_functions: List[str]            # High-priority functions to analyze
    big_pool: List[str]                  # All reachable functions in this direction
    primary_attack_types: List[str] = field(default_factory=list)
    secondary_attack_types: List[str] = field(default_factory=list)
    priority: int = 3                    # 1 (lowest) to 5 (highest)
    estimated_complexity: str = "medium" # high, medium, low
    rationale: str = ""                 # Why this priority and grouping

    VALID_CATEGORIES = {
        "http_processing", "protocol_parsing", "auth_management",
        "file_handling", "command_execution", "network_service", "other",
    }
    VALID_COMPLEXITIES = {"high", "medium", "low"}

    def __post_init__(self):
        if self.category not in self.VALID_CATEGORIES:
            raise ValueError(
                f"Invalid direction category: {self.category}. "
                f"Must be one of: {self.VALID_CATEGORIES}"
            )
        if self.priority < 1 or self.priority > 5:
            raise ValueError(f"Priority must be 1-5, got: {self.priority}")
        if self.estimated_complexity not in self.VALID_COMPLEXITIES:
            raise ValueError(
                f"Invalid complexity: {self.estimated_complexity}. "
                f"Must be one of: {self.VALID_COMPLEXITIES}"
            )

    @property
    def natural_key(self) -> str:
        """Natural key for dedup and ordering."""
        return self.name

    @property
    def is_high_priority(self) -> bool:
        """Whether this direction is priority 4 or 5."""
        return self.priority >= 4

    @property
    def core_count(self) -> int:
        """Number of core functions to analyze."""
        return len(self.core_functions)

    @property
    def pool_size(self) -> int:
        """Total size of the direction (all reachable functions)."""
        return len(self.big_pool)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Direction":
        return cls(**d)


@dataclass
class AnalysisOrder:
    """Recommended analysis order for directions."""

    recommended_sequence: List[str]       # Direction names in order
    rationale: str = ""                  # Why this order


@dataclass
class DirectionResult:
    """Complete result of direction planning."""

    directions: List[Direction]
    analysis_order: AnalysisOrder

    @property
    def count(self) -> int:
        return len(self.directions)

    @property
    def high_priority_directions(self) -> List[Direction]:
        """Directions with priority >= 4."""
        return [d for d in self.directions if d.is_high_priority]

    def get_by_name(self, name: str) -> Optional[Direction]:
        """Get a direction by name."""
        for d in self.directions:
            if d.name == name:
                return d
        return None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DirectionResult":
        directions = [Direction.from_dict(dd) for dd in d.get("directions", [])]
        order = AnalysisOrder(**d.get("analysis_order", {}))
        return cls(directions=directions, analysis_order=order)
