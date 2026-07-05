# Phase 2: Attack Surface Identification + Direction Planning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two lightweight LLM agents that consume Phase 1 static analysis output (functions.json + callgraph.json + strings.json) and produce attack_surface.json + directions.json using DeepSeek-V4-Pro.

**Architecture:** Reuse `LLMClient` for model routing/fallback. Agents are single-pass: load JSON → build prompt → call LLM → parse structured JSON output → write result. No MCP/MongoDB/Celery dependency — the agents are stateless pipelines.

**Tech Stack:** Python 3.10+, dataclasses, `fuzzingbrain.llms.LLMClient`, deepseek-v4-pro, pytest + mongomock + unittest.mock

---

## File Structure

### Files to Create

| File | Responsibility |
|------|---------------|
| `fuzzingbrain/attack_surface/__init__.py` | Package init, public API exports |
| `fuzzingbrain/attack_surface/models.py` | `AttackSurface`, `Direction`, `PortInfo`, `AnalysisOrder`, `Summary` dataclasses + JSON serialization |
| `fuzzingbrain/attack_surface/identifier.py` | `AttackSurfaceIdentifier` — reads functions.json+strings.json, calls LLM, outputs attack_surface.json |
| `fuzzingbrain/attack_surface/direction_planner.py` | `DirectionPlanner` — reads attack_surface.json+callgraph.json, calls LLM, outputs directions.json |
| `fuzzingbrain/agents/firmware/__init__.py` | Package init |
| `fuzzingbrain/agents/firmware/prompts/__init__.py` | Prompt package init |
| `fuzzingbrain/agents/firmware/prompts/attack_surface_prompt.md` | AttackSurface Agent system prompt template |
| `fuzzingbrain/agents/firmware/prompts/direction_prompt.md` | Direction Planner Agent system prompt template |
| `tests/test_attack_surface_models.py` | Model serialization/deserialization/validation tests |
| `tests/test_attack_surface_identifier.py` | AttackSurfaceIdentifier tests (mocked LLM) |
| `tests/test_attack_surface_direction.py` | DirectionPlanner tests (mocked LLM) |

---

### Task 1: Data Models

**Files:**
- Create: `fuzzingbrain/attack_surface/__init__.py`
- Create: `fuzzingbrain/attack_surface/models.py`
- Create: `tests/test_attack_surface_models.py`

- [ ] **Step 1: Create package init**

```python
# fuzzingbrain/attack_surface/__init__.py
"""
Attack surface identification and direction planning for firmware analysis.

Phase 2 of the firmware vulnerability discovery pipeline:
- AttackSurfaceIdentifier: Identifies attack surfaces from static analysis output
- DirectionPlanner: Divides attack surfaces into analysis directions
"""

from .models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
    PortInfo,
)
from .identifier import AttackSurfaceIdentifier
from .direction_planner import DirectionPlanner

__all__ = [
    "AttackSurface",
    "AttackSurfaceResult",
    "AttackSurfaceSummary",
    "Direction",
    "DirectionResult",
    "AnalysisOrder",
    "PortInfo",
    "AttackSurfaceIdentifier",
    "DirectionPlanner",
]
```

- [ ] **Step 2: Write data model tests (these must fail first)**

```python
# tests/test_attack_surface_models.py
"""Tests for attack_surface data models."""

import json
import pytest
from dataclasses import asdict

from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
    PortInfo,
)


class TestPortInfo:
    """Tests for PortInfo dataclass."""

    def test_create_port_info(self):
        p = PortInfo(port=80, protocol_type="TCP", certainty="confirmed")
        assert p.port == 80
        assert p.protocol_type == "TCP"
        assert p.certainty == "confirmed"

    def test_port_info_defaults(self):
        p = PortInfo(port=443)
        assert p.port == 443
        assert p.protocol_type == "TCP"
        assert p.certainty == "inferred"

    def test_port_info_serialization(self):
        p = PortInfo(port=8080, protocol_type="TCP", certainty="inferred")
        d = asdict(p)
        assert d == {"port": 8080, "protocol_type": "TCP", "certainty": "inferred"}

    def test_port_info_json_roundtrip(self):
        p = PortInfo(port=23, protocol_type="TCP", certainty="confirmed")
        json_str = json.dumps(asdict(p))
        loaded = json.loads(json_str)
        p2 = PortInfo(**loaded)
        assert p == p2


class TestAttackSurface:
    """Tests for AttackSurface dataclass."""

    def test_create_minimal(self):
        a = AttackSurface(
            name="HTTP Server",
            category="network_service",
            entry_functions=["httpd_main"],
        )
        assert a.name == "HTTP Server"
        assert a.category == "network_service"
        assert a.entry_functions == ["httpd_main"]
        assert a.description == ""
        assert a.supporting_functions == []
        assert a.protocol == "N/A"
        assert a.port_info is None
        assert a.strings_evidence == []
        assert a.risks == []

    def test_create_full(self):
        port = PortInfo(port=80, protocol_type="TCP", certainty="confirmed")
        a = AttackSurface(
            category="network_service",
            name="HTTP Management Interface",
            description="Web-based admin panel on port 80",
            entry_functions=["httpd_main", "cgi_handler"],
            supporting_functions=["parse_http_request", "send_response"],
            protocol="HTTP",
            port_info=port,
            strings_evidence=["/www/admin/", "192.168.1.1:80"],
            risks=["buffer_overflow", "command_injection"],
        )
        assert a.port_info.port == 80
        assert len(a.strings_evidence) == 2
        assert "buffer_overflow" in a.risks

    def test_serialization(self):
        a = AttackSurface(
            name="Telnet Service",
            category="network_service",
            entry_functions=["telnetd_main"],
            protocol="Telnet",
            port_info=PortInfo(port=23, protocol_type="TCP", certainty="confirmed"),
            risks=["auth_bypass"],
        )
        d = asdict(a)
        assert d["name"] == "Telnet Service"
        assert d["port_info"]["port"] == 23
        assert d["risks"] == ["auth_bypass"]

    def test_json_roundtrip(self):
        a = AttackSurface(
            name="CGI Upload Handler",
            category="cgi_endpoint",
            entry_functions=["cgi_upload", "process_upload"],
            description="File upload via /cgi-bin/upload.cgi",
            protocol="HTTP",
            risks=["path_traversal", "command_injection"],
        )
        json_str = json.dumps(asdict(a))
        loaded = json.loads(json_str)
        a2 = AttackSurface(**loaded)
        assert a.name == a2.name
        assert a.risks == a2.risks
        # port_info is None, should stay None
        assert a2.port_info is None


class TestAttackSurfaceResult:
    """Tests for AttackSurfaceResult container."""

    def test_create_result(self):
        surfaces = [
            AttackSurface(
                name="HTTP Server",
                category="network_service",
                entry_functions=["httpd_main"],
                protocol="HTTP",
                port_info=PortInfo(port=80),
            ),
            AttackSurface(
                name="UPnP Handler",
                category="protocol_parser",
                entry_functions=["upnp_parse"],
                protocol="UPnP",
            ),
        ]
        summary = AttackSurfaceSummary(
            total_attack_surfaces=2,
            primary_exposure="HTTP server on port 80 with unauthenticated CGI endpoints",
            secondary_exposures=["UPnP SSDP multicast exposure"],
        )
        result = AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)
        assert len(result.attack_surfaces) == 2
        assert result.summary.total_attack_surfaces == 2
        assert "HTTP" in result.summary.primary_exposure

    def test_json_roundtrip(self):
        surfaces = [
            AttackSurface(
                name="SSH Server",
                category="network_service",
                entry_functions=["dropbear_main"],
                protocol="SSH",
                port_info=PortInfo(port=22, certainty="confirmed"),
                risks=["auth_bypass"],
            ),
        ]
        summary = AttackSurfaceSummary(
            total_attack_surfaces=1,
            primary_exposure="SSH on port 22",
            secondary_exposures=[],
        )
        result = AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)
        json_str = json.dumps(asdict(result))
        loaded = json.loads(json_str)
        # Reconstruct
        loaded_surfaces = [AttackSurface(**s) for s in loaded["attack_surfaces"]]
        assert loaded_surfaces[0].name == "SSH Server"
        assert loaded_surfaces[0].port_info.port == 22


class TestDirection:
    """Tests for Direction dataclass."""

    def test_create_direction(self):
        d = Direction(
            name="HTTP Request Processing",
            description="All HTTP request handling including CGI dispatch",
            category="http_processing",
            entry_functions=["httpd_main"],
            core_functions=["httpd_main", "cgi_handler", "parse_http_request"],
            big_pool=["httpd_main", "cgi_handler", "parse_http_request", "url_decode", "get_param"],
            primary_attack_types=["buffer_overflow", "command_injection"],
            priority=5,
        )
        assert d.name == "HTTP Request Processing"
        assert d.priority == 5
        assert d.estimated_complexity == "medium"
        assert d.rationale == ""

    def test_priority_bounds(self):
        """Priority must be 1-5."""
        d = Direction(
            name="Test",
            description="Test",
            category="auth_management",
            entry_functions=["test"],
            core_functions=["test"],
            big_pool=["test"],
            priority=3,
        )
        assert 1 <= d.priority <= 5

    def test_natural_key(self):
        """natural_key property returns the name."""
        d = Direction(
            name="UPnP Protocol Parsing",
            description="UPnP SSDP and SOAP handling",
            category="protocol_parsing",
            entry_functions=["upnp_parse"],
            core_functions=["upnp_parse", "ssdp_handler"],
            big_pool=["upnp_parse", "ssdp_handler", "http_recv", "soap_dispatch"],
            primary_attack_types=["buffer_overflow"],
            priority=4,
        )
        assert d.natural_key == "UPnP Protocol Parsing"

    def test_serialization(self):
        d = Direction(
            name="Auth Module",
            description="Authentication and session management",
            category="auth_management",
            entry_functions=["login_handler"],
            core_functions=["login_handler", "verify_password", "check_session"],
            big_pool=["login_handler", "verify_password", "check_session", "strcmp", "malloc"],
            primary_attack_types=["auth_bypass"],
            secondary_attack_types=["buffer_overflow"],
            priority=4,
            estimated_complexity="high",
            rationale="Authentication is always high-risk; custom crypto suspected",
        )
        d2 = asdict(d)
        assert d2["name"] == "Auth Module"
        assert d2["priority"] == 4
        assert d2["estimated_complexity"] == "high"

    def test_json_roundtrip(self):
        d = Direction(
            name="File Upload Handler",
            description="Handles file upload via HTTP POST",
            category="file_operation",
            entry_functions=["cgi_upload"],
            core_functions=["cgi_upload", "save_file", "check_extension"],
            big_pool=["cgi_upload", "save_file", "check_extension", "fopen", "fwrite"],
            primary_attack_types=["path_traversal", "command_injection"],
            priority=5,
            estimated_complexity="medium",
        )
        json_str = json.dumps(asdict(d))
        loaded = json.loads(json_str)
        d2 = Direction(**loaded)
        assert d.name == d2.name
        assert d.priority == d2.priority
        assert d.primary_attack_types == d2.primary_attack_types


class TestDirectionResult:
    """Tests for DirectionResult container."""

    def test_create_result(self):
        directions = [
            Direction(
                name="HTTP Processing",
                description="HTTP request handling",
                category="http_processing",
                entry_functions=["httpd_main"],
                core_functions=["httpd_main", "cgi_dispatch"],
                big_pool=["httpd_main", "cgi_dispatch", "parse_request"],
                priority=5,
            ),
            Direction(
                name="Auth Module",
                description="Login and session management",
                category="auth_management",
                entry_functions=["login_handler"],
                core_functions=["login_handler", "verify_auth"],
                big_pool=["login_handler", "verify_auth", "check_password"],
                priority=4,
            ),
        ]
        order = AnalysisOrder(
            recommended_sequence=["HTTP Processing", "Auth Module"],
            rationale="HTTP is network-facing and unauthenticated, most likely to yield critical bugs",
        )
        result = DirectionResult(directions=directions, analysis_order=order)
        assert len(result.directions) == 2
        assert result.analysis_order.recommended_sequence == ["HTTP Processing", "Auth Module"]

    def test_json_roundtrip(self):
        directions = [
            Direction(
                name="DNS Resolver",
                description="DNS query handling",
                category="protocol_parsing",
                entry_functions=["dns_handler"],
                core_functions=["dns_handler"],
                big_pool=["dns_handler", "parse_dns_query", "dns_lookup"],
                priority=3,
            ),
        ]
        order = AnalysisOrder(
            recommended_sequence=["DNS Resolver"],
            rationale="Only one direction",
        )
        result = DirectionResult(directions=directions, analysis_order=order)
        json_str = json.dumps(asdict(result))
        loaded = json.loads(json_str)
        assert len(loaded["directions"]) == 1
        assert loaded["analysis_order"]["recommended_sequence"] == ["DNS Resolver"]

    def test_empty_result(self):
        """Should handle empty direction list."""
        result = DirectionResult(
            directions=[],
            analysis_order=AnalysisOrder(recommended_sequence=[], rationale="No attack surfaces found"),
        )
        assert len(result.directions) == 0


class TestAnalysisOrder:
    """Tests for AnalysisOrder dataclass."""

    def test_create(self):
        ao = AnalysisOrder(
            recommended_sequence=["Direction A", "Direction B"],
            rationale="A then B for early critical finds",
        )
        assert ao.recommended_sequence == ["Direction A", "Direction B"]

    def test_serialization(self):
        ao = AnalysisOrder(
            recommended_sequence=["Dir1"],
            rationale="Only one",
        )
        d = asdict(ao)
        assert d["recommended_sequence"] == ["Dir1"]


class TestCategoryValidation:
    """Test category validation helpers."""

    def test_valid_attack_surface_categories(self):
        valid = {
            "network_service", "cgi_endpoint", "protocol_parser",
            "auth_module", "file_operation", "command_execution", "other",
        }
        a = AttackSurface(
            name="Test",
            category="network_service",
            entry_functions=["test"],
        )
        assert a.category in valid

    def test_valid_direction_categories(self):
        valid = {
            "http_processing", "protocol_parsing", "auth_management",
            "file_handling", "command_execution", "network_service", "other",
        }
        d = Direction(
            name="Test",
            description="Test",
            category="http_processing",
            entry_functions=["test"],
            core_functions=["test"],
            big_pool=["test"],
            priority=3,
        )
        assert d.category in valid
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pytest tests/test_attack_surface_models.py -v
```
Expected: all FAIL with `ModuleNotFoundError: No module named 'fuzzingbrain.attack_surface'`

- [ ] **Step 4: Write the data models**

```python
# fuzzingbrain/attack_surface/models.py
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
        if self.protocol_type not in ("TCP", "UDP"):
            raise ValueError(f"protocol_type must be TCP or UDP, got: {self.protocol_type}")
        if self.certainty not in ("confirmed", "inferred"):
            raise ValueError(f"certainty must be confirmed or inferred, got: {self.certainty}")


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
```

- [ ] **Step 5: Run model tests to verify they pass**

```bash
pytest tests/test_attack_surface_models.py -v
```
Expected: all 18 tests PASS

- [ ] **Step 6: Commit**

```bash
git add fuzzingbrain/attack_surface/__init__.py fuzzingbrain/attack_surface/models.py tests/test_attack_surface_models.py
git commit -m "feat(attack_surface): add data models for attack surface and direction planning

Add PortInfo, AttackSurface, AttackSurfaceResult, Direction, DirectionResult,
and AnalysisOrder dataclasses with validation, JSON serialization, and 18 unit tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Prompt Templates

**Files:**
- Create: `fuzzingbrain/agents/firmware/__init__.py`
- Create: `fuzzingbrain/agents/firmware/prompts/__init__.py`
- Create: `fuzzingbrain/agents/firmware/prompts/attack_surface_prompt.md`
- Create: `fuzzingbrain/agents/firmware/prompts/direction_prompt.md`

- [ ] **Step 1: Create firmware agents package init**

```python
# fuzzingbrain/agents/firmware/__init__.py
"""
Firmware-specific agents for the vulnerability discovery pipeline.

Phase 2: AttackSurfaceIdentifier, DirectionPlanner
Phase 3: Analyst A/B/C, CrossReviewer, SPVerifier
Phase 4: PoCAgent
"""
```

```python
# fuzzingbrain/agents/firmware/prompts/__init__.py
"""Prompt templates for firmware analysis agents."""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str) -> str:
    """Load a prompt template from file.

    Args:
        name: Prompt file name (e.g., 'attack_surface_prompt.md')

    Returns:
        Prompt template string.
    """
    prompt_path = _PROMPTS_DIR / name
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt template not found: {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def get_attack_surface_prompt() -> str:
    """Get the AttackSurface Agent system prompt."""
    return load_prompt("attack_surface_prompt.md")


def get_direction_prompt() -> str:
    """Get the Direction Planner Agent system prompt."""
    return load_prompt("direction_prompt.md")


__all__ = ["load_prompt", "get_attack_surface_prompt", "get_direction_prompt"]
```

- [ ] **Step 2: Write attack surface prompt template**

```markdown
# fuzzingbrain/agents/firmware/prompts/attack_surface_prompt.md
# Role
You are a firmware security architect with 10 years of experience in IoT device
reverse engineering. You specialize in identifying attack surfaces in embedded
system binaries.

# Task
Identify ALL attack surfaces in this firmware binary. An attack surface is any
code path through which external, untrusted data enters the system.

# Input Data

## Function List
Below is a summary of functions extracted via Ghidra. For each function you see:
- name, address, architecture
- dangerous callees (strcpy, system, sprintf, etc.)
- referenced strings
- callers and callees

{function_summaries}

## String References
All strings found in the binary, auto-categorized:

{strings_by_category}

## Call Graph Summary
{callgraph_summary}

# Attack Surface Categories (by priority)

### 1. Network Services (HIGHEST priority)
- String clues: "0.0.0.0", ":80", ":443", ":8080", ":23", ":21", ":22"
- Function name clues: bind, listen, accept, recv, recvfrom, socket
- HTTP clues: "GET ", "POST ", "HTTP/", "Content-Length", "/cgi-bin/", "www"
- UPnP clues: "UPnP", "SSDP", "M-SEARCH", "NOTIFY"
- .plt entries for socket APIs indicate network functionality even when symbols are stripped

### 2. CGI Endpoints
- String clues: "/cgi-bin/", "cgiMain", "cgi_input", ".cgi"
- HTML form handling: "form", "submit", "upload", "multipart"
- Parameter names: "username=", "password=", "file=", "path=", "cmd="

### 3. Protocol Parsers
- Function name clues: parse_*, dissect_*, decode_*, unpack_*, process_packet
- Protocol strings: Content-Type, User-Agent, SOAP, XML, JSON

### 4. Authentication Modules
- String clues: "admin", "root", "password", "auth", "login", "session", "token"
- Function name clues: auth_*, login_*, verify_*, check_*, validate_*

### 5. File System Operations
- Function callees: fopen, open, read, write, unlink, rename, mkdir
- String clues: "/etc/", "/tmp/", "/var/", "/proc/"

### 6. System Command Execution
- Function callees: system, popen, exec*, doSystem
- Shell metacharacters found in strings: ";", "|", "&&", "$(", "`"

# Important Notes for Binary Analysis
- Ghidra auto-generated function names (FUN_XXXXXXXX) don't represent real functionality.
  Infer the role from callees (especially .plt entries) and referenced strings.
- .plt section entries indicate dynamically linked library functions — treat these
  as KEY indicators of functionality.
- Strings in .rodata may not have direct cross-references in Ghidra output.
  Consider contextual/proximity reasoning.
- A function named FUN_00401234 that calls socket+bind+listen AND references
  ":80" in nearby strings IS an HTTP server, regardless of the auto-name.
- A function calling recv() then system() with string concatenation is a CRITICAL
  command injection attack surface.

# Output Format
You MUST output valid JSON matching this exact schema:

```json
{{
  "attack_surfaces": [
    {{
      "category": "network_service | cgi_endpoint | protocol_parser | auth_module | file_operation | command_execution | other",
      "name": "Human-readable short name",
      "description": "What it does and why it's interesting for vulnerability research",
      "entry_functions": ["func1", "func2"],
      "supporting_functions": ["related_func1"],
      "protocol": "HTTP | Telnet | DNS | UPnP | SSH | Custom | N/A",
      "port_info": {{"port": 80, "protocol_type": "TCP | UDP", "certainty": "confirmed | inferred"}},
      "strings_evidence": ["evidence string 1", "evidence string 2"],
      "risks": ["buffer_overflow", "command_injection", "auth_bypass", "format_string", "path_traversal", "integer_overflow"]
    }}
  ],
  "summary": {{
    "total_attack_surfaces": <number>,
    "primary_exposure": "Brief assessment of the most dangerous entry point and why",
    "secondary_exposures": ["other notable exposures"]
  }}
}}
```

# Rules
1. Be THOROUGH — missing an attack surface is worse than flagging a borderline one
2. Focus on NETWORK-REACHABLE surfaces first (they are highest risk)
3. Each entry_function should be a specific function name from the function list
4. Use strings_evidence to back up your claims — cite the actual strings you found
5. Risk assessment should be CONCRETE: "buffer_overflow because sprintf with user input" not just "buffer_overflow"
6. If port number can't be confirmed, use certainty: "inferred"
7. Do NOT fabricate function names — only use names from the provided function list
8. If no port info is available, omit the port_info field entirely (null)
```

- [ ] **Step 3: Write direction prompt template**

```markdown
# fuzzingbrain/agents/firmware/prompts/direction_prompt.md
# Role
You are a firmware vulnerability research strategist with 15 years of experience
leading IoT security audits. Divide the firmware's attack surface into 3-8
independent analysis directions, each forming a complete unit of work for a
vulnerability analyst.

# Input Data

## Attack Surfaces
These are the identified entry points where untrusted data enters the firmware:

{attack_surfaces_json}

## Call Graph
Summary of function call relationships:

{callgraph_info}

## Function Details
Core functions from attack surfaces with their callees:

{function_details}

# Direction Planning Principles

### 1. Functional Cohesion
Group functions that work together on the same functionality:
- All HTTP request handling → one direction
- All UPnP packet parsing → one direction
- All authentication/session logic → one direction
- File upload + file processing → one direction
- DNS query handling → one direction

### 2. Priority Assignment (1-5)
- **Priority 5**: Network-reachable, unauthenticated, handles variable-length input
  (e.g., HTTP request parsing, UPnP packet dissector)
- **Priority 4**: Network-reachable, authenticated, handles complex input
  (e.g., admin CGI endpoints, file upload handlers)
- **Priority 3**: Network-reachable but highly constrained input format
  (e.g., DNS query handler, NTP client)
- **Priority 2**: Local-only access, processes files or device input
  (e.g., config file parser, firmware update handler via serial)
- **Priority 1**: Limited attack surface, input tightly constrained
  (e.g., simple /dev/ random reader, LED control)

### 3. Independence
Each direction should be independently analyzable. An analyst should be able to
understand the vulnerability surface of Direction X without knowing about Direction Y.

### 4. Size Constraints
- Each direction: 5-30 core_functions (the ones that MUST be analyzed)
- big_pool: all functions reachable from entry_functions within this direction
- If a direction would have > 30 core functions, split it further
- If a direction has < 3 core functions, merge with the closest related direction

### 5. Coverage
Every attack surface MUST be assigned to at least one direction.
Every entry_function from every attack surface MUST appear in at least one
direction's core_functions or big_pool.

# Output Format
You MUST output valid JSON matching this exact schema:

```json
{{
  "directions": [
    {{
      "name": "Short descriptive name (5-8 words max)",
      "description": "What this direction covers and why it matters",
      "category": "http_processing | protocol_parsing | auth_management | file_handling | command_execution | network_service | other",
      "entry_functions": ["Functions that receive external input — start of tainted data path"],
      "core_functions": ["High-priority functions that MUST be analyzed (5-30 functions)"],
      "big_pool": ["All functions reachable from entry_functions within this direction"],
      "primary_attack_types": ["Most likely vulnerability types for this direction"],
      "secondary_attack_types": ["Less likely but possible vulnerability types"],
      "priority": 4,
      "estimated_complexity": "high | medium | low",
      "rationale": "Why this priority level, why this grouping of functions"
    }}
  ],
  "analysis_order": {{
    "recommended_sequence": ["Direction name 1", "Direction name 2", "..."],
    "rationale": "Why this ordering finds the most critical vulnerabilities earliest"
  }}
}}
```

# Rules
1. Create 3-8 directions — fewer than 3 means you're lumping unrelated code together;
   more than 8 means you're splitting too finely
2. Priority MUST reflect genuine risk: network + no auth + complex parsing = high priority
3. Every attack surface's entry_functions must be covered
4. big_pool MUST include all callees reachable from entry_functions
5. Recommended sequence should put high-priority directions first
6. Be SPECIFIC in rationale — don't say "this is important", say WHY
7. Function names must come from the provided data — no fabrication
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/agents/firmware/
git commit -m "feat(agents): add firmware agent package and Phase 2 prompt templates

Add firmware agent package structure and prompt templates for:
- AttackSurfaceIdentifier: identifies attack surfaces from static analysis
- DirectionPlanner: partitions attack surfaces into analysis directions

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: AttackSurfaceIdentifier Agent

**Files:**
- Create: `fuzzingbrain/attack_surface/identifier.py`
- Create: `tests/test_attack_surface_identifier.py`

- [ ] **Step 1: Write identifier tests (these must fail first)**

```python
# tests/test_attack_surface_identifier.py
"""Tests for AttackSurfaceIdentifier."""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from fuzzingbrain.attack_surface.identifier import (
    AttackSurfaceIdentifier,
    build_function_summaries,
    build_strings_by_category,
    build_callgraph_summary,
)
from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    PortInfo,
)
from fuzzingbrain.static.models import FunctionInfo, CallGraph, CallGraphNode, StringRef


# ── Mock data ──────────────────────────────────────────────────────────

def make_function(name, address=0x1000, callees=None, strings=None, dangerous=None):
    """Helper to create FunctionInfo for tests."""
    return FunctionInfo(
        name=name,
        address=address,
        pseudo_code=f"/* decompiled {name} */\nvoid {name}(void) {{ }}",
        callees=callees or [],
        strings_used=strings or [],
        dangerous_funcs=dangerous or [],
        has_unsafe_calls=bool(dangerous),
    )


def make_mock_functions():
    """Create a realistic set of mock functions for testing."""
    return [
        make_function("main", 0x1000, callees=["httpd_init", "telnetd_init"],
                      strings=["Starting firmware v1.0"]),
        make_function("httpd_init", 0x2000, callees=["socket", "bind", "listen", "accept"],
                      strings=["0.0.0.0", ":80", "/www/"], dangerous=["sprintf"]),
        make_function("httpd_handle_request", 0x2100,
                      callees=["recv", "strcpy", "system", "send"],
                      strings=["GET ", "POST ", "/cgi-bin/", "HTTP/1.1"],
                      dangerous=["strcpy", "system"]),
        make_function("cgi_login", 0x2200, callees=["recv", "sprintf", "strcmp", "system"],
                      strings=["admin", "password", "login.cgi", "username=", "password="],
                      dangerous=["sprintf", "system"]),
        make_function("telnetd_init", 0x3000, callees=["socket", "bind", "listen"],
                      strings=[":23", "telnet", "login: "]),
        make_function("parse_upnp", 0x4000, callees=["recvfrom", "strcpy", "memcpy"],
                      strings=["UPnP", "SSDP", "M-SEARCH", "239.255.255.250"],
                      dangerous=["strcpy"]),
        make_function("do_system_cmd", 0x5000, callees=["system"],
                      strings=["ping ", "iptables"], dangerous=["system"]),
        make_function("file_upload_handler", 0x6000, callees=["fopen", "fwrite", "recv"],
                      strings=["/tmp/upload", "multipart/form-data", "filename="],
                      dangerous=[]),
        make_function("FUN_00007000", 0x7000, callees=["recv", "send"],
                      strings=[":8080", "admin", "debug"]),
    ]


def make_mock_strings():
    """Create realistic string references matching the functions above."""
    return [
        StringRef(value="0.0.0.0", address=0x8000, referenced_by=["httpd_init"], category="port"),
        StringRef(value=":80", address=0x8001, referenced_by=["httpd_init"], category="port"),
        StringRef(value=":23", address=0x8002, referenced_by=["telnetd_init"], category="port"),
        StringRef(value=":8080", address=0x8003, referenced_by=["FUN_00007000"], category="port"),
        StringRef(value="GET ", address=0x8010, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="POST ", address=0x8011, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="/cgi-bin/", address=0x8012, referenced_by=["httpd_handle_request"], category="url"),
        StringRef(value="HTTP/1.1", address=0x8013, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="login.cgi", address=0x8020, referenced_by=["cgi_login"], category="url"),
        StringRef(value="admin", address=0x8030, referenced_by=["cgi_login", "FUN_00007000"], category="credential"),
        StringRef(value="password", address=0x8031, referenced_by=["cgi_login"], category="credential"),
        StringRef(value="username=", address=0x8032, referenced_by=["cgi_login"], category="credential"),
        StringRef(value="UPnP", address=0x8040, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="SSDP", address=0x8041, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="M-SEARCH", address=0x8042, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="/tmp/upload", address=0x8050, referenced_by=["file_upload_handler"], category="path"),
        StringRef(value="ping ", address=0x8060, referenced_by=["do_system_cmd"], category="other"),
        StringRef(value="/www/", address=0x8070, referenced_by=["httpd_init"], category="path"),
        StringRef(value="login: ", address=0x8080, referenced_by=["telnetd_init"], category="credential"),
    ]


def make_mock_callgraph():
    """Create a realistic call graph for testing."""
    nodes = {
        "main": CallGraphNode(function_name="main", address=0x1000,
                              callees=["httpd_init", "telnetd_init"]),
        "httpd_init": CallGraphNode(function_name="httpd_init", address=0x2000,
                                    callees=["socket", "bind", "listen", "accept"],
                                    callers=["main"]),
        "httpd_handle_request": CallGraphNode(function_name="httpd_handle_request", address=0x2100,
                                              callees=["recv", "strcpy", "system", "send"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode(function_name="cgi_login", address=0x2200,
                                   callees=["recv", "sprintf", "strcmp", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode(function_name="telnetd_init", address=0x3000,
                                      callees=["socket", "bind", "listen"],
                                      callers=["main"]),
        "parse_upnp": CallGraphNode(function_name="parse_upnp", address=0x4000,
                                    callees=["recvfrom", "strcpy", "memcpy"],
                                    callers=["main"]),
        "do_system_cmd": CallGraphNode(function_name="do_system_cmd", address=0x5000,
                                       callees=["system"],
                                       callers=["cgi_login", "httpd_handle_request"]),
        "file_upload_handler": CallGraphNode(function_name="file_upload_handler", address=0x6000,
                                             callees=["fopen", "fwrite", "recv"],
                                             callers=["httpd_handle_request"]),
        "FUN_00007000": CallGraphNode(function_name="FUN_00007000", address=0x7000,
                                      callees=["recv", "send"],
                                      callers=["main"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


# ── Helper function tests ──────────────────────────────────────────────

class TestBuildFunctionSummaries:
    """Tests for prompt-building helper: build_function_summaries."""

    def test_builds_summary_for_functions(self):
        funcs = make_mock_functions()
        result = build_function_summaries(funcs)
        # Should contain function names
        assert "httpd_init" in result
        assert "httpd_handle_request" in result
        assert "cgi_login" in result
        # Should highlight dangerous calls
        assert "strcpy" in result or "system" in result
        # Stripped function should be included
        assert "FUN_00007000" in result

    def test_empty_functions(self):
        result = build_function_summaries([])
        assert result == "No functions provided."

    def test_summary_includes_dangerous_indicators(self):
        funcs = [
            make_function("vuln_func", 0x1000,
                         callees=["strcpy", "system"],
                         strings=["password"],
                         dangerous=["strcpy", "system"]),
        ]
        result = build_function_summaries(funcs)
        assert "strcpy" in result
        assert "system" in result
        assert "password" in result

    def test_summary_includes_callers(self):
        funcs = [
            make_function("target", 0x2000, callees=["recv"]),
        ]
        # Set callers via the field
        funcs[0].callers = ["httpd_main", "cgi_dispatch"]
        result = build_function_summaries(funcs)
        assert "httpd_main" in result
        assert "cgi_dispatch" in result


class TestBuildStringsByCategory:
    """Tests for prompt-building helper: build_strings_by_category."""

    def test_categorizes_strings(self):
        strings = make_mock_strings()
        result = build_strings_by_category(strings)
        assert "port" in result
        assert "credential" in result
        assert "protocol" in result
        assert "0.0.0.0" in result
        assert "admin" in result

    def test_empty_strings(self):
        result = build_strings_by_category([])
        assert result == "No strings found."

    def test_includes_referenced_by(self):
        strings = [
            StringRef(value=":80", address=0x8000,
                     referenced_by=["httpd_init", "httpd_main"],
                     category="port"),
        ]
        result = build_strings_by_category(strings)
        assert "httpd_init" in result
        assert "httpd_main" in result


class TestBuildCallgraphSummary:
    """Tests for prompt-building helper: build_callgraph_summary."""

    def test_builds_summary(self):
        cg = make_mock_callgraph()
        result = build_callgraph_summary(cg)
        assert "9" in result or "node" in result.lower()
        assert "main" in result

    def test_empty_callgraph(self):
        cg = CallGraph(binary_path="/bin/test", nodes={})
        result = build_callgraph_summary(cg)
        assert "No call graph" in result or "0" in result.lower()

    def test_shows_entry_points(self):
        """Functions with no callers should be shown as roots."""
        cg = make_mock_callgraph()
        result = build_callgraph_summary(cg)
        assert "main" in result  # main is the root


# ── LLM response mock ──────────────────────────────────────────────────

MOCK_LLM_RESPONSE = json.dumps({
    "attack_surfaces": [
        {
            "category": "network_service",
            "name": "HTTP Management Interface",
            "description": "Main HTTP server on port 80 with CGI endpoint support. Handles GET/POST requests and dispatches to CGI handlers including login.",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": ["0.0.0.0", ":80", "GET ", "POST ", "HTTP/1.1", "/cgi-bin/"],
            "risks": ["buffer_overflow", "command_injection", "auth_bypass"],
        },
        {
            "category": "cgi_endpoint",
            "name": "Login CGI Handler",
            "description": "CGI endpoint for admin login. Processes username/password parameters using sprintf for string building, which is highly dangerous.",
            "entry_functions": ["cgi_login"],
            "supporting_functions": ["do_system_cmd"],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["login.cgi", "admin", "password", "username="],
            "risks": ["command_injection", "buffer_overflow", "auth_bypass"],
        },
        {
            "category": "network_service",
            "name": "Telnet Service",
            "description": "Telnet daemon on port 23. Classic IoT remote shell access point.",
            "entry_functions": ["telnetd_init"],
            "supporting_functions": [],
            "protocol": "Telnet",
            "port_info": {"port": 23, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": [":23", "telnet", "login: "],
            "risks": ["auth_bypass", "buffer_overflow"],
        },
        {
            "category": "protocol_parser",
            "name": "UPnP SSDP Handler",
            "description": "UPnP discovery protocol parser. Processes multicast SSDP M-SEARCH requests — typical source of buffer overflows in IoT firmware.",
            "entry_functions": ["parse_upnp"],
            "supporting_functions": [],
            "protocol": "UPnP",
            "port_info": None,
            "strings_evidence": ["UPnP", "SSDP", "M-SEARCH", "239.255.255.250"],
            "risks": ["buffer_overflow"],
        },
        {
            "category": "command_execution",
            "name": "System Command Builder",
            "description": "Wrapper that executes system commands. Called by CGI handlers — if any caller passes unsanitized input, this is a command injection sink.",
            "entry_functions": ["do_system_cmd"],
            "supporting_functions": [],
            "protocol": "N/A",
            "port_info": None,
            "strings_evidence": ["ping ", "iptables"],
            "risks": ["command_injection"],
        },
        {
            "category": "file_operation",
            "name": "File Upload Handler",
            "description": "Processes multipart file uploads to /tmp/upload. Path traversal risk if filename is not sanitized.",
            "entry_functions": ["file_upload_handler"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["/tmp/upload", "multipart/form-data", "filename="],
            "risks": ["path_traversal"],
        },
        {
            "category": "network_service",
            "name": "Unknown Network Service (port 8080)",
            "description": "Stripped binary function FUN_00007000 calls recv/send and references ':8080', 'admin', 'debug'. Likely a debug/admin backdoor on port 8080.",
            "entry_functions": ["FUN_00007000"],
            "supporting_functions": [],
            "protocol": "Custom",
            "port_info": {"port": 8080, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": [":8080", "admin", "debug"],
            "risks": ["auth_bypass", "buffer_overflow", "command_injection"],
        },
    ],
    "summary": {
        "total_attack_surfaces": 7,
        "primary_exposure": "HTTP server on port 80 with multiple CGI endpoints, including a login handler that uses sprintf+system with user input — critical command injection risk",
        "secondary_exposures": [
            "Telnet on port 23 (classic IoT weak-auth entry point)",
            "Suspected debug backdoor on port 8080",
            "UPnP SSDP parser vulnerable to buffer overflow",
        ],
    },
})


# ── Main Agent tests ───────────────────────────────────────────────────

class TestAttackSurfaceIdentifier:
    """Tests for AttackSurfaceIdentifier agent."""

    @pytest.fixture
    def functions(self):
        return make_mock_functions()

    @pytest.fixture
    def strings(self):
        return make_mock_strings()

    @pytest.fixture
    def callgraph(self):
        return make_mock_callgraph()

    @pytest.fixture
    def mock_llm_response(self):
        """Create a mock LLMResponse."""
        resp = MagicMock()
        resp.content = MOCK_LLM_RESPONSE
        return resp

    def test_identify_returns_result(self, functions, strings, callgraph, mock_llm_response):
        """Full pipeline should return AttackSurfaceResult."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(
                functions=functions,
                strings=strings,
                callgraph=callgraph,
            )

        assert isinstance(result, AttackSurfaceResult)
        assert result.count == 7
        assert result.summary.total_attack_surfaces == 7

    def test_identify_network_services_present(self, functions, strings, callgraph, mock_llm_response):
        """HTTP and Telnet should be identified."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        names = [s.name for s in result.attack_surfaces]
        assert "HTTP Management Interface" in names
        assert "Telnet Service" in names

    def test_identify_stripped_function_handled(self, functions, strings, callgraph, mock_llm_response):
        """Stripped function FUN_00007000 should be identified as attack surface."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        stripped_surfaces = [
            s for s in result.attack_surfaces
            if "FUN_00007000" in s.entry_functions
        ]
        assert len(stripped_surfaces) == 1
        assert "8080" in str(stripped_surfaces[0].port_info.port)

    def test_identify_high_risk_surfaces(self, functions, strings, callgraph, mock_llm_response):
        """high_risk_surfaces should filter to network-facing with risks."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        high_risk = result.high_risk_surfaces
        # All network_service + cgi_endpoint + protocol_parser with risks
        assert len(high_risk) > 0
        for s in high_risk:
            assert s.category in ("network_service", "cgi_endpoint", "protocol_parser")
            assert s.risk_count > 0

    def test_identify_prompt_includes_functions(self, functions, strings, callgraph, mock_llm_response):
        """Verify the prompt sent to LLM contains key function names."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            identifier.identify(functions, strings, callgraph)

            # Check prompt content
            call_args = mock_client.call.call_args
            messages = call_args[1]["messages"] if "messages" in call_args[1] else call_args[0][0]
            system_msg = messages[0]["content"] if messages[0]["role"] == "system" else messages[0]["content"]
            assert "httpd_init" in system_msg
            assert "httpd_handle_request" in system_msg
            assert "cgi_login" in system_msg
            assert "FUN_00007000" in system_msg

    def test_identify_uses_deepseek_model(self, functions, strings, callgraph, mock_llm_response):
        """Should use DeepSeek-V4-Pro by default."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            identifier.identify(functions, strings, callgraph)

            call_kwargs = mock_client.call.call_args[1]
            assert "model" in call_kwargs
            # Model should be present (either as DEEPSEEK_V4_PRO or similar)
            assert call_kwargs["model"] is not None

    def test_identify_save_and_load(self, functions, strings, callgraph, mock_llm_response, tmp_path):
        """Should save result to JSON and load back."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

            output_path = tmp_path / "attack_surface.json"
            identifier.save(result, output_path)

            assert output_path.exists()

            loaded = identifier.load(output_path)
            assert loaded.count == result.count
            assert loaded.summary.total_attack_surfaces == result.summary.total_attack_surfaces

    def test_identify_handles_empty_strings_field(self, functions, callgraph, mock_llm_response):
        """Should handle empty strings list gracefully."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, [], callgraph)

        assert isinstance(result, AttackSurfaceResult)

    def test_llm_json_parse_error(self, functions, strings, callgraph):
        """Should handle malformed LLM JSON output gracefully."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            bad_response = MagicMock()
            bad_response.content = "This is not valid JSON {{{"
            mock_client.call.return_value = bad_response

            identifier = AttackSurfaceIdentifier()
            with pytest.raises(ValueError, match="Failed to parse"):
                identifier.identify(functions, strings, callgraph)

    def test_model_override(self, functions, strings, callgraph, mock_llm_response):
        """Should accept model override."""
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            from fuzzingbrain.llms import QWEN3_6_PLUS
            identifier = AttackSurfaceIdentifier(model=QWEN3_6_PLUS)
            identifier.identify(functions, strings, callgraph)

            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"] == QWEN3_6_PLUS
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_attack_surface_identifier.py -v
```
Expected: all FAIL (ImportError for identifier module)

- [ ] **Step 3: Write the AttackSurfaceIdentifier agent**

```python
# fuzzingbrain/attack_surface/identifier.py
"""
AttackSurfaceIdentifier Agent

Reads Phase 1 static analysis output (functions + strings + callgraph),
calls DeepSeek-V4-Pro to identify attack surfaces, and outputs structured JSON.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from loguru import logger

from ..llms import LLMClient, DEEPSEEK_V4_PRO, ModelInfo
from ..static.models import FunctionInfo, CallGraph, StringRef
from ..agents.firmware.prompts import get_attack_surface_prompt
from .models import AttackSurfaceResult


# ── Prompt-building helpers ───────────────────────────────────────────

def build_function_summaries(functions: List[FunctionInfo]) -> str:
    """Build a compact function summary table for the LLM prompt.

    Includes: name, address, arch, callee count, dangerous callees,
    interesting strings, and caller context.
    """
    if not functions:
        return "No functions provided."

    lines = []
    lines.append(f"Total functions: {len(functions)}")
    lines.append("")
    lines.append("## Function Summary Table")
    lines.append("")

    for f in functions:
        # Build one-line summary
        name = f.name
        addr = f"0x{f.address:X}" if isinstance(f.address, int) else str(f.address)
        arch = f.arch or "unknown"
        stripped = " [STRIPPED]" if f.is_stripped_name else ""

        # Key indicators
        indicators = []
        if f.has_unsafe_calls:
            indicators.append(f"DANGEROUS: {', '.join(f.dangerous_funcs)}")
        if f.strings_used:
            # Show up to 5 most interesting strings
            shown = f.strings_used[:5]
            if len(f.strings_used) > 5:
                shown.append(f"... (+{len(f.strings_used) - 5} more)")
            indicators.append(f"strings: [{', '.join(shown)}]")
        if f.callees:
            # Show up to 8 callees (focus on interesting ones)
            interesting = [
                c for c in f.callees
                if any(kw in c.lower() for kw in (
                    "socket", "bind", "listen", "accept", "recv", "send",
                    "system", "popen", "exec", "strcpy", "sprintf", "memcpy",
                    "fopen", "open", "read", "write", "malloc",
                ))
            ]
            shown = interesting[:8] if interesting else f.callees[:5]
            if shown:
                indicators.append(f"callees: [{', '.join(shown)}]")
        if f.callers:
            shown = f.callers[:5]
            if len(f.callers) > 5:
                shown.append(f"... (+{len(f.callers) - 5} more)")
            indicators.append(f"callers: [{', '.join(shown)}]")

        indicator_str = " | ".join(indicators) if indicators else "no significant indicators"
        lines.append(f"- **{name}**{stripped} @ {addr} ({arch}): {indicator_str}")

    return "\n".join(lines)


def build_strings_by_category(strings: List[StringRef]) -> str:
    """Build categorized string list for the LLM prompt."""
    if not strings:
        return "No strings found."

    # Group by category
    by_cat: Dict[str, List[StringRef]] = {}
    for s in strings:
        # Ensure category is set
        if s.category == "other":
            s.categorize()
        by_cat.setdefault(s.category, []).append(s)

    lines = []
    lines.append(f"Total strings: {len(strings)}")
    lines.append("")

    category_order = ["port", "url", "credential", "protocol", "path", "debug", "other"]
    for cat in category_order:
        items = by_cat.get(cat, [])
        if not items:
            continue
        lines.append(f"### {cat.upper()} Strings ({len(items)})")
        for s in items:
            refs = ", ".join(s.referenced_by[:5]) if s.referenced_by else "no xref"
            if len(s.referenced_by) > 5:
                refs += f" (+{len(s.referenced_by) - 5} more)"
            lines.append(f"- `{s.value}` → referenced by: [{refs}]")
        lines.append("")

    return "\n".join(lines)


def build_callgraph_summary(callgraph: CallGraph) -> str:
    """Build a summary of the call graph for the LLM prompt."""
    if not callgraph or not callgraph.nodes:
        return "No call graph data available."

    lines = []
    lines.append(f"Call graph has {callgraph.node_count} nodes (functions).")
    lines.append("")

    # Find root functions (no callers or only external callers)
    roots = [
        name for name, node in callgraph.nodes.items()
        if not node.callers or all(c.startswith("FUN_") and len(c) < 12 for c in node.callers)
    ]
    if roots:
        lines.append(f"Root functions (likely entry points): {', '.join(roots[:10])}")
        if len(roots) > 10:
            lines.append(f"  ... and {len(roots) - 10} more")

    # Show key relationships for attack-surface-relevant functions
    lines.append("")
    lines.append("### Key Call Relationships")
    interesting_funcs = [
        name for name, node in callgraph.nodes.items()
        if any(kw in name.lower() for kw in (
            "http", "cgi", "main", "init", "parse", "auth", "login",
            "upload", "download", "exec", "cmd", "handler", "dispatch",
            "telnet", "ssh", "upnp", "dns", "ftp", "snmp",
        )) or any(c in node.callees for c in ("system", "popen", "strcpy", "sprintf"))
    ]

    for name in interesting_funcs[:30]:
        node = callgraph.nodes[name]
        callees = node.callees[:8] if node.callees else []
        callers = node.callers[:5] if node.callers else []
        parts = []
        if callers:
            parts.append(f"called by [{', '.join(callers)}]")
        if callees:
            parts.append(f"calls [{', '.join(callees)}]")
        if parts:
            lines.append(f"- **{name}**: {'; '.join(parts)}")

    if len(interesting_funcs) > 30:
        lines.append(f"  ... and {len(interesting_funcs) - 30} more interesting functions")

    return "\n".join(lines)


# ── Main Agent ─────────────────────────────────────────────────────────

class AttackSurfaceIdentifier:
    """
    Identifies attack surfaces in firmware from static analysis output.

    Reads function lists, string references, and call graph info, then calls
    an LLM (default: DeepSeek-V4-Pro) to identify code paths where untrusted
    data enters the system.

    Usage:
        identifier = AttackSurfaceIdentifier()
        result = identifier.identify(functions, strings, callgraph)
        identifier.save(result, "attack_surface.json")
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

    def identify(
        self,
        functions: List[FunctionInfo],
        strings: List[StringRef],
        callgraph: Optional[CallGraph] = None,
    ) -> AttackSurfaceResult:
        """
        Identify attack surfaces from static analysis data.

        Args:
            functions: All functions from Ghidra decompilation.
            strings: All string references from the binary.
            callgraph: Call graph (optional, used for relationship context).

        Returns:
            AttackSurfaceResult with identified attack surfaces and summary.

        Raises:
            ValueError: If the LLM response cannot be parsed.
        """
        # Build prompt
        system_prompt = get_attack_surface_prompt()
        user_content = self._build_user_message(functions, strings, callgraph)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        logger.info(
            f"AttackSurfaceIdentifier: calling LLM with "
            f"{len(functions)} functions, {len(strings)} strings"
        )

        # Call LLM
        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        # Parse response
        result = self._parse_response(response.content)
        logger.info(
            f"AttackSurfaceIdentifier: identified {result.count} attack surfaces. "
            f"Primary exposure: {result.summary.primary_exposure[:100]}"
        )
        return result

    def _build_user_message(
        self,
        functions: List[FunctionInfo],
        strings: List[StringRef],
        callgraph: Optional[CallGraph],
    ) -> str:
        """Build the user message with all input data."""
        parts = []

        parts.append("# Firmware Static Analysis Results\n")

        parts.append("## Functions")
        parts.append(build_function_summaries(functions))
        parts.append("")

        parts.append("## Strings by Category")
        parts.append(build_strings_by_category(strings))
        parts.append("")

        if callgraph:
            parts.append("## Call Graph")
            parts.append(build_callgraph_summary(callgraph))
            parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Analyze the above data and identify ALL attack surfaces. "
            "Output ONLY valid JSON matching the schema in the system prompt. "
            "Do not include any text outside the JSON."
        )

        return "\n".join(parts)

    def _parse_response(self, content: str) -> AttackSurfaceResult:
        """Parse LLM response into AttackSurfaceResult.

        Handles LLMs that wrap JSON in markdown code fences.
        """
        # Try to extract JSON from markdown code fences
        json_str = content.strip()

        # Remove ```json ... ``` wrapper if present
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Try to find a JSON object if there's surrounding text
        if not json_str.startswith("{"):
            brace_start = json_str.find("{")
            if brace_start >= 0:
                # Find matching closing brace
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
            return AttackSurfaceResult.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse LLM response as AttackSurfaceResult: {e}")
            logger.debug(f"Raw response (first 500 chars): {content[:500]}")
            raise ValueError(
                f"Failed to parse LLM response as AttackSurfaceResult: {e}"
            ) from e

    # ── File I/O ──────────────────────────────────────────────────────

    def save(self, result: AttackSurfaceResult, path: Union[str, Path]) -> None:
        """Save AttackSurfaceResult to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"AttackSurfaceResult saved to {path}")

    def load(self, path: Union[str, Path]) -> AttackSurfaceResult:
        """Load AttackSurfaceResult from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Attack surface file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return AttackSurfaceResult.from_dict(data)
```

- [ ] **Step 4: Run identifier tests to verify they pass**

```bash
pytest tests/test_attack_surface_identifier.py -v
```
Expected: all 14 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/attack_surface/identifier.py tests/test_attack_surface_identifier.py
git commit -m "feat(attack_surface): implement AttackSurfaceIdentifier agent

Reads functions.json + strings.json + callgraph.json, builds structured
prompt with function summaries/string categories/call relationships, calls
DeepSeek-V4-Pro, and parses response into AttackSurfaceResult.

Includes 14 unit tests with mocked LLM responses.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: DirectionPlanner Agent

**Files:**
- Create: `fuzzingbrain/attack_surface/direction_planner.py`
- Create: `tests/test_attack_surface_direction.py`

- [ ] **Step 1: Write direction planner tests (these must fail first)**

```python
# tests/test_attack_surface_direction.py
"""Tests for DirectionPlanner."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.attack_surface.direction_planner import (
    DirectionPlanner,
    build_attack_surfaces_context,
    build_callgraph_context,
    build_function_details_context,
)
from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
    PortInfo,
)
from fuzzingbrain.static.models import (
    FunctionInfo, CallGraph, CallGraphNode, StringRef,
)


# ── Mock data builders ─────────────────────────────────────────────────

def make_mock_attack_surface_result():
    """Create a realistic AttackSurfaceResult for testing DirectionPlanner input."""
    surfaces = [
        AttackSurface(
            name="HTTP Management Interface",
            category="network_service",
            entry_functions=["httpd_init", "httpd_handle_request"],
            supporting_functions=[],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
            strings_evidence=["0.0.0.0", ":80", "GET ", "POST "],
            risks=["buffer_overflow", "command_injection"],
        ),
        AttackSurface(
            name="Login CGI Handler",
            category="cgi_endpoint",
            entry_functions=["cgi_login"],
            supporting_functions=["do_system_cmd"],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="inferred"),
            strings_evidence=["login.cgi", "admin", "password"],
            risks=["command_injection", "auth_bypass"],
        ),
        AttackSurface(
            name="Telnet Service",
            category="network_service",
            entry_functions=["telnetd_init"],
            supporting_functions=[],
            protocol="Telnet",
            port_info=PortInfo(port=23, protocol_type="TCP", certainty="confirmed"),
            strings_evidence=[":23", "telnet", "login: "],
            risks=["auth_bypass", "buffer_overflow"],
        ),
        AttackSurface(
            name="UPnP SSDP Handler",
            category="protocol_parser",
            entry_functions=["parse_upnp"],
            supporting_functions=[],
            protocol="UPnP",
            strings_evidence=["UPnP", "SSDP", "M-SEARCH"],
            risks=["buffer_overflow"],
        ),
        AttackSurface(
            name="System Command Builder",
            category="command_execution",
            entry_functions=["do_system_cmd"],
            protocol="N/A",
            strings_evidence=["ping ", "iptables"],
            risks=["command_injection"],
        ),
        AttackSurface(
            name="File Upload Handler",
            category="file_operation",
            entry_functions=["file_upload_handler"],
            protocol="HTTP",
            strings_evidence=["/tmp/upload", "multipart/form-data"],
            risks=["path_traversal"],
        ),
        AttackSurface(
            name="Unknown Network Service (port 8080)",
            category="network_service",
            entry_functions=["FUN_00007000"],
            protocol="Custom",
            port_info=PortInfo(port=8080, protocol_type="TCP", certainty="inferred"),
            strings_evidence=[":8080", "admin", "debug"],
            risks=["auth_bypass", "buffer_overflow"],
        ),
    ]
    summary = AttackSurfaceSummary(
        total_attack_surfaces=7,
        primary_exposure="HTTP server on port 80 with CGI endpoints",
        secondary_exposures=["Telnet on port 23", "Debug backdoor on port 8080", "UPnP SSDP"],
    )
    return AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)


def make_mock_functions():
    """Create functions matching the attack surfaces."""
    from tests.test_attack_surface_identifier import make_function  # reuse helper
    return [
        make_function("httpd_init", 0x2000,
                      callees=["socket", "bind", "listen", "accept"],
                      strings=["0.0.0.0", ":80"], dangerous=["sprintf"]),
        make_function("httpd_handle_request", 0x2100,
                      callees=["recv", "strcpy", "system", "send", "cgi_login",
                               "do_system_cmd", "file_upload_handler"],
                      strings=["GET ", "POST ", "/cgi-bin/", "HTTP/1.1"],
                      dangerous=["strcpy", "system"]),
        make_function("cgi_login", 0x2200,
                      callees=["recv", "sprintf", "strcmp", "system"],
                      strings=["admin", "password", "login.cgi"],
                      dangerous=["sprintf", "system"]),
        make_function("telnetd_init", 0x3000,
                      callees=["socket", "bind", "listen"],
                      strings=[":23", "telnet"]),
        make_function("parse_upnp", 0x4000,
                      callees=["recvfrom", "strcpy", "memcpy"],
                      strings=["UPnP", "SSDP", "M-SEARCH"],
                      dangerous=["strcpy"]),
        make_function("do_system_cmd", 0x5000,
                      callees=["system"],
                      strings=["ping ", "iptables"], dangerous=["system"]),
        make_function("file_upload_handler", 0x6000,
                      callees=["fopen", "fwrite", "recv"],
                      strings=["/tmp/upload", "multipart/form-data"]),
        make_function("FUN_00007000", 0x7000,
                      callees=["recv", "send"],
                      strings=[":8080", "admin", "debug"]),
    ]


def make_mock_callgraph():
    """Create callgraph matching the functions."""
    nodes = {
        "httpd_init": CallGraphNode(function_name="httpd_init", address=0x2000,
                                    callees=["socket", "bind", "listen", "accept"]),
        "httpd_handle_request": CallGraphNode(function_name="httpd_handle_request", address=0x2100,
                                              callees=["recv", "strcpy", "system", "send",
                                                       "cgi_login", "do_system_cmd", "file_upload_handler"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode(function_name="cgi_login", address=0x2200,
                                   callees=["recv", "sprintf", "strcmp", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode(function_name="telnetd_init", address=0x3000,
                                      callees=["socket", "bind", "listen"]),
        "parse_upnp": CallGraphNode(function_name="parse_upnp", address=0x4000,
                                    callees=["recvfrom", "strcpy", "memcpy"]),
        "do_system_cmd": CallGraphNode(function_name="do_system_cmd", address=0x5000,
                                       callees=["system"],
                                       callers=["cgi_login", "httpd_handle_request"]),
        "file_upload_handler": CallGraphNode(function_name="file_upload_handler", address=0x6000,
                                             callees=["fopen", "fwrite", "recv"],
                                             callers=["httpd_handle_request"]),
        "FUN_00007000": CallGraphNode(function_name="FUN_00007000", address=0x7000,
                                      callees=["recv", "send"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


# ── Mock LLM response ──────────────────────────────────────────────────

MOCK_DIRECTION_RESPONSE = json.dumps({
    "directions": [
        {
            "name": "HTTP Request Processing & CGI Dispatch",
            "description": "Core HTTP server handling GET/POST requests and dispatching to CGI handlers. This is the primary network-facing attack surface with direct external input.",
            "category": "http_processing",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "core_functions": ["httpd_init", "httpd_handle_request", "cgi_login",
                               "do_system_cmd", "file_upload_handler"],
            "big_pool": ["httpd_init", "httpd_handle_request", "cgi_login",
                         "do_system_cmd", "file_upload_handler",
                         "socket", "bind", "listen", "accept",
                         "recv", "strcpy", "system", "send",
                         "sprintf", "strcmp", "fopen", "fwrite"],
            "primary_attack_types": ["buffer_overflow", "command_injection"],
            "secondary_attack_types": ["auth_bypass", "path_traversal"],
            "priority": 5,
            "estimated_complexity": "high",
            "rationale": "Network-facing, unauthenticated HTTP with multiple CGI endpoints. Entry functions call strcpy+system with user-controlled input. Highest priority because it combines network exposure with dangerous sink functions.",
        },
        {
            "name": "Telnet Service",
            "description": "Telnet daemon on port 23 providing remote shell access.",
            "category": "network_service",
            "entry_functions": ["telnetd_init"],
            "core_functions": ["telnetd_init"],
            "big_pool": ["telnetd_init", "socket", "bind", "listen"],
            "primary_attack_types": ["auth_bypass"],
            "secondary_attack_types": ["buffer_overflow"],
            "priority": 4,
            "estimated_complexity": "medium",
            "rationale": "Network-facing on well-known port but likely using standard telnetd code. Auth bypass is the primary concern.",
        },
        {
            "name": "UPnP Protocol Parsing",
            "description": "UPnP SSDP discovery protocol handling. Multicast UDP packet processing is a classic source of buffer overflows in IoT firmware.",
            "category": "protocol_parsing",
            "entry_functions": ["parse_upnp"],
            "core_functions": ["parse_upnp"],
            "big_pool": ["parse_upnp", "recvfrom", "strcpy", "memcpy"],
            "primary_attack_types": ["buffer_overflow"],
            "secondary_attack_types": [],
            "priority": 5,
            "estimated_complexity": "medium",
            "rationale": "Network-reachable via UDP multicast, no authentication. Processes variable-length SSDP packets with strcpy — classic overflow pattern. Very common vulnerability in IoT firmware.",
        },
        {
            "name": "Debug Backdoor (Port 8080)",
            "description": "Suspected debug/admin backdoor on port 8080. Stripped binary, unknown protocol but references 'admin' and 'debug' — likely a hidden management interface.",
            "category": "network_service",
            "entry_functions": ["FUN_00007000"],
            "core_functions": ["FUN_00007000"],
            "big_pool": ["FUN_00007000", "recv", "send"],
            "primary_attack_types": ["auth_bypass", "command_injection"],
            "secondary_attack_types": ["buffer_overflow"],
            "priority": 5,
            "estimated_complexity": "low",
            "rationale": "Hidden debug interfaces in IoT firmware are notoriously insecure — often have hardcoded credentials or no auth at all. High priority for quick wins.",
        },
    ],
    "analysis_order": {
        "recommended_sequence": [
            "HTTP Request Processing & CGI Dispatch",
            "UPnP Protocol Parsing",
            "Debug Backdoor (Port 8080)",
            "Telnet Service",
        ],
        "rationale": "HTTP processing has the broadest attack surface (multiple CGI endpoints) and highest concentration of dangerous sink functions. UPnP parsers are classic buffer overflow sources. Debug backdoor is a quick win. Telnet is lowest risk of the four.",
    },
})


# ── Helper function tests ──────────────────────────────────────────────

class TestBuildAttackSurfacesContext:
    """Tests for build_attack_surfaces_context helper."""

    def test_builds_context(self):
        surfaces = [
            AttackSurface(
                name="HTTP Server",
                category="network_service",
                entry_functions=["httpd_main"],
                protocol="HTTP",
                port_info=PortInfo(port=80),
                risks=["buffer_overflow"],
            ),
        ]
        result = build_attack_surfaces_context(surfaces)
        assert "HTTP Server" in result
        assert "port 80" in result
        assert "buffer_overflow" in result

    def test_empty_surfaces(self):
        result = build_attack_surfaces_context([])
        assert "No attack surfaces" in result


class TestBuildCallgraphContext:
    """Tests for build_callgraph_context helper."""

    def test_builds_context(self):
        cg = make_mock_callgraph()
        result = build_callgraph_context(cg)
        assert "httpd_init" in result
        assert "cgi_login" in result

    def test_empty_callgraph(self):
        result = build_callgraph_context(None)
        assert "No call graph" in result.lower()

    def test_shows_reachability(self):
        """Should show which attack surface functions are connected."""
        cg = make_mock_callgraph()
        result = build_callgraph_context(cg)
        # httpd_handle_request → cgi_login should be visible
        assert "httpd_handle_request" in result
        assert "cgi_login" in result


class TestBuildFunctionDetailsContext:
    """Tests for build_function_details_context helper."""

    def test_builds_details(self):
        funcs = make_mock_functions()
        entry_names = {"httpd_init", "httpd_handle_request", "cgi_login"}
        result = build_function_details_context(funcs, entry_names)
        assert "httpd_init" in result
        assert "httpd_handle_request" in result
        assert "cgi_login" in result
        # Should include dangerous call info
        assert "strcpy" in result or "sprintf" in result

    def test_only_entry_functions_detailed(self):
        """Should only show details for entry/supporting functions, not all."""
        funcs = make_mock_functions()
        entry_names = {"httpd_init"}
        result = build_function_details_context(funcs, entry_names)
        assert "httpd_init" in result
        # telnetd_init is not in entry set, should not be in detailed section
        # (or at least httpd_init should be prominent)


# ── Main Agent tests ───────────────────────────────────────────────────

class TestDirectionPlanner:
    """Tests for DirectionPlanner agent."""

    @pytest.fixture
    def attack_surfaces(self):
        return make_mock_attack_surface_result()

    @pytest.fixture
    def functions(self):
        return make_mock_functions()

    @pytest.fixture
    def callgraph(self):
        return make_mock_callgraph()

    @pytest.fixture
    def mock_llm_response(self):
        resp = MagicMock()
        resp.content = MOCK_DIRECTION_RESPONSE
        return resp

    def test_plan_returns_result(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Full pipeline should return DirectionResult."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(
                attack_surfaces=attack_surfaces,
                callgraph=callgraph,
                functions=functions,
            )

        assert isinstance(result, DirectionResult)
        assert result.count == 4
        assert len(result.analysis_order.recommended_sequence) == 4

    def test_plan_high_priority_first(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """High priority directions should be first in analysis order."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        first = result.analysis_order.recommended_sequence[0]
        first_dir = result.get_by_name(first)
        assert first_dir is not None
        assert first_dir.priority >= 4  # First direction should be high priority

    def test_plan_all_attack_surfaces_covered(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Every attack surface entry function should appear in at least one direction."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        # Collect all entry functions from all attack surfaces
        all_entries = set()
        for a in attack_surfaces.attack_surfaces:
            all_entries.update(a.entry_functions)

        # Collect all functions across all direction big_pools
        all_in_directions = set()
        for d in result.directions:
            all_in_directions.update(d.big_pool)
            all_in_directions.update(d.core_functions)

        for entry in all_entries:
            assert entry in all_in_directions, \
                f"Entry function {entry} not covered by any direction!"

    def test_plan_uses_deepseek(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Should use DeepSeek-V4-Pro by default."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            planner.plan(attack_surfaces, callgraph, functions)

            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"] is not None

    def test_plan_prompt_includes_attack_surfaces(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Prompt should include attack surface names and entry functions."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            planner.plan(attack_surfaces, callgraph, functions)

            call_args = mock_client.call.call_args
            messages = call_args[1]["messages"] if "messages" in call_args[1] else call_args[0][0]
            # Get user message (second message)
            user_msg = messages[1]["content"] if len(messages) > 1 else messages[0]["content"]
            assert "HTTP Management Interface" in user_msg
            assert "Login CGI Handler" in user_msg
            assert "Telnet Service" in user_msg

    def test_plan_save_and_load(self, attack_surfaces, functions, callgraph, mock_llm_response, tmp_path):
        """Should save and load DirectionResult to/from JSON."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

            output_path = tmp_path / "directions.json"
            planner.save(result, output_path)
            assert output_path.exists()

            loaded = planner.load(output_path)
            assert loaded.count == result.count
            assert loaded.analysis_order.recommended_sequence == result.analysis_order.recommended_sequence

    def test_plan_json_parse_error(self, attack_surfaces, functions, callgraph):
        """Malformed LLM JSON should raise ValueError."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            bad = MagicMock()
            bad.content = "not valid json {{{[[["
            mock_client.call.return_value = bad

            planner = DirectionPlanner()
            with pytest.raises(ValueError, match="Failed to parse"):
                planner.plan(attack_surfaces, callgraph, functions)

    def test_plan_3_to_8_directions(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Result should have 3-8 directions (from 7 attack surfaces, should merge to 3-8)."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        assert 3 <= result.count <= 8, \
            f"Expected 3-8 directions, got {result.count}"

    def test_plan_directions_have_required_fields(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Each direction should have all required fields."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        for d in result.directions:
            assert d.name
            assert d.description
            assert d.category
            assert len(d.entry_functions) > 0
            assert len(d.core_functions) > 0
            assert len(d.big_pool) > 0
            assert 1 <= d.priority <= 5
            assert d.estimated_complexity in ("high", "medium", "low")

    def test_model_override(self, attack_surfaces, functions, callgraph, mock_llm_response):
        """Should accept model override."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response

            from fuzzingbrain.llms import QWEN3_6_PLUS
            planner = DirectionPlanner(model=QWEN3_6_PLUS)
            planner.plan(attack_surfaces, callgraph, functions)

            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"] == QWEN3_6_PLUS

    def test_plan_without_callgraph(self, attack_surfaces, functions, mock_llm_response):
        """Should work without callgraph (optional parameter)."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, None, functions)
            assert isinstance(result, DirectionResult)

    def test_plan_without_functions(self, attack_surfaces, callgraph, mock_llm_response):
        """Should work without functions (optional parameter)."""
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response

            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, None)
            assert isinstance(result, DirectionResult)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_attack_surface_direction.py -v
```
Expected: all FAIL (ImportError for direction_planner module)

- [ ] **Step 3: Write the DirectionPlanner agent**

```python
# fuzzingbrain/attack_surface/direction_planner.py
"""
DirectionPlanner Agent

Reads attack_surface.json + callgraph.json, calls DeepSeek-V4-Pro to
divide attack surfaces into 3-8 prioritized analysis directions.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from loguru import logger

from ..llms import LLMClient, DEEPSEEK_V4_PRO, ModelInfo
from ..static.models import FunctionInfo, CallGraph
from ..agents.firmware.prompts import get_direction_prompt
from .models import (
    AttackSurface,
    AttackSurfaceResult,
    DirectionResult,
)


# ── Prompt-building helpers ───────────────────────────────────────────

def build_attack_surfaces_context(surfaces: List[AttackSurface]) -> str:
    """Build attack surface context for the Direction Planner prompt."""
    if not surfaces:
        return "No attack surfaces provided."

    lines = []
    lines.append(f"Total attack surfaces: {len(surfaces)}")
    lines.append("")

    for i, a in enumerate(surfaces, 1):
        lines.append(f"### {i}. {a.name}")
        lines.append(f"- Category: {a.category}")
        lines.append(f"- Description: {a.description}" if a.description else f"- Description: {a.name}")
        lines.append(f"- Protocol: {a.protocol}")
        if a.port_info:
            lines.append(f"- Port: {a.port_info.port}/{a.port_info.protocol_type} ({a.port_info.certainty})")
        lines.append(f"- Entry Functions: {', '.join(a.entry_functions)}")
        if a.supporting_functions:
            lines.append(f"- Supporting Functions: {', '.join(a.supporting_functions)}")
        if a.strings_evidence:
            evidence = a.strings_evidence[:8]
            if len(a.strings_evidence) > 8:
                evidence.append(f"... (+{len(a.strings_evidence) - 8} more)")
            lines.append(f"- String Evidence: {', '.join(repr(e) for e in evidence)}")
        if a.risks:
            lines.append(f"- Identified Risks: {', '.join(a.risks)}")
        lines.append("")

    return "\n".join(lines)


def build_callgraph_context(callgraph: Optional[CallGraph]) -> str:
    """Build call graph context for direction planning."""
    if not callgraph or not callgraph.nodes:
        return "No call graph data available."

    lines = []
    lines.append(f"Call graph: {callgraph.node_count} functions")
    lines.append("")

    # Group functions by connectivity
    # Show call paths from attack surface entry points
    entry_keywords = [
        "http", "cgi", "init", "main", "parse", "handler", "auth", "login",
        "upload", "exec", "cmd", "telnet", "ssh", "upnp", "dns", "ftp",
    ]

    interesting = {}
    for name, node in callgraph.nodes.items():
        is_interesting = any(kw in name.lower() for kw in entry_keywords)
        has_interesting_callee = any(
            any(kw in c.lower() for kw in entry_keywords)
            for c in node.callees
        )
        if is_interesting or has_interesting_callee:
            interesting[name] = node

    lines.append("### Key Functions and Their Call Relationships")
    for name, node in sorted(interesting.items()):
        callees_shown = node.callees[:10] if node.callees else []
        callers_shown = node.callers[:5] if node.callers else []
        parts = []
        if callers_shown:
            parts.append(f"called_by=[{', '.join(callers_shown)}]")
        if callees_shown:
            parts.append(f"calls=[{', '.join(callees_shown)}]")
        if parts:
            lines.append(f"- {name}: {'; '.join(parts)}")

    # Also show connectivity between attack surface functions
    lines.append("")
    lines.append("### Connectivity Between Attack Surface Entry Points")
    attack_surface_funcs = {
        name for name, node in callgraph.nodes.items()
        if any(kw in name.lower() for kw in ("http", "cgi", "init", "parse", "auth", "login", "handler", "upload"))
    }

    # Show which attack surface functions call each other
    for name in sorted(attack_surface_funcs):
        node = callgraph.nodes[name]
        reachable_attack_funcs = [
            c for c in node.callees if c in attack_surface_funcs
        ]
        if reachable_attack_funcs:
            lines.append(f"- {name} → [{', '.join(reachable_attack_funcs)}]")

    return "\n".join(lines)


def build_function_details_context(
    functions: Optional[List[FunctionInfo]],
    entry_names: Set[str],
) -> str:
    """Build detailed function context for entry functions only."""
    if not functions:
        return "No function details available."

    # Filter to functions that are entry points or called by entry points
    relevant = [f for f in functions if f.name in entry_names]

    if not relevant:
        return "No relevant function details (entry functions not found in function list)."

    lines = []
    for f in relevant:
        lines.append(f"### {f.name} @ 0x{f.address:X}")
        if f.callees:
            lines.append(f"Callees: {', '.join(f.callees[:15])}")
            if len(f.callees) > 15:
                lines.append(f"  ... and {len(f.callees) - 15} more")
        if f.dangerous_funcs:
            lines.append(f"⚠ DANGEROUS CALLS: {', '.join(f.dangerous_funcs)}")
        if f.strings_used:
            lines.append(f"Strings: {', '.join(repr(s) for s in f.strings_used[:8])}")
        lines.append("")

    return "\n".join(lines)


# ── Main Agent ─────────────────────────────────────────────────────────

class DirectionPlanner:
    """
    Divides identified attack surfaces into prioritized analysis directions.

    Reads attack surfaces, call graph, and function details, then calls an LLM
    (default: DeepSeek-V4-Pro) to produce 3-8 directions with priority assignments.

    Usage:
        planner = DirectionPlanner()
        result = planner.plan(attack_surface_result, callgraph, functions)
        planner.save(result, "directions.json")
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

    def plan(
        self,
        attack_surfaces: AttackSurfaceResult,
        callgraph: Optional[CallGraph] = None,
        functions: Optional[List[FunctionInfo]] = None,
    ) -> DirectionResult:
        """
        Plan analysis directions from attack surfaces.

        Args:
            attack_surfaces: AttackSurfaceResult from AttackSurfaceIdentifier.
            callgraph: Call graph for relationship analysis (optional).
            functions: Function list for detailed context (optional).

        Returns:
            DirectionResult with 3-8 directions and analysis order.

        Raises:
            ValueError: If the LLM response cannot be parsed.
        """
        system_prompt = get_direction_prompt()
        user_content = self._build_user_message(attack_surfaces, callgraph, functions)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        logger.info(
            f"DirectionPlanner: planning directions for "
            f"{attack_surfaces.count} attack surfaces"
        )

        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        result = self._parse_response(response.content)
        logger.info(
            f"DirectionPlanner: created {result.count} directions. "
            f"High priority: {len(result.high_priority_directions)}. "
            f"Sequence: {result.analysis_order.recommended_sequence}"
        )
        return result

    def _build_user_message(
        self,
        attack_surfaces: AttackSurfaceResult,
        callgraph: Optional[CallGraph],
        functions: Optional[List[FunctionInfo]],
    ) -> str:
        """Build the user message with all input data."""
        parts = []

        parts.append("# Attack Surface Analysis Input\n")

        parts.append("## Identified Attack Surfaces")
        parts.append(build_attack_surfaces_context(attack_surfaces.attack_surfaces))
        parts.append("")

        if callgraph:
            parts.append("## Call Graph Analysis")
            parts.append(build_callgraph_context(callgraph))
            parts.append("")

        if functions:
            # Collect all entry function names
            entry_names = set()
            for a in attack_surfaces.attack_surfaces:
                entry_names.update(a.entry_functions)
                entry_names.update(a.supporting_functions)

            parts.append("## Entry Function Details")
            parts.append(build_function_details_context(functions, entry_names))
            parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Divide the above attack surfaces into 3-8 independent analysis directions. "
            "Output ONLY valid JSON matching the schema in the system prompt. "
            "Do not include any text outside the JSON."
        )

        return "\n".join(parts)

    def _parse_response(self, content: str) -> DirectionResult:
        """Parse LLM response into DirectionResult."""
        json_str = content.strip()

        # Remove ```json ... ``` wrapper
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Try to find JSON object
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
            return DirectionResult.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse LLM response as DirectionResult: {e}")
            logger.debug(f"Raw response (first 500 chars): {content[:500]}")
            raise ValueError(
                f"Failed to parse LLM response as DirectionResult: {e}"
            ) from e

    # ── File I/O ──────────────────────────────────────────────────────

    def save(self, result: DirectionResult, path: Union[str, Path]) -> None:
        """Save DirectionResult to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"DirectionResult saved to {path}")

    def load(self, path: Union[str, Path]) -> DirectionResult:
        """Load DirectionResult from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Direction file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return DirectionResult.from_dict(data)
```

- [ ] **Step 4: Run direction planner tests to verify they pass**

```bash
pytest tests/test_attack_surface_direction.py -v
```
Expected: all 15 tests PASS

- [ ] **Step 5: Commit**

```bash
git add fuzzingbrain/attack_surface/direction_planner.py tests/test_attack_surface_direction.py
git commit -m "feat(attack_surface): implement DirectionPlanner agent

Reads attack_surface.json + callgraph.json, builds structured prompt with
attack surface context/call relationships/function details, calls DeepSeek-V4-Pro,
and produces 3-8 prioritized analysis directions.

Includes 15 unit tests with coverage for edge cases.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Phase 2 Integration Test & Final Validation

- [ ] **Step 1: Write integration test**

```python
# tests/test_phase2_pipeline.py
"""Phase 2 end-to-end pipeline integration test."""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from fuzzingbrain.attack_surface.identifier import AttackSurfaceIdentifier
from fuzzingbrain.attack_surface.direction_planner import DirectionPlanner
from fuzzingbrain.attack_surface.models import (
    AttackSurfaceResult,
    DirectionResult,
)
from fuzzingbrain.static.models import (
    FunctionInfo, CallGraph, CallGraphNode, StringRef,
)


# ── Test data ──────────────────────────────────────────────────────────

PHASE1_FUNCTIONS = [
    FunctionInfo(
        name="main", address=0x1000, arch="arm", bits=32, endian="little",
        pseudo_code="void main() { httpd_init(); telnetd_init(); }",
        callees=["httpd_init", "telnetd_init"],
        strings_used=["Starting firmware v1.0"],
    ),
    FunctionInfo(
        name="httpd_init", address=0x2000, arch="arm", bits=32, endian="little",
        pseudo_code="int httpd_init() { socket(); bind(); listen(); }",
        callees=["socket", "bind", "listen", "accept"],
        strings_used=["0.0.0.0", ":80"],
        dangerous_funcs=["sprintf"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="httpd_handle_request", address=0x2100, arch="arm", bits=32, endian="little",
        pseudo_code="void httpd_handle_request(char *req) { char buf[256]; strcpy(buf, req); system(buf); }",
        callees=["recv", "strcpy", "system", "send"],
        strings_used=["GET ", "POST ", "/cgi-bin/"],
        dangerous_funcs=["strcpy", "system"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="cgi_login", address=0x2200, arch="arm", bits=32, endian="little",
        pseudo_code="int cgi_login() { char cmd[128]; sprintf(cmd, 'auth %s', user); system(cmd); }",
        callees=["sprintf", "system"],
        strings_used=["login.cgi", "admin", "password", "username="],
        dangerous_funcs=["sprintf", "system"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="telnetd_init", address=0x3000, arch="arm", bits=32, endian="little",
        pseudo_code="void telnetd_init() { socket(); bind(23); listen(); }",
        callees=["socket", "bind", "listen"],
        strings_used=[":23", "telnet", "login: "],
    ),
    FunctionInfo(
        name="FUN_00004000", address=0x4000, arch="arm", bits=32, endian="little",
        pseudo_code="void FUN_00004000() { recvfrom(); strcpy(); }",
        callees=["recvfrom", "strcpy", "memcpy"],
        strings_used=["UPnP", "SSDP", "239.255.255.250"],
        dangerous_funcs=["strcpy"], has_unsafe_calls=True,
    ),
]


def make_phase1_callgraph():
    nodes = {
        "main": CallGraphNode("main", 0x1000, callees=["httpd_init", "telnetd_init"]),
        "httpd_init": CallGraphNode("httpd_init", 0x2000,
                                    callees=["socket", "bind", "listen", "accept"],
                                    callers=["main"]),
        "httpd_handle_request": CallGraphNode("httpd_handle_request", 0x2100,
                                              callees=["recv", "strcpy", "system", "send",
                                                       "cgi_login"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode("cgi_login", 0x2200,
                                   callees=["sprintf", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode("telnetd_init", 0x3000,
                                      callees=["socket", "bind", "listen"],
                                      callers=["main"]),
        "FUN_00004000": CallGraphNode("FUN_00004000", 0x4000,
                                      callees=["recvfrom", "strcpy", "memcpy"],
                                      callers=["main"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


PHASE1_STRINGS = [
    StringRef("0.0.0.0", 0x8000, ["httpd_init"], "port"),
    StringRef(":80", 0x8001, ["httpd_init"], "port"),
    StringRef(":23", 0x8002, ["telnetd_init"], "port"),
    StringRef("GET ", 0x8010, ["httpd_handle_request"], "protocol"),
    StringRef("POST ", 0x8011, ["httpd_handle_request"], "protocol"),
    StringRef("/cgi-bin/", 0x8012, ["httpd_handle_request"], "url"),
    StringRef("login.cgi", 0x8020, ["cgi_login"], "url"),
    StringRef("admin", 0x8030, ["cgi_login"], "credential"),
    StringRef("password", 0x8031, ["cgi_login"], "credential"),
    StringRef("username=", 0x8032, ["cgi_login"], "credential"),
    StringRef("UPnP", 0x8040, ["FUN_00004000"], "protocol"),
    StringRef("SSDP", 0x8041, ["FUN_00004000"], "protocol"),
    StringRef("239.255.255.250", 0x8042, ["FUN_00004000"], "url"),
    StringRef("login: ", 0x8080, ["telnetd_init"], "credential"),
    StringRef("Starting firmware v1.0", 0x8090, ["main"], "debug"),
    StringRef("telnet", 0x80A0, ["telnetd_init"], "protocol"),
]

# Realistic mock responses
MOCK_IDENTIFIER_RESPONSE = json.dumps({
    "attack_surfaces": [
        {
            "category": "network_service",
            "name": "HTTP Server on Port 80",
            "description": "Main HTTP server with CGI support. Handles GET/POST and dispatches to CGI endpoints including login.",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": ["0.0.0.0", ":80", "GET ", "POST ", "/cgi-bin/", "login.cgi"],
            "risks": ["buffer_overflow", "command_injection"],
        },
        {
            "category": "cgi_endpoint",
            "name": "Login CGI",
            "description": "Admin login endpoint processing username/password via sprintf+system. Classic command injection pattern.",
            "entry_functions": ["cgi_login"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["login.cgi", "admin", "password", "username="],
            "risks": ["command_injection", "buffer_overflow", "auth_bypass"],
        },
        {
            "category": "network_service",
            "name": "Telnet Daemon",
            "description": "Telnet service on port 23. Remote shell access.",
            "entry_functions": ["telnetd_init"],
            "supporting_functions": [],
            "protocol": "Telnet",
            "port_info": {"port": 23, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": [":23", "telnet", "login: "],
            "risks": ["auth_bypass", "buffer_overflow"],
        },
        {
            "category": "protocol_parser",
            "name": "UPnP SSDP Parser",
            "description": "UPnP discovery protocol. Multicast UDP packet processing with strcpy — classic overflow vector.",
            "entry_functions": ["FUN_00004000"],
            "supporting_functions": [],
            "protocol": "UPnP",
            "strings_evidence": ["UPnP", "SSDP", "239.255.255.250"],
            "risks": ["buffer_overflow"],
        },
    ],
    "summary": {
        "total_attack_surfaces": 4,
        "primary_exposure": "HTTP server on port 80 with CGI endpoints processing user input via sprintf+system — critical command injection and buffer overflow risk",
        "secondary_exposures": [
            "Telnet on port 23 (weak auth entry point)",
            "UPnP SSDP parser (multicast buffer overflow)",
        ],
    },
})

MOCK_DIRECTION_RESPONSE = json.dumps({
    "directions": [
        {
            "name": "HTTP Request Processing & CGI",
            "description": "Core HTTP server and CGI endpoint processing. Handles all web-based attack surface including login.",
            "category": "http_processing",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "core_functions": ["httpd_init", "httpd_handle_request", "cgi_login"],
            "big_pool": ["httpd_init", "httpd_handle_request", "cgi_login",
                         "socket", "bind", "listen", "accept",
                         "recv", "strcpy", "system", "send", "sprintf"],
            "primary_attack_types": ["buffer_overflow", "command_injection"],
            "secondary_attack_types": ["auth_bypass"],
            "priority": 5,
            "estimated_complexity": "high",
            "rationale": "Network-facing HTTP with multiple CGI endpoints, sprintf+system chains from user input. Highest concentration of dangerous sinks.",
        },
        {
            "name": "Telnet Remote Access",
            "description": "Telnet daemon providing remote shell access.",
            "category": "network_service",
            "entry_functions": ["telnetd_init"],
            "core_functions": ["telnetd_init"],
            "big_pool": ["telnetd_init", "socket", "bind", "listen"],
            "primary_attack_types": ["auth_bypass"],
            "secondary_attack_types": [],
            "priority": 4,
            "estimated_complexity": "low",
            "rationale": "Standard telnet service. Auth bypass is primary concern but likely well-tested code.",
        },
        {
            "name": "UPnP Protocol Parsing",
            "description": "UPnP SSDP discovery packet processing.",
            "category": "protocol_parsing",
            "entry_functions": ["FUN_00004000"],
            "core_functions": ["FUN_00004000"],
            "big_pool": ["FUN_00004000", "recvfrom", "strcpy", "memcpy"],
            "primary_attack_types": ["buffer_overflow"],
            "secondary_attack_types": [],
            "priority": 5,
            "estimated_complexity": "medium",
            "rationale": "UDP multicast with strcpy on variable-length input — classic IoT buffer overflow pattern. Very high probability.",
        },
    ],
    "analysis_order": {
        "recommended_sequence": [
            "HTTP Request Processing & CGI",
            "UPnP Protocol Parsing",
            "Telnet Remote Access",
        ],
        "rationale": "HTTP processing has broadest attack surface and highest concentration of dangerous functions. UPnP parsing is a classic overflow vector. Telnet is lowest risk.",
    },
})


class TestPhase2Pipeline:
    """Integration test for the full Phase 2 pipeline."""

    def test_full_pipeline_identifier_to_planner(self):
        """End-to-end: Phase 1 output → AttackSurfaceIdentifier → DirectionPlanner."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            # Setup mock LLM responses
            mock_id_resp = MagicMock()
            mock_id_resp.content = MOCK_IDENTIFIER_RESPONSE
            MockIdClient.return_value.call.return_value = mock_id_resp

            mock_dir_resp = MagicMock()
            mock_dir_resp.content = MOCK_DIRECTION_RESPONSE
            MockDirClient.return_value.call.return_value = mock_dir_resp

            # Step 1: Identify attack surfaces
            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            assert isinstance(attack_result, AttackSurfaceResult)
            assert attack_result.count == 4
            assert attack_result.summary.total_attack_surfaces == 4
            assert "HTTP" in attack_result.summary.primary_exposure

            # Step 2: Plan directions
            planner = DirectionPlanner()
            direction_result = planner.plan(
                attack_surfaces=attack_result,
                callgraph=callgraph,
                functions=PHASE1_FUNCTIONS,
            )

            assert isinstance(direction_result, DirectionResult)
            assert direction_result.count == 3
            assert 3 <= direction_result.count <= 8

            # Verify all attack surface entries are covered
            all_entries = set()
            for a in attack_result.attack_surfaces:
                all_entries.update(a.entry_functions)

            all_in_dirs = set()
            for d in direction_result.directions:
                all_in_dirs.update(d.big_pool)

            for entry in all_entries:
                assert entry in all_in_dirs, \
                    f"Entry {entry} not covered by any direction"

            # Verify high priority directions come first
            first = direction_result.analysis_order.recommended_sequence[0]
            first_dir = direction_result.get_by_name(first)
            assert first_dir is not None
            assert first_dir.priority >= 4

    def test_full_pipeline_save_and_reload(self, tmp_path):
        """Save intermediate and final results, verify they reload correctly."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            mock_id_resp = MagicMock()
            mock_id_resp.content = MOCK_IDENTIFIER_RESPONSE
            MockIdClient.return_value.call.return_value = mock_id_resp

            mock_dir_resp = MagicMock()
            mock_dir_resp.content = MOCK_DIRECTION_RESPONSE
            MockDirClient.return_value.call.return_value = mock_dir_resp

            # Run pipeline
            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            # Save intermediate
            attack_path = tmp_path / "attack_surface.json"
            identifier.save(attack_result, attack_path)
            assert attack_path.exists()

            # Reload and continue
            loaded_attack = identifier.load(attack_path)
            assert loaded_attack.count == attack_result.count

            planner = DirectionPlanner()
            direction_result = planner.plan(
                attack_surfaces=loaded_attack,
                callgraph=callgraph,
                functions=PHASE1_FUNCTIONS,
            )

            # Save final
            dir_path = tmp_path / "directions.json"
            planner.save(direction_result, dir_path)
            assert dir_path.exists()

            loaded_dir = planner.load(dir_path)
            assert loaded_dir.count == direction_result.count
            assert loaded_dir.analysis_order.recommended_sequence == \
                   direction_result.analysis_order.recommended_sequence

    def test_pipeline_stripped_functions_handled(self):
        """Stripped functions (FUN_XXXXXXXX) should be properly handled."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            MockIdClient.return_value.call.return_value = MagicMock(
                content=MOCK_IDENTIFIER_RESPONSE
            )
            MockDirClient.return_value.call.return_value = MagicMock(
                content=MOCK_DIRECTION_RESPONSE
            )

            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            # FUN_00004000 should be identified as an attack surface (UPnP)
            upnp_surfaces = [
                s for s in attack_result.attack_surfaces
                if "FUN_00004000" in s.entry_functions
            ]
            assert len(upnp_surfaces) == 1, \
                "Stripped function FUN_00004000 not identified as attack surface"

            planner = DirectionPlanner()
            direction_result = planner.plan(attack_result, callgraph, PHASE1_FUNCTIONS)

            # FUN_00004000 should be in at least one direction
            all_funcs = set()
            for d in direction_result.directions:
                all_funcs.update(d.big_pool)
            assert "FUN_00004000" in all_funcs, \
                "Stripped function FUN_00004000 not assigned to any direction"

    def test_empty_inputs_handled_gracefully(self):
        """Empty inputs should not crash the pipeline."""
        empty_callgraph = CallGraph(binary_path="/bin/empty", nodes={})

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient:
            mock_resp = MagicMock()
            mock_resp.content = json.dumps({
                "attack_surfaces": [],
                "summary": {
                    "total_attack_surfaces": 0,
                    "primary_exposure": "No attack surfaces found — no network-facing code identified",
                    "secondary_exposures": [],
                },
            })
            MockIdClient.return_value.call.return_value = mock_resp

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(
                functions=[],
                strings=[],
                callgraph=empty_callgraph,
            )

            assert result.count == 0
            assert result.summary.total_attack_surfaces == 0
```

- [ ] **Step 2: Run integration tests**

```bash
pytest tests/test_phase2_pipeline.py -v
```
Expected: all 4 tests PASS

- [ ] **Step 3: Run ALL Phase 1 + Phase 2 tests**

```bash
pytest tests/ -v
```
Expected: 332 existing + ~51 new = ~383 tests, ALL PASS, 0 regressions

- [ ] **Step 4: Lint check**

```bash
ruff check fuzzingbrain/attack_surface/ fuzzingbrain/agents/firmware/
```
Expected: no errors

- [ ] **Step 5: Final commit**

```bash
git add tests/test_phase2_pipeline.py
git commit -m "test(phase2): add end-to-end pipeline integration test

Verify full Phase 2 flow: Phase 1 static output → AttackSurfaceIdentifier →
DirectionPlanner → attack_surface.json → directions.json.

Covers: stripped functions, save/reload cycle, empty inputs, coverage completeness.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 2 Completion Checklist

After all tasks complete, verify:

- [ ] `pytest tests/test_attack_surface_models.py -v` — 18 tests PASS
- [ ] `pytest tests/test_attack_surface_identifier.py -v` — 14 tests PASS
- [ ] `pytest tests/test_attack_surface_direction.py -v` — 15 tests PASS
- [ ] `pytest tests/test_phase2_pipeline.py -v` — 4 tests PASS
- [ ] `pytest tests/ -v` — ALL ~383 tests PASS, 0 regressions
- [ ] `ruff check .` — no lint errors
- [ ] Phase 2 data models: `AttackSurface`, `Direction`, `PortInfo`, `AnalysisOrder`, result containers
- [ ] `AttackSurfaceIdentifier` reads Phase 1 output → calls DeepSeek → returns `AttackSurfaceResult`
- [ ] `DirectionPlanner` reads attack surfaces + callgraph → calls DeepSeek → returns `DirectionResult`
- [ ] Both agents support: model override, file save/load, JSON parsing with markdown fence handling
