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
