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
