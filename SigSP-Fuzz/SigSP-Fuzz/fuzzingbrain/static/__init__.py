"""
FuzzingBrain Static Analysis Module for Firmware

Binwalk extraction + Ghidra Headless decompilation + objdump fallback + call graph analysis.
"""

from .models import (
    BinaryInfo,
    FunctionInfo,
    CallGraph,
    CallGraphNode,
    StringRef,
    ExtractResult,
    AnalysisResult,
)

from .objdump_analyzer import ObjdumpAnalyzer, AnalyzerFactory

__all__ = [
    "BinaryInfo",
    "FunctionInfo",
    "CallGraph",
    "CallGraphNode",
    "StringRef",
    "ExtractResult",
    "AnalysisResult",
    "ObjdumpAnalyzer",
    "AnalyzerFactory",
]
