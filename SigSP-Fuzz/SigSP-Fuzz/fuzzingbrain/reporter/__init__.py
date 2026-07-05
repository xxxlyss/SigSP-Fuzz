"""Report generation for firmware vulnerability discovery.

Phase 4 output: FinalReport with JSON + Markdown formats.
"""
from .generator import ReportGenerator
__all__ = ["ReportGenerator"]
