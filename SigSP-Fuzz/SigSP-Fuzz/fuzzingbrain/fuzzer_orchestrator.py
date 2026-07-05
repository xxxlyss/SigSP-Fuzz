"""
Fuzzer Orchestrator — Dual-Layer Fuzzing Pipeline Integration

Orchestrates GlobalFirmwareFuzzer (broad exploration) and SPFirmwareFuzzer
(deep verification) in a coordinated 4-phase pipeline with snapshot-based
state transfer, progress visualization, fault isolation, and checkpoint
resume support.

Pipeline:
    Phase 1: Global Exploration (5-10 min)
        → AFL++ QEMU-mode broad fuzzing
        → Collect coverage hotspots + crashes

    Phase 2: SP Generation (static + LLM)
        → Hotspot functions → Ghidra decompile → LLM analysis → SP list
        → Dedup + priority sort

    Phase 3: Targeted Verification (per-SP, parallel)
        → Baseline snapshot restore → SP Fuzzer verify → collect results
        → Fault isolation: single SP crash doesn't kill pipeline

    Phase 4: Report Generation
        → Aggregate CONFIRMED / NEEDS_REVIEW / FALSE_POSITIVE
        → SARIF-compatible JSON + human-readable summary

Usage:
    from fuzzingbrain.fuzzer_orchestrator import FuzzerOrchestrator

    orch = FuzzerOrchestrator(
        global_fuzzer=gf, sp_fuzzer=sf,
        snapshot_manager=sm, sp_generator=spg,
    )
    report = await orch.run("firmware.bin", attack_surfaces=[...])
"""

import asyncio
import json
import os
import signal
import sys
import time
import traceback
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from loguru import logger

from .firmware_fuzzer import CrashInfo, CoverageInfo, FirmwareFuzzer
from .global_fuzzer import GlobalFirmwareFuzzer
from .sp_fuzzer import SPFirmwareFuzzer, VerificationResult
from .snapshot_manager import SnapshotManager, SnapshotStats


# =============================================================================
# Constants
# =============================================================================

DEFAULT_GLOBAL_DURATION_MINUTES = 10
DEFAULT_MAX_PARALLEL_SP = 4
CHECKPOINT_FILE = "orchestrator_checkpoint.json"
PROGRESS_BAR_WIDTH = 40
SP_BATCH_SIZE = 8  # Process SPs in batches for better progress tracking


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class GlobalResult:
    """Phase 1 output — global fuzzing results."""

    fuzzer_id: str = ""
    coverage: Optional[CoverageInfo] = None
    crashes: List[CrashInfo] = field(default_factory=list)
    hotspots: List[dict] = field(default_factory=list)
    coverage_trend: List[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    plateaued: bool = False
    corpus_path: str = ""


@dataclass
class FuzzingReport:
    """Complete dual-layer fuzzing report.

    SARIF-compatible output format that can be imported into
    security tools (GitHub Code Scanning, DefectDojo, etc.).
    """

    firmware_path: str = ""
    firmware_hash: str = ""
    analysis_duration: float = 0.0
    started_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    completed_at: str = ""

    # Phase results
    global_coverage: Optional[CoverageInfo] = None
    global_crashes: List[dict] = field(default_factory=list)
    global_duration_seconds: float = 0.0

    total_sps_generated: int = 0
    total_sps_verified: int = 0

    confirmed_vulns: List[dict] = field(default_factory=list)
    needs_review: List[dict] = field(default_factory=list)
    false_positives: List[dict] = field(default_factory=list)

    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    # Errors encountered
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "firmware_path": self.firmware_path,
            "firmware_hash": self.firmware_hash,
            "analysis_duration": round(self.analysis_duration, 1),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "global_coverage": (
                self.global_coverage.to_dict()
                if self.global_coverage
                else {}
            ),
            "global_crashes": self.global_crashes,
            "global_duration_seconds": round(
                self.global_duration_seconds, 1
            ),
            "total_sps_generated": self.total_sps_generated,
            "total_sps_verified": self.total_sps_verified,
            "confirmed_vulns": self.confirmed_vulns,
            "needs_review": self.needs_review,
            "false_positives": self.false_positives,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "errors": self.errors,
        }

    def to_sarif(self) -> dict:
        """Convert to SARIF v2.1.0 format.

        SARIF (Static Analysis Results Interchange Format) is an
        OASIS standard compatible with GitHub Code Scanning,
        DefectDojo, and other security tools.
        """
        results = []
        for vuln in self.confirmed_vulns:
            crash_info = vuln.get("crash_info", {})
            result = {
                "ruleId": vuln.get("cwe", "CWE-unknown"),
                "level": "error",
                "message": {
                    "text": (
                        vuln.get("poc_guidance", "")
                        or vuln.get("notes", "")
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": self.firmware_path
                            },
                            "region": {
                                "startLine": 0,
                                "byteOffset": vuln.get(
                                    "sp_target_addr", 0
                                ),
                            },
                        }
                    }
                ],
                "properties": {
                    "sp_id": vuln.get("sp_id", ""),
                    "status": vuln.get("status", ""),
                    "crash_type": crash_info.get(
                        "crash_type", ""
                    ),
                    "crash_address": crash_info.get(
                        "crash_address", ""
                    ),
                },
            }
            results.append(result)

        for nr in self.needs_review:
            results.append(
                {
                    "ruleId": nr.get("cwe", "CWE-unknown"),
                    "level": "warning",
                    "message": {
                        "text": nr.get("notes", "Needs manual review")
                    },
                    "properties": {
                        "sp_id": nr.get("sp_id", ""),
                        "status": "NEEDS_REVIEW",
                    },
                }
            )

        return {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/"
                "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "FuzzingBrain",
                            "version": "2.0",
                            "informationUri": (
                                "https://github.com/FuzzingBrain"
                            ),
                        }
                    },
                    "invocations": [
                        {
                            "startTimeUtc": self.started_at,
                            "endTimeUtc": self.completed_at,
                            "executionSuccessful": len(
                                self.errors
                            )
                            == 0,
                        }
                    ],
                    "results": results,
                }
            ],
        }


@dataclass
class PhaseProgress:
    """Progress tracking for a pipeline phase."""

    name: str = ""
    total: int = 0
    completed: int = 0
    errors: int = 0
    started_at: float = 0.0
    eta_seconds: float = 0.0

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.completed / self.total) * 100

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.time() - self.started_at

    @property
    def is_complete(self) -> bool:
        return self.completed >= self.total

    def render_bar(self, width: int = PROGRESS_BAR_WIDTH) -> str:
        """Render an ASCII progress bar."""
        filled = int(self.percent / 100 * width)
        bar = "█" * filled + "░" * (width - filled)
        eta_str = (
            f" ETA {self.eta_seconds:.0f}s"
            if self.eta_seconds > 0
            else ""
        )
        return (
            f"[{bar}] {self.completed}/{self.total} "
            f"({self.percent:.0f}%) {self.errors} err{eta_str}"
        )


# =============================================================================
# FuzzerOrchestrator
# =============================================================================

class FuzzerOrchestrator:
    """Coordinates Global Fuzzer + SP Fuzzer in a 4-phase pipeline.

    The orchestrator manages the complete lifecycle:
    1. Global exploration → hotspots + crashes
    2. SP generation from hotspots
    3. Parallel SP verification with snapshot fast-reset
    4. Report generation (SARIF + human-readable)

    Features:
    - Progress visualization with ETA per phase
    - Fault isolation: SP fuzzer crashes don't affect others
    - Resource control: limits concurrent QEMU instances
    - Checkpoint/resume: Ctrl+C safe, restart from last phase
    - SARIF-compatible output for security tool integration

    Usage:
        orch = FuzzerOrchestrator(
            global_fuzzer=GlobalFirmwareFuzzer(work_dir="/tmp/gf"),
            sp_fuzzer=SPFirmwareFuzzer(work_dir="/tmp/sf"),
            snapshot_manager=SnapshotManager(),
            sp_generator=my_sp_generator,
        )
        report = await orch.run("firmware.bin", attack_surfaces=[...])
    """

    def __init__(
        self,
        global_fuzzer: GlobalFirmwareFuzzer,
        sp_fuzzer: SPFirmwareFuzzer,
        snapshot_manager: SnapshotManager,
        sp_generator: Optional[Any] = None,
        max_parallel_sp: int = DEFAULT_MAX_PARALLEL_SP,
        global_duration_minutes: int = DEFAULT_GLOBAL_DURATION_MINUTES,
        checkpoint_dir: Optional[str] = None,
    ):
        """
        Args:
            global_fuzzer: GlobalFirmwareFuzzer instance.
            sp_fuzzer: SPFirmwareFuzzer instance.
            snapshot_manager: SnapshotManager for VM state transfer.
            sp_generator: Optional SP generator (uses built-in if None).
            max_parallel_sp: Max concurrent SP fuzzers.
            global_duration_minutes: Duration for global fuzzing phase.
            checkpoint_dir: Directory for checkpoint files.
        """
        self.global_fuzzer = global_fuzzer
        self.sp_fuzzer = sp_fuzzer
        self.snapshot_mgr = snapshot_manager
        self.sp_generator = sp_generator
        self.max_parallel_sp = max_parallel_sp
        self.global_duration_minutes = global_duration_minutes
        self.checkpoint_dir = Path(
            checkpoint_dir or global_fuzzer.work_dir
        )

        # State
        self.results: List[dict] = []
        self._checkpoint: dict = {}
        self._shutdown_requested = False
        self._semaphore = asyncio.Semaphore(max_parallel_sp)

        # Progress tracking
        self._progress: Dict[str, PhaseProgress] = {}
        self._report: Optional[FuzzingReport] = None

        # Register signal handlers for graceful interrupt
        self._setup_signal_handlers()

    # ------------------------------------------------------------------
    # Public API — Main Pipeline
    # ------------------------------------------------------------------

    async def run(
        self,
        firmware_path: str,
        attack_surfaces: List[dict],
        resume: bool = True,
    ) -> FuzzingReport:
        """Run the complete dual-layer fuzzing pipeline.

        Args:
            firmware_path: Path to firmware binary.
            attack_surfaces: List of attack surface dicts.
            resume: If True, try to resume from checkpoint.

        Returns:
            FuzzingReport with all findings.
        """
        abs_path = os.path.abspath(firmware_path)
        overall_start = time.time()

        self._report = FuzzingReport(
            firmware_path=abs_path,
            firmware_hash=self._hash_file(abs_path),
        )

        # Try to resume from checkpoint
        if resume:
            checkpoint = self._load_checkpoint()
            if checkpoint:
                logger.info(
                    "FuzzerOrchestrator: resuming from checkpoint "
                    f"(phase={checkpoint.get('last_phase', '?')})"
                )
                self._checkpoint = checkpoint

        logger.info(
            f"FuzzerOrchestrator: starting pipeline for "
            f"{os.path.basename(abs_path)}"
        )
        self._print_header(f"DUAL-LAYER FUZZING: {os.path.basename(abs_path)}")

        try:
            # ── Phase 1: Global Exploration ─────────────────────────
            last_phase = self._checkpoint.get("last_phase", "")
            if last_phase in ("", "phase1"):
                self._print_phase("Phase 1/4", "Global Exploration (AFL++ QEMU-mode)")
                phase1_result = await self._run_global_phase(
                    abs_path,
                    attack_surfaces,
                    duration_minutes=self.global_duration_minutes,
                )
                self._checkpoint["phase1"] = {
                    "fuzzer_id": phase1_result.fuzzer_id,
                    "coverage_edges": (
                        phase1_result.coverage.edges
                        if phase1_result.coverage
                        else 0
                    ),
                    "crashes_found": len(phase1_result.crashes),
                    "hotspots_count": len(phase1_result.hotspots),
                }
                self._save_checkpoint("phase1")
            else:
                logger.info(
                    "Phase 1: skipped (resuming from checkpoint)"
                )
                phase1_result = GlobalResult(
                    **self._checkpoint.get("phase1_result", {})
                )

            self._report.global_coverage = phase1_result.coverage
            self._report.global_crashes = [
                c.to_dict() for c in phase1_result.crashes
            ]
            self._report.global_duration_seconds = (
                phase1_result.duration_seconds
            )

            # ── Phase 2: SP Generation ──────────────────────────────
            if last_phase in ("", "phase1", "phase2"):
                self._print_phase("Phase 2/4", "SP Generation (hotspots → LLM analysis)")
                sp_list = await self._run_sp_generation_phase(
                    phase1_result,
                    attack_surfaces,
                )
                self._checkpoint["phase2"] = {
                    "sp_count": len(sp_list),
                    "sp_ids": [s.get("sp_id", "") for s in sp_list],
                }
                self._checkpoint["sp_list"] = sp_list
                self._save_checkpoint("phase2")
            else:
                logger.info(
                    "Phase 2: skipped (resuming from checkpoint)"
                )
                sp_list = self._checkpoint.get("sp_list", [])

            self._report.total_sps_generated = len(sp_list)

            # ── Phase 3: SP Verification ────────────────────────────
            if last_phase in ("", "phase1", "phase2", "phase3"):
                self._print_phase("Phase 3/4", f"SP Verification (parallel, max {self.max_parallel_sp})")

                # Create baseline snapshot for fast SP restore
                baseline_snap = (
                    self.snapshot_mgr.get_or_create_baseline(
                        abs_path,
                        arch=attack_surfaces[0].get("arch", "")
                        if attack_surfaces
                        else "",
                    )
                )

                verified_results = await self._run_sp_verification_phase(
                    abs_path,
                    sp_list,
                    baseline_snap,
                    attack_surfaces[0] if attack_surfaces else {},
                )
                self._checkpoint["phase3"] = {
                    "verified_count": len(verified_results)
                }
                self._save_checkpoint("phase3")
            else:
                logger.info(
                    "Phase 3: skipped (resuming from checkpoint)"
                )
                verified_results = []

            self._report.total_sps_verified = len(verified_results)
            self._categorize_results(verified_results)

            # ── Phase 4: Report ─────────────────────────────────────
            self._print_phase("Phase 4/4", "Report Generation")
            self._generate_report(verified_results)

        except KeyboardInterrupt:
            logger.warning(
                "FuzzerOrchestrator: interrupted by user — "
                "saving checkpoint"
            )
            self._save_checkpoint("interrupted")
            self._report.errors.append(
                "Pipeline interrupted by user"
            )
        except Exception as e:
            logger.error(
                f"FuzzerOrchestrator: pipeline error: {e}\n"
                f"{traceback.format_exc()}"
            )
            self._report.errors.append(str(e))

        self._report.analysis_duration = time.time() - overall_start
        self._report.completed_at = datetime.now().isoformat()

        self._print_summary(self._report)
        return self._report

    # ------------------------------------------------------------------
    # Phase 1: Global Exploration
    # ------------------------------------------------------------------

    async def _run_global_phase(
        self,
        firmware_path: str,
        attack_surfaces: List[dict],
        duration_minutes: int = 10,
    ) -> GlobalResult:
        """Phase 1: Run Global Fuzzer for broad exploration.

        Starts AFL++ QEMU-mode fuzzers for each attack surface,
        runs for `duration_minutes`, then collects hotspots and
        crashes.
        """
        result = GlobalResult()
        fuzzer_ids = []
        start = time.time()

        # Start global fuzzers for each attack surface
        for i, attack_surface in enumerate(attack_surfaces):
            proto = attack_surface.get("protocol", "stdin")
            arch = attack_surface.get("arch", "")

            try:
                fid = self.global_fuzzer.start(
                    binary_path=firmware_path,
                    attack_surface=attack_surface,
                    arch=arch,
                )
                fuzzer_ids.append(fid)
                self._print_progress(
                    f"  Started global fuzzer [{fid[:12]}] "
                    f"for {proto}"
                )
            except Exception as e:
                logger.error(
                    f"Failed to start global fuzzer for "
                    f"{proto}: {e}"
                )
                self._report.errors.append(
                    f"Global fuzzer start failed ({proto}): {e}"
                )

        if not fuzzer_ids:
            result.duration_seconds = time.time() - start
            return result

        # Monitor loop — run for duration_minutes
        duration_sec = duration_minutes * 60
        check_interval = 30  # Status check every 30s
        elapsed = 0

        logger.info(
            f"Global fuzzing: {len(fuzzer_ids)} instances, "
            f"duration={duration_minutes}min"
        )

        while elapsed < duration_sec and not self._shutdown_requested:
            await asyncio.sleep(check_interval)
            elapsed = time.time() - start

            # Print progress
            for fid in fuzzer_ids:
                try:
                    status = self.global_fuzzer.status(fid)
                    cov_pct = status.get("coverage_percent", 0)
                    edges = status.get("edges_covered", 0)
                    crashed = status.get("crashes_found", 0)
                    plat = " [PLATEAU]" if status.get(
                        "is_plateaued"
                    ) else ""

                    remaining = max(0, duration_sec - elapsed)
                    self._print_progress(
                        f"  [{fid[:8]}] cvg={cov_pct:.2f}% "
                        f"edges={edges} crashes={crashed} "
                        f"ETA={remaining:.0f}s{plat}"
                    )
                except Exception:
                    pass

        # Collect results
        merged_coverages = []
        for fid in fuzzer_ids:
            try:
                # Coverage
                cov = self.global_fuzzer.get_coverage(fid)
                merged_coverages.append(cov)

                # Crashes
                crashes = self.global_fuzzer.get_crashes(fid)
                result.crashes.extend(crashes)

                # Hotspots
                hotspots = self.global_fuzzer.get_hotspots(fid)
                result.hotspots.extend(hotspots)

                # Trend
                trend = self.global_fuzzer.get_coverage_trend(
                    fid, minutes=duration_minutes
                )
                result.coverage_trend = trend

                # Check plateau
                result.plateaued = (
                    self.global_fuzzer.is_plateaued(fid)
                )

                # Export corpus
                corpus_dir = (
                    self.global_fuzzer.work_dir
                    / fid
                    / "exported_corpus"
                )
                exported = self.global_fuzzer.export_corpus(
                    fid, str(corpus_dir)
                )
                if exported > 0:
                    result.corpus_path = str(corpus_dir)

            except Exception as e:
                logger.error(
                    f"Failed to collect results from {fid}: {e}"
                )

        result.coverage = CoverageInfo.merge(merged_coverages)
        result.duration_seconds = time.time() - start

        # Stop all global fuzzers
        for fid in fuzzer_ids:
            try:
                self.global_fuzzer.stop(fid)
            except Exception:
                pass

        self._print_progress(
            f"  Complete: {len(result.crashes)} crashes, "
            f"{len(result.hotspots)} hotspots, "
            f"{result.duration_seconds:.0f}s"
        )

        return result

    # ------------------------------------------------------------------
    # Phase 2: SP Generation
    # ------------------------------------------------------------------

    async def _run_sp_generation_phase(
        self,
        global_result: GlobalResult,
        attack_surfaces: List[dict],
    ) -> List[dict]:
        """Phase 2: Generate Suspicious Points from global fuzzing results.

        Combines multiple signals:
        1. Coverage hotspots (frequently executed, no crash)
        2. Global fuzzer crash locations
        3. Attack surface entry points
        4. LLM analysis of decompiled hotspot functions
        """
        sp_list: List[dict] = []

        # 1. SPs from global fuzzer crashes
        for crash in global_result.crashes:
            sp = {
                "sp_id": f"SP-CRASH-{crash.crash_id}",
                "function_name": crash.func_where,
                "func_addr": crash.crash_address,
                "description": (
                    f"Crash discovered by global fuzzer: "
                    f"{crash.crash_type} at "
                    f"0x{crash.crash_address:x}"
                ),
                "cwe": self._crash_type_to_cwe(
                    crash.crash_type
                ),
                "priority": "P0",
                "source": "global_fuzzer_crash",
                "crash_info": crash.to_dict(),
            }
            sp_list.append(sp)

        # 2. SPs from coverage hotspots
        for hotspot in global_result.hotspots[
            :50
        ]:  # Cap at 50
            func_addr = hotspot.get("func_addr", 0)
            func_name = hotspot.get(
                "func_name", f"FUN_{func_addr:08x}"
            )

            sp = {
                "sp_id": f"SP-HOT-{uuid.uuid4().hex[:6]}",
                "function_name": func_name,
                "func_addr": func_addr,
                "description": (
                    f"Coverage hotspot: {hotspot.get('hit_count', 0)} "
                    f"executions, {hotspot.get('edge_density', 0):.0%} "
                    f"edge density"
                ),
                "cwe": "CWE-unknown",
                "priority": (
                    "P1"
                    if hotspot.get("has_dangerous_calls")
                    else "P2"
                ),
                "source": "coverage_hotspot",
                "hotspot_info": hotspot,
            }
            sp_list.append(sp)

        # 3. SPs from attack surface entry points
        for attack_surface in attack_surfaces:
            entry_funcs = attack_surface.get(
                "entry_functions", []
            )
            for func_name in entry_funcs[:10]:
                sp = {
                    "sp_id": f"SP-ENTRY-{uuid.uuid4().hex[:6]}",
                    "function_name": func_name,
                    "func_addr": attack_surface.get(
                        "entry_addrs", {}
                    ).get(func_name, 0),
                    "description": (
                        f"Attack surface entry point: "
                        f"{attack_surface.get('protocol', '')} "
                        f"{func_name}"
                    ),
                    "cwe": "CWE-unknown",
                    "priority": "P1",
                    "source": "attack_surface_entry",
                    "attack_surface": attack_surface,
                }
                sp_list.append(sp)

        # 4. If we have a real SP generator, use it
        if self.sp_generator:
            try:
                llm_sps = await self._call_sp_generator(
                    global_result, attack_surfaces
                )
                sp_list.extend(llm_sps)
            except Exception as e:
                logger.error(
                    f"SP generator failed: {e}"
                )

        # Deduplicate by function address
        seen_addrs: Set[int] = set()
        deduped = []
        for sp in sp_list:
            addr = sp.get("func_addr", 0)
            if addr and addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            deduped.append(sp)

        # Sort by priority
        priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        deduped.sort(
            key=lambda s: priority_order.get(
                s.get("priority", "P3"), 3
            )
        )

        self._print_progress(
            f"  Generated {len(sp_list)} SPs → "
            f"{len(deduped)} after dedup "
            f"(P0:{sum(1 for s in deduped if s.get('priority')=='P0')} "
            f"P1:{sum(1 for s in deduped if s.get('priority')=='P1')})"
        )

        return deduped

    # ------------------------------------------------------------------
    # Phase 3: SP Verification
    # ------------------------------------------------------------------

    async def _run_sp_verification_phase(
        self,
        firmware_path: str,
        sp_list: List[dict],
        baseline_snapshot: str,
        attack_surface: dict,
    ) -> List[dict]:
        """Phase 3: Parallel SP verification with fault isolation.

        Runs up to max_parallel_sp SP fuzzers concurrently.
        Each SP gets:
        1. Snapshot restore from baseline (<5s)
        2. Dedicated fuzzing session (max_iterations)
        3. VerificationResult (CONFIRMED/NEEDS_REVIEW/FALSE_POSITIVE)

        Fault isolation: if one SP fuzzer crashes, others continue.
        """
        if not sp_list:
            return []

        progress = PhaseProgress(
            name="SP Verification",
            total=len(sp_list),
            started_at=time.time(),
        )
        self._progress["phase3"] = progress

        verified = []
        arch = attack_surface.get("arch", "")

        # Process SPs in batches for progress tracking
        for batch_start in range(
            0, len(sp_list), SP_BATCH_SIZE
        ):
            if self._shutdown_requested:
                break

            batch = sp_list[
                batch_start : batch_start + SP_BATCH_SIZE
            ]

            # Launch parallel SP verifications
            tasks = []
            for sp in batch:
                task = asyncio.create_task(
                    self._verify_single_sp(
                        firmware_path,
                        sp,
                        baseline_snapshot,
                        arch,
                    )
                )
                tasks.append(task)

            # Wait for batch completion
            batch_results = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            for i, result in enumerate(batch_results):
                sp = batch[i]
                if isinstance(result, Exception):
                    logger.error(
                        f"SP {sp.get('sp_id', '?')} verification "
                        f"failed: {result}"
                    )
                    verified.append(
                        {
                            "sp_id": sp.get("sp_id", ""),
                            "status": "FALSE_POSITIVE",
                            "error": str(result),
                            "notes": f"Verification crashed: {result}",
                        }
                    )
                    progress.errors += 1
                elif result is not None:
                    verified.append(result)

                progress.completed += 1

            # Update ETA
            if progress.completed > 0:
                elapsed = progress.elapsed_seconds
                rate = progress.completed / elapsed if elapsed > 0 else 0
                remaining = (
                    (progress.total - progress.completed) / rate
                    if rate > 0
                    else 0
                )
                progress.eta_seconds = remaining

            self._print_progress(
                f"  {progress.render_bar()}"
            )

        self._print_progress(
            f"  Verified {len(verified)} SPs "
            f"({sum(1 for v in verified if v.get('status')=='CONFIRMED')} confirmed, "
            f"{sum(1 for v in verified if v.get('status')=='NEEDS_REVIEW')} needs review, "
            f"{sum(1 for v in verified if v.get('status')=='FALSE_POSITIVE')} false positive)"
        )

        return verified

    async def _verify_single_sp(
        self,
        firmware_path: str,
        sp: dict,
        baseline_snapshot: str,
        arch: str,
    ) -> Optional[dict]:
        """Verify a single SP with fault isolation.

        Wrapped in its own try/except so one SP's failure
        doesn't affect others.
        """
        async with self._semaphore:
            sp_id = sp.get("sp_id", "unknown")
            try:
                # Create SP-specific snapshot from baseline
                sp_snap = self.snapshot_mgr.create_sp_snapshot(
                    baseline_snapshot,
                    sp,
                )

                # Start SP fuzzer
                fid = self.sp_fuzzer.start(
                    binary_path=firmware_path,
                    suspicious_point=sp,
                    arch=arch,
                    global_corpus_path=(
                        self._checkpoint.get("phase1", {}).get(
                            "corpus_path", ""
                        )
                    ),
                )

                # Run verification
                result = await self.sp_fuzzer.verify_sp(
                    fid, sp, firmware_path, arch
                )

                # Stop SP fuzzer
                self.sp_fuzzer.stop(fid)

                return result.to_dict()

            except Exception as e:
                logger.error(
                    f"SP {sp_id}: verification error: {e}"
                )
                return {
                    "sp_id": sp_id,
                    "status": "FALSE_POSITIVE",
                    "error": str(e),
                    "notes": f"Verification failed: {e}",
                }

    # ------------------------------------------------------------------
    # Phase 4: Report Generation
    # ------------------------------------------------------------------

    def _generate_report(
        self, verified_results: List[dict]
    ):
        """Generate the final FuzzingReport."""
        if self._report is None:
            return

        self._categorize_results(verified_results)

        # Generate summary (LLM if available, else template)
        self._report.summary = self._build_summary()

        # Recommendations
        self._report.recommendations = (
            self._build_recommendations()
        )

        # Save SARIF report
        sarif_path = (
            self.checkpoint_dir / "fuzzing_report.sarif"
        )
        try:
            sarif_path.write_text(
                json.dumps(
                    self._report.to_sarif(),
                    indent=2,
                    ensure_ascii=False,
                )
            )
            logger.info(
                f"SARIF report saved to {sarif_path}"
            )
        except Exception as e:
            logger.error(f"Failed to save SARIF report: {e}")

        # Save JSON report
        json_path = (
            self.checkpoint_dir / "fuzzing_report.json"
        )
        try:
            json_path.write_text(
                json.dumps(
                    self._report.to_dict(),
                    indent=2,
                    ensure_ascii=False,
                )
            )
            logger.info(
                f"JSON report saved to {json_path}"
            )
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")

    def _categorize_results(
        self, verified_results: List[dict]
    ):
        """Categorize verification results into confirmed/review/fp."""
        if self._report is None:
            return

        self._report.confirmed_vulns = []
        self._report.needs_review = []
        self._report.false_positives = []

        for vr in verified_results:
            status = vr.get("status", "FALSE_POSITIVE")
            if status == "CONFIRMED":
                self._report.confirmed_vulns.append(vr)
            elif status == "NEEDS_REVIEW":
                self._report.needs_review.append(vr)
            else:
                self._report.false_positives.append(vr)

    def _build_summary(self) -> str:
        """Build executive summary text."""
        if self._report is None:
            return ""

        confirmed = len(self._report.confirmed_vulns)
        needs_review = len(self._report.needs_review)
        fp = len(self._report.false_positives)
        cvg = (
            self._report.global_coverage.coverage_percent
            if self._report.global_coverage
            else 0
        )

        parts = [
            f"FuzzingBrain dual-layer fuzzing analysis of "
            f"{os.path.basename(self._report.firmware_path)} "
            f"completed in {self._report.analysis_duration:.0f}s.",
            "",
            f"## Results",
            f"- **{confirmed} CONFIRMED** vulnerabilities found",
            f"- **{needs_review}** need manual review",
            f"- **{fp}** false positives eliminated",
            f"- Global coverage: **{cvg:.2f}%**",
            "",
            f"## Confirmed Vulnerabilities",
        ]

        if confirmed > 0:
            for i, vuln in enumerate(
                self._report.confirmed_vulns[:10], 1
            ):
                crash = vuln.get("crash_info", {})
                parts.append(
                    f"{i}. **{vuln.get('sp_id', '?')}** — "
                    f"{crash.get('crash_type', 'unknown')} at "
                    f"{crash.get('crash_address', '?')} "
                    f"({vuln.get('poc_guidance', '')[:100]})"
                )
        else:
            parts.append(
                "No confirmed vulnerabilities in this analysis."
            )

        return "\n".join(parts)

    def _build_recommendations(self) -> List[str]:
        """Build prioritized remediation recommendations."""
        recs = []

        if self._report is None:
            return recs

        confirmed = self._report.confirmed_vulns

        # Count by type
        crash_types: Dict[str, int] = defaultdict(int)
        for vuln in confirmed:
            crash = vuln.get("crash_info", {})
            ctype = crash.get("crash_type", "unknown")
            crash_types[ctype] += 1

        if crash_types.get("stack-buffer-overflow", 0) > 0:
            recs.append(
                "P0: Replace unbounded memory copies (strcpy/sprintf) "
                "with bounded alternatives (strncpy/snprintf)"
            )

        if (
            crash_types.get("heap-buffer-overflow", 0) > 0
            or crash_types.get("use-after-free", 0) > 0
        ):
            recs.append(
                "P0: Implement bounds checking for heap allocations "
                "and review all free() call sites"
            )

        if crash_types.get("SIGSEGV", 0) > 0:
            recs.append(
                "P1: Add NULL pointer checks before dereference "
                "in network-facing code paths"
            )

        if self._report.needs_review:
            recs.append(
                f"P2: Manually review {len(self._report.needs_review)} "
                f"suspicious points that couldn't be automatically "
                f"confirmed"
            )

        recs.append(
            "P3: Integrate fuzzing results into CI/CD pipeline "
            "for continuous regression testing"
        )

        return recs

    # ------------------------------------------------------------------
    # Progress Visualization
    # ------------------------------------------------------------------

    def _print_header(self, text: str):
        """Print a formatted header."""
        line = "=" * 60
        print(f"\n{line}\n  {text}\n{line}")

    def _print_phase(self, phase: str, description: str):
        """Print a phase header."""
        print(f"\n{'─' * 60}")
        print(f"  {phase}: {description}")
        print(f"{'─' * 60}")

    def _print_progress(self, text: str):
        """Print a progress message."""
        print(f"  {text}")

    def _print_summary(self, report: FuzzingReport):
        """Print final summary to console."""
        self._print_header("ANALYSIS COMPLETE")
        print(f"  Duration:    {report.analysis_duration:.0f}s")
        print(
            f"  Coverage:    {report.global_coverage.coverage_percent:.2f}%"
            if report.global_coverage
            else "  Coverage:    N/A"
        )
        print(f"  SPs analyzed: {report.total_sps_verified}")
        print(
            f"  CONFIRMED:    {len(report.confirmed_vulns)}"
        )
        print(
            f"  Needs review: {len(report.needs_review)}"
        )
        print(
            f"  False pos:    {len(report.false_positives)}"
        )
        print(f"  Errors:       {len(report.errors)}")
        print()

        if report.confirmed_vulns:
            print("  Top Confirmed Vulnerabilities:")
            for i, vuln in enumerate(
                report.confirmed_vulns[:5], 1
            ):
                crash = vuln.get("crash_info", {})
                print(
                    f"  {i}. [{vuln.get('sp_id', '?')}] "
                    f"{crash.get('crash_type', '?')} — "
                    f"{vuln.get('notes', '')[:100]}"
                )

        # Output file paths
        print(f"\n  Reports:")
        print(
            f"    JSON:  {self.checkpoint_dir / 'fuzzing_report.json'}"
        )
        print(
            f"    SARIF: {self.checkpoint_dir / 'fuzzing_report.sarif'}"
        )

    # ------------------------------------------------------------------
    # Checkpoint / Resume
    # ------------------------------------------------------------------

    def _save_checkpoint(self, phase: str):
        """Save pipeline state for resume after interrupt."""
        checkpoint = {
            "last_phase": phase,
            "firmware_path": (
                self._report.firmware_path
                if self._report
                else ""
            ),
            "timestamp": datetime.now().isoformat(),
            **{
                k: v
                for k, v in self._checkpoint.items()
                if k != "sp_list"  # sp_list can be large
            },
        }
        # Save sp_list separately if small enough
        sp_list = self._checkpoint.get("sp_list", [])
        if sp_list and len(json.dumps(sp_list)) < 100_000:
            checkpoint["sp_list"] = sp_list

        checkpoint_path = (
            self.checkpoint_dir / CHECKPOINT_FILE
        )
        try:
            checkpoint_path.parent.mkdir(
                parents=True, exist_ok=True
            )
            checkpoint_path.write_text(
                json.dumps(
                    checkpoint, indent=2, ensure_ascii=False
                )
            )
            logger.debug(
                f"Checkpoint saved: {phase}"
            )
        except Exception as e:
            logger.warning(
                f"Failed to save checkpoint: {e}"
            )

    def _load_checkpoint(self) -> Optional[dict]:
        """Load a previous checkpoint if it exists."""
        checkpoint_path = (
            self.checkpoint_dir / CHECKPOINT_FILE
        )
        if not checkpoint_path.exists():
            return None

        try:
            data = json.loads(
                checkpoint_path.read_text(encoding="utf-8")
            )
            # Check if checkpoint is stale (>24h)
            ts = data.get("timestamp", "")
            if ts:
                try:
                    created = datetime.fromisoformat(ts)
                    age = (
                        datetime.now() - created
                    ).total_seconds()
                    if age > 86400:  # 24 hours
                        logger.warning(
                            "Checkpoint is >24h old — starting fresh"
                        )
                        return None
                except Exception:
                    pass
            return data
        except Exception as e:
            logger.warning(
                f"Failed to load checkpoint: {e}"
            )
            return None

    def _setup_signal_handlers(self):
        """Register signal handlers for graceful shutdown."""

        def _handler(signum, frame):
            logger.warning(
                "Received interrupt signal — "
                "shutting down gracefully..."
            )
            self._shutdown_requested = True
            self._save_checkpoint("interrupted")

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _call_sp_generator(
        self,
        global_result: GlobalResult,
        attack_surfaces: List[dict],
    ) -> List[dict]:
        """Call an external SP generator (LLM-based).

        Wraps the call in an executor since it's typically synchronous.
        """
        if self.sp_generator is None:
            return []

        try:
            loop = asyncio.get_running_loop()
            sps = await loop.run_in_executor(
                None,
                lambda: self.sp_generator.generate(
                    hotspots=global_result.hotspots,
                    crashes=global_result.crashes,
                    attack_surfaces=attack_surfaces,
                ),
            )
            return sps or []
        except Exception as e:
            logger.error(f"SP generator call failed: {e}")
            return []

    @staticmethod
    def _crash_type_to_cwe(crash_type: str) -> str:
        """Map crash type to CWE identifier."""
        mapping = {
            "stack-buffer-overflow": "CWE-121",
            "heap-buffer-overflow": "CWE-122",
            "use-after-free": "CWE-416",
            "double-free": "CWE-415",
            "null-deref": "CWE-476",
            "global-buffer-overflow": "CWE-122",
            "SIGSEGV": "CWE-121",
            "SIGABRT": "CWE-617",
            "SIGILL": "CWE-440",
        }
        return mapping.get(crash_type, "CWE-unknown")

    @staticmethod
    def _hash_file(filepath: str) -> str:
        """Compute a fast file hash for identification."""
        if not filepath or not os.path.exists(filepath):
            return ""
        try:
            import hashlib
            sha = hashlib.sha256()
            with open(filepath, "rb") as f:
                sha.update(f.read(1024 * 1024))
            return sha.hexdigest()[:16]
        except Exception:
            return ""
