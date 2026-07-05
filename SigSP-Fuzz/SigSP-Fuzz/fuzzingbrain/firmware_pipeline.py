"""
End-to-End Firmware Vulnerability Discovery Pipeline.

Orchestrates the complete firmware.bin → FinalReport flow:
  Phase 1: Static extraction (binwalk + Ghidra + callgraph)
  Phase 2: Attack surface identification + direction planning
  Phase 3: Multi-agent cross-examination SP analysis
  Phase 4: Layered dynamic verification (L1→L2→L3)
  Report:  Final JSON + Markdown report generation

Checkpoint strategy — each phase saves its output; resume skips completed phases.

Usage:
    pipeline = FirmwarePipeline(
        binwalk_bin="binwalk",
        ghidra_headless="/opt/ghidra/support/analyzeHeadless",
        firmae_dir="/opt/FirmAE",
    )
    report = pipeline.run("firmware.bin", firmware_name="Netgear_R7000")
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from loguru import logger

from .llms import LLMClient
from .static.models import (
    AnalysisResult,
    BinaryInfo,
    CallGraph,
    ExtractResult,
    FunctionInfo,
    StringRef,
)
from .static.extractor import FirmwareExtractor
from .static.objdump_analyzer import AnalyzerFactory
from .static.callgraph import CallGraphBuilder
from .attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    DirectionResult,
)
from .attack_surface.identifier import AttackSurfaceIdentifier
from .attack_surface.direction_planner import DirectionPlanner
from .agents.firmware.pipeline import Phase3Pipeline
from .agents.firmware.sp_models import Phase3Result, VerifiedSP
from .verifier.pipeline import Phase4Pipeline
from .verifier.models import (
    CrashInfo,
    FinalReport,
    Phase4Result,
    Phase4Statistics,
    PoC,
    ReportMetadata,
    VerificationResult,
    VulnerabilityEntry,
)
from .reporter.generator import ReportGenerator
from .firmware_profile import FirmwareProfile, KnownCVE


class FirmwarePipeline:
    """End-to-end orchestrator: firmware.bin → FinalReport.

    Coordinates all four phases + report generation with checkpoint/resume
    to allow restarting from any intermediate stage.

    Checkpoint files (saved under output_dir/firmware_name/):
      phase1_result.json        — aggregated AnalysisResult (functions+callgraph+strings)
      phase2_attack_surfaces.json — AttackSurfaceResult
      phase2_directions.json      — DirectionResult
      phase3_result.json          — Phase3Result (VerifiedSP[])
      phase4_result.json          — Phase4Result
      final_report.json           — FinalReport (JSON)
      final_report.md             — FinalReport (Markdown)

    Usage:
        pipeline = FirmwarePipeline(
            firmae_dir="/opt/FirmAE",
            output_dir="results",
        )
        report = pipeline.run("firmware.bin", firmware_name="Netgear_R7000")
        print(f"Found {report.count} vulnerabilities")
    """

    VALID_PHASES = {"phase1", "phase2", "phase3", "phase4"}

    def __init__(
        self,
        # Shared infrastructure
        llm_client: Optional[LLMClient] = None,

        # Phase 1 tool paths
        binwalk_bin: str = "binwalk",
        ghidra_headless: Optional[str] = None,

        # Phase 4 tool paths
        firmae_dir: Optional[str] = None,
        qemu_dir: str = "/usr/bin",

        # 🆕 Dual-layer fuzzing (Phase 4 upgrade)
        use_dual_layer_fuzzing: bool = False,
        dual_layer_timeout_minutes: int = 10,
        dual_layer_max_parallel: int = 4,

        # Output
        output_dir: str = "results",

        # Firmware profile (optional — YAML with architecture, entry points, CVEs)
        firmware_profile: Optional[FirmwareProfile] = None,

        # Tuning
        phase3_scope: str = "all",
        temperature: float = 0.3,
        max_tokens: int = 16000,
    ):
        # Tool paths
        self.binwalk_bin = binwalk_bin
        self.ghidra_headless = ghidra_headless
        self.firmae_dir = firmae_dir
        self.qemu_dir = qemu_dir
        self.use_dual_layer_fuzzing = use_dual_layer_fuzzing
        self.dual_layer_timeout_minutes = dual_layer_timeout_minutes
        self.dual_layer_max_parallel = dual_layer_max_parallel
        self.output_dir = Path(output_dir)

        # Firmware profile
        self.profile = firmware_profile

        # Tuning
        self.phase3_scope = phase3_scope
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Shared LLM client
        self.llm_client = llm_client or LLMClient()

        # Phase 1 tools (instantiated lazily or directly)
        self._extractor = FirmwareExtractor(binwalk_path=binwalk_bin)
        self._analyzer = AnalyzerFactory.create(ghidra_home=ghidra_headless)
        self._callgraph_builder = CallGraphBuilder()

        # Phase 1 dedup: skip duplicate binaries (symlinks, busybox aliases)
        self._seen_binary_hashes: Set[str] = set()

        # Phase 2 agents
        self._attack_surface_identifier = AttackSurfaceIdentifier(
            llm_client=self.llm_client,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self._direction_planner = DirectionPlanner(
            llm_client=self.llm_client,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Phase 3 pipeline
        self._phase3 = Phase3Pipeline(
            llm_client=self.llm_client,
            scope=phase3_scope,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Phase 4 pipeline
        self._phase4 = Phase4Pipeline(
            llm_client=self.llm_client,
            firmae_dir=firmae_dir,
            qemu_dir=qemu_dir,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Report generator
        self._reporter = ReportGenerator()

    # -- Public API ------------------------------------------------------------

    def run(
        self,
        firmware_path: str,
        firmware_name: Optional[str] = None,
        *,
        resume: bool = True,
        phases: Optional[Set[str]] = None,
    ) -> FinalReport:
        """Run the complete end-to-end pipeline.

        Args:
            firmware_path: Path to the firmware binary (.bin / .img / .chk).
            firmware_name: Human-readable name (auto-derived from filename if None).
            resume: If True, skip phases whose checkpoint files already exist.
            phases: Specific phases to run (None = all). E.g. {"phase3", "phase4"}.

        Returns:
            FinalReport with confirmed vulnerabilities, statistics, and metadata.
        """
        # Validate firmware_path
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            raise FileNotFoundError(f"Firmware not found: {firmware_path}")

        # Derive firmware name
        if firmware_name is None:
            firmware_name = fw_path.stem

        # Compute firmware hash (first 4KB for speed)
        firmware_hash = self._hash_firmware(firmware_path)

        # Set up output directories
        task_dir = self.output_dir / firmware_name
        task_dir.mkdir(parents=True, exist_ok=True)

        phases_to_run = phases or self.VALID_PHASES
        logger.info(
            f"FirmwarePipeline: {firmware_name} — "
            f"phases={sorted(phases_to_run)}, resume={resume}, "
            f"output={task_dir}"
        )

        # ---- Phase 1: Static Extraction -----------------------------------

        all_functions: List[FunctionInfo] = []
        all_attack_surfaces: List[AttackSurface] = []
        direction_result: Optional[DirectionResult] = None
        phase3_result: Optional[Phase3Result] = None
        phase4_result: Optional[Phase4Result] = None
        callgraph: Optional[CallGraph] = None

        phase1_path = task_dir / "phase1_result.json"
        if "phase1" in phases_to_run and not (resume and phase1_path.exists()):
            logger.info("=" * 60)
            logger.info("Phase 1: Static Extraction")
            logger.info("=" * 60)
            all_functions, callgraph = self._run_phase1(
                firmware_path, task_dir
            )
            self._save_phase1(
                phase1_path, all_functions, callgraph, firmware_name
            )
        elif phase1_path.exists():
            logger.info(f"Phase 1: Loading from checkpoint ({phase1_path})")
            all_functions, callgraph = self._load_phase1(phase1_path)
        elif "phase1" not in phases_to_run:
            logger.info("Phase 1: Skipped (not in requested phases)")

        # ---- Phase 2: Attack Surface + Directions -------------------------

        as_path = task_dir / "phase2_attack_surfaces.json"
        dir_path = task_dir / "phase2_directions.json"
        if "phase2" in phases_to_run and not (
            resume and as_path.exists() and dir_path.exists()
        ):
            logger.info("=" * 60)
            logger.info("Phase 2: Attack Surface + Direction Planning")
            logger.info("=" * 60)
            attack_surface_result, direction_result = self._run_phase2(
                all_functions, callgraph, task_dir
            )
            all_attack_surfaces = attack_surface_result.attack_surfaces
            self._save_json(attack_surface_result.to_dict(), as_path)
            self._save_json(direction_result.to_dict(), dir_path)
        elif as_path.exists() and dir_path.exists():
            logger.info("Phase 2: Loading from checkpoints")
            as_data = json.loads(as_path.read_text(encoding="utf-8"))
            attack_surface_result = AttackSurfaceResult.from_dict(as_data)
            all_attack_surfaces = attack_surface_result.attack_surfaces
            dir_data = json.loads(dir_path.read_text(encoding="utf-8"))
            direction_result = DirectionResult.from_dict(dir_data)
        elif "phase2" not in phases_to_run:
            logger.info("Phase 2: Skipped (not in requested phases)")

        # ---- Phase 3: Multi-Agent SP Analysis -----------------------------

        phase3_path = task_dir / "phase3_result.json"
        if "phase3" in phases_to_run and not (resume and phase3_path.exists()):
            logger.info("=" * 60)
            logger.info("Phase 3: Multi-Agent Cross-Examination")
            logger.info("=" * 60)
            if direction_result is None:
                raise RuntimeError(
                    "Phase 3 requires direction_result from Phase 2. "
                    "Run Phase 2 first or provide a checkpoint."
                )
            phase3_result = self._phase3.run(
                directions=direction_result,
                functions=all_functions,
                attack_surfaces=all_attack_surfaces,
            )
            self._phase3.save(phase3_result, phase3_path)
        elif phase3_path.exists():
            logger.info(f"Phase 3: Loading from checkpoint ({phase3_path})")
            phase3_result = self._phase3.load(phase3_path)
        elif "phase3" not in phases_to_run:
            logger.info("Phase 3: Skipped (not in requested phases)")

        # ---- Phase 4: Dynamic Verification --------------------------------

        phase4_path = task_dir / "phase4_result.json"
        if "phase4" in phases_to_run and not (resume and phase4_path.exists()):
            logger.info("=" * 60)
            if self.use_dual_layer_fuzzing:
                logger.info("Phase 4: Dual-Layer Fuzzing (Global AFL++ + SP targeted)")
            else:
                logger.info("Phase 4: Layered Dynamic Verification")
            logger.info("=" * 60)
            if phase3_result is None:
                raise RuntimeError(
                    "Phase 4 requires phase3_result. "
                    "Run Phase 3 first or provide a checkpoint."
                )
            if self.use_dual_layer_fuzzing:
                phase4_result = self._run_phase4_dual_layer(
                    verified_sps=phase3_result.verified_sps,
                    functions=all_functions,
                    attack_surfaces=all_attack_surfaces,
                    callgraph=callgraph,
                    firmware_path=firmware_path,
                    firmware_name=firmware_name,
                    task_dir=task_dir,
                )
            else:
                phase4_result = self._phase4.run(
                    verified_sps=phase3_result.verified_sps,
                    functions=all_functions,
                    attack_surfaces=all_attack_surfaces,
                    callgraph=callgraph,
                    firmware_path=firmware_path,
                    firmware_name=firmware_name,
                    task_dir=str(task_dir),
                )
            self._phase4.save(phase4_result, phase4_path)
        elif phase4_path.exists():
            logger.info(f"Phase 4: Loading from checkpoint ({phase4_path})")
            phase4_result = self._phase4.load(phase4_path)
        elif "phase4" not in phases_to_run:
            logger.info("Phase 4: Skipped (not in requested phases)")

        # ---- Report Generation --------------------------------------------

        logger.info("=" * 60)
        logger.info("Report Generation")
        logger.info("=" * 60)

        if phase4_result is None:
            raise RuntimeError(
                "Report requires phase4_result. "
                "Run Phase 4 first or provide a checkpoint."
            )

        final_report = self._build_final_report(
            phase3_result=phase3_result,
            phase4_result=phase4_result,
            all_functions=all_functions,
            all_attack_surfaces=all_attack_surfaces,
            firmware_name=firmware_name,
            firmware_hash=firmware_hash,
        )

        # Save reports
        json_report_path = task_dir / "final_report.json"
        md_report_path = task_dir / "final_report.md"
        self._reporter.to_json(final_report, json_report_path)
        self._reporter.to_markdown(final_report, md_report_path)

        logger.info(
            f"Pipeline complete: {final_report.count} vulnerabilities found, "
            f"{len(final_report.confirmed_vulnerabilities)} confirmed"
        )
        logger.info(f"Reports: {json_report_path}, {md_report_path}")

        return final_report

    # -- Phase 1 Implementation -----------------------------------------------

    def _run_phase1(
        self, firmware_path: str, task_dir: Path
    ) -> tuple:
        """Run static extraction: binwalk → Ghidra → callgraph."""
        extract_dir = task_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)

        # Step 1a: binwalk extraction
        logger.info("Step 1a: binwalk extraction...")
        extract_result = self._extractor.extract(
            str(firmware_path), str(extract_dir)
        )
        if not extract_result.success:
            logger.warning(
                f"binwalk extraction incomplete: {extract_result.error}"
            )

        binaries = extract_result.binaries
        logger.info(
            f"  Extracted {extract_result.file_count} files, "
            f"{len(binaries)} binaries found"
        )

        # Step 1b: Resolve binary base path.
        # binary.path from the extractor is relative to the .extracted dir
        # (e.g. "_ad1006.bin.extracted/squashfs-root/usr/sbin/setup.cgi").
        # We need to find the .extracted dir to resolve absolute paths.
        logger.info("Step 1b: Resolving extracted filesystem root...")
        extracted_root = self._resolve_extracted_root(extract_dir)
        logger.info(f"  Extracted root: {extracted_root}")

        # Resolve the base for binary paths (the .extracted directory)
        extracted_dirs = list(extract_dir.glob("_*.extracted"))
        if extracted_dirs:
            binary_base = extracted_dirs[0]
        else:
            binary_base = extract_dir
        logger.info(f"  Binary base: {binary_base}")

        # Step 1c: Ghidra/Objdump analysis per binary
        logger.info("Step 1c: Binary decompilation...")
        all_functions: List[FunctionInfo] = []
        all_strings: List[StringRef] = []
        callgraph = CallGraph(binary_path=firmware_path)

        for binary in binaries:
            # Apply profile-based binary filtering
            if self.profile and self.profile.should_skip_binary(binary.path):
                logger.debug(
                    f"  Skipping {binary.path} (profile filter)"
                )
                continue

            # Override auto-detected architecture from profile
            if self.profile:
                arch = self.profile.architecture
                binary.arch = arch.cpu
                binary.bits = arch.bits
                binary.endian = arch.endian

            binary_abs = str(binary_base / binary.path)
            binary_path_obj = Path(binary_abs)
            if not binary_path_obj.exists():
                logger.warning(
                    f"  {binary.path}: analysis failed — Binary not found: {binary_abs}"
                )
                continue

            # Skip symlinks (many are busybox aliases)
            if binary_path_obj.is_symlink():
                logger.debug(f"  Skipping {binary.path} (symlink)")
                continue

            # Dedup by file hash (first 64KB) to avoid re-analyzing identical files
            file_hash = self._hash_file_head(binary_abs)
            if file_hash in self._seen_binary_hashes:
                logger.debug(f"  Skipping {binary.path} (duplicate hash)")
                continue
            self._seen_binary_hashes.add(file_hash)

            analysis_dir = task_dir / "ghidra_output" / binary.path
            analysis_dir.mkdir(parents=True, exist_ok=True)

            try:
                result = self._analyzer.analyze_binary(
                    binary_path=binary_abs,
                    binary_info=binary,
                    output_dir=str(analysis_dir),
                )
                if result.success:
                    all_functions.extend(result.functions)
                    all_strings.extend(result.strings)
                    if result.callgraph:
                        # Merge into combined callgraph
                        for name, node in result.callgraph.nodes.items():
                            if name not in callgraph.nodes:
                                callgraph.nodes[name] = node
                    logger.info(
                        f"  {binary.path}: {result.function_count} functions"
                    )
                else:
                    logger.warning(
                        f"  {binary.path}: analysis failed — {result.error}"
                    )
            except Exception as e:
                logger.error(f"  {binary.path}: Ghidra error — {e}")

        # Step 1d: Build combined callgraph from functions if Ghidra didn't
        #          provide one (e.g., testing with mocks)
        if not callgraph.nodes and all_functions:
            logger.info("Step 1c: Building callgraph from function metadata...")
            callgraph = self._callgraph_builder.build(
                all_functions, binary_path=firmware_path
            )

        # Limit functions for Phase 2 LLM context:
        #   - Prioritize functions with unsafe calls
        #   - Truncate pseudo_code to 1200 chars max per function
        #   - Cap at 150 functions (fits in 128K token context: 150×1200≈180K chars≈45K tokens)
        MAX_FUNCTIONS = 150
        MAX_PSEUDOCODE_LEN = 1200

        # Sort: unsafe functions first, then by complexity
        all_functions.sort(key=lambda f: (not f.has_unsafe_calls, -f.complexity))

        if len(all_functions) > MAX_FUNCTIONS:
            logger.warning(
                f"Truncating functions for Phase 2: {len(all_functions)} → {MAX_FUNCTIONS} "
                f"(LLM context limit). Prioritized unsafe calls."
            )
            all_functions = all_functions[:MAX_FUNCTIONS]

        # Truncate pseudo_code in remaining functions
        for f in all_functions:
            if len(f.pseudo_code) > MAX_PSEUDOCODE_LEN:
                f.pseudo_code = (
                    f.pseudo_code[:MAX_PSEUDOCODE_LEN] + "\n... (truncated)"
                )

        total_pseudo_bytes = sum(len(f.pseudo_code) for f in all_functions)
        unsafe_count = sum(1 for f in all_functions if f.has_unsafe_calls)
        logger.info(
            f"Phase 1 complete: {len(all_functions)} functions "
            f"({unsafe_count} unsafe), "
            f"{len(all_strings)} strings, "
            f"{callgraph.node_count} callgraph nodes, "
            f"~{total_pseudo_bytes // 1000}KB pseudo_code total"
        )

        return all_functions, callgraph

    # -- Phase 2 Implementation -----------------------------------------------

    def _run_phase2(
        self,
        functions: List[FunctionInfo],
        callgraph: Optional[CallGraph],
        task_dir: Path,
    ) -> tuple:
        """Run attack surface identification and direction planning."""
        # Also load strings if available from Phase 1 checkpoint
        strings: List[StringRef] = []
        phase1_path = task_dir / "phase1_result.json"
        if phase1_path.exists():
            try:
                data = json.loads(phase1_path.read_text(encoding="utf-8"))
                strings = [
                    StringRef(**s)
                    for s in data.get("strings", [])
                ]
            except Exception:
                pass

        # Step 2a: Attack surface identification
        logger.info("Step 2a: Identifying attack surfaces...")
        attack_surface_result = self._attack_surface_identifier.identify(
            functions=functions,
            callgraph=callgraph,
            strings=strings,
        )
        logger.info(
            f"  Found {attack_surface_result.count} attack surfaces"
        )

        # Step 2b: Direction planning
        logger.info("Step 2b: Planning analysis directions...")
        direction_result = self._direction_planner.plan(
            attack_surfaces=attack_surface_result.attack_surfaces,
            functions=functions,
            callgraph=callgraph,
        )
        logger.info(
            f"  Created {direction_result.count} directions "
            f"({len(direction_result.high_priority_directions)} high priority)"
        )

        return attack_surface_result, direction_result

    # -- Phase 4 Dual-Layer Fuzzing (new upgrade path) -----------------------

    def _run_phase4_dual_layer(
        self,
        verified_sps,
        functions,
        attack_surfaces,
        callgraph,
        firmware_path: str,
        firmware_name: str,
        task_dir,
    ):
        """Run Phase 4 via dual-layer fuzzing (Global AFL++ + SP targeted).

        Falls back to legacy Phase4Pipeline if imports fail.
        """
        from .verifier.models import (
            CrashInfo,
            Phase4Result,
            Phase4Statistics,
            VerificationResult,
        )

        try:
            from .global_fuzzer import GlobalFirmwareFuzzer
            from .sp_fuzzer import SPFirmwareFuzzer
            from .snapshot_manager import SnapshotManager
            from .fuzzer_orchestrator import FuzzerOrchestrator

            fuzz_work = task_dir / "fuzz_work"
            snap_dir = task_dir / "snapshots"

            # Build attack surface dicts
            as_dicts = []
            for a in (attack_surfaces or []):
                if isinstance(a, dict):
                    as_dicts.append(a)
                elif hasattr(a, "to_dict"):
                    as_dicts.append(a.to_dict())
                else:
                    as_dicts.append({
                        "protocol": getattr(a, "protocol", "stdin"),
                        "port": getattr(a, "port", 0),
                    })
            if not as_dicts:
                as_dicts = [{"protocol": "stdin", "port": 0}]

            # Build SP list from Phase 3 verified SPs
            sp_list = []
            for vsp in (verified_sps or []):
                sp_list.append({
                    "sp_id": getattr(vsp, "sp_id", ""),
                    "function_name": getattr(vsp, "function_name", ""),
                    "func_addr": getattr(vsp, "function_address",
                                        getattr(vsp, "address", 0)),
                    "description": getattr(vsp, "description", ""),
                    "cwe": getattr(vsp, "cwe", "CWE-unknown"),
                    "priority": getattr(vsp, "priority", "P1"),
                    "attack_surface": as_dicts[0] if as_dicts else {},
                })

            timeout_sec = self.dual_layer_timeout_minutes * 60
            global_fuzzer = GlobalFirmwareFuzzer(
                work_dir=str(fuzz_work / "global"),
                max_runtime=min(timeout_sec, 1800),
                monitor_interval=30,
            )
            sp_fuzzer = SPFirmwareFuzzer(
                work_dir=str(fuzz_work / "sp"),
                llm_client=self.llm_client,
                max_iterations=500,
            )
            snapshot_mgr = SnapshotManager(
                snapshot_dir=str(snap_dir),
            )

            orchestrator = FuzzerOrchestrator(
                global_fuzzer=global_fuzzer,
                sp_fuzzer=sp_fuzzer,
                snapshot_manager=snapshot_mgr,
                max_parallel_sp=self.dual_layer_max_parallel,
                global_duration_minutes=min(
                    self.dual_layer_timeout_minutes // 2, 10
                ),
                checkpoint_dir=str(fuzz_work),
            )

            import asyncio

            async def _run():
                return await orchestrator.run(
                    firmware_path, as_dicts, resume=True
                )

            logger.info(
                f"Dual-Layer Phase 4: {len(sp_list)} SPs, "
                f"{len(as_dicts)} attack surfaces, "
                f"timeout={self.dual_layer_timeout_minutes}min"
            )
            fuzz_report = asyncio.run(_run())

            # Convert to legacy Phase4Result format
            stats = Phase4Statistics()
            stats.total_p0_sps = len(sp_list)
            stats.unique_crashes = len(fuzz_report.confirmed_vulns)
            for _ in fuzz_report.confirmed_vulns:
                stats.dynamic_user_verified += 1
            for _ in fuzz_report.needs_review:
                stats.static_high_reserved += 1
            for _ in fuzz_report.false_positives:
                stats.discarded += 1

            verified_results = []
            for vuln in fuzz_report.confirmed_vulns:
                cd = vuln.get("crash_info", {})
                crash = CrashInfo(
                    crash_type=cd.get("crash_type", "UNKNOWN"),
                    crash_address=(
                        int(str(cd.get("crash_address", "0")), 16)
                        if cd.get("crash_address")
                        else 0
                    ),
                    signal_number=cd.get("signal_number", 0),
                ) if cd else None
                verified_results.append(VerificationResult(
                    sp_id=vuln.get("sp_id", ""),
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash,
                    output=vuln.get("poc_guidance", ""),
                ))
            for vuln in fuzz_report.needs_review:
                verified_results.append(VerificationResult(
                    sp_id=vuln.get("sp_id", ""),
                    verification_level="static_high",
                    crashed=False,
                    output=vuln.get("notes", ""),
                ))

            return Phase4Result(
                statistics=stats,
                verified_results=verified_results,
                summary=fuzz_report.summary,
            )

        except ImportError as e:
            logger.warning(
                f"Dual-layer fuzzing unavailable ({e}), "
                f"falling back to legacy Phase 4"
            )
            return self._phase4.run(
                verified_sps=verified_sps,
                functions=functions,
                attack_surfaces=attack_surfaces,
                callgraph=callgraph,
                firmware_path=firmware_path,
                firmware_name=firmware_name,
            )
        except Exception as e:
            logger.error(
                f"Dual-layer fuzzing failed: {e}, "
                f"falling back to legacy Phase 4"
            )
            import traceback
            logger.debug(traceback.format_exc())
            return self._phase4.run(
                verified_sps=verified_sps,
                functions=functions,
                attack_surfaces=attack_surfaces,
                callgraph=callgraph,
                firmware_path=firmware_path,
                firmware_name=firmware_name,
            )

    # -- Report Construction --------------------------------------------------

    def _build_final_report(
        self,
        phase3_result: Optional[Phase3Result],
        phase4_result: Phase4Result,
        all_functions: List[FunctionInfo],
        all_attack_surfaces: List[AttackSurface],
        firmware_name: str,
        firmware_hash: str,
    ) -> FinalReport:
        """Build FinalReport from Phase 3 + Phase 4 outputs.

        Cross-references VerifiedSPs from Phase 3 with VerificationResults
        from Phase 4 to construct complete VulnerabilityEntry objects.
        """
        # Build lookup maps
        verified_sps: Dict[str, VerifiedSP] = {}
        if phase3_result:
            for vsp in phase3_result.verified_sps:
                verified_sps[vsp.sp_id] = vsp

        verif_map: Dict[str, VerificationResult] = {}
        poc_map: Dict[str, PoC] = {}
        for vr in phase4_result.verified_results:
            verif_map[vr.sp_id] = vr

        # Build VulnerabilityEntry list
        vulnerabilities: List[VulnerabilityEntry] = []
        for vr in phase4_result.verified_results:
            sp_id = vr.sp_id
            vsp = verified_sps.get(sp_id)
            verification = verif_map.get(sp_id)

            # Skip discarded SPs
            if verification and verification.verification_level == "static_low":
                continue

            if vsp:
                entry = VulnerabilityEntry(
                    sp_id=sp_id,
                    cwe=vsp.cwe,
                    title=vsp.title,
                    description=vsp.description,
                    function_name=vsp.function_name,
                    binary_offset=vsp.binary_offset,
                    control_flow=vsp.control_flow,
                    trigger_condition=vsp.trigger_condition,
                    confidence=vsp.confidence,
                    severity=vsp.severity,
                    priority=vsp.priority,
                    verification_level=(
                        verification.verification_level
                        if verification
                        else "not_verified"
                    ),
                    exploitability=vsp.exploitability,
                    poc=None,
                    crash_info=(
                        verification.crash_info if verification else None
                    ),
                    fix_suggestion="",
                )
            else:
                # Verification without corresponding VerifiedSP
                # (should be rare — use verification data directly)
                entry = VulnerabilityEntry(
                    sp_id=sp_id,
                    cwe="unknown",
                    title=f"Unmatched SP: {sp_id}",
                    description="No Phase3 metadata available for this SP.",
                    function_name="unknown",
                    verification_level=(
                        verification.verification_level
                        if verification
                        else "not_verified"
                    ),
                    crash_info=(
                        verification.crash_info if verification else None
                    ),
                )

            vulnerabilities.append(entry)

        # Sort: P0 first, then by verification level quality
        def _sort_key(v: VulnerabilityEntry) -> tuple:
            priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
            level_order = {
                "dynamic_full": 0,
                "dynamic_user": 1,
                "static_high": 2,
                "not_verified": 3,
            }
            return (
                priority_order.get(v.priority, 99),
                level_order.get(v.verification_level, 99),
                -(v.confidence or 0),
            )

        vulnerabilities.sort(key=_sort_key)

        # Build report metadata
        metadata = ReportMetadata(
            firmware_name=firmware_name,
            firmware_hash=firmware_hash,
            analysis_date=datetime.now().isoformat(),
            total_functions_analyzed=len(all_functions),
            total_attack_surfaces=len(all_attack_surfaces),
            total_directions=(
                len(phase3_result.verified_sps) if phase3_result else 0
            ),
        )

        # Ground truth cross-reference (if profile has known CVEs)
        ground_truth_match = None
        if self.profile and self.profile.has_ground_truth and phase3_result:
            import json as _json
            match_data = self.profile.cross_reference_cves(
                phase3_result.verified_sps
            )
            # Convert dataclass objects to dicts for JSON compatibility
            ground_truth_match = {
                "matched": [
                    {
                        "cve": m["cve"].to_dict(),
                        "sp_id": m["sp"].sp_id,
                        "fuzzy": m.get("fuzzy", False),
                    }
                    for m in match_data["matched"]
                ],
                "unmatched_cves": [
                    c.to_dict() for c in match_data["unmatched_cves"]
                ],
                "extra_sp_ids": [
                    sp.sp_id for sp in match_data["extra"]
                ],
                "total_known": match_data["total_known"],
                "found_count": match_data["found_count"],
                "recall": match_data["recall"],
            }
            logger.info(
                f"Ground Truth: {match_data['found_count']}/{match_data['total_known']} "
                f"CVEs found (recall={match_data['recall']:.0%}), "
                f"{len(match_data['extra'])} extra SPs beyond known CVEs"
            )

        return FinalReport(
            metadata=metadata,
            vulnerabilities=vulnerabilities,
            statistics=phase4_result.statistics,
            ground_truth_match=ground_truth_match,
        )

    # -- Checkpoint I/O -------------------------------------------------------

    def _save_phase1(
        self,
        path: Path,
        functions: List[FunctionInfo],
        callgraph: Optional[CallGraph],
        firmware_name: str,
    ) -> None:
        """Save Phase 1 results as aggregated JSON checkpoint."""
        data = {
            "firmware_name": firmware_name,
            "function_count": len(functions),
            "functions": [
                {
                    "name": f.name,
                    "address": f.address,
                    "pseudo_code": f.pseudo_code,
                    "assembly": f.assembly,
                    "callers": f.callers,
                    "callees": f.callees,
                    "parameters": f.parameters,
                    "complexity": f.complexity,
                    "has_unsafe_calls": f.has_unsafe_calls,
                    "dangerous_funcs": f.dangerous_funcs,
                    "strings_used": f.strings_used,
                    "arch": f.arch,
                    "section": f.section,
                    "binary_path": f.binary_path,
                }
                for f in functions
            ],
            "strings": [],
            "callgraph": {
                "binary_path": callgraph.binary_path if callgraph else "",
                "node_count": callgraph.node_count if callgraph else 0,
                "nodes": {
                    name: {
                        "function_name": node.function_name,
                        "address": node.address,
                        "callers": node.callers,
                        "callees": node.callees,
                    }
                    for name, node in (callgraph.nodes.items() if callgraph else {})
                },
            },
        }
        self._save_json(data, path)
        logger.info(f"Phase 1 checkpoint saved: {path}")

    def _load_phase1(self, path: Path) -> tuple:
        """Load Phase 1 checkpoint."""
        data = json.loads(path.read_text(encoding="utf-8"))
        functions = [
            FunctionInfo(
                name=f["name"],
                address=f["address"],
                pseudo_code=f.get("pseudo_code", ""),
                assembly=f.get("assembly", ""),
                callers=f.get("callers", []),
                callees=f.get("callees", []),
                parameters=f.get("parameters", 0),
                complexity=f.get("complexity", 0),
                has_unsafe_calls=f.get("has_unsafe_calls", False),
                dangerous_funcs=f.get("dangerous_funcs", []),
                strings_used=f.get("strings_used", []),
                arch=f.get("arch", ""),
                section=f.get("section", ""),
                binary_path=f.get("binary_path", ""),
            )
            for f in data.get("functions", [])
        ]

        cg_data = data.get("callgraph", {})
        callgraph = CallGraph(
            binary_path=cg_data.get("binary_path", ""),
        )
        from .static.models import CallGraphNode
        for name, node_data in cg_data.get("nodes", {}).items():
            callgraph.nodes[name] = CallGraphNode(
                function_name=node_data["function_name"],
                address=node_data.get("address", 0),
                callers=node_data.get("callers", []),
                callees=node_data.get("callees", []),
            )

        logger.info(
            f"Loaded Phase 1 checkpoint: {len(functions)} functions, "
            f"{callgraph.node_count} callgraph nodes"
        )
        return functions, callgraph

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _resolve_extracted_root(extract_dir: Path) -> Path:
        """Find the actual root of the extracted filesystem.

        binwalk extracts firmware into:
          extract_dir/_<firmware>.extracted/<fs-type>-root/

        Returns the deepest directory that looks like a root filesystem
        (contains bin/, usr/, etc/ or sbin/).
        """
        # Look for the extracted subdirectory
        extracted_dirs = list(extract_dir.glob("_*.extracted"))
        if not extracted_dirs:
            # Fallback: look in any subdirectory
            extracted_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]

        if not extracted_dirs:
            return extract_dir

        # Use the first extracted dir
        base = extracted_dirs[0]

        # Look for the squashfs-root / filesystem root inside
        fs_indicators = ["bin", "sbin", "usr", "etc", "lib"]
        for candidate in [base] + sorted(base.rglob("*"), key=lambda p: len(p.parts)):
            if not candidate.is_dir():
                continue
            found = sum(1 for ind in fs_indicators if (candidate / ind).is_dir())
            if found >= 3:
                return candidate

        # Fallback: return the extracted base
        return base

    @staticmethod
    def _save_json(data: dict, path: Path) -> None:
        """Save dict as JSON to path."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def _hash_file_head(file_path: str, bytes_to_read: int = 65536) -> str:
        """Compute a quick hash of a file's head for dedup."""
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                sha.update(f.read(bytes_to_read))
        except (OSError, IOError):
            return ""
        return sha.hexdigest()

    @staticmethod
    def _hash_firmware(firmware_path: str) -> str:
        """Compute SHA-256 hash of firmware (first 4KB for large files)."""
        sha = hashlib.sha256()
        with open(firmware_path, "rb") as f:
            chunk = f.read(4096)
            sha.update(chunk)
        # If file is larger than 4KB, also hash the last 4KB
        file_size = Path(firmware_path).stat().st_size
        if file_size > 8192:
            with open(firmware_path, "rb") as f:
                f.seek(-4096, 2)  # seek 4KB from end
                sha.update(f.read(4096))
        return sha.hexdigest()
