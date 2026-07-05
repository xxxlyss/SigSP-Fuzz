"""
Phase4Pipeline -- Full Phase 4 orchestration.

Orchestrates the complete Phase 4 pipeline:
1. Filter P0 SPs
2. Generate PoCs via PoCAgent
3. For each PoC+SP pair, try L1->L2->L3 verification
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
    """Orchestrates the full Phase 4 pipeline: PoC -> Verify -> Report.

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
        static_threshold: float = 0.50,
        daemon_startup_timeout: int = 10,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.llm_client = llm_client or LLMClient()

        self.poc_agent = PoCAgent(
            llm_client=self.llm_client,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        self.firmae_runner = FirmAERunner(firmae_dir) if firmae_dir else None
        self.qemu_runner = QEMURunner(
            qemu_dir=qemu_dir,
            rootfs_dir=rootfs_dir,
            daemon_startup_timeout=daemon_startup_timeout,
        )

        self.crash_monitor = CrashMonitor()
        self.static_assessor = StaticAssessor(high_confidence_threshold=static_threshold)

    # -- Public API ----------------------------------------------------------

    def run(
        self,
        verified_sps: List[VerifiedSP],
        functions: List[FunctionInfo],
        attack_surfaces: List[AttackSurface],
        callgraph: Optional[CallGraph] = None,
        firmware_path: str = "",
        firmware_name: str = "",
        task_dir: str = "",
    ) -> Phase4Result:
        """Full Phase 4 pipeline.

        1. Filter high-confidence SPs
        2. Generate PoCs via PoCAgent
        3. For each PoC+SP pair: L1->L2->L3
        4. CrashMonitor dedup
        5. Return Phase4Result
        """
        # Resolve binary paths: func_info.binary_path is relative to .extracted dir
        extracted_base = self._find_extracted_base(task_dir) if task_dir else ""
        function_contexts = {}
        for f in functions:
            if extracted_base and f.binary_path:
                # Resolve relative binary path to absolute
                resolved = Path(extracted_base) / f.binary_path
                if resolved.exists():
                    f.binary_path = str(resolved)
            function_contexts[f.name] = f

        # Step 1: Filter high-confidence SPs (confidence >= 0.5 or P0)
        high_conf_sps = [
            sp for sp in verified_sps
            if sp.priority == "P0" or sp.confidence >= 0.5
        ]
        # Sort by confidence descending, take top 10 to limit QEMU workload
        high_conf_sps.sort(key=lambda s: s.confidence, reverse=True)
        high_conf_sps = high_conf_sps[:10]
        logger.info(
            f"Phase4Pipeline: {len(high_conf_sps)} high-confidence SPs "
            f"out of {len(verified_sps)} total (confidence >= 0.5 or P0)"
        )

        # Step 2: Generate PoCs
        pocs = self.poc_agent.generate_batch(high_conf_sps, attack_surfaces, function_contexts)
        poc_map: Dict[str, PoC] = {p.sp_id: p for p in pocs}

        # Save individual PoCs to disk
        poc_dir = self.output_dir / "pocs"
        poc_dir.mkdir(parents=True, exist_ok=True)
        for sp_id, poc in poc_map.items():
            save_path = poc_dir / f"{sp_id}_poc.json"
            self.poc_agent.save(poc, save_path)
        if pocs:
            logger.info(f"Phase4Pipeline: saved {len(pocs)} PoCs to {poc_dir}")

        # Step 3: Layered verification
        verified_results: List[VerificationResult] = []
        all_crashes: List[CrashInfo] = []

        stats = Phase4Statistics()
        stats.total_p0_sps = len(high_conf_sps)
        stats.poc_generated = len(pocs)

        for sp in high_conf_sps:
            poc = poc_map.get(sp.sp_id)
            if not poc:
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
            f"Phase4Pipeline complete: {stats.total_p0_sps} high-conf SPs -> "
            f"L1={stats.dynamic_full_verified}, L2={stats.dynamic_user_verified}, "
            f"L3={stats.static_high_reserved}, discarded={stats.discarded}, "
            f"crashes={stats.unique_crashes}"
        )

        return Phase4Result(
            verified_results=verified_results,
            crashes=unique_crashes,
            statistics=stats,
        )

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _find_extracted_base(task_dir: str) -> str:
        """Find the .extracted directory for resolving binary paths."""
        task_path = Path(task_dir)
        extracted_dir = task_path / "extracted"
        if not extracted_dir.exists():
            return ""
        # Find the first _*.extracted directory
        extracted_dirs = list(extracted_dir.glob("_*.extracted"))
        if extracted_dirs:
            return str(extracted_dirs[0])
        return str(extracted_dir)

    # -- File I/O ------------------------------------------------------------

    def save(self, result: Phase4Result, path: Union[str, Path]) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Phase4Result saved to {path}")

    def load(self, path: Union[str, Path]) -> Phase4Result:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Phase4Result file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return Phase4Result.from_dict(data)
