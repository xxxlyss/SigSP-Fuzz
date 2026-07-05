#!/usr/bin/env python3
"""
Run complete 4-phase pipeline on TEW-657BRM-1001 firmware.
TEW-657BRM is a TRENDnet wireless router based on Ralink RT3052 (MIPS big-endian).

Usage:
    python3 run_tew_pipeline.py [--resume]
"""

import sys
import time
import argparse
from pathlib import Path

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).parent))

# IMPORTANT: Import fuzzingbrain modules FIRST — they configure loguru on import.
# logger setup must happen AFTER the import to avoid being wiped.
from fuzzingbrain.firmware_pipeline import FirmwarePipeline

from loguru import logger

# Remove default handler and add custom one (AFTER fuzzingbrain imports)
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | <level>{message}</level>",
    level="INFO",
    colorize=False,  # Avoid ANSI codes in log files
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoints")
    parser.add_argument("--phases", default="phase1,phase2,phase3,phase4",
                       help="Comma-separated phases to run")
    args = parser.parse_args()

    firmware_path = str(Path(__file__).parent / "firmware" / "TEW-657BRM-1001.img")
    firmware_name = "TEW-657BRM-1001"
    output_dir = str(Path(__file__).parent / "results")

    phases = set(args.phases.split(","))

    logger.info("=" * 70)
    logger.info(f"FuzzingBrain: Complete 4-Phase Pipeline")
    logger.info(f"  Firmware: {firmware_path}")
    logger.info(f"  Name:     {firmware_name}")
    logger.info(f"  Arch:     mips (big-endian, auto-detected)")
    logger.info(f"  Phases:   {sorted(phases)}")
    logger.info(f"  Resume:   {args.resume}")
    logger.info(f"  Output:   {output_dir}")
    logger.info("=" * 70)

    total_start = time.time()

    pipeline = FirmwarePipeline(
        # Phase 1 tool paths
        binwalk_bin="binwalk",
        ghidra_headless=None,  # Use objdump fallback

        # Phase 4 tool paths
        firmae_dir=None,  # No FirmAE available (skip L1 full-system)
        qemu_dir="/usr/bin",

        # Output
        output_dir=output_dir,

        # Tuning
        phase3_scope="high_priority",  # Only process priority >= 4 directions
        temperature=0.3,
        max_tokens=16000,
    )

    try:
        report = pipeline.run(
            firmware_path=firmware_path,
            firmware_name=firmware_name,
            resume=args.resume,
            phases=phases,
        )

        elapsed = time.time() - total_start
        logger.info("=" * 70)
        logger.info(f"Pipeline Complete! ({elapsed:.0f}s total)")
        logger.info(f"  Vulnerabilities found:  {report.count}")
        logger.info(f"  Confirmed:              {len(report.confirmed_vulnerabilities)}")
        logger.info(f"  Statistics:")
        s = report.statistics
        logger.info(f"    P0 SPs:               {s.total_p0_sps}")
        logger.info(f"    PoCs generated:        {s.poc_generated}")
        logger.info(f"    L1 FirmAE verified:    {s.dynamic_full_verified}")
        logger.info(f"    L2 QEMU verified:      {s.dynamic_user_verified}")
        logger.info(f"    L3 Static verified:    {s.static_high_reserved}")
        logger.info(f"    Discarded:             {s.discarded}")
        logger.info(f"    Unique crashes:        {s.unique_crashes}")
        logger.info(f"    Verification rate:     {s.verification_rate}")

        if report.ground_truth_match:
            gt = report.ground_truth_match
            logger.info(f"  Ground Truth:")
            logger.info(f"    Known CVEs:            {gt.get('total_known', 0)}")
            logger.info(f"    Found:                 {gt.get('found_count', 0)}")
            logger.info(f"    Recall:                {gt.get('recall', 0)}")

        # Print top vulnerabilities
        if report.confirmed_vulnerabilities:
            logger.info(f"\n  Top Confirmed Vulnerabilities:")
            for i, v in enumerate(report.confirmed_vulnerabilities[:10], 1):
                crash_str = ""
                if v.crash_info:
                    crash_str = f" 💥 {v.crash_info.crash_type}"
                logger.info(
                    f"  {i:2d}. [{v.priority}] {v.title[:70]} - {v.cwe} "
                    f"({v.verification_level}){crash_str}"
                )

        return 0

    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user — checkpoints saved")
        return 130
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
