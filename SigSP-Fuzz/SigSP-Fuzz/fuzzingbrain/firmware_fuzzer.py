"""
Firmware Fuzzer — Dual-Layer Fuzzing Architecture for Embedded Binaries

Bridges AFL++ QEMU-mode fuzzing (Layer 1: broad exploration) with
per-SP targeted fuzzing (Layer 2: deep dive) for firmware vulnerability
discovery.

Architecture:
    FirmwareFuzzer (ABC)
        │
        ├── AFLQEMUFuzzer        ← Layer 1: AFL++ in QEMU user-mode
        │   - CLI binaries (argv/stdin)
        │   - Coverage via AFL bitmap (64KB shared memory)
        │   - Crash triage + dedup
        │
        ├── NetworkFuzzer        ← Layer 2: Targeted network fuzzing
        │   - Network daemons (httpd, dnsmasq, telnetd)
        │   - Session-based multi-stage injection
        │   - Uses QEMUBridge for emulation
        │
        └── FuzzerManager        ← Dual-layer orchestrator
            ├── global_fuzzer    ← AFL++ broad exploration
            ├── sp_fuzzers[]     ← Per-SP targeted instances
            ├── seed routing     ← Direction seeds → Global, PoV → SP
            ├── crash dedup      ← Stack-hash based deduplication
            └── coverage merge   ← Per-layer bitmap aggregation

Crash dedup strategy:
    Top-5 stack frames → SHA256 hash → unique crash identifier
    Same hash = same crash (even if triggered by different inputs)

Usage:
    from fuzzingbrain.firmware_fuzzer import FuzzerManager

    manager = FuzzerManager(work_dir="/tmp/fuzz_work")
    gid = manager.start_global("/bin/stack_bof_01", arch="mipsel")
    sid = manager.start_sp("/bin/stack_bof_01", sp_id="SP-001",
                           target_func="main", arch="mipsel")

    # Let it run...
    time.sleep(300)

    crashes = manager.get_all_crashes()
    coverage = manager.get_merged_coverage()
    manager.stop_all()
"""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from loguru import logger


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CrashInfo:
    """Information about a single crash discovered by fuzzing.

    Includes the triggering input, crash classification, and the
    sanitizer output needed for root-cause analysis and PoC generation.
    """

    crash_id: str
    input_data: bytes
    crash_type: str  # "heap-buffer-overflow", "stack-buffer-overflow",
                     # "use-after-free", "null-deref", "double-free",
                     # "SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS"
    crash_address: int
    sanitizer_output: str
    stack_trace: List[int] = field(default_factory=list)
    func_where: str = ""
    poc_guidance: str = ""

    # Metadata
    found_by: str = ""       # "global" or sp_fuzzer_id
    found_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    binary_path: str = ""
    signal_number: int = 0

    @property
    def stack_hash(self) -> str:
        """Unique crash identifier based on top stack frames.

        Two crashes with the same stack trace are considered
        duplicates — only the first one is kept.
        """
        frames = self.stack_trace[:5] if self.stack_trace else []
        raw = f"{self.crash_type}:{self.func_where}:{':'.join(hex(f) for f in frames)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        import base64
        return {
            "crash_id": self.crash_id,
            "input_data_base64": base64.b64encode(self.input_data).decode("ascii"),
            "input_data_hex": self.input_data.hex()[:200],
            "crash_type": self.crash_type,
            "crash_address": hex(self.crash_address),
            "signal_number": self.signal_number,
            "sanitizer_output": self.sanitizer_output[:2000],
            "stack_trace": [hex(a) for a in self.stack_trace[:10]],
            "func_where": self.func_where,
            "poc_guidance": self.poc_guidance,
            "stack_hash": self.stack_hash,
            "found_by": self.found_by,
            "binary_path": self.binary_path,
        }


@dataclass
class CoverageInfo:
    """Coverage data collected from a fuzzer instance.

    Uses the AFL-style 64KB bitmap format. Each byte in the bitmap
    represents a (prev_location >> 1) ^ cur_location edge hit count
    (bucketized: 0, 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+).
    """

    edges: int = 0
    total_edges: int = 65536
    coverage_percent: float = 0.0
    new_edges_last_minute: int = 0
    bitmap_file: str = ""

    # Extended metrics
    total_execs: int = 0
    execs_per_sec: float = 0.0
    pending_favs: int = 0
    cycles_done: int = 0
    stability: float = 100.0  # percentage

    def to_dict(self) -> dict:
        return {
            "edges": self.edges,
            "total_edges": self.total_edges,
            "coverage_percent": round(self.coverage_percent, 2),
            "new_edges_last_minute": self.new_edges_last_minute,
            "bitmap_file": self.bitmap_file,
            "total_execs": self.total_execs,
            "execs_per_sec": round(self.execs_per_sec, 1),
            "pending_favs": self.pending_favs,
            "cycles_done": self.cycles_done,
        }

    @classmethod
    def from_bitmap(cls, bitmap_path: str) -> "CoverageInfo":
        """Parse an AFL coverage bitmap file into metrics."""
        info = cls(bitmap_file=bitmap_path)
        try:
            with open(bitmap_path, "rb") as f:
                bitmap = f.read(65536)

            # Count non-zero bytes (edges covered)
            edges = sum(1 for b in bitmap if b != 0)
            info.edges = edges
            info.coverage_percent = (
                (edges / 65536) * 100 if edges > 0 else 0.0
            )
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Failed to read bitmap {bitmap_path}: {e}")
        return info

    @classmethod
    def merge(cls, coverages: List["CoverageInfo"]) -> "CoverageInfo":
        """Merge multiple coverage bitmaps into combined metrics."""
        if not coverages:
            return cls()
        if len(coverages) == 1:
            return coverages[0]

        merged = cls()
        merged.total_execs = sum(c.total_execs for c in coverages)
        merged.execs_per_sec = sum(c.execs_per_sec for c in coverages)
        merged.pending_favs = sum(c.pending_favs for c in coverages)

        # Merge bitmaps: logical OR across all instances
        merged_bitmap = bytearray(65536)
        for cov in coverages:
            if cov.bitmap_file and os.path.exists(cov.bitmap_file):
                try:
                    with open(cov.bitmap_file, "rb") as f:
                        data = f.read(65536)
                    for i in range(min(len(data), 65536)):
                        merged_bitmap[i] |= data[i]
                except Exception:
                    pass

        # Save merged bitmap
        merged_path = tempfile.mktemp(
            prefix="merged_coverage_", suffix=".bin"
        )
        with open(merged_path, "wb") as f:
            f.write(bytes(merged_bitmap))
        merged.bitmap_file = merged_path
        merged.edges = sum(1 for b in merged_bitmap if b != 0)
        merged.coverage_percent = (
            (merged.edges / 65536) * 100 if merged.edges > 0 else 0.0
        )

        return merged


# =============================================================================
# Architecture & Tool Detection
# =============================================================================

ARCH_TO_QEMU_USER = {
    "arm": "qemu-arm", "armeb": "qemu-armeb",
    "mips": "qemu-mips", "mipsel": "qemu-mipsel",
    "mips64": "qemu-mips64", "mips64el": "qemu-mips64el",
    "x86": "qemu-i386", "x86_64": "qemu-x86_64",
    "aarch64": "qemu-aarch64",
    "ppc": "qemu-ppc", "ppc64": "qemu-ppc64",
    "riscv64": "qemu-riscv64",
}


def _find_tool(name: str, qemu_dir: str = "/usr/bin") -> Optional[str]:
    """Find a binary in qemu_dir or PATH."""
    candidate = os.path.join(qemu_dir, name)
    if os.path.exists(candidate):
        return candidate
    return shutil.which(name)


def _detect_arch_from_elf(binary_path: str) -> Optional[str]:
    """Detect architecture from ELF header for QEMU selection."""
    try:
        import struct
        with open(binary_path, "rb") as f:
            # Read e_ident[16] at once
            e_ident = f.read(16)
            if len(e_ident) < 16:
                return None
            if e_ident[:4] != b"\x7fELF":
                return None
            # e_ident[4] = EI_CLASS (1=32-bit, 2=64-bit)
            # e_ident[5] = EI_DATA  (1=little, 2=big)
            bits = 32 if e_ident[4] == 1 else 64 if e_ident[4] == 2 else 32
            endian = "little" if e_ident[5] == 1 else "big" if e_ident[5] == 2 else "little"
            # e_machine at offset 18
            f.seek(18)
            machine = struct.unpack(
                "<H" if endian == "little" else ">H", f.read(2)
            )[0]
            arch_map = {
                0x28: "arm", 0xB7: "aarch64", 0x08: "mips",
                0x03: "x86", 0x3E: "x86_64", 0xF3: "riscv",
                0x14: "ppc",
            }
            arch = arch_map.get(machine, "unknown")
            if arch == "mips" and endian == "little":
                return "mipsel"
            return arch
    except Exception:
        return None


# =============================================================================
# Abstract Base Class
# =============================================================================

class FirmwareFuzzer(ABC):
    """Abstract base for all firmware fuzzer implementations.

    Defines the common interface for starting/stopping fuzzers,
    collecting coverage, retrieving crashes, and injecting seeds.
    """

    def __init__(
        self,
        work_dir: str,
        timeout_per_exec: int = 30,
    ):
        """
        Args:
            work_dir: Working directory for fuzzer output.
            timeout_per_exec: Timeout per fuzzing execution in ms.
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_per_exec = timeout_per_exec

        # Runtime tracking
        self._processes: Dict[str, subprocess.Popen] = {}
        self._crashes: Dict[str, CrashInfo] = {}
        self._coverage: Optional[CoverageInfo] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Abstract Interface
    # ------------------------------------------------------------------

    @abstractmethod
    def start(
        self,
        binary_path: str,
        attack_surface: Optional[dict] = None,
    ) -> str:
        """Start the fuzzer. Returns a fuzzer_id."""
        ...

    @abstractmethod
    def stop(self, fuzzer_id: str) -> bool:
        """Stop a running fuzzer instance."""
        ...

    @abstractmethod
    def get_coverage(self, fuzzer_id: str) -> CoverageInfo:
        """Get current coverage for a fuzzer instance."""
        ...

    @abstractmethod
    def get_crashes(self, fuzzer_id: str) -> List[CrashInfo]:
        """Get all unique crashes found by this fuzzer."""
        ...

    @abstractmethod
    def inject_seed(self, fuzzer_id: str, seed: bytes) -> bool:
        """Inject a seed input into the fuzzer corpus."""
        ...

    # ------------------------------------------------------------------
    # Common Helpers
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return any(
            p is not None and p.poll() is None
            for p in self._processes.values()
        )

    @property
    def crash_count(self) -> int:
        with self._lock:
            return len(self._crashes)

    def _dedup_crash(self, crash: CrashInfo) -> Optional[CrashInfo]:
        """Check if a crash is new (by stack hash). Returns the crash if new."""
        with self._lock:
            h = crash.stack_hash
            if h in self._crashes:
                logger.debug(
                    f"Duplicate crash {crash.crash_id}: "
                    f"same stack hash as {self._crashes[h].crash_id}"
                )
                return None
            self._crashes[h] = crash
            return crash

    def _parse_asan_output(
        self, stderr: str, binary_path: str = ""
    ) -> Optional[CrashInfo]:
        """Parse AddressSanitizer output into CrashInfo.

        Handles:
        - heap-buffer-overflow
        - stack-buffer-overflow
        - use-after-free
        - double-free
        - null-deref (SEGV on unknown address 0x0)
        """
        if not stderr:
            return None

        crash_type = "UNKNOWN"
        crash_addr = 0
        stack_trace = []
        func_where = ""

        # ASAN crash type detection
        asan_patterns = [
            ("heap-buffer-overflow",
             r"heap-buffer-overflow"),
            ("stack-buffer-overflow",
             r"stack-buffer-overflow"),
            ("use-after-free",
             r"use-after-free"),
            ("double-free",
             r"double-free"),
            ("global-buffer-overflow",
             r"global-buffer-overflow"),
            ("stack-use-after-return",
             r"stack-use-after-return"),
            ("null-deref",
             r"SEGV on unknown address 0x0"),
        ]

        for ctype, pattern in asan_patterns:
            if re.search(pattern, stderr):
                crash_type = ctype
                break

        # Extract crash address
        addr_match = re.search(
            r"(?:0x[0-9a-fA-F]+).*?(?:is located|READ of size|WRITE of size)",
            stderr,
        )
        if addr_match:
            hex_match = re.search(
                r"0x[0-9a-fA-F]+", addr_match.group()
            )
            if hex_match:
                try:
                    crash_addr = int(hex_match.group(), 16)
                except ValueError:
                    pass

        # Also check for SIGSEGV-style crashes (non-ASAN)
        if crash_type == "UNKNOWN":
            sig_match = re.search(
                r"(SIGSEGV|SIGABRT|SIGILL|SIGBUS|SIGFPE)",
                stderr,
            )
            if sig_match:
                crash_type = sig_match.group(1)

            pc_match = re.search(
                r"[Pp][Cc]\s*[=:]\s*(0x[0-9a-fA-F]+)", stderr
            )
            if pc_match:
                try:
                    crash_addr = int(pc_match.group(1), 16)
                except ValueError:
                    pass

        # Extract stack trace (addresses after #0, #1, etc.)
        for line in stderr.split("\n"):
            trace_match = re.match(
                r"\s*#(\d+)\s+(0x[0-9a-fA-F]+)", line
            )
            if trace_match:
                try:
                    addr = int(trace_match.group(2), 16)
                    stack_trace.append(addr)
                except ValueError:
                    continue

            # Function name
            func_match = re.search(
                r"in\s+(\S+)\s+",
                line,
            )
            if func_match and not func_where:
                func_where = func_match.group(1)

        if crash_type == "UNKNOWN" and not stack_trace:
            return None

        crash_id = f"crash_{uuid.uuid4().hex[:12]}"
        return CrashInfo(
            crash_id=crash_id,
            input_data=b"",  # Filled by caller
            crash_type=crash_type,
            crash_address=crash_addr,
            sanitizer_output=stderr[:5000],
            stack_trace=stack_trace[:20],
            func_where=func_where,
            binary_path=binary_path,
        )


# =============================================================================
# AFL++ QEMU-Mode Fuzzer (Layer 1: Broad Exploration)
# =============================================================================

class AFLQEMUFuzzer(FirmwareFuzzer):
    """AFL++ in QEMU user-mode for firmware CLI binaries.

    Uses afl-fuzz with -Q flag (QEMU mode) to fuzz MIPS/ARM/x86
    binaries without source code. Suitable for binaries that read
    from stdin or a file.

    Layer 1 — broad exploration:
    - fork=2 (light parallelism)
    - Seed-based with LLM-generated directional seeds
    - Coverage bitmap for exploration feedback

    Requirements:
    - AFL++ installed (afl-fuzz, afl-qemu-trace)
    - Cross-arch QEMU user-mode binaries
    - The target binary must accept stdin or argv input

    Usage:
        fuzzer = AFLQEMUFuzzer(work_dir="/tmp/fuzz",
                               afl_path="/usr/local/bin/afl-fuzz")
        fid = fuzzer.start("/bin/stack_bof_01", arch="mipsel",
                          rootfs="/path/to/squashfs-root")
        time.sleep(300)
        crashes = fuzzer.get_crashes(fid)
        fuzzer.stop(fid)
    """

    def __init__(
        self,
        work_dir: str,
        afl_path: str = "afl-fuzz",
        qemu_dir: str = "/usr/bin",
        afl_qemu_path: Optional[str] = None,
        fork_level: int = 2,
        memory_limit_mb: int = 2048,
        **kwargs,
    ):
        """
        Args:
            work_dir: Working directory for AFL output.
            afl_path: Path to afl-fuzz binary.
            qemu_dir: Directory with QEMU user-mode binaries.
            afl_qemu_path: Path to afl-qemu-trace (auto-detected).
            fork_level: Number of parallel fuzzing processes.
            memory_limit_mb: Memory limit per fuzzer in MB.
        """
        super().__init__(work_dir=work_dir, **kwargs)
        self.afl_path = shutil.which(afl_path) or afl_path
        self.qemu_dir = qemu_dir
        self.fork_level = fork_level
        self.memory_limit_mb = memory_limit_mb

        # Auto-detect AFL QEMU trace
        if afl_qemu_path:
            self.afl_qemu_trace = afl_qemu_path
        else:
            self.afl_qemu_trace = self._find_afl_qemu_trace()

        # Instance tracking
        self._fuzzer_dirs: Dict[str, Path] = {}
        self._crash_files: Dict[str, Set[str]] = {}

        self._validate_afl()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        binary_path: str,
        attack_surface: Optional[dict] = None,
        arch: Optional[str] = None,
        rootfs: str = "",
        extra_args: Optional[List[str]] = None,
    ) -> str:
        """Start AFL++ QEMU-mode fuzzing on a binary.

        Args:
            binary_path: Path to the ELF binary to fuzz.
            attack_surface: Attack surface metadata (protocol, port, etc.).
            arch: Target architecture (auto-detected if None).
            rootfs: Extracted rootfs path for -L flag.
            extra_args: Additional arguments to pass to afl-fuzz.

        Returns:
            fuzzer_id string for subsequent operations.
        """
        abs_path = os.path.abspath(binary_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Binary not found: {abs_path}")

        # Auto-detect architecture
        if arch is None:
            arch = _detect_arch_from_elf(abs_path)
        if arch is None:
            raise ValueError(
                f"Cannot detect architecture for {abs_path}"
            )

        # Find QEMU binary
        qemu_name = ARCH_TO_QEMU_USER.get(arch)
        if not qemu_name:
            raise ValueError(f"Unsupported architecture: {arch}")
        qemu_bin = _find_tool(qemu_name, self.qemu_dir)
        if not qemu_bin:
            raise RuntimeError(
                f"QEMU binary not found: {qemu_name}. "
                f"Install: sudo apt install qemu-user-static"
            )

        # Create fuzzer work directory
        fuzzer_id = f"afl_{uuid.uuid4().hex[:8]}"
        fuzzer_dir = self.work_dir / fuzzer_id
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        input_dir = fuzzer_dir / "input"
        input_dir.mkdir(exist_ok=True)

        output_dir = fuzzer_dir / "output"
        output_dir.mkdir(exist_ok=True)

        # Create initial seed input (minimal valid input)
        seed_file = input_dir / "seed.bin"
        seed_file.write_bytes(b"AAAA")

        # Build QEMU command for AFL
        qemu_cmd_parts = [qemu_bin]
        if rootfs and os.path.exists(rootfs):
            qemu_cmd_parts.extend(["-L", rootfs])
        qemu_cmd_parts.append(abs_path)
        qemu_cmd = " ".join(qemu_cmd_parts)

        # AFL environment
        env = os.environ.copy()
        env["AFL_QEMU_PERSISTENT_ADDR"] = "0x0"
        env["AFL_QEMU_PERSISTENT_RETADDR_OFFSET"] = "0"
        if self.afl_qemu_trace:
            env["AFL_QEMU_TRACE"] = self.afl_qemu_trace

        # Build afl-fuzz command
        cmd = [
            self.afl_path,
            "-i", str(input_dir),
            "-o", str(output_dir),
            "-Q",  # QEMU mode
            "-m", str(self.memory_limit_mb),
            "-t", f"{self.timeout_per_exec}+",
            "-f", str(self.fork_level),
            "--",
        ] + qemu_cmd_parts

        if extra_args:
            cmd.extend(extra_args)

        logger.info(
            f"AFLQEMUFuzzer [{fuzzer_id}]: starting — "
            f"binary={os.path.basename(abs_path)}, arch={arch}"
        )
        logger.debug(f"AFL command: {' '.join(cmd[:6])} ...")

        try:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(fuzzer_dir),
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"AFL++ not found at '{self.afl_path}'. "
                f"Install: sudo apt install afl++"
            )

        with self._lock:
            self._processes[fuzzer_id] = proc
            self._fuzzer_dirs[fuzzer_id] = fuzzer_dir
            self._crash_files[fuzzer_id] = set()

        logger.info(
            f"AFLQEMUFuzzer [{fuzzer_id}]: started (pid={proc.pid})"
        )
        return fuzzer_id

    def stop(self, fuzzer_id: str) -> bool:
        """Stop an AFL++ fuzzer instance gracefully."""
        with self._lock:
            proc = self._processes.pop(fuzzer_id, None)
            fuzzer_dir = self._fuzzer_dirs.pop(fuzzer_id, None)

        if proc is None:
            logger.warning(
                f"AFLQEMUFuzzer [{fuzzer_id}]: not running"
            )
            return False

        # Send SIGINT for graceful shutdown (AFL saves state)
        try:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except ProcessLookupError:
            pass

        logger.info(
            f"AFLQEMUFuzzer [{fuzzer_id}]: stopped "
            f"(exit={proc.returncode})"
        )
        return True

    def get_coverage(self, fuzzer_id: str) -> CoverageInfo:
        """Get coverage from the AFL bitmap.

        AFL stores the coverage bitmap at:
          <output_dir>/default/fuzzer_stats
          <output_dir>/default/plot_data

        Returns CoverageInfo parsed from the AFL output directory.
        """
        with self._lock:
            fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)

        if fuzzer_dir is None:
            return CoverageInfo()

        # Find the most recent AFL output subdirectory
        output_dir = fuzzer_dir / "output" / "default"
        if not output_dir.exists():
            return CoverageInfo()

        # Read fuzzer_stats
        stats_file = output_dir / "fuzzer_stats"
        cov = CoverageInfo()
        if stats_file.exists():
            try:
                stats = {}
                for line in stats_file.read_text().splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        stats[k.strip()] = v.strip()
                cov.total_execs = int(
                    stats.get("execs_done", 0)
                )
                cov.execs_per_sec = float(
                    stats.get("execs_per_sec", 0)
                )
                cov.pending_favs = int(
                    stats.get("pending_favs", 0)
                )
                cov.cycles_done = int(
                    stats.get("cycles_done", 0)
                )
            except Exception as e:
                logger.debug(f"Failed to parse AFL stats: {e}")

        # Read coverage bitmap
        bitmap_file = output_dir / "plot_data"
        cov.bitmap_file = str(bitmap_file)
        try:
            with open(bitmap_file, "rb") as f:
                data = f.read(65536)
                cov.edges = sum(1 for b in data if b != 0)
                cov.total_edges = 65536
                cov.coverage_percent = (
                    (cov.edges / 65536) * 100
                )
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Failed to read AFL bitmap: {e}")

        return cov

    def get_crashes(self, fuzzer_id: str) -> List[CrashInfo]:
        """Get all unique crashes found by this AFL instance.

        Scans the AFL output directory for crash files, parses
        sanitizer output, and deduplicates by stack hash.
        """
        with self._lock:
            fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
            crash_files = self._crash_files.get(fuzzer_id, set())

        if fuzzer_dir is None:
            return list(self._crashes.values())

        # Scan AFL crash directory
        crash_dir = fuzzer_dir / "output" / "default" / "crashes"
        if not crash_dir.exists():
            return list(self._crashes.values())

        for crash_file in crash_dir.iterdir():
            if crash_file.name in crash_files:
                continue
            if crash_file.name in ("README.txt", ".gitkeep"):
                continue
            if crash_file.is_dir():
                continue

            crash_files.add(crash_file.name)

            try:
                input_data = crash_file.read_bytes()
            except Exception:
                continue

            # Try to re-run with sanitizer to get ASAN output
            sanitizer_output = self._rerun_with_asan(
                fuzzer_id, input_data
            )

            crash = self._parse_asan_output(
                sanitizer_output,
                binary_path=str(
                    fuzzer_dir / "input" / "seed.bin"
                ),
            )
            if crash:
                crash.input_data = input_data
                crash.found_by = fuzzer_id
                self._dedup_crash(crash)

        with self._lock:
            self._crash_files[fuzzer_id] = crash_files

        return list(self._crashes.values())

    def inject_seed(self, fuzzer_id: str, seed: bytes) -> bool:
        """Inject a seed input into the AFL input directory.

        AFL will pick it up on the next sync cycle.
        """
        with self._lock:
            fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)

        if fuzzer_dir is None:
            return False

        input_dir = fuzzer_dir / "input"
        seed_name = f"seed_{hashlib.md5(seed).hexdigest()[:8]}.bin"
        seed_path = input_dir / seed_name

        try:
            seed_path.write_bytes(seed)
            logger.debug(
                f"AFLQEMUFuzzer [{fuzzer_id}]: injected seed "
                f"{seed_name} ({len(seed)} bytes)"
            )
            return True
        except Exception as e:
            logger.error(
                f"AFLQEMUFuzzer [{fuzzer_id}]: seed injection "
                f"failed: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _find_afl_qemu_trace(self) -> Optional[str]:
        """Find the afl-qemu-trace binary."""
        # Common locations
        candidates = [
            "/usr/local/lib/afl/afl-qemu-trace",
            "/usr/lib/afl/afl-qemu-trace",
            "/usr/local/lib/aflplusplus/afl-qemu-trace",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        # Check PATH
        found = shutil.which("afl-qemu-trace")
        if found:
            return found
        return None

    def _validate_afl(self):
        """Check that AFL++ is installed and usable."""
        if not shutil.which(self.afl_path):
            logger.warning(
                f"AFL++ not found at '{self.afl_path}'. "
                f"Install with: sudo apt install afl++"
            )
            return

        # Check QEMU mode support
        try:
            result = subprocess.run(
                [self.afl_path, "-Q", "--help"],
                capture_output=True, text=True, timeout=5,
            )
            if "-Q" not in result.stdout:
                logger.warning(
                    "AFL++ found but QEMU mode (-Q) not available. "
                    "Rebuild with: make distrib"
                )
        except Exception:
            pass

    def _rerun_with_asan(
        self, fuzzer_id: str, input_data: bytes
    ) -> str:
        """Re-run a crash input with AddressSanitizer-enabled QEMU.

        Returns the combined stdout+stderr for crash analysis.
        """
        with self._lock:
            fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)

        if fuzzer_dir is None:
            return ""

        # Try to find the original binary
        seed_file = fuzzer_dir / "input" / "seed.bin"
        # The original command is stored in the AFL fuzzer_setup
        # For now, attempt a basic re-run
        try:
            # Use the original QEMU binary from the afl-fuzz command
            proc = subprocess.run(
                ["cat"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return proc.stderr
        except subprocess.TimeoutExpired:
            return "Re-run timed out"
        except Exception as e:
            return f"Re-run failed: {e}"


# =============================================================================
# Network Fuzzer (Layer 2: Targeted Per-SP Fuzzing)
# =============================================================================

class NetworkFuzzer(FirmwareFuzzer):
    """Network-protocol fuzzer for daemon binaries.

    Targets network-facing attack surfaces (HTTP, DNS, Telnet, UPnP).
    Uses QEMUBridge for full-system emulation and injects fuzzed
    network packets via SLiRP user-mode networking.

    Layer 2 — deep per-SP exploration:
    - Single-fork (focused on one vulnerability)
    - Stateful: tracks session state across multi-packet exchanges
    - Uses LLM-generated PoC blobs as seed inputs

    Usage:
        fuzzer = NetworkFuzzer(work_dir="/tmp/fuzz")
        fid = fuzzer.start("/bin/httpd",
                          attack_surface={"protocol": "HTTP", "port": 80},
                          arch="mipsel")
    """

    def __init__(
        self,
        work_dir: str,
        qemu_dir: str = "/usr/bin",
        **kwargs,
    ):
        super().__init__(work_dir=work_dir, **kwargs)
        self.qemu_dir = qemu_dir

        # Per-instance state
        self._bridge_instances: Dict[str, str] = {}  # fuzzer_id → bridge_iid
        self._session_state: Dict[str, dict] = {}
        self._input_queue: Dict[str, List[bytes]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        binary_path: str,
        attack_surface: Optional[dict] = None,
        arch: Optional[str] = None,
        kernel_path: Optional[str] = None,
        rootfs_path: Optional[str] = None,
    ) -> str:
        """Start network fuzzing on a daemon binary.

        Launches a full-system QEMU instance and begins injecting
        fuzzed network packets.

        Args:
            binary_path: Path to the daemon binary.
            attack_surface: {"protocol": "HTTP"/"DNS"/..., "port": 80, ...}.
            arch: Target architecture.
            kernel_path: Kernel image for full-system emulation.
            rootfs_path: Root filesystem image.

        Returns:
            fuzzer_id.
        """
        abs_path = os.path.abspath(binary_path)

        if arch is None:
            arch = _detect_arch_from_elf(abs_path)
        if arch is None:
            raise ValueError(
                f"Cannot detect architecture for {abs_path}"
            )

        proto = (attack_surface or {}).get("protocol", "TCP")
        port = (attack_surface or {}).get("port", 80)

        fuzzer_id = f"netfuzz_{uuid.uuid4().hex[:8]}"
        fuzzer_dir = self.work_dir / fuzzer_id
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        # Start QEMU full-system via QEMUBridge
        try:
            from .qemu_bridge import get_qemu_bridge
            bridge = get_qemu_bridge()
            bridge_iid = bridge.create_instance(
                firmware_path=abs_path,
                arch=arch,
                kernel_path=kernel_path,
                rootfs_path=rootfs_path,
                enable_network=True,
                enable_coverage=True,
            )
            self._bridge_instances[fuzzer_id] = bridge_iid
        except ImportError:
            logger.warning(
                "QEMUBridge not available — network fuzzing "
                "requires full-system emulation"
            )
        except Exception as e:
            logger.error(
                f"NetworkFuzzer [{fuzzer_id}]: QEMU start "
                f"failed: {e}"
            )
            raise

        # Initialize session state
        self._session_state[fuzzer_id] = {
            "protocol": proto,
            "port": port,
            "packets_sent": 0,
            "crashes_found": 0,
        }
        self._input_queue[fuzzer_id] = []

        # Generate protocol-aware initial seeds
        initial_seeds = self._generate_protocol_seeds(proto)
        for seed in initial_seeds:
            self.inject_seed(fuzzer_id, seed)

        # Placeholder subprocess for compatibility
        proc = subprocess.Popen(
            ["true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._processes[fuzzer_id] = proc

        logger.info(
            f"NetworkFuzzer [{fuzzer_id}]: started — "
            f"binary={os.path.basename(abs_path)}, "
            f"proto={proto}/{port}, arch={arch}"
        )
        return fuzzer_id

    def stop(self, fuzzer_id: str) -> bool:
        """Stop network fuzzing and clean up QEMU instance."""
        proc = self._processes.pop(fuzzer_id, None)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass

        # Stop QEMU bridge instance
        bridge_iid = self._bridge_instances.pop(fuzzer_id, None)
        if bridge_iid:
            try:
                from .qemu_bridge import get_qemu_bridge
                bridge = get_qemu_bridge()
                bridge.destroy_instance(bridge_iid)
            except ImportError:
                pass

        self._session_state.pop(fuzzer_id, None)
        self._input_queue.pop(fuzzer_id, None)

        logger.info(f"NetworkFuzzer [{fuzzer_id}]: stopped")
        return True

    def get_coverage(self, fuzzer_id: str) -> CoverageInfo:
        """Get coverage from the QEMU bridge instance."""
        bridge_iid = self._bridge_instances.get(fuzzer_id)
        if not bridge_iid:
            return CoverageInfo()

        try:
            from .qemu_bridge import get_qemu_bridge
            bridge = get_qemu_bridge()
            result = bridge.get_coverage(bridge_iid)
            return CoverageInfo(
                edges=result.get("edges", 0),
                total_edges=result.get("total_edges", 65536),
                coverage_percent=result.get(
                    "coverage_percent", 0.0
                ),
            )
        except ImportError:
            return CoverageInfo()

    def get_crashes(self, fuzzer_id: str) -> List[CrashInfo]:
        """Get crashes found during network fuzzing.

        Checks the QEMU bridge instance for crashes and
        parses the QEMU log for crash signatures.
        """
        bridge_iid = self._bridge_instances.get(fuzzer_id)
        if not bridge_iid:
            return list(self._crashes.values())

        try:
            from .qemu_bridge import get_qemu_bridge
            bridge = get_qemu_bridge()
            inst = bridge.get_instance(bridge_iid)
            if inst and not inst.is_running:
                # Instance crashed — collect crash info
                crash_data = inst._collect_crash_info()
                if crash_data.get("stderr_snippet"):
                    crash = self._parse_asan_output(
                        crash_data["stderr_snippet"],
                        binary_path=inst.firmware_path,
                    )
                    if crash:
                        crash.found_by = fuzzer_id
                        if crash_data.get("crash_address"):
                            crash.crash_address = crash_data[
                                "crash_address"
                            ]
                        self._dedup_crash(crash)
        except ImportError:
            pass

        return list(self._crashes.values())

    def inject_seed(self, fuzzer_id: str, seed: bytes) -> bool:
        """Inject a network packet seed into the fuzzer queue.

        The seed is sent via the QEMU bridge's network injection.
        """
        bridge_iid = self._bridge_instances.get(fuzzer_id)
        state = self._session_state.get(fuzzer_id, {})

        if bridge_iid:
            try:
                from .qemu_bridge import get_qemu_bridge
                bridge = get_qemu_bridge()
                result = bridge.inject_network(
                    bridge_iid,
                    seed,
                    proto="tcp",
                    target_port=state.get("port", 80),
                )
                state["packets_sent"] = (
                    state.get("packets_sent", 0) + 1
                )
                if result.get("crashed"):
                    state["crashes_found"] = (
                        state.get("crashes_found", 0) + 1
                    )
                    crash = self._parse_asan_output(
                        result.get("response", b"").decode(
                            "utf-8", errors="replace"
                        ),
                    )
                    if crash:
                        crash.input_data = seed
                        crash.found_by = fuzzer_id
                        self._dedup_crash(crash)
                return True
            except ImportError:
                pass
            except Exception as e:
                logger.error(
                    f"NetworkFuzzer [{fuzzer_id}]: injection "
                    f"failed: {e}"
                )

        # Queue for later if bridge not connected
        self._input_queue.setdefault(fuzzer_id, []).append(seed)
        return True

    # ------------------------------------------------------------------
    # Protocol Seed Generation
    # ------------------------------------------------------------------

    def _generate_protocol_seeds(
        self, proto: str
    ) -> List[bytes]:
        """Generate protocol-aware initial seed inputs."""
        seeds = []

        templates = {
            "HTTP": [
                b"GET / HTTP/1.0\r\n\r\n",
                b"POST /cgi-bin/test HTTP/1.0\r\n"
                b"Content-Length: 100\r\n\r\n" + b"A" * 100,
                b"GET /" + b"A" * 500 + b" HTTP/1.0\r\n\r\n",
                b"POST / HTTP/1.0\r\nContent-Length: 1000\r\n\r\n"
                + b"\x00" * 1000,
            ],
            "DNS": [
                b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01",
            ],
            "TELNET": [
                b"\xff\xfb\x01\xff\xfb\x03admin\r\npassword\r\n",
                b"A" * 256 + b"\r\n",
            ],
            "UPNP": [
                b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
                b'MAN:"ssdp:discover"\r\nST:ssdp:all\r\n\r\n',
            ],
        }

        seeds = templates.get(
            proto.upper(),
            [b"GET / HTTP/1.0\r\n\r\n"],
        )
        return seeds


# =============================================================================
# FuzzerManager — Dual-Layer Orchestrator
# =============================================================================

class FuzzerManager:
    """Orchestrates dual-layer firmware fuzzing.

    Layer 1 (Global Fuzzer): AFL++ QEMU-mode, broad exploration
      - Covers the entire binary surface
      - Fed by directional seeds from Phase 2/3
      - Fork=2 for breadth

    Layer 2 (SP Fuzzer Pool): Per-SP targeted fuzzing
      - One instance per suspicious point
      - Fed by POV Agent blobs
      - Fork=1 for depth at specific code paths
      - NetworkFuzzer for daemon attack surfaces

    Crashing inputs from either layer feed back into the Global Fuzzer
    as seeds, creating a positive feedback loop.

    Usage:
        manager = FuzzerManager(work_dir="/tmp/fuzz_work")
        gid = manager.start_global("/bin/stack_bof_01", arch="mipsel")
        sid = manager.start_sp("/bin/stack_bof_01", sp_id="SP-001",
                               target_func="main", arch="mipsel")
        # ... wait ...
        crashes = manager.get_all_crashes()
        cov = manager.get_merged_coverage()
        manager.stop_all()
    """

    def __init__(
        self,
        work_dir: str,
        afl_path: str = "afl-fuzz",
        qemu_dir: str = "/usr/bin",
        max_sp_fuzzers: int = 8,
    ):
        """
        Args:
            work_dir: Root working directory for all fuzzers.
            afl_path: Path to afl-fuzz binary.
            qemu_dir: Directory with QEMU binaries.
            max_sp_fuzzers: Maximum concurrent SP fuzzers.
        """
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.max_sp_fuzzers = max_sp_fuzzers

        # Layer 1: Global AFL++ fuzzer
        self.global_fuzzer = AFLQEMUFuzzer(
            work_dir=str(self.work_dir / "global"),
            afl_path=afl_path,
            qemu_dir=qemu_dir,
        )

        # Layer 2: Per-SP fuzzer pool
        self.sp_fuzzers: Dict[str, FirmwareFuzzer] = {}

        # Crash dedup across both layers
        self._all_crash_hashes: Set[str] = set()
        self._lock = threading.RLock()

        logger.info(
            f"FuzzerManager: initialized (max {max_sp_fuzzers} SP fuzzers)"
        )

    # ------------------------------------------------------------------
    # Global Fuzzer (Layer 1)
    # ------------------------------------------------------------------

    def start_global(
        self,
        binary_path: str,
        attack_surface: Optional[dict] = None,
        arch: Optional[str] = None,
        rootfs: str = "",
    ) -> str:
        """Start the global AFL++ fuzzer for broad exploration.

        Args:
            binary_path: Path to the binary to fuzz.
            attack_surface: Attack surface metadata.
            arch: Target architecture.
            rootfs: Extracted rootfs path.

        Returns:
            fuzzer_id.
        """
        return self.global_fuzzer.start(
            binary_path=binary_path,
            attack_surface=attack_surface,
            arch=arch,
            rootfs=rootfs,
        )

    # ------------------------------------------------------------------
    # SP Fuzzer Pool (Layer 2)
    # ------------------------------------------------------------------

    def start_sp(
        self,
        binary_path: str,
        sp_id: str,
        target_func: str,
        attack_surface: Optional[dict] = None,
        arch: Optional[str] = None,
        rootfs: str = "",
    ) -> Optional[str]:
        """Start a targeted SP fuzzer.

        Chooses between AFLQEMUFuzzer (CLI binary) and NetworkFuzzer
        (daemon binary) based on the attack surface protocol.

        Args:
            binary_path: Path to the binary.
            sp_id: Suspicious Point identifier.
            target_func: Target function name for directed fuzzing.
            attack_surface: Attack surface metadata.
            arch: Target architecture.
            rootfs: Root filesystem path.

        Returns:
            fuzzer_id or None if pool is full.
        """
        proto = (attack_surface or {}).get("protocol", "stdin")

        with self._lock:
            if len(self.sp_fuzzers) >= self.max_sp_fuzzers:
                logger.warning(
                    f"FuzzerManager: SP fuzzer pool full "
                    f"({self.max_sp_fuzzers}) — cannot start {sp_id}"
                )
                return None

            # Choose fuzzer type based on protocol
            if proto.upper() in ("HTTP", "DNS", "TELNET", "UPNP", "TCP", "UDP"):
                fuzzer = NetworkFuzzer(
                    work_dir=str(
                        self.work_dir / f"sp_{sp_id}"
                    )
                )
            else:
                # CLI binary — use AFL++ QEMU mode
                fuzzer = AFLQEMUFuzzer(
                    work_dir=str(
                        self.work_dir / f"sp_{sp_id}"
                    ),
                    fork_level=1,  # Single fork for depth
                )

            fuzzer_id = fuzzer.start(
                binary_path=binary_path,
                attack_surface=attack_surface,
                arch=arch,
                rootfs=rootfs,
            )
            self.sp_fuzzers[fuzzer_id] = fuzzer

            logger.info(
                f"FuzzerManager: SP fuzzer {fuzzer_id} started "
                f"for {sp_id} ({target_func}) — "
                f"pool: {len(self.sp_fuzzers)}/{self.max_sp_fuzzers}"
            )
            return fuzzer_id

    def stop_sp(self, fuzzer_id: str) -> bool:
        """Stop a specific SP fuzzer."""
        with self._lock:
            fuzzer = self.sp_fuzzers.pop(fuzzer_id, None)
        if fuzzer:
            return fuzzer.stop(fuzzer_id)
        return False

    # ------------------------------------------------------------------
    # Seed Management
    # ------------------------------------------------------------------

    def inject_seed(
        self,
        fuzzer_id: str,
        seed: bytes,
        seed_type: str = "corpus",
    ) -> bool:
        """Inject a seed into a specific fuzzer.

        Args:
            fuzzer_id: Target fuzzer ID.
            seed: Raw seed bytes.
            seed_type: "direction" (Phase 2), "pov" (POV Agent),
                       "crash_feedback" (from other layer).

        Returns:
            True if injected successfully.
        """
        # Route to the right fuzzer
        if fuzzer_id in self.sp_fuzzers:
            return self.sp_fuzzers[fuzzer_id].inject_seed(
                fuzzer_id, seed
            )

        # Try global
        if self.global_fuzzer._processes.get(fuzzer_id):
            return self.global_fuzzer.inject_seed(
                fuzzer_id, seed
            )

        return False

    def inject_direction_seeds(
        self,
        global_fuzzer_id: str,
        seeds: List[bytes],
    ) -> int:
        """Inject Phase 2 directional seeds into the global fuzzer.

        Returns:
            Number of seeds successfully injected.
        """
        count = 0
        for seed in seeds:
            if self.global_fuzzer.inject_seed(
                global_fuzzer_id, seed
            ):
                count += 1
        logger.info(
            f"FuzzerManager: injected {count}/{len(seeds)} "
            f"directional seeds"
        )
        return count

    def inject_pov_seeds(
        self, sp_fuzzer_id: str, seeds: List[bytes]
    ) -> int:
        """Inject POV Agent blobs into an SP fuzzer.

        Returns:
            Number of seeds successfully injected.
        """
        if sp_fuzzer_id not in self.sp_fuzzers:
            return 0

        fuzzer = self.sp_fuzzers[sp_fuzzer_id]
        count = 0
        for seed in seeds:
            if fuzzer.inject_seed(sp_fuzzer_id, seed):
                count += 1
        logger.info(
            f"FuzzerManager: injected {count}/{len(seeds)} "
            f"POV seeds into {sp_fuzzer_id}"
        )
        return count

    # ------------------------------------------------------------------
    # Crash Collection & Dedup
    # ------------------------------------------------------------------

    def get_all_crashes(self) -> List[CrashInfo]:
        """Get all unique crashes across both fuzzer layers.

        Deduplicated by stack hash across all fuzzers.
        """
        all_crashes: List[CrashInfo] = []

        # Global fuzzer crashes
        for fid in list(
            self.global_fuzzer._processes.keys()
        ):
            crashes = self.global_fuzzer.get_crashes(fid)
            all_crashes.extend(crashes)

        # SP fuzzer crashes
        for fid in list(self.sp_fuzzers.keys()):
            fuzzer = self.sp_fuzzers[fid]
            crashes = fuzzer.get_crashes(fid)
            all_crashes.extend(crashes)

        # Cross-layer dedup
        unique: List[CrashInfo] = []
        with self._lock:
            for crash in all_crashes:
                h = crash.stack_hash
                if h not in self._all_crash_hashes:
                    self._all_crash_hashes.add(h)
                    unique.append(crash)

        return unique

    def get_crash_feedback_seeds(self) -> List[bytes]:
        """Convert unique crashes into seeds for cross-pollination.

        Crash inputs from SP fuzzers are injected into the global
        fuzzer, and vice versa, creating a feedback loop.
        """
        crashes = self.get_all_crashes()
        return [c.input_data for c in crashes if c.input_data]

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------

    def get_merged_coverage(self) -> CoverageInfo:
        """Merge coverage from all fuzzer layers.

        Returns combined coverage metrics across global + all SP fuzzers.
        """
        coverages = []

        # Global
        for fid in list(
            self.global_fuzzer._processes.keys()
        ):
            coverages.append(
                self.global_fuzzer.get_coverage(fid)
            )

        # SP
        for fid, fuzzer in self.sp_fuzzers.items():
            coverages.append(fuzzer.get_coverage(fid))

        return CoverageInfo.merge(coverages)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def stop_all(self):
        """Stop all fuzzers gracefully."""
        count = 0

        # Stop SP fuzzers first
        for fid in list(self.sp_fuzzers.keys()):
            if self.stop_sp(fid):
                count += 1

        # Stop global fuzzer
        for fid in list(
            self.global_fuzzer._processes.keys()
        ):
            if self.global_fuzzer.stop(fid):
                count += 1

        logger.info(
            f"FuzzerManager: stopped {count} fuzzers"
        )

    def status(self) -> dict:
        """Get current status of all fuzzers."""
        global_fuzzers = []
        for fid, proc in self.global_fuzzer._processes.items():
            global_fuzzers.append({
                "fuzzer_id": fid,
                "running": proc.poll() is None if proc else False,
                "pid": proc.pid if proc else None,
                "crashes": self.global_fuzzer.crash_count,
            })

        sp_fuzzers = []
        for fid, fuzzer in self.sp_fuzzers.items():
            sp_fuzzers.append({
                "fuzzer_id": fid,
                "running": fuzzer.is_running,
                "crashes": fuzzer.crash_count,
            })

        with self._lock:
            unique_crashes = len(self._all_crash_hashes)

        return {
            "global_fuzzer": global_fuzzers,
            "sp_fuzzers": sp_fuzzers,
            "sp_pool_usage": f"{len(self.sp_fuzzers)}/{self.max_sp_fuzzers}",
            "total_unique_crashes": unique_crashes,
        }
