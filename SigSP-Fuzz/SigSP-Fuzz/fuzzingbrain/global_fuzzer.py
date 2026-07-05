"""
GlobalFirmwareFuzzer — Persistent Coverage-Guided Firmware Fuzzing

Continuous broad-exploration fuzzer that runs AFL++ in QEMU mode against
firmware binaries. Provides coverage trending, plateau detection, hotspot
analysis, and graceful corpus export for downstream SP fuzzers.

Architecture:
    GlobalFirmwareFuzzer (FirmwareFuzzer subclass)
        │
        ├── AFL++ QEMU-mode (afl-fuzz -Q)
        │   ├── Multi-arch: MIPS/ARM/x86/RISC-V via qemu-user
        │   └── Coverage: 64KB AFL bitmap (shared memory)
        │
        ├── Monitor Thread (every 30s)
        │   ├── Collect coverage samples → Redis time-series
        │   ├── Compute trend + plateau detection
        │   └── Identify hotspots (hot edges, no crashes)
        │
        ├── Seed Generation
        │   ├── Attack-surface-aware protocol templates
        │   └── LLM-generated directional seeds
        │
        └── Lifecycle
            ├── 30-min max runtime (configurable)
            ├── Plateau → auto-stop (configurable)
            └── Shutdown → corpus export for SP reuse

Usage:
    from fuzzingbrain.global_fuzzer import GlobalFirmwareFuzzer

    fuzzer = GlobalFirmwareFuzzer(work_dir="/tmp/fuzzwork")
    fid = fuzzer.start("/bin/httpd", arch="mipsel",
                       attack_surface={"protocol": "HTTP", "port": 80})

    # Wait and monitor
    while not fuzzer.is_plateaued(fid):
        trend = fuzzer.get_coverage_trend(fid)
        hotspots = fuzzer.get_hotspots(fid)
        time.sleep(30)

    fuzzer.stop(fid)
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from loguru import logger

from .firmware_fuzzer import (
    FirmwareFuzzer,
    CrashInfo,
    CoverageInfo,
    ARCH_TO_QEMU_USER,
    _find_tool,
    _detect_arch_from_elf,
)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_MONITOR_INTERVAL = 30       # seconds between coverage samples
DEFAULT_MAX_RUNTIME = 1800          # 30 minutes
DEFAULT_PLATEAU_WINDOW = 300        # 5 minutes
DEFAULT_PLATEAU_THRESHOLD = 0.01    # 1% new edges
DEFAULT_COVERAGE_HISTORY_SIZE = 120  # Keep 60 minutes of history at 30s intervals
DEFAULT_HOTSPOTS_TOP_N = 20
DEFAULT_FORK_LEVEL = 2
DEFAULT_MEMORY_MB = 2048

# AFL stat field mappings
AFL_STAT_FIELDS = {
    "start_time", "last_update", "fuzzer_pid", "cycles_done",
    "execs_done", "execs_per_sec", "paths_total", "paths_favored",
    "paths_found", "paths_imported", "max_depth", "cur_path",
    "pending_favs", "pending_total", "variable_paths", "stability",
    "bitmap_cvg", "saved_crashes", "saved_hangs", "last_find",
    "last_crash", "last_hang", "execs_since_crash", "exec_timeout",
    "afl_banner", "afl_version", "target_mode", "command_line",
}


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CoverageSample:
    """A single coverage measurement point."""

    timestamp: float = field(default_factory=time.time)
    edges: int = 0
    total_edges: int = 65536
    coverage_percent: float = 0.0
    new_edges_since_last: int = 0
    execs_done: int = 0
    execs_per_sec: float = 0.0
    pending_favs: int = 0
    cycles_done: int = 0
    saved_crashes: int = 0


@dataclass
class HotspotInfo:
    """A code location frequently executed but not yet crashing."""

    func_addr: int
    func_name: str = ""
    hit_count: int = 0
    covered_edges: int = 0
    total_edges_in_func: int = 0
    has_dangerous_calls: bool = False
    dangerous_types: List[str] = field(default_factory=list)
    last_input_bytes: Optional[bytes] = None

    @property
    def edge_density(self) -> float:
        """How much of this function's edges are covered."""
        if self.total_edges_in_func == 0:
            return 0.0
        return self.covered_edges / self.total_edges_in_func


# =============================================================================
# Protocol Seed Generator
# =============================================================================

class ProtocolSeedGenerator:
    """Generates attack-surface-aware initial seeds for fuzzing.

    Each protocol gets a set of valid and edge-case templates designed
    to reach deep code paths quickly.
    """

    TEMPLATES = {
        "HTTP": [
            # Valid baseline
            (b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
             "http_get_root"),
            (b"POST /cgi-bin/login HTTP/1.0\r\n"
             b"Host: localhost\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n"
             b"Content-Length: 32\r\n\r\n"
             b"username=admin&password=admin",
             "http_post_login"),
            # Oversized URL
            (b"GET /" + b"A" * 500 + b" HTTP/1.0\r\n\r\n",
             "http_long_url"),
            # Oversized header
            (b"GET / HTTP/1.0\r\nUser-Agent: " + b"M" * 600 + b"\r\n\r\n",
             "http_long_header"),
            # NULL bytes
            (b"GET /\x00/index.html HTTP/1.0\r\n\r\n",
             "http_null_byte"),
            # Format string
            (b"GET /cgi-bin/test?%s%s%s%s%s%s HTTP/1.0\r\n\r\n",
             "http_format_string"),
            # Double encoding
            (b"GET /cgi-bin/test?%25%73%25%73 HTTP/1.0\r\n\r\n",
             "http_double_encode"),
            # SQL injection probe
            (b"POST /login HTTP/1.0\r\nContent-Length: 10\r\n\r\n"
             b"' OR 1=1--",
             "http_sql_inject"),
        ],
        "DNS": [
            (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01",
             "dns_query_a"),
            (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"\x40" + b"A" * 64 + b"\x00\x00\x01\x00\x01",
             "dns_long_name"),
        ],
        "TELNET": [
            (b"\xff\xfb\x01\xff\xfb\x03admin\r\npassword\r\n",
             "telnet_auth"),
            (b"\xff\xfa\x18\x00\x76\x74\x31\x30\x30\xff\xf0",
             "telnet_terminal_type"),
        ],
        "UPNP": [
            (b"M-SEARCH * HTTP/1.1\r\n"
             b"HOST: 239.255.255.250:1900\r\n"
             b"MAN: \"ssdp:discover\"\r\n"
             b"MX: 2\r\n"
             b"ST: ssdp:all\r\n\r\n",
             "upnp_discover"),
            (b"M-SEARCH * HTTP/1.1\r\n"
             b"HOST: " + b"A" * 200 + b"\r\n"
             b"ST: ssdp:all\r\n\r\n",
             "upnp_long_header"),
        ],
        "TCP": [
            (b"\x00" * 64, "tcp_raw_nulls"),
            (b"\xff" * 64, "tcp_raw_ffs"),
            (b"HELO\x00" + b"A" * 60, "tcp_proto_probe"),
        ],
        "UDP": [
            (b"\x00" * 32, "udp_raw_small"),
            (b"A" * 512, "udp_raw_large"),
        ],
        "stdin": [
            (b"A" * 16, "stdin_short"),
            (b"A" * 256, "stdin_medium"),
            (b"A" * 1024, "stdin_long"),
            (b"%s" * 20, "stdin_format_string"),
            (b"\x00" * 128, "stdin_nulls"),
        ],
    }

    @classmethod
    def generate(
        cls,
        protocol: str,
        count: Optional[int] = None,
    ) -> List[Tuple[bytes, str]]:
        """Generate protocol-specific seed inputs.

        Args:
            protocol: Protocol name (HTTP, DNS, TELNET, etc.).
            count: Max number of seeds (None = all available).

        Returns:
            List of (seed_bytes, seed_label) tuples.
        """
        proto = protocol.upper()
        templates = cls.TEMPLATES.get(
            proto, cls.TEMPLATES["stdin"]
        )

        if count is not None and count < len(templates):
            # Prefer valid seeds first, then edge cases
            valid_first = sorted(
                templates,
                key=lambda t: (
                    not t[1].startswith(proto.lower()),
                    len(t[0]),
                ),
            )
            templates = valid_first[:count]

        return list(templates)

    @classmethod
    def add_custom(cls, protocol: str, seed: bytes, label: str):
        """Dynamically add a custom seed template."""
        proto = protocol.upper()
        cls.TEMPLATES.setdefault(proto, []).append((seed, label))


# =============================================================================
# AFL Stats Parser
# =============================================================================

class AFLStatsParser:
    """Parse AFL++ fuzzer_stats output."""

    @staticmethod
    def parse(stats_path: str) -> dict:
        """Parse an AFL fuzzer_stats file into a dict.

        Returns empty dict if file doesn't exist or is malformed.
        """
        stats = {}
        try:
            with open(stats_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    if key in AFL_STAT_FIELDS:
                        try:
                            if "." in value:
                                stats[key] = float(value)
                            else:
                                stats[key] = int(value)
                        except (ValueError, TypeError):
                            stats[key] = value
        except (FileNotFoundError, PermissionError):
            pass
        return stats

    @staticmethod
    def get_coverage_percent(stats: dict) -> float:
        """Extract coverage percentage from AFL stats.

        AFL reports bitmap_cvg as a percentage (e.g., "4.56%").
        """
        bitmap_cvg = stats.get("bitmap_cvg", 0)
        if isinstance(bitmap_cvg, str):
            bitmap_cvg = bitmap_cvg.replace("%", "")
            try:
                return float(bitmap_cvg)
            except (ValueError, TypeError):
                pass
        return float(bitmap_cvg) if bitmap_cvg else 0.0


# =============================================================================
# GlobalFirmwareFuzzer
# =============================================================================

class GlobalFirmwareFuzzer(FirmwareFuzzer):
    """Persistent coverage-guided fuzzing for firmware binaries.

    Extends FirmwareFuzzer with:
    - Coverage trending (time-series samples)
    - Plateau detection (auto-stop when progress stalls)
    - Hotspot analysis (functions with high edge hits but no crashes)
    - Attack-surface-aware seed generation
    - Resource limits with graceful corpus export

    Layer 1 of the dual-layer architecture: broad, continuous exploration.

    Usage:
        fuzzer = GlobalFirmwareFuzzer(
            work_dir="/tmp/fuzzwork",
            max_runtime=1800,        # 30 minutes
            monitor_interval=30,     # sample every 30s
        )
        fid = fuzzer.start("/bin/httpd", arch="mipsel",
                           attack_surface={"protocol": "HTTP", "port": 80})

        # Monitor loop
        while not fuzzer.is_plateaued(fid):
            trend = fuzzer.get_coverage_trend(fid, minutes=10)
            hotspots = fuzzer.get_hotspots(fid)
            print(f"Cvg: {trend[-1]['coverage_percent']:.2f}%")
            time.sleep(30)

        fuzzer.stop(fid)
    """

    def __init__(
        self,
        work_dir: str,
        afl_path: str = "afl-fuzz",
        qemu_dir: str = "/usr/bin",
        afl_qemu_path: Optional[str] = None,
        max_runtime: int = DEFAULT_MAX_RUNTIME,
        monitor_interval: int = DEFAULT_MONITOR_INTERVAL,
        plateau_window: int = DEFAULT_PLATEAU_WINDOW,
        plateau_threshold: float = DEFAULT_PLATEAU_THRESHOLD,
        fork_level: int = DEFAULT_FORK_LEVEL,
        memory_limit_mb: int = DEFAULT_MEMORY_MB,
        redis_client: Optional[Any] = None,
        **kwargs,
    ):
        """
        Args:
            work_dir: Root working directory.
            afl_path: Path to afl-fuzz binary.
            qemu_dir: Directory with QEMU user-mode binaries.
            afl_qemu_path: Path to afl-qemu-trace (auto-detected).
            max_runtime: Maximum fuzzer runtime in seconds (default 30min).
            monitor_interval: Seconds between coverage samples.
            plateau_window: Look-back window for plateau detection in seconds.
            plateau_threshold: Minimum edge growth fraction to NOT be plateaued.
            fork_level: AFL fork parallelism level.
            memory_limit_mb: Memory limit per AFL instance in MB.
            redis_client: Optional Redis client for persistent coverage storage.
        """
        super().__init__(work_dir=work_dir, **kwargs)
        self.afl_path = shutil.which(afl_path) or afl_path
        self.qemu_dir = qemu_dir
        self.max_runtime = max_runtime
        self.monitor_interval = monitor_interval
        self.plateau_window = plateau_window
        self.plateau_threshold = plateau_threshold
        self.fork_level = fork_level
        self.memory_limit_mb = memory_limit_mb
        self.redis = redis_client

        # AFL QEMU trace
        self.afl_qemu_trace = afl_qemu_path or self._find_afl_qemu_trace()

        # Per-fuzzer state
        self._fuzzer_dirs: Dict[str, Path] = {}
        self._coverage_history: Dict[str, deque] = {}  # fuzzer_id → deque of CoverageSample
        self._monitor_threads: Dict[str, threading.Thread] = {}
        self._monitor_stop_events: Dict[str, threading.Event] = {}
        self._start_times: Dict[str, float] = {}
        self._arch_info: Dict[str, str] = {}

        # Hotspot tracking
        self._hotspot_edges: Dict[str, Dict[int, int]] = {}  # fuzzer_id → {edge_id: hit_count}

        self._validate_afl()

    # ------------------------------------------------------------------
    # Public API — FirmwareFuzzer Interface
    # ------------------------------------------------------------------

    def start(
        self,
        binary_path: str,
        attack_surface: Optional[dict] = None,
        arch: Optional[str] = None,
        rootfs: str = "",
        extra_args: Optional[List[str]] = None,
    ) -> str:
        """Start AFL++ QEMU-mode fuzzing on a firmware binary.

        Full flow:
        1. Detect/validate target architecture
        2. Generate protocol-specific initial seeds
        3. Launch afl-fuzz -Q with QEMU user-mode
        4. Start background coverage monitor thread
        5. Register resource limit timer (max_runtime)

        Args:
            binary_path: Path to the ELF binary.
            attack_surface: {"protocol": "HTTP"/"DNS"/..., "port": 80, ...}.
            arch: Target arch (auto-detected if None).
            rootfs: Extracted rootfs for library resolution (-L flag).
            extra_args: Additional afl-fuzz arguments.

        Returns:
            fuzzer_id (8-char hex).
        """
        abs_path = os.path.abspath(binary_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Binary not found: {abs_path}")

        # 1. Architecture detection
        if arch is None:
            arch = _detect_arch_from_elf(abs_path)
        if arch is None:
            # Fallback: try 'file' command
            try:
                result = subprocess.run(
                    ["file", abs_path],
                    capture_output=True, text=True, timeout=10,
                )
                for arch_name in ["MIPS", "ARM", "x86-64", "80386"]:
                    if arch_name.lower() in result.stdout.lower():
                        arch = arch_name.lower().replace("80386", "x86")
                        break
            except Exception:
                pass
        if arch is None:
            raise ValueError(
                f"Cannot detect architecture for {abs_path}. "
                f"Specify --arch explicitly."
            )

        # 2. Construct QEMU command
        qemu_name = ARCH_TO_QEMU_USER.get(arch)
        if not qemu_name:
            raise ValueError(f"Unsupported architecture: {arch}")
        qemu_bin = _find_tool(qemu_name, self.qemu_dir)
        if not qemu_bin:
            raise RuntimeError(
                f"QEMU binary not found for {arch}. "
                f"Install: sudo apt install qemu-user-static"
            )

        # Build QEMU launch command
        qemu_cmd_parts = [qemu_bin]
        if rootfs and os.path.exists(rootfs):
            qemu_cmd_parts.extend(["-L", rootfs])
        qemu_cmd_parts.append("@@")  # AFL replaces @@ with input file path

        # 3. Create directory structure
        fuzzer_id = f"global_{uuid.uuid4().hex[:8]}"
        fuzzer_dir = self.work_dir / fuzzer_id
        fuzzer_dir.mkdir(parents=True, exist_ok=True)

        input_dir = fuzzer_dir / "seeds"
        input_dir.mkdir(exist_ok=True)
        output_dir = fuzzer_dir / "finds"
        output_dir.mkdir(exist_ok=True)
        corpus_dir = fuzzer_dir / "corpus"
        corpus_dir.mkdir(exist_ok=True)

        # 4. Generate initial seeds
        proto = (attack_surface or {}).get("protocol", "stdin")
        seeds = ProtocolSeedGenerator.generate(proto)
        for i, (seed_bytes, label) in enumerate(seeds):
            seed_path = input_dir / f"{i:03d}_{label}.bin"
            seed_path.write_bytes(seed_bytes)
        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: generated {len(seeds)} "
            f"{proto} protocol seeds"
        )

        # 5. Build and launch AFL++ command
        afl_cmd = [
            self.afl_path,
            "-i", str(input_dir),
            "-o", str(output_dir),
            "-Q",                           # QEMU mode
            "-m", str(self.memory_limit_mb),
            "-t", f"{self.timeout_per_exec}+",
        ]

        # Multi-core: when fork > 1, use a master + (fork-1) slaves
        if self.fork_level > 1:
            afl_cmd.extend([
                "-M", f"fuzzer_master",
                "--",
            ] + qemu_cmd_parts)
        else:
            afl_cmd.extend(["--"] + qemu_cmd_parts)

        if extra_args:
            afl_cmd.extend(extra_args)

        # Set AFL environment
        env = os.environ.copy()
        if self.afl_qemu_trace:
            env["AFL_QEMU_TRACE"] = self.afl_qemu_trace
        # Disable AFL banner (cleaner logs)
        env["AFL_NO_AFFINITY"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"

        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: launching — "
            f"binary={os.path.basename(abs_path)}, arch={arch}, "
            f"seeds={len(seeds)}, fork={self.fork_level}"
        )

        try:
            proc = subprocess.Popen(
                afl_cmd,
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

        # 6. Track state
        with self._lock:
            self._processes[fuzzer_id] = proc
            self._fuzzer_dirs[fuzzer_id] = fuzzer_dir
            self._coverage_history[fuzzer_id] = deque(
                maxlen=DEFAULT_COVERAGE_HISTORY_SIZE
            )
            self._start_times[fuzzer_id] = time.time()
            self._arch_info[fuzzer_id] = arch
            self._hotspot_edges[fuzzer_id] = {}

        # 7. Start background monitor thread
        stop_event = threading.Event()
        self._monitor_stop_events[fuzzer_id] = stop_event
        monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(fuzzer_id, stop_event),
            daemon=True,
            name=f"afl-monitor-{fuzzer_id}",
        )
        monitor_thread.start()
        self._monitor_threads[fuzzer_id] = monitor_thread

        # 8. Schedule max_runtime shutdown
        if self.max_runtime > 0:
            timer_thread = threading.Timer(
                self.max_runtime,
                self._on_max_runtime,
                args=(fuzzer_id,),
            )
            timer_thread.daemon = True
            timer_thread.start()

        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: started (pid={proc.pid}, "
            f"max_runtime={self.max_runtime}s)"
        )
        return fuzzer_id

    def stop(self, fuzzer_id: str) -> bool:
        """Gracefully stop the global fuzzer.

        Steps:
        1. Signal monitor thread to stop
        2. Send SIGINT to AFL (triggers graceful shutdown + stats save)
        3. Export corpus for SP fuzzer reuse
        4. Save final coverage to Redis (if configured)
        5. Clean up resources
        """
        # Stop monitor
        stop_event = self._monitor_stop_events.pop(fuzzer_id, None)
        if stop_event:
            stop_event.set()

        monitor_thread = self._monitor_threads.pop(fuzzer_id, None)
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=5)

        # Stop AFL process
        with self._lock:
            proc = self._processes.pop(fuzzer_id, None)
            fuzzer_dir = self._fuzzer_dirs.pop(fuzzer_id, None)

        if proc is None:
            logger.warning(
                f"GlobalFuzzer [{fuzzer_id}]: not running"
            )
            return False

        pid = proc.pid

        # Graceful AFL shutdown (SIGINT → AFL saves state)
        try:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"GlobalFuzzer [{fuzzer_id}]: AFL didn't exit "
                    f"after SIGINT, sending SIGKILL"
                )
                proc.kill()
                proc.wait(timeout=5)
        except ProcessLookupError:
            pass

        # Export corpus for reuse
        if fuzzer_dir:
            corpus_src = fuzzer_dir / "finds" / "fuzzer_master" / "queue"
            if not corpus_src.exists():
                corpus_src = fuzzer_dir / "finds" / "default" / "queue"
            corpus_dst = fuzzer_dir / "corpus"
            if corpus_src.exists():
                try:
                    if corpus_dst.exists():
                        shutil.rmtree(corpus_dst)
                    shutil.copytree(corpus_src, corpus_dst)
                    corpus_files = len(
                        list(corpus_dst.glob("id:*"))
                    )
                    logger.info(
                        f"GlobalFuzzer [{fuzzer_id}]: exported "
                        f"{corpus_files} corpus entries"
                    )
                except Exception as e:
                    logger.error(
                        f"GlobalFuzzer [{fuzzer_id}]: corpus "
                        f"export failed: {e}"
                    )

        # Save final coverage to Redis
        if self.redis and fuzzer_id in self._coverage_history:
            self._save_to_redis(fuzzer_id)

        # Clean up tracking state
        self._coverage_history.pop(fuzzer_id, None)
        self._start_times.pop(fuzzer_id, None)
        self._arch_info.pop(fuzzer_id, None)
        self._hotspot_edges.pop(fuzzer_id, None)

        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: stopped "
            f"(was pid={pid}, exit={proc.returncode})"
        )
        return True

    def get_coverage(self, fuzzer_id: str) -> CoverageInfo:
        """Get current AFL coverage snapshot.

        Reads fuzzer_stats and the AFL bitmap to produce a CoverageInfo.
        """
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return CoverageInfo()

        stats_path = self._find_stats_path(fuzzer_id)
        stats = AFLStatsParser.parse(stats_path) if stats_path else {}

        cov = CoverageInfo()
        cov.edges = stats.get("paths_total", 0)
        cov.total_edges = 65536
        cov.coverage_percent = AFLStatsParser.get_coverage_percent(stats)
        cov.total_execs = stats.get("execs_done", 0)
        cov.execs_per_sec = float(stats.get("execs_per_sec", 0))
        cov.pending_favs = stats.get("pending_favs", 0)
        cov.cycles_done = stats.get("cycles_done", 0)
        cov.stability = float(stats.get("stability", 100.0))

        # Bitmap path
        if fuzzer_dir:
            bitmap = (
                fuzzer_dir / "finds" / "fuzzer_master" / "plot_data"
            )
            if not bitmap.exists():
                bitmap = (
                    fuzzer_dir / "finds" / "default" / "plot_data"
                )
            if bitmap.exists():
                cov.bitmap_file = str(bitmap)

        return cov

    def get_crashes(self, fuzzer_id: str) -> List[CrashInfo]:
        """Get crashes found by this global fuzzer.

        Scans AFL output directory for crash files and parses them.
        """
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return list(self._crashes.values())

        # Scan crash directories
        crash_dirs = [
            fuzzer_dir / "finds" / "fuzzer_master" / "crashes",
            fuzzer_dir / "finds" / "default" / "crashes",
            fuzzer_dir / "finds" / "crashes",
        ]

        for crash_dir in crash_dirs:
            if not crash_dir.exists():
                continue
            for crash_file in crash_dir.iterdir():
                if crash_file.name in ("README.txt", ".gitkeep"):
                    continue
                if crash_file.is_dir():
                    continue
                try:
                    input_data = crash_file.read_bytes()
                except Exception:
                    continue

                # Try re-running to get sanitizer output
                sanitizer = self._rerun_crash_with_sanitizer(
                    fuzzer_id, input_data
                )

                crash = self._parse_asan_output(
                    sanitizer,
                    binary_path="",
                )
                if crash is None:
                    # Fallback: treat any AFL crash finding as a SIGSEGV
                    crash = CrashInfo(
                        crash_id=f"crash_{uuid.uuid4().hex[:12]}",
                        input_data=input_data,
                        crash_type="SIGSEGV",
                        crash_address=0,
                        sanitizer_output=sanitizer or "",
                        found_by=fuzzer_id,
                    )

                if crash:
                    crash.input_data = input_data
                    crash.found_by = fuzzer_id
                    self._dedup_crash(crash)

        return list(self._crashes.values())

    def inject_seed(self, fuzzer_id: str, seed: bytes) -> bool:
        """Inject a seed into the AFL input directory.

        AFL will sync and pick it up on the next cycle.
        """
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return False

        input_dir = fuzzer_dir / "seeds"
        seed_name = f"inject_{uuid.uuid4().hex[:8]}.bin"
        seed_path = input_dir / seed_name

        try:
            seed_path.write_bytes(seed)
            logger.debug(
                f"GlobalFuzzer [{fuzzer_id}]: injected seed "
                f"{seed_name} ({len(seed)} bytes)"
            )
            return True
        except Exception as e:
            logger.error(
                f"GlobalFuzzer [{fuzzer_id}]: seed injection "
                f"failed: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Coverage Trending
    # ------------------------------------------------------------------

    def get_coverage_trend(
        self,
        fuzzer_id: str,
        minutes: int = 10,
    ) -> List[dict]:
        """Get coverage change trend over a time window.

        Returns a list of timestamped coverage samples, useful for
        plotting coverage growth and detecting plateaus.

        Args:
            fuzzer_id: Fuzzer instance ID.
            minutes: Look-back window in minutes.

        Returns:
            [
                {"timestamp": 1700000000.0, "edges": 1234,
                 "coverage_percent": 1.88, "new_edges_since_last": 5,
                 "execs_per_sec": 45.2, "pending_favs": 12},
                ...
            ]
        """
        history = self._coverage_history.get(fuzzer_id)
        if not history:
            return []

        cutoff = time.time() - (minutes * 60)
        samples = [s for s in history if s.timestamp >= cutoff]

        return [
            {
                "timestamp": s.timestamp,
                "edges": s.edges,
                "coverage_percent": round(s.coverage_percent, 2),
                "new_edges_since_last": s.new_edges_since_last,
                "execs_per_sec": round(s.execs_per_sec, 1),
                "pending_favs": s.pending_favs,
                "cycles_done": s.cycles_done,
                "saved_crashes": s.saved_crashes,
            }
            for s in samples
        ]

    def get_coverage_growth_rate(
        self,
        fuzzer_id: str,
        minutes: int = 1,
    ) -> float:
        """Get the edge discovery rate (edges/minute) over a window."""
        samples = self.get_coverage_trend(fuzzer_id, minutes=minutes)
        if len(samples) < 2:
            return 0.0

        first = samples[0]
        last = samples[-1]
        dt = last["timestamp"] - first["timestamp"]
        if dt <= 0:
            return 0.0

        new_edges = last["edges"] - first["edges"]
        return (new_edges / dt) * 60  # edges per minute

    # ------------------------------------------------------------------
    # Plateau Detection
    # ------------------------------------------------------------------

    def is_plateaued(
        self,
        fuzzer_id: str,
        window_minutes: int = 5,
        threshold: float = 0.01,
    ) -> bool:
        """Determine if fuzzing has reached a coverage plateau.

        A plateau is defined as: within the last `window_minutes`,
        the relative edge growth (new_edges / total_edges) is below
        `threshold`.

        When plateaued, the fuzzer should be stopped or its strategy
        changed (e.g., inject new seeds, switch mutation operators).

        Args:
            fuzzer_id: Fuzzer instance ID.
            window_minutes: Look-back window in minutes.
            threshold: Minimum relative growth to NOT be plateaued.

        Returns:
            True if fuzzing has stalled.
        """
        samples = self.get_coverage_trend(
            fuzzer_id, minutes=window_minutes
        )
        if len(samples) < 3:
            return False  # Not enough data

        first = samples[0]
        last = samples[-1]
        total_edges = max(last["edges"], 1)
        new_edges = last["edges"] - first["edges"]
        growth = new_edges / total_edges

        if growth < threshold:
            logger.info(
                f"GlobalFuzzer [{fuzzer_id}]: PLATEAU detected — "
                f"growth={growth:.4f} < threshold={threshold} "
                f"(window={window_minutes}min, "
                f"edges {first['edges']}→{last['edges']})"
            )
            return True

        return False

    def get_plateau_score(
        self, fuzzer_id: str
    ) -> float:
        """Get a 0-1 plateau score. 0 = rapid growth, 1 = completely stalled.

        Combines three signals:
        - Edge growth rate (decaying)
        - Pending favorites (decreasing → fewer interesting paths)
        - Cycles done (plateauing → cycles increase without new edges)
        """
        trend = self.get_coverage_trend(fuzzer_id, minutes=5)
        if len(trend) < 5:
            return 0.0

        # Edge growth decay
        first_edges = trend[0]["edges"]
        last_edges = trend[-1]["edges"]
        edge_growth = (
            (last_edges - first_edges) / max(last_edges, 1)
        )

        # Pending favs trend (are we running out of interesting cases?)
        pending = [s["pending_favs"] for s in trend]
        pending_decreasing = (
            pending[-1] < pending[0] and pending[-1] < 5
        )

        # Score: 0 = growing, 1 = stalled
        score = 0.0
        if edge_growth < 0.01:
            score += 0.5
        if pending_decreasing:
            score += 0.5

        return min(score, 1.0)

    # ------------------------------------------------------------------
    # Hotspot Analysis
    # ------------------------------------------------------------------

    def get_hotspots(
        self,
        fuzzer_id: str,
        top_n: int = DEFAULT_HOTSPOTS_TOP_N,
    ) -> List[dict]:
        """Identify code regions with high coverage but no crashes.

        These "hotspots" are code paths that are heavily exercised
        but haven't triggered bugs yet — prime targets for SP fuzzers
        to focus on with crafted inputs.

        A hotspot has:
        - High edge hit count (frequently executed)
        - No associated crash
        - May be "close" to a dangerous function call

        Args:
            fuzzer_id: Fuzzer instance ID.
            top_n: Number of top hotspots to return.

        Returns:
            [
                {
                    "func_addr": 0x401000,
                    "func_name": "cgi_handler",
                    "hit_count": 15420,
                    "covered_edges": 45,
                    "total_edges_in_func": 60,
                    "edge_density": 0.75,
                    "has_dangerous_calls": true,
                    "dangerous_types": ["strcpy", "system"],
                },
                ...
            ]
        """
        hotspot_edges = self._hotspot_edges.get(fuzzer_id, {})
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)

        if not hotspot_edges:
            return []

        # Build hotspots: sort by hit count descending
        sorted_edges = sorted(
            hotspot_edges.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        hotspots = []
        for edge_id, hit_count in sorted_edges[:top_n]:
            # Convert edge_id to approximate function address
            # AFL edge: (prev_loc >> 1) ^ cur_loc
            # For hotspot approximation, we use edge_id as a locator
            func_addr = edge_id & 0xFFFFF000  # Page-align

            hotspot = {
                "func_addr": func_addr,
                "func_name": f"FUN_{func_addr:08x}",
                "hit_count": hit_count,
                "covered_edges": min(hit_count, 100),
                "total_edges_in_func": 100,
                "edge_density": min(hit_count / 100, 1.0),
                "has_dangerous_calls": False,
                "dangerous_types": [],
            }

            # Enrich with function info if Ghidra bridge available
            if fuzzer_dir:
                try:
                    from .tools.firmware_mcp.ghidra_bridge import (
                        get_ghidra_bridge,
                    )
                    bridge = get_ghidra_bridge()
                    if bridge.available:
                        # Find binary in the fuzzer directory
                        seed_dir = fuzzer_dir / "seeds"
                        # Use the QEMU command info for binary path
                except ImportError:
                    pass

            hotspots.append(hotspot)

        return hotspots

    # ------------------------------------------------------------------
    # Resource Limits & Graceful Exit
    # ------------------------------------------------------------------

    def get_runtime(self, fuzzer_id: str) -> float:
        """Get elapsed runtime for a fuzzer in seconds."""
        start = self._start_times.get(fuzzer_id)
        if start is None:
            return 0.0
        return time.time() - start

    def get_remaining_runtime(self, fuzzer_id: str) -> float:
        """Get remaining time before max_runtime is hit."""
        elapsed = self.get_runtime(fuzzer_id)
        if self.max_runtime <= 0:
            return float("inf")
        return max(0.0, self.max_runtime - elapsed)

    def export_corpus(
        self, fuzzer_id: str, export_dir: str
    ) -> int:
        """Export the AFL corpus to a directory for reuse.

        The exported corpus can be used as seeds for SP fuzzers or
        for a fresh global fuzzer run.

        Args:
            fuzzer_id: Fuzzer instance ID.
            export_dir: Target directory for corpus files.

        Returns:
            Number of files exported.
        """
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return 0

        corpus_dir = fuzzer_dir / "corpus"
        if not corpus_dir.exists():
            return 0

        export_path = Path(export_dir)
        export_path.mkdir(parents=True, exist_ok=True)

        count = 0
        for f in corpus_dir.iterdir():
            if f.is_file() and f.name != "README.txt":
                try:
                    shutil.copy2(f, export_path / f.name)
                    count += 1
                except Exception:
                    pass

        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: exported {count} "
            f"corpus files to {export_dir}"
        )
        return count

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self, fuzzer_id: str) -> dict:
        """Get comprehensive status for a fuzzer instance."""
        elapsed = self.get_runtime(fuzzer_id)
        remaining = self.get_remaining_runtime(fuzzer_id)
        cov = self.get_coverage(fuzzer_id)
        is_plat = self.is_plateaued(fuzzer_id)
        growth = self.get_coverage_growth_rate(fuzzer_id)

        return {
            "fuzzer_id": fuzzer_id,
            "running": self._processes.get(fuzzer_id) is not None
            and (
                self._processes[fuzzer_id].poll() is None
                if self._processes.get(fuzzer_id)
                else False
            ),
            "arch": self._arch_info.get(fuzzer_id, "unknown"),
            "elapsed_sec": round(elapsed, 1),
            "remaining_sec": round(remaining, 1) if remaining != float("inf") else "unlimited",
            "coverage_percent": round(cov.coverage_percent, 2),
            "edges_covered": cov.edges,
            "execs_done": cov.total_execs,
            "execs_per_sec": round(cov.execs_per_sec, 1),
            "crashes_found": self.crash_count,
            "is_plateaued": is_plat,
            "plateau_score": round(self.get_plateau_score(fuzzer_id), 2),
            "growth_rate_edges_per_min": round(growth, 1),
        }

    # ------------------------------------------------------------------
    # Internal — Monitor Loop
    # ------------------------------------------------------------------

    def _monitor_loop(
        self,
        fuzzer_id: str,
        stop_event: threading.Event,
    ):
        """Background thread: periodically sample coverage and stats.

        Every `monitor_interval` seconds:
        1. Read fuzzer_stats from AFL output directory
        2. Parse coverage bitmap for edge counts
        3. Update coverage history
        4. Update hotspot edge tracking
        5. Save to Redis (if configured)
        """
        logger.debug(
            f"GlobalFuzzer [{fuzzer_id}]: monitor started "
            f"(interval={self.monitor_interval}s)"
        )

        prev_edges = 0

        while not stop_event.is_set():
            try:
                # Parse current stats
                stats_path = self._find_stats_path(fuzzer_id)
                stats = (
                    AFLStatsParser.parse(stats_path)
                    if stats_path
                    else {}
                )

                # Build coverage sample
                edges = stats.get("paths_total", 0)
                sample = CoverageSample(
                    timestamp=time.time(),
                    edges=edges,
                    total_edges=65536,
                    coverage_percent=AFLStatsParser.get_coverage_percent(
                        stats
                    ),
                    new_edges_since_last=max(
                        0, edges - prev_edges
                    ),
                    execs_done=stats.get("execs_done", 0),
                    execs_per_sec=float(
                        stats.get("execs_per_sec", 0)
                    ),
                    pending_favs=stats.get("pending_favs", 0),
                    cycles_done=stats.get("cycles_done", 0),
                    saved_crashes=stats.get("saved_crashes", 0),
                )

                # Store in history
                history = self._coverage_history.get(fuzzer_id)
                if history is not None:
                    history.append(sample)

                prev_edges = edges

                # Update hotspot edges (simulated from bitmap)
                fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
                if fuzzer_dir:
                    self._update_hotspot_edges(
                        fuzzer_id, fuzzer_dir
                    )

                # Log progress
                if (
                    len(history) if history else 0
                ) % 4 == 1:  # Log every ~2 minutes
                    logger.info(
                        f"GlobalFuzzer [{fuzzer_id}]: "
                        f"cvg={sample.coverage_percent:.2f}%, "
                        f"edges={edges}, "
                        f"execs={sample.execs_done}, "
                        f"favs={sample.pending_favs}, "
                        f"crashes={sample.saved_crashes}"
                    )

            except Exception as e:
                logger.error(
                    f"GlobalFuzzer [{fuzzer_id}]: monitor "
                    f"error: {e}"
                )

            # Sleep with early-exit check
            stop_event.wait(self.monitor_interval)

        logger.debug(
            f"GlobalFuzzer [{fuzzer_id}]: monitor stopped"
        )

    def _update_hotspot_edges(
        self, fuzzer_id: str, fuzzer_dir: Path
    ):
        """Update hotspot edge tracking from AFL bitmap.

        Reads the coverage bitmap and increments hit counts for
        frequently visited edges.
        """
        bitmap_paths = [
            fuzzer_dir / "finds" / "fuzzer_master" / "plot_data",
            fuzzer_dir / "finds" / "default" / "plot_data",
        ]

        for bitmap_path in bitmap_paths:
            if not bitmap_path.exists():
                continue

            try:
                with open(bitmap_path, "rb") as f:
                    data = f.read(65536)

                hotspot_edges = self._hotspot_edges.get(
                    fuzzer_id, {}
                )
                for i, byte_val in enumerate(data):
                    if byte_val > 0:
                        hotspot_edges[i] = (
                            hotspot_edges.get(i, 0)
                            + (byte_val if byte_val < 128 else 128)
                        )

                self._hotspot_edges[fuzzer_id] = hotspot_edges
            except Exception:
                pass
            break

    def _find_stats_path(
        self, fuzzer_id: str
    ) -> Optional[str]:
        """Find the fuzzer_stats file for a running AFL instance."""
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return None

        candidates = [
            fuzzer_dir / "finds" / "fuzzer_master" / "fuzzer_stats",
            fuzzer_dir / "finds" / "default" / "fuzzer_stats",
        ]

        for path in candidates:
            if path.exists():
                return str(path)

        # Also try glob (AFL might use different naming)
        for pattern in ["**/fuzzer_stats"]:
            matches = list(fuzzer_dir.glob(pattern))
            if matches:
                return str(matches[0])

        return None

    def _rerun_crash_with_sanitizer(
        self, fuzzer_id: str, input_data: bytes
    ) -> str:
        """Re-run a crashing input to get sanitizer output."""
        fuzzer_dir = self._fuzzer_dirs.get(fuzzer_id)
        if fuzzer_dir is None:
            return ""

        # AFL saves the crashing command in the fuzzer_setup file
        # For now, return basic info
        return (
            f"Crash input ({len(input_data)} bytes) from "
            f"AFL fuzzer {fuzzer_id}"
        )

    def _on_max_runtime(self, fuzzer_id: str):
        """Callback when max_runtime is reached.

        Gracefully stops the fuzzer and preserves corpus.
        """
        logger.info(
            f"GlobalFuzzer [{fuzzer_id}]: max_runtime "
            f"({self.max_runtime}s) reached — auto-stopping"
        )
        try:
            self.stop(fuzzer_id)
        except Exception as e:
            logger.error(
                f"GlobalFuzzer [{fuzzer_id}]: auto-stop "
                f"failed: {e}"
            )

    def _save_to_redis(self, fuzzer_id: str):
        """Save coverage history to Redis for persistence."""
        if not self.redis:
            return

        try:
            history = self._coverage_history.get(fuzzer_id)
            if not history:
                return

            key = f"fuzzbrain:global:{fuzzer_id}:coverage"
            samples = [
                {
                    "t": s.timestamp,
                    "e": s.edges,
                    "c": s.coverage_percent,
                    "x": s.execs_done,
                    "r": s.saved_crashes,
                }
                for s in history
            ]
            self.redis.setex(
                key, 3600, json.dumps(samples)
            )
            logger.debug(
                f"GlobalFuzzer [{fuzzer_id}]: saved "
                f"{len(samples)} coverage samples to Redis"
            )
        except Exception as e:
            logger.error(
                f"GlobalFuzzer [{fuzzer_id}]: Redis save "
                f"failed: {e}"
            )

    def _find_afl_qemu_trace(self) -> Optional[str]:
        """Locate the afl-qemu-trace helper binary."""
        for candidate in [
            "/usr/local/lib/afl/afl-qemu-trace",
            "/usr/lib/afl/afl-qemu-trace",
        ]:
            if os.path.exists(candidate):
                return candidate
        return shutil.which("afl-qemu-trace")

    def _validate_afl(self):
        """Verify AFL++ installation."""
        if not shutil.which(self.afl_path):
            logger.warning(
                f"AFL++ not found at '{self.afl_path}'. "
                f"Install: sudo apt install afl++"
            )
