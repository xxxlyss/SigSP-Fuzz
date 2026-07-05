"""
Snapshot Manager — Fast QEMU VM State Transfer for Dual-Layer Fuzzing

The critical performance bridge between Global Fuzzer (broad exploration)
and SP Fuzzer (deep verification). Instead of cold-booting firmware (30-60s)
for every SP fuzzing session, SP Fuzzers restore from Global Fuzzer snapshots
(<5s), inheriting the coverage corpus instantly.

Architecture:
    GlobalFirmwareFuzzer (30min runtime)
        │
        ├── create_snapshot("baseline")    ← save at clean-booted state
        ├── create_snapshot("post_fuzz_10min")  ← save mid-fuzzing state
        └── create_snapshot("pre_shutdown")     ← save final corpus state
                │
                ▼  restore (<5s)
    SPFirmwareFuzzer (per-SP, deep dive)
        ├── restore_snapshot("baseline")     ← skip boot, start immediately
        ├── inject global corpus             ← inherit exploration coverage
        ├── fuzz deeply around SP            ← focused, fast iterations
        └── restore_snapshot → retry         ← fast reset between attempts

Multi-Level Snapshot Hierarchy:
    Level 0: Cold boot     (30-60s)   — from scratch
    Level 1: Baseline      (<5s restore) — firmware booted, services ready
    Level 2: Post-Global   (<5s restore) — + global corpus coverage
    Level 3: SP-Specific   (<5s restore) — + breakpoint at target addr

Performance targets:
    - Create snapshot:  <10s (QEMU savevm is near-instant for <512MB RAM)
    - Restore snapshot: <5s  (QEMU loadvm + short re-init)
    - Snapshot size:    <2× firmware (QEMU compresses RAM + device state)
    - Concurrent:       20+ snapshots managed simultaneously
    - Auto-cleanup:     delete >24h-old snapshots, keep disk usage bounded

Usage:
    from fuzzingbrain.snapshot_manager import SnapshotManager

    mgr = SnapshotManager(snapshot_dir="/tmp/qemu_snapshots")
    baseline = mgr.get_or_create_baseline("/bin/httpd", arch="mipsel",
                                          attack_surface={"protocol": "HTTP"})
    sp_snap = mgr.create_sp_snapshot(baseline, sp, global_corpus="/tmp/corpus")
"""

import fcntl
import json
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from loguru import logger


# =============================================================================
# Constants
# =============================================================================

DEFAULT_SNAPSHOT_DIR = "/tmp/qemu_snapshots"
DEFAULT_MAX_AGE_HOURS = 24
DEFAULT_MAX_SNAPSHOTS_PER_BINARY = 10
DEFAULT_BASELINE_TTL_HOURS = 24
SNAPSHOT_METADATA_FILE = "snapshot_metadata.json"
MAX_SNAPSHOT_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2GB warning threshold


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SnapshotMetadata:
    """Metadata for a single QEMU VM snapshot.

    Stored alongside the snapshot files as JSON for querying
    and lifecycle management.
    """

    snapshot_name: str
    snapshot_id: str = field(
        default_factory=lambda: uuid.uuid4().hex[:12]
    )
    binary_path: str = ""
    binary_hash: str = ""
    arch: str = ""
    level: str = "baseline"  # "baseline" | "global" | "sp_specific"

    # Timing
    created_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    last_accessed_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    ttl_hours: int = DEFAULT_BASELINE_TTL_HOURS

    # Coverage state
    coverage_edges: int = 0
    coverage_percent: float = 0.0

    # Associated metadata
    attack_surface: dict = field(default_factory=dict)
    sp_id: str = ""
    sp_target_addr: int = 0
    sp_target_func: str = ""
    global_corpus_size: int = 0
    qemu_instance_id: str = ""

    # File info
    snapshot_path: str = ""
    snapshot_size_bytes: int = 0

    # Tags for querying
    tags: List[str] = field(default_factory=list)

    @property
    def age_hours(self) -> float:
        """Age of this snapshot in hours."""
        try:
            created = datetime.fromisoformat(self.created_at)
            delta = datetime.now() - created
            return delta.total_seconds() / 3600
        except Exception:
            return float("inf")

    @property
    def is_expired(self) -> bool:
        return self.age_hours > self.ttl_hours

    def to_dict(self) -> dict:
        return {
            "snapshot_name": self.snapshot_name,
            "snapshot_id": self.snapshot_id,
            "binary_path": self.binary_path,
            "binary_hash": self.binary_hash,
            "arch": self.arch,
            "level": self.level,
            "created_at": self.created_at,
            "last_accessed_at": self.last_accessed_at,
            "age_hours": round(self.age_hours, 1),
            "ttl_hours": self.ttl_hours,
            "is_expired": self.is_expired,
            "coverage_edges": self.coverage_edges,
            "coverage_percent": self.coverage_percent,
            "attack_surface": self.attack_surface,
            "sp_id": self.sp_id,
            "sp_target_addr": (
                hex(self.sp_target_addr)
                if self.sp_target_addr
                else ""
            ),
            "sp_target_func": self.sp_target_func,
            "global_corpus_size": self.global_corpus_size,
            "qemu_instance_id": self.qemu_instance_id,
            "snapshot_path": self.snapshot_path,
            "snapshot_size_bytes": self.snapshot_size_bytes,
            "tags": self.tags,
        }

    def touch(self):
        """Update last-accessed timestamp."""
        self.last_accessed_at = datetime.now().isoformat()


@dataclass
class SnapshotStats:
    """Aggregate statistics for the snapshot manager."""

    total_snapshots: int = 0
    total_size_bytes: int = 0
    by_level: Dict[str, int] = field(default_factory=dict)
    by_arch: Dict[str, int] = field(default_factory=dict)
    expired_count: int = 0
    oldest_hours: float = 0.0
    newest_hours: float = 0.0


# =============================================================================
# SnapshotManager
# =============================================================================

class SnapshotManager:
    """QEMU VM snapshot lifecycle manager for dual-layer fuzzing.

    Manages creation, restoration, querying, and cleanup of QEMU
    emulator snapshots. The critical performance optimization:
    SP Fuzzers restore from Global Fuzzer snapshots instead of
    cold-booting, saving 30-60s per fuzzing session.

    Usage:
        mgr = SnapshotManager(snapshot_dir="/tmp/snapshots")

        # Get or create baseline (reuses if <24h old)
        baseline = mgr.get_or_create_baseline(
            "/bin/httpd", arch="mipsel",
            attack_surface={"protocol": "HTTP", "port": 80},
        )

        # Create SP-specific snapshot from baseline
        sp_snap = mgr.create_sp_snapshot(
            baseline, sp,
            global_corpus="/tmp/global_fuzzer/corpus",
        )

        # List all snapshots for a binary
        for snap in mgr.list_snapshots(binary_path="/bin/httpd"):
            print(f"{snap['snapshot_name']}: {snap['age_hours']}h old")
    """

    def __init__(
        self,
        snapshot_dir: str = DEFAULT_SNAPSHOT_DIR,
        qemu_bridge: Optional[Any] = None,
        max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
        max_per_binary: int = DEFAULT_MAX_SNAPSHOTS_PER_BINARY,
    ):
        """
        Args:
            snapshot_dir: Root directory for snapshot storage.
            qemu_bridge: QEMUBridge instance (auto-created if None).
            max_age_hours: Auto-delete snapshots older than this.
            max_per_binary: Max snapshots per binary (oldest deleted first).
        """
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_hours = max_age_hours
        self.max_per_binary = max_per_binary

        # QEMU bridge (lazy init)
        self._qemu_bridge = qemu_bridge

        # In-memory metadata index: snapshot_name → SnapshotMetadata
        self._metadata: Dict[str, SnapshotMetadata] = {}
        self._lock = threading.RLock()

        # Load existing metadata from disk
        self._load_metadata_index()

        # Background cleanup on init
        self.cleanup_old_snapshots(max_age_hours)

        logger.info(
            f"SnapshotManager: initialized — "
            f"{len(self._metadata)} snapshots in {snapshot_dir}"
        )

    # ------------------------------------------------------------------
    # Public API — Snapshot Creation
    # ------------------------------------------------------------------

    def create_snapshot(
        self,
        instance_id: str,
        snapshot_name: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """Create a QEMU VM snapshot for a running instance.

        Sends "savevm <name>" via QMP monitor, waits for completion,
        then records metadata for future queries.

        Args:
            instance_id: QEMUBridge instance ID (must be running).
            snapshot_name: Unique name for this snapshot.
            metadata: Optional dict with extra info (binary_path, arch,
                      coverage, sp_id, etc.).

        Returns:
            Path to the snapshot directory.

        Raises:
            RuntimeError: if instance not found or savevm fails.
        """
        bridge = self._get_bridge()
        instance = bridge.get_instance(instance_id)
        if instance is None:
            raise RuntimeError(
                f"Instance '{instance_id}' not found"
            )
        if not instance.is_running:
            raise RuntimeError(
                f"Instance '{instance_id}' is not running — "
                f"cannot create snapshot"
            )

        start = time.time()
        logger.info(
            f"SnapshotManager: creating snapshot "
            f"'{snapshot_name}' for instance {instance_id}..."
        )

        # 1. Create per-instance snapshot directory
        snap_dir = (
            self.snapshot_dir / instance_id / snapshot_name
        )
        snap_dir.mkdir(parents=True, exist_ok=True)

        # 2. Send savevm command via QMP (HMP fallback)
        try:
            if instance._qmp:
                result = instance._qmp.hmp(
                    f"savevm {snapshot_name}"
                )
                if "Error" in result:
                    raise RuntimeError(
                        f"savevm failed: {result}"
                    )
        except Exception as e:
            raise RuntimeError(
                f"Failed to create snapshot '{snapshot_name}': {e}"
            )

        # 3. Check snapshot was created
        snapshots = instance.list_snapshots()
        if snapshot_name not in snapshots:
            raise RuntimeError(
                f"Snapshot '{snapshot_name}' not found after "
                f"savevm — available: {snapshots}"
            )

        elapsed = time.time() - start

        # 4. Record metadata
        meta = metadata or {}
        snap_meta = SnapshotMetadata(
            snapshot_name=snapshot_name,
            binary_path=meta.get(
                "binary_path",
                getattr(instance, "firmware_path", ""),
            ),
            binary_hash=self._hash_file(
                meta.get("binary_path", "")
            ),
            arch=meta.get(
                "arch",
                getattr(instance, "arch", "unknown"),
            ),
            level=meta.get("level", "baseline"),
            coverage_edges=meta.get("coverage_edges", 0),
            coverage_percent=meta.get(
                "coverage_percent", 0.0
            ),
            attack_surface=meta.get(
                "attack_surface", {}
            ),
            sp_id=meta.get("sp_id", ""),
            sp_target_addr=meta.get("sp_target_addr", 0),
            sp_target_func=meta.get("sp_target_func", ""),
            global_corpus_size=meta.get(
                "global_corpus_size", 0
            ),
            qemu_instance_id=instance_id,
            snapshot_path=str(snap_dir),
            tags=meta.get("tags", []),
        )

        # Estimate snapshot size
        try:
            snap_meta.snapshot_size_bytes = (
                self._estimate_dir_size(snap_dir)
            )
        except Exception:
            pass

        # 5. Save metadata to disk
        self._save_snapshot_metadata(snap_meta, snap_dir)
        with self._lock:
            self._metadata[snapshot_name] = snap_meta

        logger.info(
            f"SnapshotManager: created '{snapshot_name}' "
            f"in {elapsed:.1f}s "
            f"({snap_meta.snapshot_size_bytes / 1024 / 1024:.1f}MB)"
        )

        # 6. Enforce per-binary limit
        self._enforce_per_binary_limit(
            snap_meta.binary_path
        )

        return str(snap_dir)

    def get_or_create_baseline(
        self,
        binary_path: str,
        arch: str,
        attack_surface: Optional[dict] = None,
        force_recreate: bool = False,
    ) -> str:
        """Get an existing baseline snapshot or create a new one.

        Baseline snapshot = firmware fully booted, basic services
        ready, initial coverage collected. This is the starting
        state for both Global and SP fuzzers.

        Reuses existing baseline if:
        - Same binary (matched by path + hash)
        - Same architecture
        - Created within TTL (default 24h)
        - Not force_recreate

        Args:
            binary_path: Path to the firmware binary.
            arch: Target CPU architecture.
            attack_surface: Attack surface metadata.
            force_recreate: If True, always create a new baseline.

        Returns:
            Snapshot name string.
        """
        abs_path = os.path.abspath(binary_path)
        binary_hash = self._hash_file(abs_path)

        # Check for existing baseline
        if not force_recreate:
            existing = self._find_baseline(
                abs_path, binary_hash, arch
            )
            if existing:
                existing.touch()
                self._update_metadata(existing)
                logger.info(
                    f"SnapshotManager: reusing baseline "
                    f"'{existing.snapshot_name}' "
                    f"(age={existing.age_hours:.1f}h)"
                )
                return existing.snapshot_name

        # No existing baseline — create one
        logger.info(
            f"SnapshotManager: creating new baseline for "
            f"{os.path.basename(abs_path)} ({arch})"
        )

        # Launch a fresh QEMU instance
        bridge = self._get_bridge()
        instance_id = bridge.create_instance(
            firmware_path=abs_path,
            arch=arch,
            enable_network=True,
            enable_coverage=True,
            auto_start=True,
        )

        # Wait for boot (poll QMP for "running" status)
        self._wait_for_boot(instance_id, timeout=120)

        # Collect initial coverage
        coverage = bridge.get_coverage(instance_id)

        # Create snapshot
        snapshot_name = (
            f"baseline_{os.path.basename(abs_path)}"
            f"_{arch}_{binary_hash[:8]}"
        )
        snap_path = self.create_snapshot(
            instance_id,
            snapshot_name,
            metadata={
                "binary_path": abs_path,
                "arch": arch,
                "level": "baseline",
                "attack_surface": attack_surface or {},
                "coverage_edges": coverage.get("edges", 0),
                "coverage_percent": coverage.get(
                    "coverage_percent", 0.0
                ),
                "tags": ["baseline", arch, "boot_complete"],
            },
        )

        # Keep instance running (it's the global fuzzer's base)
        # Don't destroy — let the caller manage lifecycle

        return snapshot_name

    def create_sp_snapshot(
        self,
        baseline_snapshot: str,
        sp: dict,
        global_corpus: Optional[str] = None,
        bridge_instance_id: Optional[str] = None,
    ) -> str:
        """Create an SP-specific snapshot from a baseline.

        Flow:
        1. Restore baseline snapshot → VM boots instantly
        2. Inject Global Fuzzer corpus (reach baseline coverage)
        3. Set breakpoint at SP target address
        4. Save as new SP-specific snapshot

        SP Fuzzer starts from this snapshot, immediately having:
        - Booted firmware (from baseline)
        - Global Fuzzer coverage (from corpus injection)
        - Breakpoint at SP target (for reward-guided fuzzing)

        Args:
            baseline_snapshot: Name of baseline snapshot to restore.
            sp: SuspiciousPoint dict.
            global_corpus: Path to Global Fuzzer corpus directory.
            bridge_instance_id: Existing instance ID (uses baseline's if None).

        Returns:
            SP snapshot name.
        """
        baseline_meta = self._metadata.get(baseline_snapshot)
        if baseline_meta is None:
            raise RuntimeError(
                f"Baseline snapshot '{baseline_snapshot}' "
                f"not found"
            )

        sp_id = sp.get("sp_id", f"SP-{uuid.uuid4().hex[:6]}")
        target_addr = sp.get(
            "func_addr", sp.get("target_address", 0)
        )
        target_func = sp.get(
            "function_name", sp.get("target_func", "")
        )
        sp_snapshot_name = (
            f"sp_{sp_id.lower().replace('-', '_')}"
            f"_{target_func}_{target_addr:x}"
        )

        logger.info(
            f"SnapshotManager: creating SP snapshot "
            f"'{sp_snapshot_name}' from baseline "
            f"'{baseline_snapshot}'"
        )

        # 1. Get or create instance from baseline
        bridge = self._get_bridge()
        if bridge_instance_id:
            instance_id = bridge_instance_id
        else:
            # Create a new instance and restore baseline
            instance_id = bridge.create_instance(
                firmware_path=baseline_meta.binary_path,
                arch=baseline_meta.arch,
                auto_start=True,
            )
            # Wait for boot then restore baseline
            self._wait_for_boot(instance_id, timeout=60)
            self.restore_snapshot(
                instance_id, baseline_snapshot
            )

        inst = bridge.get_instance(instance_id)

        # 2. Inject Global Fuzzer corpus
        corpus_injected = 0
        if global_corpus and os.path.isdir(global_corpus):
            corpus_dir = Path(global_corpus)
            for f in corpus_dir.iterdir():
                if (
                    f.is_file()
                    and f.name != "README.txt"
                    and f.stat().st_size < 10 * 1024
                ):
                    try:
                        seed = f.read_bytes()
                        bridge.inject_network(
                            instance_id,
                            seed,
                            target_port=baseline_meta.attack_surface.get(
                                "port", 80
                            ),
                        )
                        corpus_injected += 1
                    except Exception:
                        pass
            logger.info(
                f"SnapshotManager: injected {corpus_injected} "
                f"global corpus entries"
            )

        # 3. Set breakpoint at SP target address
        if target_addr and inst:
            inst.set_breakpoint(target_addr)

        # 4. Collect current coverage
        coverage = bridge.get_coverage(instance_id)

        # 5. Create SP snapshot
        snap_path = self.create_snapshot(
            instance_id,
            sp_snapshot_name,
            metadata={
                "binary_path": baseline_meta.binary_path,
                "arch": baseline_meta.arch,
                "level": "sp_specific",
                "sp_id": sp_id,
                "sp_target_addr": target_addr,
                "sp_target_func": target_func,
                "global_corpus_size": corpus_injected,
                "coverage_edges": coverage.get("edges", 0),
                "coverage_percent": coverage.get(
                    "coverage_percent", 0.0
                ),
                "attack_surface": baseline_meta.attack_surface,
                "tags": [
                    "sp_specific",
                    sp_id,
                    baseline_meta.arch,
                ],
            },
        )

        return sp_snapshot_name

    # ------------------------------------------------------------------
    # Public API — Snapshot Restoration
    # ------------------------------------------------------------------

    def restore_snapshot(
        self, instance_id: str, snapshot_name: str
    ) -> bool:
        """Restore a QEMU VM from a named snapshot.

        Sends "loadvm <name>" via QMP. The VM resumes from the
        exact state captured at snapshot time.

        Target restore time: <5s (vs 30-60s cold boot).

        Args:
            instance_id: QEMUBridge instance ID.
            snapshot_name: Name of the snapshot to restore.

        Returns:
            True if restored successfully.
        """
        bridge = self._get_bridge()
        instance = bridge.get_instance(instance_id)
        if instance is None:
            logger.error(
                f"SnapshotManager: instance '{instance_id}' "
                f"not found"
            )
            return False

        start = time.time()

        try:
            if instance._qmp:
                result = instance._qmp.hmp(
                    f"loadvm {snapshot_name}"
                )
                if "Error" in result:
                    logger.error(
                        f"SnapshotManager: loadvm failed: "
                        f"{result}"
                    )
                    return False
        except Exception as e:
            logger.error(
                f"SnapshotManager: restore error: {e}"
            )
            return False

        elapsed = time.time() - start

        # Update access timestamp
        with self._lock:
            meta = self._metadata.get(snapshot_name)
            if meta:
                meta.touch()
                self._update_metadata(meta)

        # Resume VM if paused
        try:
            if instance._qmp:
                instance._qmp.hmp("cont")
        except Exception:
            pass

        logger.info(
            f"SnapshotManager: restored '{snapshot_name}' "
            f"in {elapsed:.1f}s"
        )
        return True

    # ------------------------------------------------------------------
    # Public API — Query
    # ------------------------------------------------------------------

    def list_snapshots(
        self,
        binary_path: Optional[str] = None,
        level: Optional[str] = None,
        arch: Optional[str] = None,
        include_expired: bool = False,
    ) -> List[dict]:
        """List available snapshots with optional filters.

        Args:
            binary_path: Filter by binary path (substring match).
            level: Filter by level ("baseline", "global", "sp_specific").
            arch: Filter by architecture.
            include_expired: Include expired snapshots.

        Returns:
            List of snapshot metadata dicts.
        """
        with self._lock:
            snapshots = list(self._metadata.values())

        if not include_expired:
            snapshots = [
                s for s in snapshots if not s.is_expired
            ]

        if binary_path:
            snapshots = [
                s
                for s in snapshots
                if binary_path in s.binary_path
            ]
        if level:
            snapshots = [
                s for s in snapshots if s.level == level
            ]
        if arch:
            snapshots = [
                s for s in snapshots if s.arch == arch
            ]

        # Sort: newest first
        snapshots.sort(
            key=lambda s: s.created_at, reverse=True
        )
        return [s.to_dict() for s in snapshots]

    def find_baseline_for_sp(
        self,
        binary_path: str,
        sp: dict,
    ) -> Optional[str]:
        """Find the best baseline snapshot for a given SP.

        Preference order:
        1. SP-specific snapshot for this exact SP (instant)
        2. Baseline for same binary + arch (skip boot)
        3. Any baseline (least preferred)

        Args:
            binary_path: Firmware binary path.
            sp: SuspiciousPoint dict.

        Returns:
            Snapshot name or None.
        """
        abs_path = os.path.abspath(binary_path)
        sp_id = sp.get("sp_id", "")
        target_addr = sp.get("func_addr", 0)

        with self._lock:
            snapshots = list(self._metadata.values())

        # Prefer SP-specific
        for s in snapshots:
            if s.sp_id == sp_id and not s.is_expired:
                return s.snapshot_name

        # Prefer matching binary + architecture
        arch = sp.get("arch", "")
        binary_hash = self._hash_file(abs_path)
        for s in snapshots:
            if (
                s.binary_hash == binary_hash
                and (not arch or s.arch == arch)
                and s.level == "baseline"
                and not s.is_expired
            ):
                return s.snapshot_name

        # Any baseline by binary path
        for s in snapshots:
            if (
                s.binary_path == abs_path
                and not s.is_expired
            ):
                return s.snapshot_name

        return None

    def get_stats(self) -> SnapshotStats:
        """Get aggregate snapshot statistics."""
        with self._lock:
            snapshots = list(self._metadata.values())

        stats = SnapshotStats()
        stats.total_snapshots = len(snapshots)
        stats.total_size_bytes = sum(
            s.snapshot_size_bytes for s in snapshots
        )
        stats.expired_count = sum(
            1 for s in snapshots if s.is_expired
        )

        for s in snapshots:
            stats.by_level[s.level] = (
                stats.by_level.get(s.level, 0) + 1
            )
            stats.by_arch[s.arch] = (
                stats.by_arch.get(s.arch, 0) + 1
            )

        if snapshots:
            stats.oldest_hours = max(
                s.age_hours for s in snapshots
            )
            stats.newest_hours = min(
                s.age_hours for s in snapshots
            )

        return stats

    # ------------------------------------------------------------------
    # Public API — Cleanup
    # ------------------------------------------------------------------

    def cleanup_old_snapshots(
        self, max_age_hours: Optional[int] = None
    ) -> int:
        """Delete expired snapshots to prevent disk exhaustion.

        Also deletes QEMU VM snapshots via monitor for running
        instances.

        Args:
            max_age_hours: Override the default max age.

        Returns:
            Number of snapshots deleted.
        """
        max_age = max_age_hours or self.max_age_hours
        deleted = 0

        with self._lock:
            expired = [
                name
                for name, meta in self._metadata.items()
                if meta.age_hours > max_age
            ]

        bridge = self._get_bridge()

        for name in expired:
            try:
                meta = self._metadata.get(name)
                if meta is None:
                    continue

                snap_dir = Path(meta.snapshot_path)
                if snap_dir.exists():
                    shutil.rmtree(snap_dir, ignore_errors=True)

                # Also delete from QEMU if instance is running
                if meta.qemu_instance_id:
                    inst = bridge.get_instance(
                        meta.qemu_instance_id
                    )
                    if inst and inst._qmp:
                        try:
                            inst._qmp.hmp(
                                f"delvm {name}"
                            )
                        except Exception:
                            pass

                with self._lock:
                    self._metadata.pop(name, None)

                # Remove metadata file
                meta_file = (
                    snap_dir.parent / SNAPSHOT_METADATA_FILE
                )
                if meta_file.exists():
                    meta_file.unlink(missing_ok=True)

                deleted += 1
                logger.info(
                    f"SnapshotManager: deleted expired "
                    f"snapshot '{name}' "
                    f"(age={meta.age_hours:.1f}h)"
                )
            except Exception as e:
                logger.warning(
                    f"SnapshotManager: failed to delete "
                    f"'{name}': {e}"
                )

        if deleted > 0:
            logger.info(
                f"SnapshotManager: cleaned up {deleted} "
                f"expired snapshots"
            )

        return deleted

    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a specific snapshot by name."""
        with self._lock:
            meta = self._metadata.pop(snapshot_name, None)

        if meta is None:
            return False

        snap_dir = Path(meta.snapshot_path)
        if snap_dir.exists():
            shutil.rmtree(snap_dir, ignore_errors=True)

        logger.info(
            f"SnapshotManager: deleted '{snapshot_name}'"
        )
        return True

    # ------------------------------------------------------------------
    # Internal — Metadata Persistence
    # ------------------------------------------------------------------

    def _save_snapshot_metadata(
        self,
        meta: SnapshotMetadata,
        snap_dir: Path,
    ):
        """Save snapshot metadata as JSON file."""
        meta_file = snap_dir / SNAPSHOT_METADATA_FILE
        try:
            meta_file.write_text(
                json.dumps(
                    meta.to_dict(), indent=2, ensure_ascii=False
                )
            )
        except Exception as e:
            logger.warning(
                f"SnapshotManager: failed to save metadata: {e}"
            )

    def _load_metadata_index(self):
        """Load all snapshot metadata from disk on startup."""
        loaded = 0
        for meta_file in self.snapshot_dir.rglob(
            SNAPSHOT_METADATA_FILE
        ):
            try:
                data = json.loads(
                    meta_file.read_text(encoding="utf-8")
                )
                meta = SnapshotMetadata(
                    snapshot_name=data.get(
                        "snapshot_name", ""
                    ),
                    snapshot_id=data.get("snapshot_id", ""),
                    binary_path=data.get("binary_path", ""),
                    binary_hash=data.get("binary_hash", ""),
                    arch=data.get("arch", ""),
                    level=data.get("level", "baseline"),
                    created_at=data.get("created_at", ""),
                    last_accessed_at=data.get(
                        "last_accessed_at", ""
                    ),
                    ttl_hours=data.get(
                        "ttl_hours",
                        DEFAULT_BASELINE_TTL_HOURS,
                    ),
                    coverage_edges=data.get(
                        "coverage_edges", 0
                    ),
                    coverage_percent=data.get(
                        "coverage_percent", 0.0
                    ),
                    attack_surface=data.get(
                        "attack_surface", {}
                    ),
                    sp_id=data.get("sp_id", ""),
                    sp_target_addr=data.get(
                        "sp_target_addr", 0
                    ),
                    sp_target_func=data.get(
                        "sp_target_func", ""
                    ),
                    global_corpus_size=data.get(
                        "global_corpus_size", 0
                    ),
                    qemu_instance_id=data.get(
                        "qemu_instance_id", ""
                    ),
                    snapshot_path=data.get(
                        "snapshot_path", ""
                    ),
                    snapshot_size_bytes=data.get(
                        "snapshot_size_bytes", 0
                    ),
                    tags=data.get("tags", []),
                )
                self._metadata[
                    meta.snapshot_name
                ] = meta
                loaded += 1
            except Exception as e:
                logger.debug(
                    f"SnapshotManager: skip corrupted "
                    f"metadata {meta_file}: {e}"
                )

        if loaded > 0:
            logger.info(
                f"SnapshotManager: loaded {loaded} snapshot "
                f"metadata entries"
            )

    def _update_metadata(self, meta: SnapshotMetadata):
        """Update a metadata entry on disk."""
        snap_dir = Path(meta.snapshot_path)
        if snap_dir.exists():
            self._save_snapshot_metadata(meta, snap_dir)

    # ------------------------------------------------------------------
    # Internal — Helpers
    # ------------------------------------------------------------------

    def _get_bridge(self):
        """Get or create the QEMUBridge instance."""
        if self._qemu_bridge is None:
            from .tools.firmware_mcp.qemu_bridge import (
                get_qemu_bridge,
            )
            self._qemu_bridge = get_qemu_bridge()
        return self._qemu_bridge

    def _find_baseline(
        self,
        binary_path: str,
        binary_hash: str,
        arch: str,
    ) -> Optional[SnapshotMetadata]:
        """Find a valid cached baseline for the given binary."""
        with self._lock:
            for meta in self._metadata.values():
                if (
                    meta.level == "baseline"
                    and meta.binary_hash == binary_hash
                    and meta.arch == arch
                    and not meta.is_expired
                ):
                    return meta
                # Also match by path as fallback
                if (
                    meta.level == "baseline"
                    and meta.binary_path == binary_path
                    and meta.arch == arch
                    and not meta.is_expired
                ):
                    return meta
        return None

    def _wait_for_boot(
        self,
        instance_id: str,
        timeout: float = 120,
    ):
        """Wait for a QEMU instance to finish booting.

        Polls QMP query-status until the VM reports "running".
        """
        bridge = self._get_bridge()
        instance = bridge.get_instance(instance_id)
        if instance is None:
            return

        deadline = time.time() + timeout
        while time.time() < deadline:
            if instance.is_running and instance.health_check():
                # Give it a few more seconds for services to start
                time.sleep(5)
                return
            time.sleep(1)

        logger.warning(
            f"SnapshotManager: instance {instance_id} boot "
            f"wait timed out after {timeout}s"
        )

    def _enforce_per_binary_limit(
        self, binary_path: str
    ):
        """Delete oldest snapshots if per-binary limit exceeded."""
        with self._lock:
            binary_snapshots = [
                (name, meta)
                for name, meta in self._metadata.items()
                if meta.binary_path == binary_path
            ]

        if len(binary_snapshots) <= self.max_per_binary:
            return

        # Sort by age (oldest first) and delete excess
        binary_snapshots.sort(
            key=lambda x: x[1].created_at
        )
        to_delete = binary_snapshots[
            : len(binary_snapshots) - self.max_per_binary
        ]

        for name, meta in to_delete:
            logger.info(
                f"SnapshotManager: pruning old snapshot "
                f"'{name}' (per-binary limit "
                f"{self.max_per_binary})"
            )
            self.delete_snapshot(name)

    @staticmethod
    def _hash_file(filepath: str) -> str:
        """Compute SHA256 hash of a file (first 1MB for speed)."""
        if not filepath or not os.path.exists(filepath):
            return ""
        try:
            import hashlib
            sha = hashlib.sha256()
            with open(filepath, "rb") as f:
                # Hash first 1MB (fast, sufficient for identification)
                sha.update(f.read(1024 * 1024))
            return sha.hexdigest()[:16]
        except Exception:
            return ""

    @staticmethod
    def _estimate_dir_size(dirpath: Path) -> int:
        """Estimate total size of a directory in bytes."""
        total = 0
        try:
            for f in dirpath.rglob("*"):
                if f.is_file():
                    total += f.stat().st_size
        except Exception:
            pass
        return total


# =============================================================================
# Convenience Factory
# =============================================================================

def create_snapshot_manager(
    snapshot_dir: str = DEFAULT_SNAPSHOT_DIR,
    qemu_bridge=None,
    **kwargs,
) -> SnapshotManager:
    """Create a SnapshotManager with sensible defaults.

    Args:
        snapshot_dir: Root directory for snapshots.
        qemu_bridge: Optional pre-configured QEMUBridge.
        **kwargs: Passed to SnapshotManager.

    Returns:
        Configured SnapshotManager.
    """
    return SnapshotManager(
        snapshot_dir=snapshot_dir,
        qemu_bridge=qemu_bridge,
        **kwargs,
    )
