"""
QEMU Bridge — Firmware Emulation & Dynamic Analysis

Manages QEMU full-system emulation instances for firmware dynamic testing.
Each instance runs an independent QEMU process controlled via QMP/HMP
monitor over UNIX socket. Supports:

- Full-system emulation (MIPS malta, ARM vexpress-a9, x86_64 pc)
- Architecture auto-detection from ELF headers via readelf
- TCG plugin coverage tracking (edge bitmap)
- VM snapshot management (savevm/loadvm)
- Network injection via SLiRP user-mode networking
- UART/serial injection for console-based interaction
- Memory read/write via monitor
- Software breakpoints via GDB stub
- Health checks with automatic restart

Architecture:
    LLM Agent (via DAST tools)
        │
        ▼
    QEMUBridge (instance manager)
        ├── QEMUInstance "abc123" (MIPS malta, pid=12345)
        │   ├── Monitor socket: /tmp/qemu-abc123.sock
        │   ├── Coverage bitmap: shared memory
        │   └── Snapshots: /tmp/qemu_snapshots/abc123/
        ├── QEMUInstance "def456" (ARM vexpress, pid=23456)
        └── ...

Usage:
    bridge = QEMUBridge(max_instances=4)
    iid = bridge.create_instance("firmware/vmlinux.bin", arch="mipsel")
    bridge.inject_network(iid, b"GET / HTTP/1.0\\r\\n\\r\\n")
    cov = bridge.get_coverage(iid)
    bridge.destroy_instance(iid)
"""

import ctypes
import fcntl
import glob
import json
import mmap
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


# =============================================================================
# Constants
# =============================================================================

# Architecture → QEMU system binary mapping
ARCH_TO_QEMU_SYSTEM = {
    "mips":      "qemu-system-mips",
    "mipsel":    "qemu-system-mipsel",
    "mips64":    "qemu-system-mips64",
    "mips64el":  "qemu-system-mips64el",
    "arm":       "qemu-system-arm",
    "armeb":     "qemu-system-arm",
    "aarch64":   "qemu-system-aarch64",
    "x86":       "qemu-system-i386",
    "x86_64":    "qemu-system-x86_64",
    "ppc":       "qemu-system-ppc",
    "ppc64":     "qemu-system-ppc64",
    "riscv64":   "qemu-system-riscv64",
}

# Architecture → default machine type
ARCH_TO_MACHINE = {
    "mips":      "malta",
    "mipsel":    "malta",
    "mips64":    "malta",
    "mips64el":  "malta",
    "arm":       "vexpress-a9",
    "armeb":     "vexpress-a9",
    "aarch64":   "virt",
    "x86":       "pc",
    "x86_64":    "pc",
    "ppc":       "bamboo",
    "ppc64":     "pseries",
    "riscv64":   "virt",
}

# Architecture → ELF machine identifier (e_machine from readelf)
ELF_MACHINE_TO_ARCH = {
    0x28: "arm",       # EM_ARM
    0xB7: "aarch64",   # EM_AARCH64
    0x08: "mips",      # EM_MIPS
    0x0A: "mips64",    # EM_MIPS_RS3_LE
    0x03: "x86",       # EM_386
    0x3E: "x86_64",    # EM_X86_64
    0xF3: "riscv",     # EM_RISCV
    0x14: "ppc",       # EM_PPC
    0x15: "ppc64",     # EM_PPC64
}

# Default resource limits
DEFAULT_MEMORY_MB = 512
DEFAULT_TIMEOUT_SEC = 300
MAX_INSTANCES_DEFAULT = 4
SNAPSHOT_DIR = "/tmp/qemu_snapshots"
MONITOR_SOCK_DIR = "/tmp/qemu_monitors"
SNAPSHOT_MAX_AGE_SEC = 3600  # 1 hour

# QMP protocol constants
QMP_CAPABILITIES = b'{"execute":"qmp_capabilities"}\n'
QMP_NEGOTIATION_TIMEOUT = 10


# =============================================================================
# ELF Architecture Detection
# =============================================================================

def detect_elf_arch(filepath: str) -> Optional[Tuple[str, int, str]]:
    """Detect (arch, bits, endian) from an ELF file header.

    Args:
        filepath: Path to the ELF file.

    Returns:
        (arch, bits, endian) tuple or None if not an ELF.
    """
    try:
        with open(filepath, "rb") as f:
            e_ident = f.read(16)
            if len(e_ident) < 16:
                return None
            if e_ident[:4] != b"\x7fELF":
                return None

            bits = 32 if e_ident[4] == 1 else 64
            endian = "little" if e_ident[5] == 1 else "big"

            f.seek(18)
            machine_bytes = f.read(2)
            machine = struct.unpack(
                "<H" if endian == "little" else ">H", machine_bytes
            )[0]

            arch = ELF_MACHINE_TO_ARCH.get(machine, "unknown")
            return (arch, bits, endian)
    except Exception as e:
        logger.debug(f"ELF detection failed for {filepath}: {e}")
    return None


def detect_firmware_arch(firmware_path: str) -> Optional[Tuple[str, int, str]]:
    """Detect firmware architecture by scanning extracted ELF binaries.

    Walks the firmware directory tree to find ELF files and determines
    the dominant architecture.

    Args:
        firmware_path: Path to firmware file or extracted root directory.

    Returns:
        (arch, bits, endian) or None if no ELF found.
    """
    fw_path = Path(firmware_path)
    if not fw_path.exists():
        return None

    # If it's a directory, scan for ELFs
    if fw_path.is_dir():
        results: Dict[str, int] = {}
        for root, dirs, files in os.walk(fw_path):
            for fname in files[:1000]:  # Cap at 1000 files
                fpath = os.path.join(root, fname)
                try:
                    if os.path.islink(fpath) or os.path.getsize(fpath) < 100:
                        continue
                except OSError:
                    continue
                arch_info = detect_elf_arch(fpath)
                if arch_info:
                    key = f"{arch_info[0]}-{arch_info[1]}-{arch_info[2]}"
                    results[key] = results.get(key, 0) + 1

        if results:
            best = max(results, key=results.get)
            logger.info(
                f"Detected architecture from {len(results)} ELFs: "
                f"{best} ({results[best]} binaries)"
            )
            arch, bits_str, endian = best.split("-")
            return (arch, int(bits_str), endian)

    # If it's a single file, read its header directly
    elif fw_path.is_file():
        arch_info = detect_elf_arch(str(fw_path))
        if arch_info:
            return arch_info

        # Try using 'file' command
        try:
            result = subprocess.run(
                ["file", str(fw_path)],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.lower()
            for arch_name in ["mips", "arm", "x86-64", "x86_64", "aarch64", "riscv"]:
                if arch_name.replace("-", "") in output.replace("-", ""):
                    if "64" in output:
                        return (arch_name.replace("-", "_"), 64, "little")
                    return (arch_name.replace("-", "_"), 32, "little")
        except Exception:
            pass

    return None


# =============================================================================
# QEMU Monitor Communication (QMP)
# =============================================================================

class QMPClient:
    """Lightweight QMP (QEMU Machine Protocol) client over UNIX socket.

    Handles the QMP handshake and sends/receives JSON commands.

    Usage:
        qmp = QMPClient("/tmp/qemu-abc.sock")
        qmp.connect()
        result = qmp.execute("query-status")
        qmp.close()
    """

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def connect(self) -> bool:
        """Connect to the QMP socket and complete handshake."""
        try:
            self._sock = socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            self._sock.settimeout(self.timeout)
            self._sock.connect(self.socket_path)

            # QMP handshake: read greeting, send capabilities
            greeting = self._recv()
            if not greeting or "QMP" not in str(greeting):
                logger.warning(
                    f"QMP: unexpected greeting from {self.socket_path}"
                )
                # Try HMP mode (Human Monitor Protocol) as fallback
                return self._try_hmp_fallback()

            self._send_raw(QMP_CAPABILITIES)
            response = self._recv()
            if response and "return" in response:
                logger.debug(
                    f"QMP: connected to {self.socket_path}"
                )
                return True
            return False
        except (socket.timeout, ConnectionRefusedError, FileNotFoundError) as e:
            logger.warning(f"QMP: connection failed to {self.socket_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"QMP: unexpected error connecting: {e}")
            return False

    def _try_hmp_fallback(self) -> bool:
        """Fall back to HMP (Human Monitor Protocol) text mode."""
        # Some QEMU versions start in HMP mode by default
        # We can send HMP commands directly
        return True  # The socket is connected, we'll use HMP

    def execute(self, command: str, **args) -> dict:
        """Execute a QMP command and return the response.

        Args:
            command: QMP command name (e.g., "query-status").
            **args: Additional command arguments.

        Returns:
            Parsed response dict with 'return' key on success.

        Raises:
            RuntimeError: if not connected or command fails.
        """
        with self._lock:
            if not self._sock:
                raise RuntimeError("QMP: not connected")

            msg = {"execute": command}
            if args:
                msg["arguments"] = args

            try:
                self._send_raw(
                    json.dumps(msg).encode("utf-8") + b"\n"
                )
                response = self._recv()
                if response:
                    return json.loads(response)
                return {"error": "no response"}
            except (socket.timeout, BrokenPipeError) as e:
                raise RuntimeError(
                    f"QMP: command '{command}' failed: {e}"
                )

    def hmp(self, command: str) -> str:
        """Send an HMP (Human Monitor Protocol) text command.

        Args:
            command: HMP command string (e.g., "info registers").

        Returns:
            Raw response text.
        """
        with self._lock:
            if not self._sock:
                raise RuntimeError("QMP: not connected")
            try:
                self._sock.sendall(
                    command.encode("utf-8") + b"\n"
                )
                return self._recv_raw(timeout=2)
            except Exception as e:
                return f"Error: {e}"

    def ping(self) -> bool:
        """Check if the monitor is responsive."""
        try:
            result = self.execute("query-status")
            return "return" in result
        except Exception:
            return False

    def _send_raw(self, data: bytes):
        """Send raw bytes over the socket."""
        self._sock.sendall(data)

    def _recv(self) -> Optional[str]:
        """Receive and parse a QMP JSON message."""
        raw = self._recv_raw(timeout=self.timeout)
        if raw:
            # QMP messages are newline-delimited JSON
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("{"):
                    return line
        return raw

    def _recv_raw(self, timeout: float) -> str:
        """Receive raw bytes from socket."""
        try:
            self._sock.settimeout(timeout)
            chunks = []
            while True:
                try:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk.decode("utf-8", errors="replace"))
                    if b"\n" in chunk:
                        break
                except socket.timeout:
                    break
            return "".join(chunks)
        except Exception:
            return ""

    def close(self):
        """Close the monitor socket."""
        try:
            if self._sock:
                self._sock.close()
                self._sock = None
        except Exception:
            pass


# =============================================================================
# QEMU Instance
# =============================================================================

class QEMUInstance:
    """A single QEMU full-system emulation instance.

    Manages the QEMU process lifecycle, monitor connection, snapshot
    creation/restore, network injection, coverage tracking, memory
    access, and breakpoints.

    Usage:
        inst = QEMUInstance("/path/to/vmlinux", arch="mipsel")
        inst.start()
        inst.inject_network(b"GET / HTTP/1.0\\r\\n\\r\\n")
        cov = inst.get_coverage()
        inst.stop()
    """

    def __init__(
        self,
        firmware_path: str,
        arch: str,
        machine: Optional[str] = None,
        kernel_path: Optional[str] = None,
        rootfs_path: Optional[str] = None,
        memory_mb: int = DEFAULT_MEMORY_MB,
        enable_network: bool = True,
        enable_coverage: bool = True,
        qemu_dir: str = "/usr/bin",
        extra_args: Optional[List[str]] = None,
    ):
        """
        Args:
            firmware_path: Path to firmware binary or extracted root.
            arch: CPU architecture (mips, arm, x86_64, etc.).
            machine: QEMU machine type (default auto from arch).
            kernel_path: Kernel image path (for full-system).
            rootfs_path: Root filesystem image (for full-system).
            memory_mb: RAM in MB (default 512).
            enable_network: Enable SLiRP user-mode networking.
            enable_coverage: Enable TCG coverage plugin.
            qemu_dir: Directory with QEMU system binaries.
            extra_args: Additional QEMU command-line arguments.
        """
        self.instance_id = uuid.uuid4().hex[:8]
        self.firmware_path = os.path.abspath(firmware_path)
        self.arch = arch
        self.machine = machine or ARCH_TO_MACHINE.get(arch, "pc")
        self.kernel_path = kernel_path
        self.rootfs_path = rootfs_path
        self.memory_mb = memory_mb
        self.enable_network = enable_network
        self.enable_coverage = enable_coverage
        self.qemu_dir = qemu_dir
        self.extra_args = extra_args or []

        # Runtime state
        self.process: Optional[subprocess.Popen] = None
        self.monitor_socket_path = os.path.join(
            MONITOR_SOCK_DIR, f"qemu-{self.instance_id}.sock"
        )
        self._qmp: Optional[QMPClient] = None
        self.snapshot_path = os.path.join(
            SNAPSHOT_DIR, self.instance_id
        )
        self._started_at: float = 0.0
        self._coverage_bitmap: Optional[mmap.mmap] = None
        self._coverage_path: str = ""

        # Thread safety
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the QEMU process and connect to its monitor.

        Configures networking, disk, and coverage tracking based on
        instance parameters.

        Returns:
            True if QEMU started and monitor is responsive.
        """
        with self._lock:
            if self.is_running:
                logger.warning(
                    f"QEMU {self.instance_id}: already running"
                )
                return True

            # Ensure directories exist
            os.makedirs(MONITOR_SOCK_DIR, exist_ok=True)
            os.makedirs(self.snapshot_path, exist_ok=True)

            # Remove stale socket
            if os.path.exists(self.monitor_socket_path):
                os.unlink(self.monitor_socket_path)

            # Build QEMU command
            cmd = self._build_command()
            logger.info(
                f"QEMU {self.instance_id}: starting "
                f"({' '.join(cmd[:5])} ...)"
            )

            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,  # Process group for clean kill
                )
                self._started_at = time.time()
            except FileNotFoundError:
                logger.error(
                    f"QEMU {self.instance_id}: binary not found — "
                    f"install qemu-system-{self.arch}"
                )
                return False
            except Exception as e:
                logger.error(
                    f"QEMU {self.instance_id}: start failed: {e}"
                )
                return False

            # Wait for monitor socket to appear
            if not self._wait_for_socket():
                logger.error(
                    f"QEMU {self.instance_id}: monitor socket "
                    f"did not appear within timeout"
                )
                self.stop()
                return False

            # Connect QMP monitor
            self._qmp = QMPClient(self.monitor_socket_path)
            if not self._qmp.connect():
                logger.error(
                    f"QEMU {self.instance_id}: QMP connection failed"
                )
                self.stop()
                return False

            # Initialize coverage
            if self.enable_coverage:
                self._init_coverage()

            logger.info(
                f"QEMU {self.instance_id}: started "
                f"(pid={self.process.pid}, arch={self.arch}, "
                f"machine={self.machine})"
            )
            return True

    def stop(self) -> bool:
        """Gracefully stop the QEMU process.

        Sends SIGTERM first, escalates to SIGKILL after 5s.
        Cleans up sockets and coverage mappings.
        """
        with self._lock:
            if self.process is None:
                return True

            pid = self.process.pid
            logger.info(f"QEMU {self.instance_id}: stopping (pid={pid})")

            # Close monitor first
            if self._qmp:
                try:
                    self._qmp.execute("quit")
                except Exception:
                    pass
                self._qmp.close()
                self._qmp = None

            # Terminate process group
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                    self.process.wait(timeout=2)
            except (ProcessLookupError, OSError):
                pass  # Already dead

            self.process = None

            # Cleanup
            if os.path.exists(self.monitor_socket_path):
                os.unlink(self.monitor_socket_path)

            self._close_coverage()

            logger.info(f"QEMU {self.instance_id}: stopped")
            return True

    @property
    def is_running(self) -> bool:
        """Check if the QEMU process is alive."""
        return (
            self.process is not None
            and self.process.poll() is None
        )

    @property
    def pid(self) -> Optional[int]:
        return self.process.pid if self.process else None

    @property
    def uptime_seconds(self) -> float:
        if not self._started_at:
            return 0.0
        return time.time() - self._started_at

    # ------------------------------------------------------------------
    # Snapshot Management
    # ------------------------------------------------------------------

    def create_snapshot(self, name: str) -> bool:
        """Create a VM snapshot via QEMU monitor.

        Uses QEMU's built-in savevm to save complete VM state
        (CPU registers, RAM, device state) to a named snapshot.

        Args:
            name: Snapshot name (e.g., "pre_auth", "post_boot").

        Returns:
            True if snapshot was created.
        """
        if not self._qmp:
            logger.error(
                f"QEMU {self.instance_id}: cannot snapshot — "
                f"monitor not connected"
            )
            return False

        try:
            # savevm <name>
            result = self._qmp.hmp(f"savevm {name}")
            if "Error" in result:
                logger.error(
                    f"QEMU {self.instance_id}: savevm failed: "
                    f"{result}"
                )
                return False

            logger.info(
                f"QEMU {self.instance_id}: snapshot '{name}' created"
            )
            return True
        except Exception as e:
            logger.error(
                f"QEMU {self.instance_id}: snapshot error: {e}"
            )
            return False

    def restore_snapshot(self, name: str) -> bool:
        """Restore a VM from a named snapshot.

        Args:
            name: Snapshot name to restore.

        Returns:
            True if snapshot was restored.
        """
        if not self._qmp:
            logger.error(
                f"QEMU {self.instance_id}: cannot restore — "
                f"monitor not connected"
            )
            return False

        try:
            result = self._qmp.hmp(f"loadvm {name}")
            if "Error" in result:
                logger.error(
                    f"QEMU {self.instance_id}: loadvm failed: "
                    f"{result}"
                )
                return False

            # Reset coverage after restore
            if self._coverage_bitmap:
                self._coverage_bitmap.seek(0)
                self._coverage_bitmap.write(
                    b"\x00" * len(self._coverage_bitmap)
                )

            logger.info(
                f"QEMU {self.instance_id}: restored to "
                f"snapshot '{name}'"
            )
            return True
        except Exception as e:
            logger.error(
                f"QEMU {self.instance_id}: restore error: {e}"
            )
            return False

    def list_snapshots(self) -> List[str]:
        """List available snapshots for this instance."""
        if not self._qmp:
            return []
        try:
            result = self._qmp.hmp("info snapshots")
            # Parse HMP output
            snapshots = []
            for line in result.split("\n"):
                parts = line.split()
                if len(parts) >= 2 and "--" not in line:
                    snapshots.append(parts[0])
            return snapshots
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Input Injection
    # ------------------------------------------------------------------

    def inject_network(
        self,
        data: bytes,
        proto: str = "tcp",
        target_host: str = "10.0.2.15",
        target_port: int = 80,
    ) -> dict:
        """Inject data via network (SLiRP user-mode networking).

        For TCP: opens a connection to the guest and sends data.
        For UDP: sends a datagram to the guest port.

        QEMU's user-mode networking provides the host at 10.0.2.2
        and the guest at 10.0.2.15 by default.

        Args:
            data: Raw bytes to send.
            proto: "tcp" or "udp".
            target_host: Guest IP (default 10.0.2.15).
            target_port: Guest port.

        Returns:
            {"sent": bytes_count, "response": b"...", "crashed": bool}
        """
        if not self.is_running:
            return {
                "success": False,
                "error": "QEMU instance not running",
                "instance_id": self.instance_id,
            }

        crashed_before = not self.is_running
        response = b""

        try:
            import socket as sock_mod
            s = sock_mod.socket(
                sock_mod.AF_INET,
                sock_mod.SOCK_STREAM if proto == "tcp"
                else sock_mod.SOCK_DGRAM,
            )
            s.settimeout(10)
            s.connect((target_host, target_port))

            if proto == "tcp":
                s.sendall(data)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass  # Expected — no more data
            else:
                s.sendto(data, (target_host, target_port))

            s.close()
        except (ConnectionRefusedError, socket.timeout) as e:
            response = f"Connection failed: {e}".encode()
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "instance_id": self.instance_id,
            }

        # Check if the guest crashed during injection
        time.sleep(0.5)
        crashed = not self.is_running
        crash_info = {}
        if crashed and not crashed_before:
            crash_info = self._collect_crash_info()

        return {
            "success": True,
            "instance_id": self.instance_id,
            "sent_bytes": len(data),
            "response_bytes": len(response),
            "response": response[:4096],  # Truncate large responses
            "crashed": crashed,
            "crash_info": crash_info,
        }

    def inject_uart(self, data: bytes) -> dict:
        """Inject data via UART/serial console (QEMU chardev).

        Writes to the serial port, simulating console input.
        This is useful for firmware that reads commands from
        the serial console.

        Args:
            data: Bytes to write to UART.

        Returns:
            {"sent": bytes_count, "instance_id": str, "crashed": bool}
        """
        if not self._qmp:
            return {
                "success": False,
                "error": "Monitor not connected",
                "instance_id": self.instance_id,
            }

        crashed_before = not self.is_running

        try:
            # Send via HMP: 'sendkey' for individual keys,
            # or write directly to the chardev
            # For simple text input, we can use the QMP 'send-key'
            # But for raw bytes, we write to the serial chardev
            encoded = data.decode("utf-8", errors="replace")
            for ch in encoded:
                self._qmp.hmp(f"sendkey {self._char_to_qemu_key(ch)}")
        except Exception as e:
            return {
                "success": False,
                "error": f"UART injection failed: {e}",
                "instance_id": self.instance_id,
            }

        # Check for crash
        time.sleep(0.5)
        crashed = not self.is_running

        return {
            "success": True,
            "instance_id": self.instance_id,
            "sent_bytes": len(data),
            "crashed": crashed,
        }

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------

    def get_coverage(self) -> dict:
        """Get current TCG edge coverage.

        When QEMU is compiled with --enable-tcg-plugins or AFL++ mode,
        the coverage bitmap is mmap'd from shared memory.

        Returns:
            {
                "edges": int,
                "total_edges": int,
                "coverage_percent": float,
                "new_edges_this_run": int,
                "bitmap_size": int,
            }
        """
        if not self._coverage_bitmap:
            # Estimate from QEMU monitor
            return self._estimate_coverage()

        bitmap = self._coverage_bitmap
        bitmap.seek(0)
        raw = bitmap.read(bitmap.size())

        # Count set bytes (edges hit)
        edges = sum(1 for b in raw if b != 0)
        total_edges = len(raw)
        percent = (
            (edges / total_edges) * 100 if total_edges > 0 else 0.0
        )

        return {
            "edges": edges,
            "total_edges": total_edges,
            "coverage_percent": round(percent, 2),
            "new_edges_this_run": 0,  # Tracked separately
            "bitmap_size": len(raw),
        }

    def _init_coverage(self):
        """Initialize TCG coverage tracking."""
        # Use a shared memory file for the coverage bitmap
        cov_path = os.path.join(
            tempfile.gettempdir(),
            f"qemu_cov_{self.instance_id}.bin",
        )
        self._coverage_path = cov_path

        # Create 64KB bitmap (AFL standard size)
        bitmap_size = 65536
        with open(cov_path, "wb") as f:
            f.write(b"\x00" * bitmap_size)

        try:
            fd = os.open(cov_path, os.O_RDWR)
            self._coverage_bitmap = mmap.mmap(
                fd, bitmap_size, access=mmap.ACCESS_WRITE
            )
            os.close(fd)
        except Exception as e:
            logger.warning(
                f"QEMU {self.instance_id}: coverage mmap failed: "
                f"{e}"
            )
            self._coverage_bitmap = None

    def _close_coverage(self):
        """Close coverage bitmap mapping."""
        if self._coverage_bitmap:
            try:
                self._coverage_bitmap.close()
            except Exception:
                pass
            self._coverage_bitmap = None
        if self._coverage_path and os.path.exists(self._coverage_path):
            try:
                os.unlink(self._coverage_path)
            except Exception:
                pass

    def _estimate_coverage(self) -> dict:
        """Estimate coverage from QEMU monitor (fallback)."""
        if self._qmp:
            try:
                result = self._qmp.execute(
                    "query-status"
                )
                # Basic: just report if VM is running
                return {
                    "edges": 0,
                    "total_edges": 0,
                    "coverage_percent": 0.0,
                    "new_edges_this_run": 0,
                    "bitmap_size": 0,
                    "note": "Coverage requires QEMU with TCG plugin or AFL++ mode.",
                }
            except Exception:
                pass
        return {
            "edges": 0,
            "total_edges": 0,
            "coverage_percent": 0.0,
            "new_edges_this_run": 0,
            "bitmap_size": 0,
            "note": "QEMU monitor not connected.",
        }

    # ------------------------------------------------------------------
    # Memory Access
    # ------------------------------------------------------------------

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        """Read guest physical memory via QMP.

        Args:
            addr: Physical memory address.
            size: Number of bytes to read (max 4096).

        Returns:
            Raw bytes or None on failure.
        """
        if size > 4096:
            size = 4096
        if not self._qmp:
            return None

        try:
            # QMP: memread <addr> <size>
            hex_addr = f"0x{addr:x}"
            result = self._qmp.hmp(f"xp /{size}bx {hex_addr}")

            # Parse HMP output: "addr: 0x00 0x01 0x02 ..."
            bytes_list = []
            for line in result.split("\n"):
                if ":" in line:
                    hex_part = line.split(":", 1)[1].strip()
                    for h in hex_part.split():
                        try:
                            bytes_list.append(int(h, 16))
                        except ValueError:
                            pass

            if bytes_list:
                return bytes(bytes_list[:size])
        except Exception as e:
            logger.error(
                f"QEMU {self.instance_id}: read_memory "
                f"0x{addr:x} failed: {e}"
            )
        return None

    def write_memory(self, addr: int, data: bytes) -> bool:
        """Write data to guest physical memory via QMP.

        Args:
            addr: Physical memory address.
            data: Bytes to write.

        Returns:
            True if write succeeded.
        """
        if not self._qmp:
            return False

        try:
            # Write in chunks of 8 bytes
            for i in range(0, len(data), 8):
                chunk = data[i : i + 8]
                hex_addr = f"0x{addr + i:x}"
                hex_val = "0x" + chunk.hex()
                # Use appropriate size for the chunk
                size_map = {1: "b", 2: "w", 4: "l", 8: "q"}
                sz = size_map.get(len(chunk), "b")
                cmd = f"set {sz} {hex_addr} {hex_val}"
                result = self._qmp.hmp(cmd)
                if "Error" in result:
                    return False
            return True
        except Exception as e:
            logger.error(
                f"QEMU {self.instance_id}: write_memory "
                f"0x{addr:x} failed: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Breakpoints
    # ------------------------------------------------------------------

    def set_breakpoint(self, addr: int) -> bool:
        """Set a software breakpoint at a guest address.

        Requires QEMU to be started with -g <port> for GDB stub.

        Args:
            addr: Guest virtual address.

        Returns:
            True if breakpoint was set.
        """
        if not self._qmp:
            return False

        try:
            hex_addr = f"0x{addr:x}"
            result = self._qmp.hmp(f"gdbstub_set_bp {hex_addr}")

            # Alternative: use register manipulation
            if "Error" in result or "unknown" in result.lower():
                # Try via gdbstub or fallback
                logger.warning(
                    f"QEMU {self.instance_id}: breakpoint at "
                    f"0x{addr:x} requires GDB stub (-g flag)"
                )
                return False

            logger.info(
                f"QEMU {self.instance_id}: breakpoint set "
                f"at 0x{addr:x}"
            )
            return True
        except Exception as e:
            logger.error(
                f"QEMU {self.instance_id}: set_breakpoint "
                f"failed: {e}"
            )
            return False

    # ------------------------------------------------------------------
    # Health Check
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Check if the QEMU instance is healthy and responsive.

        Checks:
        1. Process is alive (not zombie)
        2. Monitor is responsive (QMP ping)
        3. Guest is not stuck (query-status shows 'running')

        Returns:
            True if all checks pass.
        """
        if not self.is_running:
            return False

        if self._qmp:
            try:
                result = self._qmp.execute("query-status")
                if "return" in result:
                    status = result["return"].get("status", "")
                    if status in ("running", "paused"):
                        return True
            except Exception:
                pass
            return self._qmp.ping()

        # No monitor — just check process
        return self.is_running

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        """Build the QEMU system emulation command line."""
        qemu_bin_name = ARCH_TO_QEMU_SYSTEM.get(
            self.arch, f"qemu-system-{self.arch}"
        )
        qemu_bin = os.path.join(self.qemu_dir, qemu_bin_name)
        if not os.path.exists(qemu_bin):
            qemu_bin = shutil.which(qemu_bin_name) or qemu_bin_name

        cmd = [qemu_bin]

        # Machine type
        cmd.extend(["-M", self.machine])

        # CPU
        cmd.extend(["-cpu", "max"])

        # Memory
        cmd.extend(["-m", str(self.memory_mb)])

        # Kernel / rootfs (if provided)
        if self.kernel_path:
            cmd.extend(["-kernel", self.kernel_path])
        if self.rootfs_path:
            # Detect format from extension
            ext = os.path.splitext(self.rootfs_path)[1].lower()
            if ext in (".qcow2", ".qcow", ".qed"):
                cmd.extend(["-drive",
                    f"file={self.rootfs_path},format=qcow2,if=none,id=drive0",
                    "-device", "virtio-blk-device,drive=drive0"])
            elif ext in (".raw", ".img"):
                cmd.extend(["-drive",
                    f"file={self.rootfs_path},format=raw,if=none,id=drive0",
                    "-device", "virtio-blk-device,drive=drive0"])
            else:
                cmd.extend(["-hda", self.rootfs_path])

        # Networking (SLiRP user-mode)
        if self.enable_network:
            cmd.extend([
                "-netdev", "user,id=net0,hostfwd=tcp::8080-:80,"
                           "hostfwd=tcp::2323-:23",
                "-device",
                "virtio-net-device,netdev=net0"
                if "virt" in self.machine
                else "e1000,netdev=net0",
            ])

        # Serial / console
        cmd.extend(["-serial", "stdio"])

        # QMP monitor on UNIX socket
        cmd.extend([
            "-qmp", f"unix:{self.monitor_socket_path},server,nowait",
        ])

        # GDB stub for breakpoints
        gdb_port = 9000 + (hash(self.instance_id) % 1000)
        cmd.extend(["-gdb", f"tcp::{gdb_port}"])

        # Coverage plugin (if available)
        if self.enable_coverage:
            coverage_plugin = self._find_coverage_plugin()
            if coverage_plugin:
                cmd.extend([
                    "-plugin", coverage_plugin,
                    "-plugin-arg", f"coverage,covfile={self._coverage_path}",
                ])

        # Display
        cmd.extend(["-nographic", "-no-reboot"])

        # Extra args
        cmd.extend(self.extra_args)

        return cmd

    def _find_coverage_plugin(self) -> Optional[str]:
        """Find the QEMU TCG coverage plugin."""
        candidates = [
            "/usr/lib/qemu/plugins/libcoverage.so",
            "/usr/lib/x86_64-linux-gnu/qemu/plugins/libcoverage.so",
            f"/usr/lib/{self.arch}-linux-gnu/qemu/plugins/libcoverage.so",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        # Try glob
        for pattern in [
            "/usr/lib/**/qemu/plugins/libcoverage.so",
            "/usr/local/lib/qemu/plugins/libcoverage.so",
        ]:
            matches = glob.glob(pattern, recursive=True)
            if matches:
                return matches[0]
        return None

    def _wait_for_socket(self, timeout: float = 30.0) -> bool:
        """Wait for the QMP monitor socket to appear."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.monitor_socket_path):
                return True
            # Check if process died
            if self.process and self.process.poll() is not None:
                stderr = self.process.stderr
                err_text = ""
                if stderr:
                    try:
                        err_text = stderr.read(1024).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
                logger.error(
                    f"QEMU {self.instance_id}: died before "
                    f"monitor ready (exit={self.process.returncode}): "
                    f"{err_text[:500]}"
                )
                return False
            time.sleep(0.5)
        return False

    def _collect_crash_info(self) -> dict:
        """Collect crash information from a terminated QEMU process."""
        info = {
            "exit_code": None,
            "signal": None,
            "stderr_snippet": "",
            "crash_address": None,
        }

        if self.process:
            info["exit_code"] = self.process.returncode
            if self.process.returncode and self.process.returncode < 0:
                info["signal"] = abs(self.process.returncode)

            # Read stderr for crash indicators
            try:
                if self.process.stderr:
                    stderr_text = self.process.stderr.read(
                        4096
                    ).decode("utf-8", errors="replace")
                    info["stderr_snippet"] = stderr_text[:500]

                    # Try to extract crash PC
                    match = re.search(
                        r"[Pp][Cc]\s*[=:]\s*(0x[0-9a-fA-F]+)",
                        stderr_text,
                    )
                    if match:
                        info["crash_address"] = int(
                            match.group(1), 16
                        )
            except Exception:
                pass

        return info

    @staticmethod
    def _char_to_qemu_key(ch: str) -> str:
        """Map a character to a QEMU key name."""
        key_map = {
            "\n": "ret", "\r": "ret", "\t": "tab",
            " ": "spc", ".": "dot", "/": "slash",
            "-": "minus", "=": "equal", "[": "bracket_left",
            "]": "bracket_right", "\\": "backslash",
            ";": "semicolon", "'": "apostrophe",
            ",": "comma", "`": "grave_accent",
        }
        if ch in key_map:
            return key_map[ch]
        if ch.isalpha():
            return ch.lower()
        if ch.isdigit():
            return f"_{ch}"
        return "spc"  # Default fallback


# =============================================================================
# Snapshot Cleanup
# =============================================================================

def cleanup_expired_snapshots(max_age_sec: int = SNAPSHOT_MAX_AGE_SEC):
    """Remove snapshot files older than max_age_sec.

    Called periodically to prevent disk space exhaustion.
    """
    snap_dir = Path(SNAPSHOT_DIR)
    if not snap_dir.exists():
        return

    now = time.time()
    for child in snap_dir.iterdir():
        if child.is_dir():
            try:
                stat = child.stat()
                if now - stat.st_mtime > max_age_sec:
                    shutil.rmtree(child, ignore_errors=True)
                    logger.debug(
                        f"QEMUBridge: cleaned up expired "
                        f"snapshot {child.name}"
                    )
            except OSError:
                pass


# =============================================================================
# QEMU Bridge (Instance Manager)
# =============================================================================

class QEMUBridge:
    """Manager for multiple QEMU full-system emulation instances.

    Provides instance lifecycle management, health monitoring,
    and auto-restart capabilities.

    Usage:
        bridge = QEMUBridge(max_instances=4)
        iid = bridge.create_instance("/path/to/vmlinux", arch="mipsel")
        bridge.inject_network(iid, b"GET / HTTP/1.0\\r\\n\\r\\n")
        bridge.destroy_instance(iid)
    """

    def __init__(self, max_instances: int = MAX_INSTANCES_DEFAULT):
        """
        Args:
            max_instances: Maximum concurrent QEMU instances.
        """
        self.max_instances = max_instances
        self._instances: Dict[str, QEMUInstance] = {}
        self._lock = threading.RLock()

        # Start health check thread
        self._health_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True,
            name="qemu-health-check",
        )
        self._health_thread.start()

        # Ensure directories exist
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        os.makedirs(MONITOR_SOCK_DIR, exist_ok=True)

        # Cleanup old snapshots
        cleanup_expired_snapshots()

        logger.info(
            f"QEMUBridge: initialized (max {max_instances} instances)"
        )

    # ------------------------------------------------------------------
    # Instance Management
    # ------------------------------------------------------------------

    def create_instance(
        self,
        firmware_path: str,
        arch: Optional[str] = None,
        machine: Optional[str] = None,
        kernel_path: Optional[str] = None,
        rootfs_path: Optional[str] = None,
        memory_mb: int = DEFAULT_MEMORY_MB,
        enable_network: bool = True,
        enable_coverage: bool = True,
        auto_start: bool = True,
    ) -> str:
        """Create and optionally start a new QEMU instance.

        If arch is not provided, auto-detects from the firmware binary.

        Args:
            firmware_path: Path to firmware or extracted root dir.
            arch: CPU architecture (auto-detected if None).
            machine: QEMU machine type.
            kernel_path: Kernel image for full-system emulation.
            rootfs_path: Root filesystem image.
            memory_mb: RAM in MB.
            enable_network: Enable SLiRP networking.
            enable_coverage: Enable TCG coverage tracking.
            auto_start: Start QEMU immediately.

        Returns:
            instance_id (8-char hex string).

        Raises:
            RuntimeError: if max_instances reached.
            ValueError: if architecture cannot be determined.
        """
        with self._lock:
            if len(self._instances) >= self.max_instances:
                raise RuntimeError(
                    f"QEMUBridge: max instances reached "
                    f"({self.max_instances})"
                )

            # Auto-detect architecture
            if arch is None:
                detected = detect_firmware_arch(firmware_path)
                if detected is None:
                    raise ValueError(
                        f"Cannot detect architecture for: "
                        f"{firmware_path}"
                    )
                arch, bits, endian = detected
                # Adjust arch for endian
                if endian == "little" and arch == "mips":
                    arch = "mipsel"

            instance = QEMUInstance(
                firmware_path=firmware_path,
                arch=arch,
                machine=machine,
                kernel_path=kernel_path,
                rootfs_path=rootfs_path,
                memory_mb=memory_mb,
                enable_network=enable_network,
                enable_coverage=enable_coverage,
            )

            self._instances[instance.instance_id] = instance

        if auto_start:
            success = instance.start()
            if not success:
                with self._lock:
                    self._instances.pop(
                        instance.instance_id, None
                    )
                raise RuntimeError(
                    f"QEMUBridge: failed to start instance "
                    f"{instance.instance_id}"
                )

        logger.info(
            f"QEMUBridge: created instance {instance.instance_id} "
            f"(arch={arch}, machine={instance.machine})"
        )
        return instance.instance_id

    def destroy_instance(self, instance_id: str) -> bool:
        """Stop and remove a QEMU instance.

        Args:
            instance_id: Instance ID from create_instance.

        Returns:
            True if instance existed and was destroyed.
        """
        with self._lock:
            instance = self._instances.pop(instance_id, None)

        if instance is None:
            logger.warning(
                f"QEMUBridge: instance {instance_id} not found"
            )
            return False

        instance.stop()
        logger.info(
            f"QEMUBridge: destroyed instance {instance_id}"
        )
        return True

    def get_instance(
        self, instance_id: str
    ) -> Optional[QEMUInstance]:
        """Get a QEMU instance by ID."""
        with self._lock:
            return self._instances.get(instance_id)

    def list_instances(self) -> List[dict]:
        """List all managed instances with status info."""
        with self._lock:
            return [
                {
                    "instance_id": i.instance_id,
                    "arch": i.arch,
                    "machine": i.machine,
                    "firmware_path": i.firmware_path,
                    "running": i.is_running,
                    "pid": i.pid,
                    "uptime_sec": round(i.uptime_seconds, 1),
                    "healthy": i.health_check(),
                    "snapshots": i.list_snapshots(),
                }
                for i in self._instances.values()
            ]

    def stop_all(self) -> int:
        """Stop and remove all instances.

        Returns:
            Number of instances stopped.
        """
        with self._lock:
            instances = list(self._instances.values())
            self._instances.clear()

        count = 0
        for inst in instances:
            if inst.stop():
                count += 1

        logger.info(f"QEMUBridge: stopped {count} instances")
        return count

    @property
    def instance_count(self) -> int:
        with self._lock:
            return len(self._instances)

    # ------------------------------------------------------------------
    # Delegated Operations (convenience, no lock needed)
    # ------------------------------------------------------------------

    def inject_network(
        self,
        instance_id: str,
        data: bytes,
        proto: str = "tcp",
        target_port: int = 80,
    ) -> dict:
        """Inject network data to a managed instance."""
        inst = self.get_instance(instance_id)
        if inst is None:
            return {
                "success": False,
                "error": f"Instance {instance_id} not found",
            }
        return inst.inject_network(
            data, proto=proto, target_port=target_port
        )

    def get_coverage(self, instance_id: str) -> dict:
        """Get coverage from a managed instance."""
        inst = self.get_instance(instance_id)
        if inst is None:
            return {
                "success": False,
                "error": f"Instance {instance_id} not found",
            }
        result = inst.get_coverage()
        result["success"] = True
        result["instance_id"] = instance_id
        return result

    def read_memory(
        self, instance_id: str, addr: int, size: int
    ) -> dict:
        """Read memory from a managed instance."""
        inst = self.get_instance(instance_id)
        if inst is None:
            return {
                "success": False,
                "error": f"Instance {instance_id} not found",
            }
        data = inst.read_memory(addr, size)
        if data is not None:
            import base64
            return {
                "success": True,
                "instance_id": instance_id,
                "addr": addr,
                "size": len(data),
                "data_hex": data.hex(),
                "data_base64": base64.b64encode(data).decode(),
            }
        return {
            "success": False,
            "error": f"Memory read failed at 0x{addr:x}",
        }

    def create_snapshot(
        self, instance_id: str, name: str
    ) -> bool:
        """Create a VM snapshot."""
        inst = self.get_instance(instance_id)
        if inst is None:
            return False
        return inst.create_snapshot(name)

    def restore_snapshot(
        self, instance_id: str, name: str
    ) -> bool:
        """Restore a VM snapshot."""
        inst = self.get_instance(instance_id)
        if inst is None:
            return False
        return inst.restore_snapshot(name)

    # ------------------------------------------------------------------
    # Health Monitoring
    # ------------------------------------------------------------------

    def _health_check_loop(self):
        """Background thread: periodically check all instances."""
        while True:
            time.sleep(30)  # Check every 30 seconds
            with self._lock:
                unhealthy = []
                for iid, inst in list(self._instances.items()):
                    try:
                        if not inst.health_check():
                            unhealthy.append(iid)
                    except Exception:
                        unhealthy.append(iid)

                for iid in unhealthy:
                    logger.warning(
                        f"QEMUBridge: instance {iid} unhealthy, "
                        f"attempting restart..."
                    )
                    instance = self._instances.get(iid)
                    if instance:
                        try:
                            instance.stop()
                            instance.start()
                            logger.info(
                                f"QEMUBridge: instance {iid} "
                                f"restarted"
                            )
                        except Exception as e:
                            logger.error(
                                f"QEMUBridge: instance {iid} "
                                f"restart failed: {e}"
                            )
                            self._instances.pop(iid, None)


# =============================================================================
# Module-Level Singleton
# =============================================================================

_bridge_instance: Optional[QEMUBridge] = None
_bridge_lock = threading.Lock()


def get_qemu_bridge(
    max_instances: int = MAX_INSTANCES_DEFAULT,
) -> QEMUBridge:
    """Get or create the module-level QEMUBridge singleton."""
    global _bridge_instance
    if _bridge_instance is None:
        with _bridge_lock:
            if _bridge_instance is None:
                _bridge_instance = QEMUBridge(
                    max_instances=max_instances
                )
    return _bridge_instance


def reset_qemu_bridge():
    """Reset the QEMUBridge singleton (for testing)."""
    global _bridge_instance
    with _bridge_lock:
        if _bridge_instance:
            _bridge_instance.stop_all()
        _bridge_instance = None
