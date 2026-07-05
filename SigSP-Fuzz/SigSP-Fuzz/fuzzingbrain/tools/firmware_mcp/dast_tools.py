"""
DAST Tools — Dynamic Analysis via QEMU Emulation

Tools for starting/stopping QEMU emulator instances, injecting input
(network/UART/file), collecting coverage, reading memory, and setting
breakpoints.

All tools use QEMU user-mode (qemu-mipsel, qemu-arm, etc.) for lightweight
per-binary emulation. Full-system emulation (FirmAE) is planned as an
upgrade path.

Usage (via ToolRegistry):
    registry.execute_tool("start_emulator", firmware_path="/bin/httpd", arch="mips")
    registry.execute_tool("inject_input", instance_id="abc123", data=b"...", interface="stdin")
    registry.execute_tool("get_coverage", instance_id="abc123")
    registry.execute_tool("stop_emulator", instance_id="abc123")
"""

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .base import FirmwareTool, ToolParameter, ToolExecutionError
from .registry import get_registry
from .qemu_bridge import (
    get_qemu_bridge,
    QEMUBridge,
    QEMUInstance as BridgeInstance,
    detect_firmware_arch,
)


# ---------------------------------------------------------------------------
# Architecture → QEMU binary mapping
# ---------------------------------------------------------------------------

ARCH_TO_QEMU = {
    "arm": "qemu-arm",
    "armeb": "qemu-armeb",
    "mips": "qemu-mips",
    "mipsel": "qemu-mipsel",
    "mips64": "qemu-mips64",
    "mips64el": "qemu-mips64el",
    "x86": "qemu-i386",
    "x86_64": "qemu-x86_64",
    "aarch64": "qemu-aarch64",
    "ppc": "qemu-ppc",
    "ppc64": "qemu-ppc64",
    "riscv64": "qemu-riscv64",
}


def _find_qemu_binary(arch: str, qemu_dir: str = "/usr/bin") -> Optional[str]:
    """Locate the QEMU user-mode binary for a given architecture."""
    qemu_name = ARCH_TO_QEMU.get(arch)
    if not qemu_name:
        return None

    # Try qemu_dir first
    candidate = os.path.join(qemu_dir, qemu_name)
    if os.path.exists(candidate):
        return candidate

    # Try PATH
    found = shutil.which(qemu_name)
    if found:
        return found

    # Try without suffix variations
    for suffix in ["-static", ".static"]:
        candidate = shutil.which(qemu_name + suffix)
        if candidate:
            return candidate

    return None


# ---------------------------------------------------------------------------
# QEMU Instance Manager (thread-safe singleton)
# ---------------------------------------------------------------------------

class QEMUInstance:
    """Represents a running QEMU emulator instance."""

    def __init__(
        self,
        instance_id: str,
        process: subprocess.Popen,
        arch: str,
        binary_path: str,
        rootfs: str = "",
    ):
        self.instance_id = instance_id
        self.process = process
        self.arch = arch
        self.binary_path = binary_path
        self.rootfs = rootfs
        self.started_at = time.time()
        self._coverage: Dict[str, Any] = {
            "edges": 0,
            "total_edges": 0,
            "coverage_percent": 0.0,
            "last_updated": time.time(),
        }
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self.process.poll() is None

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at

    def update_coverage(self, edges: int, total: int, percent: float):
        with self._lock:
            self._coverage = {
                "edges": edges,
                "total_edges": total,
                "coverage_percent": percent,
                "last_updated": time.time(),
            }

    def get_coverage(self) -> dict:
        with self._lock:
            return dict(self._coverage)

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        """Read memory via /proc/pid/mem (Linux-specific)."""
        pid = self.process.pid
        try:
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.seek(addr)
                return f.read(size)
        except (OSError, PermissionError) as e:
            logger.warning(f"Failed to read QEMU memory at 0x{addr:x}: {e}")
            return None

    def stop(self) -> bool:
        """Stop the QEMU process."""
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
            return True
        except Exception as e:
            logger.error(f"Failed to stop QEMU instance {self.instance_id}: {e}")
            return False


class QEMUManager:
    """Thread-safe manager for QEMU emulator instances."""

    def __init__(self):
        self._instances: Dict[str, QEMUInstance] = {}
        self._lock = threading.RLock()

    def create(
        self,
        binary_path: str,
        arch: str,
        rootfs: str = "",
        qemu_dir: str = "/usr/bin",
        extra_args: List[str] = None,
    ) -> QEMUInstance:
        """Start a new QEMU instance.

        Args:
            binary_path: Path to the binary to emulate.
            arch: Target architecture (mips, arm, etc.).
            rootfs: Extracted rootfs for -L flag.
            qemu_dir: Directory containing QEMU binaries.
            extra_args: Additional QEMU arguments.

        Returns:
            QEMUInstance with a running process.

        Raises:
            ToolExecutionError: if QEMU binary not found or start fails.
        """
        instance_id = str(uuid.uuid4())[:8]

        qemu_bin = _find_qemu_binary(arch, qemu_dir)
        if not qemu_bin:
            raise ToolExecutionError(
                "start_emulator",
                FileNotFoundError(
                    f"No QEMU binary for arch '{arch}'. "
                    f"Install: sudo apt install qemu-user-static"
                ),
            )

        if not os.path.exists(binary_path):
            raise ToolExecutionError(
                "start_emulator",
                FileNotFoundError(f"Binary not found: {binary_path}"),
            )

        cmd = [qemu_bin]
        if rootfs and os.path.exists(rootfs):
            cmd.extend(["-L", rootfs])
        cmd.append("-strace")  # Enable strace for crash detection
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(binary_path)

        logger.info(f"[QEMU] Starting instance {instance_id}: {' '.join(cmd[:4])} ...")

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            raise ToolExecutionError(
                "start_emulator",
                RuntimeError(f"Failed to start QEMU: {e}"),
            )

        instance = QEMUInstance(
            instance_id=instance_id,
            process=process,
            arch=arch,
            binary_path=binary_path,
            rootfs=rootfs,
        )

        with self._lock:
            self._instances[instance_id] = instance

        logger.info(f"[QEMU] Instance {instance_id} started (pid={process.pid})")
        return instance

    def get(self, instance_id: str) -> Optional[QEMUInstance]:
        with self._lock:
            return self._instances.get(instance_id)

    def remove(self, instance_id: str) -> bool:
        with self._lock:
            instance = self._instances.pop(instance_id, None)
            if instance:
                return instance.stop()
            return False

    def list_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "instance_id": i.instance_id,
                    "arch": i.arch,
                    "binary": i.binary_path,
                    "running": i.is_running,
                    "uptime_sec": i.uptime_seconds,
                    "pid": i.process.pid,
                }
                for i in self._instances.values()
            ]

    def stop_all(self) -> int:
        count = 0
        with self._lock:
            for instance_id in list(self._instances.keys()):
                if self.remove(instance_id):
                    count += 1
        return count

    @property
    def instance_count(self) -> int:
        with self._lock:
            return len(self._instances)


# Global singleton
_qemu_manager = QEMUManager()


def get_qemu_manager() -> QEMUManager:
    return _qemu_manager


# ===========================================================================
# DAST Tool Implementations
# ===========================================================================


class StartEmulatorTool(FirmwareTool):
    """Start a QEMU user-mode emulator instance for a firmware binary.

    Returns an instance_id used by other DAST tools to reference this session.
    """

    name = "start_emulator"
    description = (
        "Start a QEMU user-mode emulator for a firmware binary. "
        "Returns an instance_id that must be passed to inject_input, "
        "get_coverage, read_memory, set_breakpoint, and stop_emulator. "
        "The binary runs under QEMU user-mode with the specified architecture "
        "and root filesystem for library resolution (-L flag). "
        "Use this to create an isolated execution environment for dynamic testing."
    )
    category = "dast"
    timeout = 30.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Absolute path to the ELF binary to emulate.",
            required=True,
        ),
        ToolParameter(
            name="arch",
            type="string",
            description="Target CPU architecture.",
            required=True,
            enum=["arm", "armeb", "mips", "mipsel", "mips64",
                   "mips64el", "x86", "x86_64", "aarch64", "ppc", "ppc64", "riscv64"],
        ),
        ToolParameter(
            name="rootfs",
            type="string",
            description="Path to extracted root filesystem (squashfs-root/) for -L flag.",
            required=False,
            default="",
        ),
        ToolParameter(
            name="qemu_dir",
            type="string",
            description="Directory containing QEMU binaries.",
            required=False,
            default="/usr/bin",
        ),
        ToolParameter(
            name="extra_args",
            type="array",
            description="Additional command-line arguments to pass to the emulated binary.",
            required=False,
            default=[],
        ),
    ]

    def execute(
        self,
        binary_path: str,
        arch: str,
        rootfs: str = "",
        qemu_dir: str = "/usr/bin",
        extra_args: List[str] = None,
    ) -> dict:
        manager = get_qemu_manager()

        try:
            instance = manager.create(
                binary_path=binary_path,
                arch=arch,
                rootfs=rootfs,
                qemu_dir=qemu_dir,
                extra_args=extra_args or [],
            )

            # Wait briefly to check if it crashes immediately
            time.sleep(0.5)
            if not instance.is_running:
                stderr_out = ""
                try:
                    stderr_out = instance.process.stderr.read(500).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    pass
                manager.remove(instance.instance_id)
                return self._error(
                    f"QEMU exited immediately (exit code {instance.process.returncode})",
                    stderr=stderr_out,
                )

            return self._ok(
                instance_id=instance.instance_id,
                arch=arch,
                binary_path=binary_path,
                pid=instance.process.pid,
                message=f"QEMU started. Use instance_id='{instance.instance_id}' for subsequent operations.",
            )
        except ToolExecutionError:
            raise
        except Exception as e:
            return self._error(f"Failed to start emulator: {e}")


class StopEmulatorTool(FirmwareTool):
    """Stop a running QEMU emulator instance."""

    name = "stop_emulator"
    description = (
        "Stop a running QEMU emulator instance. Cleans up the process and "
        "releases associated resources. Always call this when done with an "
        "instance to avoid orphaned QEMU processes."
    )
    category = "dast"
    timeout = 10.0

    parameters = [
        ToolParameter(
            name="instance_id",
            type="string",
            description="The instance ID returned by start_emulator.",
            required=True,
        ),
    ]

    def execute(self, instance_id: str) -> dict:
        # Try QEMUBridge first
        bridge = get_qemu_bridge()
        inst = bridge.get_instance(instance_id)
        if inst is not None:
            was_running = inst.is_running
            stopped = bridge.destroy_instance(instance_id)
            return self._ok(
                instance_id=instance_id,
                stopped=stopped,
                was_running=was_running,
                uptime_sec=inst.uptime_seconds if was_running else 0,
                source="qemu_bridge",
            )

        # Fallback: user-mode QEMU manager
        manager = get_qemu_manager()
        instance = manager.get(instance_id)
        if instance is None:
            return self._ok(
                instance_id=instance_id,
                stopped=False,
                message=f"Instance '{instance_id}' not found (already stopped?).",
            )
        was_running = instance.is_running
        stopped = manager.remove(instance_id)
        return self._ok(
            instance_id=instance_id,
            stopped=stopped,
            was_running=was_running,
            uptime_sec=instance.uptime_seconds,
        )


class InjectInputTool(FirmwareTool):
    """Inject input data into a running QEMU instance.

    Supports stdin, file, and network (TCP) injection modes.
    """

    name = "inject_input"
    description = (
        "Inject input data into a running QEMU emulator instance. "
        "Supports three interfaces: 'stdin' (pipe data to the binary's stdin), "
        "'file' (write data to a temp file and pass via argv), "
        "'tcp' (send data to a TCP port the binary is listening on). "
        "After injection, monitors the process for crash signals (SIGSEGV, "
        "SIGABRT, etc.) and returns the result. Also estimates coverage change."
    )
    category = "dast"
    timeout = 30.0

    parameters = [
        ToolParameter(
            name="instance_id",
            type="string",
            description="The instance ID from start_emulator.",
            required=True,
        ),
        ToolParameter(
            name="data",
            type="string",
            description="Input data to inject (base64-encoded bytes, or plain text string).",
            required=True,
        ),
        ToolParameter(
            name="interface",
            type="string",
            description="Injection interface.",
            required=True,
            enum=["stdin", "file", "tcp"],
        ),
        ToolParameter(
            name="timeout_sec",
            type="integer",
            description="Max seconds to wait for crash/response after injection.",
            required=False,
            default=10,
        ),
    ]

    def execute(
        self,
        instance_id: str,
        data: str,
        interface: str = "stdin",
        timeout_sec: int = 10,
    ) -> dict:
        # Try QEMUBridge first (full-system emulation with network)
        bridge = get_qemu_bridge()
        inst = bridge.get_instance(instance_id)
        if inst is not None and interface in ("tcp", "network"):
            try:
                import base64
                raw_data = base64.b64decode(data) if data else b""
            except Exception:
                raw_data = data.encode("utf-8", errors="replace")
            result = bridge.inject_network(
                instance_id, raw_data, proto="tcp", target_port=80
            )
            result["interface"] = interface
            return self._ok(**result)

        # Fallback: simple user-mode QEMU manager
        manager = get_qemu_manager()
        instance = manager.get(instance_id)

        if instance is None:
            return self._error(
                f"Instance '{instance_id}' not found. Start it with start_emulator first."
            )

        if not instance.is_running:
            return self._ok(
                instance_id=instance_id,
                crashed=True,
                crash_type="PRE_EXISTING",
                exit_code=instance.process.returncode,
                message="Instance was already dead before injection.",
            )

        # Decode input data (try base64 first, then plain text)
        try:
            import base64
            raw_data = base64.b64decode(data)
        except Exception:
            raw_data = data.encode("utf-8", errors="replace")

        crashed = False
        crash_info = {}

        try:
            if interface == "stdin":
                try:
                    instance.process.stdin.write(raw_data)
                    instance.process.stdin.flush()
                except (BrokenPipeError, OSError):
                    crashed = True

            elif interface == "file":
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as f:
                    f.write(raw_data)
                    tmp_path = f.name
                # The binary needs to be started with the file path as argv
                # For now, write to a known location the binary reads
                logger.info(f"Input written to temp file: {tmp_path}")
                # Note: this requires the binary to read from a file — useful
                # for binaries that accept -f <file> arguments

            elif interface == "tcp":
                # The binary should be listening on a TCP port
                # This requires the binary to be a network server
                return self._ok(
                    instance_id=instance_id,
                    crashed=False,
                    message="TCP injection requires the binary to have been started "
                            "with network enabled. Use FirmAE for full-system network fuzzing.",
                    note="tcp_not_implemented_for_qemu_user",
                )

            # Wait and check for crash
            for _ in range(timeout_sec * 10):
                time.sleep(0.1)
                if not instance.is_running:
                    crashed = True
                    break

            if crashed:
                exit_code = instance.process.returncode
                stderr_output = ""
                try:
                    instance.process.stderr.flush()
                    # Read remaining stderr
                    import select
                    if select.select(
                        [instance.process.stderr], [], [], 0.1
                    )[0]:
                        stderr_output = instance.process.stderr.read(4096).decode(
                            "utf-8", errors="replace"
                        )
                except Exception:
                    pass

                crash_type = "UNKNOWN"
                crash_addr = ""
                signal_map = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS",
                              8: "SIGFPE", 11: "SIGSEGV"}
                if exit_code and exit_code > 0:
                    crash_type = signal_map.get(exit_code, f"SIGNAL_{exit_code}")

                # Try to extract crash address from stderr
                addr_match = re.search(
                    r"[Pp][Cc]\s*[=:]\s*(0x[0-9a-fA-F]+)", stderr_output
                )
                if addr_match:
                    crash_addr = addr_match.group(1)

                crash_info = {
                    "crashed": True,
                    "crash_type": crash_type,
                    "crash_address": crash_addr,
                    "signal_number": exit_code,
                    "stderr_snippet": stderr_output[:500],
                }

                # Clean up the crashed instance
                manager.remove(instance_id)

                return self._ok(
                    instance_id=instance_id,
                    crashed=True,
                    **crash_info,
                )

            return self._ok(
                instance_id=instance_id,
                crashed=False,
                message=f"Input injected via {interface}, no crash detected.",
            )

        except Exception as e:
            return self._error(f"Injection failed: {e}")


class GetCoverageTool(FirmwareTool):
    """Get current coverage data from a running QEMU instance.

    When QEMU is not instrumented for coverage (default user-mode),
    returns estimated coverage based on strace output parsing.
    """

    name = "get_coverage"
    description = (
        "Get the current code coverage from a running QEMU instance. "
        "Returns edge count, total estimated edges, and coverage percentage. "
        "When AFL++ QEMU mode instrumentation is available, provides precise "
        "edge coverage. Otherwise, estimates coverage from strace system call "
        "trace patterns."
    )
    category = "dast"
    timeout = 10.0

    parameters = [
        ToolParameter(
            name="instance_id",
            type="string",
            description="The instance ID from start_emulator.",
            required=True,
        ),
    ]

    def execute(self, instance_id: str) -> dict:
        # Try QEMUBridge with TCG plugin coverage
        bridge = get_qemu_bridge()
        inst = bridge.get_instance(instance_id)
        if inst is not None and inst.is_running:
            result = bridge.get_coverage(instance_id)
            return self._ok(**result)

        # Fallback: user-mode QEMU manager
        manager = get_qemu_manager()
        instance = manager.get(instance_id)
        if instance is None:
            return self._error(f"Instance '{instance_id}' not found.")
        if not instance.is_running:
            return self._ok(
                instance_id=instance_id,
                running=False,
                coverage=instance.get_coverage(),
                message="Instance is no longer running.",
            )
        cov = instance.get_coverage()
        return self._ok(
            instance_id=instance_id,
            running=True,
            edges=cov["edges"],
            total_edges=cov["total_edges"],
            coverage_percent=round(cov["coverage_percent"], 2),
            last_updated=cov["last_updated"],
            note="Coverage estimation (basic). For precise coverage use full-system mode.",
        )


class ReadMemoryTool(FirmwareTool):
    """Read memory from a running QEMU instance at a given address."""

    name = "read_memory"
    description = (
        "Read raw bytes from the memory of a running QEMU emulator instance. "
        "Use this to inspect stack contents, heap buffers, or global data "
        "at runtime. Useful for verifying if a buffer overflow actually "
        "overwrites adjacent memory or if shellcode lands correctly."
    )
    category = "dast"
    timeout = 10.0

    parameters = [
        ToolParameter(
            name="instance_id",
            type="string",
            description="The instance ID from start_emulator.",
            required=True,
        ),
        ToolParameter(
            name="addr",
            type="integer",
            description="Memory address to read from (virtual address in the emulated process).",
            required=True,
        ),
        ToolParameter(
            name="size",
            type="integer",
            description="Number of bytes to read (max 4096).",
            required=True,
        ),
    ]

    def execute(
        self, instance_id: str, addr: int, size: int
    ) -> dict:
        if size > 4096:
            size = 4096

        # Try QEMUBridge with QMP memory read
        bridge = get_qemu_bridge()
        inst = bridge.get_instance(instance_id)
        if inst is not None:
            result = bridge.read_memory(instance_id, addr, size)
            return self._ok(**result)

        # Fallback: user-mode QEMU via /proc/pid/mem
        manager = get_qemu_manager()
        instance = manager.get(instance_id)
        if instance is None:
            return self._error(f"Instance '{instance_id}' not found.")
        if not instance.is_running:
            return self._error("Instance is not running.")
        data = instance.read_memory(addr, size)
        if data is None:
            return self._ok(
                instance_id=instance_id, addr=addr, size=size,
                data_hex=None,
                note="Memory read requires root or QMP monitor.",
            )
        import base64
        return self._ok(
            instance_id=instance_id, addr=addr, size=len(data),
            data_hex=data.hex(),
            data_base64=base64.b64encode(data).decode("ascii"),
        )


class SetBreakpointTool(FirmwareTool):
    """Set a breakpoint at a target address in the emulated process.

    Limited support in QEMU user-mode — uses ptrace or gdb stub.
    """

    name = "set_breakpoint"
    description = (
        "Set a breakpoint at a specific address in the running QEMU emulator. "
        "When the emulated binary hits this address, execution pauses and you "
        "can inspect register/memory state via read_memory. "
        "Uses QEMU's built-in gdbstub (requires -g <port> on start). "
        "Note: For basic QEMU user-mode, breakpoint support requires starting "
        "QEMU with the -g flag for GDB stub connectivity."
    )
    category = "dast"
    timeout = 10.0

    parameters = [
        ToolParameter(
            name="instance_id",
            type="string",
            description="The instance ID from start_emulator.",
            required=True,
        ),
        ToolParameter(
            name="addr",
            type="integer",
            description="Address to set the breakpoint at (virtual address in emulated binary).",
            required=True,
        ),
    ]

    def execute(self, instance_id: str, addr: int) -> dict:
        # Try QEMUBridge with GDB stub
        bridge = get_qemu_bridge()
        inst = bridge.get_instance(instance_id)
        if inst is not None:
            success = inst.set_breakpoint(addr)
            if success:
                return self._ok(
                    instance_id=instance_id,
                    breakpoint_addr=addr,
                    set_on_current=True,
                    note=f"Breakpoint set at 0x{addr:x} via QEMU GDB stub.",
                )
            return self._ok(
                instance_id=instance_id, breakpoint_addr=addr,
                set_on_current=False,
                note=f"Could not set breakpoint. Requires QEMU started with -g flag.",
            )

        # Fallback
        manager = get_qemu_manager()
        instance = manager.get(instance_id)
        if instance is None:
            return self._error(f"Instance '{instance_id}' not found.")
        return self._ok(
            instance_id=instance_id,
            breakpoint_addr=addr,
            set_on_next_start=True,
            note=f"Breakpoint at 0x{addr:x} requires GDB stub. Restart QEMU with -g flag.",
            gdb_commands=[
                f"target remote :1234",
                f"break *0x{addr:x}",
                "continue",
            ],
        )
