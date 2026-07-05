"""
QEMURunner -- L2 user-mode emulation verification.

Uses QEMU user-mode (qemu-arm, qemu-mipsel, etc.) to run individual
binaries with PoC input and capture crash signals.

**Input Modes** (auto-detected from PoC type / SP input_vector):
  - stdin:   Pipe payload to binary's stdin (CLI tools, stack_bof_01)
  - argv:    Pass payload as command-line argument
  - network: Start daemon in background, deliver payload via curl/nc,
             monitor for crash via QEMU -strace output

Requirements:
- QEMU user-mode binaries installed (qemu-arm, qemu-mipsel, etc.)
- Extracted rootfs for library dependencies (-L flag)
- Target binary extracted from firmware
"""

import enum
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from ..agents.firmware.sp_models import VerifiedSP
from .models import PoC, VerificationResult, CrashInfo


# ---------------------------------------------------------------------------
# Input Mode
# ---------------------------------------------------------------------------

class InputMode(enum.Enum):
    STDIN = "stdin"       # Pipe payload to binary's stdin
    ARGV = "argv"         # Pass payload as command-line argument
    NETWORK = "network"   # Start daemon, deliver via HTTP/TCP/UDP


# Maps SP input_vector patterns to InputMode
INPUT_VECTOR_TO_MODE = {
    "stdin": InputMode.STDIN,
    "argv": InputMode.ARGV,
    "http_post": InputMode.NETWORK,
    "http_get": InputMode.NETWORK,
    "network_packet": InputMode.NETWORK,
    "udp_packet": InputMode.NETWORK,
    "tcp_stream": InputMode.NETWORK,
    "cgi_param": InputMode.NETWORK,
}


def detect_input_mode(sp: "VerifiedSP", poc: "PoC") -> InputMode:
    """Detect the best input delivery mode for an SP+PoC pair."""
    # 1. Try SP input_vector first
    mode = INPUT_VECTOR_TO_MODE.get(sp.input_vector)
    if mode:
        return mode

    # 2. Try PoC type
    poc_mode_map = {
        "stdin_input": InputMode.STDIN,
        "http_request": InputMode.NETWORK,
        "http_response": InputMode.NETWORK,
        "udp_packet": InputMode.NETWORK,
        "tcp_stream": InputMode.NETWORK,
        "other": InputMode.STDIN,
    }
    mode = poc_mode_map.get(poc.poc_type)
    if mode:
        return mode

    # 3. Default: stdin for safety
    return InputMode.STDIN


class QEMURunner:
    """L2: QEMU user-mode emulation verification.

    Runs the target binary under QEMU user-mode, delivers PoC payload
    through the appropriate input mode, and monitors for crash signals.

    Usage:
        runner = QEMURunner(qemu_dir="/usr/bin", rootfs_dir="/path/to/rootfs")
        result = runner.verify(sp, poc, binary_path="/path/to/binary", arch="arm")
    """

    # Architecture -> QEMU binary mapping
    # "mips" defaults to little-endian (most common in embedded firmware)
    ARCH_TO_QEMU = {
        "arm": "qemu-arm",
        "armeb": "qemu-armeb",
        "mips": "qemu-mipsel",       # default: little-endian (more common)
        "mipseb": "qemu-mips",       # explicit big-endian
        "mipsel": "qemu-mipsel",
        "mips64": "qemu-mips64el",
        "mips64el": "qemu-mips64el",
        "mips64eb": "qemu-mips64",
        "x86": "qemu-i386",
        "x86_64": "qemu-x86_64",
        "aarch64": "qemu-aarch64",
        "ppc": "qemu-ppc",
        "ppc64": "qemu-ppc64",
        "riscv64": "qemu-riscv64",
    }

    # QEMU signal -> (CrashType, SignalNumber) mapping
    SIGNAL_MAP = {
        4: ("SIGILL", 4),
        6: ("SIGABRT", 6),
        7: ("SIGBUS", 7),
        8: ("SIGFPE", 8),
        11: ("SIGSEGV", 11),
    }

    # Common ports to probe for daemon readiness
    PROBE_PORTS = [80, 8080, 443, 8443, 23, 2323, 8888, 9000]

    def __init__(
        self,
        qemu_dir: str = "/usr/bin",
        rootfs_dir: str = "",
        timeout: int = 30,
        daemon_startup_timeout: int = 10,
        daemon_probe_ports: Optional[List[int]] = None,
    ):
        self.qemu_dir = Path(qemu_dir)
        self.rootfs_dir = rootfs_dir
        self.timeout = timeout
        self.daemon_startup_timeout = daemon_startup_timeout
        self.daemon_probe_ports = daemon_probe_ports or self.PROBE_PORTS
        self._background_process: Optional[subprocess.Popen] = None

    # -- Public API ----------------------------------------------------------

    def verify(
        self,
        sp: VerifiedSP,
        poc: PoC,
        binary_path: str,
        arch: str,
    ) -> VerificationResult:
        """Attempt L2 verification via QEMU user-mode.

        Auto-detects input mode (stdin / network) and routes accordingly.
        """
        input_mode = detect_input_mode(sp, poc)
        logger.info(
            f"QEMURunner: verifying {sp.sp_id} (arch={arch}, mode={input_mode.value})"
        )

        # Detect QEMU binary
        qemu_bin = self._detect_qemu_binary(arch)
        if not qemu_bin:
            error_msg = (
                f"QEMU binary not found for arch '{arch}'. "
                f"Supported: {sorted(self.ARCH_TO_QEMU.keys())}"
            )
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Check target binary exists
        if not Path(binary_path).exists():
            error_msg = f"Target binary not found: {binary_path}"
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Route to appropriate mode
        if input_mode == InputMode.STDIN:
            return self._verify_stdin(sp, poc, qemu_bin, binary_path, arch)
        elif input_mode == InputMode.ARGV:
            return self._verify_argv(sp, poc, qemu_bin, binary_path, arch)
        elif input_mode == InputMode.NETWORK:
            return self._verify_network(sp, poc, qemu_bin, binary_path, arch)
        else:
            return self._verify_stdin(sp, poc, qemu_bin, binary_path, arch)

    # -- STDIN Mode ----------------------------------------------------------

    def _verify_stdin(
        self,
        sp: VerifiedSP,
        poc: PoC,
        qemu_bin: str,
        binary_path: str,
        arch: str,
    ) -> VerificationResult:
        """Deliver PoC via stdin pipe (CLI binary)."""
        cmd = self._build_stdin_command(qemu_bin, binary_path, poc)
        logger.debug(f"QEMU stdin command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                input=poc.poc_content,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            crash_info = self._parse_crash_output(
                result.stdout, result.stderr, result.returncode
            )

            if crash_info:
                logger.info(
                    f"QEMURunner: CRASH CONFIRMED for {sp.sp_id} -- "
                    f"{crash_info.crash_type} signal={crash_info.signal_number}"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash_info,
                    output=(
                        f"QEMU L2 (stdin): {crash_info.crash_type} "
                        f"(signal {crash_info.signal_number})\n"
                        f"stderr: {result.stderr[:500]}"
                    ),
                )
            else:
                logger.info(
                    f"QEMURunner: no crash for {sp.sp_id} (exit {result.returncode})"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output=f"QEMU stdin: exited normally with code {result.returncode}",
                )

        except subprocess.TimeoutExpired:
            logger.info(f"QEMURunner: {sp.sp_id} timed out ({self.timeout}s)")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output=f"QEMU stdin: timed out after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"QEMURunner: execution failed for {sp.sp_id}: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"QEMU execution failed: {e}",
            )

    # -- ARGV Mode -----------------------------------------------------------

    def _verify_argv(
        self,
        sp: VerifiedSP,
        poc: PoC,
        qemu_bin: str,
        binary_path: str,
        arch: str,
    ) -> VerificationResult:
        """Deliver PoC via command-line argument (argv[1])."""
        cmd = self._build_argv_command(qemu_bin, binary_path, poc)
        logger.debug(f"QEMU argv command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            crash_info = self._parse_crash_output(
                result.stdout, result.stderr, result.returncode
            )

            if crash_info:
                logger.info(
                    f"QEMURunner: CRASH CONFIRMED for {sp.sp_id} -- "
                    f"{crash_info.crash_type} signal={crash_info.signal_number}"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash_info,
                    output=(
                        f"QEMU L2 (argv): {crash_info.crash_type} "
                        f"(signal {crash_info.signal_number})\n"
                        f"stderr: {result.stderr[:500]}"
                    ),
                )
            else:
                logger.info(
                    f"QEMURunner: no crash for {sp.sp_id} (exit {result.returncode})"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output=f"QEMU argv: exited normally with code {result.returncode}",
                )

        except subprocess.TimeoutExpired:
            logger.info(f"QEMURunner: {sp.sp_id} timed out ({self.timeout}s)")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output=f"QEMU argv: timed out after {self.timeout}s",
            )
        except Exception as e:
            logger.error(f"QEMURunner: execution failed for {sp.sp_id}: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"QEMU execution failed: {e}",
            )

    # -- NETWORK Mode --------------------------------------------------------

    def _verify_network(
        self,
        sp: VerifiedSP,
        poc: PoC,
        qemu_bin: str,
        binary_path: str,
        arch: str,
    ) -> VerificationResult:
        """Deliver PoC to a network daemon.

        Strategy:
        1. Start daemon under QEMU in background with -strace
        2. Wait for daemon to be ready (probe common ports)
        3. Deliver PoC payload via curl/nc
        4. Check if daemon crashed (process exit / crash in stderr)
        5. Clean up
        """
        logger.info(f"QEMURunner: network mode for {sp.sp_id}")

        # Step 1: Start daemon in background
        # Pass PoC target port as argument for binaries that need it
        port_arg = str(poc.poc_target.port) if poc.poc_target.port else None
        cmd = self._build_daemon_command(qemu_bin, binary_path, port_arg)
        logger.debug(f"QEMU daemon command: {' '.join(cmd)}")

        try:
            self._background_process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            logger.error(f"Failed to start daemon: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"Failed to start daemon under QEMU: {e}",
            )

        # Step 2: Wait for daemon to be ready (process alive, no crash)
        ready = self._wait_for_daemon(timeout=self.daemon_startup_timeout)

        # Check for early crash
        if self._background_process.poll() is not None:
            exit_code = self._background_process.returncode
            stdout, stderr = self._background_process.communicate(timeout=5)
            crash_info = self._parse_crash_output(
                (stdout or b"").decode("utf-8", errors="replace"),
                (stderr or b"").decode("utf-8", errors="replace"),
                exit_code
            )
            if crash_info:
                logger.info(
                    f"QEMURunner: daemon CRASHED on startup for {sp.sp_id} -- "
                    f"{crash_info.crash_type}"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash_info,
                    output=f"QEMU L2 (network/startup crash): {crash_info.crash_type}",
                )
            else:
                logger.info(
                    f"QEMURunner: daemon exited early ({exit_code}) for {sp.sp_id}"
                )
                error_msg = stderr[:500] if stderr else f"Exit code {exit_code}"
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output=f"Daemon exited with code {exit_code}: {error_msg}",
                    error=error_msg,
                )

        # Step 3: Deliver PoC payload
        crash_info = None
        try:
            if poc.poc_type in ("http_request", "http_response"):
                crash_info = self._deliver_http(poc)
            elif poc.poc_type == "tcp_stream":
                crash_info = self._deliver_tcp(poc)
            elif poc.poc_type == "udp_packet":
                crash_info = self._deliver_udp(poc)
        except Exception as e:
            logger.warning(f"Payload delivery error: {e}")

        # Step 4: Check daemon status after payload
        time.sleep(1)
        if self._background_process.poll() is not None:
            exit_code = self._background_process.returncode
            stdout, stderr = self._background_process.communicate(timeout=5)
            output_str = (stdout or b"").decode("utf-8", errors="replace")
            err_str = (stderr or b"").decode("utf-8", errors="replace")
            combined = output_str + err_str

            if crash_info is None:
                crash_info = self._parse_crash_output(
                    output_str, err_str, exit_code
                )
            if crash_info is None and exit_code > 0:
                crash_info = self._parse_crash_from_stderr(err_str)

            if crash_info:
                logger.info(
                    f"QEMURunner: daemon CRASHED after payload for {sp.sp_id} -- "
                    f"{crash_info.crash_type} @ {crash_info.crash_address}"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="dynamic_user",
                    crashed=True,
                    crash_info=crash_info,
                    output=f"QEMU L2 (network): {crash_info.crash_type} @ {crash_info.crash_address}\n{err_str[:500]}",
                )

            logger.info(
                f"QEMURunner: daemon exited with {exit_code} after payload, "
                f"no crash pattern detected"
            )
        else:
            # Daemon still running — no crash
            logger.info(f"QEMURunner: daemon still running for {sp.sp_id}, no crash")
            self._cleanup_daemon()

        if crash_info:
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="dynamic_user",
                crashed=True,
                crash_info=crash_info,
                output=f"QEMU L2 (network): crash confirmed",
            )
        else:
            ready_str = "daemon ready" if ready else f"daemon not ready (probed ports {self.daemon_probe_ports})"
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output=f"QEMU network: {ready_str}, no crash with PoC",
            )

    # -- Daemon Lifecycle ----------------------------------------------------

    def _build_daemon_command(
        self, qemu_bin: str, binary_path: str, port_arg: Optional[str] = None
    ) -> List[str]:
        """Build QEMU command for daemon mode (with -strace).

        If port_arg is provided, it's passed as argv[1] — needed by
        binaries like socket_bof that take a port number argument.
        """
        cmd = [qemu_bin]
        if self.rootfs_dir and Path(self.rootfs_dir).exists():
            cmd.extend(["-L", self.rootfs_dir])
        cmd.append("-strace")
        cmd.append(binary_path)
        if port_arg:
            cmd.append(port_arg)
        return cmd

    def _wait_for_daemon(self, timeout: int = 10, ports: Optional[List[int]] = None) -> bool:
        """Wait for daemon to be ready (process alive + short settle time).

        IMPORTANT: Does NOT probe by connecting — that would consume the
        daemon's first accept() for single-accept servers like socket_bof.
        Instead, just waits for the process to survive past startup.
        """
        settle_time = min(timeout, 2)  # 2-second settle is enough for most daemons
        start = time.time()
        while time.time() - start < settle_time:
            if self._background_process and self._background_process.poll() is not None:
                return False
            time.sleep(0.2)

        # Process survived startup → assume ready
        if self._background_process and self._background_process.poll() is None:
            logger.info("Daemon ready (process alive after startup)")
            return True
        return False

    def _deliver_http(self, poc: PoC) -> Optional[CrashInfo]:
        """Deliver HTTP payload via curl. Returns crash info if detected."""
        target = poc.poc_target
        url = f"http://{target.host}:{target.port}{target.path}"
        cmd = ["curl", "-s", "--max-time", str(min(self.timeout, 30))]
        if target.method == "POST":
            cmd.extend(["-X", "POST", "-d", poc.poc_content])
        else:
            cmd.extend(["-G", "--data-urlencode", f"data={poc.poc_content}"])
        cmd.append(url)
        logger.debug(f"HTTP delivery: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                          timeout=min(self.timeout, 30))
        except subprocess.TimeoutExpired:
            logger.debug("HTTP request timed out (daemon may have crashed)")
        except Exception as e:
            logger.debug(f"HTTP delivery error: {e}")
        return None

    def _deliver_tcp(self, poc: PoC) -> Optional[CrashInfo]:
        """Deliver TCP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-w", str(min(self.timeout, 10)), target.host, str(target.port)]
        try:
            subprocess.run(cmd, input=poc.poc_content, capture_output=True,
                          text=True, timeout=min(self.timeout + 5, 30))
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"TCP delivery error: {e}")
        return None

    def _deliver_udp(self, poc: PoC) -> Optional[CrashInfo]:
        """Deliver UDP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-u", "-w", str(min(self.timeout, 10)), target.host, str(target.port)]
        try:
            subprocess.run(cmd, input=poc.poc_content, capture_output=True,
                          text=True, timeout=min(self.timeout + 5, 30))
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"UDP delivery error: {e}")
        return None

    def _cleanup_daemon(self) -> None:
        """Terminate the background daemon process."""
        if self._background_process and self._background_process.poll() is None:
            try:
                self._background_process.terminate()
                self._background_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    self._background_process.kill()
                    self._background_process.wait(timeout=3)
                except Exception:
                    pass
            except Exception:
                pass
        self._background_process = None

    # -- Command Building ----------------------------------------------------

    def _build_stdin_command(
        self, qemu_bin: str, binary_path: str, poc: PoC
    ) -> List[str]:
        """Build QEMU command for stdin delivery."""
        cmd = [qemu_bin]
        if self.rootfs_dir and Path(self.rootfs_dir).exists():
            cmd.extend(["-L", self.rootfs_dir])
        cmd.append("-strace")
        cmd.append(binary_path)
        return cmd

    def _build_argv_command(
        self, qemu_bin: str, binary_path: str, poc: PoC
    ) -> List[str]:
        """Build QEMU command for argv[1] delivery."""
        cmd = [qemu_bin]
        if self.rootfs_dir and Path(self.rootfs_dir).exists():
            cmd.extend(["-L", self.rootfs_dir])
        cmd.append("-strace")
        cmd.append(binary_path)
        # Pass PoC content as argv[1]
        cmd.append(poc.poc_content)
        return cmd

    def _detect_qemu_binary(self, arch: str) -> Optional[str]:
        """Map architecture to QEMU binary and check if it exists."""
        qemu_name = self.ARCH_TO_QEMU.get(arch)
        if not qemu_name:
            # Try case-insensitive match
            arch_lower = arch.lower()
            for key, val in self.ARCH_TO_QEMU.items():
                if key.lower() == arch_lower:
                    qemu_name = val
                    break
            if not qemu_name:
                return None

        qemu_path = self.qemu_dir / qemu_name
        if qemu_path.exists():
            return str(qemu_path)

        # Try without directory (in PATH)
        try:
            subprocess.run(["which", qemu_name], capture_output=True, check=True)
            return qemu_name
        except subprocess.CalledProcessError:
            return None

    # -- Crash Parsing -------------------------------------------------------

    def _parse_crash_output(
        self, stdout: str, stderr: str, returncode: int
    ) -> Optional[CrashInfo]:
        """Parse QEMU output for crash information.

        QEMU user-mode crash patterns:
        1. exit code = signal number (older QEMU)
        2. exit code = 128 + signal number (shell convention)
        3. exit code = 0 + stderr "uncaught target signal N" (newer QEMU)
        """
        combined_output = stdout + stderr

        # Normalize exit code → signal
        signal_num = 0
        if 0 < returncode < 32:
            signal_num = returncode
        elif 128 < returncode < 160:
            signal_num = returncode - 128

        crash_type, _ = self.SIGNAL_MAP.get(signal_num, (None, 0))

        # Also detect "qemu: uncaught target signal" in stderr (exit code 0!)
        if not crash_type:
            match = re.search(
                r'uncaught target signal\s+(\d+)\s*\((\w+)',
                combined_output, re.IGNORECASE
            )
            if match:
                signal_num = int(match.group(1))
                sig_name = match.group(2).upper()
                if sig_name in {"SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGFPE"}:
                    crash_type = sig_name
                else:
                    crash_type, _ = self.SIGNAL_MAP.get(signal_num, (sig_name, signal_num))

        # Check stderr/stdout for crash indicators (textual)
        if not crash_type:
            for sig_name in ["SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGFPE"]:
                if sig_name in combined_output:
                    sig_map = {
                        "SIGSEGV": 11, "SIGABRT": 6, "SIGILL": 4,
                        "SIGBUS": 7, "SIGFPE": 8,
                    }
                    crash_type = sig_name
                    signal_num = sig_map.get(sig_name, 0)
                    break

        # Human-readable crash strings
        if not crash_type:
            if "Segmentation fault" in combined_output:
                crash_type = "SIGSEGV"
                signal_num = 11
            elif "Illegal instruction" in combined_output:
                crash_type = "SIGILL"
                signal_num = 4
            elif "Aborted" in combined_output or "abort" in combined_output.lower():
                crash_type = "SIGABRT"
                signal_num = 6
            elif "Bus error" in combined_output:
                crash_type = "SIGBUS"
                signal_num = 7

        if not crash_type:
            return None

        # Extract crash address
        crash_address = self._extract_crash_address(combined_output)

        # Extract backtrace and register state
        backtrace = self._extract_backtrace(combined_output)
        register_state = self._extract_registers(combined_output)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
            signal_number=signal_num,
            backtrace=backtrace,
            register_state=register_state,
        )

    def _parse_crash_from_stderr(self, stderr: str) -> Optional[CrashInfo]:
        """Parse crash info from stderr alone (for daemon mode)."""
        for sig_name in ["SIGSEGV", "SIGABRT", "SIGILL", "SIGBUS", "SIGFPE"]:
            if sig_name in stderr:
                sig_map = {"SIGSEGV": 11, "SIGABRT": 6, "SIGILL": 4, "SIGBUS": 7, "SIGFPE": 8}
                addr = self._extract_crash_address(stderr)
                bt = self._extract_backtrace(stderr)
                regs = self._extract_registers(stderr)
                return CrashInfo(
                    crash_type=sig_name,
                    crash_address=addr,
                    signal_number=sig_map[sig_name],
                    backtrace=bt,
                    register_state=regs,
                )
        return None

    def _extract_crash_address(self, output: str) -> str:
        """Extract crash/fault address from QEMU output."""
        patterns = [
            r'[Pp][Cc]\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'fault addr(?:ess)?\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'at address\s*(0x[0-9a-fA-F]+)',
            r'qemu: uncaught target signal.*address\s*(0x[0-9a-fA-F]+)',
            r'signal \d+.*at\s+(0x[0-9a-fA-F]+)',
        ]
        for pat in patterns:
            match = re.search(pat, output, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _extract_backtrace(self, output: str) -> List[str]:
        """Extract backtrace lines from QEMU output."""
        lines = []
        for line in output.split("\n"):
            line = line.strip()
            if "0x" in line and (" in " in line or "::" in line or "#" in line):
                lines.append(line)
        return lines[:20]

    def _extract_registers(self, output: str) -> Dict[str, str]:
        """Extract register state from QEMU strace output."""
        regs = {}
        reg_patterns = [
            r'(?:^|\n)\s*(R[0-9]+|PC|SP|LR|FP|r[0-9]+|pc|sp|lr)\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'(PC|SP|LR)\s*=\s*(0x[0-9a-fA-F]+)',
        ]
        for pat in reg_patterns:
            for match in re.finditer(pat, output, re.IGNORECASE):
                regs[match.group(1).upper()] = match.group(2)
        return regs
