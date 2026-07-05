"""
FirmAERunner -- L1 full-system emulation verification.

Uses FirmAE to emulate the entire firmware system, send PoC payloads
to the target service, and monitor for crashes.

Requirements:
- FirmAE installed at firmae_dir
- Extracted firmware filesystem
- Target binary identified

FirmAE Reference: https://github.com/pr0v3rbs/FirmAE
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from loguru import logger

from ..agents.firmware.sp_models import VerifiedSP
from .models import PoC, VerificationResult, CrashInfo


class FirmAERunner:
    """L1: FirmAE full-system emulation verification.

    Attempts to boot the firmware in FirmAE, send PoC payloads,
    and capture crash results.

    Usage:
        runner = FirmAERunner(firmae_dir="/opt/FirmAE")
        result = runner.verify(sp, poc, firmware_path="/path/to/firmware.bin")
    """

    def __init__(
        self,
        firmae_dir: str,
        workspace_dir: Optional[str] = None,
        boot_timeout: int = 120,
        poc_timeout: int = 30,
    ):
        self.firmae_dir = Path(firmae_dir)
        self.workspace_dir = Path(workspace_dir or self.firmae_dir / "workspace")
        self.boot_timeout = boot_timeout
        self.poc_timeout = poc_timeout
        self._firmae_init_script = self.firmae_dir / "init.sh"
        self._firmae_run_script = self.firmae_dir / "run.sh"
        self._firmae_process = None

    def verify(
        self,
        sp: VerifiedSP,
        poc: PoC,
        firmware_path: str,
    ) -> VerificationResult:
        """Attempt L1 verification via FirmAE full-system emulation."""
        logger.info(f"FirmAERunner: attempting L1 verification for {sp.sp_id}")

        # Check FirmAE installation
        if not self._firmae_init_script.exists():
            error_msg = (
                f"FirmAE init.sh not found at {self._firmae_init_script}. "
                f"Is FirmAE installed?"
            )
            logger.error(error_msg)
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=error_msg,
            )

        # Step 1: Initialize FirmAE
        try:
            self._initialize_firmae()
        except Exception as e:
            logger.error(f"FirmAE initialization failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"FirmAE init failed: {e}",
            )

        # Step 2: Prepare workspace
        workspace = None
        try:
            workspace = self._prepare_workspace(firmware_path)
            if not workspace:
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    error="Failed to prepare FirmAE workspace",
                )
        except Exception as e:
            logger.error(f"Workspace preparation failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"Workspace preparation failed: {e}",
            )

        # Step 3: Deploy and boot firmware
        try:
            booted = self._deploy_firmware(workspace)
            if not booted:
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="not_verified",
                    crashed=False,
                    output="FirmAE boot failed or timed out",
                )
        except Exception as e:
            logger.error(f"FirmAE deploy failed: {e}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                error=f"FirmAE deploy failed: {e}",
            )

        # Step 4: Send PoC payload
        crash_info = None
        try:
            payload_sent = self._send_payload(poc)
            if payload_sent:
                crash_info = self._check_crash(workspace)
        except Exception as e:
            logger.error(f"PoC delivery failed: {e}")

        # Step 5: Cleanup
        try:
            self._cleanup()
        except Exception as e:
            logger.warning(f"FirmAE cleanup failed (non-fatal): {e}")

        # Build result
        if crash_info:
            logger.info(
                f"FirmAERunner: CRASH CONFIRMED for {sp.sp_id} -- "
                f"{crash_info.crash_type} at {crash_info.crash_address}"
            )
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="dynamic_full",
                crashed=True,
                crash_info=crash_info,
                output=f"FirmAE L1: {crash_info.crash_type} at {crash_info.crash_address}",
            )
        else:
            logger.info(f"FirmAERunner: no crash detected for {sp.sp_id}")
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="not_verified",
                crashed=False,
                output="FirmAE booted but no crash detected with PoC",
            )

    def _initialize_firmae(self) -> None:
        """Initialize FirmAE (run init.sh if needed)."""
        result = subprocess.run(
            [str(self._firmae_init_script)],
            cwd=str(self.firmae_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"FirmAE init.sh failed (exit {result.returncode}): {result.stderr}"
            )
        logger.info("FirmAE initialized successfully")

    def _prepare_workspace(self, firmware_path: str) -> Optional[str]:
        """Prepare FirmAE workspace for the firmware."""
        firmware_name = Path(firmware_path).stem
        workspace = str(self.workspace_dir / firmware_name)

        if Path(workspace).exists() and Path(workspace, "run.sh").exists():
            logger.info(f"Using existing workspace: {workspace}")
            return workspace

        extract_script = self.firmae_dir / "sources" / "extractor" / "extractor.py"
        if not extract_script.exists():
            extract_script = self.firmae_dir / "extractor.py"

        if extract_script.exists():
            result = subprocess.run(
                ["python3", str(extract_script), "-b", "brand", firmware_path, workspace],
                cwd=str(self.firmae_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.error(f"FirmAE extractor failed: {result.stderr}")
                return None

        Path(workspace).mkdir(parents=True, exist_ok=True)
        return workspace

    def _deploy_firmware(self, workspace: str) -> bool:
        """Deploy firmware in FirmAE and wait for boot."""
        run_script = Path(workspace) / "run.sh"
        if not run_script.exists():
            logger.error(f"FirmAE run script not found: {run_script}")
            return False

        try:
            self._firmae_process = subprocess.Popen(
                ["bash", str(run_script)],
                cwd=workspace,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            booted = self._wait_for_boot(workspace)
            return booted
        except Exception as e:
            logger.error(f"FirmAE deploy exception: {e}")
            return False

    def _wait_for_boot(self, workspace: str) -> bool:
        """Wait for firmware to complete boot process."""
        start_time = time.time()
        while time.time() - start_time < self.boot_timeout:
            tap_file = Path(workspace) / "tap.sh"
            if tap_file.exists():
                logger.info("FirmAE boot detected (tap interface ready)")
                time.sleep(5)
                return True

            if self._firmae_process and self._firmae_process.poll() is not None:
                logger.error(
                    f"FirmAE process exited early with code {self._firmae_process.returncode}"
                )
                return False

            time.sleep(1)

        logger.warning(f"FirmAE boot timed out after {self.boot_timeout}s")
        return False

    def _send_payload(self, poc: PoC) -> bool:
        """Send PoC payload to the target service inside FirmAE emulation."""
        try:
            if poc.poc_type in ("http_request", "http_response"):
                return self._send_http_payload(poc)
            elif poc.poc_type == "tcp_stream":
                return self._send_tcp_payload(poc)
            elif poc.poc_type == "udp_packet":
                return self._send_udp_payload(poc)
            else:
                logger.warning(f"Unsupported poc_type for FirmAE: {poc.poc_type}")
                return False
        except Exception as e:
            logger.error(f"Payload delivery failed: {e}")
            return False

    def _send_http_payload(self, poc: PoC) -> bool:
        """Send HTTP-based PoC via curl."""
        target = poc.poc_target
        url = f"http://{target.host}:{target.port}{target.path}"
        cmd = ["curl", "-s", "--max-time", str(self.poc_timeout)]
        if target.method == "POST":
            cmd.extend(["-X", "POST", "-d", poc.poc_content])
        else:
            cmd.extend(["-G", "--data-urlencode", f"data={poc.poc_content}"])
        cmd.append(url)
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.poc_timeout + 5
        )
        return result.returncode in (0, 7, 52, 56)

    def _send_tcp_payload(self, poc: PoC) -> bool:
        """Send TCP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-w", str(self.poc_timeout), target.host, str(target.port)]
        subprocess.run(
            cmd,
            input=poc.poc_content,
            capture_output=True,
            text=True,
            timeout=self.poc_timeout + 5,
        )
        return True

    def _send_udp_payload(self, poc: PoC) -> bool:
        """Send UDP payload via netcat."""
        target = poc.poc_target
        cmd = ["nc", "-u", "-w", str(self.poc_timeout), target.host, str(target.port)]
        subprocess.run(
            cmd,
            input=poc.poc_content,
            capture_output=True,
            text=True,
            timeout=self.poc_timeout + 5,
        )
        return True

    def _check_crash(self, workspace: str) -> Optional[CrashInfo]:
        """Check for crashes in the FirmAE emulated system."""
        crash_dir = Path(workspace) / "crash"
        if crash_dir.exists():
            crash_files = list(crash_dir.glob("*"))
            if crash_files:
                crash_file = max(crash_files, key=lambda p: p.stat().st_mtime)
                return self._parse_crash_file(crash_file)

        try:
            stdout, stderr = self._firmae_process.communicate(timeout=5)
            output = (stdout or b"") + (stderr or b"")
            output_str = output.decode("utf-8", errors="replace")

            if "SIGSEGV" in output_str:
                return CrashInfo(crash_type="SIGSEGV", signal_number=11)
            elif "SIGABRT" in output_str:
                return CrashInfo(crash_type="SIGABRT", signal_number=6)
            elif "SIGILL" in output_str:
                return CrashInfo(crash_type="SIGILL", signal_number=4)
            elif "SIGBUS" in output_str:
                return CrashInfo(crash_type="SIGBUS", signal_number=7)
            elif "Segmentation fault" in output_str:
                return CrashInfo(crash_type="SIGSEGV", signal_number=11)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.warning(f"Error checking crash: {e}")

        return None

    def _parse_crash_file(self, crash_file: Path) -> CrashInfo:
        """Parse a FirmAE crash file into CrashInfo."""
        content = crash_file.read_text(encoding="utf-8", errors="replace")

        crash_type = "SIGSEGV"
        crash_address = ""
        signal_number = 11
        backtrace_lines = []

        for line in content.split("\n"):
            line = line.strip()
            if "SIGSEGV" in line:
                crash_type = "SIGSEGV"
                signal_number = 11
            elif "SIGABRT" in line:
                crash_type = "SIGABRT"
                signal_number = 6
            elif "SIGILL" in line:
                crash_type = "SIGILL"
                signal_number = 4
            elif "SIGBUS" in line:
                crash_type = "SIGBUS"
                signal_number = 7

            if "fault addr" in line.lower():
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)
            elif "at" in line.lower() and "0x" in line:
                match = re.search(r"(0x[0-9a-fA-F]+)", line)
                if match:
                    crash_address = match.group(1)

            if "0x" in line and ("::" in line or " in " in line):
                backtrace_lines.append(line)

        return CrashInfo(
            crash_type=crash_type,
            crash_address=crash_address,
            signal_number=signal_number,
            backtrace=backtrace_lines,
        )

    def _cleanup(self) -> None:
        """Cleanup FirmAE emulation."""
        if hasattr(self, "_firmae_process") and self._firmae_process:
            try:
                self._firmae_process.terminate()
                self._firmae_process.wait(timeout=10)
            except Exception:
                try:
                    self._firmae_process.kill()
                except Exception:
                    pass
