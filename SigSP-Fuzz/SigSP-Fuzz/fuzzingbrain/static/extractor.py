"""
Firmware Extractor using binwalk.

Extracts firmware binaries: binwalk -e to unpack, then identifies
binaries (ELF), web files, configurations, and shared libraries.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from loguru import logger

from .models import BinaryInfo, ExtractResult


# Known binary file extensions and magic bytes
ELF_MAGIC = b"\x7fELF"
KNOWN_WEB_EXTENSIONS = {".cgi", ".html", ".htm", ".php", ".asp", ".js", ".css"}
KNOWN_CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".xml", ".json", ".yaml", ".yml"}
KNOWN_LIB_PATTERNS = {"lib", ".so"}


class FirmwareExtractor:
    """
    Extract firmware binaries using binwalk.

    Usage:
        extractor = FirmwareExtractor()
        result = extractor.extract("firmware.bin", "output_dir/")
        for binary in result.binaries:
            print(f"{binary.path}: {binary.arch} {binary.file_type}")
    """

    def __init__(self, binwalk_path: str = "binwalk"):
        """
        Args:
            binwalk_path: Path to binwalk executable (default: find in PATH)
        """
        self.binwalk_path = binwalk_path
        self._check_binwalk()

    def _check_binwalk(self) -> None:
        """Verify binwalk is installed and accessible."""
        if not shutil.which(self.binwalk_path):
            logger.warning(
                f"binwalk not found at '{self.binwalk_path}'. "
                "Install with: sudo apt install binwalk"
            )

    def extract(self, firmware_path: str, output_dir: str) -> ExtractResult:
        """
        Extract firmware and identify binaries.

        Args:
            firmware_path: Path to firmware binary file
            output_dir: Directory to extract into

        Returns:
            ExtractResult with list of identified BinaryInfo objects
        """
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error=f"Firmware file not found: {firmware_path}",
            )

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Extracting {fw_path.name} to {output_dir}")

        # Step 1: Run binwalk -e to extract
        try:
            result = subprocess.run(
                [self.binwalk_path, "-e", "-M", "-C", str(out_path), str(fw_path)],
                capture_output=True,
                text=True,
                timeout=600,  # 10 min timeout for large firmware
            )

            if result.returncode != 0 and "No valid signatures" not in result.stderr:
                logger.warning(f"binwalk returned non-zero: {result.returncode}")
                logger.debug(f"binwalk stderr: {result.stderr[:500]}")

        except subprocess.TimeoutExpired:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error="binwalk extraction timed out (10 min)",
            )
        except FileNotFoundError:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error="binwalk not found. Install: sudo apt install binwalk",
            )

        # Step 2: Find extracted filesystem
        extracted_dirs = self._find_extracted_dirs(out_path, fw_path.name)

        if not extracted_dirs:
            return ExtractResult(
                firmware_path=firmware_path,
                output_dir=output_dir,
                success=False,
                error="No extracted filesystem found. Firmware may be encrypted or unsupported format.",
            )

        # Step 3: Identify binaries in extracted filesystem
        binaries = []
        file_count = 0
        for ext_dir in extracted_dirs:
            for root, dirs, files in os.walk(ext_dir):
                file_count += len(files)
                for fname in files:
                    fpath = os.path.join(root, fname)
                    binary_info = self._identify_file(fpath, ext_dir)
                    if binary_info:
                        binaries.append(binary_info)

        logger.info(
            f"Extraction complete: {len(binaries)} binaries found "
            f"out of {file_count} total files"
        )

        # Step 4: Detect filesystem type
        fs_type = self._detect_filesystem_type(extracted_dirs)

        return ExtractResult(
            firmware_path=firmware_path,
            output_dir=output_dir,
            success=True,
            filesystem_type=fs_type,
            binaries=binaries,
            file_count=file_count,
        )

    def _find_extracted_dirs(self, base_dir: Path, firmware_name: str) -> List[str]:
        """
        Find extracted filesystem directories.
        binwalk typically creates: <base>/_<firmware>.extracted/squashfs-root/

        Note: firmware_name should be the full filename (with extension), not
        stem, because binwalk uses the full filename in its output directory name.
        """
        extracted_dirs = []

        # Candidate patterns for binwalk's .extracted directory.
        # binwalk uses the full filename: _firmware.bin.extracted
        # But some versions may strip the extension.
        candidates = [
            base_dir / f"_{firmware_name}.extracted",
            base_dir / f"_{Path(firmware_name).stem}.extracted",
        ]

        # Also glob for any _<name>*.extracted directory (robust fallback)
        for cand in candidates:
            if cand.exists():
                extracted_dirs = self._scan_extracted_dir(cand)
                if extracted_dirs:
                    return extracted_dirs

        # Glob fallback: look for any _*.extracted directory
        for item in base_dir.iterdir():
            if item.is_dir() and item.name.endswith(".extracted"):
                extracted_dirs = self._scan_extracted_dir(item)
                if extracted_dirs:
                    return extracted_dirs

        # Pattern 2: Direct extraction to base_dir (no .extracted wrapper)
        for item in base_dir.iterdir():
            if item.is_dir() and not item.name.endswith(".extracted"):
                if any(
                    (item / d).exists()
                    for d in ["bin", "sbin", "usr", "etc", "lib"]
                ):
                    extracted_dirs.append(str(item))

        return extracted_dirs

    @staticmethod
    def _scan_extracted_dir(extracted_path: Path) -> List[str]:
        """Scan a .extracted directory for filesystem roots.

        Looks for squashfs-root, jffs2-root, or similar inside.
        If no obvious root found, returns the .extracted dir itself.
        """
        dirs = []
        for item in extracted_path.iterdir():
            if item.is_dir() and (
                "root" in item.name.lower()
                or "fs" in item.name.lower()
                or "filesystem" in item.name.lower()
            ):
                dirs.append(str(item))
        if not dirs:
            dirs.append(str(extracted_path))
        return dirs

    def _identify_file(self, filepath: str, base_dir: str) -> Optional[BinaryInfo]:
        """Identify a single file as a binary of interest."""
        fpath = Path(filepath)

        # Skip very small files and non-files
        try:
            if not fpath.is_file() or fpath.stat().st_size < 100:
                return None
        except OSError:
            return None

        # Check for ELF magic
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
        except (IOError, PermissionError):
            return None

        if magic != ELF_MAGIC:
            return None

        # Parse ELF header for architecture info
        arch_info = self._parse_elf_header(filepath)
        if arch_info is None:
            return None

        arch, bits, endian, entry = arch_info

        # Classify file type based on path and name
        rel_path = os.path.relpath(filepath, base_dir)
        file_type = self._classify_binary(rel_path, Path(filepath).name)

        # Check if stripped
        stripped = self._is_stripped(filepath)

        return BinaryInfo(
            path=rel_path,
            arch=arch,
            bits=bits,
            endian=endian,
            file_type=file_type,
            stripped=stripped,
            entry_point=entry,
        )

    def _parse_elf_header(self, filepath: str) -> Optional[tuple]:
        """
        Parse ELF header to extract (arch, bits, endian, entry_point).
        Returns None if file is not a valid ELF or parsing fails.
        """
        try:
            import struct

            with open(filepath, "rb") as f:
                # Read e_ident (16 bytes)
                ident = f.read(16)
                if len(ident) < 16:
                    return None

                # Byte 4: EI_CLASS (1=32-bit, 2=64-bit)
                bits = 32 if ident[4] == 1 else 64 if ident[4] == 2 else 0

                # Byte 5: EI_DATA (1=little, 2=big)
                endian = "little" if ident[5] == 1 else "big" if ident[5] == 2 else "unknown"

                # Bytes 18-19: e_machine
                f.seek(18)
                machine_bytes = f.read(2)
                machine = struct.unpack("<H" if endian == "little" else ">H", machine_bytes)[0]

                # Map e_machine to architecture string
                ARCH_MAP = {
                    0x28: "arm",     # EM_ARM
                    0xB7: "aarch64", # EM_AARCH64
                    0x08: "mips",    # EM_MIPS
                    0x0A: "mips64",  # EM_MIPS_RS3_LE (approximate)
                    0xF3: "riscv",   # EM_RISCV
                    0x03: "x86",     # EM_386
                    0x3E: "x86_64",  # EM_X86_64
                    0x14: "ppc",     # EM_PPC
                    0x15: "ppc64",   # EM_PPC64
                }
                arch = ARCH_MAP.get(machine, f"unknown_{machine:#x}")

                # Read entry point (offset varies by 32/64-bit)
                if bits == 64:
                    f.seek(24)
                    entry_bytes = f.read(8)
                    entry = struct.unpack("<Q" if endian == "little" else ">Q", entry_bytes)[0]
                else:
                    f.seek(24)
                    entry_bytes = f.read(4)
                    entry = struct.unpack("<I" if endian == "little" else ">I", entry_bytes)[0]

                return (arch, bits, endian, entry)

        except Exception:
            return None

    def _classify_binary(self, rel_path: str, filename: str) -> str:
        """Classify a binary by its path and name."""
        rel_lower = rel_path.lower()
        name_lower = filename.lower()

        # CGI scripts
        if ".cgi" in name_lower or "cgi" in rel_lower:
            return "cgi"

        # Web servers
        web_server_names = {"httpd", "nginx", "lighttpd", "apache2", "boa", "goahead", "uhttpd"}
        if any(w in name_lower for w in web_server_names):
            return "web_server"

        # Located in web directories
        if any(d in rel_lower for d in ["/www/", "/cgi-bin/", "/htdocs/", "/web/"]):
            return "cgi" if ".cgi" in name_lower else "web_related"

        # Libraries
        if name_lower.startswith("lib") or ".so" in name_lower or "/lib/" in rel_lower:
            return "library"

        # System daemons in /bin/ or /sbin/ or /usr/
        if any(d in rel_lower for d in ["/bin/", "/sbin/", "/usr/sbin/", "/usr/bin/"]):
            # Further classify by name hints
            if any(d in name_lower for d in ["dns", "dnsmasq"]):
                return "dns_server"
            if any(d in name_lower for d in ["telnet", "telnetd"]):
                return "telnet_server"
            if any(d in name_lower for d in ["upnp", "ssdp"]):
                return "upnp_server"
            return "daemon"

        return "daemon"

    def _is_stripped(self, filepath: str) -> bool:
        """Check if an ELF binary is stripped of symbols."""
        try:
            result = subprocess.run(
                ["file", filepath],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "stripped" in result.stdout.lower()
        except Exception:
            return False

    def _detect_filesystem_type(self, extracted_dirs: List[str]) -> str:
        """Detect the filesystem type of the extracted firmware."""
        for ext_dir in extracted_dirs:
            try:
                result = subprocess.run(
                    ["file", ext_dir],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                stdout = result.stdout.lower()
                if "squashfs" in stdout:
                    return "squashfs"
                if "jffs2" in stdout:
                    return "jffs2"
                if "cramfs" in stdout:
                    return "cramfs"
                if "ext" in stdout and "filesystem" in stdout:
                    return "ext"
            except Exception:
                pass
        return "unknown"


def extract_firmware(firmware_path: str, output_dir: str = None) -> ExtractResult:
    """
    Convenience function to extract firmware.

    Args:
        firmware_path: Path to firmware binary
        output_dir: Output directory (default: ./extracted_<firmware_name>/)

    Returns:
        ExtractResult
    """
    if output_dir is None:
        fw_stem = Path(firmware_path).stem
        output_dir = f"extracted_{fw_stem}"

    extractor = FirmwareExtractor()
    return extractor.extract(firmware_path, output_dir)
