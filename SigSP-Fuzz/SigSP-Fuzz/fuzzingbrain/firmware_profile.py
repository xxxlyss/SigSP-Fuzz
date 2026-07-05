"""
Firmware Profile YAML Mechanism.

Lets users specify firmware metadata — architecture, endianness, known entry
points, known CVEs (for ground truth validation) — in a YAML file that is
loaded at pipeline start and used to steer analysis + cross-reference results.

Usage:
    # From YAML file
    profile = FirmwareProfile.from_yaml("profiles/DVRF.yaml")

    # Inline with CLI
    ./FuzzingBrain.sh --firmware firmware.bin --profile profiles/DVRF.yaml

    # Cross-reference discovered vulnerabilities with known CVEs
    matches = profile.cross_reference_cves(verified_sps)
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

try:
    import yaml
except ImportError:
    yaml = None  # defer error to from_yaml()


# =============================================================================
# Architecture
# =============================================================================

VALID_CPUS = {"mips", "mipsel", "arm", "armeb", "x86", "x86_64", "riscv", "riscv64", "ppc", "m68k"}
VALID_ENDIANS = {"little", "big"}
VALID_BITS = {16, 32, 64}
VALID_DEVICE_TYPES = {"router", "iot", "camera", "nas", "gateway", "switch", "firewall", "other"}
VALID_FILESYSTEMS = {"squashfs", "jffs2", "cramfs", "ext2", "ext3", "ext4", "ubifs", "yaffs2", "cpio", "initramfs", "other"}


@dataclass
class FirmwareArchitecture:
    """CPU architecture and endianness.

    Used to: select the right cross-binutils prefix (e.g. mipsel-linux-gnu-),
    pick the correct QEMU binary (qemu-mipsel-static), and interpret memory
    layouts during disassembly.
    """

    cpu: str                      # mips, arm, x86, riscv, ...
    endian: str = "little"        # little or big
    bits: int = 32                # 32 or 64
    thumb_mode: bool = False      # ARM Thumb interworking

    def __post_init__(self):
        if self.cpu not in VALID_CPUS:
            raise ValueError(
                f"Invalid cpu: '{self.cpu}'. Must be one of: {sorted(VALID_CPUS)}"
            )
        if self.endian not in VALID_ENDIANS:
            raise ValueError(
                f"Invalid endian: '{self.endian}'. Must be one of: {sorted(VALID_ENDIANS)}"
            )
        if self.bits not in VALID_BITS:
            raise ValueError(
                f"Invalid bits: {self.bits}. Must be one of: {sorted(VALID_BITS)}"
            )

    @property
    def qemu_arch(self) -> str:
        """Arch string for QEMU user-mode (e.g., 'mipsel', 'arm', 'x86_64')."""
        if self.cpu == "x86_64":
            return "x86_64"
        if self.cpu == "x86":
            return "i386"
        # ARM 32-bit little-endian is just 'arm' (qemu-arm), not 'armel'
        if self.cpu == "arm" and self.endian == "little" and self.bits == 32:
            return "arm"
        if self.cpu == "arm" and self.endian == "big" and self.bits == 32:
            return "armeb"
        if self.cpu == "arm" and self.bits == 64:
            return "aarch64"
        base = self.cpu
        if self.endian == "little" and not base.endswith("el"):
            base += "el"
        return base

    @property
    def objdump_prefix(self) -> str:
        """Cross-tool prefix (e.g., 'mipsel-linux-gnu-', 'arm-linux-gnueabi-')."""
        _MAP = {
            ("mips", 32, "little"): "mipsel-linux-gnu-",
            ("mips", 32, "big"):    "mips-linux-gnu-",
            ("mips", 64, "little"): "mips64el-linux-gnuabi64-",
            ("mips", 64, "big"):    "mips64-linux-gnuabi64-",
            ("arm", 32, "little"):  "arm-linux-gnueabi-",
            ("arm", 32, "big"):     "armeb-linux-gnueabi-",
            ("arm", 64, "little"):  "aarch64-linux-gnu-",
            ("x86", 32, "little"):  "",
            ("x86_64", 64, "little"): "",
            ("riscv", 32, "little"): "riscv32-linux-gnu-",
            ("riscv", 64, "little"): "riscv64-linux-gnu-",
            ("ppc", 32, "big"):     "powerpc-linux-gnu-",
            ("m68k", 32, "big"):    "m68k-linux-gnu-",
        }
        return _MAP.get((self.cpu, self.bits, self.endian), "")

    def to_dict(self) -> dict:
        return {
            "cpu": self.cpu,
            "endian": self.endian,
            "bits": self.bits,
            "thumb_mode": self.thumb_mode,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FirmwareArchitecture":
        cpu = d.get("cpu", "mips")
        # Allow "unknown" in from_dict as a passthrough for incomplete profiles
        if cpu == "unknown" or not cpu:
            cpu = "mips"
        return cls(
            cpu=cpu,
            endian=d.get("endian", "little"),
            bits=int(d.get("bits", 32)),
            thumb_mode=bool(d.get("thumb_mode", False)),
        )


# =============================================================================
# Known Entry Points
# =============================================================================

@dataclass
class KnownEntryPoint:
    """A known entry point into the firmware (network service, CGI, daemon).

    Used by Phase 2 to validate and enrich attack surface identification.
    """

    name: str                     # Human-readable name (e.g. "HTTP Management")
    binary: str                   # Binary path within extracted fs (e.g. "usr/sbin/httpd")
    protocol: str = ""            # HTTP, UPNP, DNS, FTP, SSH, Telnet, custom
    port: int = 0                 # Default listening port (0 = unknown)
    description: str = ""         # Free-text description

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "binary": self.binary,
            "protocol": self.protocol,
            "port": self.port,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KnownEntryPoint":
        return cls(
            name=d.get("name", ""),
            binary=d.get("binary", ""),
            protocol=d.get("protocol", ""),
            port=int(d.get("port", 0)),
            description=d.get("description", ""),
        )

    def validate(self) -> List[str]:
        errors = []
        if not self.name.strip():
            errors.append("KnownEntryPoint.name is required")
        if not self.binary.strip():
            errors.append("KnownEntryPoint.binary is required")
        return errors


# =============================================================================
# Known CVEs (Ground Truth)
# =============================================================================

@dataclass
class KnownCVE:
    """A known CVE (vulnerability) used for ground truth validation.

    After the pipeline completes, discovered vulnerabilities are cross-referenced
    against known_cves to compute detection rate / recall.
    """

    cve_id: str                   # CVE-2020-XXXXX or custom ID
    cwe: str                      # CWE-121, CWE-78, CWE-787, ...
    function_name: str            # Vulnerable function
    binary_path: str              # Path to the binary within firmware
    description: str = ""         # Vulnerability description
    cvss_score: float = 0.0       # CVSS v3 score (0.0–10.0)
    patch_commit: Optional[str] = None  # Upstream commit hash

    def __post_init__(self):
        if self.cvss_score < 0.0 or self.cvss_score > 10.0:
            raise ValueError(
                f"Invalid cvss_score: {self.cvss_score}. Must be 0.0–10.0"
            )

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cwe": self.cwe,
            "function_name": self.function_name,
            "binary_path": self.binary_path,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "patch_commit": self.patch_commit,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KnownCVE":
        return cls(
            cve_id=d.get("cve_id", ""),
            cwe=d.get("cwe", ""),
            function_name=d.get("function_name", ""),
            binary_path=d.get("binary_path", ""),
            description=d.get("description", ""),
            cvss_score=float(d.get("cvss_score", 0.0)),
            patch_commit=d.get("patch_commit"),
        )

    def validate(self) -> List[str]:
        errors = []
        if not self.cve_id.strip():
            errors.append("KnownCVE.cve_id is required")
        if not self.cwe.strip():
            errors.append("KnownCVE.cwe is required")
        if not self.function_name.strip():
            errors.append("KnownCVE.function_name is required")
        if not self.binary_path.strip():
            errors.append("KnownCVE.binary_path is required")
        return errors


# =============================================================================
# Firmware Profile
# =============================================================================

@dataclass
class FirmwareProfile:
    """Complete firmware profile loaded from a YAML file.

    Attributes:
        name: Short firmware name (e.g. "DVRF", "Netgear R7000").
        version: Firmware version string.
        vendor: Manufacturer name (e.g. "TP-Link", "Netgear").
        device_type: Category — router, iot, camera, nas, gateway, ...
        architecture: CPU arch, endianness, bitness.
        filesystem: Root filesystem type (squashfs, jffs2, ...).
        known_entry_points: Services/daemons expected on the device.
        known_cves: Previously disclosed vulnerabilities (ground truth).
        binwalk_options: Extra flags passed to binwalk (e.g. "-e -M").
        skip_binaries: Binaries to skip during static analysis.
        focus_binaries: Only analyse these binaries (mutually exclusive with skip).
        metadata: Arbitrary extra key-value pairs.
    """

    name: str
    version: str = ""
    vendor: str = ""
    device_type: str = "other"

    # Hardware architecture
    architecture: FirmwareArchitecture = field(
        default_factory=lambda: FirmwareArchitecture(cpu="mips")
    )

    # Filesystem
    filesystem: str = ""

    # Known-good data
    known_entry_points: List[KnownEntryPoint] = field(default_factory=list)
    known_cves: List[KnownCVE] = field(default_factory=list)

    # Tuning
    binwalk_options: Optional[str] = None
    skip_binaries: List[str] = field(default_factory=list)
    focus_binaries: List[str] = field(default_factory=list)

    # Free-form metadata
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if self.device_type not in VALID_DEVICE_TYPES:
            raise ValueError(
                f"Invalid device_type: '{self.device_type}'. "
                f"Must be one of: {sorted(VALID_DEVICE_TYPES)}"
            )
        if self.filesystem and self.filesystem not in VALID_FILESYSTEMS:
            raise ValueError(
                f"Invalid filesystem: '{self.filesystem}'. "
                f"Must be one of: {sorted(VALID_FILESYSTEMS)}"
            )
        if self.skip_binaries and self.focus_binaries:
            raise ValueError(
                "skip_binaries and focus_binaries are mutually exclusive"
            )

    # ------------------------------------------------------------------
    # YAML I/O
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "FirmwareProfile":
        """Load firmware profile from a YAML file.

        Uses pyyaml internally.  Raises ImportError if pyyaml is not installed
        and RuntimeError for parse / schema errors.
        """
        if yaml is None:
            raise ImportError(
                "pyyaml is required for firmware profile support. "
                "Install with: pip install pyyaml"
            )

        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Profile YAML not found: {yaml_path}")

        with open(path, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise RuntimeError(f"Failed to parse YAML: {e}") from e

        if data is None:
            raise RuntimeError(f"Empty profile YAML: {yaml_path}")
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Profile YAML must be a mapping, got {type(data).__name__}"
            )

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, d: dict) -> "FirmwareProfile":
        """Construct profile from a dictionary (JSON-compatible)."""
        arch = FirmwareArchitecture.from_dict(d.get("architecture", {}))

        entry_points = [
            KnownEntryPoint.from_dict(ep)
            for ep in d.get("known_entry_points", [])
        ]
        known_cves = [
            KnownCVE.from_dict(cve)
            for cve in d.get("known_cves", [])
        ]

        return cls(
            name=d.get("name", ""),
            version=str(d.get("version", "")),
            vendor=d.get("vendor", ""),
            device_type=d.get("device_type", "other"),
            architecture=arch,
            filesystem=d.get("filesystem", ""),
            known_entry_points=entry_points,
            known_cves=known_cves,
            binwalk_options=d.get("binwalk_options"),
            skip_binaries=d.get("skip_binaries", []),
            focus_binaries=d.get("focus_binaries", []),
            metadata=d.get("metadata", {}),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "architecture": self.architecture.to_dict(),
            "filesystem": self.filesystem,
            "known_entry_points": [ep.to_dict() for ep in self.known_entry_points],
            "known_cves": [cve.to_dict() for cve in self.known_cves],
            "binwalk_options": self.binwalk_options,
            "skip_binaries": self.skip_binaries,
            "focus_binaries": self.focus_binaries,
            "metadata": self.metadata,
        }

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        """Validate the profile, returning a list of error messages.

        An empty list means the profile is valid.
        """
        errors = []

        if not self.name.strip():
            errors.append("profile 'name' is required")

        if self.device_type not in VALID_DEVICE_TYPES:
            errors.append(
                f"Invalid device_type: '{self.device_type}'. "
                f"Must be one of: {sorted(VALID_DEVICE_TYPES)}"
            )

        if self.filesystem and self.filesystem not in VALID_FILESYSTEMS:
            errors.append(
                f"Invalid filesystem: '{self.filesystem}'. "
                f"Must be one of: {sorted(VALID_FILESYSTEMS)}"
            )

        # Validate entry points
        for i, ep in enumerate(self.known_entry_points):
            for e in ep.validate():
                errors.append(f"known_entry_points[{i}]: {e}")

        # Validate CVEs
        for i, cve in enumerate(self.known_cves):
            for e in cve.validate():
                errors.append(f"known_cves[{i}]: {e}")

        # skip / focus mutual exclusion
        if self.skip_binaries and self.focus_binaries:
            errors.append("skip_binaries and focus_binaries are mutually exclusive")

        return errors

    # ------------------------------------------------------------------
    # Ground Truth Cross-Referencing
    # ------------------------------------------------------------------

    def cross_reference_cves(
        self, verified_sps: List["VerifiedSP"]  # noqa: F821
    ) -> dict:
        """Cross-reference discovered SPs against known_cves (ground truth).

        Returns a dict with:
            matched:    list of (cve, sp) tuples — known CVE was found
            unmatched:  list of CVEs that were NOT discovered
            extra:      list of SPs that don't match any known CVE (new finds)
        """
        from .agents.firmware.sp_models import VerifiedSP  # local to avoid circular

        matched = []
        unmatched_cves = []
        unmatched_sp_ids = {sp.sp_id: sp for sp in verified_sps}

        for cve in self.known_cves:
            found = False
            for sp in verified_sps:
                # Match by function name (primary) or binary path
                cve_func = cve.function_name.lower()
                sp_func = sp.function_name.lower()
                cve_bin = cve.binary_path.lower()
                sp_bin = getattr(sp, "binary_path", "").lower()

                if cve_func == sp_func and (
                    not cve_bin or cve_bin in sp_bin or sp_bin in cve_bin
                ):
                    matched.append({"cve": cve, "sp": sp})
                    unmatched_sp_ids.pop(sp.sp_id, None)
                    found = True
                    break

                # Fuzzy: function name contains each other
                if not found and (
                    cve_func in sp_func or sp_func in cve_func
                ):
                    matched.append({"cve": cve, "sp": sp, "fuzzy": True})
                    unmatched_sp_ids.pop(sp.sp_id, None)
                    found = True
                    break

            if not found:
                unmatched_cves.append(cve)

        extra = list(unmatched_sp_ids.values())

        return {
            "matched": matched,
            "unmatched_cves": unmatched_cves,
            "extra": extra,
            "total_known": len(self.known_cves),
            "found_count": len(matched),
            "recall": (
                len(matched) / len(self.known_cves) if self.known_cves else 1.0
            ),
        }

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def has_ground_truth(self) -> bool:
        """Whether this profile has CVE ground truth data."""
        return len(self.known_cves) > 0

    @property
    def has_entry_points(self) -> bool:
        """Whether this profile specifies known entry points."""
        return len(self.known_entry_points) > 0

    def should_skip_binary(self, binary_path: str) -> bool:
        """Check whether a binary should be skipped based on profile settings."""
        bp = binary_path.lstrip("/")
        if self.focus_binaries:
            return not any(
                f.lstrip("/") in bp for f in self.focus_binaries
            )
        if self.skip_binaries:
            return any(
                s.lstrip("/") in bp for s in self.skip_binaries
            )
        return False


# =============================================================================
# Profile Discovery
# =============================================================================

def discover_profiles(profiles_dir: Optional[str] = None) -> Dict[str, str]:
    """Find all .yaml/.yml profiles in the given directory.

    If no directory is given, looks in the 'profiles/' directory at the
    project root (relative to this file).
    """
    if profiles_dir is None:
        # Project root: 2 levels up from this file
        profiles_dir = Path(__file__).parent.parent / "profiles"

    profiles_dir = Path(profiles_dir)
    if not profiles_dir.is_dir():
        logger.debug(f"Profiles directory not found: {profiles_dir}")
        return {}

    profiles = {}
    for ext in ("*.yaml", "*.yml"):
        for p in sorted(profiles_dir.glob(ext)):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            name = data.get("name", p.stem) if isinstance(data, dict) else p.stem
            profiles[name] = str(p)

    return profiles


def load_profile(profile_ref: str) -> FirmwareProfile:
    """Load a firmware profile by path or registered name.

    - If profile_ref is an existing file path, load it directly.
    - Otherwise, search the built-in profiles/ directory for a matching name.
    """
    path = Path(profile_ref)
    if path.exists():
        return FirmwareProfile.from_yaml(str(path))

    # Try by name in built-in profiles directory
    profiles = discover_profiles()
    if profile_ref in profiles:
        return FirmwareProfile.from_yaml(profiles[profile_ref])

    # Try fuzzy match (case-insensitive)
    lower = profile_ref.lower()
    for name, filepath in profiles.items():
        if name.lower() == lower:
            return FirmwareProfile.from_yaml(filepath)

    available = list(profiles.keys())
    if available:
        raise FileNotFoundError(
            f"Profile not found: '{profile_ref}'. "
            f"Available: {', '.join(available)}"
        )
    raise FileNotFoundError(
        f"Profile not found: '{profile_ref}'. "
        f"No profiles directory found either."
    )
