"""
CrashMonitor -- Captures, classifies, and deduplicates crashes.

Pure algorithm (no LLM). Used by FirmAERunner and QEMURunner to track
and deduplicate crash results from dynamic verification.

Dedup Strategy:
1. Exact crash_signature match -> duplicate
2. Same crash_type + crash_address within ASLR tolerance -> duplicate
"""

from typing import Dict, List

from loguru import logger


class CrashMonitor:
    """Captures, classifies, and deduplicates crashes from dynamic verification."""

    def __init__(self, aslr_tolerance: int = 0x1000):
        self.aslr_tolerance = aslr_tolerance
        self._recorded: Dict[str, List] = {}  # sp_id -> [crashes]
        self._signatures: set = set()

    @property
    def crash_count(self) -> int:
        return sum(len(crashes) for crashes in self._recorded.values())

    def record_crash(self, sp_id: str, crash: "CrashInfo") -> None:
        if sp_id not in self._recorded:
            self._recorded[sp_id] = []
        self._recorded[sp_id].append(crash)
        self._signatures.add(crash.crash_signature)

    def is_duplicate(self, crash: "CrashInfo") -> bool:
        # Check exact signature match first
        if crash.crash_signature in self._signatures:
            return True

        # Check address proximity for same crash_type
        for sig in self._signatures:
            if not sig.startswith(crash.crash_type + "-"):
                continue
            sig_addr_str = sig[len(crash.crash_type) + 1:]
            crash_addr_str = crash.crash_address
            try:
                sig_addr = int(sig_addr_str, 16) if sig_addr_str else None
                crash_addr = int(crash_addr_str, 16) if crash_addr_str else None
            except (ValueError, AttributeError):
                continue
            if sig_addr is not None and crash_addr is not None:
                if abs(sig_addr - crash_addr) <= self.aslr_tolerance:
                    return True
        return False

    def deduplicate(self, crashes: List["CrashInfo"]) -> List["CrashInfo"]:
        seen: set = set()
        unique: List = []
        for crash in crashes:
            if crash.crash_signature in seen:
                continue
            is_dup = False
            for sig in seen:
                if not sig.startswith(crash.crash_type + "-"):
                    continue
                sig_addr_str = sig[len(crash.crash_type) + 1:]
                crash_addr_str = crash.crash_address
                try:
                    sig_addr = int(sig_addr_str, 16) if sig_addr_str else None
                    crash_addr = int(crash_addr_str, 16) if crash_addr_str else None
                except (ValueError, AttributeError):
                    continue
                if (sig_addr is not None and crash_addr is not None
                        and abs(sig_addr - crash_addr) <= self.aslr_tolerance):
                    is_dup = True
                    break
            if not is_dup:
                seen.add(crash.crash_signature)
                unique.append(crash)
        return unique

    def get_unique_crashes(self) -> List["CrashInfo"]:
        all_crashes = []
        for crashes in self._recorded.values():
            all_crashes.extend(crashes)
        return self.deduplicate(all_crashes)

    def classify(self, crash: "CrashInfo") -> str:
        crash_type = crash.crash_type
        addr = crash.crash_address

        if crash_type == "SIGSEGV":
            if addr and "41414141" in addr:
                return "stack_buffer_overflow"
            if addr and ("00000000" in addr or addr in ("0x0", "0x00")):
                return "null_pointer_deref"
            try:
                addr_int = int(addr, 16)
                if 0x08000000 <= addr_int <= 0x7FFFFFFF:
                    return "heap_corruption"
            except (ValueError, AttributeError):
                pass
            return "likely_stack_or_heap_corruption"
        elif crash_type == "SIGABRT":
            return "assertion_failure_or_abort"
        elif crash_type == "SIGILL":
            return "corrupted_function_pointer"
        elif crash_type == "SIGBUS":
            return "bus_error_unaligned_access"
        else:
            return "unknown_crash"


from .models import CrashInfo
