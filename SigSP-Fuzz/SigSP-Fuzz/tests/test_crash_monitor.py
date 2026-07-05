"""Tests for CrashMonitor."""

import pytest
from fuzzingbrain.verifier.crash_monitor import CrashMonitor
from fuzzingbrain.verifier.models import CrashInfo


class TestCrashMonitorRecord:
    def test_record_single_crash(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", crash)
        assert cm.crash_count == 1

    def test_record_multiple_crashes(self):
        cm = CrashMonitor()
        cm.record_crash("sp-1", CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11))
        cm.record_crash("sp-2", CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6))
        assert cm.crash_count == 2

    def test_get_unique_crashes(self):
        cm = CrashMonitor()
        cm.record_crash("sp-1", CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11))
        cm.record_crash("sp-2", CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6))
        unique = cm.get_unique_crashes()
        assert len(unique) == 2


class TestCrashMonitorDedup:
    def test_exact_signature_match_is_duplicate(self):
        cm = CrashMonitor()
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        assert cm.is_duplicate(c1) is False  # First one is not dup
        cm.record_crash("sp-1", c1)
        assert cm.is_duplicate(c2) is True   # Second one matches

    def test_different_crash_type_not_duplicate(self):
        cm = CrashMonitor()
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        c2 = CrashInfo(crash_type="SIGABRT", crash_address="0x41414141", signal_number=6)
        assert cm.is_duplicate(c2) is False

    def test_aslr_tolerance(self):
        cm = CrashMonitor(aslr_tolerance=0x1000)
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41415141", signal_number=11)
        assert cm.is_duplicate(c2) is True

    def test_aslr_outside_tolerance(self):
        cm = CrashMonitor(aslr_tolerance=0x1000)
        c1 = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        cm.record_crash("sp-1", c1)
        c2 = CrashInfo(crash_type="SIGSEGV", crash_address="0x42424242", signal_number=11)
        assert cm.is_duplicate(c2) is False

    def test_deduplicate_list(self):
        cm = CrashMonitor()
        crashes = [
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11),  # dup
            CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6),
            CrashInfo(crash_type="SIGSEGV", crash_address="0x41415141", signal_number=11),  # near
        ]
        unique = cm.deduplicate(crashes)
        assert len(unique) == 2  # SIGSEGV merged (within tolerance) + SIGABRT

    def test_deduplicate_empty(self):
        cm = CrashMonitor()
        assert cm.deduplicate([]) == []


class TestCrashMonitorClassification:
    def test_classify_stack_overflow(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGSEGV", crash_address="0x41414141", signal_number=11)
        category = cm.classify(crash)
        assert "stack" in category.lower() or "controlled" in category.lower()

    def test_classify_sigabrt(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGABRT", crash_address="0x0804a000", signal_number=6)
        category = cm.classify(crash)
        assert "abort" in category.lower() or "assertion" in category.lower()

    def test_classify_sigill(self):
        cm = CrashMonitor()
        crash = CrashInfo(crash_type="SIGILL", crash_address="0x0804a000", signal_number=4)
        category = cm.classify(crash)
        assert "illegal" in category.lower() or "corrupted" in category.lower()
