"""Tests for pure-algorithm SP deduplication (sp_dedup.py)."""

import pytest

from fuzzingbrain.agents.firmware.sp_models import FirmwareSP
from fuzzingbrain.agents.firmware.sp_dedup import SPDedupper


# ── Helper ────────────────────────────────────────────────────────────────

def make_sp(function_name="test_func", cwe="CWE-121", confidence=0.8,
            control_flow="", trigger_condition="", **kwargs):
    """Create a FirmwareSP with minimal required fields for dedup tests."""
    sp_id = kwargs.pop("sp_id", None) or f"sp-{function_name}-{cwe}"
    return FirmwareSP(
        sp_id=sp_id,
        cwe=cwe,
        title="Test SP",
        description="test",
        function_name=function_name,
        confidence=confidence,
        severity="high",
        analyst_type="memory_corruption",
        control_flow=control_flow,
        trigger_condition=trigger_condition,
        vulnerable_code_snippet="int x = 0;",
        root_cause="test root cause",
        **kwargs,
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestSPDedupper:
    """Tests for SPDedupper.deduplicate()."""

    def test_empty_list_returns_empty(self):
        """An empty input list should return an empty list."""
        dedup = SPDedupper()
        assert dedup.deduplicate([]) == []

    def test_single_sp_returns_same(self):
        """A single SP should be returned unchanged."""
        sp = make_sp()
        dedup = SPDedupper()
        result = dedup.deduplicate([sp])
        assert len(result) == 1
        assert result[0] is sp  # same object reference

    def test_merge_same_function_same_cwe(self):
        """Two SPs on same function + CWE with overlapping control flow → merged to one."""
        sp1 = make_sp(
            function_name="parse_packet",
            cwe="CWE-121",
            confidence=0.9,
            control_flow="recv() -> parse() -> memcpy()",
            trigger_condition="packet length > 1024",
        )
        sp2 = make_sp(
            function_name="parse_packet",
            cwe="CWE-121",
            confidence=0.7,
            control_flow="recv() -> parse() -> memcpy()",
            trigger_condition="packet length > 2048",
        )
        dedup = SPDedupper()
        result = dedup.deduplicate([sp1, sp2])

        # Merged to one with higher confidence
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_keep_same_function_different_cwe(self):
        """Same function, different CWE → keep both."""
        sp1 = make_sp(
            function_name="parse_packet",
            cwe="CWE-121",
            confidence=0.9,
            control_flow="recv() -> parse() -> memcpy()",
            trigger_condition="packet length > 1024",
        )
        sp2 = make_sp(
            function_name="parse_packet",
            cwe="CWE-78",
            confidence=0.8,
            control_flow="recv() -> parse() -> system()",
            trigger_condition="URL parameter passed to shell",
        )
        dedup = SPDedupper()
        result = dedup.deduplicate([sp1, sp2])

        assert len(result) == 2

    def test_keep_different_functions_same_cwe(self):
        """Different functions, same CWE → keep both."""
        sp1 = make_sp(
            function_name="httpd_handle",
            cwe="CWE-121",
            control_flow="recv() -> strcpy()",
            trigger_condition="long URL",
        )
        sp2 = make_sp(
            function_name="dhcp_parse",
            cwe="CWE-121",
            control_flow="recv() -> memcpy()",
            trigger_condition="long option field",
        )
        dedup = SPDedupper()
        result = dedup.deduplicate([sp1, sp2])

        assert len(result) == 2

    def test_merge_by_trigger_similarity(self):
        """Same function with >=80% trigger condition similarity → merge."""
        sp1 = make_sp(
            function_name="httpd_handle",
            cwe="CWE-121",
            confidence=0.85,
            control_flow="recv() -> parse() -> strcpy()",
            trigger_condition="URL parameter longer than 256 bytes causes overflow",
        )
        sp2 = make_sp(
            function_name="httpd_handle",
            cwe="CWE-122",
            confidence=0.75,
            control_flow="recv() -> parse() -> malloc() -> strcpy()",
            trigger_condition="URL parameter longer than 256 bytes causes overflow",
        )
        dedup = SPDedupper()
        result = dedup.deduplicate([sp1, sp2])

        # Should be merged via trigger similarity rule (identical trigger conditions)
        assert len(result) == 1
        # Higher confidence kept
        assert result[0].confidence == 0.85

    def test_merge_by_trigger_similarity_high_threshold(self):
        """Identical trigger conditions (100% similarity) definitely trigger merge."""
        sp1 = make_sp(
            function_name="parse_config",
            cwe="CWE-121",
            confidence=0.6,
            control_flow="read() -> parse()",
            trigger_condition="long input line causes buffer overflow",
        )
        sp2 = make_sp(
            function_name="parse_config",
            cwe="CWE-122",
            confidence=0.9,
            control_flow="read() -> malloc() -> copy()",
            trigger_condition="long input line causes buffer overflow",
        )
        dedup = SPDedupper()
        result = dedup.deduplicate([sp1, sp2])

        assert len(result) == 1
        # sp2 has higher confidence (0.9)
        assert result[0].confidence == 0.9

    def test_all_unique_returns_all(self):
        """All SPs with different functions, CWEs, and trigger conditions → keep all."""
        sps = [
            make_sp(
                function_name="func_a",
                cwe="CWE-121",
                control_flow="call_a -> memcpy()",
                trigger_condition="trigger a",
            ),
            make_sp(
                function_name="func_b",
                cwe="CWE-78",
                control_flow="call_b -> system()",
                trigger_condition="trigger b",
            ),
            make_sp(
                function_name="func_c",
                cwe="CWE-190",
                control_flow="call_c -> malloc()",
                trigger_condition="trigger c",
            ),
        ]
        dedup = SPDedupper()
        result = dedup.deduplicate(sps)

        assert len(result) == 3

    def test_control_flow_overlap_computation(self):
        """Unit test for _control_flow_overlap method."""
        dedup = SPDedupper()

        # Identical strings -> 1.0
        assert dedup._control_flow_overlap("a b c", "a b c") == 1.0

        # No overlap -> 0.0
        assert dedup._control_flow_overlap("a b c", "d e f") == 0.0

        # Partial overlap
        overlap = dedup._control_flow_overlap("recv parse memcpy", "recv parse strcpy")
        assert overlap == 2.0 / 4.0  # 2 common: recv, parse; union of 4

        # Empty strings -> 0.0
        assert dedup._control_flow_overlap("", "a b c") == 0.0
        assert dedup._control_flow_overlap("a b c", "") == 0.0
        assert dedup._control_flow_overlap("", "") == 0.0

        # Case insensitivity
        assert dedup._control_flow_overlap("RECV PARSE", "recv parse") == 1.0

    def test_trigger_similarity(self):
        """Unit test for _trigger_similarity method."""
        dedup = SPDedupper()

        # Identical -> 1.0
        assert dedup._trigger_similarity("overflow in buffer", "overflow in buffer") == 1.0

        # Empty -> 0.0
        assert dedup._trigger_similarity("", "buffer overflow") == 0.0
        assert dedup._trigger_similarity("", "") == 0.0

        # Partial match
        sim = dedup._trigger_similarity(
            "URL parameter causes overflow",
            "URL parameter causes buffer overflow",
        )
        assert sim > 0.5  # significant overlap

    def test_multiple_merges_same_function(self):
        """Multiple SPs on same function+CWE with overlap → all merged into one."""
        sps = [
            make_sp(
                function_name="memcpy_safe",
                cwe="CWE-121",
                confidence=0.95,
                control_flow="recv() -> memcpy()",
                trigger_condition="large input",
            ),
            make_sp(
                function_name="memcpy_safe",
                cwe="CWE-121",
                confidence=0.80,
                control_flow="recv() -> memcpy() -> copy()",
                trigger_condition="very large input",
            ),
            make_sp(
                function_name="memcpy_safe",
                cwe="CWE-121",
                confidence=0.65,
                control_flow="recv() -> memcpy() -> checksum()",
                trigger_condition="oversized packet",
            ),
        ]
        dedup = SPDedupper()
        result = dedup.deduplicate(sps)

        assert len(result) == 1
        # Highest confidence kept
        assert result[0].confidence == 0.95

    def test_mixed_scenario(self):
        """Mix of mergeable and non-mergeable SPs produces correct results."""
        sps = [
            # Group A: same function+CWE -> should merge (control flow overlaps)
            make_sp(
                sp_id="sp-A1",
                function_name="func_x",
                cwe="CWE-121",
                confidence=0.9,
                control_flow="recv -> parse -> copy",
                trigger_condition="long input A",
            ),
            make_sp(
                sp_id="sp-A2",
                function_name="func_x",
                cwe="CWE-121",
                confidence=0.7,
                control_flow="recv -> parse -> copy",
                trigger_condition="long input B",
            ),
            # Group B: same function but different CWE -> keep both
            make_sp(
                sp_id="sp-B1",
                function_name="func_y",
                cwe="CWE-78",
                confidence=0.85,
                control_flow="recv -> exec",
                trigger_condition="shell injection",
            ),
            make_sp(
                sp_id="sp-B2",
                function_name="func_y",
                cwe="CWE-190",
                confidence=0.75,
                control_flow="recv -> malloc -> add",
                trigger_condition="integer overflow",
            ),
            # Group C: unique SP
            make_sp(
                sp_id="sp-C1",
                function_name="func_z",
                cwe="CWE-121",
                confidence=0.8,
                control_flow="read -> write",
                trigger_condition="short read",
            ),
        ]
        dedup = SPDedupper()
        result = dedup.deduplicate(sps)

        # Group A: 2 merged into 1
        # Group B: 2 kept (different CWE)
        # Group C: 1 kept
        assert len(result) == 4

        # Verify SP IDs from B and C are present (these were not merged)
        result_ids = {sp.sp_id for sp in result}
        assert "sp-B1" in result_ids
        assert "sp-B2" in result_ids
        assert "sp-C1" in result_ids
