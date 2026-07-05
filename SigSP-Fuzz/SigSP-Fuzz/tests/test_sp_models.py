"""Tests for Phase 3 SP data models."""

import json
import pytest
from dataclasses import asdict

from fuzzingbrain.agents.firmware.sp_models import (
    ExploitabilityAssessment,
    FirmwareSP,
    CrossReviewVerdict,
    CrossReviewResult,
    AnalystConsensus,
    VerifiedSP,
    Phase3Statistics,
    Phase3Result,
)


# ===========================================================================
# ExploitabilityAssessment
# ===========================================================================

class TestExploitabilityAssessment:
    """Tests for ExploitabilityAssessment dataclass."""

    def test_create_with_valid_fields(self):
        e = ExploitabilityAssessment(
            attack_vector="network",
            difficulty="trivial",
            reliability="reliable",
            impact="RCE",
        )
        assert e.attack_vector == "network"
        assert e.difficulty == "trivial"
        assert e.reliability == "reliable"
        assert e.impact == "RCE"

    def test_default_values(self):
        """Verify that non-provided fields are not expected — all are required."""
        e = ExploitabilityAssessment(
            attack_vector="local",
            difficulty="moderate",
            reliability="medium",
            impact="DoS",
        )
        assert e.attack_vector == "local"
        assert e.difficulty == "moderate"
        assert e.reliability == "medium"
        assert e.impact == "DoS"

    def test_invalid_attack_vector_raises_error(self):
        with pytest.raises(ValueError, match="attack_vector"):
            ExploitabilityAssessment(
                attack_vector="invalid",
                difficulty="trivial",
                reliability="reliable",
                impact="RCE",
            )

    def test_invalid_difficulty_raises_error(self):
        with pytest.raises(ValueError, match="difficulty"):
            ExploitabilityAssessment(
                attack_vector="network",
                difficulty="impossible",
                reliability="reliable",
                impact="RCE",
            )


# ===========================================================================
# FirmwareSP
# ===========================================================================

class TestFirmwareSP:
    """Tests for FirmwareSP dataclass."""

    def test_create_with_all_fields(self):
        sp = FirmwareSP(
            sp_id="SP-001",
            cwe="CWE-121",
            title="Stack buffer overflow in parse_request",
            description="A stack buffer overflow occurs when parsing long URI",
            function_name="parse_request",
            vulnerable_code_snippet='strcpy(buffer, request->uri);',
            control_flow="parse_request -> strcpy (no bounds check)",
            trigger_condition="URI longer than 256 bytes",
            root_cause="Missing bounds check before strcpy",
            confidence=0.85,
            severity="critical",
            analyst_type="memory_corruption",
            binary_offset="0x1234",
            input_vector="HTTP URI path",
            supporting_evidence=["Similar pattern found in parse_header"],
            potential_false_positive_triggers=["Stack canary may be present"],
        )
        assert sp.sp_id == "SP-001"
        assert sp.cwe == "CWE-121"
        assert sp.severity == "critical"
        assert sp.confidence == 0.85
        assert sp.analyst_type == "memory_corruption"
        assert sp.supporting_evidence == ["Similar pattern found in parse_header"]
        assert sp.exploitability is None

    def test_to_dict_from_dict_roundtrip(self):
        sp = FirmwareSP(
            sp_id="SP-002",
            cwe="CWE-89",
            title="Command injection in cgi_handler",
            description="User-controlled input passed to system()",
            function_name="cgi_handler",
            vulnerable_code_snippet='system(cmd);',
            control_flow="cgi_handler -> build_cmd -> system",
            trigger_condition="Input contains shell metacharacters",
            root_cause="No input sanitization before system()",
            confidence=0.92,
            severity="high",
            analyst_type="injection",
            binary_offset="0x5678",
            input_vector="CGI query string",
            supporting_evidence=["strstr checks bypassable"],
            potential_false_positive_triggers=["May require auth"],
        )
        d = sp.to_dict()
        assert d["sp_id"] == "SP-002"
        assert d["severity"] == "high"
        assert d["analyst_type"] == "injection"
        assert d["supporting_evidence"] == ["strstr checks bypassable"]

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        sp2 = FirmwareSP.from_dict(loaded)
        assert sp.sp_id == sp2.sp_id
        assert sp.cwe == sp2.cwe
        assert sp.title == sp2.title
        assert sp.confidence == sp2.confidence
        assert sp.severity == sp2.severity

    def test_invalid_severity_raises_error(self):
        with pytest.raises(ValueError, match="severity"):
            FirmwareSP(
                sp_id="SP-003",
                cwe="CWE-121",
                title="Test",
                description="Test",
                function_name="test",
                vulnerable_code_snippet="test",
                control_flow="test",
                trigger_condition="test",
                root_cause="test",
                confidence=0.5,
                severity="invalid",
                analyst_type="memory_corruption",
                binary_offset="0x0000",
                input_vector="test",
            )

    def test_invalid_confidence_raises_error(self):
        with pytest.raises(ValueError, match="confidence"):
            FirmwareSP(
                sp_id="SP-004",
                cwe="CWE-121",
                title="Test",
                description="Test",
                function_name="test",
                vulnerable_code_snippet="test",
                control_flow="test",
                trigger_condition="test",
                root_cause="test",
                confidence=1.5,
                severity="medium",
                analyst_type="logic_flaw",
                binary_offset="0x0000",
                input_vector="test",
            )

    def test_default_values(self):
        """Verify that list fields default to empty and exploitability to None."""
        sp = FirmwareSP(
            sp_id="SP-005",
            cwe="CWE-190",
            title="Integer overflow",
            description="Integer overflow in size calculation",
            function_name="calc_size",
            vulnerable_code_snippet="size = a * b;",
            control_flow="calc_size -> malloc",
            trigger_condition="a*b > INT_MAX",
            root_cause="No overflow check",
            confidence=0.6,
            severity="medium",
            analyst_type="memory_corruption",
            binary_offset="0x9abc",
            input_vector="HTTP body length",
        )
        assert sp.supporting_evidence == []
        assert sp.potential_false_positive_triggers == []
        assert sp.exploitability is None

    def test_invalid_analyst_type_raises_error(self):
        with pytest.raises(ValueError, match="analyst_type"):
            FirmwareSP(
                sp_id="SP-006",
                cwe="CWE-121",
                title="Test",
                description="Test",
                function_name="test",
                vulnerable_code_snippet="test",
                control_flow="test",
                trigger_condition="test",
                root_cause="test",
                confidence=0.5,
                severity="low",
                analyst_type="invalid_type",
                binary_offset="0x0000",
                input_vector="test",
            )

    def test_confidence_below_zero_raises_error(self):
        with pytest.raises(ValueError, match="confidence"):
            FirmwareSP(
                sp_id="SP-007",
                cwe="CWE-121",
                title="Test",
                description="Test",
                function_name="test",
                vulnerable_code_snippet="test",
                control_flow="test",
                trigger_condition="test",
                root_cause="test",
                confidence=-0.1,
                severity="low",
                analyst_type="memory_corruption",
                binary_offset="0x0000",
                input_vector="test",
            )


# ===========================================================================
# CrossReviewVerdict
# ===========================================================================

class TestCrossReviewVerdict:
    """Tests for CrossReviewVerdict dataclass."""

    def test_create_with_confirmed_verdict(self):
        v = CrossReviewVerdict(
            sp_id="SP-001",
            reviewer_type="analyst_a",
            verdict="confirmed",
        )
        assert v.sp_id == "SP-001"
        assert v.reviewer_type == "analyst_a"
        assert v.verdict == "confirmed"
        assert v.confidence_adjustment == ""
        assert v.refutation_reason == ""
        assert v.missed_context == ""
        assert v.merged_with is None

    def test_invalid_verdict_raises_error(self):
        with pytest.raises(ValueError, match="verdict"):
            CrossReviewVerdict(
                sp_id="SP-001",
                reviewer_type="analyst_b",
                verdict="invalid_verdict",
            )

    def test_to_dict_from_dict_roundtrip(self):
        v = CrossReviewVerdict(
            sp_id="SP-002",
            reviewer_type="analyst_c",
            verdict="refuted",
            confidence_adjustment="-0.3",
            refutation_reason="Stack canary present",
            missed_context="Binary compiled with -fstack-protector",
            merged_with="SP-003",
        )
        d = v.to_dict()
        assert d["verdict"] == "refuted"
        assert d["confidence_adjustment"] == "-0.3"

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        v2 = CrossReviewVerdict.from_dict(loaded)
        assert v.sp_id == v2.sp_id
        assert v.verdict == v2.verdict
        assert v.merged_with == v2.merged_with


# ===========================================================================
# CrossReviewResult
# ===========================================================================

class TestCrossReviewResult:
    """Tests for CrossReviewResult container."""

    def test_create_with_reviews(self):
        reviews = [
            CrossReviewVerdict(sp_id="SP-001", reviewer_type="analyst_a", verdict="confirmed"),
            CrossReviewVerdict(sp_id="SP-001", reviewer_type="analyst_b", verdict="refuted"),
        ]
        result = CrossReviewResult(reviews=reviews)
        assert len(result.reviews) == 2
        assert result.count == 2

    def test_empty_reviews(self):
        result = CrossReviewResult(reviews=[])
        assert result.count == 0

    def test_to_dict_from_dict_roundtrip(self):
        reviews = [
            CrossReviewVerdict(sp_id="SP-001", reviewer_type="analyst_a", verdict="confirmed",
                               confidence_adjustment="+0.1"),
        ]
        result = CrossReviewResult(reviews=reviews)
        d = result.to_dict()
        assert len(d["reviews"]) == 1
        assert d["reviews"][0]["verdict"] == "confirmed"

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        result2 = CrossReviewResult.from_dict(loaded)
        assert result2.count == 1
        assert result2.reviews[0].verdict == "confirmed"
        assert result2.reviews[0].confidence_adjustment == "+0.1"


# ===========================================================================
# AnalystConsensus
# ===========================================================================

class TestAnalystConsensus:
    """Tests for AnalystConsensus dataclass."""

    def test_create_with_all_fields(self):
        c = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="confirmed",
            analyst_c="refuted",
            votes_confirmed=2,
            votes_refuted=1,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        assert c.analyst_a == "confirmed"
        assert c.analyst_b == "confirmed"
        assert c.analyst_c == "refuted"
        assert c.votes_confirmed == 2
        assert c.final_vote == "confirmed"

    def test_invalid_analyst_vote_raises_error(self):
        with pytest.raises(ValueError, match="analyst_a"):
            AnalystConsensus(
                analyst_a="invalid",
                analyst_b="confirmed",
                analyst_c="refuted",
                votes_confirmed=1,
                votes_refuted=1,
                votes_uncertain=0,
                final_vote="confirmed",
            )

    def test_invalid_final_vote_raises_error(self):
        with pytest.raises(ValueError, match="final_vote"):
            AnalystConsensus(
                analyst_a="confirmed",
                analyst_b="confirmed",
                analyst_c="refuted",
                votes_confirmed=2,
                votes_refuted=1,
                votes_uncertain=0,
                final_vote="invalid",
            )

    def test_to_dict_from_dict_roundtrip(self):
        c = AnalystConsensus(
            analyst_a="uncertain",
            analyst_b="confirmed",
            analyst_c="—",
            votes_confirmed=1,
            votes_refuted=0,
            votes_uncertain=1,
            final_vote="uncertain",
        )
        d = c.to_dict()
        assert d["analyst_a"] == "uncertain"
        assert d["analyst_c"] == "—"  # em dash

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        c2 = AnalystConsensus.from_dict(loaded)
        assert c.analyst_a == c2.analyst_a
        assert c.analyst_c == c2.analyst_c
        assert c.final_vote == c2.final_vote


# ===========================================================================
# VerifiedSP
# ===========================================================================

class TestVerifiedSP:
    """Tests for VerifiedSP dataclass."""

    def test_create_with_consensus(self):
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="confirmed",
            analyst_c="confirmed",
            votes_confirmed=3,
            votes_refuted=0,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        vsp = VerifiedSP(
            sp_id="SP-001",
            cwe="CWE-121",
            title="Stack buffer overflow in parse_request",
            description="Stack buffer overflow",
            function_name="parse_request",
            vulnerable_code_snippet='strcpy(buffer, request->uri);',
            control_flow="parse_request -> strcpy",
            trigger_condition="URI > 256 bytes",
            root_cause="Missing bounds check",
            confidence=0.85,
            severity="critical",
            analyst_type="memory_corruption",
            binary_offset="0x1234",
            input_vector="HTTP URI path",
            analyst_consensus=consensus,
            cross_review_summary="All three analysts confirmed",
            verification_priority="immediate",
            priority="P0",
        )
        assert vsp.sp_id == "SP-001"
        assert vsp.priority == "P0"
        assert vsp.verification_priority == "immediate"
        assert vsp.analyst_consensus.votes_confirmed == 3
        assert vsp.merged_from == []

    def test_invalid_priority_raises_error(self):
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="confirmed",
            analyst_c="confirmed",
            votes_confirmed=3,
            votes_refuted=0,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        with pytest.raises(ValueError, match="priority"):
            VerifiedSP(
                sp_id="SP-002",
                cwe="CWE-121",
                title="Test",
                description="Test",
                function_name="test",
                vulnerable_code_snippet="test",
                control_flow="test",
                trigger_condition="test",
                root_cause="test",
                confidence=0.5,
                severity="medium",
                analyst_type="logic_flaw",
                binary_offset="0x0000",
                input_vector="test",
                analyst_consensus=consensus,
                cross_review_summary="Summary",
                verification_priority="medium",
                priority="P5",
            )

    def test_merged_from_defaults_to_empty_list(self):
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="refuted",
            analyst_c="uncertain",
            votes_confirmed=1,
            votes_refuted=1,
            votes_uncertain=1,
            final_vote="uncertain",
        )
        vsp = VerifiedSP(
            sp_id="SP-003",
            cwe="CWE-190",
            title="Integer overflow",
            description="Integer overflow",
            function_name="calc_size",
            vulnerable_code_snippet="size = a * b;",
            control_flow="calc_size -> malloc",
            trigger_condition="a*b > INT_MAX",
            root_cause="No overflow check",
            confidence=0.6,
            severity="medium",
            analyst_type="memory_corruption",
            binary_offset="0x9abc",
            input_vector="HTTP body length",
            analyst_consensus=consensus,
            cross_review_summary="Split decision",
            verification_priority="high",
            priority="P1",
        )
        assert vsp.merged_from == []
        assert vsp.priority == "P1"
        assert vsp.verification_priority == "high"

    def test_to_dict_from_dict_roundtrip(self):
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="refuted",
            analyst_c="confirmed",
            votes_confirmed=2,
            votes_refuted=1,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        vsp = VerifiedSP(
            sp_id="SP-004",
            cwe="CWE-89",
            title="Command injection",
            description="Command injection in cgi_handler",
            function_name="cgi_handler",
            vulnerable_code_snippet='system(cmd);',
            control_flow="cgi_handler -> system",
            trigger_condition="Shell metacharacters in input",
            root_cause="No sanitization",
            confidence=0.92,
            severity="high",
            analyst_type="injection",
            binary_offset="0x5678",
            input_vector="CGI query string",
            analyst_consensus=consensus,
            cross_review_summary="Majority confirmed",
            verification_priority="immediate",
            priority="P0",
            merged_from=["SP-002"],
            supporting_evidence=["Also found in parse_header"],
        )
        d = vsp.to_dict()
        assert d["priority"] == "P0"
        assert d["analyst_consensus"]["votes_confirmed"] == 2
        assert d["merged_from"] == ["SP-002"]

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        vsp2 = VerifiedSP.from_dict(loaded)
        assert vsp.sp_id == vsp2.sp_id
        assert vsp.priority == vsp2.priority
        assert vsp.analyst_consensus.votes_confirmed == vsp2.analyst_consensus.votes_confirmed
        assert vsp.merged_from == vsp2.merged_from
        assert vsp.supporting_evidence == vsp2.supporting_evidence


# ===========================================================================
# Phase3Statistics + Phase3Result
# ===========================================================================

class TestPhase3Statistics:
    """Tests for Phase3Statistics dataclass."""

    def test_create_statistics(self):
        stats = Phase3Statistics(
            total_raw_sps=50,
            after_dedup=30,
            after_verification=15,
            discarded_as_false_positive=15,
            false_positive_rate_estimate=0.5,
            high_confidence_sps=8,
            needs_dynamic_verification=7,
        )
        assert stats.total_raw_sps == 50
        assert stats.after_dedup == 30
        assert stats.after_verification == 15
        assert stats.false_positive_rate_estimate == 0.5


class TestPhase3Result:
    """Tests for Phase3Result container."""

    def test_create_result(self):
        stats = Phase3Statistics(
            total_raw_sps=10,
            after_dedup=8,
            after_verification=5,
            discarded_as_false_positive=3,
            false_positive_rate_estimate=0.3,
            high_confidence_sps=4,
            needs_dynamic_verification=1,
        )
        result = Phase3Result(verified_sps=[], statistics=stats)
        assert result.count == 0
        assert result.high_confidence == []
        assert result.statistics.after_verification == 5

    def test_count_property(self):
        stats = Phase3Statistics(
            total_raw_sps=10,
            after_dedup=8,
            after_verification=5,
            discarded_as_false_positive=3,
            false_positive_rate_estimate=0.3,
            high_confidence_sps=4,
            needs_dynamic_verification=1,
        )
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="confirmed",
            analyst_c="confirmed",
            votes_confirmed=3,
            votes_refuted=0,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        sps = [
            VerifiedSP(
                sp_id="SP-001", cwe="CWE-121", title="BOF", description="Test",
                function_name="test", vulnerable_code_snippet="test",
                control_flow="a->b", trigger_condition="x", root_cause="y",
                confidence=0.95, severity="critical", analyst_type="memory_corruption",
                binary_offset="0x0", input_vector="HTTP",
                analyst_consensus=consensus, cross_review_summary="OK",
                verification_priority="immediate", priority="P0",
            ),
            VerifiedSP(
                sp_id="SP-002", cwe="CWE-190", title="Overflow", description="Test",
                function_name="test2", vulnerable_code_snippet="test",
                control_flow="a->b", trigger_condition="x", root_cause="y",
                confidence=0.5, severity="medium", analyst_type="logic_flaw",
                binary_offset="0x1", input_vector="HTTP",
                analyst_consensus=consensus, cross_review_summary="OK",
                verification_priority="medium", priority="P2",
            ),
        ]
        result = Phase3Result(verified_sps=sps, statistics=stats)
        assert result.count == 2
        assert len(result.high_confidence) == 1
        assert result.high_confidence[0].sp_id == "SP-001"

    def test_to_dict_from_dict_roundtrip(self):
        stats = Phase3Statistics(
            total_raw_sps=10,
            after_dedup=8,
            after_verification=5,
            discarded_as_false_positive=3,
            false_positive_rate_estimate=0.3,
            high_confidence_sps=4,
            needs_dynamic_verification=1,
        )
        consensus = AnalystConsensus(
            analyst_a="confirmed",
            analyst_b="confirmed",
            analyst_c="confirmed",
            votes_confirmed=3,
            votes_refuted=0,
            votes_uncertain=0,
            final_vote="confirmed",
        )
        sps = [
            VerifiedSP(
                sp_id="SP-001", cwe="CWE-121", title="BOF", description="Test",
                function_name="test", vulnerable_code_snippet="test",
                control_flow="a->b", trigger_condition="x", root_cause="y",
                confidence=0.95, severity="critical", analyst_type="memory_corruption",
                binary_offset="0x0", input_vector="HTTP",
                analyst_consensus=consensus, cross_review_summary="OK",
                verification_priority="immediate", priority="P0",
            ),
        ]
        result = Phase3Result(verified_sps=sps, statistics=stats)
        d = result.to_dict()
        assert len(d["verified_sps"]) == 1
        assert d["statistics"]["total_raw_sps"] == 10

        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        result2 = Phase3Result.from_dict(loaded)
        assert result2.count == 1
        assert result2.statistics.total_raw_sps == 10
        assert result2.verified_sps[0].priority == "P0"
        assert result2.verified_sps[0].analyst_consensus.votes_confirmed == 3
        assert result2.high_confidence[0].sp_id == "SP-001"
