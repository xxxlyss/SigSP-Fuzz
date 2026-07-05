"""Tests for Phase3Pipeline (pipeline.py)."""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
)
from fuzzingbrain.static.models import FunctionInfo
from fuzzingbrain.agents.firmware.sp_models import (
    FirmwareSP,
    CrossReviewVerdict,
    Phase3Result,
    Phase3Statistics,
    VerifiedSP,
    ExploitabilityAssessment,
)


# ── Helpers ─────────────────────────────────────────────────────────────────


def make_direction(
    name="http_processing",
    priority=3,
    core_functions=None,
    category="http_processing",
):
    """Helper to create a Direction for tests."""
    return Direction(
        name=name,
        description=f"Direction: {name}",
        category=category,
        entry_functions=["entry_func"],
        core_functions=core_functions or ["func_a"],
        big_pool=core_functions or ["func_a"],
        primary_attack_types=["buffer_overflow"],
        priority=priority,
        estimated_complexity="medium",
        rationale=f"Priority {priority} direction",
    )


def make_function(name="func_a", address=0x1000):
    """Helper to create a FunctionInfo for tests."""
    return FunctionInfo(
        name=name,
        address=address,
        pseudo_code=f"void {name}(void) {{ }}",
        callees=[],
    )


def make_attack_surface(name="HTTP"):
    """Helper to create an AttackSurface for tests."""
    return AttackSurface(
        name=name,
        category="network_service",
        entry_functions=["entry_func"],
        description="Test surface",
    )


def make_verified_sp(sp_id="mc-func_a-CWE-121-0001"):
    """Helper to create a VerifiedSP for tests."""
    return VerifiedSP(
        sp_id=sp_id,
        cwe="CWE-121",
        title="Stack Buffer Overflow",
        description="Buffer overflow in func_a",
        function_name="func_a",
        vulnerable_code_snippet="char buf[256]; strcpy(buf, param);",
        control_flow="recv() -> strcpy()",
        trigger_condition="Input > 256 bytes",
        root_cause="Missing bounds check",
        confidence=0.85,
        severity="critical",
        analyst_type="memory_corruption",
        exploitability=ExploitabilityAssessment(
            attack_vector="network",
            difficulty="trivial",
            reliability="reliable",
            impact="RCE",
        ),
    )


def make_direction_result(directions):
    """Helper to create DirectionResult."""
    return DirectionResult(
        directions=directions,
        analysis_order=AnalysisOrder(
            recommended_sequence=[d.name for d in directions],
            rationale="Priority order",
        ),
    )


# ── Tests: Scope filtering ──────────────────────────────────────────────────


class TestScopeFiltering:
    """Tests for _filter_directions method."""

    def test_high_priority_scope_filters(self):
        """high_priority scope -> only directions with priority >= 4."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(scope="high_priority")

        high_pri = make_direction("direction_a", priority=5)
        low_pri = make_direction("direction_b", priority=2)
        directions = make_direction_result([high_pri, low_pri])

        filtered = pipeline._filter_directions(directions)

        assert len(filtered) == 1
        assert filtered[0].name == "direction_a"
        assert filtered[0].priority == 5

    def test_all_scope_includes_all(self):
        """all scope -> all directions included."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(scope="all")

        high_pri = make_direction("direction_a", priority=5)
        low_pri = make_direction("direction_b", priority=2)
        directions = make_direction_result([high_pri, low_pri])

        filtered = pipeline._filter_directions(directions)

        assert len(filtered) == 2

    def test_invalid_scope_raises_error(self):
        """Invalid scope value -> ValueError."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        with pytest.raises(ValueError, match="Invalid scope"):
            Phase3Pipeline(scope="invalid_scope")


# ── Tests: _run_analysts_serial ───────────────────────────────────────────


class TestRunAnalystsParallel:
    """Tests for _run_analysts_serial method."""

    def test_all_three_analysts_run_successfully(self):
        """All 3 analysts run and return SPs."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()
        functions = [make_function("func_a")]
        direction = make_direction()
        surfaces = [make_attack_surface()]

        # Mock all 3 analysts
        mc_sp = FirmwareSP(
            sp_id="mc-func_a-CWE-121-0001",
            cwe="CWE-121",
            title="Stack Overflow",
            description="desc",
            function_name="func_a",
            vulnerable_code_snippet="buf[256]",
            control_flow="recv()->cpy()",
            trigger_condition="long input",
            root_cause="no bounds check",
            confidence=0.85,
            analyst_type="memory_corruption",
        )
        lf_sp = FirmwareSP(
            sp_id="lf-func_a-CWE-287-0001",
            cwe="CWE-287",
            title="Auth Bypass",
            description="desc",
            function_name="func_a",
            vulnerable_code_snippet="if(auth)",
            control_flow="recv()->cmp()",
            trigger_condition="forged cookie",
            root_cause="no signature",
            confidence=0.65,
            analyst_type="logic_flaw",
        )
        inj_sp = FirmwareSP(
            sp_id="inj-func_a-CWE-78-0001",
            cwe="CWE-78",
            title="Command Injection",
            description="desc",
            function_name="func_a",
            vulnerable_code_snippet="system(input)",
            control_flow="recv()->system()",
            trigger_condition="attacker input",
            root_cause="no sanitization",
            confidence=0.55,
            analyst_type="injection",
        )

        pipeline.analyst_a.analyze = MagicMock(return_value=[mc_sp])
        pipeline.analyst_b.analyze = MagicMock(return_value=[lf_sp])
        pipeline.analyst_c.analyze = MagicMock(return_value=[inj_sp])

        result = pipeline._run_analysts_serial(functions, direction, surfaces)

        assert "memory_corruption" in result
        assert "logic_flaw" in result
        assert "injection" in result
        assert len(result["memory_corruption"]) == 1
        assert len(result["logic_flaw"]) == 1
        assert len(result["injection"]) == 1
        assert result["memory_corruption"][0].sp_id == mc_sp.sp_id
        assert result["logic_flaw"][0].sp_id == lf_sp.sp_id
        assert result["injection"][0].sp_id == inj_sp.sp_id

    def test_analyst_failure_returns_empty_list(self):
        """If an analyst raises an exception, returns [] for that type."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()
        functions = [make_function("func_a")]
        direction = make_direction()
        surfaces = [make_attack_surface()]

        pipeline.analyst_a.analyze = MagicMock(side_effect=RuntimeError("API error"))
        pipeline.analyst_b.analyze = MagicMock(return_value=[])
        pipeline.analyst_c.analyze = MagicMock(return_value=[])

        result = pipeline._run_analysts_serial(functions, direction, surfaces)

        assert "memory_corruption" in result
        assert "logic_flaw" in result
        assert "injection" in result
        assert result["memory_corruption"] == []


# ── Tests: _run_cross_reviews ───────────────────────────────────────────────


class TestRunCrossReviews:
    """Tests for _run_cross_reviews method."""

    def test_cross_reviews_distribute_sps_correctly(self):
        """A reviews B+C, B reviews C+A, C reviews A+B."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()

        mc_sp = FirmwareSP(
            sp_id="mc-func-CWE-121-0001",
            cwe="CWE-121",
            title="Stack Overflow",
            description="desc",
            function_name="func",
            vulnerable_code_snippet="buf[256]",
            control_flow="recv()->cpy()",
            trigger_condition="long input",
            root_cause="no bounds",
            confidence=0.85,
            analyst_type="memory_corruption",
        )
        lf_sp = FirmwareSP(
            sp_id="lf-func-CWE-287-0001",
            cwe="CWE-287",
            title="Auth Bypass",
            description="desc",
            function_name="func",
            vulnerable_code_snippet="if(auth)",
            control_flow="recv()->cmp()",
            trigger_condition="forged cookie",
            root_cause="no sig",
            confidence=0.65,
            analyst_type="logic_flaw",
        )
        inj_sp = FirmwareSP(
            sp_id="inj-func-CWE-78-0001",
            cwe="CWE-78",
            title="Command Injection",
            description="desc",
            function_name="func",
            vulnerable_code_snippet="system(input)",
            control_flow="recv()->system()",
            trigger_condition="input",
            root_cause="no sanitize",
            confidence=0.55,
            analyst_type="injection",
        )

        sps_by_analyst = {
            "memory_corruption": [mc_sp],
            "logic_flaw": [lf_sp],
            "injection": [inj_sp],
        }

        verdict_a = CrossReviewVerdict(
            sp_id="lf-func-CWE-287-0001",
            reviewer_type="memory_corruption",
            verdict="confirmed",
        )
        verdict_b = CrossReviewVerdict(
            sp_id="mc-func-CWE-121-0001",
            reviewer_type="logic_flaw",
            verdict="confirmed",
        )
        verdict_c = CrossReviewVerdict(
            sp_id="mc-func-CWE-121-0001",
            reviewer_type="injection",
            verdict="refuted",
        )

        function_contexts = {"func": make_function("func")}

        pipeline.reviewer_a.review = MagicMock(return_value=[verdict_a])
        pipeline.reviewer_b.review = MagicMock(return_value=[verdict_b])
        pipeline.reviewer_c.review = MagicMock(return_value=[verdict_c])

        result = pipeline._run_cross_reviews(sps_by_analyst, function_contexts)

        assert len(result) == 3
        assert any(v.reviewer_type == "memory_corruption" for v in result)
        assert any(v.reviewer_type == "logic_flaw" for v in result)
        assert any(v.reviewer_type == "injection" for v in result)


# ── Tests: _build_function_contexts ─────────────────────────────────────────


class TestBuildFunctionContexts:
    """Tests for _build_function_contexts helper."""

    def test_builds_lookup_dict(self):
        """Builds dict mapping function name to FunctionInfo."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        func_a = make_function("func_a", 0x1000)
        func_b = make_function("func_b", 0x2000)
        functions = [func_a, func_b]

        result = Phase3Pipeline._build_function_contexts(functions)

        assert len(result) == 2
        assert result["func_a"] is func_a
        assert result["func_b"] is func_b

    def test_empty_functions(self):
        """Empty functions list -> empty dict."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        result = Phase3Pipeline._build_function_contexts([])
        assert result == {}


# ── Tests: Initialization ───────────────────────────────────────────────────


class TestInitialization:
    """Tests for Phase3Pipeline.__init__."""

    def test_creates_all_agents(self):
        """Pipeline creates analysts, reviewers, verifier, dedupper."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline
        from fuzzingbrain.agents.firmware.sp_analysts import AnalystAgent
        from fuzzingbrain.agents.firmware.cross_reviewer import CrossReviewer
        from fuzzingbrain.agents.firmware.sp_verifier import SPVerifier
        from fuzzingbrain.agents.firmware.sp_dedup import SPDedupper

        pipeline = Phase3Pipeline()

        assert isinstance(pipeline.analyst_a, AnalystAgent)
        assert isinstance(pipeline.analyst_b, AnalystAgent)
        assert isinstance(pipeline.analyst_c, AnalystAgent)
        assert pipeline.analyst_a.analyst_type == "memory_corruption"
        assert pipeline.analyst_b.analyst_type == "logic_flaw"
        assert pipeline.analyst_c.analyst_type == "injection"

        assert isinstance(pipeline.reviewer_a, CrossReviewer)
        assert isinstance(pipeline.reviewer_b, CrossReviewer)
        assert isinstance(pipeline.reviewer_c, CrossReviewer)
        assert pipeline.reviewer_a.reviewer_type == "memory_corruption"
        assert pipeline.reviewer_b.reviewer_type == "logic_flaw"
        assert pipeline.reviewer_c.reviewer_type == "injection"

        assert isinstance(pipeline.verifier, SPVerifier)
        assert isinstance(pipeline.dedupper, SPDedupper)

    def test_agents_share_llm_client(self):
        """All agents share the same LLM client instance."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()

        assert pipeline.analyst_a.llm_client is pipeline.llm_client
        assert pipeline.analyst_b.llm_client is pipeline.llm_client
        assert pipeline.analyst_c.llm_client is pipeline.llm_client
        assert pipeline.reviewer_a.llm_client is pipeline.llm_client
        assert pipeline.reviewer_b.llm_client is pipeline.llm_client
        assert pipeline.reviewer_c.llm_client is pipeline.llm_client
        assert pipeline.verifier.llm_client is pipeline.llm_client

    def test_scope_defaults_to_all(self):
        """Default scope is 'all'."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()
        assert pipeline.scope == "all"


# ── Tests: save/load ────────────────────────────────────────────────────────


class TestSaveLoad:
    """Tests for save/load roundtrip."""

    def test_save_load_roundtrip(self, tmp_path):
        """Save -> Load returns identical data."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()

        verified_sp = make_verified_sp("mc-func_a-CWE-121-0001")
        statistics = Phase3Statistics(
            total_raw_sps=3,
            after_dedup=3,
            after_verification=2,
            discarded_as_false_positive=1,
            false_positive_rate_estimate=0.33,
            high_confidence_sps=1,
            needs_dynamic_verification=1,
        )
        result = Phase3Result(
            verified_sps=[verified_sp],
            statistics=statistics,
        )

        output_path = tmp_path / "phase3_result.json"
        pipeline.save(result, output_path)

        assert output_path.exists()

        loaded = pipeline.load(output_path)

        assert isinstance(loaded, Phase3Result)
        assert loaded.count == 1
        assert loaded.verified_sps[0].sp_id == "mc-func_a-CWE-121-0001"
        assert loaded.statistics.total_raw_sps == 3
        assert loaded.statistics.after_verification == 2

    def test_load_nonexistent_file_raises(self):
        """Loading a nonexistent file raises FileNotFoundError."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()

        with pytest.raises(FileNotFoundError, match="Phase3Result file not found"):
            pipeline.load("/nonexistent/path/result.json")


# ── Tests: run (integration) ────────────────────────────────────────────────


class TestRun:
    """Tests for the main run method."""

    def test_empty_directions_returns_empty_result(self):
        """No directions -> empty Phase3Result."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline()
        directions = make_direction_result([])
        functions = [make_function("func_a")]
        surfaces = [make_attack_surface()]

        result = pipeline.run(directions, functions, surfaces)

        assert isinstance(result, Phase3Result)
        assert result.count == 0
        assert result.statistics.total_raw_sps == 0
        assert result.statistics.after_verification == 0

    def test_pipeline_integration_all_mocked(self):
        """Full run with mocked analyst/reviewer/verifier methods.

        Uses a single direction with 1 function. Mocks the pipeline's
        inner methods to avoid real LLM calls and ThreadPoolExecutor issues.
        """
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(scope="all")

        direction = make_direction(
            name="http_processing",
            priority=5,
            core_functions=["func_a"],
        )
        directions = make_direction_result([direction])

        func_a = make_function("func_a", 0x1000)
        functions = [func_a]
        surfaces = [make_attack_surface()]

        # Mock analysts
        mc_sp = FirmwareSP(
            sp_id="mc-func_a-CWE-121-0001",
            cwe="CWE-121",
            title="Stack Overflow",
            description="desc",
            function_name="func_a",
            vulnerable_code_snippet="buf[256]",
            control_flow="recv()->cpy()",
            trigger_condition="long input",
            root_cause="no bounds",
            confidence=0.85,
            analyst_type="memory_corruption",
        )
        lf_sp = FirmwareSP(
            sp_id="lf-func_a-CWE-287-0001",
            cwe="CWE-287",
            title="Auth Bypass",
            description="desc",
            function_name="func_a",
            vulnerable_code_snippet="if(auth)",
            control_flow="recv()->cmp()",
            trigger_condition="forged cookie",
            root_cause="no sig",
            confidence=0.65,
            analyst_type="logic_flaw",
        )

        pipeline._run_analysts_serial = MagicMock(
            return_value={
                "memory_corruption": [mc_sp],
                "logic_flaw": [lf_sp],
                "injection": [],
            }
        )

        # Mock cross reviews
        verdict_b_on_mc = CrossReviewVerdict(
            sp_id="mc-func_a-CWE-121-0001",
            reviewer_type="logic_flaw",
            verdict="confirmed",
        )
        verdict_c_on_mc = CrossReviewVerdict(
            sp_id="mc-func_a-CWE-121-0001",
            reviewer_type="injection",
            verdict="confirmed",
        )
        verdict_a_on_lf = CrossReviewVerdict(
            sp_id="lf-func_a-CWE-287-0001",
            reviewer_type="memory_corruption",
            verdict="confirmed",
        )
        verdict_c_on_lf = CrossReviewVerdict(
            sp_id="lf-func_a-CWE-287-0001",
            reviewer_type="injection",
            verdict="uncertain",
        )

        pipeline._run_cross_reviews = MagicMock(
            return_value=[
                verdict_b_on_mc,
                verdict_c_on_mc,
                verdict_a_on_lf,
                verdict_c_on_lf,
            ]
        )

        # Mock verifier
        verified_sp = make_verified_sp("mc-func_a-CWE-121-0001")
        statistics = Phase3Statistics(
            total_raw_sps=2,
            after_verification=1,
            discarded_as_false_positive=1,
        )
        expected_result = Phase3Result(
            verified_sps=[verified_sp],
            statistics=statistics,
        )
        pipeline.verifier.verify = MagicMock(return_value=expected_result)

        # Run pipeline
        result = pipeline.run(directions, functions, surfaces)

        # Verify integration
        assert isinstance(result, Phase3Result)
        assert result.count == 1
        assert result.statistics.total_raw_sps == 2
        assert result.statistics.after_verification == 1
        assert result.statistics.discarded_as_false_positive == 1
        assert result.verified_sps[0].sp_id == "mc-func_a-CWE-121-0001"

        # Verify pipeline called the right methods
        pipeline._run_analysts_serial.assert_called_once()
        pipeline._run_cross_reviews.assert_called_once()
        pipeline.verifier.verify.assert_called_once()

    def test_run_sorts_by_priority_descending(self):
        """Directions are processed in priority descending order."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(scope="all")

        # Create directions with different priorities
        dir_high = make_direction(
            name="high_pri", priority=5, core_functions=["func_a"],
        )
        dir_medium = make_direction(
            name="medium_pri", priority=3, core_functions=["func_b"],
        )
        dir_low = make_direction(
            name="low_pri", priority=1, core_functions=["func_c"],
        )
        directions = make_direction_result([dir_low, dir_high, dir_medium])

        func_a = make_function("func_a", 0x1000)
        func_b = make_function("func_b", 0x2000)
        func_c = make_function("func_c", 0x3000)
        functions = [func_a, func_b, func_c]
        surfaces = [make_attack_surface()]

        # Track call order
        call_order = []

        def tracking_analyst(functions, direction, surfaces):
            call_order.append(direction.name)
            return {}

        pipeline._run_analysts_serial = MagicMock(side_effect=tracking_analyst)
        pipeline._run_cross_reviews = MagicMock(return_value=[])
        pipeline.verifier.verify = MagicMock(
            return_value=Phase3Result(
                verified_sps=[],
                statistics=Phase3Statistics(),
            )
        )

        pipeline.run(directions, functions, surfaces)

        # Should be sorted high->low: high_pri, medium_pri, low_pri
        assert call_order == ["high_pri", "medium_pri", "low_pri"]

    def test_run_skips_direction_with_no_functions(self):
        """Directions with no matching functions are skipped with a warning."""
        from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(scope="all")

        dir_a = make_direction(
            name="dir_a", priority=3, core_functions=["nonexistent_func"],
        )
        directions = make_direction_result([dir_a])

        functions = [make_function("func_a")]
        surfaces = [make_attack_surface()]

        pipeline._run_analysts_serial = MagicMock()
        pipeline._run_cross_reviews = MagicMock()
        pipeline.verifier.verify = MagicMock(
            return_value=Phase3Result(
                verified_sps=[],
                statistics=Phase3Statistics(),
            )
        )

        result = pipeline.run(directions, functions, surfaces)

        # Pipeline should not crash, just skip the direction
        assert isinstance(result, Phase3Result)
        pipeline._run_analysts_serial.assert_not_called()
