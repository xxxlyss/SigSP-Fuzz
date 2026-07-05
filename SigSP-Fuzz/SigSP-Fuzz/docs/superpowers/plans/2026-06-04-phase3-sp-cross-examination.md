# Phase 3: Multi-Agent Cross-Examination SP Analysis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the 3-analyst cross-examination SP analysis pipeline — Analyst A/B/C independently find vulnerabilities from different perspectives, then cross-review each other's findings, and a final verifier adjudicates.

**Architecture:** Parameterized `AnalystAgent` (A/B/C differ only by prompt), `CrossReviewer`, `SPVerifier` (voting + merge), `SPDedupper` (pure algorithm). Orchestrated by `Phase3Pipeline` with configurable scope (all directions vs high-priority only). Follows Phase 2 patterns: dataclass models, class-based agents with `LLMClient`, prompt files in `agents/firmware/prompts/`.

**Tech Stack:** Python dataclasses, DeepSeek-V4-Pro (Analyst A/B + Verifier), Qwen3.6-Plus (Analyst C + CrossReviewer C), `unittest.mock` for LLM mocking

**Design Spec:** `docs/superpowers/specs/2026-06-04-firmware-vuln-discovery-design.md` Section 5

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `fuzzingbrain/agents/firmware/sp_models.py` | **Create** | FirmwareSP, CrossReviewVerdict, VerifiedSP, Phase3Result dataclasses |
| `fuzzingbrain/agents/firmware/prompts/analyst_a_prompt.md` | **Create** | Memory corruption analyst system prompt |
| `fuzzingbrain/agents/firmware/prompts/analyst_b_prompt.md` | **Create** | Logic flaw analyst system prompt |
| `fuzzingbrain/agents/firmware/prompts/analyst_c_prompt.md` | **Create** | Injection analyst system prompt |
| `fuzzingbrain/agents/firmware/prompts/cross_review_prompt.md` | **Create** | Cross-review system prompt |
| `fuzzingbrain/agents/firmware/prompts/verifier_prompt.md` | **Create** | Final SP verifier system prompt |
| `fuzzingbrain/agents/firmware/prompts/__init__.py` | **Modify** | Add 5 new prompt loader functions |
| `fuzzingbrain/agents/firmware/sp_analysts.py` | **Create** | AnalystAgent class (parameterized A/B/C) |
| `fuzzingbrain/agents/firmware/cross_reviewer.py` | **Create** | CrossReviewer class |
| `fuzzingbrain/agents/firmware/sp_verifier.py` | **Create** | SPVerifier class (voting + adjudication) |
| `fuzzingbrain/agents/firmware/sp_dedup.py` | **Create** | Pure-algorithm SP deduplication |
| `fuzzingbrain/agents/firmware/pipeline.py` | **Create** | Phase3Pipeline orchestration |
| `fuzzingbrain/agents/firmware/__init__.py` | **Modify** | Export new public classes |
| `tests/test_sp_models.py` | **Create** | Model serialization/validation tests (~18 tests) |
| `tests/test_sp_analysts.py` | **Create** | AnalystAgent tests with mocked LLM (~12 tests) |
| `tests/test_cross_reviewer.py` | **Create** | CrossReviewer tests (~6 tests) |
| `tests/test_sp_verifier.py` | **Create** | SPVerifier voting/merge tests (~8 tests) |
| `tests/test_sp_dedup.py` | **Create** | Dedup algorithm tests (~8 tests) |
| `tests/test_phase3_pipeline.py` | **Create** | Integration tests (~5 tests) |

**Total: 13 new files, 2 modified, ~57 new tests**

---

### Task 1: Data Models (`sp_models.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/sp_models.py`
- Create: `tests/test_sp_models.py`

#### Models to implement

```python
# ExploitabilityAssessment — embedded in FirmwareSP
#   attack_vector: network | local | authenticated_network
#   difficulty: trivial | moderate | hard
#   reliability: reliable | medium | fragile
#   impact: RCE | DoS | Information_Disclosure

# FirmwareSP — raw SP from an analyst
#   sp_id, cwe, title, description, function_name, vulnerable_code_snippet,
#   control_flow, trigger_condition, root_cause, exploitability (optional),
#   confidence (0.0-1.0), severity (critical|high|medium|low),
#   analyst_type (memory_corruption|logic_flaw|injection),
#   binary_offset, input_vector, supporting_evidence[],
#   potential_false_positive_triggers[]

# CrossReviewVerdict — one reviewer's judgment on one SP
#   sp_id, reviewer_type, verdict (confirmed|refuted|uncertain|needs_more_context),
#   confidence_adjustment (str, e.g. "+0.1"), refutation_reason, missed_context,
#   merged_with (optional str)

# CrossReviewResult — collection of verdicts
#   reviews: List[CrossReviewVerdict]

# AnalystConsensus — voting summary for VerifiedSP
#   analyst_a, analyst_b, analyst_c (each: confirmed|refuted|uncertain|—)
#   votes_confirmed, votes_refuted, votes_uncertain, final_vote

# VerifiedSP — final SP after verification
#   all FirmwareSP fields + analyst_consensus, cross_review_summary,
#   merged_from: List[str], verification_priority (immediate|high|medium|low),
#   priority (P0|P1|P2|P3)

# Phase3Statistics
#   total_raw_sps, after_dedup, after_verification, discarded_as_false_positive,
#   false_positive_rate_estimate, high_confidence_sps, needs_dynamic_verification

# Phase3Result
#   verified_sps: List[VerifiedSP], statistics: Phase3Statistics
```

- [ ] **Step 1: Write sp_models.py with all dataclasses**

See full code below.

- [ ] **Step 2: Write test_sp_models.py (18 tests)**

Tests: ExploitabilityAssessment validation, FirmwareSP to_dict/from_dict/validation, CrossReviewVerdict verdict enum, VerifiedSP consensus, Phase3Statistics, Phase3Result to_dict/from_dict, edge cases (confidence boundary, empty lists).

- [ ] **Step 3: Run model tests**

```bash
pytest tests/test_sp_models.py -v
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/agents/firmware/sp_models.py tests/test_sp_models.py
git commit -m "feat(phase3): add SP data models for cross-examination pipeline"
```

---

### Task 2: Prompt Templates (5 files)

**Files:**
- Create: `fuzzingbrain/agents/firmware/prompts/analyst_a_prompt.md`
- Create: `fuzzingbrain/agents/firmware/prompts/analyst_b_prompt.md`
- Create: `fuzzingbrain/agents/firmware/prompts/analyst_c_prompt.md`
- Create: `fuzzingbrain/agents/firmware/prompts/cross_review_prompt.md`
- Create: `fuzzingbrain/agents/firmware/prompts/verifier_prompt.md`
- Modify: `fuzzingbrain/agents/firmware/prompts/__init__.py`

Prompts are taken verbatim from the design spec Section 5.4-5.8. Each file contains the full system prompt with role, checklist, output format (JSON schema), and critical rules.

- [ ] **Step 1: Write analyst_a_prompt.md** — Memory corruption expert (CWE-120/121/122/190/193). Checklists: stack overflow, heap overflow, integer overflow, off-by-one.

- [ ] **Step 2: Write analyst_b_prompt.md** — Logic flaw expert (CWE-287/862/20/362/200). Checklists: auth bypass, authorization flaws, input validation, race conditions, info disclosure.

- [ ] **Step 3: Write analyst_c_prompt.md** — Injection expert (CWE-78/134/22/626). Checklists: command injection, format string, path traversal, null byte injection. Uses tainted-source-to-dangerous-sink methodology.

- [ ] **Step 4: Write cross_review_prompt.md** — Review panel member. Reviews other analysts' SPs for: reachability, input feasibility, mitigation, alternative explanations. Output: confirmed/refuted/uncertain with specific reasoning.

- [ ] **Step 5: Write verifier_prompt.md** — Final adjudicator. 3-step process: resolve disputes (voting), merge duplicates, assign P0-P3 priority. Output: verified_sps + statistics.

- [ ] **Step 6: Update prompts/__init__.py** — Add 5 loader functions:

```python
def get_analyst_a_prompt() -> str:
    return load_prompt("analyst_a_prompt.md")

def get_analyst_b_prompt() -> str:
    return load_prompt("analyst_b_prompt.md")

def get_analyst_c_prompt() -> str:
    return load_prompt("analyst_c_prompt.md")

def get_cross_review_prompt() -> str:
    return load_prompt("cross_review_prompt.md")

def get_verifier_prompt() -> str:
    return load_prompt("verifier_prompt.md")
```

- [ ] **Step 7: Verify prompts load correctly**

```bash
python -c "
from fuzzingbrain.agents.firmware.prompts import (
    get_analyst_a_prompt, get_analyst_b_prompt, get_analyst_c_prompt,
    get_cross_review_prompt, get_verifier_prompt
)
for name, getter in [('A', get_analyst_a_prompt), ('B', get_analyst_b_prompt),
                      ('C', get_analyst_c_prompt), ('review', get_cross_review_prompt),
                      ('verifier', get_verifier_prompt)]:
    p = getter()
    assert len(p) > 500, f'{name} prompt too short: {len(p)} chars'
    print(f'Analyst {name}: {len(p)} chars OK')
print('All prompts loaded successfully')
"
```

- [ ] **Step 8: Commit**

```bash
git add fuzzingbrain/agents/firmware/prompts/
git commit -m "feat(phase3): add 5 prompt templates for SP analysis pipeline"
```

---

### Task 3: AnalystAgent (`sp_analysts.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/sp_analysts.py`
- Create: `tests/test_sp_analysts.py`

**Design:** One `AnalystAgent` class parameterized by `analyst_type` ("memory_corruption" | "logic_flaw" | "injection"). The type selects which prompt to load, which model to use (A/B→DeepSeek, C→Qwen), and annotates output SPs.

```python
class AnalystAgent:
    """
    Vulnerability analyst specializing in one perspective.

    analyst_type: "memory_corruption" | "logic_flaw" | "injection"
    Agent A (memory_corruption): DeepSeek-V4-Pro
    Agent B (logic_flaw): DeepSeek-V4-Pro
    Agent C (injection): Qwen3.6-Plus
    """

    def __init__(self, llm_client=None, analyst_type="memory_corruption",
                 model=None, temperature=0.3, max_tokens=8000)

    def analyze(self, functions: List[FunctionInfo],
                direction: Direction,
                attack_surfaces: List[AttackSurface]) -> List[FirmwareSP]:
        """
        Analyze all functions in the direction.
        Processes functions sequentially, one LLM call per function.
        Returns all SPs with confidence >= 0.3.
        """

    def _get_system_prompt(self) -> str:
        """Return the prompt for this analyst type."""

    def _get_default_model(self) -> ModelInfo:
        """A/B → DEEPSEEK_V4_PRO, C → QWEN3_6_PLUS"""

    def _build_function_prompt(self, func: FunctionInfo,
                                direction: Direction,
                                surfaces: List[AttackSurface]) -> str:
        """Build user message with function pseudo-code + context."""

    def _parse_response(self, content: str, func_name: str) -> List[FirmwareSP]:
        """Parse LLM JSON response, assign sp_ids, filter confidence < 0.3."""

    # sp_id format: {type_prefix}-{func_name}-{cwe}-{counter:04d}
    # type_prefix: mc (memory_corruption), lf (logic_flaw), inj (injection)
```

- [ ] **Step 1: Write test_sp_analysts.py — test prompt selection**

```python
def test_analyst_a_uses_memory_corruption_prompt():
    agent = AnalystAgent(analyst_type="memory_corruption")
    prompt = agent._get_system_prompt()
    assert "memory corruption" in prompt.lower()
    assert "buffer overflow" in prompt.lower()

def test_analyst_b_uses_logic_flaw_prompt():
    agent = AnalystAgent(analyst_type="logic_flaw")
    prompt = agent._get_system_prompt()
    assert "logic" in prompt.lower()
    assert "authentication bypass" in prompt.lower()

def test_analyst_c_uses_injection_prompt():
    agent = AnalystAgent(analyst_type="injection")
    prompt = agent._get_system_prompt()
    assert "injection" in prompt.lower()
    assert "command injection" in prompt.lower()
```

- [ ] **Step 2: Write test_sp_analysts.py — test model defaults**

```python
def test_analyst_a_default_model_is_deepseek():
    from fuzzingbrain.llms import DEEPSEEK_V4_PRO
    agent = AnalystAgent(analyst_type="memory_corruption")
    assert agent.model == DEEPSEEK_V4_PRO

def test_analyst_c_default_model_is_qwen():
    from fuzzingbrain.llms import QWEN3_6_PLUS
    agent = AnalystAgent(analyst_type="injection")
    assert agent.model == QWEN3_6_PLUS
```

- [ ] **Step 3: Write test_sp_analysts.py — test invalid analyst_type**

```python
def test_invalid_analyst_type_raises_error():
    with pytest.raises(ValueError, match="analyst_type"):
        AnalystAgent(analyst_type="invalid_type")
```

- [ ] **Step 4: Write test_sp_analysts.py — test SP parsing from mock LLM response**

```python
def test_parse_valid_sp_response():
    agent = AnalystAgent(analyst_type="memory_corruption")
    mock_json = json.dumps({
        "analyst_type": "memory_corruption",
        "findings": [{
            "cwe": "CWE-121",
            "title": "Stack Buffer Overflow in httpd_handler",
            "description": "strcpy without bounds check",
            "vulnerable_function": "httpd_handler",
            "vulnerable_code_snippet": "char buf[256]; strcpy(buf, param);",
            "control_flow": "httpd_handler → get_param → strcpy",
            "trigger_condition": "Send HTTP request with param > 256 bytes",
            "root_cause": "Missing bounds check before strcpy",
            "exploitability_initial": {
                "attack_vector": "network", "difficulty": "trivial",
                "reliability": "reliable", "impact": "RCE"
            },
            "confidence": 0.85,
            "severity": "critical",
            "supporting_evidence": ["no size check before strcpy"],
            "potential_false_positive_triggers": ["Check if wrapper validates"]
        }]
    })
    sps = agent._parse_response(mock_json, "httpd_handler")
    assert len(sps) == 1
    sp = sps[0]
    assert sp.cwe == "CWE-121"
    assert sp.confidence == 0.85
    assert sp.analyst_type == "memory_corruption"
    assert sp.sp_id.startswith("mc-httpd_handler-CWE-121-")
```

- [ ] **Step 5: Write test_sp_analysts.py — test low confidence filtering**

```python
def test_filters_low_confidence_sps():
    agent = AnalystAgent(analyst_type="memory_corruption")
    mock_json = json.dumps({
        "analyst_type": "memory_corruption",
        "findings": [
            {"cwe": "CWE-121", "title": "Real", "description": "...",
             "vulnerable_function": "func1", "confidence": 0.85,
             "severity": "high",
             "exploitability_initial": {"attack_vector": "network",
             "difficulty": "moderate", "reliability": "medium", "impact": "RCE"}},
            {"cwe": "CWE-122", "title": "Noise", "description": "...",
             "vulnerable_function": "func2", "confidence": 0.2,
             "severity": "low",
             "exploitability_initial": {"attack_vector": "local",
             "difficulty": "hard", "reliability": "fragile", "impact": "DoS"}}
        ]
    })
    sps = agent._parse_response(mock_json, "func1")
    assert len(sps) == 1
    assert sps[0].confidence == 0.85
```

- [ ] **Step 6: Write test_sp_analysts.py — test code fence parsing**

```python
def test_parse_response_with_markdown_fence():
    agent = AnalystAgent(analyst_type="logic_flaw")
    response = '```json\n{"analyst_type":"logic_flaw","findings":[]}\n```'
    sps = agent._parse_response(response, "test_func")
    assert sps == []
```

- [ ] **Step 7: Write test_sp_analysts.py — integration test with mocked LLM**

```python
def test_analyze_with_mocked_llm():
    from unittest.mock import MagicMock
    from fuzzingbrain.attack_surface.models import Direction

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.content = json.dumps({
        "analyst_type": "memory_corruption",
        "findings": [{
            "cwe": "CWE-121", "title": "Test SP",
            "description": "Test desc",
            "vulnerable_function": "test_func",
            "confidence": 0.75, "severity": "high",
            "exploitability_initial": {
                "attack_vector": "network", "difficulty": "trivial",
                "reliability": "reliable", "impact": "RCE"
            }
        }]
    })
    mock_client.call.return_value = mock_response

    agent = AnalystAgent(llm_client=mock_client, analyst_type="memory_corruption")
    func = FunctionInfo(name="test_func", address=0x1000,
                        pseudo_code="void test_func() { strcpy(buf, input); }",
                        callees=["strcpy"], strings_used=["input"],
                        dangerous_funcs=["strcpy"], has_unsafe_calls=True)
    direction = Direction(
        name="Test Direction", description="test", category="network_service",
        entry_functions=["entry"], core_functions=["test_func"],
        big_pool=["test_func", "entry"], priority=5
    )

    sps = agent.analyze([func], direction, [])
    assert len(sps) == 1
    assert sps[0].cwe == "CWE-121"
    mock_client.call.assert_called_once()
```

- [ ] **Step 8: Run analyst tests**

```bash
pytest tests/test_sp_analysts.py -v
```

- [ ] **Step 9: Implement sp_analysts.py**

Full implementation with `_build_function_prompt` building per-function context (name, address, arch, pseudo_code, assembly excerpt, callers, callees, strings, direction context, attack surface context).

- [ ] **Step 10: Run tests to verify pass**

```bash
pytest tests/test_sp_analysts.py -v
```

- [ ] **Step 11: Commit**

```bash
git add fuzzingbrain/agents/firmware/sp_analysts.py tests/test_sp_analysts.py
git commit -m "feat(phase3): implement parameterized AnalystAgent for SP generation"
```

---

### Task 4: CrossReviewer (`cross_reviewer.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/cross_reviewer.py`
- Create: `tests/test_cross_reviewer.py`

```python
class CrossReviewer:
    """
    Reviews SPs from other analysts for false positive detection.

    Each reviewer critiques SPs from the other two analysts.
    Reviewers A, B use DeepSeek-V4-Pro; Reviewer C uses Qwen3.6-Plus.

    Usage:
        reviewer = CrossReviewer(reviewer_type="memory_corruption")
        verdicts = reviewer.review(sps_to_review, function_contexts)
    """

    def __init__(self, llm_client=None, reviewer_type="memory_corruption",
                 model=None, temperature=0.3, max_tokens=8000)

    def review(self, sps_to_review: List[FirmwareSP],
               function_contexts: Dict[str, FunctionInfo]) -> List[CrossReviewVerdict]:
        """
        Review a batch of SPs from other analysts.
        Only reviews SPs with confidence > 0.6.
        Returns one CrossReviewVerdict per reviewed SP.
        """

    def _build_review_prompt(self, sps: List[FirmwareSP],
                              contexts: Dict[str, FunctionInfo]) -> str:
        """Build prompt with SP details + function pseudo-code for context."""

    def _parse_response(self, content: str) -> List[CrossReviewVerdict]:
        """Parse JSON array of verdicts."""

    def _get_default_model(self) -> ModelInfo:
        """A/B → DEEPSEEK_V4_PRO, C → QWEN3_6_PLUS"""
```

- [ ] **Step 1: Write tests — mock LLM review**

6 tests: valid verdict parsing, confidence filter (>0.6 only), refutation reason required, uncertain verdict, code fence parsing, integration with mocked client.

- [ ] **Step 2: Implement cross_reviewer.py**

- [ ] **Step 3: Run tests**

```bash
pytest tests/test_cross_reviewer.py -v
```

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/agents/firmware/cross_reviewer.py tests/test_cross_reviewer.py
git commit -m "feat(phase3): implement CrossReviewer for adversarial SP review"
```

---

### Task 5: SPVerifier (`sp_verifier.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/sp_verifier.py`
- Create: `tests/test_sp_verifier.py`

```python
class SPVerifier:
    """
    Final vulnerability adjudicator. Uses DeepSeek-V4-Pro.

    Three-step process:
    1. Resolve disputes via voting (3/3→accept+0.1, 2/3→accept,
       1/3→downgrade, 0/3→discard)
    2. Merge duplicates (same function + same CWE)
    3. Assign P0-P3 priority based on confidence, attack vector, impact
    """

    def __init__(self, llm_client=None, model=None,
                 temperature=0.3, max_tokens=8000)

    def verify(self, raw_sps: List[FirmwareSP],
               cross_reviews: List[CrossReviewVerdict],
               function_contexts: dict) -> Phase3Result:
        """
        Full verification pipeline:
        1. Compute consensus votes (algorithmic)
        2. Call LLM for final adjudication of disputed SPs
        3. Assign priorities
        4. Build Phase3Result
        """

    def _compute_consensus(self, sp: FirmwareSP,
                            verdicts: List[CrossReviewVerdict]
                            ) -> AnalystConsensus:
        """Count votes from cross-reviews. Pure algorithm, no LLM."""

    def _build_verifier_prompt(self, disputed_sps, reviews, contexts) -> str:
        """Build prompt with SPs + all review comments + function code."""

    def _parse_response(self, content: str) -> Phase3Result:
        """Parse the final verified SP list + statistics."""

    def _assign_priority(self, sp: VerifiedSP) -> str:
        """
        P0: network + unauthenticated + RCE + confidence > 0.7
        P1: network + authenticated/complex + confidence > 0.6
        P2: network constrained or confidence < 0.6
        P3: local, hard exploit, or low confidence
        """
```

- [ ] **Step 1: Write tests — consensus voting logic**

```python
def test_consensus_all_confirmed():
    verifier = SPVerifier()
    sp = make_sp(sp_id="test-1", confidence=0.8)
    verdicts = [
        CrossReviewVerdict(sp_id="test-1", reviewer_type="memory_corruption",
                           verdict="confirmed", confidence_adjustment="+0.1"),
        CrossReviewVerdict(sp_id="test-1", reviewer_type="logic_flaw",
                           verdict="confirmed", confidence_adjustment="+0.1"),
        CrossReviewVerdict(sp_id="test-1", reviewer_type="injection",
                           verdict="confirmed", confidence_adjustment="0.0"),
    ]
    consensus = verifier._compute_consensus(sp, verdicts)
    assert consensus.votes_confirmed == 3
    assert consensus.final_vote == "accept_boost"  # 3/3 → +0.1

def test_consensus_all_refuted():
    verifier = SPVerifier()
    sp = make_sp(sp_id="test-2", confidence=0.7)
    verdicts = [
        CrossReviewVerdict(sp_id="test-2", reviewer_type="memory_corruption",
                           verdict="refuted", confidence_adjustment="-0.5"),
        CrossReviewVerdict(sp_id="test-2", reviewer_type="logic_flaw",
                           verdict="refuted", confidence_adjustment="-0.5"),
        CrossReviewVerdict(sp_id="test-2", reviewer_type="injection",
                           verdict="refuted", confidence_adjustment="-0.3"),
    ]
    consensus = verifier._compute_consensus(sp, verdicts)
    assert consensus.votes_refuted == 3
    assert consensus.final_vote == "discard"

def test_consensus_two_of_three():
    verifier = SPVerifier()
    sp = make_sp(sp_id="test-3", confidence=0.7)
    verdicts = [
        CrossReviewVerdict(sp_id="test-3", reviewer_type="A",
                           verdict="confirmed", confidence_adjustment="0.0"),
        CrossReviewVerdict(sp_id="test-3", reviewer_type="B",
                           verdict="confirmed", confidence_adjustment="0.0"),
        CrossReviewVerdict(sp_id="test-3", reviewer_type="C",
                           verdict="refuted", confidence_adjustment="-0.2"),
    ]
    consensus = verifier._compute_consensus(sp, verdicts)
    assert consensus.final_vote == "accept"  # 2/3 → accept
```

- [ ] **Step 2: Write tests — priority assignment**

```python
def test_p0_priority_network_rce_high_confidence():
    sp = VerifiedSP(..., confidence=0.85, exploitability=ExploitabilityAssessment(
        attack_vector="network", difficulty="trivial",
        reliability="reliable", impact="RCE"))
    assert SPVerifier._assign_priority(sp) == "P0"

def test_p3_priority_local_low_confidence():
    sp = VerifiedSP(..., confidence=0.4, exploitability=ExploitabilityAssessment(
        attack_vector="local", difficulty="hard",
        reliability="fragile", impact="DoS"))
    assert SPVerifier._assign_priority(sp) == "P3"
```

- [ ] **Step 3: Write test — full verify with mocked LLM**

```python
def test_verify_with_mocked_llm():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.content = json.dumps({
        "verified_sps": [...],
        "statistics": {"total_raw_sps": 3, ...}
    })
    mock_client.call.return_value = mock_response

    verifier = SPVerifier(llm_client=mock_client)
    raw_sps = [make_sp(f"sp-{i}", 0.8) for i in range(3)]
    verdicts = [make_verdict(f"sp-{i}", "confirmed") for i in range(3)]

    result = verifier.verify(raw_sps, verdicts, {})
    assert result.statistics.total_raw_sps == 3
```

- [ ] **Step 4: Implement sp_verifier.py**

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_sp_verifier.py -v
```

- [ ] **Step 6: Commit**

```bash
git add fuzzingbrain/agents/firmware/sp_verifier.py tests/test_sp_verifier.py
git commit -m "feat(phase3): implement SPVerifier with voting and priority assignment"
```

---

### Task 6: SPDedupper (`sp_dedup.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/sp_dedup.py`
- Create: `tests/test_sp_dedup.py`

```python
class SPDedupper:
    """
    Pure-algorithm SP deduplication (no LLM involved).

    Dedup rules (from design spec 5.9):
    1. Same function + same CWE + overlapping control_flow → MERGE (keep higher confidence)
    2. Same function + different CWE → KEEP BOTH
    3. Different functions + similar pattern → KEEP BOTH + cross-reference note
    4. Same trigger_condition with >= 80% text similarity → MERGE
    """

    def deduplicate(self, sps: List[FirmwareSP]) -> List[FirmwareSP]:
        """
        Deduplicate a list of SPs. Returns deduplicated list.
        Merged SPs have their merged_from field populated.
        """

    def _control_flow_overlap(self, cf1: str, cf2: str) -> float:
        """Compute control flow text overlap ratio (0.0-1.0)."""

    def _trigger_similarity(self, tc1: str, tc2: str) -> float:
        """Compute trigger condition text similarity using word overlap."""
```

- [ ] **Step 1: Write tests — same function + same CWE merge**

```python
def test_merge_same_function_same_cwe():
    dedupper = SPDedupper()
    sp1 = make_sp(function_name="httpd_handler", cwe="CWE-121",
                  control_flow="recv → strcpy", confidence=0.8)
    sp2 = make_sp(function_name="httpd_handler", cwe="CWE-121",
                  control_flow="recv → strcpy → overflow", confidence=0.6)
    result = dedupper.deduplicate([sp1, sp2])
    assert len(result) == 1
    assert result[0].confidence == 0.8  # keep higher
```

- [ ] **Step 2: Write tests — same function different CWE keep both**

```python
def test_keep_same_function_different_cwe():
    dedupper = SPDedupper()
    sp1 = make_sp(function_name="httpd_handler", cwe="CWE-121")
    sp2 = make_sp(function_name="httpd_handler", cwe="CWE-78")
    result = dedupper.deduplicate([sp1, sp2])
    assert len(result) == 2
```

- [ ] **Step 3: Write tests — different functions keep both**

- [ ] **Step 4: Write tests — similar trigger condition merge**

- [ ] **Step 5: Write tests — empty list, single SP, all unique**

- [ ] **Step 6: Implement sp_dedup.py**

- [ ] **Step 7: Run tests**

```bash
pytest tests/test_sp_dedup.py -v
```

- [ ] **Step 8: Commit**

```bash
git add fuzzingbrain/agents/firmware/sp_dedup.py tests/test_sp_dedup.py
git commit -m "feat(phase3): implement pure-algorithm SP deduplication"
```

---

### Task 7: Phase3Pipeline (`pipeline.py`)

**Files:**
- Create: `fuzzingbrain/agents/firmware/pipeline.py`
- Create: `tests/test_phase3_pipeline.py`

```python
class Phase3Pipeline:
    """
    Orchestrates the full Phase 3 cross-examination pipeline.

    scope: "all" — analyze all directions
           "high_priority" — only directions with priority >= 4
    """

    def __init__(self, llm_client=None,
                 scope: str = "all",
                 temperature: float = 0.3,
                 max_tokens: int = 8000):
        # Creates 3 AnalystAgents (A, B, C)
        # Creates 3 CrossReviewers (A, B, C)
        # Creates 1 SPVerifier
        # Creates 1 SPDedupper

    def run(self, directions: DirectionResult,
            functions: List[FunctionInfo],
            attack_surfaces: List[AttackSurface]) -> Phase3Result:
        """
        Full pipeline:
        1. Filter directions by scope
        2. For each direction (sorted by priority desc):
           a. Run 3 analysts in parallel (concurrent.futures.ThreadPoolExecutor)
           b. Collect all SPs, filter confidence >= 0.3
           c. Cross-review: each reviewer reviews others' SPs (confidence > 0.6)
           d. Accumulate
        3. SPVerifier.verify(all_sps, all_reviews, function_contexts)
        4. SPDedupper.deduplicate(verified_sps)
        5. Return Phase3Result
        """

    def _filter_directions(self, directions: DirectionResult) -> List[Direction]:
        """Filter by scope."""

    def _run_analysts_parallel(self, functions, direction, surfaces
                               ) -> Dict[str, List[FirmwareSP]]:
        """Run 3 analysts in parallel, return {analyst_type: [SPs]}."""

    def _run_cross_reviews(self, sps_by_analyst, function_contexts
                           ) -> List[CrossReviewVerdict]:
        """Each reviewer reviews the other two's high-confidence SPs."""

    # File I/O (matching Phase 2 pattern)
    def save(self, result: Phase3Result, path: Union[str, Path]) -> None
    def load(self, path: Union[str, Path]) -> Phase3Result
```

- [ ] **Step 1: Write test — pipeline with all mocked LLMs**

```python
def test_pipeline_integration_all_mocked():
    """Full pipeline run with all LLM calls mocked."""
    from unittest.mock import MagicMock, patch

    # Create mock functions
    functions = [
        FunctionInfo(name="httpd_handler", address=0x1000,
                     pseudo_code="void httpd_handler() { char buf[256]; strcpy(buf, input); }",
                     callees=["strcpy"], strings_used=["GET"], dangerous_funcs=["strcpy"],
                     has_unsafe_calls=True),
        FunctionInfo(name="cgi_login", address=0x2000,
                     pseudo_code="void cgi_login() { system(cmd); }",
                     callees=["system"], strings_used=["admin"], dangerous_funcs=["system"],
                     has_unsafe_calls=True),
    ]

    # Mock directions
    from fuzzingbrain.attack_surface.models import (
        Direction, DirectionResult, AnalysisOrder
    )
    direction = Direction(
        name="HTTP Processing", description="HTTP request handling",
        category="http_processing", entry_functions=["httpd_handler"],
        core_functions=["httpd_handler", "cgi_login"],
        big_pool=["httpd_handler", "cgi_login"], priority=5
    )
    directions = DirectionResult(
        directions=[direction],
        analysis_order=AnalysisOrder(recommended_sequence=["HTTP Processing"])
    )

    # Mock LLM responses for analysts
    analyst_response = MagicMock()
    analyst_response.content = json.dumps({
        "analyst_type": "memory_corruption",
        "findings": [{
            "cwe": "CWE-121", "title": "Test SP",
            "description": "test", "vulnerable_function": "httpd_handler",
            "confidence": 0.85, "severity": "critical",
            "exploitability_initial": {
                "attack_vector": "network", "difficulty": "trivial",
                "reliability": "reliable", "impact": "RCE"
            }
        }]
    })

    review_response = MagicMock()
    review_response.content = json.dumps([{
        "sp_id": "mc-httpd_handler-CWE-121-0001",
        "verdict": "confirmed",
        "confidence_adjustment": "+0.1",
        "refutation_reason": "",
        "missed_context": ""
    }])

    verifier_response = MagicMock()
    verifier_response.content = json.dumps({
        "verified_sps": [{
            "sp_id": "mc-httpd_handler-CWE-121-0001",
            "cwe": "CWE-121", "title": "Test SP",
            "description": "test", "function_name": "httpd_handler",
            "confidence": 0.85, "severity": "critical",
            "priority": "P0", "verification_priority": "immediate",
            "analyst_consensus": {
                "analyst_a": "confirmed", "analyst_b": "confirmed",
                "analyst_c": "confirmed"
            },
            "exploitability": {
                "attack_vector": "network", "difficulty": "trivial",
                "reliability": "reliable", "impact": "RCE"
            }
        }],
        "statistics": {
            "total_raw_sps": 3, "after_dedup": 1,
            "after_verification": 1, "discarded_as_false_positive": 2,
            "false_positive_rate_estimate": "66%",
            "high_confidence_sps": 1, "needs_dynamic_verification": True
        }
    })

    mock_client = MagicMock()
    mock_client.call.side_effect = [
        analyst_response, analyst_response, analyst_response,  # 3 analysts × 2 functions
        analyst_response, analyst_response, analyst_response,
        review_response, review_response, review_response,      # 3 reviewers
        verifier_response,                                      # 1 verifier
    ]

    pipeline = Phase3Pipeline(llm_client=mock_client, scope="high_priority")
    result = pipeline.run(directions, functions, [])

    assert result.statistics.total_raw_sps == 3
    assert len(result.verified_sps) == 1
    assert result.verified_sps[0].priority == "P0"
```

- [ ] **Step 2: Write test — scope filtering**

```python
def test_high_priority_scope_filters_low_priority():
    from fuzzingbrain.attack_surface.models import Direction, DirectionResult, AnalysisOrder
    high_dir = Direction(name="High", description="h", category="network_service",
                         entry_functions=["f1"], core_functions=["f1"],
                         big_pool=["f1"], priority=5)
    low_dir = Direction(name="Low", description="l", category="file_handling",
                        entry_functions=["f2"], core_functions=["f2"],
                        big_pool=["f2"], priority=2)
    directions = DirectionResult(
        directions=[high_dir, low_dir],
        analysis_order=AnalysisOrder(recommended_sequence=["High", "Low"])
    )

    pipeline = Phase3Pipeline(scope="high_priority")
    filtered = pipeline._filter_directions(directions)
    assert len(filtered) == 1
    assert filtered[0].name == "High"
```

- [ ] **Step 3: Write test — save/load roundtrip**

- [ ] **Step 4: Implement pipeline.py**

- [ ] **Step 5: Run all Phase 3 tests**

```bash
pytest tests/test_phase3_pipeline.py tests/test_sp_models.py \
       tests/test_sp_analysts.py tests/test_cross_reviewer.py \
       tests/test_sp_verifier.py tests/test_sp_dedup.py -v
```

- [ ] **Step 6: Commit**

```bash
git add fuzzingbrain/agents/firmware/pipeline.py tests/test_phase3_pipeline.py
git commit -m "feat(phase3): implement Phase3Pipeline orchestration with configurable scope"
```

---

### Task 8: Update `__init__.py` Exports + Final Verification

**Files:**
- Modify: `fuzzingbrain/agents/firmware/__init__.py`
- No new tests needed (verification step only)

- [ ] **Step 1: Update firmware/__init__.py**

```python
"""
Firmware-specific agents for the vulnerability discovery pipeline.

Phase 2: AttackSurfaceIdentifier, DirectionPlanner
Phase 3: AnalystAgent, CrossReviewer, SPVerifier, SPDedupper, Phase3Pipeline
Phase 4: PoCAgent
"""

from .sp_analysts import AnalystAgent
from .cross_reviewer import CrossReviewer
from .sp_verifier import SPVerifier
from .sp_dedup import SPDedupper
from .pipeline import Phase3Pipeline
from .sp_models import (
    FirmwareSP,
    CrossReviewVerdict,
    CrossReviewResult,
    AnalystConsensus,
    VerifiedSP,
    Phase3Statistics,
    Phase3Result,
    ExploitabilityAssessment,
)

__all__ = [
    # Phase 2 (existing)
    # Phase 3 agents
    "AnalystAgent",
    "CrossReviewer",
    "SPVerifier",
    "SPDedupper",
    "Phase3Pipeline",
    # Phase 3 models
    "FirmwareSP",
    "CrossReviewVerdict",
    "CrossReviewResult",
    "AnalystConsensus",
    "VerifiedSP",
    "Phase3Statistics",
    "Phase3Result",
    "ExploitabilityAssessment",
]
```

- [ ] **Step 2: Verify all imports work**

```bash
python -c "
from fuzzingbrain.agents.firmware import (
    AnalystAgent, CrossReviewer, SPVerifier, SPDedupper, Phase3Pipeline,
    FirmwareSP, CrossReviewVerdict, CrossReviewResult, AnalystConsensus,
    VerifiedSP, Phase3Statistics, Phase3Result, ExploitabilityAssessment,
)
print('All Phase 3 imports successful')

# Quick smoke test: create instances
a = AnalystAgent(analyst_type='memory_corruption')
b = AnalystAgent(analyst_type='logic_flaw')
c = AnalystAgent(analyst_type='injection')
print(f'AnalystAgent types: A={a.analyst_type}, B={b.analyst_type}, C={c.analyst_type}')

r = CrossReviewer(reviewer_type='memory_corruption')
print(f'CrossReviewer type: {r.reviewer_type}')

v = SPVerifier()
print(f'SPVerifier model: {v.model}')

d = SPDedupper()
print(f'SPDedupper created')

print('Smoke test PASSED')
"
```

- [ ] **Step 3: Run full test suite to check for regressions**

```bash
pytest tests/ -v --ignore=tests/test_analyzer_socket_isolation.py 2>&1 | tail -30
```

Expected: All tests pass, no regressions from Phase 1/2.

- [ ] **Step 4: Commit**

```bash
git add fuzzingbrain/agents/firmware/__init__.py
git commit -m "feat(phase3): export Phase 3 agents and models from firmware package"
```

---

## Summary

| Task | Files Created | Tests | Effort |
|------|-------------|-------|--------|
| 1. Data Models | `sp_models.py` | 18 | Medium |
| 2. Prompt Templates | 5 `.md` files + modify `__init__.py` | 0 (manual verify) | Small |
| 3. AnalystAgent | `sp_analysts.py` | 12 | Large |
| 4. CrossReviewer | `cross_reviewer.py` | 6 | Medium |
| 5. SPVerifier | `sp_verifier.py` | 8 | Medium |
| 6. SPDedupper | `sp_dedup.py` | 8 | Small |
| 7. Phase3Pipeline | `pipeline.py` | 5 | Large |
| 8. Exports + Verify | modify `__init__.py` | 0 | Small |

**Total: ~8 commits, ~57 tests, 13 new files, 2 modified files**
