"""
Firmware Analyzer — LLM Agent with ReAct Loop for Autonomous Tool Calling

Lets an LLM Agent autonomously analyze firmware binaries by iteratively:
  Thought → Action (call tool) → Observation (tool result) → ... → Answer

The agent receives the full ToolRegistry schema (OpenAI Function Calling format),
allowing it to decide WHICH tool to call, with WHAT parameters, based on the
current analysis state.

Architecture:
    FirmwareAnalyzer
        ├── analyze_firmware(firmware_path)  ← main entry point
        │   ├── Phase 1: Extract (binwalk)
        │   ├── Phase 2: Identify key binaries
        │   ├── Phase 3: Per-binary deep analysis (ReAct)
        │   └── Phase 4: Aggregate report
        │
        └── _react_loop(task, context, max_iterations)
            ├── _build_tool_prompt()
            ├── LLM call → parse Thought / Action / Answer
            ├── Tool execution (serial or parallel)
            └── Memory management (summarize old context)

Usage:
    from fuzzingbrain.tools.firmware_mcp import get_registry
    from fuzzingbrain.tools.firmware_mcp.firmware_analyzer import FirmwareAnalyzer
    from fuzzingbrain.llms import LLMClient

    registry = get_registry()
    llm = LLMClient()
    analyzer = FirmwareAnalyzer(llm, registry)
    report = await analyzer.analyze_firmware("/path/to/firmware.bin")
"""

import asyncio
import json
import re
import textwrap
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from loguru import logger

from .registry import ToolRegistry


# =============================================================================
# Constants
# =============================================================================

DEFAULT_MAX_ITERATIONS = 10
DEFAULT_PER_ROUND_TIMEOUT = 60  # seconds
DEFAULT_TOTAL_TIMEOUT = 1800    # 30 minutes
MAX_OBSERVATION_CHARS = 2000    # Truncate tool outputs
MAX_CONTEXT_TOKENS_ESTIMATE = 80_000  # ~80K tokens before summarization
MAX_MEMORY_ENTRIES_BEFORE_SUMMARY = 20
STALE_ROUNDS_BEFORE_EARLY_STOP = 3


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class MemoryEntry:
    """A single entry in the ReAct memory."""

    role: str  # "thought", "action", "observation", "answer", "system"
    content: str
    timestamp: float = field(default_factory=time.time)
    round_number: int = 0

    def to_message(self) -> dict:
        """Convert to LLM-compatible message dict."""
        role_map = {
            "thought": "assistant",
            "action": "assistant",
            "observation": "user",
            "answer": "assistant",
            "system": "system",
        }
        return {
            "role": role_map.get(self.role, "user"),
            "content": self.content,
        }


@dataclass
class AnalysisReport:
    """Complete firmware analysis report."""

    firmware_path: str
    analysis_date: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    total_rounds: int = 0
    total_tool_calls: int = 0
    total_time_seconds: float = 0.0

    # Per-phase results
    phase1_binaries: List[dict] = field(default_factory=list)
    phase2_key_binaries: List[str] = field(default_factory=list)
    phase3_findings: List[dict] = field(default_factory=list)

    # Final synthesis
    vulnerabilities: List[dict] = field(default_factory=list)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    # Errors encountered
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "firmware_path": self.firmware_path,
            "analysis_date": self.analysis_date,
            "total_rounds": self.total_rounds,
            "total_tool_calls": self.total_tool_calls,
            "total_time_seconds": round(self.total_time_seconds, 1),
            "phase1_binaries": self.phase1_binaries,
            "phase2_key_binaries": self.phase2_key_binaries,
            "phase3_findings": self.phase3_findings,
            "vulnerabilities": self.vulnerabilities,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "errors": self.errors,
        }


# =============================================================================
# FirmwareAnalyzer
# =============================================================================

class FirmwareAnalyzer:
    """LLM Agent that autonomously analyzes firmware using registered tools.

    Uses a ReAct (Reasoning + Acting) loop to iteratively:
    1. Think about what to do next
    2. Call a tool with appropriate parameters
    3. Observe the result
    4. Decide: continue or produce final answer

    The agent reads tool schemas from ToolRegistry (OpenAI Function Calling
    format) and includes them in the LLM prompt.

    Usage:
        registry = get_registry()
        llm = LLMClient()
        analyzer = FirmwareAnalyzer(llm, registry)
        report = await analyzer.analyze_firmware("firmware/DVRF_v03.bin")
    """

    def __init__(
        self,
        llm_client,
        tool_registry: ToolRegistry,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        per_round_timeout: float = DEFAULT_PER_ROUND_TIMEOUT,
        total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
        verbose: bool = True,
    ):
        """
        Args:
            llm_client: LLMClient instance for LLM calls.
            tool_registry: ToolRegistry with registered firmware tools.
            max_iterations: Max ReAct rounds per task.
            per_round_timeout: Max seconds per LLM call + tool execution.
            total_timeout: Max seconds for the entire analysis.
            verbose: Print detailed ReAct round logs.
        """
        self.llm = llm_client
        self.tools = tool_registry
        self.max_iterations = max_iterations
        self.per_round_timeout = per_round_timeout
        self.total_timeout = total_timeout
        self.verbose = verbose

        # Working memory (conversation history)
        self.memory: List[MemoryEntry] = []

        # Statistics
        self._total_tool_calls = 0
        self._stale_rounds = 0
        self._start_time = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_firmware(
        self, firmware_path: str
    ) -> AnalysisReport:
        """Main analysis pipeline: extract → identify → analyze → report.

        This is the primary entry point. It orchestrates the full
        firmware vulnerability discovery process using the ReAct agent.

        Args:
            firmware_path: Path to the firmware .bin file.

        Returns:
            AnalysisReport with findings and recommendations.
        """
        self._start_time = time.time()
        self.memory = []
        self._total_tool_calls = 0
        self._stale_rounds = 0

        report = AnalysisReport(firmware_path=firmware_path)
        fw_path = Path(firmware_path)
        fw_name = fw_path.stem

        logger.info(
            f"FirmwareAnalyzer: starting analysis of {fw_path.name}"
        )

        try:
            # Phase 1: Extract and identify binaries
            logger.info("Phase 1: Extracting firmware + identifying binaries...")
            binaries_result = await self._react_loop(
                task=(
                    f"Extract the firmware at '{firmware_path}' and identify "
                    f"all ELF binaries. Use find_string_xrefs to discover "
                    f"interesting strings across the main daemons. "
                    f"List the top 5 most important binaries to analyze."
                ),
                context={"firmware_path": firmware_path},
                max_iterations=5,
            )
            report.phase1_binaries = binaries_result.get("data", {}).get(
                "binaries", []
            )

            # Phase 2: Identify key attack surfaces per binary
            logger.info("Phase 2: Attack surface analysis...")
            key_binaries = self._extract_key_binaries(binaries_result)
            report.phase2_key_binaries = key_binaries

            # Phase 3: Deep analysis of each key binary
            logger.info(
                f"Phase 3: Deep analysis of {len(key_binaries)} binaries..."
            )
            for binary_name in key_binaries:
                logger.info(f"  Analyzing: {binary_name}")
                finding = await self._react_loop(
                    task=(
                        f"Deep-analyze the binary '{binary_name}' from "
                        f"firmware '{firmware_path}'. Do the following:\n"
                        f"1. Decompile the main/entry function\n"
                        f"2. Trace callers and callees\n"
                        f"3. Check for dangerous function calls "
                        f"(strcpy, system, popen, sprintf, etc.)\n"
                        f"4. Identify suspicious points (potential vulns)\n"
                        f"5. If possible, try dynamic QEMU verification\n"
                        f"Report any confirmed or high-confidence "
                        f"vulnerabilities."
                    ),
                    context={
                        "firmware_path": firmware_path,
                        "binary_name": binary_name,
                    },
                    max_iterations=8,
                )
                if finding.get("vulnerabilities"):
                    report.phase3_findings.append(
                        {
                            "binary": binary_name,
                            "findings": finding["vulnerabilities"],
                        }
                    )

            # Phase 4: Synthesize final report
            logger.info("Phase 4: Synthesizing final report...")
            synthesis = await self._react_loop(
                task=(
                    f"Synthesize a final vulnerability analysis report "
                    f"for firmware: {fw_name}\n"
                    f"Key binaries analyzed: {', '.join(key_binaries)}\n"
                    f"Findings so far: {json.dumps(report.phase3_findings, indent=2)[:3000]}\n"
                    f"Provide:\n"
                    f"1. Executive summary (2-3 sentences)\n"
                    f"2. List of confirmed/high-confidence vulnerabilities "
                    f"with CWE IDs and CVSS estimates\n"
                    f"3. Remediation recommendations (prioritized)\n"
                    f"4. Any limitations or areas needing further analysis"
                ),
                context={
                    "findings": report.phase3_findings,
                    "firmware_name": fw_name,
                },
                max_iterations=3,
            )

            report.vulnerabilities = synthesis.get("vulnerabilities", [])
            report.summary = synthesis.get("summary", "")
            report.recommendations = synthesis.get("recommendations", [])

        except asyncio.TimeoutError:
            report.errors.append(
                f"Analysis timed out after {self.total_timeout}s"
            )
            logger.error(report.errors[-1])
        except Exception as e:
            report.errors.append(f"Analysis failed: {e}")
            logger.error(
                f"FirmwareAnalyzer: {e}\n{traceback.format_exc()}"
            )

        report.total_time_seconds = time.time() - self._start_time
        report.total_tool_calls = self._total_tool_calls
        report.total_rounds = len(
            [m for m in self.memory if m.role == "action"]
        )

        logger.info(
            f"FirmwareAnalyzer: complete — {report.total_rounds} rounds, "
            f"{report.total_tool_calls} tool calls, "
            f"{report.total_time_seconds:.1f}s"
        )
        return report

    # ------------------------------------------------------------------
    # ReAct Loop
    # ------------------------------------------------------------------

    async def _react_loop(
        self,
        task: str,
        context: dict,
        max_iterations: Optional[int] = None,
    ) -> dict:
        """Core ReAct loop: Thought → Action → Observation → ... → Answer.

        Args:
            task: Natural language description of what to accomplish.
            context: Key-value context (firmware_path, binary_name, etc.).
            max_iterations: Override default max iterations.

        Returns:
            Parsed final answer dict with LLM's conclusions.

        Raises:
            asyncio.TimeoutError: if total timeout exceeded.
        """
        max_iter = max_iterations or self.max_iterations
        stale_count = 0
        last_observation_hash = None

        # Ensure start time is set (in case _react_loop called directly)
        if self._start_time == 0.0:
            self._start_time = time.time()

        # Seed memory with system prompt
        system_prompt = self._build_system_prompt(task, context)
        self.memory.append(
            MemoryEntry(role="system", content=system_prompt, round_number=0)
        )

        for round_num in range(1, max_iter + 1):
            # Check total timeout
            elapsed = time.time() - self._start_time
            if elapsed > self.total_timeout:
                raise asyncio.TimeoutError(
                    f"Total analysis timeout ({self.total_timeout}s) exceeded"
                )

            # Build prompt from current memory
            messages = self._build_messages()

            # Call LLM
            try:
                response = await asyncio.wait_for(
                    self._call_llm_async(messages),
                    timeout=self.per_round_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"[Round {round_num}] LLM call timed out "
                    f"({self.per_round_timeout}s)"
                )
                self.memory.append(
                    MemoryEntry(
                        role="system",
                        content=(
                            f"LLM call timed out after "
                            f"{self.per_round_timeout}s. Please "
                            f"provide a shorter response or "
                            f"proceed to the answer."
                        ),
                        round_number=round_num,
                    )
                )
                continue

            # Parse LLM output
            parsed = self._parse_react_output(response.content)
            if parsed is None:
                logger.warning(
                    f"[Round {round_num}] Failed to parse LLM output: "
                    f"{response.content[:200]}"
                )
                self.memory.append(
                    MemoryEntry(
                        role="system",
                        content=(
                            "Failed to parse your response. Please use "
                            'the format: {"thought": "...", '
                            '"action": {"tool": "...", "params": {...}}} '
                            'or {"thought": "...", "answer": {...}}'
                        ),
                        round_number=round_num,
                    )
                )
                continue

            # Case 1: LLM provides final answer
            if "answer" in parsed:
                thought = parsed.get("thought", "")
                answer = parsed["answer"]

                if self.verbose:
                    logger.info(
                        f"[Round {round_num}] Thought: "
                        f"{thought[:150]}"
                    )
                    logger.info(
                        f"[Round {round_num}] ANSWER: "
                        f"{json.dumps(answer, ensure_ascii=False)[:200]}"
                    )

                self.memory.append(
                    MemoryEntry(
                        role="answer",
                        content=json.dumps(answer, ensure_ascii=False),
                        round_number=round_num,
                    )
                )
                return answer

            # Case 2: LLM wants to call a tool
            if "action" in parsed:
                thought = parsed.get("thought", "")
                action = parsed["action"]
                tool_name = action.get("tool", "")
                params = action.get("params", {})

                if self.verbose:
                    logger.info(
                        f"[Round {round_num}] Thought: "
                        f"{thought[:150]}"
                    )
                    logger.info(
                        f"[Round {round_num}] Action: "
                        f"{tool_name}({json.dumps(params, default=str)[:150]})"
                    )

                # Validate tool exists
                if not self.tools.get(tool_name):
                    obs = (
                        f"Tool '{tool_name}' not found. Available: "
                        f"{sorted(self.tools.list_by_category())}"
                    )
                    if self.verbose:
                        logger.warning(
                            f"[Round {round_num}] Unknown tool: "
                            f"{tool_name}"
                        )
                else:
                    # Execute tool
                    try:
                        result = await asyncio.wait_for(
                            self._execute_tool_async(
                                tool_name, params
                            ),
                            timeout=30,
                        )
                        obs = json.dumps(
                            result, default=str, ensure_ascii=False
                        )
                    except asyncio.TimeoutError:
                        obs = (
                            f"Tool '{tool_name}' timed out after 30s."
                        )
                    except Exception as e:
                        obs = (
                            f"Tool '{tool_name}' failed: {type(e).__name__}: {e}"
                        )

                # Truncate long observations
                obs_truncated = (
                    obs[:MAX_OBSERVATION_CHARS]
                    + (
                        f"\n... (truncated, {len(obs)} chars total)"
                        if len(obs) > MAX_OBSERVATION_CHARS
                        else ""
                    )
                )

                if self.verbose:
                    logger.info(
                        f"[Round {round_num}] Observation: "
                        f"{obs_truncated[:200]}"
                    )

                # Record in memory
                self.memory.append(
                    MemoryEntry(
                        role="thought",
                        content=thought,
                        round_number=round_num,
                    )
                )
                self.memory.append(
                    MemoryEntry(
                        role="action",
                        content=json.dumps(action, ensure_ascii=False),
                        round_number=round_num,
                    )
                )
                self.memory.append(
                    MemoryEntry(
                        role="observation",
                        content=obs_truncated,
                        round_number=round_num,
                    )
                )

                self._total_tool_calls += 1

                # Staleness check: if observation is identical to last,
                # the agent might be stuck in a loop
                obs_hash = hash(obs)
                if obs_hash == last_observation_hash:
                    stale_count += 1
                else:
                    stale_count = 0
                last_observation_hash = obs_hash

                if stale_count >= STALE_ROUNDS_BEFORE_EARLY_STOP:
                    logger.warning(
                        f"[Round {round_num}] Detected stale loop "
                        f"({stale_count} identical observations). "
                        f"Prompting agent to conclude."
                    )
                    self.memory.append(
                        MemoryEntry(
                            role="system",
                            content=(
                                f"You've received the same result "
                                f"{stale_count} times. The tool may "
                                f"not be providing new information. "
                                f"Please adjust your approach or "
                                f"provide your final answer."
                            ),
                            round_number=round_num,
                        )
                    )
                    stale_count = 0

                continue

            # Case 3: Neither action nor answer → malformed
            logger.warning(
                f"[Round {round_num}] LLM output missing 'action' "
                f"or 'answer': {response.content[:200]}"
            )
            self.memory.append(
                MemoryEntry(
                    role="system",
                    content=(
                        "Your response should contain either "
                        '"action" (to call a tool) or "answer" '
                        "(to provide final conclusions)."
                    ),
                    round_number=round_num,
                )
            )

        # Max iterations reached → force summary
        logger.warning(
            f"Max iterations ({max_iter}) reached. "
            f"Forcing answer synthesis."
        )
        return await self._force_answer(task)

    # ------------------------------------------------------------------
    # Prompt Building
    # ------------------------------------------------------------------

    def _build_system_prompt(
        self, task: str, context: dict
    ) -> str:
        """Build the initial system prompt with task, context, and tools.

        The prompt includes:
        1. Role description and task
        2. Available context
        3. Full tool catalog with descriptions and parameters
        4. Output format specification
        5. Rules and constraints
        """
        tool_descriptions = self._format_tools_for_prompt()
        context_str = json.dumps(context, indent=2, ensure_ascii=False)

        return textwrap.dedent(f"""\
        You are a firmware vulnerability analysis expert. Your job is to
        systematically analyze firmware binaries to find security
        vulnerabilities using the tools provided.

        ## Task
        {task}

        ## Current Context
        ```json
        {context_str}
        ```

        ## Available Tools
        You have access to the following tools. Each tool is described with
        its name, description, and parameter types.

        {tool_descriptions}

        ## Output Format
        You MUST respond with valid JSON. There are two response types:

        **To call a tool:**
        ```json
        {{
            "thought": "I need to decompile function X to see if it calls strcpy with user input...",
            "action": {{
                "tool": "decompile_function",
                "params": {{
                    "binary_path": "/path/to/binary",
                    "func_addr": 4198400
                }}
            }}
        }}
        ```

        **To provide your final answer:**
        ```json
        {{
            "thought": "I have gathered enough information. Here is my analysis...",
            "answer": {{
                "summary": "...",
                "vulnerabilities": [...],
                "recommendations": [...]
            }}
        }}
        ```

        ## Rules
        1. Think before acting — explain your reasoning in "thought"
        2. Always use EXACT tool names and parameter names from the list
        3. If a tool fails, analyze the error and try a different approach
        4. When you find evidence of a vulnerability, verify it with a
           second tool before reporting
        5. After 8-10 rounds, synthesize your findings and provide an answer
        6. Be specific: mention function names, addresses, CWE IDs
        7. Only report vulnerabilities you have evidence for
        """)

    def _format_tools_for_prompt(self) -> str:
        """Format the tool catalog as human-readable text for the prompt.

        Uses the OpenAI Function Calling schema from ToolRegistry
        and converts it to a compact text format for the LLM.
        """
        schemas = self.tools.get_function_schemas()
        lines = []

        for schema in schemas:
            func = schema["function"]
            name = func["name"]
            desc = func["description"]
            params = func["parameters"]["properties"]
            required = func["parameters"].get("required", [])

            lines.append(f"### {name}")
            lines.append(f"    Description: {desc}")
            lines.append(f"    Parameters:")
            for pname, pschema in params.items():
                req_mark = " [REQUIRED]" if pname in required else ""
                ptype = pschema.get("type", "string")
                pdesc = pschema.get("description", "")
                default = pschema.get("default")
                extra = ""
                if "enum" in pschema:
                    extra = f" (choices: {pschema['enum']})"
                if default is not None:
                    extra += f" (default: {default})"
                lines.append(
                    f"      - {pname}: {ptype}{req_mark} — {pdesc}{extra}"
                )
            lines.append("")

        return "\n".join(lines)

    def _build_messages(self) -> List[dict]:
        """Build the message list for the current LLM call.

        Includes the system prompt and recent memory entries.
        Automatically summarizes older entries when context grows
        too large.
        """
        self._manage_memory()

        messages = []
        for entry in self.memory:
            messages.append(entry.to_message())

        return messages

    def _manage_memory(self):
        """Manage memory size to prevent context window overflow.

        When memory grows too large, summarizes older entries into
        a condensed form while preserving the most recent context.
        """
        if len(self.memory) <= MAX_MEMORY_ENTRIES_BEFORE_SUMMARY:
            return

        # Keep: system prompt + last 10 entries
        keep_last = 10
        to_summarize = self.memory[1:-keep_last]  # Skip system prompt
        to_keep = [self.memory[0]] + self.memory[-keep_last:]

        if len(to_summarize) <= 5:
            return  # Not enough to warrant summarization

        # Build summary of old observations
        summary_parts = ["[Prior analysis summary]"]
        for entry in to_summarize:
            if entry.role == "action":
                summary_parts.append(
                    f"Round {entry.round_number}: Called tool → "
                    f"{entry.content[:100]}"
                )
            elif entry.role == "observation":
                # Extract key information
                try:
                    data = json.loads(entry.content)
                    if data.get("success"):
                        keys = [
                            k for k in data
                            if k not in ("success",)
                        ]
                        summary_parts.append(
                            f"  Result: {', '.join(keys[:5])}"
                        )
                    else:
                        summary_parts.append(
                            f"  Error: {data.get('error', '')[:80]}"
                        )
                except json.JSONDecodeError:
                    summary_parts.append(
                        f"  Result: {entry.content[:80]}"
                    )

        summary = "\n".join(summary_parts)
        logger.debug(
            f"Memory summarized: {len(to_summarize)} entries → "
            f"{len(summary)} chars"
        )

        # Replace memory with summary + recent entries
        self.memory = (
            [self.memory[0]]  # System prompt
            + [
                MemoryEntry(
                    role="system",
                    content=summary,
                    round_number=0,
                )
            ]
            + to_keep[-keep_last:]
        )

    # ------------------------------------------------------------------
    # JSON Parsing
    # ------------------------------------------------------------------

    def _parse_react_output(self, content: str) -> Optional[dict]:
        """Parse the LLM's JSON response.

        Handles various LLM output quirks: markdown code fences,
        extra text before/after JSON, truncated output.

        Returns:
            Parsed dict or None if unparseable.
        """
        json_str = content.strip()

        # Extract from markdown code fence
        fence_match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?```",
            json_str,
            re.DOTALL,
        )
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Find the outermost JSON object
        if not json_str.startswith("{"):
            brace_start = json_str.find("{")
            if brace_start >= 0:
                # Find matching closing brace
                depth = 0
                end = -1
                for i, ch in enumerate(
                    json_str[brace_start:], brace_start
                ):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                if end >= 0:
                    json_str = json_str[brace_start : end + 1]

        # Try to parse
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Repair attempt: close unclosed braces
        try:
            depth = json_str.count("{") - json_str.count("}")
            if depth > 0:
                json_str += "}" * depth
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Last resort: try to extract any JSON-like structure
        try:
            # Find "thought" or "action" or "answer" key
            for key in ["thought", "action", "answer"]:
                match = re.search(
                    rf'"{key}"\s*:\s*(".*?"|{{.*?}}|\[.*?\])',
                    content,
                    re.DOTALL,
                )
                if match:
                    partial = "{" + match.group(0) + "}"
                    return json.loads(partial)
        except json.JSONDecodeError:
            pass

        return None

    # ------------------------------------------------------------------
    # Async Helpers
    # ------------------------------------------------------------------

    async def _call_llm_async(self, messages: List[dict]) -> Any:
        """Call the LLM asynchronously.

        Uses a thread pool since LLMClient.call() is synchronous.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.llm.call(
                messages=messages,
                temperature=0.3,
                max_tokens=8000,
            ),
        )

    async def _execute_tool_async(
        self, tool_name: str, params: dict
    ) -> dict:
        """Execute a tool asynchronously.

        Uses a thread pool since tool execution is synchronous
        (subprocess calls).
        """
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.tools.execute_tool(tool_name, **params),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_key_binaries(self, phase1_result: dict) -> List[str]:
        """Extract the list of key binaries from Phase 1 results."""
        data = phase1_result.get("data", phase1_result)
        binaries = data.get("binaries", [])
        if not binaries:
            # Try to get from answer field
            binaries = data.get(
                "key_binaries",
                data.get("important_binaries", []),
            )
        if isinstance(binaries, list) and binaries:
            if isinstance(binaries[0], dict):
                return [
                    b.get("path", b.get("name", str(b)))
                    for b in binaries[:5]
                ]
            return binaries[:5]
        return ["/bin/httpd"]  # Sensible default

    async def _force_answer(self, task: str) -> dict:
        """Force the LLM to produce a final answer.

        Called when max iterations are exhausted.
        """
        prompt = textwrap.dedent(f"""\
        You have reached the maximum number of analysis rounds.
        Based on all the observations collected, please provide your
        final analysis report now.

        Original task: {task}

        Include:
        - summary: 2-3 sentence executive summary
        - vulnerabilities: list of findings with CWE, confidence,
          function names, and descriptions
        - recommendations: prioritized remediation steps
        - limitations: what couldn't be verified and why
        """)

        messages = [
            {"role": "system", "content": prompt},
            {
                "role": "user",
                "content": "Provide your final analysis report as JSON.",
            },
        ]

        try:
            response = self.llm.call(
                messages=messages, temperature=0.3, max_tokens=8000
            )
            parsed = self._parse_react_output(response.content)
            if parsed and "answer" in parsed:
                return parsed["answer"]
            if parsed:
                return parsed
        except Exception as e:
            logger.error(f"Force answer failed: {e}")

        return {
            "summary": "Analysis incomplete — max iterations reached.",
            "vulnerabilities": [],
            "recommendations": [
                "Re-run analysis with more iterations"
            ],
            "limitations": [
                f"Analysis truncated after exhausting iteration budget"
            ],
        }


# =============================================================================
# Convenience factory
# =============================================================================

def create_firmware_analyzer(
    llm_client=None,
    registry: Optional[ToolRegistry] = None,
    **kwargs,
) -> FirmwareAnalyzer:
    """Create a FirmwareAnalyzer with default dependencies.

    Args:
        llm_client: LLMClient instance (created if None).
        registry: ToolRegistry (fetched from global if None).
        **kwargs: Passed to FirmwareAnalyzer.

    Returns:
        Configured FirmwareAnalyzer.
    """
    if llm_client is None:
        from fuzzingbrain.llms import LLMClient
        llm_client = LLMClient()

    if registry is None:
        from .registry import get_registry
        registry = get_registry()

    return FirmwareAnalyzer(
        llm_client=llm_client,
        tool_registry=registry,
        **kwargs,
    )
