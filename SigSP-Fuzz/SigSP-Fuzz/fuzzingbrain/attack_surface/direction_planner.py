"""
DirectionPlanner Agent

Reads attack_surface.json + callgraph.json, calls DeepSeek-V4-Pro to
divide attack surfaces into 3-8 prioritized analysis directions.
"""

import json
import re
from pathlib import Path


def _repair_truncated_json(json_str: str) -> dict:
    """Attempt to repair truncated JSON by closing unclosed strings/braces."""
    try:
        # Remove trailing incomplete content after last valid closing brace
        # Count open vs close braces
        depth = 0
        for i, ch in enumerate(json_str):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        # Close remaining open braces
        if depth > 0:
            json_str = json_str + "}" * depth
        # Try parsing repaired JSON
        return json.loads(json_str)
    except (json.JSONDecodeError, Exception):
        pass

    # Second attempt: truncate to last complete object and close
    try:
        # Find the last successful "}," or "]" pattern
        last_good = max(
            json_str.rfind('}",'),
            json_str.rfind('"],'),
            json_str.rfind('"}'),
            json_str.rfind('"]'),
        )
        if last_good > 0:
            truncated = json_str[:last_good + 2]  # include }"
            # Close remaining structure
            depth = truncated.count("{") - truncated.count("}")
            truncated = truncated + "}" * depth
            return json.loads(truncated)
    except (json.JSONDecodeError, Exception):
        pass

    return None
from typing import Dict, List, Optional, Set, Union

from loguru import logger

from ..llms import LLMClient, CLAUDE_SONNET_4_6, ModelInfo
from ..static.models import FunctionInfo, CallGraph
from ..agents.firmware.prompts import get_direction_prompt
from .models import (
    AttackSurface,
    AttackSurfaceResult,
    DirectionResult,
)


# ── Prompt-building helpers ───────────────────────────────────────────

def build_attack_surfaces_context(surfaces: List[AttackSurface]) -> str:
    """Build attack surface context for the Direction Planner prompt."""
    if not surfaces:
        return "No attack surfaces provided."

    lines = []
    lines.append(f"Total attack surfaces: {len(surfaces)}")
    lines.append("")

    for i, a in enumerate(surfaces, 1):
        lines.append(f"### {i}. {a.name}")
        lines.append(f"- Category: {a.category}")
        if a.description:
            lines.append(f"- Description: {a.description}")
        else:
            lines.append(f"- Description: {a.name}")
        lines.append(f"- Protocol: {a.protocol}")
        if a.port_info:
            lines.append(
                f"- Port: {a.port_info.port}/{a.port_info.protocol_type} "
                f"({a.port_info.certainty})"
            )
        lines.append(f"- Entry Functions: {', '.join(a.entry_functions)}")
        if a.supporting_functions:
            lines.append(f"- Supporting Functions: {', '.join(a.supporting_functions)}")
        if a.strings_evidence:
            evidence = a.strings_evidence[:8]
            if len(a.strings_evidence) > 8:
                evidence.append(f"... (+{len(a.strings_evidence) - 8} more)")
            lines.append(f"- String Evidence: {', '.join(repr(e) for e in evidence)}")
        if a.risks:
            lines.append(f"- Identified Risks: {', '.join(a.risks)}")
        lines.append("")

    return "\n".join(lines)


def build_callgraph_context(callgraph: Optional[CallGraph]) -> str:
    """Build call graph context for direction planning."""
    if not callgraph or not callgraph.nodes:
        return "No call graph data available."

    lines = []
    lines.append(f"Call graph: {callgraph.node_count} functions")
    lines.append("")

    entry_keywords = [
        "http", "cgi", "init", "main", "parse", "handler", "auth", "login",
        "upload", "exec", "cmd", "telnet", "ssh", "upnp", "dns", "ftp",
    ]

    interesting = {}
    for name, node in callgraph.nodes.items():
        is_interesting = any(kw in name.lower() for kw in entry_keywords)
        has_interesting_callee = any(
            any(kw in c.lower() for kw in entry_keywords)
            for c in node.callees
        )
        if is_interesting or has_interesting_callee:
            interesting[name] = node

    lines.append("### Key Functions and Their Call Relationships")
    for name, node in sorted(interesting.items()):
        callees_shown = node.callees[:10] if node.callees else []
        callers_shown = node.callers[:5] if node.callers else []
        parts = []
        if callers_shown:
            parts.append(f"called_by=[{', '.join(callers_shown)}]")
        if callees_shown:
            parts.append(f"calls=[{', '.join(callees_shown)}]")
        if parts:
            lines.append(f"- {name}: {'; '.join(parts)}")

    lines.append("")
    lines.append("### Connectivity Between Attack Surface Entry Points")
    attack_surface_funcs = {
        name for name, node in callgraph.nodes.items()
        if any(kw in name.lower() for kw in (
            "http", "cgi", "init", "parse", "auth", "login", "handler", "upload"
        ))
    }

    for name in sorted(attack_surface_funcs):
        node = callgraph.nodes[name]
        reachable_attack_funcs = [
            c for c in node.callees if c in attack_surface_funcs
        ]
        if reachable_attack_funcs:
            lines.append(f"- {name} → [{', '.join(reachable_attack_funcs)}]")

    return "\n".join(lines)


def build_function_details_context(
    functions: Optional[List[FunctionInfo]],
    entry_names: Set[str],
) -> str:
    """Build detailed function context for entry functions only."""
    if not functions:
        return "No function details available."

    relevant = [f for f in functions if f.name in entry_names]

    if not relevant:
        return "No relevant function details (entry functions not found in function list)."

    lines = []
    for f in relevant:
        lines.append(f"### {f.name} @ 0x{f.address:X}")
        if f.callees:
            lines.append(f"Callees: {', '.join(f.callees[:15])}")
            if len(f.callees) > 15:
                lines.append(f"  ... and {len(f.callees) - 15} more")
        if f.dangerous_funcs:
            lines.append(f"⚠ DANGEROUS CALLS: {', '.join(f.dangerous_funcs)}")
        if f.strings_used:
            lines.append(f"Strings: {', '.join(repr(s) for s in f.strings_used[:8])}")
        lines.append("")

    return "\n".join(lines)


# ── Main Agent ─────────────────────────────────────────────────────────

class DirectionPlanner:
    """
    Divides identified attack surfaces into prioritized analysis directions.

    Reads attack surfaces, call graph, and function details, then calls an LLM
    (default: DeepSeek-V4-Pro) to produce 3-8 directions with priority assignments.

    Usage:
        planner = DirectionPlanner()
        result = planner.plan(attack_surface_result, callgraph, functions)
        planner.save(result, "directions.json")
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        temperature: float = 0.3,
        max_tokens: int = 8000,
    ):
        """
        Args:
            llm_client: LLMClient instance (creates new one if None).
            model: Model to use (default: DEEPSEEK_V4_PRO).
            temperature: LLM temperature for structured output.
            max_tokens: Maximum output tokens.
        """
        self.llm_client = llm_client or LLMClient()
        self.model = (
            model
            or self.llm_client.config.get_agent_model("direction_planner")
            or CLAUDE_SONNET_4_6
        )
        self.temperature = temperature
        self.max_tokens = max_tokens

    def plan(
        self,
        attack_surfaces: AttackSurfaceResult,
        callgraph: Optional[CallGraph] = None,
        functions: Optional[List[FunctionInfo]] = None,
    ) -> DirectionResult:
        """
        Plan analysis directions from attack surfaces.

        Args:
            attack_surfaces: AttackSurfaceResult from AttackSurfaceIdentifier.
            callgraph: Call graph for relationship analysis (optional).
            functions: Function list for detailed context (optional).

        Returns:
            DirectionResult with 3-8 directions and analysis order.

        Raises:
            ValueError: If the LLM response cannot be parsed.
        """
        system_prompt = get_direction_prompt()
        user_content = self._build_user_message(attack_surfaces, callgraph, functions)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        # Normalize: accept both List[AttackSurface] and AttackSurfaceResult
        if hasattr(attack_surfaces, 'attack_surfaces'):
            num_surfaces = len(attack_surfaces.attack_surfaces)
        else:
            num_surfaces = len(attack_surfaces)

        logger.info(
            f"DirectionPlanner: planning directions for "
            f"{num_surfaces} attack surfaces"
        )

        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        result = self._parse_response(response.content)
        logger.info(
            f"DirectionPlanner: created {result.count} directions. "
            f"High priority: {len(result.high_priority_directions)}. "
            f"Sequence: {result.analysis_order.recommended_sequence}"
        )
        return result

    def _build_user_message(
        self,
        attack_surfaces,
        callgraph: Optional[CallGraph],
        functions: Optional[List[FunctionInfo]],
    ) -> str:
        """Build the user message with all input data.

        attack_surfaces can be either:
          - List[AttackSurface] (from FirmwarePipeline._run_phase2)
          - AttackSurfaceResult (from tests / direct API)
        """
        # Normalize: accept both List[AttackSurface] and AttackSurfaceResult
        if hasattr(attack_surfaces, 'attack_surfaces'):
            surfaces = attack_surfaces.attack_surfaces
        else:
            surfaces = attack_surfaces

        parts = []

        parts.append("# Attack Surface Analysis Input\n")

        parts.append("## Identified Attack Surfaces")
        parts.append(build_attack_surfaces_context(surfaces))
        parts.append("")

        if callgraph:
            parts.append("## Call Graph Analysis")
            parts.append(build_callgraph_context(callgraph))
            parts.append("")

        if functions:
            entry_names = set()
            for a in surfaces:
                entry_names.update(a.entry_functions)
                entry_names.update(a.supporting_functions)

            parts.append("## Entry Function Details")
            parts.append(build_function_details_context(functions, entry_names))
            parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Divide the above attack surfaces into 3-8 independent analysis directions. "
            "Output ONLY valid JSON matching the schema in the system prompt. "
            "Do not include any text outside the JSON."
        )

        return "\n".join(parts)

    def _parse_response(self, content: str) -> DirectionResult:
        """Parse LLM response into DirectionResult."""
        json_str = content.strip()

        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if fence_match:
            json_str = fence_match.group(1).strip()

        if not json_str.startswith("{"):
            brace_start = json_str.find("{")
            if brace_start >= 0:
                depth = 0
                end = -1
                for i, ch in enumerate(json_str[brace_start:], brace_start):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                if end >= 0:
                    json_str = json_str[brace_start:end + 1]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Attempt JSON repair for truncated responses
            data = _repair_truncated_json(json_str)
            if data is None:
                # Last resort: try to find and parse ANY valid top-level JSON
                # array in the response (LLM sometimes returns a bare array)
                try:
                    array_start = content.find("[")
                    if array_start >= 0:
                        depth = 0
                        end = -1
                        for i, ch in enumerate(content[array_start:], array_start):
                            if ch == "[":
                                depth += 1
                            elif ch == "]":
                                depth -= 1
                                if depth == 0:
                                    end = i
                                    break
                        if end >= 0:
                            data = json.loads(content[array_start:end + 1])
                            if isinstance(data, list):
                                logger.warning(
                                    "LLM returned a bare JSON array for DirectionResult. "
                                    "Wrapping in expected object format."
                                )
                                data = {
                                    "directions": data,
                                    "analysis_order": {
                                        "recommended_sequence": [],
                                        "rationale": "",
                                    },
                                }
                except (json.JSONDecodeError, Exception):
                    pass

            if data is None or not isinstance(data, dict):
                logger.error(
                    f"Failed to parse LLM response as DirectionResult: "
                    f"invalid JSON (after all repair attempts). "
                    f"Raw response (first 1000 chars): {content[:1000]}"
                )
                raise ValueError(
                    "Failed to parse LLM response as DirectionResult: invalid JSON"
                )

        try:
            # Handle LLM returning a top-level array instead of object
            if isinstance(data, list):
                logger.warning(
                    "LLM returned a top-level JSON array for DirectionResult. "
                    "Wrapping in expected object format."
                )
                data = {
                    "directions": data,
                    "high_priority_directions": [],
                    "total_functions_covered": 0,
                }
            return DirectionResult.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
            logger.error(f"Failed to parse LLM response as DirectionResult: {e}")
            logger.debug(f"Raw response (first 500 chars): {content[:500]}")
            raise ValueError(
                f"Failed to parse LLM response as DirectionResult: {e}"
            ) from e

    # ── File I/O ──────────────────────────────────────────────────────

    def save(self, result: DirectionResult, path: Union[str, Path]) -> None:
        """Save DirectionResult to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"DirectionResult saved to {path}")

    def load(self, path: Union[str, Path]) -> DirectionResult:
        """Load DirectionResult from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Direction file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return DirectionResult.from_dict(data)
