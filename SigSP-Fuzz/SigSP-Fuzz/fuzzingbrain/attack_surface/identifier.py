"""
AttackSurfaceIdentifier Agent

Reads Phase 1 static analysis output (functions + strings + callgraph),
calls DeepSeek-V4-Pro to identify attack surfaces, and outputs structured JSON.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from loguru import logger

from ..llms import LLMClient, CLAUDE_SONNET_4_6, ModelInfo
from ..static.models import FunctionInfo, CallGraph, StringRef
from ..agents.firmware.prompts import get_attack_surface_prompt
from .models import AttackSurfaceResult


# ── Prompt-building helpers ───────────────────────────────────────────

def build_function_summaries(functions: List[FunctionInfo]) -> str:
    """Build a compact function summary table for the LLM prompt.

    Includes: name, address, arch, callee count, dangerous callees,
    interesting strings, and caller context.
    """
    if not functions:
        return "No functions provided."

    lines = []
    lines.append(f"Total functions: {len(functions)}")
    lines.append("")
    lines.append("## Function Summary Table")
    lines.append("")

    for f in functions:
        name = f.name
        addr = f"0x{f.address:X}" if isinstance(f.address, int) else str(f.address)
        arch = f.arch or "unknown"
        stripped = " [STRIPPED]" if f.is_stripped_name else ""

        indicators = []
        if f.has_unsafe_calls:
            indicators.append(f"DANGEROUS: {', '.join(f.dangerous_funcs)}")
        if f.strings_used:
            shown = f.strings_used[:5]
            if len(f.strings_used) > 5:
                shown.append(f"... (+{len(f.strings_used) - 5} more)")
            indicators.append(f"strings: [{', '.join(shown)}]")
        if f.callees:
            interesting = [
                c for c in f.callees
                if any(kw in c.lower() for kw in (
                    "socket", "bind", "listen", "accept", "recv", "send",
                    "system", "popen", "exec", "strcpy", "sprintf", "memcpy",
                    "fopen", "open", "read", "write", "malloc",
                ))
            ]
            shown = interesting[:8] if interesting else f.callees[:5]
            if shown:
                indicators.append(f"callees: [{', '.join(shown)}]")
        if f.callers:
            shown = f.callers[:5]
            if len(f.callers) > 5:
                shown.append(f"... (+{len(f.callers) - 5} more)")
            indicators.append(f"callers: [{', '.join(shown)}]")

        indicator_str = " | ".join(indicators) if indicators else "no significant indicators"
        lines.append(f"- **{name}**{stripped} @ {addr} ({arch}): {indicator_str}")

    return "\n".join(lines)


def build_strings_by_category(strings: List[StringRef]) -> str:
    """Build categorized string list for the LLM prompt."""
    if not strings:
        return "No strings found."

    by_cat: Dict[str, List[StringRef]] = {}
    for s in strings:
        if s.category == "other":
            s.categorize()
        by_cat.setdefault(s.category, []).append(s)

    lines = []
    lines.append(f"Total strings: {len(strings)}")
    lines.append("")

    category_order = ["port", "url", "credential", "protocol", "path", "debug", "other"]
    for cat in category_order:
        items = by_cat.get(cat, [])
        if not items:
            continue
        lines.append(f"### {cat.upper()} Strings ({len(items)})")
        for s in items:
            refs = ", ".join(s.referenced_by[:5]) if s.referenced_by else "no xref"
            if len(s.referenced_by) > 5:
                refs += f" (+{len(s.referenced_by) - 5} more)"
            lines.append(f"- `{s.value}` → referenced by: [{refs}]")
        lines.append("")

    return "\n".join(lines)


def build_callgraph_summary(callgraph: CallGraph) -> str:
    """Build a summary of the call graph for the LLM prompt."""
    if not callgraph or not callgraph.nodes:
        return "No call graph data available."

    lines = []
    lines.append(f"Call graph has {callgraph.node_count} nodes (functions).")
    lines.append("")

    roots = [
        name for name, node in callgraph.nodes.items()
        if not node.callers
    ]
    if roots:
        lines.append(f"Root functions (likely entry points): {', '.join(roots[:10])}")
        if len(roots) > 10:
            lines.append(f"  ... and {len(roots) - 10} more")

    lines.append("")
    lines.append("### Key Call Relationships")
    interesting_funcs = [
        name for name, node in callgraph.nodes.items()
        if any(kw in name.lower() for kw in (
            "http", "cgi", "main", "init", "parse", "auth", "login",
            "upload", "download", "exec", "cmd", "handler", "dispatch",
            "telnet", "ssh", "upnp", "dns", "ftp", "snmp",
        )) or any(c in node.callees for c in ("system", "popen", "strcpy", "sprintf"))
    ]

    for name in interesting_funcs[:30]:
        node = callgraph.nodes[name]
        callees = node.callees[:8] if node.callees else []
        callers = node.callers[:5] if node.callers else []
        parts = []
        if callers:
            parts.append(f"called by [{', '.join(callers)}]")
        if callees:
            parts.append(f"calls [{', '.join(callees)}]")
        if parts:
            lines.append(f"- **{name}**: {'; '.join(parts)}")

    if len(interesting_funcs) > 30:
        lines.append(f"  ... and {len(interesting_funcs) - 30} more interesting functions")

    return "\n".join(lines)


# ── Main Agent ─────────────────────────────────────────────────────────

class AttackSurfaceIdentifier:
    """
    Identifies attack surfaces in firmware from static analysis output.

    Reads function lists, string references, and call graph info, then calls
    an LLM (default: DeepSeek-V4-Pro) to identify code paths where untrusted
    data enters the system.

    Usage:
        identifier = AttackSurfaceIdentifier()
        result = identifier.identify(functions, strings, callgraph)
        identifier.save(result, "attack_surface.json")
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
            or self.llm_client.config.get_agent_model("attack_surface_identifier")
            or CLAUDE_SONNET_4_6
        )
        self.temperature = temperature
        self.max_tokens = max_tokens

    def identify(
        self,
        functions: List[FunctionInfo],
        strings: List[StringRef],
        callgraph: Optional[CallGraph] = None,
    ) -> AttackSurfaceResult:
        """
        Identify attack surfaces from static analysis data.

        Args:
            functions: All functions from Ghidra decompilation.
            strings: All string references from the binary.
            callgraph: Call graph (optional, used for relationship context).

        Returns:
            AttackSurfaceResult with identified attack surfaces and summary.

        Raises:
            ValueError: If the LLM response cannot be parsed.
        """
        system_prompt = get_attack_surface_prompt()
        user_content = self._build_user_message(functions, strings, callgraph)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        logger.info(
            f"AttackSurfaceIdentifier: calling LLM with "
            f"{len(functions)} functions, {len(strings)} strings"
        )

        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        result = self._parse_response(response.content)
        logger.info(
            f"AttackSurfaceIdentifier: identified {result.count} attack surfaces. "
            f"Primary exposure: {result.summary.primary_exposure[:100]}"
        )
        return result

    def _build_user_message(
        self,
        functions: List[FunctionInfo],
        strings: List[StringRef],
        callgraph: Optional[CallGraph],
    ) -> str:
        """Build the user message with all input data."""
        parts = []

        parts.append("# Firmware Static Analysis Results\n")

        parts.append("## Functions")
        parts.append(build_function_summaries(functions))
        parts.append("")

        parts.append("## Strings by Category")
        parts.append(build_strings_by_category(strings))
        parts.append("")

        if callgraph:
            parts.append("## Call Graph")
            parts.append(build_callgraph_summary(callgraph))
            parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Analyze the above data and identify ALL attack surfaces. "
            "Output ONLY valid JSON matching the schema in the system prompt. "
            "Do not include any text outside the JSON."
        )

        return "\n".join(parts)

    def _parse_response(self, content: str) -> AttackSurfaceResult:
        """Parse LLM response into AttackSurfaceResult.

        Handles LLMs that wrap JSON in markdown code fences.
        """
        json_str = content.strip()

        # Remove ```json ... ``` wrapper if present
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Try to find a JSON object if there's surrounding text
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
        except json.JSONDecodeError as e:
            # Attempt to repair truncated JSON
            data = self._repair_json(json_str)
            if data is None:
                # Last resort: try parsing as a top-level array
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
                                    "LLM returned a bare JSON array. "
                                    "Wrapping in expected object format."
                                )
                                data = {
                                    "attack_surfaces": data,
                                    "summary": {
                                        "primary_exposure": "network",
                                        "total_attack_surfaces": len(data),
                                    },
                                }
                except (json.JSONDecodeError, Exception):
                    pass

            if data is None or not isinstance(data, dict):
                logger.error(
                    f"Failed to parse LLM response as AttackSurfaceResult: {e}. "
                    f"Raw response (first 1000 chars): {content[:1000]}"
                )
                raise ValueError(
                    f"Failed to parse LLM response as AttackSurfaceResult: {e}"
                ) from e

        try:
            # Handle LLM returning a top-level array instead of object
            if isinstance(data, list):
                logger.warning(
                    "LLM returned a top-level JSON array for AttackSurfaceResult. "
                    "Wrapping in expected object format."
                )
                data = {
                    "attack_surfaces": data,
                    "summary": {
                        "primary_exposure": "network",
                        "total_attack_surfaces": len(data),
                    },
                }
            return AttackSurfaceResult.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
            logger.error(f"Failed to parse LLM response as AttackSurfaceResult: {e}")
            logger.debug(f"Raw response (first 500 chars): {content[:500]}")
            raise ValueError(
                f"Failed to parse LLM response as AttackSurfaceResult: {e}"
            ) from e

    @staticmethod
    def _repair_json(json_str: str) -> Optional[dict]:
        """Attempt to repair truncated/incomplete JSON from LLM output.

        Strategies:
        1. Remove last incomplete line and re-close braces
        2. Close unbalanced braces
        """
        # Strategy 1: Remove trailing incomplete line
        lines = json_str.split("\n")
        if len(lines) > 1:
            for trim in range(1, min(10, len(lines))):
                truncated = "\n".join(lines[:-trim])
                # Close unclosed strings on the last line
                if truncated.count('"') % 2 != 0:
                    truncated += '"'
                # Close unbalanced braces
                depth = truncated.count("{") - truncated.count("}")
                if depth > 0:
                    truncated += "}" * depth
                try:
                    return json.loads(truncated)
                except json.JSONDecodeError:
                    continue

        # Strategy 2: Close unbalanced braces only
        try:
            depth = 0
            in_string = False
            for ch in json_str:
                if ch == '"' and (depth == 0 or True):
                    in_string = not in_string
                elif not in_string:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
            if depth > 0:
                return json.loads(json_str + "}" * depth)
        except (json.JSONDecodeError, Exception):
            pass

        return None

    # ── File I/O ──────────────────────────────────────────────────────

    def save(self, result: AttackSurfaceResult, path: Union[str, Path]) -> None:
        """Save AttackSurfaceResult to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"AttackSurfaceResult saved to {path}")

    def load(self, path: Union[str, Path]) -> AttackSurfaceResult:
        """Load AttackSurfaceResult from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Attack surface file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return AttackSurfaceResult.from_dict(data)
