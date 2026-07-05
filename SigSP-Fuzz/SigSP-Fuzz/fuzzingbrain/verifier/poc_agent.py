"""
PoCAgent -- Generates PoC trigger inputs for P0 SPs.

Uses DeepSeek-V4-Pro to construct minimal exploit trigger inputs based on
the SP's control flow, vulnerability type, and attack surface context.

Only generates PoCs for P0 SPs (priority == "P0") to control token cost.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

from loguru import logger

from ..llms import LLMClient, CLAUDE_SONNET_4_6, ModelInfo
from ..static.models import FunctionInfo
from ..attack_surface.models import AttackSurface
from ..agents.firmware.sp_models import VerifiedSP
from ..agents.firmware.prompts import get_poc_prompt
from .models import PoC


class PoCAgent:
    """
    Generates PoC trigger inputs for P0 SPs using DeepSeek-V4-Pro.

    Only generates PoCs for P0 SPs (network + unauthenticated + RCE +
    confidence > 0.7). Follows Phase 2/3 pattern: LLMClient, prompt template,
    JSON parsing.

    Usage:
        agent = PoCAgent()
        poc = agent.generate(sp, attack_surface, function_info)
        agent.save(poc, "poc/sp_001_poc.json")
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        temperature: float = 0.3,
        max_tokens: int = 8000,
    ):
        self.llm_client = llm_client or LLMClient()
        self.model = (
            model
            or self.llm_client.config.get_agent_model("poc_agent")
            or CLAUDE_SONNET_4_6
        )
        self.temperature = temperature
        self.max_tokens = max_tokens

    # -- Public API ----------------------------------------------------------

    def generate(
        self,
        sp: VerifiedSP,
        attack_surface: AttackSurface,
        function_info: FunctionInfo,
    ) -> PoC:
        system_prompt = get_poc_prompt()
        user_content = self._build_user_message(sp, attack_surface, function_info)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        logger.info(
            f"PoCAgent: generating PoC for SP {sp.sp_id} "
            f"({sp.cwe}, {sp.function_name})"
        )

        response = self.llm_client.call(
            messages=messages,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        poc = self._parse_response(response.content, sp.sp_id)
        logger.info(
            f"PoCAgent: generated PoC for {sp.sp_id} "
            f"(type={poc.poc_type}, {len(poc.alternate_payloads)} alternates)"
        )
        return poc

    def generate_batch(
        self,
        sps: List[VerifiedSP],
        attack_surfaces: List[AttackSurface],
        function_contexts: Dict[str, FunctionInfo],
    ) -> List[PoC]:
        """Generate PoCs for the given SPs (filtering is done upstream)."""
        if not sps:
            logger.info("PoCAgent: no SPs to generate PoCs for")
            return []

        surface_map = {s.name: s for s in attack_surfaces}

        pocs = []
        for sp in sps:
            try:
                func_info = function_contexts.get(sp.function_name)
                if not func_info:
                    logger.warning(
                        f"PoCAgent: no FunctionInfo for {sp.function_name}, skipping {sp.sp_id}"
                    )
                    continue
                surface = surface_map.get(
                    sp.input_vector,
                    next(
                        iter(attack_surfaces),
                        AttackSurface(
                            name="unknown", category="other", entry_functions=[]
                        ),
                    ),
                )
                poc = self.generate(sp, surface, func_info)
                pocs.append(poc)
            except Exception as e:
                logger.error(
                    f"PoCAgent: failed to generate PoC for {sp.sp_id}: {e}"
                )
                continue

        logger.info(
            f"PoCAgent: generated {len(pocs)} PoCs from {len(sps)} SPs"
        )
        return pocs

    # -- P0 Filtering --------------------------------------------------------

    def _filter_p0(self, sps: List[VerifiedSP]) -> List[VerifiedSP]:
        return [sp for sp in sps if sp.priority == "P0"]

    # -- Prompt Building -----------------------------------------------------

    def _build_user_message(
        self,
        sp: VerifiedSP,
        attack_surface: AttackSurface,
        function_info: FunctionInfo,
    ) -> str:
        parts = []

        parts.append("# Suspicious Point for PoC Generation\n")
        parts.append("## Vulnerability Details")
        parts.append(f"- SP ID: {sp.sp_id}")
        parts.append(f"- CWE: {sp.cwe}")
        parts.append(f"- Title: {sp.title}")
        parts.append(f"- Description: {sp.description}")
        parts.append(f"- Control Flow: {sp.control_flow}")
        parts.append(f"- Trigger Condition: {sp.trigger_condition}")
        parts.append(f"- Root Cause: {sp.root_cause}")
        parts.append(f"- Confidence: {sp.confidence}")
        parts.append(f"- Input Vector: {sp.input_vector}")
        parts.append(f"- Severity: {sp.severity}")
        parts.append(f"- Analyst Type: {sp.analyst_type}")
        if sp.exploitability:
            parts.append(
                f"- Exploitability: attack_vector={sp.exploitability.attack_vector}, "
                f"difficulty={sp.exploitability.difficulty}, "
                f"impact={sp.exploitability.impact}"
            )
        parts.append("")

        parts.append("## Attack Surface Context")
        parts.append(f"- Name: {attack_surface.name}")
        parts.append(f"- Category: {attack_surface.category}")
        parts.append(f"- Protocol: {attack_surface.protocol}")
        if attack_surface.port_info:
            parts.append(
                f"- Port: {attack_surface.port_info.port}/{attack_surface.port_info.protocol_type}"
            )
        parts.append(
            f"- Entry Functions: {', '.join(attack_surface.entry_functions)}"
        )
        if attack_surface.strings_evidence:
            parts.append(
                f"- String Evidence: {', '.join(attack_surface.strings_evidence[:5])}"
            )
        parts.append("")

        parts.append("## Target Function")
        parts.append(f"- Name: {function_info.name}")
        parts.append(f"- Address: 0x{function_info.address:X}")
        parts.append(
            f"- Architecture: {function_info.arch}"
        )
        if function_info.callers:
            parts.append(f"- Callers: {', '.join(function_info.callers[:5])}")
        if function_info.callees:
            parts.append(f"- Callees: {', '.join(function_info.callees[:8])}")
        parts.append("")
        parts.append("### Pseudo-code / Disassembly")
        parts.append("```")
        parts.append(function_info.pseudo_code)
        parts.append("```")
        parts.append("")

        if function_info.assembly:
            parts.append("### Assembly Excerpt")
            parts.append("```asm")
            asm_lines = function_info.assembly.split("\n")[:40]
            parts.append("\n".join(asm_lines))
            if len(function_info.assembly.split("\n")) > 40:
                parts.append("... (truncated)")
            parts.append("```")
            parts.append("")

        parts.append("## Call Path from Entry Point")
        parts.append(sp.control_flow)
        parts.append("")

        parts.append(
            "\n# Instructions\n"
            "Based on the above vulnerability details and code, construct the "
            "MINIMAL PoC input to trigger this vulnerability. Output ONLY valid "
            "JSON matching the schema in the system prompt. Do not include any "
            "text outside the JSON."
        )

        return "\n".join(parts)

    # -- Response Parsing ----------------------------------------------------

    def _parse_response(self, content: str, sp_id: str) -> PoC:
        """Parse LLM response into PoC with auto-fix for common JSON errors.

        Common LLM JSON mistakes handled:
        1. Markdown code fences (```json ... ```)
        2. Surrounding text before/after JSON object
        3. Unescaped control characters in string values (\\r\\n, tabs)
        4. Missing commas between fields (try auto-fix via regex)
        5. Trailing commas before } or ]
        """
        json_str = content.strip()

        # Step 1: Extract from markdown fence if present
        fence_match = re.search(
            r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL
        )
        if fence_match:
            json_str = fence_match.group(1).strip()

        # Step 2: Extract JSON object boundaries
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
                    json_str = json_str[brace_start : end + 1]

        # Step 3: Try standard parse first
        try:
            data = json.loads(json_str)
            return PoC.from_dict(data)
        except json.JSONDecodeError as e:
            logger.debug(f"Standard JSON parse failed: {e}")

        # Step 4: Auto-fix common LLM JSON errors
        fixed = self._fix_json(json_str, content)
        try:
            data = json.loads(fixed)
            logger.info(f"PoCAgent: JSON fixed successfully after auto-repair")
            return PoC.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse LLM response as PoC (after auto-fix): {e}")
            logger.debug(f"Raw response (first 800 chars): {content[:800]}")
            raise ValueError(
                f"Failed to parse LLM response as PoC: {e}"
            ) from e

    def _fix_json(self, json_str: str, original: str) -> str:
        """Apply auto-fixes for common LLM JSON formatting errors."""
        fixed = json_str

        # Fix 1: Remove trailing commas before } or ]
        fixed = re.sub(r",\s*([}\]])", r"\1", fixed)

        # Fix 2: Fix missing commas between string value and next key
        # Pattern: "value"\n  "next_key" -> "value",\n  "next_key"
        fixed = re.sub(r'"\s*\n\s*"', '",\n  "', fixed)

        # Fix 3: Fix missing commas between number/true/false/null and next key
        fixed = re.sub(r'([0-9]+|true|false|null)\s*\n\s*"', r'\1,\n  "', fixed)

        # Fix 4: Fix missing comma between } or ] and next key
        fixed = re.sub(r'([}\]])\s*\n\s*"', r'\1,\n  "', fixed)

        # Fix 5: Fix unescaped backslashes in string values (LLM forgets to escape \\r\\n)
        # Only fix \r\n, \t, \n patterns that should be \\r\\n in JSON
        # Look for literal \r\n inside JSON string values
        def escape_in_strings(match):
            key = match.group(1)
            value = match.group(2)
            # Escape backslashes and control chars in value
            value = value.replace("\\", "\\\\")
            value = value.replace("\r", "\\r")
            value = value.replace("\n", "\\n")
            value = value.replace("\t", "\\t")
            return f'"{key}": "{value}"'

        # Only attempt if poc_content looks problematic
        if "poc_content" in fixed:
            # Fix unescaped quotes inside poc_content
            # Pattern: "poc_content": "...unescaped quotes..."
            poc_match = re.search(
                r'"(poc_content|poc_content_hex|poc_explanation|description|fix_suggestion)"\s*:\s*"([^"]*?)"',
                fixed
            )
            if poc_match:
                val = poc_match.group(2)
                if any(c in val for c in ['\r', '\n', '\t', '\x00']):
                    fixed = re.sub(
                        r'"(poc_content|poc_content_hex|poc_explanation|description|fix_suggestion)"\s*:\s*"([^"]*?)"',
                        escape_in_strings,
                        fixed
                    )

        return fixed

    # -- File I/O ------------------------------------------------------------

    def save(self, poc: PoC, path: Union[str, Path]) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = poc.to_dict()
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"PoC saved to {path}")

    def load(self, path: Union[str, Path]) -> PoC:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"PoC file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return PoC.from_dict(data)
