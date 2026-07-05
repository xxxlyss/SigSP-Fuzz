"""
StaticAssessor -- L3 static confidence fallback for dynamic verification.

Pure algorithm (no LLM). When FirmAE (L1) and QEMU (L2) cannot confirm
a vulnerability, assess based on static confidence and call chain completeness.

Rules:
- confidence >= threshold AND complete call chain -> static_high
- confidence >= threshold AND incomplete call chain -> static_low
- confidence < threshold -> static_low
"""

from typing import Optional

from loguru import logger

from ..static.models import CallGraph
from ..agents.firmware.sp_models import VerifiedSP
from .models import VerificationResult


class StaticAssessor:
    """L3: Pure static confidence assessment -- no dynamic execution."""

    def __init__(self, high_confidence_threshold: float = 0.85):
        self.high_confidence_threshold = high_confidence_threshold

    def assess(
        self,
        sp: VerifiedSP,
        callgraph: Optional[CallGraph] = None,
    ) -> VerificationResult:
        # Check confidence threshold
        if sp.confidence < self.high_confidence_threshold:
            logger.info(
                f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f} < "
                f"threshold={self.high_confidence_threshold} -> static_low (discarded)"
            )
            return VerificationResult(
                sp_id=sp.sp_id,
                verification_level="static_low",
                crashed=False,
                output=(
                    f"L3 assessment: confidence={sp.confidence:.2f} < "
                    f"threshold={self.high_confidence_threshold}. Discarded."
                ),
            )

        # Check call chain completeness
        if callgraph is not None:
            chain_complete = self._check_call_chain_completeness(sp, callgraph)
            if chain_complete:
                logger.info(
                    f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f}, "
                    f"chain complete -> static_high"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="static_high",
                    crashed=False,
                    output=(
                        f"L3 assessment: confidence={sp.confidence:.2f} >= "
                        f"threshold={self.high_confidence_threshold}, "
                        f"call chain complete from entry to sink. Reserved."
                    ),
                )
            else:
                logger.info(
                    f"StaticAssessor: {sp.sp_id} high confidence but "
                    f"incomplete chain -> static_low"
                )
                return VerificationResult(
                    sp_id=sp.sp_id,
                    verification_level="static_low",
                    crashed=False,
                    output=(
                        f"L3 assessment: confidence={sp.confidence:.2f} >= "
                        f"threshold but call chain incomplete. Discarded."
                    ),
                )

        # No callgraph available
        logger.info(
            f"StaticAssessor: {sp.sp_id} confidence={sp.confidence:.2f}, "
            f"no callgraph -> static_high (confidence-based)"
        )
        return VerificationResult(
            sp_id=sp.sp_id,
            verification_level="static_high",
            crashed=False,
            output=(
                f"L3 assessment: confidence={sp.confidence:.2f} >= "
                f"threshold={self.high_confidence_threshold}. "
                f"No callgraph available for path verification. Reserved."
            ),
        )

    # Externally-facing input vectors (reachable without source-code call chain)
    NETWORK_INPUT_VECTORS = {
        "http_post", "http_get", "http_request", "network_packet",
        "udp_packet", "tcp_stream", "cgi_param", "socket",
    }

    def _check_call_chain_completeness(
        self, sp: VerifiedSP, callgraph: CallGraph
    ) -> bool:
        vuln_func = sp.function_name

        # --- Path A: function in callgraph with callers → BFS to roots ---
        if vuln_func in callgraph.nodes:
            node = callgraph.nodes[vuln_func]
            if node.callers:
                root_funcs = {
                    name for name, n in callgraph.nodes.items()
                    if not n.callers
                }
                if root_funcs:
                    visited = set()
                    queue = list(root_funcs)
                    while queue:
                        current = queue.pop(0)
                        if current in visited:
                            continue
                        visited.add(current)
                        if current == vuln_func:
                            logger.debug(
                                f"BFS: found path from root -> '{vuln_func}'"
                            )
                            return True
                        if current in callgraph.nodes:
                            for callee in callgraph.nodes[current].callees:
                                if callee not in visited:
                                    queue.append(callee)

        # --- Path B: function has no callers in callgraph ---
        # Ghidra cannot resolve indirect calls (function pointers), which is how
        # httpd dispatches to CGI/goform handlers.  Fall back to SP metadata.
        return self._check_chain_from_sp_metadata(sp)

    def _check_chain_from_sp_metadata(self, sp: VerifiedSP) -> bool:
        """Check call-chain completeness from SP metadata when the static
        callgraph lacks caller edges (e.g. indirect calls via function pointers).

        Evidence sources (any one is sufficient):
        1. input_vector: network-facing vectors imply external reachability
           (the attack surface already identified this function as an entry point)
        2. control_flow: LLM-written call path mentioning entry→sink flow
        3. control_flow keywords: 'invoke', 'dispatch', 'entry', 'handler', 'request'
        """
        evidence = []

        # Evidence 1: network-facing input vector
        if sp.input_vector in self.NETWORK_INPUT_VECTORS:
            evidence.append(f"network input vector ({sp.input_vector})")

        # Evidence 2: control_flow describes a call path
        cf = (sp.control_flow or "").lower()
        if cf:
            # Look for chain-like patterns: "invokes", "calls", "dispatches",
            # "entry point", "handler", "request arrives"
            chain_keywords = [
                "invoke", "invokes", "invoked", "call", "calls",
                "dispatch", "dispatches", "handler", "entry point",
                "request arrives", "request is received", "triggers",
                "passed to", "cgi endpoint", "goform", "flows to",
                "reaches", "enters",
            ]
            found_keywords = [kw for kw in chain_keywords if kw in cf]
            if found_keywords:
                evidence.append(
                    f"control_flow keywords: {found_keywords[:5]}"
                )

        # Evidence 3: control_flow mentions specific functions in a chain
        if cf and "→" in sp.control_flow:
            evidence.append("control_flow has call chain arrow (→)")

        if evidence:
            logger.info(
                f"StaticAssessor: {sp.sp_id} ({sp.function_name}) "
                f"no callers in callgraph, but chain inferred from SP metadata: "
                f"{'; '.join(evidence)}"
            )
            return True

        logger.debug(
            f"StaticAssessor: {sp.sp_id} ({sp.function_name}) "
            f"no callers and no chain evidence in SP metadata"
        )
        return False
