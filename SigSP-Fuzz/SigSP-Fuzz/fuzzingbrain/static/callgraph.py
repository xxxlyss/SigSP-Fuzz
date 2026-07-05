"""
Call Graph construction and analysis for firmware binaries.

Builds call graphs from Ghidra-exported function data and provides
path-finding and reachability queries.
"""

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from .models import CallGraph, CallGraphNode, FunctionInfo


class CallGraphBuilder:
    """
    Builds CallGraph from a list of FunctionInfo objects.

    Usage:
        functions: List[FunctionInfo] = [...]  # from Ghidra export
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path="bin/httpd")

        # Query paths
        path = callgraph.get_call_path("main", "strcpy")
    """

    def build(self, functions: List[FunctionInfo], binary_path: str = "") -> CallGraph:
        """
        Build a CallGraph from FunctionInfo list.

        Args:
            functions: List of function info from Ghidra export
            binary_path: Path to the binary for identification

        Returns:
            CallGraph with all nodes and edges populated
        """
        cg = CallGraph(binary_path=binary_path)

        for func in functions:
            node = CallGraphNode(
                function_name=func.name,
                address=func.address,
                callers=list(func.callers),
                callees=list(func.callees),
            )
            cg.nodes[func.name] = node

        logger.debug(f"Built call graph: {cg.node_count} nodes for {binary_path}")
        return cg

    def build_from_json(self, json_path: str, binary_path: str = "") -> CallGraph:
        """
        Build a CallGraph from a Ghidra-exported JSON file.

        Expected JSON format:
        {
          "functions": [
            {
              "name": "main",
              "address": 4096,
              "callers": ["_start"],
              "callees": ["httpd_main", "printf"]
            },
            ...
          ]
        }

        Args:
            json_path: Path to functions.json from Ghidra export
            binary_path: Path to the binary for identification

        Returns:
            CallGraph
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cg = CallGraph(binary_path=binary_path)

        functions = data.get("functions", [])
        for func_data in functions:
            node = CallGraphNode(
                function_name=func_data.get("name", ""),
                address=func_data.get("address", 0),
                callers=func_data.get("callers", []),
                callees=func_data.get("callees", []),
            )
            cg.nodes[node.function_name] = node

        logger.info(f"Loaded call graph from JSON: {cg.node_count} nodes")
        return cg

    def to_json(self, callgraph: CallGraph, output_path: str) -> None:
        """
        Serialize CallGraph to JSON.

        Args:
            callgraph: CallGraph to serialize
            output_path: Output JSON file path
        """
        nodes_data = []
        for name, node in callgraph.nodes.items():
            nodes_data.append({
                "name": node.function_name,
                "address": node.address,
                "callers": node.callers,
                "callees": node.callees,
            })

        data = {
            "binary_path": callgraph.binary_path,
            "node_count": callgraph.node_count,
            "functions": nodes_data,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported call graph to {output_path}: {callgraph.node_count} nodes")


class CallGraphAnalyzer:
    """
    Analyze and query a CallGraph for vulnerability research.

    Provides common queries needed for attack surface analysis:
    - Find all reachable functions from an entry point
    - Find the shortest path between two functions
    - Identify functions that call dangerous sinks
    """

    DANGEROUS_SINKS = {
        # Buffer overflow sinks
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "memcpy", "memmove", "bcopy",
        # Command injection sinks
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "doSystem", "do_system",
        # Format string sinks
        "printf", "fprintf", "snprintf", "syslog", "vprintf",
        # Path traversal sinks
        "fopen", "open", "read", "write", "unlink", "rename",
        # Network sinks
        "recv", "recvfrom", "read", "fread",
        "bind", "listen", "accept",
    }

    def __init__(self, callgraph: CallGraph):
        self.cg = callgraph

    def find_reachable_functions(
        self, entry_function: str, max_depth: int = 20
    ) -> Set[str]:
        """
        Find all functions reachable from an entry point via BFS.

        Args:
            entry_function: Starting function name
            max_depth: Maximum call depth to traverse

        Returns:
            Set of reachable function names
        """
        if entry_function not in self.cg.nodes:
            return set()

        reachable = {entry_function}
        queue = deque([(entry_function, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for callee in self.cg.get_callees(current):
                if callee not in reachable:
                    reachable.add(callee)
                    queue.append((callee, depth + 1))

        return reachable

    def find_dangerous_calls(
        self, entry_function: str
    ) -> List[tuple]:
        """
        Find all dangerous sink calls reachable from an entry point.

        Returns:
            List of (dangerous_sink, call_path) tuples
        """
        reachable = self.find_reachable_functions(entry_function)
        dangerous = []

        for func_name in reachable:
            node = self.cg.nodes.get(func_name)
            if node:
                for callee in node.callees:
                    if callee in self.DANGEROUS_SINKS:
                        path = self.cg.get_call_path(entry_function, func_name)
                        dangerous.append((callee, path or [func_name], func_name))

        return dangerous

    def find_entry_points(self) -> List[str]:
        """
        Find likely entry points — functions with no callers or called by
        well-known start functions.

        Returns:
            List of potential entry point function names
        """
        entry_points = []
        start_functions = {"main", "_start", "entry", "start", "WinMain", "DllMain"}

        for name, node in self.cg.nodes.items():
            # No callers = potential entry
            if not node.callers:
                entry_points.append(name)
            # Called by known start functions
            elif any(c in start_functions for c in node.callers):
                entry_points.append(name)

        return entry_points
