"""
Data models for firmware static analysis.

These models represent the output of binwalk extraction and Ghidra decompilation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BinaryInfo:
    """Information about an extracted binary file."""

    path: str                      # Relative path within extracted filesystem
    arch: str                      # Architecture: arm, mips, riscv, x86
    bits: int                      # 32 or 64
    endian: str                    # little or big
    file_type: str                 # web_server, daemon, cgi, library, kernel_module
    stripped: bool                 # Whether symbols are stripped
    entry_point: int               # Entry point address (0 if library)
    sections: List[str] = field(default_factory=list)  # Section names

    @property
    def is_stripped(self) -> bool:
        """Alias for stripped."""
        return self.stripped

    @property
    def arch_tuple(self) -> tuple:
        """Return (arch, bits, endian) as a tuple for QEMU selection."""
        return (self.arch, self.bits, self.endian)


@dataclass
class FunctionInfo:
    """Information about a single function extracted by Ghidra."""

    name: str                      # Function name (FUN_XXXXXXXX if stripped)
    address: int                   # Binary offset address
    pseudo_code: str               # Ghidra decompiled C pseudo-code
    assembly: str = ""             # Assembly code (optional, can be empty)
    callers: List[str] = field(default_factory=list)    # Function names that call this
    callees: List[str] = field(default_factory=list)    # Function names this calls
    parameters: int = 0            # Inferred parameter count
    complexity: int = 0            # Cyclomatic complexity
    has_unsafe_calls: bool = False # Whether it calls dangerous functions
    dangerous_funcs: List[str] = field(default_factory=list)  # List of dangerous callees
    strings_used: List[str] = field(default_factory=list)     # Strings referenced
    arch: str = ""                 # Architecture
    section: str = ""              # .text, .data, .plt, etc.
    binary_path: str = ""          # Which binary this function belongs to

    @property
    def is_stripped_name(self) -> bool:
        """Check if function name is Ghidra auto-generated (FUN_XXXXXXXX)."""
        return self.name.startswith("FUN_")

    @property
    def dangeous_call_count(self) -> int:
        """Count of dangerous function calls."""
        return len(self.dangerous_funcs)


@dataclass
class CallGraphNode:
    """A node in the call graph."""

    function_name: str
    address: int
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)


@dataclass
class CallGraph:
    """Complete call graph for a binary."""

    binary_path: str
    nodes: Dict[str, CallGraphNode] = field(default_factory=dict)

    def get_callers(self, func_name: str) -> List[str]:
        """Get all callers of a function."""
        node = self.nodes.get(func_name)
        return node.callers if node else []

    def get_callees(self, func_name: str) -> List[str]:
        """Get all callees of a function."""
        node = self.nodes.get(func_name)
        return node.callees if node else []

    def get_call_path(self, from_func: str, to_func: str, max_depth: int = 10) -> Optional[List[str]]:
        """
        Find a call path from from_func to to_func using BFS.
        Returns list of function names representing the path, or None if not found.
        """
        if from_func not in self.nodes or to_func not in self.nodes:
            return None
        if from_func == to_func:
            return [from_func]

        from collections import deque
        queue = deque([(from_func, [from_func])])
        visited = {from_func}

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for callee in self.get_callees(current):
                if callee == to_func:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return None

    @property
    def node_count(self) -> int:
        return len(self.nodes)


@dataclass
class StringRef:
    """A string reference with its location and cross-references."""

    value: str                     # The string value
    address: int                   # Address in .rodata
    referenced_by: List[str] = field(default_factory=list)  # Functions that reference it
    category: str = "other"        # port, url, path, protocol, credential, debug, other

    CATEGORY_KEYWORDS = {
        "port": ["port", ":80", ":443", ":8080", ":23", ":21", ":22"],
        "url": ["http://", "https://", "www.", "/cgi-bin/", "/www/", ".html", ".cgi"],
        "path": ["/etc/", "/tmp/", "/var/", "/proc/", "/sys/", "/dev/"],
        "protocol": ["HTTP", "UPnP", "SSDP", "DNS", "FTP", "Telnet", "SSH", "SNMP"],
        "credential": ["admin", "root", "password", "login", "passwd", "token", "cookie"],
        "debug": ["debug", "test", "TODO", "FIXME", "printf", "assert"],
    }

    def categorize(self) -> str:
        """Auto-categorize this string based on content."""
        lower_val = self.value.lower()
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in lower_val:
                    self.category = category
                    return category
        return "other"


@dataclass
class ExtractResult:
    """Result of firmware extraction via binwalk."""

    firmware_path: str             # Original firmware path
    output_dir: str                # Extraction output directory
    success: bool                  # Whether extraction succeeded
    filesystem_type: str = ""      # squashfs, jffs2, cramfs, etc.
    binaries: List[BinaryInfo] = field(default_factory=list)
    file_count: int = 0
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete result of Ghidra static analysis for one binary."""

    binary: BinaryInfo
    success: bool
    functions: List[FunctionInfo] = field(default_factory=list)
    callgraph: Optional[CallGraph] = None
    strings: List[StringRef] = field(default_factory=list)
    error: Optional[str] = None
    analysis_time_seconds: float = 0.0

    @property
    def function_count(self) -> int:
        return len(self.functions)

    @property
    def stripped_function_count(self) -> int:
        return sum(1 for f in self.functions if f.is_stripped_name)

    @property
    def unsafe_function_count(self) -> int:
        return sum(1 for f in self.functions if f.has_unsafe_calls)
