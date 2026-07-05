"""
SAST Tools — Static Analysis via Ghidra Headless

Tools that call Ghidra's headless analyzer to decompile, query call graphs,
find string cross-references, and locate function boundaries.

All tools wrap the GhidraAnalyzer or ObjdumpAnalyzer depending on what's
available at runtime (auto-fallback via AnalyzerFactory).

Usage (via ToolRegistry):
    registry.execute_tool("decompile_function", binary_path="/bin/httpd", func_addr=0x401000)
    registry.execute_tool("get_callers", binary_path="/bin/httpd", func_addr=0x401000)
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .base import FirmwareTool, ToolParameter, ToolExecutionError
from .registry import get_registry
from .ghidra_bridge import get_ghidra_bridge, GhidraBridge


def _resolve_binary_path(binary_path: str, extracted_root: Optional[str] = None) -> str:
    """Resolve a binary path (relative or absolute) to an existing file.

    Args:
        binary_path: Relative or absolute path to the binary.
        extracted_root: Root of extracted filesystem (e.g., squashfs-root/).

    Returns:
        Absolute path to an existing file.

    Raises:
        ToolExecutionError: if the binary cannot be found.
    """
    # Try absolute first
    if os.path.isabs(binary_path) and os.path.exists(binary_path):
        return binary_path

    # Try relative to extracted root
    if extracted_root:
        candidate = os.path.join(extracted_root, binary_path)
        if os.path.exists(candidate):
            return candidate

    # Try as-is (maybe it's relative to CWD)
    if os.path.exists(binary_path):
        return os.path.abspath(binary_path)

    raise ToolExecutionError(
        "decompile_function",
        FileNotFoundError(
            f"Binary not found: '{binary_path}'. "
            f"Provide an absolute path or set extracted_root."
        ),
    )


# ---------------------------------------------------------------------------
# Ghidra Adapter — wraps analyzeHeadless subprocess calls
# ---------------------------------------------------------------------------

class GhidraAdapter:
    """Lightweight adapter for making one-off queries to Ghidra headless.

    Uses subprocess to run Ghidra scripts for specific queries rather than
    loading the full GhidraAnalyzer (which is designed for batch analysis).
    """

    def __init__(self, ghidra_headless: Optional[str] = None):
        self.headless = ghidra_headless or _find_ghidra_headless()
        self.available = self.headless is not None and os.path.exists(self.headless)
        if not self.available:
            logger.warning(
                "Ghidra analyzeHeadless not found. SAST tools will fall back "
                "to ObjdumpAnalyzer for basic queries."
            )

    def run_script(
        self,
        binary_path: str,
        script_name: str,
        script_args: str = "",
        timeout: int = 60,
    ) -> dict:
        """Run a Ghidra headless script against a binary.

        Args:
            binary_path: Absolute path to the ELF binary.
            script_name: Name of the script (must exist in Ghidra's script paths).
            script_args: Arguments passed to the script.
            timeout: Subprocess timeout in seconds.

        Returns:
            {"success": True, "data": ...} or {"success": False, "error": "..."}
        """
        if not self.available:
            return {
                "success": False,
                "error": "Ghidra analyzeHeadless is not available. "
                         "Install Ghidra to /opt/ghidra or set GHIDRA_HOME.",
            }

        if not os.path.exists(binary_path):
            return {
                "success": False,
                "error": f"Binary not found: {binary_path}",
            }

        # Create a temp project directory
        with tempfile.TemporaryDirectory(prefix="ghidra_mcp_") as tmpdir:
            project_dir = os.path.join(tmpdir, "project")
            os.makedirs(project_dir, exist_ok=True)

            project_name = f"mcp_{os.path.basename(binary_path)}"

            cmd = [
                self.headless,
                project_dir,
                project_name,
                "-import",
                binary_path,
                "-scriptPath",
                os.path.dirname(os.path.abspath(__file__)),
                "-postScript",
                script_name,
                script_args,
                "-deleteProject",
                "-noanalysis",  # Skip full auto-analysis for speed
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": f"Ghidra exited with code {result.returncode}: "
                                 f"{result.stderr[:500]}",
                    }

                # Parse JSON from stdout (script writes JSON to stdout)
                stdout = result.stdout.strip()
                if stdout:
                    try:
                        data = json.loads(stdout)
                        return {"success": True, "data": data}
                    except json.JSONDecodeError:
                        # Try to find JSON block in output
                        for line in stdout.split("\n"):
                            line = line.strip()
                            if line.startswith("{") or line.startswith("["):
                                try:
                                    data = json.loads(line)
                                    return {"success": True, "data": data}
                                except json.JSONDecodeError:
                                    continue
                        return {
                            "success": False,
                            "error": f"Failed to parse Ghidra output as JSON. "
                                     f"Raw: {stdout[:500]}",
                        }
                return {"success": True, "data": {}}

            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": f"Ghidra script '{script_name}' timed out after {timeout}s",
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Ghidra execution failed: {e}",
                }


# ---------------------------------------------------------------------------
# Objdump Fallback Adapter
# ---------------------------------------------------------------------------

class ObjdumpAdapter:
    """Fallback adapter using cross-binutils objdump/readelf for basic queries.

    Used when Ghidra is not available. Provides a subset of SAST tool
    functionality with disassembly-level accuracy.
    """

    def __init__(self):
        self._prefix_cache: Dict[str, str] = {}

    def _get_objdump(self, binary_path: str) -> str:
        """Get the appropriate objdump binary for the given ELF."""
        arch, bits, endian = self._detect_arch(binary_path)
        prefix = self._get_cross_prefix(arch, endian)
        return f"{prefix}objdump" if prefix else "objdump"

    def _detect_arch(self, binary_path: str) -> tuple:
        """Detect (arch, bits, endian) from ELF header."""
        try:
            import struct
            with open(binary_path, "rb") as f:
                e_ident = f.read(16)
                if len(e_ident) < 16:
                    return ("unknown", 32, "little")
                if e_ident[:4] != b"\x7fELF":
                    return ("unknown", 32, "little")
                bits = 32 if e_ident[4] == 1 else 64
                endian = "little" if e_ident[5] == 1 else "big"
                f.seek(18)
                machine = struct.unpack(
                    "<H" if endian == "little" else ">H",
                    f.read(2),
                )[0]
                arch_map = {
                    0x28: "arm", 0xB7: "aarch64", 0x08: "mips",
                    0x03: "x86", 0x3E: "x86_64", 0xF3: "riscv",
                    0x14: "ppc",
                }
                return (arch_map.get(machine, "unknown"), bits, endian)
        except Exception:
            return ("unknown", 32, "little")

    def _get_cross_prefix(self, arch: str, endian: str) -> str:
        """Get cross-compile prefix for the architecture."""
        cross_map = {
            "mips": {"little": "mipsel-linux-gnu-", "big": "mips-linux-gnu-"},
            "arm": {"little": "arm-linux-gnueabi-", "big": "arm-linux-gnueabi-"},
            "aarch64": {"little": "aarch64-linux-gnu-", "big": "aarch64-linux-gnu-"},
            "riscv": {"little": "riscv64-linux-gnu-", "big": "riscv64-linux-gnu-"},
            "ppc": {"little": "powerpc-linux-gnu-", "big": "powerpc-linux-gnu-"},
            "x86": {"little": "", "big": ""},
            "x86_64": {"little": "", "big": ""},
        }
        arch_map = cross_map.get(arch, {})
        prefix = arch_map.get(endian, "")
        if prefix:
            import shutil
            if not shutil.which(f"{prefix}objdump"):
                logger.warning(f"Cross-tool not found: {prefix}objdump")
                return ""
        return prefix

    def get_function_at(
        self, binary_path: str, func_addr: int
    ) -> dict:
        """Find a function at the given address using objdump."""
        objdump = self._get_objdump(binary_path)
        try:
            result = subprocess.run(
                [objdump, "-d", f"--start-address=0x{func_addr:x}",
                 f"--stop-address=0x{func_addr+0x1000:x}", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr[:500]}

            lines = result.stdout.split("\n")
            disasm_lines = []
            current_func = None
            for line in lines:
                if "<" in line and ">:" in line:
                    # Function label
                    current_func = line.strip().split("<")[-1].rstrip(">:")
                if current_func:
                    disasm_lines.append(line)
                    if len(disasm_lines) > 200:
                        break

            return {
                "success": True,
                "function_name": current_func or f"FUN_{func_addr:08x}",
                "address": func_addr,
                "disassembly": "\n".join(disasm_lines),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "objdump timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_callers_callees(
        self, binary_path: str, func_name: str
    ) -> dict:
        """Get callers and callees from objdump disassembly analysis."""
        objdump = self._get_objdump(binary_path)
        try:
            # Get full disassembly
            result = subprocess.run(
                [objdump, "-d", binary_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr[:500]}

            callers = []
            callees = []
            current_func = None
            func_body = []
            in_target = False

            for line in result.stdout.split("\n"):
                # Detect function boundaries
                if "<" in line and ">:" in line:
                    if current_func == func_name:
                        # We've been collecting target function's body
                        # Extract callees
                        callees_set = set()
                        for bline in func_body:
                            if "<" in bline and ">:" not in bline:
                                continue
                            for pattern in ["jal ", "bal ", "bl ", "call "]:
                                if pattern in bline and "<" in bline:
                                    target = bline.split("<")[-1].split(">")[0]
                                    callees_set.add(target.split("+")[0])
                        callees = list(callees_set)
                        in_target = False
                        func_body = []

                    current_func = line.strip().split("<")[-1].rstrip(">:")
                    if current_func == func_name:
                        in_target = True
                        func_body.append(line)
                    elif func_name in line and "<" in line:
                        # Caller found
                        callers.append(current_func)
                    continue

                if in_target:
                    func_body.append(line)

            return {
                "success": True,
                "function": func_name,
                "callers": callers,
                "callees": callees,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "objdump timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def find_strings(
        self, binary_path: str, target_string: str
    ) -> List[int]:
        """Find addresses that reference a string."""
        try:
            # First find the string in .rodata
            strings_result = subprocess.run(
                ["strings", "-t", "x", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            string_addrs = []
            for line in strings_result.stdout.split("\n"):
                if target_string in line:
                    parts = line.strip().split(None, 1)
                    if parts:
                        try:
                            string_addrs.append(int(parts[0], 16))
                        except ValueError:
                            continue

            # Search disassembly for references to these string addresses
            objdump = self._get_objdump(binary_path)
            disasm_result = subprocess.run(
                [objdump, "-d", binary_path],
                capture_output=True, text=True, timeout=120,
            )

            xrefs = []
            for addr in string_addrs:
                addr_hex = f"{addr:x}"
                for line in disasm_result.stdout.split("\n"):
                    if addr_hex in line:
                        # Extract the code address from the line
                        code_match = line.strip().split(":")[0].strip()
                        try:
                            xrefs.append(int(code_match, 16))
                        except ValueError:
                            pass

            return list(set(xrefs))
        except Exception as e:
            logger.error(f"find_strings error: {e}")
            return []


# ---------------------------------------------------------------------------
# Global Adapters (lazy init)
# ---------------------------------------------------------------------------

_objdump: Optional[ObjdumpAdapter] = None


def _get_objdump() -> ObjdumpAdapter:
    global _objdump
    if _objdump is None:
        _objdump = ObjdumpAdapter()
    return _objdump


def _try_ghidra_bridge() -> Optional[GhidraBridge]:
    """Get GhidraBridge if Ghidra is installed, None otherwise."""
    try:
        bridge = get_ghidra_bridge()
        if bridge.available:
            return bridge
    except Exception:
        pass
    return None


# ===========================================================================
# SAST Tool Implementations
# ===========================================================================


class DecompileFunctionTool(FirmwareTool):
    """Decompile a function at a given address using Ghidra (or objdump fallback).

    Returns C-like pseudo-code when Ghidra is available, or MIPS/ARM/x86
    disassembly when using the objdump fallback.
    """

    name = "decompile_function"
    description = (
        "Decompile a function at a specific address in a firmware binary. "
        "Returns C-like pseudo-code from Ghidra (if available) or raw disassembly "
        "from objdump as a fallback. The output shows the function's logic, "
        "called functions, and data flow — essential for understanding how "
        "user input reaches dangerous sinks (strcpy, system, etc.)."
    )
    category = "sast"
    timeout = 60.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to the ELF binary (relative to extracted root, or absolute).",
            required=True,
        ),
        ToolParameter(
            name="func_addr",
            type="integer",
            description="Function entry point address (hex or decimal, e.g., 0x401000 or 4198400).",
            required=True,
        ),
        ToolParameter(
            name="extracted_root",
            type="string",
            description="Root directory of the extracted filesystem (e.g., squashfs-root/). Used to resolve relative binary_path.",
            required=False,
            default="",
        ),
    ]

    def execute(
        self,
        binary_path: str,
        func_addr: int,
        extracted_root: str = "",
    ) -> dict:
        abs_path = _resolve_binary_path(binary_path, extracted_root or None)

        # Primary: GhidraBridge with real C pseudo-code
        bridge = _try_ghidra_bridge()
        if bridge is not None:
            try:
                code = bridge.decompile_function(abs_path, func_addr)
                # Also get function metadata from bridge cache
                func_info = bridge.get_function_by_address(abs_path, func_addr)
                func_name = func_info.get("name", "") if func_info else ""
                signature = func_info.get("signature", "") if func_info else ""
                return self._ok(
                    binary_path=binary_path,
                    func_addr=func_addr,
                    source="ghidra",
                    decompiled_code=code,
                    function_name=func_name,
                    signature=signature,
                )
            except FileNotFoundError:
                pass  # Fall through to objdump
            except Exception as e:
                logger.warning(f"GhidraBridge.decompile_function failed: {e}")

        # Fallback: ObjdumpAdapter
        obj = _get_objdump()
        result = obj.get_function_at(abs_path, func_addr)
        if result.get("success"):
            return self._ok(
                binary_path=binary_path,
                func_addr=func_addr,
                source="objdump",
                decompiled_code=result.get("disassembly", ""),
                function_name=result.get("function_name", ""),
                note="Ghidra not available — showing raw disassembly.",
            )
        return result


class GetCallersTool(FirmwareTool):
    """Get all functions that call the function at func_addr.

    Uses Ghidra's call graph or objdump disassembly analysis.
    """

    name = "get_callers"
    description = (
        "Get the list of functions that CALL the function at the given address. "
        "Returns function addresses. Use this to trace how a vulnerable function "
        "is reached — trace backwards from a dangerous sink (strcpy/system) to "
        "find the attack surface entry points."
    )
    category = "sast"
    timeout = 45.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to the ELF binary.",
            required=True,
        ),
        ToolParameter(
            name="func_addr",
            type="integer",
            description="Address of the target function.",
            required=True,
        ),
        ToolParameter(
            name="extracted_root",
            type="string",
            description="Root of extracted filesystem.",
            required=False,
            default="",
        ),
    ]

    def execute(
        self,
        binary_path: str,
        func_addr: int,
        extracted_root: str = "",
    ) -> dict:
        abs_path = _resolve_binary_path(binary_path, extracted_root or None)

        # Primary: GhidraBridge call graph
        bridge = _try_ghidra_bridge()
        if bridge is not None:
            try:
                cg = bridge.export_call_graph(abs_path)
                func_node = cg.get("call_graph", {}).get(func_addr)
                if func_node:
                    callers = func_node.get("callers", [])
                    return self._ok(
                        binary_path=binary_path,
                        func_addr=func_addr,
                        function_name=func_node.get("name", ""),
                        callers=[c["name"] for c in callers],
                        callers_with_addr=callers,
                        count=len(callers),
                        source="ghidra",
                    )
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"GhidraBridge.export_call_graph failed: {e}")

        # Fallback: ObjdumpAdapter
        obj = _get_objdump()
        func_info = obj.get_function_at(abs_path, func_addr)
        func_name = func_info.get("function_name", "") if func_info.get("success") else f"FUN_{func_addr:08x}"

        result = obj.get_callers_callees(abs_path, func_name)
        if result.get("success"):
            return self._ok(
                binary_path=binary_path,
                func_addr=func_addr,
                function_name=func_name,
                callers=result.get("callers", []),
                count=len(result.get("callers", [])),
                source="objdump",
            )
        return self._error(f"Could not determine function name at 0x{func_addr:x}")


class GetCalleesTool(FirmwareTool):
    """Get all functions called by the function at func_addr.

    This reveals what the function does — if it calls strcpy/system/popen,
    it's immediately flagged as dangerous.
    """

    name = "get_callees"
    description = (
        "Get the list of functions CALLED BY the function at the given address. "
        "This reveals what the function does internally. If the callee list "
        "includes strcpy, system, popen, sprintf, etc., the function is likely "
        "vulnerable to buffer overflow or command injection. Also shows library "
        "calls and helper functions."
    )
    category = "sast"
    timeout = 45.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to the ELF binary.",
            required=True,
        ),
        ToolParameter(
            name="func_addr",
            type="integer",
            description="Address of the target function.",
            required=True,
        ),
        ToolParameter(
            name="extracted_root",
            type="string",
            description="Root of extracted filesystem.",
            required=False,
            default="",
        ),
    ]

    # Dangerous functions to highlight in output
    DANGEROUS = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
        "memcpy", "read", "recv", "recvfrom", "system", "popen",
        "execve", "execvp", "execl", "execlp", "printf", "fprintf",
        "snprintf", "vprintf", "syslog",
    }

    def execute(
        self,
        binary_path: str,
        func_addr: int,
        extracted_root: str = "",
    ) -> dict:
        abs_path = _resolve_binary_path(binary_path, extracted_root or None)

        # Primary: GhidraBridge call graph
        bridge = _try_ghidra_bridge()
        if bridge is not None:
            try:
                cg = bridge.export_call_graph(abs_path)
                func_node = cg.get("call_graph", {}).get(func_addr)
                if func_node:
                    callees = func_node.get("callees", [])
                    callee_names = [c["name"] for c in callees]
                    dangerous = [n for n in callee_names if n in self.DANGEROUS]
                    return self._ok(
                        binary_path=binary_path,
                        func_addr=func_addr,
                        function_name=func_node.get("name", ""),
                        callees=callee_names,
                        callees_with_addr=callees,
                        dangerous_callees=dangerous,
                        has_dangerous_calls=len(dangerous) > 0,
                        count=len(callees),
                        source="ghidra",
                    )
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"GhidraBridge.export_call_graph failed: {e}")

        # Fallback: ObjdumpAdapter
        obj = _get_objdump()
        func_info = obj.get_function_at(abs_path, func_addr)
        func_name = func_info.get("function_name", "") if func_info.get("success") else f"FUN_{func_addr:08x}"

        result = obj.get_callers_callees(abs_path, func_name)
        if result.get("success"):
            callees = result.get("callees", [])
            dangerous = [c for c in callees if c in self.DANGEROUS]
            return self._ok(
                binary_path=binary_path,
                func_addr=func_addr,
                function_name=func_name,
                callees=callees,
                dangerous_callees=dangerous,
                has_dangerous_calls=len(dangerous) > 0,
                count=len(callees),
                source="objdump",
            )
        return self._error(f"Could not determine function name at 0x{func_addr:x}")


class FindStringXrefsTool(FirmwareTool):
    """Find all code locations that reference a given string.

    Useful for finding where error messages, debug strings, or command
    templates (e.g., "reboot", "iptables") are used in the binary.
    """

    name = "find_string_xrefs"
    description = (
        "Find all code addresses that reference a specific string in the binary. "
        "Use this to locate where commands are constructed (e.g., search for "
        "'iptables', 'reboot', 'echo') or where error/debug messages reveal "
        "functionality. Returns a list of code addresses that reference the string."
    )
    category = "sast"
    timeout = 60.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to the ELF binary.",
            required=True,
        ),
        ToolParameter(
            name="target_string",
            type="string",
            description="The string to search for (e.g., 'iptables', 'reboot', '/bin/sh').",
            required=True,
        ),
        ToolParameter(
            name="extracted_root",
            type="string",
            description="Root of extracted filesystem.",
            required=False,
            default="",
        ),
    ]

    def execute(
        self,
        binary_path: str,
        target_string: str,
        extracted_root: str = "",
    ) -> dict:
        abs_path = _resolve_binary_path(binary_path, extracted_root or None)

        # Primary: GhidraBridge string export
        bridge = _try_ghidra_bridge()
        if bridge is not None:
            try:
                strings = bridge.export_strings(abs_path, target_string)
                # Flatten xrefs to address list
                all_xrefs = []
                for s in strings:
                    for xref in s.get("xrefs", []):
                        addr = xref.get("from_address") or xref.get("from_address", 0)
                        if addr:
                            all_xrefs.append(addr)
                all_xrefs = list(set(all_xrefs))
                return self._ok(
                    binary_path=binary_path,
                    target_string=target_string,
                    xrefs=all_xrefs,
                    string_matches=len(strings),
                    count=len(all_xrefs),
                    source="ghidra",
                )
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"GhidraBridge.export_strings failed: {e}")

        # Fallback: ObjdumpAdapter
        obj = _get_objdump()
        xrefs = obj.find_strings(abs_path, target_string)
        return self._ok(
            binary_path=binary_path,
            target_string=target_string,
            xrefs=xrefs,
            count=len(xrefs),
            source="objdump",
        )


class GetFunctionBoundsTool(FirmwareTool):
    """Get the start/end addresses and name of the function containing addr.

    For stripped binaries, returns the auto-generated name (FUN_XXXXXXXX).
    """

    name = "get_function_bounds"
    description = (
        "Given any address within a binary, identify the function that contains "
        "it and return its boundaries (start address, end address, name). "
        "Essential for understanding which function a crash address or a "
        "cross-reference falls within. Works on both stripped and unstripped binaries."
    )
    category = "sast"
    timeout = 30.0

    parameters = [
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to the ELF binary.",
            required=True,
        ),
        ToolParameter(
            name="addr",
            type="integer",
            description="Any address within the binary (doesn't need to be a function start).",
            required=True,
        ),
        ToolParameter(
            name="extracted_root",
            type="string",
            description="Root of extracted filesystem.",
            required=False,
            default="",
        ),
    ]

    def execute(
        self,
        binary_path: str,
        addr: int,
        extracted_root: str = "",
    ) -> dict:
        abs_path = _resolve_binary_path(binary_path, extracted_root or None)

        # Primary: GhidraBridge
        bridge = _try_ghidra_bridge()
        if bridge is not None:
            try:
                func_info = bridge.get_function_by_address(abs_path, addr)
                if func_info:
                    return self._ok(
                        binary_path=binary_path,
                        query_addr=addr,
                        name=func_info.get("name", ""),
                        start=func_info.get("address", 0),
                        end=func_info.get("address", 0) + max(
                            len(func_info.get("pseudo_code", "")), 4
                        ),
                        size=max(len(func_info.get("pseudo_code", "")), 4),
                        signature=func_info.get("signature", ""),
                        source="ghidra",
                    )
                # If not in cache, run single decompile to find function
                bridge.decompile_function(abs_path, addr)
                func_info = bridge.get_function_by_address(abs_path, addr)
                if func_info:
                    return self._ok(
                        binary_path=binary_path,
                        query_addr=addr,
                        name=func_info.get("name", ""),
                        start=func_info.get("address", 0),
                        end=func_info.get("address", 0) + 4,
                        size=4,
                        source="ghidra",
                    )
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"GhidraBridge.get_function_by_address failed: {e}")

        # Fallback: objdump symbol table
        obj = _get_objdump()
        objdump = obj._get_objdump(abs_path)

        try:
            # Get symbol table to find function boundaries
            readelf_prefix = obj._get_cross_prefix(
                *obj._detect_arch(abs_path)[:2]
            )
            readelf = f"{readelf_prefix}readelf" if readelf_prefix else "readelf"

            # Get function symbols with sizes
            sym_result = subprocess.run(
                [objdump, "-t", abs_path],
                capture_output=True, text=True, timeout=30,
            )

            functions = []
            for line in sym_result.stdout.split("\n"):
                if " F " not in line and "F " not in line:
                    # Check if this is a function symbol
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    flags = parts[1] if len(parts) > 1 else ""
                    if "F" not in flags:
                        continue
                else:
                    parts = line.split()

                try:
                    func_addr = int(parts[0], 16)
                    func_size = int(parts[3], 16) if len(parts) > 3 else 0
                    func_name = parts[-1] if len(parts) > 4 else parts[4]
                    functions.append((func_addr, func_size, func_name))
                except (ValueError, IndexError):
                    continue

            if not functions:
                # Try dynamic symbols
                try:
                    dyn_result = subprocess.run(
                        [objdump, "-T", abs_path],
                        capture_output=True, text=True, timeout=30,
                    )
                    for line in dyn_result.stdout.split("\n"):
                        parts = line.split()
                        if len(parts) >= 6 and "DF" in parts[2]:
                            try:
                                func_addr = int(parts[0], 16)
                                func_size = int(parts[4], 16)
                                func_name = parts[-1]
                                functions.append((func_addr, func_size, func_name))
                            except (ValueError, IndexError):
                                continue
                except Exception:
                    pass

            # Sort by address
            functions.sort(key=lambda x: x[0])

            # Find the function containing 'addr'
            containing_func = None
            for func_addr, func_size, func_name in functions:
                if func_addr <= addr < func_addr + max(func_size, 4):
                    containing_func = {
                        "name": func_name,
                        "start": func_addr,
                        "end": func_addr + func_size,
                        "size": func_size,
                    }
                    break

            if containing_func:
                return self._ok(
                    binary_path=binary_path,
                    query_addr=addr,
                    **containing_func,
                )
            else:
                return self._ok(
                    binary_path=binary_path,
                    query_addr=addr,
                    name=f"FUN_{addr:08x}",
                    start=addr,
                    end=addr + 4,
                    size=4,
                    note="Function boundaries estimated (no symbol table entry found).",
                )

        except Exception as e:
            return self._error(f"Failed to get function bounds: {e}")
