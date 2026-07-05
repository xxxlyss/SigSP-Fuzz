"""
Firmware MCP Tools

Provides a unified MCP (Model Context Protocol) server for firmware
vulnerability discovery, exposing SAST (Ghidra) and DAST (QEMU) tools
through a consistent interface.

Architecture:
    FirmwareTool (base)  ←  all tools inherit this
         │
         ├── SAST Tools (sast_tools.py)
         │   ├── decompile_function    — Ghidra/objdump decompile
         │   ├── get_callers          — who calls this function?
         │   ├── get_callees          — what does this function call?
         │   ├── find_string_xrefs    — where is a string referenced?
         │   └── get_function_bounds  — what function contains this addr?
         │
         ├── DAST Tools (dast_tools.py)
         │   ├── start_emulator       — launch QEMU instance
         │   ├── stop_emulator        — kill QEMU instance
         │   ├── inject_input         — send data to emulated binary
         │   ├── get_coverage         — read coverage data
         │   ├── read_memory          — read emulated memory
         │   └── set_breakpoint       — set execution breakpoint
         │
         └── ToolRegistry (registry.py)
             ├── list_tools()             → tool summaries
             ├── get_function_schemas()  → OpenAI Function Calling format
             └── execute_tool(name, **params) → tool execution

Usage:
    from fuzzingbrain.tools.firmware_mcp import (
        get_registry,
        create_firmware_mcp_server,
        get_qemu_manager,
    )

    # Direct registry access
    registry = get_registry()
    result = registry.execute_tool("decompile_function",
        binary_path="/bin/httpd", func_addr=0x401000)

    # OpenAI Function Calling format
    schemas = registry.get_function_schemas(category="sast")

    # MCP server for LLM agents
    mcp = create_firmware_mcp_server(agent_id="agent_1")

    # Clean up QEMU instances
    get_qemu_manager().stop_all()
"""

from .base import FirmwareTool, ToolParameter, ToolTimeoutError, ToolExecutionError
from .registry import (
    ToolRegistry,
    get_registry,
    reset_registry,
    register_tool,
)
from .dast_tools import get_qemu_manager

# Import tool modules to trigger auto-registration via __init_subclass__
from . import sast_tools  # noqa: F401
from . import dast_tools  # noqa: F401

from .server import create_firmware_mcp_server
from .firmware_analyzer import (
    FirmwareAnalyzer,
    AnalysisReport,
    create_firmware_analyzer,
)

__all__ = [
    # Base classes
    "FirmwareTool",
    "ToolParameter",
    "ToolTimeoutError",
    "ToolExecutionError",
    # Registry
    "ToolRegistry",
    "get_registry",
    "reset_registry",
    "register_tool",
    # Server
    "create_firmware_mcp_server",
    # DAST manager
    "get_qemu_manager",
    # LLM Agent
    "FirmwareAnalyzer",
    "AnalysisReport",
    "create_firmware_analyzer",
]
