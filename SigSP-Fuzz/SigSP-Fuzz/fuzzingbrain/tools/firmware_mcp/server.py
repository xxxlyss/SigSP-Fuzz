"""
Firmware MCP Server Factory

Creates FastMCP server instances with all firmware tools registered.
Follows the same pattern as tools/mcp_factory.py for consistency.

Usage:
    from fuzzingbrain.tools.firmware_mcp import create_firmware_mcp_server

    mcp = create_firmware_mcp_server()
    async with Client(mcp) as client:
        result = await client.call_tool("decompile_function", {
            "binary_path": "/bin/httpd",
            "func_addr": 0x401000,
        })
"""

from typing import Any, Dict, Optional

from fastmcp import FastMCP
from loguru import logger

from .registry import get_registry

# Import tool modules to trigger auto-registration via __init_subclass__
from . import sast_tools  # noqa: F401
from . import dast_tools  # noqa: F401


def create_firmware_mcp_server(
    agent_id: str = "default",
    include_sast: bool = True,
    include_dast: bool = True,
) -> FastMCP:
    """Create an isolated FastMCP server instance with firmware tools.

    Each LLM agent should create its own server to prevent response mixing
    in concurrent execution.

    Args:
        agent_id: Unique identifier for this agent.
        include_sast: Register static analysis tools (Ghidra/objdump).
        include_dast: Register dynamic analysis tools (QEMU).

    Returns:
        FastMCP instance with firmware tools registered as MCP tools.
    """
    mcp = FastMCP(f"FuzzingBrain-Firmware-{agent_id}")
    registry = get_registry()

    if include_sast:
        _register_sast_tools(mcp, registry)
    if include_dast:
        _register_dast_tools(mcp, registry)

    # Always register utility tools
    _register_utility_tools(mcp, registry)

    tool_count = len(mcp._tool_manager._tools) if hasattr(mcp, "_tool_manager") else 0
    logger.info(
        f"Created firmware MCP server '{agent_id}': "
        f"{tool_count} tools registered "
        f"(sast={include_sast}, dast={include_dast})"
    )

    return mcp


def _async_wrapper(tool_instance):
    """Wrap a synchronous tool.execute() as an async function for FastMCP.

    FastMCP expects async tool functions. Since our tools are CPU-bound
    (subprocess calls), we wrap them without actually being async.
    """

    async def _wrapper(**params):
        return tool_instance.run(**params)

    # Copy metadata from the tool instance
    _wrapper.__name__ = tool_instance.name
    _wrapper.__doc__ = tool_instance.description
    _wrapper.__annotations__ = {
        p.name: _type_to_python(p.type)
        for p in tool_instance.parameters
    }
    return _wrapper


def _type_to_python(type_str: str) -> type:
    """Convert JSON Schema type string to Python type."""
    mapping = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    return mapping.get(type_str, str)


def _build_param_signature(params: list) -> str:
    """Build a Python function parameter signature string from ToolParameter list.

    Example output: "binary_path: str, func_addr: int, extracted_root: str = ''"
    """
    parts = []
    type_map = {
        "string": "str", "integer": "int", "number": "float",
        "boolean": "bool", "array": "list", "object": "dict",
    }
    for p in params:
        py_type = type_map.get(p.type, "str")
        if p.required:
            parts.append(f"{p.name}: {py_type}")
        else:
            default_val = p.default
            if isinstance(default_val, str):
                default_repr = repr(default_val)
            elif default_val is None:
                default_repr = "None"
            else:
                default_repr = repr(default_val)
            parts.append(f"{p.name}: {py_type} = {default_repr}")
    return ", ".join(parts)


def _build_call_args(params: list) -> str:
    """Build the arguments string for the tool.run() call.

    Example output: "binary_path=binary_path, func_addr=func_addr, extracted_root=extracted_root"
    """
    return ", ".join(f"{p.name}={p.name}" for p in params)


def _make_tool_wrapper(tool_instance):
    """Create an async wrapper function with explicit parameters for FastMCP.

    FastMCP requires functions with explicit parameters (no **kwargs).
    We dynamically generate the wrapper using exec() so the function
    signature is inspectable.

    The generated function looks like:
        async def decompile_function(binary_path: str, func_addr: int,
                                     extracted_root: str = '') -> dict:
            return decompile_function_tool.run(
                binary_path=binary_path, func_addr=func_addr,
                extracted_root=extracted_root
            )
    """

    param_sig = _build_param_signature(tool_instance.parameters)
    call_args = _build_call_args(tool_instance.parameters)
    func_name = tool_instance.name

    # Build the function source
    source = (
        f"async def {func_name}({param_sig}) -> dict:\n"
        f'    """{tool_instance.description}"""\n'
        f"    return _tool_instance.run({call_args})\n"
    )

    # Execute in a local namespace that captures _tool_instance
    local_ns = {"_tool_instance": tool_instance}
    exec(source, local_ns)
    wrapper = local_ns[func_name]

    return wrapper


def _register_sast_tools(mcp: FastMCP, registry) -> None:
    """Register all SAST tools on the MCP server."""
    tool_names = registry.list_by_category().get("sast", [])
    for name in tool_names:
        tool = registry.get(name)
        if tool:
            wrapper = _make_tool_wrapper(tool)
            mcp.tool(wrapper)


def _register_dast_tools(mcp: FastMCP, registry) -> None:
    """Register all DAST tools on the MCP server."""
    tool_names = registry.list_by_category().get("dast", [])
    for name in tool_names:
        tool = registry.get(name)
        if tool:
            wrapper = _make_tool_wrapper(tool)
            mcp.tool(wrapper)


def _register_utility_tools(mcp: FastMCP, registry) -> None:
    """Register utility/meta tools."""

    @mcp.tool
    async def list_firmware_tools(category: str = None) -> Dict[str, Any]:
        """
        List all available firmware analysis tools.

        Args:
            category: Optional filter — "sast", "dast", or None for all.
        """
        tools = registry.list_tools(category=category)
        grouped = registry.list_by_category()
        return {
            "success": True,
            "total": len(tools),
            "by_category": grouped,
            "tools": tools,
        }

    @mcp.tool
    async def get_firmware_tool_schema(tool_name: str) -> Dict[str, Any]:
        """
        Get the JSON Schema for a specific firmware tool.

        Args:
            tool_name: Name of the tool (e.g., "decompile_function").
        """
        tool = registry.get(tool_name)
        if tool is None:
            return {
                "success": False,
                "error": f"Unknown tool: '{tool_name}'",
            }
        return {
            "success": True,
            "schema": tool.get_schema(),
        }
