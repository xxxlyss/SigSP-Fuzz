"""
Tool Registry with Decorator-based Auto-Registration.

Provides:
  - @register_tool: decorator to register tool classes
  - ToolRegistry:  manages all registered tools, outputs OpenAI Function Calling format

Usage:
    # Auto-registration via subclassing FirmwareTool (in base.py)
    class DecompileFunction(FirmwareTool):
        name = "decompile_function"
        ...

    # Or explicit decorator
    @register_tool
    class MyCustomTool(FirmwareTool):
        name = "my_custom_tool"
        ...

    # Query registry
    registry = get_registry()
    schemas = registry.list_tools()  # OpenAI Function Calling format
    result = registry.execute_tool("decompile_function", binary_path="...", func_addr=0x1000)
"""

import threading
from typing import Any, Dict, List, Optional

from loguru import logger


# ---------------------------------------------------------------------------
# Global Tool Registry (singleton per process)
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Manages registered firmware tools.

    Thread-safe. Provides OpenAI Function Calling compatible output.

    Usage:
        registry = ToolRegistry()
        registry.register(my_tool_instance)
        schemas = registry.list_tools()
        result = registry.execute_tool("tool_name", param1=val1)
    """

    def __init__(self):
        self._tools: Dict[str, "FirmwareTool"] = {}  # type: ignore
        self._lock = threading.RLock()

    # -- Registration -------------------------------------------------------

    def register(self, tool: "FirmwareTool") -> None:  # type: ignore
        """Register a tool instance.

        Args:
            tool: A FirmwareTool instance with a unique .name

        Raises:
            ValueError: if a tool with the same name is already registered.
        """
        with self._lock:
            name = tool.name
            if not name:
                raise ValueError(f"Tool has no name: {tool.__class__.__name__}")
            if name in self._tools:
                existing = self._tools[name].__class__.__name__
                logger.warning(
                    f"Tool '{name}' already registered ({existing}). "
                    f"Overwriting with {tool.__class__.__name__}."
                )
            self._tools[name] = tool
            logger.debug(
                f"Registered tool: {name} [{tool.category}] — "
                f"{len(tool.parameters)} params"
            )

    def unregister(self, name: str) -> bool:
        """Remove a tool from the registry.

        Returns:
            True if the tool was removed, False if it wasn't registered.
        """
        with self._lock:
            if name in self._tools:
                del self._tools[name]
                logger.debug(f"Unregistered tool: {name}")
                return True
            return False

    def get(self, name: str) -> Optional["FirmwareTool"]:  # type: ignore
        """Get a tool by name."""
        with self._lock:
            return self._tools.get(name)

    # -- Listing / Schema Output --------------------------------------------

    def list_tools(self, category: Optional[str] = None) -> List[dict]:
        """List all registered tools.

        Args:
            category: Optional filter ("sast", "dast", "utility").

        Returns:
            List of tool summaries (name, description, category, parameter_count, timeout).
        """
        with self._lock:
            tools = list(self._tools.values())
            if category:
                tools = [t for t in tools if t.category == category]
            return [t.get_summary() for t in tools]

    def get_function_schemas(
        self, category: Optional[str] = None
    ) -> List[dict]:
        """Get OpenAI Function Calling compatible JSON schemas for all tools.

        Args:
            category: Optional filter ("sast", "dast", "utility").

        Returns:
            List of function schemas, each with:
                {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}}
        """
        with self._lock:
            tools = list(self._tools.values())
            if category:
                tools = [t for t in tools if t.category == category]
            return [t.get_schema() for t in tools]

    def list_by_category(self) -> Dict[str, List[str]]:
        """Get tools grouped by category.

        Returns:
            {"sast": ["decompile_function", ...], "dast": ["start_emulator", ...]}
        """
        with self._lock:
            grouped: Dict[str, List[str]] = {}
            for tool in self._tools.values():
                cat = tool.category or "other"
                grouped.setdefault(cat, []).append(tool.name)
            return grouped

    # -- Execution ----------------------------------------------------------

    def execute_tool(self, name: str, **params) -> dict:
        """Execute a registered tool by name.

        Args:
            name: Tool name (must be registered).
            **params: Tool-specific parameters (validated by the tool).

        Returns:
            Tool result dict — always has "success": True/False.

        Raises:
            KeyError: if the tool name is not registered.
        """
        tool = self.get(name)
        if tool is None:
            available = sorted(self._tools.keys())
            return {
                "success": False,
                "error": f"Unknown tool: '{name}'. Available: {available}",
                "error_type": "unknown_tool",
            }

        # Validate parameters
        validation_error = tool._validate_params(params)
        if validation_error:
            return {
                "success": False,
                "error": validation_error,
                "error_type": "invalid_parameters",
                "tool": name,
            }

        return tool.run(**params)

    def execute_tool_batch(
        self, calls: List[Dict[str, Any]]
    ) -> List[dict]:
        """Execute multiple tools sequentially.

        Args:
            calls: List of {"name": str, "params": dict} entries.

        Returns:
            List of result dicts, one per call (same order).
        """
        results = []
        for i, call in enumerate(calls):
            name = call.get("name", "")
            params = call.get("params", {})
            try:
                result = self.execute_tool(name, **params)
            except Exception as e:
                result = {
                    "success": False,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            results.append(result)
        return results

    @property
    def tool_count(self) -> int:
        """Number of registered tools."""
        return len(self._tools)


# ---------------------------------------------------------------------------
# Singleton access
# ---------------------------------------------------------------------------

_registry: Optional[ToolRegistry] = None
_registry_lock = threading.Lock()


def get_registry() -> ToolRegistry:
    """Get the global ToolRegistry singleton."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ToolRegistry()
    return _registry


def reset_registry() -> None:
    """Reset the global registry (mainly for testing)."""
    global _registry
    with _registry_lock:
        _registry = ToolRegistry()


# ---------------------------------------------------------------------------
# Decorator-based registration
# ---------------------------------------------------------------------------

# Registry of classes that were decorated but not yet instantiated
_pending_classes: List[type] = []


def register_tool(cls=None, *, name: Optional[str] = None):
    """Decorator: register a FirmwareTool subclass.

    Can be used as @register_tool or @register_tool(name="custom_name").

    When applied to a class, the class is instantiated and registered
    at module import time. For classes that need runtime dependencies,
    use deferred=True to delay instantiation.

    Usage:
        @register_tool
        class MyTool(FirmwareTool):
            name = "my_tool"
            ...

        @register_tool(name="custom_tool_name")
        class AnotherTool(FirmwareTool):
            ...
    """

    def _wrap(cls_to_register):
        # Store the class for later instantiation
        _pending_classes.append(cls_to_register)

        # If the class has a concrete name (not the abstract base),
        # instantiate and register immediately
        if (
            hasattr(cls_to_register, "name")
            and cls_to_register.name
            and cls_to_register.name != "firmware_tool"
        ):
            try:
                instance = cls_to_register()
                registry = get_registry()
                registry.register(instance)
                logger.debug(
                    f"@register_tool: {cls_to_register.__name__} → {instance.name}"
                )
            except Exception as e:
                logger.warning(
                    f"@register_tool: failed to instantiate "
                    f"{cls_to_register.__name__}: {e}"
                )

        if name is not None and hasattr(cls_to_register, "name"):
            cls_to_register.name = name

        return cls_to_register

    # Support both @register_tool and @register_tool(name="...")
    if cls is None:
        return _wrap
    return _wrap(cls)


def register_tool_instance(tool: "FirmwareTool") -> None:  # type: ignore
    """Register a pre-instantiated tool (called by FirmwareTool.__init_subclass__)."""
    registry = get_registry()
    registry.register(tool)
