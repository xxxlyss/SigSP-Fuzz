"""
FirmwareTool Base Class

Abstract base for all firmware analysis tools (SAST + DAST).
Provides timeout protection, structured error responses, and
a uniform interface for the ToolRegistry.

Usage:
    class MyTool(FirmwareTool):
        name = "my_tool"
        description = "Does something useful"

        def execute(self, **params) -> dict:
            ...
"""

import signal
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from loguru import logger


class ToolTimeoutError(Exception):
    """Raised when a tool execution exceeds its timeout."""

    def __init__(self, tool_name: str, timeout: float):
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"Tool '{tool_name}' timed out after {timeout}s")


class ToolExecutionError(Exception):
    """Wraps errors that occur during tool execution."""

    def __init__(self, tool_name: str, original_error: Exception):
        self.tool_name = tool_name
        self.original_error = original_error
        super().__init__(f"Tool '{tool_name}' failed: {original_error}")


@dataclass
class ToolParameter:
    """Describes a single parameter accepted by a tool.

    Used to auto-generate OpenAI Function Calling JSON Schema.
    """

    name: str
    type: str  # "string", "integer", "number", "boolean", "array", "object"
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[list] = None

    def to_json_schema(self) -> dict:
        """Convert to a JSON Schema property entry."""
        schema: Dict[str, Any] = {
            "type": self.type,
            "description": self.description,
        }
        if self.enum:
            schema["enum"] = self.enum
        if self.default is not None:
            schema["default"] = self.default
        return schema


class FirmwareTool(ABC):
    """Abstract base class for all firmware analysis tools.

    Subclasses must define:
      - name: str         — unique tool identifier (snake_case)
      - description: str  — human-readable description (LLM reads this)
      - parameters: list  — ToolParameter definitions (auto-generates JSON Schema)
      - execute(**params) — the actual tool logic

    Optional overrides:
      - timeout: float = 30.0  — per-tool timeout in seconds
      - category: str = ""     — "sast" | "dast" | "utility"

    Error handling:
      - Return {"success": False, "error": "..."} for recoverable errors
      - Raise ToolExecutionError for unrecoverable errors (caught by registry)
    """

    # -- Subclass overrides --------------------------------------------------
    name: str = ""
    description: str = ""
    parameters: list = []  # List[ToolParameter]
    timeout: float = 30.0
    category: str = ""

    def __init_subclass__(cls, **kwargs):
        """Auto-register concrete subclasses when they are defined."""
        super().__init_subclass__(**kwargs)
        # Only register if the subclass defines a name (not the base class)
        if cls.name and cls.name != "firmware_tool":
            from .registry import register_tool_instance

            register_tool_instance(cls())

    # -- Public API ----------------------------------------------------------

    def run(self, **params) -> dict:
        """Execute the tool with timeout protection.

        This is the public entry point called by ToolRegistry.execute_tool().
        It wraps self.execute() with a signal-based timeout alarm.

        Returns:
            {"success": True, ...} on success
            {"success": False, "error": "..."} on failure
        """
        tool_name = self.name or self.__class__.__name__
        logger.debug(f"[{tool_name}] executing with params: {params}")

        try:
            result = self._run_with_timeout(**params)
            if not isinstance(result, dict):
                result = {"success": True, "data": result}
            elif "success" not in result:
                result["success"] = True
            logger.debug(f"[{tool_name}] completed successfully")
            return result
        except ToolTimeoutError as e:
            logger.warning(f"[{tool_name}] timed out after {e.timeout}s")
            return {
                "success": False,
                "error": str(e),
                "error_type": "timeout",
                "tool": tool_name,
            }
        except ToolExecutionError as e:
            logger.error(f"[{tool_name}] execution failed: {e.original_error}")
            return {
                "success": False,
                "error": str(e.original_error),
                "error_type": type(e.original_error).__name__,
                "tool": tool_name,
            }
        except Exception as e:
            logger.error(f"[{tool_name}] unexpected error: {e}\n{traceback.format_exc()}")
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "tool": tool_name,
            }

    @abstractmethod
    def execute(self, **params) -> dict:
        """Core tool logic — override in subclasses.

        Args are validated against self.parameters by the registry before
        this is called.

        Returns:
            dict with at minimum {"success": True/False}. Additional keys
            provide tool-specific data.

        Raises:
            ToolExecutionError: for unrecoverable failures.
        """
        ...

    # -- Introspection -------------------------------------------------------

    def get_schema(self) -> dict:
        """Generate OpenAI Function Calling compatible JSON Schema.

        Returns:
            {
                "type": "function",
                "function": {
                    "name": "...",
                    "description": "...",
                    "parameters": {
                        "type": "object",
                        "properties": {...},
                        "required": [...]
                    }
                }
            }
        """
        properties = {}
        required = []

        for param in self.parameters:
            properties[param.name] = param.to_json_schema()
            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }

    def get_summary(self) -> dict:
        """Get a compact summary for tool listing."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "parameter_count": len(self.parameters),
            "timeout": self.timeout,
        }

    # -- Internal ------------------------------------------------------------

    def _run_with_timeout(self, **params) -> dict:
        """Execute self.execute() with a SIGALRM-based timeout.

        Falls back to no-timeout execution on platforms without SIGALRM
        (e.g., Windows).
        """

        def _timeout_handler(signum, frame):
            raise ToolTimeoutError(self.name, self.timeout)

        # Only use signal-based timeout on Unix
        try:
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(int(self.timeout))
            try:
                result = self.execute(**params)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            return result
        except AttributeError:
            # signal.SIGALRM not available (e.g., Windows) — run without timeout
            return self.execute(**params)

    def _validate_params(self, params: dict) -> Optional[str]:
        """Validate incoming parameters against self.parameters schema.

        Returns:
            Error message string if invalid, None if valid.
        """
        param_map = {p.name: p for p in self.parameters}

        # Check required params
        for p in self.parameters:
            if p.required and p.name not in params:
                return f"Missing required parameter: '{p.name}'"

        # Check unknown params (strict mode — warn but don't fail)
        for key in params:
            if key not in param_map:
                logger.warning(
                    f"[{self.name}] unknown parameter '{key}' — will be passed through"
                )

        return None

    def _error(self, message: str, **extra) -> dict:
        """Convenience: build a structured error response."""
        return {"success": False, "error": message, **extra}

    def _ok(self, **data) -> dict:
        """Convenience: build a structured success response."""
        return {"success": True, **data}
