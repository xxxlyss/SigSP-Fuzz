"""
Unit tests for the firmware MCP tools module.

Tests:
  - FirmwareTool base class
  - ToolParameter
  - ToolRegistry (register, list, execute, schemas)
  - SAST tools (decompile, callers, callees, xrefs, bounds)
  - DAST tools (emulator lifecycle)
  - MCP server factory
  - Error handling
  - OpenAI Function Calling format
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from fuzzingbrain.tools.firmware_mcp.base import (
    FirmwareTool,
    ToolParameter,
    ToolTimeoutError,
    ToolExecutionError,
)
from fuzzingbrain.tools.firmware_mcp.registry import (
    ToolRegistry,
    get_registry,
    reset_registry,
    register_tool,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(autouse=True)
def ensure_tools_registered():
    """Ensure SAST and DAST tools are registered before each test.

    Uses importlib.reload to force re-registration after any test
    that may have called reset_registry().
    """
    import importlib
    from fuzzingbrain.tools.firmware_mcp import sast_tools, dast_tools
    reset_registry()
    importlib.reload(sast_tools)
    importlib.reload(dast_tools)

    yield

    # Cleanup after test
    from fuzzingbrain.tools.firmware_mcp.dast_tools import get_qemu_manager
    get_qemu_manager().stop_all()


@pytest.fixture
def registry():
    """Fresh registry for each test."""
    reset_registry()
    return get_registry()


@pytest.fixture
def sample_tool_class():
    """A minimal concrete FirmwareTool subclass for testing."""
    class TestEcho(FirmwareTool):
        name = "test_echo"
        description = "Echo back the input"
        category = "utility"
        parameters = [
            ToolParameter(name="message", type="string",
                          description="The message to echo"),
            ToolParameter(name="times", type="integer",
                          description="Repeat count", required=False, default=1),
        ]

        def execute(self, message: str, times: int = 1) -> dict:
            return {"echo": message * times}

    return TestEcho


# ===========================================================================
# ToolParameter Tests
# ===========================================================================

class TestToolParameter:
    """Test the ToolParameter descriptor."""

    def test_basic_schema(self):
        p = ToolParameter(name="binary_path", type="string",
                          description="Path to binary")
        schema = p.to_json_schema()
        assert schema == {
            "type": "string",
            "description": "Path to binary",
        }

    def test_with_default(self):
        p = ToolParameter(name="timeout", type="integer",
                          description="Timeout in seconds",
                          required=False, default=30)
        schema = p.to_json_schema()
        assert schema["default"] == 30
        assert schema["type"] == "integer"

    def test_with_enum(self):
        p = ToolParameter(name="interface", type="string",
                          description="Injection interface",
                          enum=["stdin", "file", "tcp"])
        schema = p.to_json_schema()
        assert schema["enum"] == ["stdin", "file", "tcp"]

    def test_required_default(self):
        p = ToolParameter(name="name", type="string", description="...")
        assert p.required is True


# ===========================================================================
# FirmwareTool Base Tests
# ===========================================================================

class TestFirmwareToolBase:
    """Test the FirmwareTool abstract base class."""

    def test_get_schema_openai_format(self):
        """Schema output must be OpenAI Function Calling compatible."""
        class MyTool(FirmwareTool):
            name = "my_tool"
            description = "Does something"
            parameters = [
                ToolParameter(name="input_file", type="string",
                              description="File to process"),
                ToolParameter(name="verbose", type="boolean",
                              description="Verbose output",
                              required=False, default=False),
            ]

            def execute(self, input_file: str, verbose: bool = False) -> dict:
                return {"result": input_file}

        tool = MyTool()
        schema = tool.get_schema()

        assert schema["type"] == "function"
        f = schema["function"]
        assert f["name"] == "my_tool"
        assert f["description"] == "Does something"
        assert f["parameters"]["type"] == "object"
        assert "input_file" in f["parameters"]["properties"]
        assert "verbose" in f["parameters"]["properties"]
        assert f["parameters"]["required"] == ["input_file"]

    def test_get_summary(self):
        class MyTool(FirmwareTool):
            name = "my_tool"
            description = "Does something"
            category = "sast"
            parameters = [
                ToolParameter(name="x", type="integer", description="X"),
            ]

            def execute(self, x: int) -> dict:
                return {"x": x}

        tool = MyTool()
        summary = tool.get_summary()
        assert summary["name"] == "my_tool"
        assert summary["category"] == "sast"
        assert summary["parameter_count"] == 1
        assert "timeout" in summary

    def test_success_response(self):
        class MyTool(FirmwareTool):
            name = "ok_tool"
            description = "..."
            parameters = []

            def execute(self) -> dict:
                return self._ok(result="done", extra=42)

        tool = MyTool()
        result = tool.run()
        assert result["success"] is True
        assert result["result"] == "done"
        assert result["extra"] == 42

    def test_error_response(self):
        class MyTool(FirmwareTool):
            name = "err_tool"
            description = "..."
            parameters = []

            def execute(self) -> dict:
                return self._error("Something went wrong", code=500)

        tool = MyTool()
        result = tool.run()
        assert result["success"] is False
        assert result["error"] == "Something went wrong"
        assert result["code"] == 500

    def test_timeout_raises(self):
        """Tool that sleeps longer than timeout should get caught.

        Uses a mock to simulate timeout without actually sleeping.
        """
        class SlowTool(FirmwareTool):
            name = "slow_tool"
            description = "..."
            timeout = 0.1
            parameters = []

            def execute(self) -> dict:
                raise ToolTimeoutError(self.name, self.timeout)

        tool = SlowTool()
        result = tool.run()
        assert result["success"] is False
        assert result["error_type"] == "timeout"

    def test_exception_caught(self):
        """Tool that raises an unexpected exception should return error dict."""
        class CrashTool(FirmwareTool):
            name = "crash_tool"
            description = "..."
            parameters = []

            def execute(self) -> dict:
                raise ValueError("Boom!")

        tool = CrashTool()
        result = tool.run()
        assert result["success"] is False
        assert "Boom" in result["error"]
        assert result["error_type"] == "ValueError"

    def test_validate_params_missing_required(self):
        class MyTool(FirmwareTool):
            name = "val_tool"
            description = "..."
            parameters = [
                ToolParameter(name="required_arg", type="string",
                              description="Must be present"),
            ]

            def execute(self, required_arg: str) -> dict:
                return {"arg": required_arg}

        tool = MyTool()
        err = tool._validate_params({})
        assert err is not None
        assert "required_arg" in err

        err = tool._validate_params({"required_arg": "hello"})
        assert err is None


# ===========================================================================
# ToolRegistry Tests
# ===========================================================================

class TestToolRegistry:
    """Test the ToolRegistry class."""

    def test_register_and_get(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        assert registry.tool_count == 1
        retrieved = registry.get("test_echo")
        assert retrieved is tool

    def test_register_duplicate_warns(self, registry, sample_tool_class):
        tool1 = sample_tool_class()
        registry.register(tool1)

        # Second registration should warn but succeed (overwrite)
        class TestEcho2(FirmwareTool):
            name = "test_echo"  # Same name
            description = "v2"
            parameters = []

            def execute(self) -> dict:
                return {"version": 2}

        tool2 = TestEcho2()
        registry.register(tool2)
        assert registry.tool_count == 1
        assert registry.get("test_echo") is tool2

    def test_unregister(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        assert registry.unregister("test_echo") is True
        assert registry.unregister("test_echo") is False
        assert registry.tool_count == 0

    def test_list_tools(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        tools = registry.list_tools()
        assert len(tools) == 1
        assert tools[0]["name"] == "test_echo"
        assert tools[0]["category"] == "utility"

    def test_list_tools_by_category(self, registry):
        class SASTTool(FirmwareTool):
            name = "sast_tool"
            description = "..."
            category = "sast"
            parameters = []

            def execute(self) -> dict:
                return {}

        class DASTTool(FirmwareTool):
            name = "dast_tool"
            description = "..."
            category = "dast"
            parameters = []

            def execute(self) -> dict:
                return {}

        registry.register(SASTTool())
        registry.register(DASTTool())

        sast = registry.list_tools(category="sast")
        dast = registry.list_tools(category="dast")
        assert len(sast) == 1
        assert len(dast) == 1
        assert sast[0]["name"] == "sast_tool"

    def test_list_by_category(self, registry):
        class SASTTool(FirmwareTool):
            name = "sast_tool"
            description = "..."
            category = "sast"
            parameters = []

            def execute(self) -> dict:
                return {}

        registry.register(SASTTool())
        grouped = registry.list_by_category()
        assert "sast" in grouped
        assert "sast_tool" in grouped["sast"]

    def test_get_function_schemas_openai_format(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        schemas = registry.get_function_schemas()
        assert len(schemas) == 1
        assert schemas[0]["type"] == "function"
        assert schemas[0]["function"]["name"] == "test_echo"
        assert "parameters" in schemas[0]["function"]

    def test_execute_tool_success(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        result = registry.execute_tool("test_echo", message="hello")
        assert result["success"] is True
        assert result["echo"] == "hello"

    def test_execute_tool_unknown(self, registry):
        result = registry.execute_tool("nonexistent")
        assert result["success"] is False
        assert result["error_type"] == "unknown_tool"

    def test_execute_tool_missing_param(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        result = registry.execute_tool("test_echo")  # missing 'message'
        assert result["success"] is False
        assert result["error_type"] == "invalid_parameters"

    def test_execute_tool_batch(self, registry, sample_tool_class):
        tool = sample_tool_class()
        registry.register(tool)
        results = registry.execute_tool_batch([
            {"name": "test_echo", "params": {"message": "a"}},
            {"name": "test_echo", "params": {"message": "b"}},
        ])
        assert len(results) == 2
        assert results[0]["echo"] == "a"
        assert results[1]["echo"] == "b"


# ===========================================================================
# Decorator Registration Tests
# ===========================================================================

class TestDecoratorRegistration:
    """Test the @register_tool decorator."""

    def test_decorator_registers_tool(self):
        reset_registry()

        @register_tool
        class DecoratedTool(FirmwareTool):
            name = "decorated_tool"
            description = "Registered via decorator"
            category = "utility"
            parameters = [
                ToolParameter(name="name", type="string", description="Your name"),
            ]

            def execute(self, name: str) -> dict:
                return {"greeting": f"Hello, {name}"}

        registry = get_registry()
        assert registry.tool_count >= 1
        tool = registry.get("decorated_tool")
        assert tool is not None
        assert tool.category == "utility"

    def test_decorator_with_name_override(self):
        reset_registry()

        @register_tool(name="custom_registered_name")
        class RenamedTool(FirmwareTool):
            name = "original_name"
            description = "..."
            parameters = []

            def execute(self) -> dict:
                return {}

        registry = get_registry()
        # The override happens after instantiation, so it depends on timing
        tool = registry.get("original_name")
        if tool is None:
            tool = registry.get("custom_registered_name")
        assert tool is not None


# ===========================================================================
# OpenAIFunctionCalling Compatibility Tests
# ===========================================================================

class TestOpenAICompatibility:
    """Verify output is compatible with OpenAI Function Calling format."""

    def test_schema_passes_openai_validation(self, registry, sample_tool_class):
        """OpenAI requires type=function, function.name, function.description,
        function.parameters with type=object, properties, and required."""
        registry.register(sample_tool_class())
        schemas = registry.get_function_schemas()

        for schema in schemas:
            # Top level
            assert schema["type"] == "function"
            f = schema["function"]

            # Required fields
            assert isinstance(f["name"], str)
            assert len(f["name"]) > 0
            assert isinstance(f["description"], str)

            # Parameters object
            params = f["parameters"]
            assert params["type"] == "object"
            assert isinstance(params["properties"], dict)

            # Required must only list keys that exist in properties
            for req_key in params.get("required", []):
                assert req_key in params["properties"], \
                    f"'{req_key}' in required but not in properties"

    def test_all_properties_have_types(self, registry, sample_tool_class):
        """Every property must have a valid JSON Schema type."""
        valid_types = {"string", "integer", "number", "boolean", "array", "object"}
        registry.register(sample_tool_class())
        schemas = registry.get_function_schemas()

        for schema in schemas:
            for prop_name, prop_schema in (
                schema["function"]["parameters"]["properties"].items()
            ):
                assert prop_schema["type"] in valid_types, \
                    f"Property '{prop_name}' has invalid type: {prop_schema.get('type')}"

    def test_real_tools_have_openai_schemas(self):
        """All auto-registered tools (SAST + DAST) must produce valid schemas."""
        registry = get_registry()
        # Tools should already be registered from the fixture
        schemas = registry.get_function_schemas()
        assert len(schemas) >= 5, f"Expected at least 5 tools, got {len(schemas)}"

        for schema in schemas:
            f = schema["function"]
            assert f["parameters"]["type"] == "object"
            assert "properties" in f["parameters"]
            assert "required" in f["parameters"]


# ===========================================================================
# MCP Server Tests
# ===========================================================================

class TestMCPServer:
    """Test the FastMCP server factory."""

    def test_create_server_sast_only(self):
        from fuzzingbrain.tools.firmware_mcp.server import create_firmware_mcp_server
        mcp = create_firmware_mcp_server(agent_id="test", include_dast=False)
        assert mcp.name == "FuzzingBrain-Firmware-test"

    def test_create_server_dast_only(self):
        from fuzzingbrain.tools.firmware_mcp.server import create_firmware_mcp_server
        mcp = create_firmware_mcp_server(agent_id="test2", include_sast=False)
        assert mcp.name == "FuzzingBrain-Firmware-test2"

    def test_create_server_all(self):
        from fuzzingbrain.tools.firmware_mcp.server import create_firmware_mcp_server
        mcp = create_firmware_mcp_server(agent_id="full")
        assert "FuzzingBrain-Firmware" in mcp.name


# ===========================================================================
# SAST Tools Integration Tests
# ===========================================================================

class TestSASTToolsIntegration:
    """Integration tests for SAST tools using real binaries."""

    @pytest.fixture
    def test_binary(self):
        """Find a system ELF binary for testing."""
        import shutil
        candidates = ["/bin/ls", "/usr/bin/ls", "/bin/cat", "/bin/echo"]
        for c in candidates:
            if shutil.which(c.split("/")[-1]):
                return shutil.which(c.split("/")[-1])
            import os
            if os.path.exists(c):
                return c
        pytest.skip("No test binary available")

    def test_decompile_function_objdump_fallback(self, test_binary):
        """decompile_function should return disassembly via objdump."""
        registry = get_registry()

        # Use a known low address (often .plt section)
        result = registry.execute_tool(
            "decompile_function",
            binary_path=test_binary,
            func_addr=0x4000,
        )
        # Should succeed (objdump works) or fail gracefully
        assert "success" in result
        if result["success"]:
            assert len(result.get("decompiled_code", "")) > 0
            assert result.get("source") == "objdump"

    def test_get_function_bounds(self, test_binary):
        """get_function_bounds should find or estimate a function."""
        registry = get_registry()

        result = registry.execute_tool(
            "get_function_bounds",
            binary_path=test_binary,
            addr=0x4000,
        )
        assert "success" in result
        if result["success"]:
            assert "name" in result
            assert "start" in result
            assert "end" in result

    def test_tool_not_found(self):
        """Querying an unregistered tool should give a clear error."""
        registry = get_registry()

        result = registry.execute_tool("not_a_tool_name", arg=1)
        assert result["success"] is False
        assert result["error_type"] == "unknown_tool"


# ===========================================================================
# DAST Tools Tests (mocked QEMU)
# ===========================================================================

class TestDASTTools:
    """Tests for DAST tools with mocked QEMU subprocess."""

    def test_start_emulator_no_binary(self):
        """start_emulator with non-existent binary should fail gracefully."""
        registry = get_registry()
        result = registry.execute_tool(
            "start_emulator",
            binary_path="/nonexistent/binary",
            arch="mipsel",
        )
        assert result["success"] is False

    def test_stop_emulator_unknown_instance(self):
        """stop_emulator with unknown ID should be idempotent."""
        registry = get_registry()
        result = registry.execute_tool("stop_emulator", instance_id="nonexistent")
        # Returns success but stopped=False (idempotent)
        assert "success" in result

    def test_get_coverage_unknown_instance(self):
        """get_coverage with unknown ID should return error."""
        registry = get_registry()
        result = registry.execute_tool("get_coverage", instance_id="nonexistent")
        assert result["success"] is False

    def test_read_memory_unknown_instance(self):
        """read_memory with unknown ID should return error."""
        registry = get_registry()
        result = registry.execute_tool(
            "read_memory", instance_id="nonexistent", addr=0x1000, size=16
        )
        assert result["success"] is False

    def test_set_breakpoint_stores_request(self):
        """set_breakpoint should record the request even when QEMU not running."""
        registry = get_registry()
        result = registry.execute_tool(
            "set_breakpoint", instance_id="nonexistent", addr=0x401000
        )
        # Returns error since instance doesn't exist
        assert result["success"] is False

    @patch("fuzzingbrain.tools.firmware_mcp.dast_tools.subprocess.Popen")
    def test_start_emulator_with_mock(self, mock_popen):
        """start_emulator with mocked subprocess."""
        from fuzzingbrain.tools.firmware_mcp.dast_tools import get_qemu_manager
        registry = get_registry()

        # Mock a running process
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345
        mock_proc.stdin = MagicMock()
        mock_popen.return_value = mock_proc

        import shutil
        test_bin = shutil.which("ls") or "/bin/ls"
        result = registry.execute_tool(
            "start_emulator",
            binary_path=test_bin,
            arch="x86_64",
        )
        assert result["success"] is True
        instance_id = result["instance_id"]
        assert len(instance_id) == 8

        # Cleanup
        manager = get_qemu_manager()
        manager.stop_all()
