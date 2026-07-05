"""
Tests for firmware static analysis data models and call graph operations.
"""

import json
import tempfile
import os
from pathlib import Path

from fuzzingbrain.static.models import (
    BinaryInfo,
    FunctionInfo,
    CallGraph,
    CallGraphNode,
    StringRef,
    ExtractResult,
    AnalysisResult,
)
from fuzzingbrain.static.callgraph import CallGraphBuilder, CallGraphAnalyzer


class TestBinaryInfo:
    def test_basic_construction(self):
        bi = BinaryInfo(
            path="bin/httpd",
            arch="arm",
            bits=32,
            endian="little",
            file_type="web_server",
            stripped=True,
            entry_point=0x10000,
        )
        assert bi.path == "bin/httpd"
        assert bi.arch == "arm"
        assert bi.arch_tuple == ("arm", 32, "little")
        assert bi.is_stripped is True

    def test_sections_default(self):
        bi = BinaryInfo(
            path="test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=False, entry_point=0x4000,
        )
        assert bi.sections == []

    def test_sections_provided(self):
        bi = BinaryInfo(
            path="test", arch="arm", bits=64, endian="little",
            file_type="library", stripped=True, entry_point=0,
            sections=[".text", ".data", ".rodata"],
        )
        assert len(bi.sections) == 3


class TestFunctionInfo:
    def test_basic_construction(self):
        fi = FunctionInfo(
            name="http_cgi_handler",
            address=0x1234,
            pseudo_code="void handler() { strcpy(buf, input); }",
            assembly="push {lr}\nbl strcpy",
            callers=["main"],
            callees=["strcpy", "sprintf"],
            parameters=2,
            has_unsafe_calls=True,
            dangerous_funcs=["strcpy"],
        )
        assert fi.name == "http_cgi_handler"
        assert fi.is_stripped_name is False
        assert fi.dangeous_call_count == 1

    def test_stripped_name_detection(self):
        fi = FunctionInfo(
            name="FUN_00001234",
            address=0x1234,
            pseudo_code="",
            has_unsafe_calls=False,
        )
        assert fi.is_stripped_name is True

    def test_defaults(self):
        fi = FunctionInfo(
            name="test_func",
            address=0x100,
            pseudo_code="",
            assembly="",
        )
        assert fi.callers == []
        assert fi.callees == []
        assert fi.parameters == 0
        assert fi.complexity == 0
        assert fi.has_unsafe_calls is False
        assert fi.dangerous_funcs == []
        assert fi.strings_used == []


class TestCallGraph:
    def setup_method(self):
        self.cg = CallGraph(binary_path="bin/httpd")

    def test_empty_graph(self):
        assert self.cg.node_count == 0
        assert self.cg.get_callers("nonexistent") == []
        assert self.cg.get_callees("nonexistent") == []

    def test_add_and_query_nodes(self):
        self.cg.nodes["main"] = CallGraphNode(
            function_name="main",
            address=0x1000,
            callers=["_start"],
            callees=["httpd_main"],
        )
        self.cg.nodes["httpd_main"] = CallGraphNode(
            function_name="httpd_main",
            address=0x2000,
            callers=["main"],
            callees=["process_request"],
        )
        self.cg.nodes["process_request"] = CallGraphNode(
            function_name="process_request",
            address=0x3000,
            callers=["httpd_main"],
            callees=["strcpy"],
        )

        assert self.cg.node_count == 3
        assert self.cg.get_callers("httpd_main") == ["main"]
        assert self.cg.get_callees("main") == ["httpd_main"]

    def test_call_path_direct(self):
        self.cg.nodes["main"] = CallGraphNode(
            "main", 0x1000, callers=[], callees=["target"]
        )
        self.cg.nodes["target"] = CallGraphNode(
            "target", 0x2000, callers=["main"], callees=[]
        )
        path = self.cg.get_call_path("main", "target")
        assert path == ["main", "target"]

    def test_call_path_chain(self):
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=["b"])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=["a"], callees=["c"])
        self.cg.nodes["c"] = CallGraphNode("c", 2, callers=["b"], callees=["d"])
        self.cg.nodes["d"] = CallGraphNode("d", 3, callers=["c"], callees=[])
        path = self.cg.get_call_path("a", "d")
        assert path == ["a", "b", "c", "d"]

    def test_call_path_not_found(self):
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=[])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=[], callees=[])
        path = self.cg.get_call_path("a", "b")
        assert path is None

    def test_call_path_max_depth(self):
        """Verify max_depth prevents infinite loops."""
        self.cg.nodes["a"] = CallGraphNode("a", 0, callers=[], callees=["b"])
        self.cg.nodes["b"] = CallGraphNode("b", 1, callers=["a"], callees=["a"])  # cycle
        path = self.cg.get_call_path("a", "b", max_depth=1)
        assert path == ["a", "b"]
        path_cycle = self.cg.get_call_path("a", "b", max_depth=0)
        assert path_cycle is None


class TestCallGraphBuilder:
    def test_build_from_functions(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=["_start"], callees=["parse"]),
            FunctionInfo(name="parse", address=0x2000, pseudo_code="",
                        callers=["main"], callees=["strcpy"]),
        ]
        builder = CallGraphBuilder()
        cg = builder.build(funcs, binary_path="bin/test")
        assert cg.node_count == 2
        assert cg.binary_path == "bin/test"
        assert cg.get_call_path("main", "parse") == ["main", "parse"]

    def test_build_from_json(self):
        json_data = {
            "functions": [
                {"name": "main", "address": 4096, "callers": ["_start"], "callees": ["foo"]},
                {"name": "foo", "address": 8192, "callers": ["main"], "callees": ["bar"]},
                {"name": "bar", "address": 12288, "callers": ["foo"], "callees": []},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(json_data, f)
            tmp_path = f.name

        try:
            builder = CallGraphBuilder()
            cg = builder.build_from_json(tmp_path, "bin/test")
            assert cg.node_count == 3
            path = cg.get_call_path("main", "bar")
            assert path == ["main", "foo", "bar"]
        finally:
            os.unlink(tmp_path)

    def test_to_json(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=[], callees=["foo"]),
        ]
        builder = CallGraphBuilder()
        cg = builder.build(funcs, binary_path="bin/test")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            builder.to_json(cg, tmp_path)
            with open(tmp_path) as f:
                loaded = json.load(f)
            assert loaded["binary_path"] == "bin/test"
            assert loaded["node_count"] == 1
            assert len(loaded["functions"]) == 1
        finally:
            os.unlink(tmp_path)


class TestCallGraphAnalyzer:
    def setup_method(self):
        funcs = [
            FunctionInfo(name="main", address=0x1000, pseudo_code="",
                        callers=["_start"], callees=["http_handler", "init"]),
            FunctionInfo(name="http_handler", address=0x2000, pseudo_code="",
                        callers=["main"], callees=["parse_request"]),
            FunctionInfo(name="parse_request", address=0x3000, pseudo_code="",
                        callers=["http_handler"], callees=["strcpy", "sprintf"]),
            FunctionInfo(name="init", address=0x4000, pseudo_code="",
                        callers=["main"], callees=[]),
        ]
        builder = CallGraphBuilder()
        self.cg = builder.build(funcs, binary_path="bin/httpd")
        self.analyzer = CallGraphAnalyzer(self.cg)

    def test_find_reachable(self):
        reachable = self.analyzer.find_reachable_functions("main")
        assert "http_handler" in reachable
        assert "parse_request" in reachable
        assert "init" in reachable

    def test_find_reachable_nonexistent(self):
        reachable = self.analyzer.find_reachable_functions("nonexistent")
        assert reachable == set()

    def test_find_dangerous_calls(self):
        dangerous = self.analyzer.find_dangerous_calls("main")
        dangerous_sinks = [d[0] for d in dangerous]
        assert "strcpy" in dangerous_sinks
        assert "sprintf" in dangerous_sinks

    def test_find_entry_points(self):
        entries = self.analyzer.find_entry_points()
        assert "main" in entries  # called by _start


class TestStringRef:
    def test_categorize_url(self):
        sr = StringRef(value="http://192.168.1.1/admin", address=0x5000)
        assert sr.categorize() == "url"

    def test_categorize_port(self):
        sr = StringRef(value="Listening on :80", address=0x6000)
        assert sr.categorize() == "port"

    def test_categorize_credential(self):
        sr = StringRef(value="admin:password123", address=0x7000)
        assert sr.categorize() == "credential"

    def test_categorize_path(self):
        sr = StringRef(value="/etc/shadow", address=0x8000)
        assert sr.categorize() == "path"

    def test_categorize_debug(self):
        sr = StringRef(value="TODO: fix this", address=0x9000)
        assert sr.categorize() == "debug"

    def test_categorize_other(self):
        sr = StringRef(value="some random text", address=0xA000)
        assert sr.categorize() == "other"


class TestExtractResult:
    def test_success(self):
        result = ExtractResult(
            firmware_path="test.bin",
            output_dir="extracted/",
            success=True,
            filesystem_type="squashfs",
            file_count=150,
        )
        assert result.success is True
        assert result.filesystem_type == "squashfs"

    def test_failure(self):
        result = ExtractResult(
            firmware_path="test.bin",
            output_dir="extracted/",
            success=False,
            error="binwalk not found",
        )
        assert result.success is False
        assert result.error == "binwalk not found"


class TestAnalysisResult:
    def test_basic(self):
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=True, entry_point=0x10000,
        )
        result = AnalysisResult(binary=bi, success=True)
        assert result.function_count == 0
        assert result.stripped_function_count == 0

    def test_with_functions(self):
        bi = BinaryInfo(
            path="test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )
        funcs = [
            FunctionInfo(name="FUN_00001000", address=0x1000, pseudo_code="", has_unsafe_calls=True, dangerous_funcs=["strcpy"]),
            FunctionInfo(name="main", address=0x2000, pseudo_code="", has_unsafe_calls=False),
        ]
        result = AnalysisResult(binary=bi, success=True, functions=funcs)
        assert result.function_count == 2
        assert result.stripped_function_count == 1
        assert result.unsafe_function_count == 1
