"""Tests for DirectionPlanner."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.attack_surface.direction_planner import (
    DirectionPlanner,
    build_attack_surfaces_context,
    build_callgraph_context,
    build_function_details_context,
)
from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
    PortInfo,
)
from fuzzingbrain.static.models import (
    FunctionInfo, CallGraph, CallGraphNode, StringRef,
)


# ── Helper ─────────────────────────────────────────────────────────────

def make_function(name, address=0x1000, callees=None, strings=None, dangerous=None):
    """Helper to create FunctionInfo for tests."""
    return FunctionInfo(
        name=name,
        address=address,
        pseudo_code=f"/* decompiled {name} */\nvoid {name}(void) {{ }}",
        callees=callees or [],
        strings_used=strings or [],
        dangerous_funcs=dangerous or [],
        has_unsafe_calls=bool(dangerous),
    )


# ── Mock data ──────────────────────────────────────────────────────────

def make_mock_attack_surface_result():
    """Create a realistic AttackSurfaceResult for testing DirectionPlanner input."""
    surfaces = [
        AttackSurface(
            name="HTTP Management Interface",
            category="network_service",
            entry_functions=["httpd_init", "httpd_handle_request"],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="confirmed"),
            strings_evidence=["0.0.0.0", ":80", "GET ", "POST "],
            risks=["buffer_overflow", "command_injection"],
        ),
        AttackSurface(
            name="Login CGI Handler",
            category="cgi_endpoint",
            entry_functions=["cgi_login"],
            supporting_functions=["do_system_cmd"],
            protocol="HTTP",
            port_info=PortInfo(port=80, protocol_type="TCP", certainty="inferred"),
            strings_evidence=["login.cgi", "admin", "password"],
            risks=["command_injection", "auth_bypass"],
        ),
        AttackSurface(
            name="Telnet Service",
            category="network_service",
            entry_functions=["telnetd_init"],
            protocol="Telnet",
            port_info=PortInfo(port=23, protocol_type="TCP", certainty="confirmed"),
            strings_evidence=[":23", "telnet", "login: "],
            risks=["auth_bypass", "buffer_overflow"],
        ),
        AttackSurface(
            name="UPnP SSDP Handler",
            category="protocol_parser",
            entry_functions=["parse_upnp"],
            protocol="UPnP",
            strings_evidence=["UPnP", "SSDP", "M-SEARCH"],
            risks=["buffer_overflow"],
        ),
        AttackSurface(
            name="System Command Builder",
            category="command_execution",
            entry_functions=["do_system_cmd"],
            protocol="N/A",
            strings_evidence=["ping ", "iptables"],
            risks=["command_injection"],
        ),
        AttackSurface(
            name="File Upload Handler",
            category="file_operation",
            entry_functions=["file_upload_handler"],
            protocol="HTTP",
            strings_evidence=["/tmp/upload", "multipart/form-data"],
            risks=["path_traversal"],
        ),
        AttackSurface(
            name="Unknown Network Service (port 8080)",
            category="network_service",
            entry_functions=["FUN_00007000"],
            protocol="Custom",
            port_info=PortInfo(port=8080, protocol_type="TCP", certainty="inferred"),
            strings_evidence=[":8080", "admin", "debug"],
            risks=["auth_bypass", "buffer_overflow"],
        ),
    ]
    summary = AttackSurfaceSummary(
        total_attack_surfaces=7,
        primary_exposure="HTTP server on port 80 with CGI endpoints",
        secondary_exposures=["Telnet on port 23", "Debug backdoor on port 8080", "UPnP SSDP"],
    )
    return AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)


def make_mock_functions():
    """Create functions matching the attack surfaces."""
    return [
        make_function("httpd_init", 0x2000,
                      callees=["socket", "bind", "listen", "accept"],
                      strings=["0.0.0.0", ":80"], dangerous=["sprintf"]),
        make_function("httpd_handle_request", 0x2100,
                      callees=["recv", "strcpy", "system", "send", "cgi_login",
                               "do_system_cmd", "file_upload_handler"],
                      strings=["GET ", "POST ", "/cgi-bin/", "HTTP/1.1"],
                      dangerous=["strcpy", "system"]),
        make_function("cgi_login", 0x2200,
                      callees=["recv", "sprintf", "strcmp", "system"],
                      strings=["admin", "password", "login.cgi"],
                      dangerous=["sprintf", "system"]),
        make_function("telnetd_init", 0x3000,
                      callees=["socket", "bind", "listen"],
                      strings=[":23", "telnet"]),
        make_function("parse_upnp", 0x4000,
                      callees=["recvfrom", "strcpy", "memcpy"],
                      strings=["UPnP", "SSDP", "M-SEARCH"],
                      dangerous=["strcpy"]),
        make_function("do_system_cmd", 0x5000,
                      callees=["system"],
                      strings=["ping ", "iptables"], dangerous=["system"]),
        make_function("file_upload_handler", 0x6000,
                      callees=["fopen", "fwrite", "recv"],
                      strings=["/tmp/upload", "multipart/form-data"]),
        make_function("FUN_00007000", 0x7000,
                      callees=["recv", "send"],
                      strings=[":8080", "admin", "debug"]),
    ]


def make_mock_callgraph():
    """Create callgraph matching the functions."""
    nodes = {
        "httpd_init": CallGraphNode(function_name="httpd_init", address=0x2000,
                                    callees=["socket", "bind", "listen", "accept"]),
        "httpd_handle_request": CallGraphNode(function_name="httpd_handle_request", address=0x2100,
                                              callees=["recv", "strcpy", "system", "send",
                                                       "cgi_login", "do_system_cmd", "file_upload_handler"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode(function_name="cgi_login", address=0x2200,
                                   callees=["recv", "sprintf", "strcmp", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode(function_name="telnetd_init", address=0x3000,
                                      callees=["socket", "bind", "listen"]),
        "parse_upnp": CallGraphNode(function_name="parse_upnp", address=0x4000,
                                    callees=["recvfrom", "strcpy", "memcpy"]),
        "do_system_cmd": CallGraphNode(function_name="do_system_cmd", address=0x5000,
                                       callees=["system"],
                                       callers=["cgi_login", "httpd_handle_request"]),
        "file_upload_handler": CallGraphNode(function_name="file_upload_handler", address=0x6000,
                                             callees=["fopen", "fwrite", "recv"],
                                             callers=["httpd_handle_request"]),
        "FUN_00007000": CallGraphNode(function_name="FUN_00007000", address=0x7000,
                                      callees=["recv", "send"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


# ── Mock LLM response ──────────────────────────────────────────────────

MOCK_DIRECTION_RESPONSE = json.dumps({
    "directions": [
        {
            "name": "HTTP Request Processing & CGI Dispatch",
            "description": "Core HTTP server handling GET/POST requests and dispatching to CGI handlers.",
            "category": "http_processing",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "core_functions": ["httpd_init", "httpd_handle_request", "cgi_login",
                               "do_system_cmd", "file_upload_handler"],
            "big_pool": ["httpd_init", "httpd_handle_request", "cgi_login",
                         "do_system_cmd", "file_upload_handler",
                         "socket", "bind", "listen", "accept",
                         "recv", "strcpy", "system", "send",
                         "sprintf", "strcmp", "fopen", "fwrite"],
            "primary_attack_types": ["buffer_overflow", "command_injection"],
            "secondary_attack_types": ["auth_bypass", "path_traversal"],
            "priority": 5,
            "estimated_complexity": "high",
            "rationale": "Network-facing HTTP with multiple CGI endpoints. Entry functions call strcpy+system with user input.",
        },
        {
            "name": "Telnet Service",
            "description": "Telnet daemon on port 23 providing remote shell access.",
            "category": "network_service",
            "entry_functions": ["telnetd_init"],
            "core_functions": ["telnetd_init"],
            "big_pool": ["telnetd_init", "socket", "bind", "listen"],
            "primary_attack_types": ["auth_bypass"],
            "secondary_attack_types": ["buffer_overflow"],
            "priority": 4,
            "estimated_complexity": "medium",
            "rationale": "Network-facing on well-known port. Auth bypass is the primary concern.",
        },
        {
            "name": "UPnP Protocol Parsing",
            "description": "UPnP SSDP discovery protocol handling.",
            "category": "protocol_parsing",
            "entry_functions": ["parse_upnp"],
            "core_functions": ["parse_upnp"],
            "big_pool": ["parse_upnp", "recvfrom", "strcpy", "memcpy"],
            "primary_attack_types": ["buffer_overflow"],
            "secondary_attack_types": [],
            "priority": 5,
            "estimated_complexity": "medium",
            "rationale": "Network-reachable via UDP multicast, no authentication. Classic overflow pattern.",
        },
        {
            "name": "Debug Backdoor (Port 8080)",
            "description": "Suspected debug/admin backdoor on port 8080. Stripped binary, unknown protocol.",
            "category": "network_service",
            "entry_functions": ["FUN_00007000"],
            "core_functions": ["FUN_00007000"],
            "big_pool": ["FUN_00007000", "recv", "send"],
            "primary_attack_types": ["auth_bypass", "command_injection"],
            "secondary_attack_types": ["buffer_overflow"],
            "priority": 5,
            "estimated_complexity": "low",
            "rationale": "Hidden debug interfaces in IoT firmware are notoriously insecure.",
        },
    ],
    "analysis_order": {
        "recommended_sequence": [
            "HTTP Request Processing & CGI Dispatch",
            "UPnP Protocol Parsing",
            "Debug Backdoor (Port 8080)",
            "Telnet Service",
        ],
        "rationale": "HTTP processing has the broadest attack surface. UPnP parsers are classic overflow sources. Debug backdoor is a quick win. Telnet is lowest risk.",
    },
})


# ── Helper function tests ──────────────────────────────────────────────

class TestBuildAttackSurfacesContext:
    """Tests for build_attack_surfaces_context helper."""

    def test_builds_context(self):
        surfaces = [
            AttackSurface(
                name="HTTP Server",
                category="network_service",
                entry_functions=["httpd_main"],
                protocol="HTTP",
                port_info=PortInfo(port=80),
                risks=["buffer_overflow"],
            ),
        ]
        result = build_attack_surfaces_context(surfaces)
        assert "HTTP Server" in result
        assert "80" in result
        assert "buffer_overflow" in result

    def test_empty_surfaces(self):
        result = build_attack_surfaces_context([])
        assert "No attack surfaces" in result


class TestBuildCallgraphContext:
    """Tests for build_callgraph_context helper."""

    def test_builds_context(self):
        cg = make_mock_callgraph()
        result = build_callgraph_context(cg)
        assert "httpd_init" in result
        assert "cgi_login" in result

    def test_empty_callgraph(self):
        result = build_callgraph_context(None)
        assert "no call graph" in result.lower()


class TestBuildFunctionDetailsContext:
    """Tests for build_function_details_context helper."""

    def test_builds_details(self):
        funcs = make_mock_functions()
        entry_names = {"httpd_init", "httpd_handle_request", "cgi_login"}
        result = build_function_details_context(funcs, entry_names)
        assert "httpd_init" in result
        assert "httpd_handle_request" in result
        assert "cgi_login" in result


# ── Main Agent tests ───────────────────────────────────────────────────

class TestDirectionPlanner:
    """Tests for DirectionPlanner agent."""

    @pytest.fixture
    def attack_surfaces(self):
        return make_mock_attack_surface_result()

    @pytest.fixture
    def functions(self):
        return make_mock_functions()

    @pytest.fixture
    def callgraph(self):
        return make_mock_callgraph()

    @pytest.fixture
    def mock_llm_response(self):
        resp = MagicMock()
        resp.content = MOCK_DIRECTION_RESPONSE
        return resp

    def test_plan_returns_result(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces=attack_surfaces, callgraph=callgraph, functions=functions)

        assert isinstance(result, DirectionResult)
        assert result.count == 4
        assert len(result.analysis_order.recommended_sequence) == 4

    def test_plan_high_priority_first(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        first = result.analysis_order.recommended_sequence[0]
        first_dir = result.get_by_name(first)
        assert first_dir is not None
        assert first_dir.priority >= 4

    def test_plan_all_attack_surfaces_covered(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        all_entries = set()
        for a in attack_surfaces.attack_surfaces:
            all_entries.update(a.entry_functions)

        all_in_directions = set()
        for d in result.directions:
            all_in_directions.update(d.big_pool)
            all_in_directions.update(d.core_functions)

        for entry in all_entries:
            assert entry in all_in_directions, \
                f"Entry function {entry} not covered by any direction!"

    def test_plan_save_and_load(self, attack_surfaces, functions, callgraph, mock_llm_response, tmp_path):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

            output_path = tmp_path / "directions.json"
            planner.save(result, output_path)
            assert output_path.exists()

            loaded = planner.load(output_path)
            assert loaded.count == result.count

    def test_plan_json_parse_error(self, attack_surfaces, functions, callgraph):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = MagicMock(content="not valid json {{{[[[")
            planner = DirectionPlanner()
            with pytest.raises(ValueError, match="Failed to parse"):
                planner.plan(attack_surfaces, callgraph, functions)

    def test_plan_3_to_8_directions(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)
        assert 3 <= result.count <= 8

    def test_plan_directions_have_required_fields(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, functions)

        for d in result.directions:
            assert d.name
            assert d.description
            assert d.category
            assert len(d.entry_functions) > 0
            assert len(d.core_functions) > 0
            assert len(d.big_pool) > 0
            assert 1 <= d.priority <= 5
            assert d.estimated_complexity in ("high", "medium", "low")

    def test_model_override(self, attack_surfaces, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.llms import QWEN3_6_PLUS
            planner = DirectionPlanner(model=QWEN3_6_PLUS)
            planner.plan(attack_surfaces, callgraph, functions)
            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"] == QWEN3_6_PLUS

    def test_plan_without_callgraph(self, attack_surfaces, functions, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, None, functions)
            assert isinstance(result, DirectionResult)

    def test_plan_without_functions(self, attack_surfaces, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            planner = DirectionPlanner()
            result = planner.plan(attack_surfaces, callgraph, None)
            assert isinstance(result, DirectionResult)
