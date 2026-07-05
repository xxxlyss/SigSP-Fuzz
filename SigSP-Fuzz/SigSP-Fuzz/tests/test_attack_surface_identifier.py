"""Tests for AttackSurfaceIdentifier."""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from fuzzingbrain.attack_surface.identifier import (
    AttackSurfaceIdentifier,
    build_function_summaries,
    build_strings_by_category,
    build_callgraph_summary,
)
from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    PortInfo,
)
from fuzzingbrain.static.models import FunctionInfo, CallGraph, CallGraphNode, StringRef


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

def make_mock_functions():
    """Create a realistic set of mock functions for testing."""
    return [
        make_function("main", 0x1000, callees=["httpd_init", "telnetd_init"],
                      strings=["Starting firmware v1.0"]),
        make_function("httpd_init", 0x2000, callees=["socket", "bind", "listen", "accept"],
                      strings=["0.0.0.0", ":80", "/www/"], dangerous=["sprintf"]),
        make_function("httpd_handle_request", 0x2100,
                      callees=["recv", "strcpy", "system", "send"],
                      strings=["GET ", "POST ", "/cgi-bin/", "HTTP/1.1"],
                      dangerous=["strcpy", "system"]),
        make_function("cgi_login", 0x2200, callees=["recv", "sprintf", "strcmp", "system"],
                      strings=["admin", "password", "login.cgi", "username=", "password="],
                      dangerous=["sprintf", "system"]),
        make_function("telnetd_init", 0x3000, callees=["socket", "bind", "listen"],
                      strings=[":23", "telnet", "login: "]),
        make_function("parse_upnp", 0x4000, callees=["recvfrom", "strcpy", "memcpy"],
                      strings=["UPnP", "SSDP", "M-SEARCH", "239.255.255.250"],
                      dangerous=["strcpy"]),
        make_function("do_system_cmd", 0x5000, callees=["system"],
                      strings=["ping ", "iptables"], dangerous=["system"]),
        make_function("file_upload_handler", 0x6000, callees=["fopen", "fwrite", "recv"],
                      strings=["/tmp/upload", "multipart/form-data", "filename="],
                      dangerous=[]),
        make_function("FUN_00007000", 0x7000, callees=["recv", "send"],
                      strings=[":8080", "admin", "debug"]),
    ]


def make_mock_strings():
    """Create realistic string references matching the functions above."""
    return [
        StringRef(value="0.0.0.0", address=0x8000, referenced_by=["httpd_init"], category="port"),
        StringRef(value=":80", address=0x8001, referenced_by=["httpd_init"], category="port"),
        StringRef(value=":23", address=0x8002, referenced_by=["telnetd_init"], category="port"),
        StringRef(value=":8080", address=0x8003, referenced_by=["FUN_00007000"], category="port"),
        StringRef(value="GET ", address=0x8010, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="POST ", address=0x8011, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="/cgi-bin/", address=0x8012, referenced_by=["httpd_handle_request"], category="url"),
        StringRef(value="HTTP/1.1", address=0x8013, referenced_by=["httpd_handle_request"], category="protocol"),
        StringRef(value="login.cgi", address=0x8020, referenced_by=["cgi_login"], category="url"),
        StringRef(value="admin", address=0x8030, referenced_by=["cgi_login", "FUN_00007000"], category="credential"),
        StringRef(value="password", address=0x8031, referenced_by=["cgi_login"], category="credential"),
        StringRef(value="username=", address=0x8032, referenced_by=["cgi_login"], category="credential"),
        StringRef(value="UPnP", address=0x8040, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="SSDP", address=0x8041, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="M-SEARCH", address=0x8042, referenced_by=["parse_upnp"], category="protocol"),
        StringRef(value="/tmp/upload", address=0x8050, referenced_by=["file_upload_handler"], category="path"),
        StringRef(value="ping ", address=0x8060, referenced_by=["do_system_cmd"], category="other"),
        StringRef(value="/www/", address=0x8070, referenced_by=["httpd_init"], category="path"),
        StringRef(value="login: ", address=0x8080, referenced_by=["telnetd_init"], category="credential"),
    ]


def make_mock_callgraph():
    """Create a realistic call graph for testing."""
    nodes = {
        "main": CallGraphNode(function_name="main", address=0x1000,
                              callees=["httpd_init", "telnetd_init"]),
        "httpd_init": CallGraphNode(function_name="httpd_init", address=0x2000,
                                    callees=["socket", "bind", "listen", "accept"],
                                    callers=["main"]),
        "httpd_handle_request": CallGraphNode(function_name="httpd_handle_request", address=0x2100,
                                              callees=["recv", "strcpy", "system", "send"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode(function_name="cgi_login", address=0x2200,
                                   callees=["recv", "sprintf", "strcmp", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode(function_name="telnetd_init", address=0x3000,
                                      callees=["socket", "bind", "listen"],
                                      callers=["main"]),
        "parse_upnp": CallGraphNode(function_name="parse_upnp", address=0x4000,
                                    callees=["recvfrom", "strcpy", "memcpy"],
                                    callers=["main"]),
        "do_system_cmd": CallGraphNode(function_name="do_system_cmd", address=0x5000,
                                       callees=["system"],
                                       callers=["cgi_login", "httpd_handle_request"]),
        "file_upload_handler": CallGraphNode(function_name="file_upload_handler", address=0x6000,
                                             callees=["fopen", "fwrite", "recv"],
                                             callers=["httpd_handle_request"]),
        "FUN_00007000": CallGraphNode(function_name="FUN_00007000", address=0x7000,
                                      callees=["recv", "send"],
                                      callers=["main"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


# ── Mock LLM response ──────────────────────────────────────────────────

MOCK_LLM_RESPONSE = json.dumps({
    "attack_surfaces": [
        {
            "category": "network_service",
            "name": "HTTP Management Interface",
            "description": "Main HTTP server on port 80 with CGI endpoint support.",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": ["0.0.0.0", ":80", "GET ", "POST ", "HTTP/1.1", "/cgi-bin/"],
            "risks": ["buffer_overflow", "command_injection", "auth_bypass"],
        },
        {
            "category": "cgi_endpoint",
            "name": "Login CGI Handler",
            "description": "CGI endpoint for admin login. Processes username/password using sprintf+system.",
            "entry_functions": ["cgi_login"],
            "supporting_functions": ["do_system_cmd"],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["login.cgi", "admin", "password", "username="],
            "risks": ["command_injection", "buffer_overflow", "auth_bypass"],
        },
        {
            "category": "network_service",
            "name": "Telnet Service",
            "description": "Telnet daemon on port 23. Classic IoT remote shell access point.",
            "entry_functions": ["telnetd_init"],
            "supporting_functions": [],
            "protocol": "Telnet",
            "port_info": {"port": 23, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": [":23", "telnet", "login: "],
            "risks": ["auth_bypass", "buffer_overflow"],
        },
        {
            "category": "protocol_parser",
            "name": "UPnP SSDP Handler",
            "description": "UPnP discovery protocol parser. Processes multicast SSDP M-SEARCH requests.",
            "entry_functions": ["parse_upnp"],
            "supporting_functions": [],
            "protocol": "UPnP",
            "port_info": None,
            "strings_evidence": ["UPnP", "SSDP", "M-SEARCH", "239.255.255.250"],
            "risks": ["buffer_overflow"],
        },
        {
            "category": "command_execution",
            "name": "System Command Builder",
            "description": "Wrapper that executes system commands. Called by CGI handlers.",
            "entry_functions": ["do_system_cmd"],
            "supporting_functions": [],
            "protocol": "N/A",
            "port_info": None,
            "strings_evidence": ["ping ", "iptables"],
            "risks": ["command_injection"],
        },
        {
            "category": "file_operation",
            "name": "File Upload Handler",
            "description": "Processes multipart file uploads to /tmp/upload.",
            "entry_functions": ["file_upload_handler"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["/tmp/upload", "multipart/form-data", "filename="],
            "risks": ["path_traversal"],
        },
        {
            "category": "network_service",
            "name": "Unknown Network Service (port 8080)",
            "description": "Stripped binary function FUN_00007000 on port 8080. Likely debug/admin backdoor.",
            "entry_functions": ["FUN_00007000"],
            "supporting_functions": [],
            "protocol": "Custom",
            "port_info": {"port": 8080, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": [":8080", "admin", "debug"],
            "risks": ["auth_bypass", "buffer_overflow", "command_injection"],
        },
    ],
    "summary": {
        "total_attack_surfaces": 7,
        "primary_exposure": "HTTP server on port 80 with multiple CGI endpoints, including a login handler with sprintf+system — critical command injection risk",
        "secondary_exposures": [
            "Telnet on port 23 (classic IoT weak-auth entry point)",
            "Suspected debug backdoor on port 8080",
            "UPnP SSDP parser vulnerable to buffer overflow",
        ],
    },
})


# ── Helper function tests ──────────────────────────────────────────────

class TestBuildFunctionSummaries:
    """Tests for prompt-building helper: build_function_summaries."""

    def test_builds_summary_for_functions(self):
        funcs = make_mock_functions()
        result = build_function_summaries(funcs)
        assert "httpd_init" in result
        assert "httpd_handle_request" in result
        assert "cgi_login" in result
        assert "strcpy" in result or "system" in result
        assert "FUN_00007000" in result

    def test_empty_functions(self):
        result = build_function_summaries([])
        assert result == "No functions provided."

    def test_summary_includes_dangerous_indicators(self):
        funcs = [
            make_function("vuln_func", 0x1000,
                         callees=["strcpy", "system"],
                         strings=["password"],
                         dangerous=["strcpy", "system"]),
        ]
        result = build_function_summaries(funcs)
        assert "strcpy" in result
        assert "system" in result
        assert "password" in result

    def test_summary_includes_callers(self):
        funcs = [make_function("target", 0x2000, callees=["recv"])]
        funcs[0].callers = ["httpd_main", "cgi_dispatch"]
        result = build_function_summaries(funcs)
        assert "httpd_main" in result
        assert "cgi_dispatch" in result


class TestBuildStringsByCategory:
    """Tests for prompt-building helper: build_strings_by_category."""

    def test_categorizes_strings(self):
        strings = make_mock_strings()
        result = build_strings_by_category(strings)
        assert "PORT" in result
        assert "CREDENTIAL" in result
        assert "PROTOCOL" in result
        assert "0.0.0.0" in result
        assert "admin" in result

    def test_empty_strings(self):
        result = build_strings_by_category([])
        assert result == "No strings found."

    def test_includes_referenced_by(self):
        strings = [
            StringRef(value=":80", address=0x8000,
                     referenced_by=["httpd_init", "httpd_main"],
                     category="port"),
        ]
        result = build_strings_by_category(strings)
        assert "httpd_init" in result
        assert "httpd_main" in result


class TestBuildCallgraphSummary:
    """Tests for prompt-building helper: build_callgraph_summary."""

    def test_builds_summary(self):
        cg = make_mock_callgraph()
        result = build_callgraph_summary(cg)
        assert "9" in result or "node" in result.lower()
        assert "main" in result

    def test_empty_callgraph(self):
        cg = CallGraph(binary_path="/bin/test", nodes={})
        result = build_callgraph_summary(cg)
        assert "No call graph" in result or "0" in result.lower()

    def test_shows_entry_points(self):
        cg = make_mock_callgraph()
        result = build_callgraph_summary(cg)
        assert "main" in result


# ── Main Agent tests ───────────────────────────────────────────────────

class TestAttackSurfaceIdentifier:
    """Tests for AttackSurfaceIdentifier agent."""

    @pytest.fixture
    def functions(self):
        return make_mock_functions()

    @pytest.fixture
    def strings(self):
        return make_mock_strings()

    @pytest.fixture
    def callgraph(self):
        return make_mock_callgraph()

    @pytest.fixture
    def mock_llm_response(self):
        resp = MagicMock()
        resp.content = MOCK_LLM_RESPONSE
        return resp

    def test_identify_returns_result(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions=functions, strings=strings, callgraph=callgraph)

        assert isinstance(result, AttackSurfaceResult)
        assert result.count == 7
        assert result.summary.total_attack_surfaces == 7

    def test_identify_network_services_present(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        names = [s.name for s in result.attack_surfaces]
        assert "HTTP Management Interface" in names
        assert "Telnet Service" in names

    def test_identify_stripped_function_handled(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        stripped_surfaces = [
            s for s in result.attack_surfaces
            if "FUN_00007000" in s.entry_functions
        ]
        assert len(stripped_surfaces) == 1
        assert stripped_surfaces[0].port_info.port == 8080

    def test_identify_high_risk_surfaces(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)

        high_risk = result.high_risk_surfaces
        assert len(high_risk) > 0
        for s in high_risk:
            assert s.category in ("network_service", "cgi_endpoint", "protocol_parser")
            assert s.risk_count > 0

    def test_identify_prompt_includes_functions(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            identifier.identify(functions, strings, callgraph)

            call_args = mock_client.call.call_args
            messages = call_args[1]["messages"] if "messages" in call_args[1] else call_args[0][0]
            # The user message (second one) contains the actual function data
            user_msg = messages[1]["content"] if len(messages) > 1 else messages[0]["content"]
            assert "httpd_init" in user_msg
            assert "httpd_handle_request" in user_msg
            assert "cgi_login" in user_msg
            assert "FUN_00007000" in user_msg

    def test_identify_save_and_load(self, functions, strings, callgraph, mock_llm_response, tmp_path):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, strings, callgraph)
            output_path = tmp_path / "attack_surface.json"
            identifier.save(result, output_path)
            assert output_path.exists()
            loaded = identifier.load(output_path)
            assert loaded.count == result.count

    def test_identify_handles_empty_strings_field(self, functions, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = mock_llm_response
            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(functions, [], callgraph)
        assert isinstance(result, AttackSurfaceResult)

    def test_llm_json_parse_error(self, functions, strings, callgraph):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            MockClient.return_value.call.return_value = MagicMock(content="This is not valid JSON {{{")
            identifier = AttackSurfaceIdentifier()
            with pytest.raises(ValueError, match="Failed to parse"):
                identifier.identify(functions, strings, callgraph)

    def test_model_override(self, functions, strings, callgraph, mock_llm_response):
        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockClient:
            mock_client = MockClient.return_value
            mock_client.call.return_value = mock_llm_response
            from fuzzingbrain.llms import QWEN3_6_PLUS
            identifier = AttackSurfaceIdentifier(model=QWEN3_6_PLUS)
            identifier.identify(functions, strings, callgraph)
            call_kwargs = mock_client.call.call_args[1]
            assert call_kwargs["model"] == QWEN3_6_PLUS
