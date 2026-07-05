"""Phase 2 end-to-end pipeline integration test."""

import json
import pytest
from unittest.mock import MagicMock, patch

from fuzzingbrain.attack_surface.identifier import AttackSurfaceIdentifier
from fuzzingbrain.attack_surface.direction_planner import DirectionPlanner
from fuzzingbrain.attack_surface.models import (
    AttackSurfaceResult,
    DirectionResult,
)
from fuzzingbrain.static.models import (
    FunctionInfo, CallGraph, CallGraphNode, StringRef,
)


# ── Test data ──────────────────────────────────────────────────────────

PHASE1_FUNCTIONS = [
    FunctionInfo(
        name="main", address=0x1000, arch="arm",
pseudo_code="void main() { httpd_init(); telnetd_init(); }",
        callees=["httpd_init", "telnetd_init"],
        strings_used=["Starting firmware v1.0"],
    ),
    FunctionInfo(
        name="httpd_init", address=0x2000, arch="arm",
pseudo_code="int httpd_init() { socket(); bind(); listen(); }",
        callees=["socket", "bind", "listen", "accept"],
        strings_used=["0.0.0.0", ":80"],
        dangerous_funcs=["sprintf"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="httpd_handle_request", address=0x2100, arch="arm",
pseudo_code="void httpd_handle_request(char *req) { char buf[256]; strcpy(buf, req); system(buf); }",
        callees=["recv", "strcpy", "system", "send"],
        strings_used=["GET ", "POST ", "/cgi-bin/"],
        dangerous_funcs=["strcpy", "system"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="cgi_login", address=0x2200, arch="arm",
pseudo_code="int cgi_login() { char cmd[128]; sprintf(cmd, 'auth %s', user); system(cmd); }",
        callees=["sprintf", "system"],
        strings_used=["login.cgi", "admin", "password", "username="],
        dangerous_funcs=["sprintf", "system"], has_unsafe_calls=True,
    ),
    FunctionInfo(
        name="telnetd_init", address=0x3000, arch="arm",
pseudo_code="void telnetd_init() { socket(); bind(23); listen(); }",
        callees=["socket", "bind", "listen"],
        strings_used=[":23", "telnet", "login: "],
    ),
    FunctionInfo(
        name="FUN_00004000", address=0x4000, arch="arm",
pseudo_code="void FUN_00004000() { recvfrom(); strcpy(); }",
        callees=["recvfrom", "strcpy", "memcpy"],
        strings_used=["UPnP", "SSDP", "239.255.255.250"],
        dangerous_funcs=["strcpy"], has_unsafe_calls=True,
    ),
]


def make_phase1_callgraph():
    nodes = {
        "main": CallGraphNode("main", 0x1000, callees=["httpd_init", "telnetd_init"]),
        "httpd_init": CallGraphNode("httpd_init", 0x2000,
                                    callees=["socket", "bind", "listen", "accept"],
                                    callers=["main"]),
        "httpd_handle_request": CallGraphNode("httpd_handle_request", 0x2100,
                                              callees=["recv", "strcpy", "system", "send",
                                                       "cgi_login"],
                                              callers=["httpd_init"]),
        "cgi_login": CallGraphNode("cgi_login", 0x2200,
                                   callees=["sprintf", "system"],
                                   callers=["httpd_handle_request"]),
        "telnetd_init": CallGraphNode("telnetd_init", 0x3000,
                                      callees=["socket", "bind", "listen"],
                                      callers=["main"]),
        "FUN_00004000": CallGraphNode("FUN_00004000", 0x4000,
                                      callees=["recvfrom", "strcpy", "memcpy"],
                                      callers=["main"]),
    }
    return CallGraph(binary_path="/bin/webserver", nodes=nodes)


PHASE1_STRINGS = [
    StringRef("0.0.0.0", 0x8000, ["httpd_init"], "port"),
    StringRef(":80", 0x8001, ["httpd_init"], "port"),
    StringRef(":23", 0x8002, ["telnetd_init"], "port"),
    StringRef("GET ", 0x8010, ["httpd_handle_request"], "protocol"),
    StringRef("POST ", 0x8011, ["httpd_handle_request"], "protocol"),
    StringRef("/cgi-bin/", 0x8012, ["httpd_handle_request"], "url"),
    StringRef("login.cgi", 0x8020, ["cgi_login"], "url"),
    StringRef("admin", 0x8030, ["cgi_login"], "credential"),
    StringRef("password", 0x8031, ["cgi_login"], "credential"),
    StringRef("username=", 0x8032, ["cgi_login"], "credential"),
    StringRef("UPnP", 0x8040, ["FUN_00004000"], "protocol"),
    StringRef("SSDP", 0x8041, ["FUN_00004000"], "protocol"),
    StringRef("239.255.255.250", 0x8042, ["FUN_00004000"], "url"),
    StringRef("login: ", 0x8080, ["telnetd_init"], "credential"),
    StringRef("Starting firmware v1.0", 0x8090, ["main"], "debug"),
    StringRef("telnet", 0x80A0, ["telnetd_init"], "protocol"),
]

MOCK_IDENTIFIER_RESPONSE = json.dumps({
    "attack_surfaces": [
        {
            "category": "network_service",
            "name": "HTTP Server on Port 80",
            "description": "Main HTTP server with CGI support.",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": ["0.0.0.0", ":80", "GET ", "POST ", "/cgi-bin/"],
            "risks": ["buffer_overflow", "command_injection"],
        },
        {
            "category": "cgi_endpoint",
            "name": "Login CGI",
            "description": "Admin login via sprintf+system.",
            "entry_functions": ["cgi_login"],
            "supporting_functions": [],
            "protocol": "HTTP",
            "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "inferred"},
            "strings_evidence": ["login.cgi", "admin", "password", "username="],
            "risks": ["command_injection", "buffer_overflow", "auth_bypass"],
        },
        {
            "category": "network_service",
            "name": "Telnet Daemon",
            "description": "Telnet service on port 23.",
            "entry_functions": ["telnetd_init"],
            "supporting_functions": [],
            "protocol": "Telnet",
            "port_info": {"port": 23, "protocol_type": "TCP", "certainty": "confirmed"},
            "strings_evidence": [":23", "telnet", "login: "],
            "risks": ["auth_bypass", "buffer_overflow"],
        },
        {
            "category": "protocol_parser",
            "name": "UPnP SSDP Parser",
            "description": "UPnP discovery protocol with strcpy.",
            "entry_functions": ["FUN_00004000"],
            "supporting_functions": [],
            "protocol": "UPnP",
            "strings_evidence": ["UPnP", "SSDP", "239.255.255.250"],
            "risks": ["buffer_overflow"],
        },
    ],
    "summary": {
        "total_attack_surfaces": 4,
        "primary_exposure": "HTTP server on port 80 with CGI endpoints — critical command injection and buffer overflow risk",
        "secondary_exposures": [
            "Telnet on port 23 (weak auth entry point)",
            "UPnP SSDP parser (multicast buffer overflow)",
        ],
    },
})

MOCK_DIRECTION_RESPONSE = json.dumps({
    "directions": [
        {
            "name": "HTTP Request Processing & CGI",
            "description": "Core HTTP server and CGI endpoint processing.",
            "category": "http_processing",
            "entry_functions": ["httpd_init", "httpd_handle_request"],
            "core_functions": ["httpd_init", "httpd_handle_request", "cgi_login"],
            "big_pool": ["httpd_init", "httpd_handle_request", "cgi_login",
                         "socket", "bind", "listen", "accept",
                         "recv", "strcpy", "system", "send", "sprintf"],
            "primary_attack_types": ["buffer_overflow", "command_injection"],
            "secondary_attack_types": ["auth_bypass"],
            "priority": 5,
            "estimated_complexity": "high",
            "rationale": "Network-facing HTTP with multiple CGI endpoints.",
        },
        {
            "name": "Telnet Remote Access",
            "description": "Telnet daemon providing remote shell access.",
            "category": "network_service",
            "entry_functions": ["telnetd_init"],
            "core_functions": ["telnetd_init"],
            "big_pool": ["telnetd_init", "socket", "bind", "listen"],
            "primary_attack_types": ["auth_bypass"],
            "secondary_attack_types": [],
            "priority": 4,
            "estimated_complexity": "low",
            "rationale": "Standard telnet service.",
        },
        {
            "name": "UPnP Protocol Parsing",
            "description": "UPnP SSDP discovery packet processing.",
            "category": "protocol_parsing",
            "entry_functions": ["FUN_00004000"],
            "core_functions": ["FUN_00004000"],
            "big_pool": ["FUN_00004000", "recvfrom", "strcpy", "memcpy"],
            "primary_attack_types": ["buffer_overflow"],
            "secondary_attack_types": [],
            "priority": 5,
            "estimated_complexity": "medium",
            "rationale": "UDP multicast with strcpy — classic IoT overflow pattern.",
        },
    ],
    "analysis_order": {
        "recommended_sequence": [
            "HTTP Request Processing & CGI",
            "UPnP Protocol Parsing",
            "Telnet Remote Access",
        ],
        "rationale": "HTTP processing has broadest attack surface and highest concentration of dangerous functions.",
    },
})


class TestPhase2Pipeline:
    """Integration test for the full Phase 2 pipeline."""

    def test_full_pipeline_identifier_to_planner(self):
        """End-to-end: Phase 1 output → AttackSurfaceIdentifier → DirectionPlanner."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            MockIdClient.return_value.call.return_value = MagicMock(content=MOCK_IDENTIFIER_RESPONSE)
            MockDirClient.return_value.call.return_value = MagicMock(content=MOCK_DIRECTION_RESPONSE)

            # Step 1: Identify attack surfaces
            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            assert isinstance(attack_result, AttackSurfaceResult)
            assert attack_result.count == 4
            assert "HTTP" in attack_result.summary.primary_exposure

            # Step 2: Plan directions
            planner = DirectionPlanner()
            direction_result = planner.plan(
                attack_surfaces=attack_result,
                callgraph=callgraph,
                functions=PHASE1_FUNCTIONS,
            )

            assert isinstance(direction_result, DirectionResult)
            assert direction_result.count == 3

            # Verify all attack surface entries are covered
            all_entries = set()
            for a in attack_result.attack_surfaces:
                all_entries.update(a.entry_functions)

            all_in_dirs = set()
            for d in direction_result.directions:
                all_in_dirs.update(d.big_pool)

            for entry in all_entries:
                assert entry in all_in_dirs, \
                    f"Entry {entry} not covered by any direction"

            # Verify high priority directions come first
            first = direction_result.analysis_order.recommended_sequence[0]
            first_dir = direction_result.get_by_name(first)
            assert first_dir is not None
            assert first_dir.priority >= 4

    def test_full_pipeline_save_and_reload(self, tmp_path):
        """Save intermediate and final results, verify they reload correctly."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            MockIdClient.return_value.call.return_value = MagicMock(content=MOCK_IDENTIFIER_RESPONSE)
            MockDirClient.return_value.call.return_value = MagicMock(content=MOCK_DIRECTION_RESPONSE)

            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            attack_path = tmp_path / "attack_surface.json"
            identifier.save(attack_result, attack_path)
            assert attack_path.exists()

            loaded_attack = identifier.load(attack_path)
            assert loaded_attack.count == attack_result.count

            planner = DirectionPlanner()
            direction_result = planner.plan(
                attack_surfaces=loaded_attack,
                callgraph=callgraph,
                functions=PHASE1_FUNCTIONS,
            )

            dir_path = tmp_path / "directions.json"
            planner.save(direction_result, dir_path)
            assert dir_path.exists()

            loaded_dir = planner.load(dir_path)
            assert loaded_dir.count == direction_result.count
            assert loaded_dir.analysis_order.recommended_sequence == \
                   direction_result.analysis_order.recommended_sequence

    def test_pipeline_stripped_functions_handled(self):
        """Stripped functions (FUN_XXXXXXXX) should be properly handled."""
        callgraph = make_phase1_callgraph()

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient, \
             patch("fuzzingbrain.attack_surface.direction_planner.LLMClient") as MockDirClient:

            MockIdClient.return_value.call.return_value = MagicMock(content=MOCK_IDENTIFIER_RESPONSE)
            MockDirClient.return_value.call.return_value = MagicMock(content=MOCK_DIRECTION_RESPONSE)

            identifier = AttackSurfaceIdentifier()
            attack_result = identifier.identify(
                functions=PHASE1_FUNCTIONS,
                strings=PHASE1_STRINGS,
                callgraph=callgraph,
            )

            upnp_surfaces = [
                s for s in attack_result.attack_surfaces
                if "FUN_00004000" in s.entry_functions
            ]
            assert len(upnp_surfaces) == 1, \
                "Stripped function FUN_00004000 not identified as attack surface"

            planner = DirectionPlanner()
            direction_result = planner.plan(attack_result, callgraph, PHASE1_FUNCTIONS)

            all_funcs = set()
            for d in direction_result.directions:
                all_funcs.update(d.big_pool)
            assert "FUN_00004000" in all_funcs, \
                "Stripped function FUN_00004000 not assigned to any direction"

    def test_empty_inputs_handled_gracefully(self):
        """Empty inputs should not crash the pipeline."""
        empty_callgraph = CallGraph(binary_path="/bin/empty", nodes={})

        with patch("fuzzingbrain.attack_surface.identifier.LLMClient") as MockIdClient:
            MockIdClient.return_value.call.return_value = MagicMock(content=json.dumps({
                "attack_surfaces": [],
                "summary": {
                    "total_attack_surfaces": 0,
                    "primary_exposure": "No attack surfaces found",
                    "secondary_exposures": [],
                },
            }))

            identifier = AttackSurfaceIdentifier()
            result = identifier.identify(
                functions=[],
                strings=[],
                callgraph=empty_callgraph,
            )

            assert result.count == 0
            assert result.summary.total_attack_surfaces == 0
