"""Tests for attack_surface data models."""

import json
import pytest
from dataclasses import asdict

from fuzzingbrain.attack_surface.models import (
    AttackSurface,
    AttackSurfaceResult,
    AttackSurfaceSummary,
    Direction,
    DirectionResult,
    AnalysisOrder,
    PortInfo,
)


class TestPortInfo:
    """Tests for PortInfo dataclass."""

    def test_create_port_info(self):
        p = PortInfo(port=80, protocol_type="TCP", certainty="confirmed")
        assert p.port == 80
        assert p.protocol_type == "TCP"
        assert p.certainty == "confirmed"

    def test_port_info_defaults(self):
        p = PortInfo(port=443)
        assert p.port == 443
        assert p.protocol_type == "TCP"
        assert p.certainty == "inferred"

    def test_port_info_serialization(self):
        p = PortInfo(port=8080, protocol_type="TCP", certainty="inferred")
        d = asdict(p)
        assert d == {"port": 8080, "protocol_type": "TCP", "certainty": "inferred"}

    def test_port_info_json_roundtrip(self):
        p = PortInfo(port=23, protocol_type="TCP", certainty="confirmed")
        json_str = json.dumps(asdict(p))
        loaded = json.loads(json_str)
        p2 = PortInfo(**loaded)
        assert p == p2


class TestAttackSurface:
    """Tests for AttackSurface dataclass."""

    def test_create_minimal(self):
        a = AttackSurface(
            name="HTTP Server",
            category="network_service",
            entry_functions=["httpd_main"],
        )
        assert a.name == "HTTP Server"
        assert a.category == "network_service"
        assert a.entry_functions == ["httpd_main"]
        assert a.description == ""
        assert a.supporting_functions == []
        assert a.protocol == "N/A"
        assert a.port_info is None
        assert a.strings_evidence == []
        assert a.risks == []

    def test_create_full(self):
        port = PortInfo(port=80, protocol_type="TCP", certainty="confirmed")
        a = AttackSurface(
            category="network_service",
            name="HTTP Management Interface",
            description="Web-based admin panel on port 80",
            entry_functions=["httpd_main", "cgi_handler"],
            supporting_functions=["parse_http_request", "send_response"],
            protocol="HTTP",
            port_info=port,
            strings_evidence=["/www/admin/", "192.168.1.1:80"],
            risks=["buffer_overflow", "command_injection"],
        )
        assert a.port_info.port == 80
        assert len(a.strings_evidence) == 2
        assert "buffer_overflow" in a.risks

    def test_serialization(self):
        a = AttackSurface(
            name="Telnet Service",
            category="network_service",
            entry_functions=["telnetd_main"],
            protocol="Telnet",
            port_info=PortInfo(port=23, protocol_type="TCP", certainty="confirmed"),
            risks=["auth_bypass"],
        )
        d = asdict(a)
        assert d["name"] == "Telnet Service"
        assert d["port_info"]["port"] == 23
        assert d["risks"] == ["auth_bypass"]

    def test_json_roundtrip(self):
        a = AttackSurface(
            name="CGI Upload Handler",
            category="cgi_endpoint",
            entry_functions=["cgi_upload", "process_upload"],
            description="File upload via /cgi-bin/upload.cgi",
            protocol="HTTP",
            risks=["path_traversal", "command_injection"],
        )
        json_str = json.dumps(asdict(a))
        loaded = json.loads(json_str)
        a2 = AttackSurface(**loaded)
        assert a.name == a2.name
        assert a.risks == a2.risks
        assert a2.port_info is None


class TestAttackSurfaceResult:
    """Tests for AttackSurfaceResult container."""

    def test_create_result(self):
        surfaces = [
            AttackSurface(
                name="HTTP Server",
                category="network_service",
                entry_functions=["httpd_main"],
                protocol="HTTP",
                port_info=PortInfo(port=80),
            ),
            AttackSurface(
                name="UPnP Handler",
                category="protocol_parser",
                entry_functions=["upnp_parse"],
                protocol="UPnP",
            ),
        ]
        summary = AttackSurfaceSummary(
            total_attack_surfaces=2,
            primary_exposure="HTTP server on port 80 with unauthenticated CGI endpoints",
            secondary_exposures=["UPnP SSDP multicast exposure"],
        )
        result = AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)
        assert len(result.attack_surfaces) == 2
        assert result.summary.total_attack_surfaces == 2
        assert "HTTP" in result.summary.primary_exposure

    def test_json_roundtrip(self):
        surfaces = [
            AttackSurface(
                name="SSH Server",
                category="network_service",
                entry_functions=["dropbear_main"],
                protocol="SSH",
                port_info=PortInfo(port=22, certainty="confirmed"),
                risks=["auth_bypass"],
            ),
        ]
        summary = AttackSurfaceSummary(
            total_attack_surfaces=1,
            primary_exposure="SSH on port 22",
            secondary_exposures=[],
        )
        result = AttackSurfaceResult(attack_surfaces=surfaces, summary=summary)
        json_str = json.dumps(asdict(result))
        loaded = json.loads(json_str)
        loaded_surfaces = [AttackSurface.from_dict(s) for s in loaded["attack_surfaces"]]
        assert loaded_surfaces[0].name == "SSH Server"
        assert loaded_surfaces[0].port_info.port == 22

    def test_from_dict(self):
        """Test from_dict classmethod with nested data."""
        d = {
            "attack_surfaces": [
                {
                    "name": "HTTP Server",
                    "category": "network_service",
                    "entry_functions": ["httpd_main"],
                    "protocol": "HTTP",
                    "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed"},
                    "risks": ["buffer_overflow"],
                }
            ],
            "summary": {
                "total_attack_surfaces": 1,
                "primary_exposure": "HTTP",
                "secondary_exposures": [],
            },
        }
        result = AttackSurfaceResult.from_dict(d)
        assert result.count == 1
        assert result.attack_surfaces[0].port_info.port == 80


class TestDirection:
    """Tests for Direction dataclass."""

    def test_create_direction(self):
        d = Direction(
            name="HTTP Request Processing",
            description="All HTTP request handling including CGI dispatch",
            category="http_processing",
            entry_functions=["httpd_main"],
            core_functions=["httpd_main", "cgi_handler", "parse_http_request"],
            big_pool=["httpd_main", "cgi_handler", "parse_http_request", "url_decode", "get_param"],
            primary_attack_types=["buffer_overflow", "command_injection"],
            priority=5,
        )
        assert d.name == "HTTP Request Processing"
        assert d.priority == 5
        assert d.estimated_complexity == "medium"
        assert d.rationale == ""

    def test_priority_bounds(self):
        d = Direction(
            name="Test",
            description="Test",
            category="auth_management",
            entry_functions=["test"],
            core_functions=["test"],
            big_pool=["test"],
            priority=3,
        )
        assert 1 <= d.priority <= 5

    def test_priority_out_of_bounds(self):
        with pytest.raises(ValueError, match="Priority must be 1-5"):
            Direction(
                name="Test",
                description="Test",
                category="auth_management",
                entry_functions=["test"],
                core_functions=["test"],
                big_pool=["test"],
                priority=0,
            )

    def test_invalid_category(self):
        with pytest.raises(ValueError, match="Invalid direction category"):
            Direction(
                name="Test",
                description="Test",
                category="invalid_category",
                entry_functions=["test"],
                core_functions=["test"],
                big_pool=["test"],
            )

    def test_natural_key(self):
        d = Direction(
            name="UPnP Protocol Parsing",
            description="UPnP SSDP and SOAP handling",
            category="protocol_parsing",
            entry_functions=["upnp_parse"],
            core_functions=["upnp_parse", "ssdp_handler"],
            big_pool=["upnp_parse", "ssdp_handler", "http_recv", "soap_dispatch"],
            primary_attack_types=["buffer_overflow"],
            priority=4,
        )
        assert d.natural_key == "UPnP Protocol Parsing"

    def test_serialization(self):
        d = Direction(
            name="Auth Module",
            description="Authentication and session management",
            category="auth_management",
            entry_functions=["login_handler"],
            core_functions=["login_handler", "verify_password", "check_session"],
            big_pool=["login_handler", "verify_password", "check_session", "strcmp", "malloc"],
            primary_attack_types=["auth_bypass"],
            secondary_attack_types=["buffer_overflow"],
            priority=4,
            estimated_complexity="high",
            rationale="Authentication is always high-risk; custom crypto suspected",
        )
        d2 = asdict(d)
        assert d2["name"] == "Auth Module"
        assert d2["priority"] == 4
        assert d2["estimated_complexity"] == "high"

    def test_json_roundtrip(self):
        d = Direction(
            name="File Upload Handler",
            description="Handles file upload via HTTP POST",
            category="file_handling",
            entry_functions=["cgi_upload"],
            core_functions=["cgi_upload", "save_file", "check_extension"],
            big_pool=["cgi_upload", "save_file", "check_extension", "fopen", "fwrite"],
            primary_attack_types=["path_traversal", "command_injection"],
            priority=5,
            estimated_complexity="medium",
        )
        json_str = json.dumps(asdict(d))
        loaded = json.loads(json_str)
        d2 = Direction(**loaded)
        assert d.name == d2.name
        assert d.priority == d2.priority
        assert d.primary_attack_types == d2.primary_attack_types


class TestDirectionResult:
    """Tests for DirectionResult container."""

    def test_create_result(self):
        directions = [
            Direction(
                name="HTTP Processing",
                description="HTTP request handling",
                category="http_processing",
                entry_functions=["httpd_main"],
                core_functions=["httpd_main", "cgi_dispatch"],
                big_pool=["httpd_main", "cgi_dispatch", "parse_request"],
                priority=5,
            ),
            Direction(
                name="Auth Module",
                description="Login and session management",
                category="auth_management",
                entry_functions=["login_handler"],
                core_functions=["login_handler", "verify_auth"],
                big_pool=["login_handler", "verify_auth", "check_password"],
                priority=4,
            ),
        ]
        order = AnalysisOrder(
            recommended_sequence=["HTTP Processing", "Auth Module"],
            rationale="HTTP is network-facing and unauthenticated, most likely to yield critical bugs",
        )
        result = DirectionResult(directions=directions, analysis_order=order)
        assert len(result.directions) == 2
        assert result.analysis_order.recommended_sequence == ["HTTP Processing", "Auth Module"]

    def test_json_roundtrip(self):
        directions = [
            Direction(
                name="DNS Resolver",
                description="DNS query handling",
                category="protocol_parsing",
                entry_functions=["dns_handler"],
                core_functions=["dns_handler"],
                big_pool=["dns_handler", "parse_dns_query", "dns_lookup"],
                priority=3,
            ),
        ]
        order = AnalysisOrder(
            recommended_sequence=["DNS Resolver"],
            rationale="Only one direction",
        )
        result = DirectionResult(directions=directions, analysis_order=order)
        json_str = json.dumps(asdict(result))
        loaded = json.loads(json_str)
        assert len(loaded["directions"]) == 1
        assert loaded["analysis_order"]["recommended_sequence"] == ["DNS Resolver"]

    def test_empty_result(self):
        result = DirectionResult(
            directions=[],
            analysis_order=AnalysisOrder(recommended_sequence=[], rationale="No attack surfaces found"),
        )
        assert len(result.directions) == 0

    def test_from_dict(self):
        d = {
            "directions": [
                {
                    "name": "Test Dir",
                    "description": "A test direction",
                    "category": "network_service",
                    "entry_functions": ["test_func"],
                    "core_functions": ["test_func"],
                    "big_pool": ["test_func", "helper"],
                    "priority": 4,
                }
            ],
            "analysis_order": {
                "recommended_sequence": ["Test Dir"],
                "rationale": "Only direction",
            },
        }
        result = DirectionResult.from_dict(d)
        assert result.count == 1
        assert result.directions[0].name == "Test Dir"


class TestAnalysisOrder:
    """Tests for AnalysisOrder dataclass."""

    def test_create(self):
        ao = AnalysisOrder(
            recommended_sequence=["Direction A", "Direction B"],
            rationale="A then B for early critical finds",
        )
        assert ao.recommended_sequence == ["Direction A", "Direction B"]

    def test_serialization(self):
        ao = AnalysisOrder(
            recommended_sequence=["Dir1"],
            rationale="Only one",
        )
        d = asdict(ao)
        assert d["recommended_sequence"] == ["Dir1"]
