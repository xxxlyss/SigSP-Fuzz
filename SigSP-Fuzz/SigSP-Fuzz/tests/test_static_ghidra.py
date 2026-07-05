"""
Tests for Ghidra analyzer and strings analyzer (with mocked subprocess).

No real Ghidra or firmware binaries needed.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from fuzzingbrain.static.models import BinaryInfo, FunctionInfo, AnalysisResult
from fuzzingbrain.static.ghidra_analyzer import GhidraAnalyzer
from fuzzingbrain.static.strings_analyzer import StringsAnalyzer


# Sample Ghidra JSON output to use in mocks
SAMPLE_GHIDRA_OUTPUT = {
    "binary_name": "httpd",
    "arch": "ARM",
    "bits": 32,
    "functions": [
        {
            "name": "main",
            "address": 4096,
            "pseudo_code": "int main(int argc, char **argv) {\n  httpd_main();\n  return 0;\n}",
            "parameter_count": 2,
            "callers": ["_start"],
            "callees": ["httpd_main"],
        },
        {
            "name": "httpd_main",
            "address": 8192,
            "pseudo_code": "void httpd_main(void) {\n  char buf[256];\n  char *input = recv_request();\n  strcpy(buf, input);\n}",
            "parameter_count": 0,
            "callers": ["main"],
            "callees": ["recv_request", "strcpy"],
        },
        {
            "name": "recv_request",
            "address": 16384,
            "pseudo_code": "char * recv_request(void) {\n  return recv(sock, buf, 4096, 0);\n}",
            "parameter_count": 0,
            "callers": ["httpd_main"],
            "callees": ["recv"],
        },
    ],
    "function_count": 3,
}


class TestGhidraAnalyzer:
    """Tests for GhidraAnalyzer with mocked Ghidra subprocess."""

    def test_init_default(self):
        analyzer = GhidraAnalyzer()
        assert analyzer.project_name == "firmware_analysis"
        assert analyzer.timeout == 1800

    def test_init_custom(self):
        analyzer = GhidraAnalyzer(
            ghidra_home="/custom/ghidra",
            timeout_seconds=600,
        )
        assert analyzer.ghidra_home == "/custom/ghidra"
        assert analyzer.timeout == 600

    def test_parse_functions_json(self):
        """Test parsing of Ghidra JSON output into FunctionInfo list."""
        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=True, entry_point=0x10000,
        )

        # Write sample JSON to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(SAMPLE_GHIDRA_OUTPUT, f)
            tmp_path = f.name

        try:
            functions, callgraph = analyzer._parse_functions_json(tmp_path, bi)

            assert len(functions) == 3
            assert functions[0].name == "main"
            assert functions[1].has_unsafe_calls is True  # calls strcpy
            assert "strcpy" in functions[1].dangerous_funcs
            assert callgraph.node_count == 3
            # 'strcpy' is an external function, not a graph node
            # get_call_path finds path TO the calling function
            path = callgraph.get_call_path("main", "httpd_main")
            assert path == ["main", "httpd_main"]

            # Check function with unsafe call detection
            unsafe_funcs = [f for f in functions if f.has_unsafe_calls]
            # httpd_main calls strcpy (dangerous), recv_request calls recv (dangerous)
            assert len(unsafe_funcs) == 2
            assert unsafe_funcs[0].name == "httpd_main"

        finally:
            os.unlink(tmp_path)

    @patch("subprocess.run")
    def test_analyze_binary_success(self, mock_run):
        """Test full analyze_binary flow with mocked Ghidra success."""
        # Mock subprocess.run to simulate Ghidra success
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Exported 3 functions"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/httpd", arch="arm", bits=32, endian="little",
            file_type="web_server", stripped=False, entry_point=0x10000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the expected output file
            func_json = Path(tmpdir) / "httpd_functions.json"
            with open(func_json, "w") as f:
                json.dump(SAMPLE_GHIDRA_OUTPUT, f)

            # Create a fake binary file
            fake_binary = Path(tmpdir) / "httpd"
            fake_binary.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100)

            result = analyzer.analyze_binary(
                str(fake_binary), bi, tmpdir
            )

            assert result.success is True
            assert result.function_count == 3
            assert result.callgraph is not None
            assert result.analysis_time_seconds > 0

    @patch("subprocess.run")
    def test_analyze_binary_ghidra_not_found(self, mock_run):
        """Test analyze_binary when Ghidra is not installed."""
        mock_run.side_effect = FileNotFoundError("No such file")

        analyzer = GhidraAnalyzer()
        bi = BinaryInfo(
            path="bin/test", arch="mips", bits=32, endian="big",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = Path(tmpdir) / "test"
            fake_binary.write_bytes(b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 100)

            result = analyzer.analyze_binary(str(fake_binary), bi, tmpdir)

            assert result.success is False
            assert result.error is not None
            assert "not found" in result.error.lower()

    @patch("subprocess.run")
    def test_analyze_binary_timeout(self, mock_run):
        """Test Ghidra timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("ghidra", 1800)

        analyzer = GhidraAnalyzer(timeout_seconds=1)
        bi = BinaryInfo(
            path="bin/test", arch="arm", bits=32, endian="little",
            file_type="daemon", stripped=True, entry_point=0x4000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = Path(tmpdir) / "test"
            fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

            result = analyzer.analyze_binary(str(fake_binary), bi, tmpdir)

            assert result.success is False
            assert "timed out" in result.error.lower()


class TestStringsAnalyzer:
    """Tests for StringsAnalyzer."""

    def test_init(self):
        sa = StringsAnalyzer()
        assert sa.MIN_STRING_LENGTH == 4

    def test_python_strings_extraction(self):
        """Test the fallback Python string extraction."""
        sa = StringsAnalyzer()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Create a simple binary with some known strings
            # Note: "Hello World" won't match INTERESTING_PATTERNS and gets filtered
            f.write(b"admin:password123\x00")
            f.write(b"http://192.168.1.1/cgi-bin/admin\x00")
            f.write(b"/etc/shadow\x00")
            f.write(b"xyz\x00")  # Too short, should be filtered
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            assert len(strings) >= 3

            categories = [s.category for s in strings]
            assert "credential" in categories
            assert "url" in categories
            assert "path" in categories

        finally:
            os.unlink(tmp_path)

    def test_string_categorization(self):
        """Test that extract_strings correctly categorizes strings."""
        sa = StringsAnalyzer()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # URL-related
            f.write(b"/cgi-bin/vuln\x00")
            f.write(b"/www/admin.html\x00")
            f.write(b"GET / HTTP/1.1\x00")

            # Port-related
            f.write(b"0.0.0.0:80\x00")
            f.write(b"Listening on port 8080\x00")

            # Protocol-related
            f.write(b"UPnP/1.0\x00")
            f.write(b"M-SEARCH * HTTP/1.1\x00")

            # Debug-related
            f.write(b"TODO: fix buffer size\x00")
            f.write(b"DEBUG: entering handler\x00")

            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)

            categories = {s.category for s in strings}
            assert "url" in categories
            assert "port" in categories
            assert "protocol" in categories
            assert "debug" in categories

        finally:
            os.unlink(tmp_path)

    def test_empty_file(self):
        """Test string extraction on empty file."""
        sa = StringsAnalyzer()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"")
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            assert len(strings) == 0
        finally:
            os.unlink(tmp_path)

    def test_short_strings_filtered(self):
        """Test that strings shorter than MIN_STRING_LENGTH are filtered."""
        sa = StringsAnalyzer()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"ab\x00")      # Too short (2 chars)
            f.write(b"abc\x00")     # Too short (3 chars)
            f.write(b"root\x00")    # 4 chars, matches 'credential' pattern
            tmp_path = f.name

        try:
            strings = sa.extract_strings(tmp_path)
            # Only "root" should appear (4 chars + matches interesting pattern)
            assert len(strings) == 1
            assert strings[0].value == "root"
        finally:
            os.unlink(tmp_path)
