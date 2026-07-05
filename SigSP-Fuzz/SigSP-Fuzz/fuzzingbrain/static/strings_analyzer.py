"""
String extraction and analysis from firmware binaries.

Extracts strings from extracted firmware and categorizes them
for attack surface identification.
"""

import re
import subprocess
from pathlib import Path
from typing import List

from loguru import logger

from .models import StringRef


class StringsAnalyzer:
    """
    Extract and categorize strings from binaries.

    Uses the 'strings' command (or Python fallback) to extract printable
    strings, then categorizes them for attack surface analysis.

    Usage:
        analyzer = StringsAnalyzer()
        strings = analyzer.extract_strings("bin/httpd")
        for s in strings:
            print(f"[{s.category}] {s.value}")
    """

    # Minimum string length
    MIN_STRING_LENGTH = 4

    # Regex for interesting strings in firmware
    INTERESTING_PATTERNS = [
        re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP address
        re.compile(r":\d{2,5}"),                                 # Port
        re.compile(r"https?://"),                                # URL
        re.compile(r"/[a-zA-Z0-9/_.-]+"),                        # File path
        re.compile(r"[A-Z_]{3,}"),                               # ALL_CAPS identifiers
        re.compile(r"%[sdXxcnpf]"),                              # Format specifiers
        re.compile(r"password|passwd|admin|root|login|auth", re.I),
        re.compile(r"debug|test|TODO|FIXME", re.I),
    ]

    def __init__(self, strings_binary: str = "strings"):
        """
        Args:
            strings_binary: Path to 'strings' command (default: find in PATH)
        """
        self.strings_binary = strings_binary

    def extract_strings(self, binary_path: str) -> List[StringRef]:
        """
        Extract strings from a binary file and categorize them.

        Args:
            binary_path: Path to binary file

        Returns:
            List of StringRef objects
        """
        raw_strings = self._run_strings(binary_path)
        results = []

        for addr, value in raw_strings:
            # Skip very short strings and pure whitespace
            if len(value) < self.MIN_STRING_LENGTH or value.isspace():
                continue

            ref = StringRef(value=value, address=addr)
            ref.categorize()

            # Only keep interesting strings (reduce noise)
            if self._is_interesting(value):
                results.append(ref)

        logger.debug(f"Extracted {len(results)} interesting strings from {binary_path}")
        return results

    def _run_strings(self, binary_path: str) -> List[tuple]:
        """
        Run 'strings' command and return (offset, string) pairs.
        Falls back to pure Python if 'strings' command not available.
        """
        try:
            result = subprocess.run(
                [self.strings_binary, "-t", "x", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return self._python_strings(binary_path)

            pairs = []
            for line in result.stdout.strip().split("\n"):
                # Format: "<hex_offset> <string>"
                parts = line.split(None, 1)
                if len(parts) == 2:
                    try:
                        addr = int(parts[0], 16)
                        pairs.append((addr, parts[1]))
                    except ValueError:
                        pairs.append((0, parts[1]))

            return pairs

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return self._python_strings(binary_path)

    def _python_strings(self, binary_path: str) -> List[tuple]:
        """Fallback: extract strings using pure Python (slower but no deps)."""
        pairs = []
        current_string = []
        current_offset = 0

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except Exception:
            return pairs

        for i, byte in enumerate(data):
            # Printable ASCII: 0x20-0x7E
            if 0x20 <= byte <= 0x7E:
                if not current_string:
                    current_offset = i
                current_string.append(chr(byte))
            else:
                if len(current_string) >= self.MIN_STRING_LENGTH:
                    pairs.append((current_offset, "".join(current_string)))
                current_string = []

        # Don't forget the last string
        if len(current_string) >= self.MIN_STRING_LENGTH:
            pairs.append((current_offset, "".join(current_string)))

        return pairs

    def _is_interesting(self, value: str) -> bool:
        """Check if a string is interesting for vulnerability analysis."""
        for pattern in self.INTERESTING_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def extract_from_directory(self, dir_path: str, file_pattern: str = "*.so") -> List[StringRef]:
        """
        Extract strings from all matching files in a directory.

        Args:
            dir_path: Directory to search
            file_pattern: Glob pattern for files to analyze

        Returns:
            Combined list of StringRef objects
        """
        all_strings = []
        for file_path in Path(dir_path).rglob(file_pattern):
            if file_path.is_file():
                strings = self.extract_strings(str(file_path))
                all_strings.extend(strings)
        return all_strings
