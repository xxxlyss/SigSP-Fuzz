"""
Objdump-based binary analysis — Ghidra-free fallback for Phase 1.

Uses standard binutils (objdump, readelf, strings) to extract:
- Function symbols with addresses
- Disassembly (as pseudo_code replacement)
- Dynamic imports (dangerous function detection)
- Printable strings with categorization

Same interface as GhidraAnalyzer.analyze_binary() → returns AnalysisResult.
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger

from .models import BinaryInfo, FunctionInfo, CallGraph, StringRef, AnalysisResult
from .callgraph import CallGraphBuilder
from .strings_analyzer import StringsAnalyzer


# ---------------------------------------------------------------------------
# Known dangerous function names (matching GhidraAnalyzer list)
# ---------------------------------------------------------------------------

DANGEROUS_FUNCTIONS: Set[str] = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "memcpy", "memmove", "bcopy", "read", "recv", "recvfrom",
    "system", "popen", "execve", "execvp", "execl", "execlp",
    "printf", "fprintf", "snprintf", "vprintf", "syslog",
}

# Broader set for detection from dynamic symbols
DANGEROUS_PATTERNS = re.compile(
    r'\b(' + '|'.join(re.escape(f) for f in DANGEROUS_FUNCTIONS) + r')\b'
)


class ObjdumpAnalyzer:
    """Analyze a single ELF binary using objdump + readelf + strings.

    Drop-in replacement for GhidraAnalyzer when Ghidra is not installed.
    Produces FunctionInfo entries with disassembly in the pseudo_code field.

    Usage:
        analyzer = ObjdumpAnalyzer()
        result = analyzer.analyze_binary(
            binary_path="extracted/bin/httpd",
            binary_info=BinaryInfo(...),
            output_dir="analysis/httpd/",
        )
    """

    # Architecture → cross-tool prefix mapping (for objdump/readelf)
    CROSS_PREFIX_MAP = {
        "mips":   {"little": "mipsel-linux-gnu-", "big": "mips-linux-gnu-"},
        "arm":    {"little": "arm-linux-gnueabi-", "big": "arm-linux-gnueabi-"},
        "aarch64": {"little": "aarch64-linux-gnu-", "big": "aarch64_be-linux-gnu-"},
        "riscv":  {"little": "riscv64-linux-gnu-", "big": "riscv64-linux-gnu-"},
        "x86":    {"little": "", "big": ""},  # native tools
        "i386":   {"little": "", "big": ""},
        "x86_64": {"little": "", "big": ""},
        "powerpc": {"little": "powerpc-linux-gnu-", "big": "powerpc-linux-gnu-"},
    }

    def __init__(
        self,
        objdump_bin: str = "objdump",
        readelf_bin: str = "readelf",
        strings_bin: str = "strings",
        disassemble_all: bool = False,  # True = full disassembly (slow)
        max_disasm_funcs: int = 200,     # Max functions to disassemble
        timeout_seconds: int = 600,
    ):
        self.objdump_bin = objdump_bin
        self.readelf_bin = readelf_bin
        self.strings_bin = strings_bin
        self.disassemble_all = disassemble_all
        self.max_disasm_funcs = max_disasm_funcs
        self.timeout = timeout_seconds
        self._strings_analyzer = StringsAnalyzer(strings_binary=strings_bin)

        # Auto-detect cross-tool availability
        self._cross_tools_cache: Dict[str, str] = {}

    def _get_tool(self, base: str, arch: str, endian: str) -> str:
        """Get the best available tool for a given architecture.

        Tries cross-prefix version first, falls back to native.
        """
        cache_key = f"{base}-{arch}-{endian}"
        if cache_key in self._cross_tools_cache:
            return self._cross_tools_cache[cache_key]

        arch_lower = arch.lower()
        endian_lower = endian.lower()

        # Look up prefix
        prefix_map = self.CROSS_PREFIX_MAP.get(arch_lower, {})
        prefix = prefix_map.get(endian_lower, "")

        if prefix:
            cross_tool = f"{prefix}{base}"
            import shutil
            if shutil.which(cross_tool):
                self._cross_tools_cache[cache_key] = cross_tool
                return cross_tool

        # Fallback: search common patterns
        for prefix_candidate in [
            f"{arch_lower}-linux-gnu-",
            f"{arch_lower}el-linux-gnu-",
            f"{arch_lower}eb-linux-gnu-",
        ]:
            cross_tool = f"{prefix_candidate}{base}"
            import shutil
            if shutil.which(cross_tool):
                self._cross_tools_cache[cache_key] = cross_tool
                return cross_tool

        # Native tool
        self._cross_tools_cache[cache_key] = base
        return base

    # -- Public API (matching GhidraAnalyzer) -------------------------------

    def analyze_binary(
        self,
        binary_path: str,
        binary_info: BinaryInfo,
        output_dir: str,
    ) -> AnalysisResult:
        """Analyze a single binary and return FunctionInfo + CallGraph.

        Args:
            binary_path: Path to the ELF binary.
            binary_info: BinaryInfo from FirmwareExtractor.
            output_dir: Directory for analysis artifacts.

        Returns:
            AnalysisResult with functions, callgraph, and strings.
        """
        start_time = time.time()

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        if not os.path.exists(binary_path):
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error=f"Binary not found: {binary_path}",
            )

        # Store current arch info for internal tool selection
        self._current_arch = binary_info.arch
        self._current_endian = binary_info.endian

        binary_name = Path(binary_path).name
        logger.info(
            f"[objdump] Analyzing {binary_name} "
            f"({binary_info.arch}, {binary_info.bits}-bit)"
        )

        # Collect errors as we go (non-fatal individually)
        errors: List[str] = []

        # Step 1: Extract function symbols (local + imported)
        symbols = self._get_function_symbols(binary_path, binary_info.bits)
        imported_symbols = self._get_imported_symbols(binary_path)
        # Merge: local symbols + imported symbols (for address resolution)
        all_symbols = symbols + imported_symbols

        if not symbols and not imported_symbols:
            # Fallback: disassemble entire text segment for stripped binaries
            logger.info(
                f"[objdump] {binary_name}: stripped — using full text disassembly"
            )
            return self._analyze_stripped_binary(
                binary_path, binary_info, output_dir, start_time
            )

        # Step 2: Get dynamic imports (dangerous function detection)
        dynamic_imports = self._get_dynamic_imports(binary_path)

        # Step 3: Get disassembly for selected functions
        disasm_map = self._get_disassembly(
            binary_path, symbols, binary_info
        )

        # Step 4: Build FunctionInfo list
        functions = self._build_function_info_list(
            all_symbols, dynamic_imports, disasm_map, binary_info
        )

        # Step 5: Build call graph
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path=binary_info.path)

        # Step 6: Extract strings
        try:
            strings = self._strings_analyzer.extract_strings(binary_path)
        except Exception as e:
            logger.warning(f"String extraction failed for {binary_name}: {e}")
            strings = []

        elapsed = time.time() - start_time
        unsafe_count = sum(1 for f in functions if f.has_unsafe_calls)
        logger.info(
            f"[objdump] {binary_name}: {len(functions)} functions "
            f"({unsafe_count} with unsafe calls), "
            f"{len(strings)} strings, {elapsed:.1f}s"
        )

        return AnalysisResult(
            binary=binary_info,
            success=True,
            functions=functions,
            callgraph=callgraph,
            strings=strings,
            analysis_time_seconds=elapsed,
        )

    # -- Stripped Binary Fallback --------------------------------------------

    def _get_text_segment_info(self, binary_path: str) -> Optional[Tuple[int, int, int]]:
        """Parse program headers to find executable LOAD segment.

        Returns (file_offset, virtual_address, memsz) or None.
        For stripped binaries without section headers, we use program
        headers to locate the .text segment in the file.
        """
        readelf = self._get_tool("readelf", self._current_arch, self._current_endian)
        try:
            result = subprocess.run(
                [readelf, "-l", binary_path],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return None

            # Parse LOAD segments with R|E flags
            #   LOAD  0x000000 0x00400000 0x00400000 0x99460 0x99460 R E 0x10000
            # Flags may be single (R, RW) or multi-word (R E, RW E).
            load_re = re.compile(
                r'\s+LOAD\s+'
                r'(0x[0-9a-fA-F]+)\s+'   # offset
                r'(0x[0-9a-fA-F]+)\s+'   # vaddr
                r'(0x[0-9a-fA-F]+)\s+'   # paddr
                r'(0x[0-9a-fA-F]+)\s+'   # filesz
                r'(0x[0-9a-fA-F]+)\s+'   # memsz
                r'([RWE ]+?)\s+'          # flags (R, E, W, or combos like R E)
                r'0x'                     # start of Align column
            )
            for m in load_re.finditer(result.stdout):
                flags = m.group(6)
                if 'R' in flags and 'E' in flags:
                    offset = int(m.group(1), 16)
                    vaddr = int(m.group(2), 16)
                    memsz = int(m.group(5), 16)
                    logger.debug(
                        f"[objdump] Text segment: offset=0x{offset:x} "
                        f"vaddr=0x{vaddr:x} size=0x{memsz:x}"
                    )
                    return (offset, vaddr, memsz)

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"[objdump] readelf -l failed: {e}")

        return None

    def _disassemble_raw_segment(
        self,
        binary_path: str,
        offset: int,
        vaddr: int,
        size: int,
    ) -> Optional[str]:
        """Disassemble a raw binary segment using objdump -D on extracted bytes.

        For stripped binaries, we extract the text segment bytes and
        disassemble them as a raw binary blob.
        """
        import tempfile

        # Extract text segment bytes
        try:
            with open(binary_path, "rb") as f:
                f.seek(offset)
                raw_bytes = f.read(size)
            if not raw_bytes:
                return None
        except (OSError, IOError) as e:
            logger.warning(f"[objdump] Failed to read text segment: {e}")
            return None

        # Write raw bytes to temp file for objdump
        with tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        try:
            # Map architecture to objdump -m target
            ARCH_MAP = {
                "mips": "mips",
                "mipsel": "mips",
                "arm": "arm",
                "armeb": "arm",
                "aarch64": "aarch64",
                "riscv": "riscv",
                "riscv64": "riscv",
                "x86": "i386",
                "x86_64": "i386:x86-64",
                "ppc": "powerpc",
            }

            # Build arch-specific flags
            arch_lower = self._current_arch.lower()
            machine = ARCH_MAP.get(arch_lower, arch_lower)

            start_addr = vaddr
            stop_addr = vaddr + size

            objdump = self._get_tool(
                "objdump", self._current_arch, self._current_endian
            )
            result = subprocess.run(
                [
                    objdump,
                    "-D", "-b", "binary", "-m", machine,
                    f"--start-address=0x{start_addr:x}",
                    f"--stop-address=0x{stop_addr:x}",
                    f"--adjust-vma=0x{vaddr:x}",
                    tmp_path,
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                logger.warning(
                    f"[objdump] raw disassembly failed: {result.stderr[:200]}"
                )
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"[objdump] raw disassembly error: {e}")
            return None
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _find_function_boundaries_mips(
        self, disasm_lines: List[str], vaddr: int, size: int
    ) -> List[Tuple[int, str]]:
        """Find function entry points in MIPS disassembly.

        Uses two strategies:
        1. jal/bal call targets — any address explicitly called is a function
        2. Stack-frame prologue — addiu sp,sp,-N indicates a new frame

        Filters entries to those within [vaddr, vaddr+size).

        Returns list of (address, label) sorted by address.
        """
        entries: Dict[int, str] = {}
        max_addr = vaddr + size

        # Strategy 1: Find all jal/bal targets (most reliable)
        jal_re = re.compile(
            r'(?:jal|bal)\s+'
            r'(0x)?([0-9a-fA-F]+)'
        )
        for line in disasm_lines:
            m = jal_re.search(line)
            if m:
                addr = int(m.group(2), 16)
                if vaddr <= addr < max_addr and addr not in entries:
                    entries[addr] = f"func_{addr:08x}"

        # Strategy 2: MIPS stack-frame prologue (addiu sp,sp,-N)
        prologue_re = re.compile(
            r'\s+([0-9a-fA-F]+):\s+\S+\s+addiu\s+sp,sp,-'
        )
        for line in disasm_lines:
            m = prologue_re.search(line)
            if m:
                addr = int(m.group(1), 16)
                if vaddr <= addr < max_addr and addr not in entries:
                    entries[addr] = f"func_{addr:08x}"

        # Sort by address
        sorted_entries = sorted(entries.items(), key=lambda x: x[0])
        return sorted_entries

    def _get_dynamic_plt_imports(self, binary_path: str) -> Set[str]:
        """Get imported function names from PLT relocations.

        Works even for stripped binaries with no section headers,
        since program headers still reference the dynamic section.
        """
        imports: Set[str] = set()
        readelf = self._get_tool("readelf", self._current_arch, self._current_endian)
        try:
            result = subprocess.run(
                [readelf, "--use-dynamic", "-r", binary_path],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return imports

            # Parse R_MIPS_JUMP_SLOT entries
            #   004aa01c  0000017f R_MIPS_JUMP_SLOT  00000000   printf
            for line in result.stdout.split("\n"):
                if "R_MIPS_JUMP_SLOT" in line or "R_ARM_JUMP_SLOT" in line or \
                   "R_X86_64_JUMP_SLOT" in line or "R_386_JMP_SLOT" in line or \
                   "R_RISCV_JUMP_SLOT" in line:
                    parts = line.split()
                    if parts:
                        name = parts[-1]
                        if name and not name.startswith("R_"):
                            imports.add(name)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return imports

    def _analyze_stripped_binary(
        self,
        binary_path: str,
        binary_info: BinaryInfo,
        output_dir: str,
        start_time: float,
    ) -> AnalysisResult:
        """Analyze a stripped binary using raw text-segment disassembly.

        For binaries without symbol tables or section headers:
        1. Parse program headers to find the .text LOAD segment
        2. Extract raw bytes and disassemble with objdump -D
        3. Identify function boundaries via call targets and prologues
        4. Build synthetic FunctionInfo objects

        Returns AnalysisResult with functions populated.
        """
        binary_name = Path(binary_path).name
        errors: List[str] = []

        # Step 1: Find text segment via program headers
        seg_info = self._get_text_segment_info(binary_path)
        if not seg_info:
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error="Cannot locate text segment (no program headers with R|E LOAD)",
                analysis_time_seconds=time.time() - start_time,
            )

        offset, vaddr, size = seg_info
        logger.info(
            f"[objdump] Stripped binary: offset=0x{offset:x} "
            f"vaddr=0x{vaddr:x} size=0x{size:x} ({size//1024}KB)"
        )

        # Step 2: Get entry point (for naming the first function)
        entry_point = None
        try:
            readelf = self._get_tool("readelf", self._current_arch, self._current_endian)
            result = subprocess.run(
                [readelf, "-h", binary_path],
                capture_output=True, text=True, timeout=10,
            )
            m = re.search(r'Entry point address:\s+(0x[0-9a-fA-F]+)', result.stdout)
            if m:
                entry_point = int(m.group(1), 16)
        except Exception:
            pass

        # Step 3: Disassemble the raw text segment
        disasm = self._disassemble_raw_segment(
            binary_path, offset, vaddr, size
        )
        if not disasm:
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error="Raw text segment disassembly failed",
                analysis_time_seconds=time.time() - start_time,
            )
        disasm_lines = disasm.split("\n")

        # Step 4: Find function boundaries
        func_entries = self._find_function_boundaries_mips(
            disasm_lines, vaddr, size
        )

        # Ensure entry point is included
        if entry_point and entry_point not in dict(func_entries):
            func_entries.append((entry_point, f"entry_{entry_point:08x}"))
            func_entries.sort(key=lambda x: x[0])

        if not func_entries:
            # No call targets found — create a single function for the
            # entire disassembly
            func_entries = [(vaddr, f"binary_{binary_name.replace('.', '_')}")]

        logger.info(
            f"[objdump] Found {len(func_entries)} function entries "
            f"in stripped binary {binary_name}"
        )

        # Step 5: Split disassembly into per-function chunks
        # Build address-to-line mapping
        addr_to_line: Dict[int, int] = {}
        addr_re = re.compile(r'\s+([0-9a-fA-F]+):\s')
        for i, line in enumerate(disasm_lines):
            m = addr_re.match(line)
            if m:
                addr = int(m.group(1), 16)
                if addr not in addr_to_line:
                    addr_to_line[addr] = i

        # Get PLT imports for dangerous function detection
        # (stripped binaries still have PLT/GOT via program headers)
        plt_imports = self._get_dynamic_plt_imports(binary_path)
        dangerous_imports = plt_imports & DANGEROUS_FUNCTIONS

        # Build FunctionInfo for each detected function
        functions: List[FunctionInfo] = []
        MAX_FUNC_DISASM_LINES = 3000  # ~100KB of text per function max
        MAX_FUNCTIONS = 200           # Cap for stripped binaries

        # Limit function count
        if len(func_entries) > MAX_FUNCTIONS:
            # Prioritize: entry point + largest functions
            header_entries = func_entries[:1]  # entry point
            body_entries = func_entries[1:]
            # Sort body by gap size (larger functions have bigger gaps)
            body_with_gaps = []
            for i, (addr, label) in enumerate(body_entries):
                next_addr = (
                    body_entries[i + 1][0]
                    if i + 1 < len(body_entries)
                    else vaddr + size
                )
                gap = next_addr - addr
                body_with_gaps.append((gap, addr, label))
            body_with_gaps.sort(key=lambda x: x[0], reverse=True)
            func_entries = header_entries + [
                (addr, label) for _, addr, label in body_with_gaps[:MAX_FUNCTIONS - 1]
            ]

        for i, (func_addr, func_name) in enumerate(func_entries):
            # Find the line index for this function's start
            start_line = addr_to_line.get(func_addr)
            if start_line is None:
                # Find closest line
                closest_addrs = sorted(
                    addr_to_line.keys(),
                    key=lambda a: abs(a - func_addr),
                )
                if closest_addrs:
                    start_line = addr_to_line[closest_addrs[0]]

            if start_line is None:
                continue

            # Determine end line: next function's start line
            if i + 1 < len(func_entries):
                next_addr = func_entries[i + 1][0]
                end_line = addr_to_line.get(next_addr, start_line + MAX_FUNC_DISASM_LINES)
            else:
                end_line = len(disasm_lines)

            # Cap to prevent huge functions
            end_line = min(end_line, start_line + MAX_FUNC_DISASM_LINES)

            # Extract function disassembly
            func_lines = disasm_lines[start_line:end_line]
            pseudo_code = "\n".join(func_lines)

            # Detect dangerous calls — for stripped binaries, we look for
            # indirect jumps (jalr t9) which are MIPS PLT calls, and
            # cross-reference with the binary's dangerous PLT imports.
            dangerous = []
            func_text = pseudo_code
            if "jalr" in func_text and dangerous_imports:
                # Function makes indirect calls (likely to PLT) and binary
                # imports dangerous functions.  Conservatively mark all
                # dangerous imports that appear in this function's text
                # (referenced via gp-relative loads).
                for df in sorted(dangerous_imports):
                    # Look for the function name anywhere in this function's
                    # code region (may appear in gp-relative load comments)
                    # or mark all if jalr is present.
                    if df in func_text:
                        dangerous.append(df)
                # If no individual matches but function uses jalr,
                # include all dangerous imports (conservative).
                if not dangerous:
                    dangerous = sorted(dangerous_imports)

            # Detect callees from direct jal targets in disassembly
            callees: Set[str] = set()
            # Direct calls with label:  jal 0x402d60 <func_name>
            jal_sym_re = re.compile(
                r'(?:jal|bal)\s+(?:0x)?[0-9a-fA-F]+\s+<(.+?)>'
            )
            for line in func_lines:
                for m in jal_sym_re.finditer(line):
                    callee = m.group(1)
                    if "+" in callee and not callee.startswith("+"):
                        callee = callee.split("+")[0]
                    callees.add(callee)
            # Also include PLT-imported dangerous functions as callees
            callees.update(dangerous_imports)

            fi = FunctionInfo(
                name=func_name,
                address=func_addr,
                pseudo_code=pseudo_code,
                assembly="",
                callers=[],
                callees=list(callees),
                parameters=0,
                complexity=len(func_lines),
                has_unsafe_calls=len(dangerous) > 0,
                dangerous_funcs=dangerous,
                strings_used=[],
                arch=binary_info.arch,
                section=".text",
                binary_path=binary_info.path,
            )
            functions.append(fi)

        # Step 6: Build call graph
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path=binary_info.path)

        # Step 7: Extract strings
        try:
            strings = self._strings_analyzer.extract_strings(binary_path)
        except Exception as e:
            logger.warning(f"String extraction failed for {binary_name}: {e}")
            strings = []

        elapsed = time.time() - start_time
        unsafe_count = sum(1 for f in functions if f.has_unsafe_calls)
        logger.info(
            f"[objdump] {binary_name} (stripped): {len(functions)} functions "
            f"({unsafe_count} with unsafe calls), "
            f"{len(strings)} strings, {elapsed:.1f}s"
        )

        return AnalysisResult(
            binary=binary_info,
            success=True,
            functions=functions,
            callgraph=callgraph,
            strings=strings,
            analysis_time_seconds=elapsed,
        )

    # -- Symbol extraction --------------------------------------------------

    def _get_function_symbols(
        self, binary_path: str, bits: int
    ) -> List[Dict]:
        """Extract function symbols using readelf or objdump.

        Returns list of dicts with: name, address, size
        """
        symbols = []

        # Try readelf first (cleaner output)
        readelf = self._get_tool("readelf", self._current_arch, self._current_endian)
        try:
            result = subprocess.run(
                [readelf, "-s", "-W", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                symbols = self._parse_readelf_symbols(result.stdout, bits)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback to objdump -t
        if not symbols:
            objdump = self._get_tool("objdump", self._current_arch, self._current_endian)
            try:
                result = subprocess.run(
                    [objdump, "-t", binary_path],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    symbols = self._parse_objdump_symbols(result.stdout)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # If still empty, binary is likely stripped
        if not symbols:
            dyn_symbols = self._get_dynamic_symbols(binary_path)
            if dyn_symbols:
                symbols = dyn_symbols

        return symbols

    def _parse_readelf_symbols(
        self, output: str, bits: int
    ) -> List[Dict]:
        """Parse readelf -s -W output for function symbols."""
        symbols = []
        # readelf format:  Num:    Value  Size Type    Bind   Vis      Ndx Name
        # Example:         42: 00400630   112 FUNC    GLOBAL DEFAULT   12 main
        for line in output.split("\n"):
            if " FUNC " not in line:
                continue
            parts = line.split()
            # Find the index of "FUNC"
            try:
                func_idx = parts.index("FUNC")
                # Value is the field before Num (index 1 after the colon)
                # Actually the format is: Num: Value Size Type Bind Vis Ndx Name
                # After splitting: ["42:", "00400630", "112", "FUNC", ...]
                if len(parts) >= func_idx + 1:
                    addr_str = parts[1]  # 0th is "Num:", 1st is Value
                    try:
                        if addr_str.startswith("0x") or addr_str.startswith("0X"):
                            address = int(addr_str, 16)
                        else:
                            # Some readelf versions don't prefix with 0x
                            address = int(addr_str, 16)
                    except ValueError:
                        continue

                    size_str = parts[2]
                    try:
                        size = int(size_str)
                    except ValueError:
                        size = 0

                    name = parts[-1]
                    # Filter out non-function symbols and tiny entries
                    if name and not name.startswith(".") and size > 0:
                        symbols.append({
                            "name": name,
                            "address": address,
                            "size": size,
                        })
            except (ValueError, IndexError):
                continue

        return symbols

    def _parse_objdump_symbols(self, output: str) -> List[Dict]:
        """Parse objdump -t output for function symbols."""
        symbols = []
        # Format: address  flags  section  size  name
        # Example: 00400630 g     F .text  00000070 main
        for line in output.split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            # objdump symbol flags: g=global, l=local, F=function, O=object
            flags = parts[1]
            if "F" not in flags:
                continue
            try:
                address = int(parts[0], 16)
                size = int(parts[3], 16)
                name = parts[4]
                if name and not name.startswith(".") and size > 0:
                    symbols.append({
                        "name": name,
                        "address": address,
                        "size": size,
                    })
            except (ValueError, IndexError):
                continue

        return symbols

    def _get_dynamic_symbols(self, binary_path: str) -> List[Dict]:
        """Get exported dynamic symbols (for stripped binaries)."""
        symbols = []
        objdump = self._get_tool("objdump", self._current_arch, self._current_endian)
        try:
            result = subprocess.run(
                [objdump, "-T", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if not line.strip() or "UND" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            address = int(parts[0], 16)
                            size_str = parts[4]
                            try:
                                size = int(size_str, 16)
                            except ValueError:
                                size = 0
                            name = parts[-1]
                            if name and size > 0:
                                symbols.append({
                                    "name": name,
                                    "address": address,
                                    "size": size,
                                })
                        except (ValueError, IndexError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return symbols

    def _get_imported_symbols(self, binary_path: str) -> List[Dict]:
        """Get imported function symbols (UND) with their resolved addresses.

        For statically-linked binaries (like DVRF with uClibc), imported
        functions may be resolved at link-time and appear in the symbol
        table with addresses. We extract them so _extract_callees can
        match disassembly calls to function names.
        """
        symbols = []
        objdump = self._get_tool("objdump", self._current_arch, self._current_endian)

        try:
            result = subprocess.run(
                [objdump, "-t", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return symbols

            for line in result.stdout.split("\n"):
                if "*UND*" not in line:
                    continue
                # Format: 00400a30       F *UND*  00000024              strcpy
                parts = line.split()
                if len(parts) < 5:
                    continue
                try:
                    address = int(parts[0], 16)
                    name = parts[-1]
                    if name and not name.startswith("."):
                        symbols.append({
                            "name": name,
                            "address": address,
                            "size": 0,  # imported, size unknown
                        })
                except ValueError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return symbols

    # -- Dynamic imports ----------------------------------------------------

    def _get_dynamic_imports(self, binary_path: str) -> Dict[str, Set[str]]:
        """Get dangerous imported functions via dynamic symbol table.

        Uses objdump -T (dynamic) and objdump -t (full symbol table, for
        statically-linked binaries) to find all imported functions that
        match the DANGEROUS_FUNCTIONS set.

        Returns dict: {"*": set_of_dangerous_imports} for global annotation.
        """
        imports: Set[str] = set()
        objdump = self._get_tool("objdump", self._current_arch, self._current_endian)

        # Try dynamic symbol table first (dynamically linked binaries)
        try:
            result = subprocess.run(
                [objdump, "-T", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "*UND*" in line:
                        parts = line.split()
                        if parts:
                            name = parts[-1]
                            if name in DANGEROUS_FUNCTIONS:
                                imports.add(name)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Also check full symbol table (statically-linked binaries like DVRF)
        # In statically-linked uClibc binaries, imported functions have
        # resolved addresses but appear as *UND* in the full symbol table.
        if not imports:
            try:
                result = subprocess.run(
                    [objdump, "-t", binary_path],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "*UND*" in line:
                            parts = line.split()
                            if parts:
                                name = parts[-1]
                                if name in DANGEROUS_FUNCTIONS:
                                    imports.add(name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return {"*": imports}

    # -- Disassembly --------------------------------------------------------

    def _get_disassembly(
        self,
        binary_path: str,
        symbols: List[Dict],
        binary_info: BinaryInfo,
    ) -> Dict[str, str]:
        """Disassemble selected functions via objdump -d.

        Limits to max_disasm_funcs (largest functions first) unless
        disassemble_all is True.
        """
        # Select functions to disassemble
        if self.disassemble_all:
            to_disasm = symbols
        else:
            sorted_syms = sorted(symbols, key=lambda s: s["size"], reverse=True)
            to_disasm = sorted_syms[:self.max_disasm_funcs]

        if not to_disasm:
            return {}

        objdump = self._get_tool("objdump", self._current_arch, self._current_endian)

        try:
            result = subprocess.run(
                [objdump, "-d", binary_path],
                capture_output=True, text=True, timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.warning(
                    f"objdump -d failed: {result.stderr[:200]}"
                )
                return {}

            return self._parse_disassembly(result.stdout, to_disasm)

        except subprocess.TimeoutExpired:
            logger.warning("objdump -d timed out")
            return {}
        except FileNotFoundError:
            logger.warning(f"objdump not found: {objdump}")
            return {}

    def _parse_disassembly(
        self, output: str, symbols: List[Dict]
    ) -> Dict[str, str]:
        """Parse objdump -d output, mapping function names to disassembly text.

        Also extracts call targets from jump instructions to build callee lists.
        """
        disasm_map: Dict[str, str] = {}

        current_func: Optional[str] = None
        current_lines: List[str] = []

        for line in output.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            # Detect function start: "<function_name>:"
            if stripped.endswith(">:") and "<" in stripped:
                # Save previous function
                if current_func and current_lines:
                    disasm_map[current_func] = "\n".join(current_lines)

                name = stripped.split("<")[-1].rstrip(">:")
                current_func = name
                current_lines = [line]
                continue

            if current_func:
                current_lines.append(line)

        # Save last function
        if current_func and current_lines:
            disasm_map[current_func] = "\n".join(current_lines)

        return disasm_map

    # -- FunctionInfo construction ------------------------------------------

    def _build_function_info_list(
        self,
        symbols: List[Dict],
        dynamic_imports: Dict[str, Set[str]],
        disasm_map: Dict[str, str],
        binary_info: BinaryInfo,
    ) -> List[FunctionInfo]:
        """Build FunctionInfo objects from extracted symbol data.

        Uses disassembly to extract call targets via:
        - Direct calls: jal/bl/call <addr> <symbol>
        - Indirect calls: jalr t9 (MIPS PLT) — resolved via symbol table
        """
        global_imports = dynamic_imports.get("*", set())

        # Build address→name map from ALL symbols (including imports)
        addr_to_name: Dict[int, str] = {}
        for s in symbols:
            addr_to_name[s["address"]] = s["name"]

        functions = []

        for sym in symbols:
            name = sym["name"]
            address = sym["address"]

            pseudo_code = disasm_map.get(name, "")

            # Extract callees from disassembly
            callees = self._extract_callees(
                pseudo_code, addr_to_name, global_imports
            )

            dangerous = [
                c for c in callees
                if c in DANGEROUS_FUNCTIONS or c in global_imports
            ]

            # Fallback: if binary imports dangerous functions but we couldn't
            # resolve per-function callees, conservatively annotate functions.
            if not dangerous and global_imports:
                if pseudo_code:
                    # Function has disasm — check for indirect calls (jalr)
                    if "jalr" in pseudo_code:
                        dangerous = list(global_imports & DANGEROUS_FUNCTIONS)
                elif len(name) > 0 and not name.startswith("_"):
                    # No disasm but binary has dangerous imports —
                    # conservatively flag user-named functions
                    dangerous = list(global_imports & DANGEROUS_FUNCTIONS)

            fi = FunctionInfo(
                name=name,
                address=address,
                pseudo_code=pseudo_code,  # MIPS/ARM/x86 disassembly
                assembly="",              # No separate assembly (pseudo_code IS the asm)
                callers=[],
                callees=callees,
                parameters=0,
                complexity=len(pseudo_code.split("\n")) if pseudo_code else 0,
                has_unsafe_calls=len(dangerous) > 0,
                dangerous_funcs=dangerous,
                strings_used=[],
                arch=binary_info.arch,
                section=".text",
                binary_path=binary_info.path,
            )
            functions.append(fi)

        return functions

    @staticmethod
    def _extract_callees(
        disasm: str,
        addr_to_name: Dict[int, str],
        global_imports: Set[str],
    ) -> List[str]:
        """Extract callee names from disassembly text.

        Handles:
        - Direct calls:  jal <addr> <name>, bal <addr> <name>
        - MIPS GOT calls: lw t9, OFFSET(gp) → jalr t9 (resolved via addr_to_name)
        """
        callees: Set[str] = set()

        if not disasm:
            return list(callees)

        lines = disasm.split("\n")

        for i, line in enumerate(lines):
            # Pattern 1: Direct calls with symbol name
            #   jal  400a90 <strcpy>, bal  4005c0 <_init+0x24>
            for pattern in [
                r'(?:jal|bal|bl|blx|b\s+)\s+[0-9a-fA-F]+\s+<(.+?)>',
                r'call\s+(?:0x)?[0-9a-fA-F]+\s+<(.+?)>',
            ]:
                for m in re.finditer(pattern, line):
                    target = m.group(1)
                    # Strip offset suffix: "_init+0x24" → "_init"
                    if "+" in target and not target.startswith("+"):
                        target = target.split("+")[0]
                    callees.add(target)

            # Pattern 2: Numeric branch target (no symbol name)
            m = re.match(
                r'\s+[0-9a-fA-F]+:\s+[0-9a-fA-F]+\s+'
                r'(?:jal|bal|b)\s+([0-9a-fA-F]+)\s*$',
                line,
            )
            if m:
                try:
                    target_addr = int(m.group(1), 16)
                    if target_addr in addr_to_name:
                        callees.add(addr_to_name[target_addr])
                except ValueError:
                    pass

            # Pattern 3: MIPS jalr t9 with GOT load
            #   lw t9, OFFSET(gp)
            #   ...
            #   jalr t9
            # We look backwards from jalr to find the lw
            if "jalr" in line:
                got_addr = None
                for j in range(i - 1, max(i - 6, -1), -1):
                    prev = lines[j]
                    # Match: lw t9, OFFSET(gp) or lw t9, OFFSET(s0) etc
                    m = re.search(
                        r'lw\s+(?:t9|v0|a0)\s*,\s*(-?\d+)\(gp\)', prev
                    )
                    if m:
                        try:
                            gp_offset = int(m.group(1))
                            # _gp is typically at a known location.
                            # For MIPS statically-linked uClibc binaries,
                            # gp is stored at _gp symbol.
                            # We check addr_to_name for "_gp" to get gp value.
                            got_addr = gp_offset
                        except ValueError:
                            pass
                        break

        return list(callees)


class AnalyzerFactory:
    """Create the best available analyzer for a binary.

    Tries GhidraAnalyzer first; falls back to ObjdumpAnalyzer.
    """

    @staticmethod
    def create(
        ghidra_home: Optional[str] = None,
        **kwargs,
    ) -> "ObjdumpAnalyzer":
        """Create the best available analyzer.

        Currently always returns ObjdumpAnalyzer (Ghidra integration is
        a future enhancement once Ghidra is installed).
        """
        # Check for Ghidra first
        headless = os.path.join(
            ghidra_home or os.environ.get("GHIDRA_HOME", "/opt/ghidra"),
            "support/analyzeHeadless",
        )
        if os.path.exists(headless):
            try:
                from .ghidra_analyzer import GhidraAnalyzer
                logger.info("Using GhidraAnalyzer")
                return GhidraAnalyzer(ghidra_home=ghidra_home, **kwargs)
            except ImportError:
                pass

        logger.info("Ghidra not found — using ObjdumpAnalyzer (disassembly)")
        return ObjdumpAnalyzer(**kwargs)
