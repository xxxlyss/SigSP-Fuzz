"""
Ghidra Bridge — Python ↔ Ghidra Headless Integration

Allows Python to call Ghidra for binary analysis via headless mode.
Communication happens through JSON files: Python writes a request,
triggers Ghidra analysis, then reads the result JSON.

Architecture:
    Python (SAST tools)
        │
        ▼
    GhidraBridge
        ├── analyze_binary()      → full import + decompile all functions
        ├── decompile_function()  → decompile single function (cached)
        ├── export_call_graph()   → callers/callees per function
        ├── export_strings()      → strings + cross-references
        └── _run_ghidra_headless() → subprocess + timeout + file lock

Key features:
    - Caching: 30-min TTL per binary (in-memory LRU)
    - Concurrency: fcntl.flock prevents simultaneous Ghidra runs
    - Big binary: >50MB → .text-only mode
    - Error handling: structured errors on Ghidra crash/timeout

Usage:
    bridge = GhidraBridge(ghidra_home="/opt/ghidra")
    code = bridge.decompile_function("/bin/httpd", 0x401000)
    cg = bridge.export_call_graph("/bin/httpd")
    strings = bridge.export_strings("/bin/httpd")
"""

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


# =============================================================================
# Defaults
# =============================================================================

DEFAULT_GHIDRA_HOME = "/opt/ghidra"
GHIDRA_HEADLESS_REL = "support/analyzeHeadless"
DEFAULT_TIMEOUT = 300  # 5 minutes per Ghidra run
CACHE_TTL_SECONDS = 1800  # 30 minutes
LARGE_BINARY_THRESHOLD = 50 * 1024 * 1024  # 50 MB


# =============================================================================
# Embedded Ghidra Java Scripts
# =============================================================================

# Script 1: Full export — decompile ALL functions + call graph
GHIDRA_FULL_EXPORT_SCRIPT = r"""
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import com.google.gson.*;

public class FullExport extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        String mode = getScriptArgs().length > 1 ? getScriptArgs()[1] : "all";

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        JsonObject root = new JsonObject();
        root.addProperty("binary_name", currentProgram.getName());
        root.addProperty("arch",
            currentProgram.getLanguage().getProcessor().toString());
        root.addProperty("bits",
            currentProgram.getLanguage().getLanguageDescription().getSize());
        root.addProperty("image_base",
            currentProgram.getImageBase().getOffset());

        // --- Functions ---
        JsonArray functions = new JsonArray();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator iter = funcManager.getFunctions(true);

        // .text-only mode: filter to functions in executable sections
        boolean textOnly = mode.equals("text_only");
        AddressSetView textAddrs = null;
        if (textOnly) {
            textAddrs = currentProgram.getMemory()
                .getExecuteSet();
        }

        int count = 0;
        int decompileFailures = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function func = iter.next();
            try {
                // Skip if not in executable memory (.text-only mode)
                if (textOnly) {
                    Address entry = func.getEntryPoint();
                    if (!textAddrs.contains(entry)) {
                        continue;
                    }
                }

                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address",
                    func.getEntryPoint().getOffset());
                funcObj.addProperty("signature",
                    func.getSignature().getPrototypeString());
                funcObj.addProperty("parameter_count",
                    func.getParameterCount());

                // Decompile (60s timeout per function)
                DecompileResults dr = decompiler.decompileFunction(
                    func, 60, monitor);
                if (dr != null && dr.decompileCompleted()) {
                    funcObj.addProperty("pseudo_code",
                        dr.getDecompiledFunction().getC());
                } else {
                    funcObj.addProperty("pseudo_code",
                        "// Decompilation failed");
                    decompileFailures++;
                }

                // Callers
                JsonArray callers = new JsonArray();
                for (Function caller :
                     func.getCallingFunctions(monitor)) {
                    JsonObject c = new JsonObject();
                    c.addProperty("name", caller.getName());
                    c.addProperty("address",
                        caller.getEntryPoint().getOffset());
                    callers.add(c);
                }
                funcObj.add("callers", callers);

                // Callees
                JsonArray callees = new JsonArray();
                for (Function callee :
                     func.getCalledFunctions(monitor)) {
                    JsonObject c = new JsonObject();
                    c.addProperty("name", callee.getName());
                    c.addProperty("address",
                        callee.getEntryPoint().getOffset());
                    callees.add(c);
                }
                funcObj.add("callees", callees);

                // Referenced strings (within function body)
                JsonArray strings = new JsonArray();
                AddressSet body = func.getBody();
                Listing listing = currentProgram.getListing();
                DataIterator dataIter = listing.getDefinedData(body, true);
                while (dataIter.hasNext() && !monitor.isCancelled()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        strings.add(new JsonPrimitive(
                            data.getDefaultValueRepresentation()));
                    }
                }
                funcObj.add("strings_used", strings);

                functions.add(funcObj);
                count++;
            } catch (Exception e) {
                // Skip functions that fail
            }
        }
        root.add("functions", functions);
        root.addProperty("function_count", count);
        root.addProperty("decompile_failures", decompileFailures);

        // --- Strings (global) ---
        JsonArray allStrings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator sIter = listing.getDefinedData(true);
        int stringCount = 0;
        while (sIter.hasNext() && !monitor.isCancelled() && stringCount < 50000) {
            Data data = sIter.next();
            if (data.hasStringValue()) {
                JsonObject strObj = new JsonObject();
                strObj.addProperty("value",
                    data.getDefaultValueRepresentation());
                strObj.addProperty("address",
                    data.getAddress().getOffset());

                // Cross-references to this string
                JsonArray xrefs = new JsonArray();
                ReferenceIterator refIter =
                    currentProgram.getReferenceManager()
                        .getReferencesTo(data.getAddress());
                while (refIter.hasNext() && !monitor.isCancelled()) {
                    Reference ref = refIter.next();
                    xrefs.add(new JsonPrimitive(
                        ref.getFromAddress().getOffset()));
                }
                strObj.add("xrefs", xrefs);

                allStrings.add(strObj);
                stringCount++;
            }
        }
        root.add("strings", allStrings);
        root.addProperty("string_count", stringCount);

        // Write JSON output
        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            new GsonBuilder().setPrettyPrinting().create().toJson(root)
        );

        println("GHIDRA_OK: exported " + count + " functions, "
            + stringCount + " strings to " + outputPath);
    }
}
"""

# Script 2: Single-function decompile (fast, for per-address queries)
GHIDRA_SINGLE_FUNC_SCRIPT = r"""
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;

public class DecompileOne extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        long targetAddr = Long.parseUnsignedLong(
            getScriptArgs()[1].substring(2), 16);

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        JsonObject root = new JsonObject();

        // Find function containing targetAddr
        Function func = getFunctionContaining(
            currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(targetAddr));

        if (func == null) {
            root.addProperty("error",
                "No function found at address 0x"
                + Long.toHexString(targetAddr));
            root.addProperty("success", false);
        } else {
            root.addProperty("success", true);
            root.addProperty("name", func.getName());
            root.addProperty("address",
                func.getEntryPoint().getOffset());
            root.addProperty("signature",
                func.getSignature().getPrototypeString());

            // Decompile
            DecompileResults dr = decompiler.decompileFunction(
                func, 60, monitor);
            if (dr != null && dr.decompileCompleted()) {
                root.addProperty("pseudo_code",
                    dr.getDecompiledFunction().getC());
            } else {
                root.addProperty("pseudo_code",
                    "// Decompilation failed");
            }

            // Callers
            JsonArray callers = new JsonArray();
            for (Function caller :
                 func.getCallingFunctions(monitor)) {
                JsonObject c = new JsonObject();
                c.addProperty("name", caller.getName());
                c.addProperty("address",
                    caller.getEntryPoint().getOffset());
                callers.add(c);
            }
            root.add("callers", callers);

            // Callees
            JsonArray callees = new JsonArray();
            for (Function callee :
                 func.getCalledFunctions(monitor)) {
                JsonObject c = new JsonObject();
                c.addProperty("name", callee.getName());
                c.addProperty("address",
                    callee.getEntryPoint().getOffset());
                callees.add(c);
            }
            root.add("callees", callees);
        }

        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            new GsonBuilder().setPrettyPrinting().create().toJson(root)
        );

        println("GHIDRA_OK: decompiled "
            + (func != null ? func.getName() : "null")
            + " to " + outputPath);
    }
}
"""

# Script 3: String export with cross-references
GHIDRA_STRINGS_SCRIPT = r"""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;

public class ExportStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        String filter = getScriptArgs().length > 1
            ? getScriptArgs()[1] : "";

        JsonObject root = new JsonObject();
        root.addProperty("binary_name", currentProgram.getName());

        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator iter = listing.getDefinedData(true);

        int count = 0;
        int maxStrings = 200000;
        while (iter.hasNext() && !monitor.isCancelled()
               && count < maxStrings) {
            Data data = iter.next();
            if (!data.hasStringValue()) continue;

            String value = data.getDefaultValueRepresentation();

            // Apply filter if specified
            if (!filter.isEmpty() && !value.contains(filter)) {
                continue;
            }

            JsonObject strObj = new JsonObject();
            strObj.addProperty("value", value);
            strObj.addProperty("address",
                data.getAddress().getOffset());
            strObj.addProperty("length", data.getLength());

            // Xrefs
            JsonArray xrefs = new JsonArray();
            ReferenceIterator refIter =
                currentProgram.getReferenceManager()
                    .getReferencesTo(data.getAddress());
            while (refIter.hasNext() && !monitor.isCancelled()) {
                Reference ref = refIter.next();
                JsonObject xref = new JsonObject();
                xref.addProperty("from_address",
                    ref.getFromAddress().getOffset());
                Function fromFunc = getFunctionContaining(
                    ref.getFromAddress());
                if (fromFunc != null) {
                    xref.addProperty("from_function",
                        fromFunc.getName());
                }
                xrefs.add(xref);
            }
            strObj.add("xrefs", xrefs);

            strings.add(strObj);
            count++;
        }

        root.add("strings", strings);
        root.addProperty("count", count);

        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            new GsonBuilder().setPrettyPrinting().create().toJson(root)
        );

        println("GHIDRA_OK: exported " + count
            + " strings to " + outputPath);
    }
}
"""

# Script name → source mapping
EMBEDDED_SCRIPTS = {
    "FullExport.java": GHIDRA_FULL_EXPORT_SCRIPT,
    "DecompileOne.java": GHIDRA_SINGLE_FUNC_SCRIPT,
    "ExportStrings.java": GHIDRA_STRINGS_SCRIPT,
}


# =============================================================================
# Cache
# =============================================================================

class _CacheEntry:
    """A cached analysis result with TTL."""

    def __init__(self, data: dict):
        self.data = data
        self.created_at = time.time()

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > CACHE_TTL_SECONDS


# =============================================================================
# GhidraBridge
# =============================================================================

class GhidraBridge:
    """Bridge between Python and Ghidra Headless.

    Manages Ghidra binary import, decompilation, call graph export,
    and string extraction. Uses file-based locking for concurrency
    safety and in-memory caching for performance.

    Usage:
        bridge = GhidraBridge(ghidra_home="/opt/ghidra")
        code = bridge.decompile_function("/bin/httpd", 0x401000)
        cg = bridge.export_call_graph("/bin/httpd")
    """

    def __init__(
        self,
        ghidra_home: Optional[str] = None,
        project_dir: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache_ttl: int = CACHE_TTL_SECONDS,
    ):
        """
        Args:
            ghidra_home: Path to Ghidra installation.
                         Defaults to GHIDRA_HOME env or /opt/ghidra.
            project_dir: Directory for Ghidra projects.
                         Defaults to a temp dir.
            timeout: Max seconds per Ghidra headless invocation.
            cache_ttl: Cache lifetime in seconds (default 1800 = 30 min).
        """
        self.ghidra_home = ghidra_home or os.environ.get(
            "GHIDRA_HOME", DEFAULT_GHIDRA_HOME
        )
        self.headless = os.path.join(
            self.ghidra_home, GHIDRA_HEADLESS_REL
        )
        self.project_dir = Path(
            project_dir or tempfile.mkdtemp(prefix="ghidra_bridge_")
        )
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.cache_ttl = cache_ttl

        # In-memory cache: binary_path → _CacheEntry
        self._cache: Dict[str, _CacheEntry] = {}
        self._cache_lock = threading.RLock()

        # File-level lock for serializing Ghidra subprocess calls
        self._process_lock_path = (
            self.project_dir / ".ghidra_bridge.lock"
        )

        self._validate_ghidra()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_binary(self, binary_path: str) -> str:
        """Run full Ghidra analysis on a binary.

        Imports the binary into a Ghidra project, decompiles all functions,
        and caches the result.

        Args:
            binary_path: Absolute path to the ELF binary.

        Returns:
            Path to the JSON export file with full analysis results.

        Raises:
            FileNotFoundError: if binary doesn't exist.
            RuntimeError: if Ghidra fails.
        """
        abs_path = os.path.abspath(binary_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Binary not found: {abs_path}")

        # Check cache first
        cache_key = self._cache_key(abs_path)
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and not entry.expired:
                logger.debug(
                    f"GhidraBridge: cache hit for {os.path.basename(abs_path)}"
                )
                # Return cached result path
                return entry.data.get("_output_path", "")

        # Determine mode: text_only for large binaries
        file_size = os.path.getsize(abs_path)
        mode = "text_only" if file_size > LARGE_BINARY_THRESHOLD else "all"
        if mode == "text_only":
            logger.info(
                f"GhidraBridge: binary {os.path.basename(abs_path)} "
                f"is {file_size / 1024 / 1024:.0f}MB — using .text-only mode"
            )

        # Run full export
        output_path = str(
            self.project_dir
            / f"{self._safe_name(abs_path)}_full_export.json"
        )

        result = self._run_ghidra_headless(
            abs_path,
            "FullExport.java",
            [output_path, mode],
        )

        if not result.get("success"):
            raise RuntimeError(
                f"Ghidra analysis failed for {abs_path}: "
                f"{result.get('error', 'unknown error')}"
            )

        # Cache the result
        with self._cache_lock:
            result["_output_path"] = output_path
            self._cache[cache_key] = _CacheEntry(result)

        logger.info(
            f"GhidraBridge: analyzed {os.path.basename(abs_path)} — "
            f"{result.get('function_count', 0)} functions, "
            f"{result.get('string_count', 0)} strings"
        )
        return output_path

    def decompile_function(
        self, binary_path: str, func_addr: int
    ) -> str:
        """Decompile a single function at the given address.

        If the binary hasn't been analyzed yet, runs a fast single-function
        Ghidra script. If already analyzed, returns from cache.

        Args:
            binary_path: Absolute path to the ELF binary.
            func_addr: Function entry address.

        Returns:
            C-like pseudo-code string.
        """
        abs_path = os.path.abspath(binary_path)
        self._ensure_exists(abs_path)

        # Try cache first
        cache_key = self._cache_key(abs_path)
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and not entry.expired:
                funcs = entry.data.get("functions", [])
                for f in funcs:
                    if f.get("address") == func_addr:
                        return f.get("pseudo_code", "// No code available")

        # Not cached — run single-function decompile
        output_path = str(
            self.project_dir
            / f"{self._safe_name(abs_path)}_func_{func_addr:08x}.json"
        )

        result = self._run_ghidra_headless(
            abs_path,
            "DecompileOne.java",
            [output_path, f"0x{func_addr:X}"],
        )

        if result.get("success"):
            code = result.get("pseudo_code", "")
            if code:
                return code

        # Fallback: run full analysis to get everything
        logger.info(
            f"GhidraBridge: single decompile missed 0x{func_addr:x}, "
            f"running full analysis..."
        )
        self.analyze_binary(abs_path)
        return self.decompile_function(abs_path, func_addr)

    def export_call_graph(self, binary_path: str) -> dict:
        """Export the complete call graph for a binary.

        Args:
            binary_path: Absolute path to the ELF binary.

        Returns:
            {
                "binary_name": str,
                "function_count": int,
                "call_graph": {
                    func_addr (int): {
                        "name": str,
                        "address": int,
                        "callers": [{"name": str, "address": int}, ...],
                        "callees": [{"name": str, "address": int}, ...],
                    }
                }
            }
        """
        abs_path = os.path.abspath(binary_path)
        data = self._get_or_analyze(abs_path)

        call_graph = {}
        for func in data.get("functions", []):
            addr = func.get("address", 0)
            call_graph[addr] = {
                "name": func.get("name", ""),
                "address": addr,
                "callers": func.get("callers", []),
                "callees": func.get("callees", []),
                "signature": func.get("signature", ""),
            }

        return {
            "binary_name": data.get("binary_name", ""),
            "function_count": data.get("function_count", 0),
            "call_graph": call_graph,
        }

    def export_strings(
        self, binary_path: str, filter_str: str = ""
    ) -> List[dict]:
        """Export all strings and their cross-references.

        Uses the cached full-analysis data when available; otherwise
        runs a dedicated Ghidra script.

        Args:
            binary_path: Absolute path to the ELF binary.
            filter_str: Optional substring filter.

        Returns:
            [
                {
                    "value": str,
                    "address": int,
                    "length": int,
                    "xrefs": [{"from_address": int, "from_function": str}, ...]
                },
                ...
            ]
        """
        abs_path = os.path.abspath(binary_path)

        # Try cached full analysis first
        cache_key = self._cache_key(abs_path)
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and not entry.expired:
                strings = entry.data.get("strings", [])
                if strings and not filter_str:
                    return strings
                elif strings and filter_str:
                    return [
                        s for s in strings
                        if filter_str in s.get("value", "")
                    ]

        # Run dedicated string export
        output_path = str(
            self.project_dir
            / f"{self._safe_name(abs_path)}_strings.json"
        )

        result = self._run_ghidra_headless(
            abs_path,
            "ExportStrings.java",
            [output_path, filter_str],
        )

        if result.get("success") or "strings" in result:
            return result.get("strings", [])

        # Fallback: do full analysis
        data = self._get_or_analyze(abs_path)
        strings = data.get("strings", [])
        if filter_str:
            strings = [
                s for s in strings
                if filter_str in s.get("value", "")
            ]
        return strings

    def get_function_by_name(
        self, binary_path: str, func_name: str
    ) -> Optional[dict]:
        """Look up a function by name in the cached analysis.

        Returns:
            {"name": str, "address": int, "pseudo_code": str, ...} or None.
        """
        abs_path = os.path.abspath(binary_path)
        data = self._get_or_analyze(abs_path)

        for func in data.get("functions", []):
            if func.get("name") == func_name:
                return func
        return None

    def get_function_by_address(
        self, binary_path: str, func_addr: int
    ) -> Optional[dict]:
        """Look up a function by address in the cached analysis."""
        abs_path = os.path.abspath(binary_path)
        data = self._get_or_analyze(abs_path)

        for func in data.get("functions", []):
            if func.get("address") == func_addr:
                return func
        return None

    def is_analyzed(self, binary_path: str) -> bool:
        """Check if a binary has been analyzed and is still cached."""
        abs_path = os.path.abspath(binary_path)
        cache_key = self._cache_key(abs_path)
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            return entry is not None and not entry.expired

    def clear_cache(self, binary_path: Optional[str] = None):
        """Clear the analysis cache.

        Args:
            binary_path: If provided, clear only this binary's cache.
                         If None, clear all.
        """
        with self._cache_lock:
            if binary_path:
                abs_path = os.path.abspath(binary_path)
                cache_key = self._cache_key(abs_path)
                self._cache.pop(cache_key, None)
                logger.debug(
                    f"GhidraBridge: cleared cache for "
                    f"{os.path.basename(abs_path)}"
                )
            else:
                count = len(self._cache)
                self._cache.clear()
                logger.debug(
                    f"GhidraBridge: cleared all {count} cache entries"
                )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _validate_ghidra(self):
        """Check that Ghidra headless is accessible."""
        if not os.path.exists(self.headless):
            logger.warning(
                f"Ghidra headless not found at {self.headless}. "
                f"Install Ghidra or set GHIDRA_HOME. "
                f"SAST tools will use objdump fallback."
            )

    @property
    def available(self) -> bool:
        """Whether Ghidra is ready to use."""
        return os.path.exists(self.headless)

    def _ensure_exists(self, binary_path: str):
        """Raise FileNotFoundError if binary doesn't exist."""
        if not os.path.exists(binary_path):
            raise FileNotFoundError(
                f"Binary not found: {binary_path}"
            )

    def _cache_key(self, binary_path: str) -> str:
        """Generate a cache key from the binary path and file hash."""
        abs_path = os.path.abspath(binary_path)
        try:
            stat = os.stat(abs_path)
            # Path + mtime + size → unique key
            raw = f"{abs_path}:{stat.st_mtime}:{stat.st_size}"
            return hashlib.sha256(raw.encode()).hexdigest()[:16]
        except OSError:
            return hashlib.sha256(abs_path.encode()).hexdigest()[:16]

    def _safe_name(self, binary_path: str) -> str:
        """Get a filesystem-safe name from a binary path."""
        name = os.path.basename(binary_path)
        # Remove special characters
        safe = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in name
        )
        return safe or "binary"

    def _get_or_analyze(self, binary_path: str) -> dict:
        """Get cached analysis data or run analyze_binary.

        Returns the parsed JSON dict from the full export.
        """
        abs_path = os.path.abspath(binary_path)
        cache_key = self._cache_key(abs_path)

        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and not entry.expired:
                return entry.data

        output_path = self.analyze_binary(abs_path)

        # Load from output file
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        with self._cache_lock:
            self._cache[cache_key] = _CacheEntry(data)

        return data

    def _run_ghidra_headless(
        self,
        binary_path: str,
        script_name: str,
        script_args: List[str],
    ) -> dict:
        """Run Ghidra headless with a named embedded script.

        This is the core method. All other methods delegate here.

        Flow:
        1. Acquire file lock (prevents concurrent Ghidra processes)
        2. Write the embedded Java script to a temp file
        3. Build and run the Ghidra headless command
        4. Parse the JSON output
        5. Release the lock

        Args:
            binary_path: Absolute path to the ELF binary.
            script_name: Name of the embedded script (key in EMBEDDED_SCRIPTS).
            script_args: Arguments passed to the Java script.

        Returns:
            Parsed JSON dict. Always has a "success" key.
        """
        if script_name not in EMBEDDED_SCRIPTS:
            return {
                "success": False,
                "error": f"Unknown script: {script_name}. "
                         f"Available: {list(EMBEDDED_SCRIPTS.keys())}",
            }

        if not self.available:
            return {
                "success": False,
                "error": (
                    f"Ghidra headless not found at {self.headless}. "
                    f"Set GHIDRA_HOME or install Ghidra."
                ),
            }

        # Write the Java script to a temp file
        script_dir = Path(tempfile.mkdtemp(prefix="ghidra_mcp_script_"))
        script_path = script_dir / script_name
        with open(script_path, "w") as f:
            f.write(EMBEDDED_SCRIPTS[script_name])

        # Ensure the output directory exists
        if script_args:
            out_dir = os.path.dirname(script_args[0])
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

        # Build command
        project_subdir = self.project_dir / self._safe_name(binary_path)
        project_subdir.mkdir(parents=True, exist_ok=True)
        project_name = f"proj_{self._safe_name(binary_path)}"

        cmd = [
            self.headless,
            str(project_subdir),
            project_name,
            "-import",
            binary_path,
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script_name.replace(".java", ""),
            *script_args,
            "-deleteProject",
        ]

        # Detect JAVA_HOME
        env = {**os.environ}
        if "JAVA_HOME" not in os.environ:
            java_bin = shutil.which("java")
            if java_bin:
                java_home = (
                    Path(java_bin).resolve().parent.parent
                )
                env["JAVA_HOME"] = str(java_home)

        logger.debug(
            f"GhidraBridge: running {' '.join(cmd[:5])} ..."
        )

        # Acquire file lock and run
        with self._ghidra_lock():
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "error": (
                        f"Ghidra headless timed out after "
                        f"{self.timeout}s for {os.path.basename(binary_path)}"
                    ),
                    "script": script_name,
                }
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": (
                        f"Ghidra headless not found at {self.headless}"
                    ),
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Ghidra subprocess failed: {e}",
                }

        # Parse output
        if result.returncode != 0:
            stderr_snippet = (
                result.stderr[:800] if result.stderr else ""
            )
            return {
                "success": False,
                "error": (
                    f"Ghidra exited with code {result.returncode}. "
                    f"stderr: {stderr_snippet}"
                ),
                "script": script_name,
                "returncode": result.returncode,
            }

        # Read and parse the output JSON file
        output_file = script_args[0] if script_args else None
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["success"] = data.get("success", True)
                return data
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": (
                        f"Failed to parse Ghidra output JSON: {e}"
                    ),
                    "output_file": output_file,
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to read Ghidra output: {e}",
                }

        # No output file — check stdout for "GHIDRA_OK"
        if "GHIDRA_OK" in result.stdout:
            return {"success": True, "stdout": result.stdout}

        return {
            "success": False,
            "error": (
                f"Ghidra completed but no output found. "
                f"stdout: {result.stdout[:500]}"
            ),
        }

    def _ghidra_lock(self):
        """Context manager: acquire/release a file lock for Ghidra.

        Prevents concurrent Ghidra headless processes which would
        corrupt each other's project files.
        """
        self._process_lock_path.parent.mkdir(
            parents=True, exist_ok=True
        )
        lock_fd = None

        class _LockContext:
            def __enter__(self2):
                nonlocal lock_fd
                lock_fd = open(self._process_lock_path, "w")
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                return lock_fd

            def __exit__(self2, *args):
                if lock_fd:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    lock_fd.close()

        return _LockContext()


# =============================================================================
# Module-level singleton
# =============================================================================

_bridge_instance: Optional[GhidraBridge] = None
_bridge_lock = threading.Lock()


def get_ghidra_bridge(
    ghidra_home: Optional[str] = None,
    project_dir: Optional[str] = None,
) -> GhidraBridge:
    """Get or create the module-level GhidraBridge singleton."""
    global _bridge_instance
    if _bridge_instance is None:
        with _bridge_lock:
            if _bridge_instance is None:
                _bridge_instance = GhidraBridge(
                    ghidra_home=ghidra_home,
                    project_dir=project_dir,
                )
    return _bridge_instance


def reset_ghidra_bridge():
    """Reset the singleton (for testing)."""
    global _bridge_instance
    with _bridge_lock:
        if _bridge_instance:
            _bridge_instance.clear_cache()
        _bridge_instance = None
