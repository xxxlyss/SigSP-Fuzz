"""
Ghidra Headless Automation for Firmware Binary Analysis.

Runs Ghidra in headless mode to decompile firmware binaries and export:
- Function pseudo-code (C)
- Call graph (callers/callees per function)
- String cross-references

Requires Ghidra installation. Set GHIDRA_HOME environment variable.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from .models import BinaryInfo, FunctionInfo, CallGraph, StringRef, AnalysisResult
from .callgraph import CallGraphBuilder


# Default Ghidra paths
DEFAULT_GHIDRA_HOME = "/opt/ghidra"
GHIDRA_HEADLESS = "support/analyzeHeadless"

# Ghidra export script (Java) — embedded as a resource
GHIDRA_EXPORT_SCRIPT = """
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import com.google.gson.*;

public class ExportFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        String outputPath = getScriptArgs()[0];
        String binaryName = currentProgram.getName();

        JsonObject root = new JsonObject();
        root.addProperty("binary_name", binaryName);
        root.addProperty("arch", currentProgram.getLanguage().getProcessor().toString());
        root.addProperty("bits", currentProgram.getLanguage().getLanguageDescription().getSize());

        // Export functions
        JsonArray functions = new JsonArray();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator iter = funcManager.getFunctions(true);

        int count = 0;
        for (Function func : iter) {
            try {
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().getOffset());

                // Decompile
                DecompileResults decompiled = decompiler.decompileFunction(func, 60, monitor);
                if (decompiled != null && decompiled.decompileCompleted()) {
                    funcObj.addProperty("pseudo_code",
                        decompiled.getDecompiledFunction().getC());
                } else {
                    funcObj.addProperty("pseudo_code",
                        "// Decompilation failed for " + func.getName());
                }

                // Parameters
                funcObj.addProperty("parameter_count", func.getParameterCount());

                // Callers
                JsonArray callers = new JsonArray();
                for (Function caller : func.getCallingFunctions(monitor)) {
                    callers.add(new JsonPrimitive(caller.getName()));
                }
                funcObj.add("callers", callers);

                // Callees
                JsonArray callees = new JsonArray();
                for (Function callee : func.getCalledFunctions(monitor)) {
                    callees.add(new JsonPrimitive(callee.getName()));
                }
                funcObj.add("callees", callees);

                functions.add(funcObj);
                count++;
            } catch (Exception e) {
                // Skip functions that fail to decompile
            }
        }
        root.add("functions", functions);
        root.addProperty("function_count", count);

        // Write output
        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            new GsonBuilder().setPrettyPrinting().create().toJson(root)
        );

        println("Exported " + count + " functions to " + outputPath);
    }
}
"""


class GhidraAnalyzer:
    """
    Ghidra Headless automation for batch binary decompilation.

    Usage:
        analyzer = GhidraAnalyzer(ghidra_home="/opt/ghidra")
        result = analyzer.analyze_binary(
            binary="extracted/bin/httpd",
            binary_info=BinaryInfo(...),
            output_dir="analysis/httpd/",
        )
    """

    def __init__(
        self,
        ghidra_home: Optional[str] = None,
        project_name: str = "firmware_analysis",
        timeout_seconds: int = 1800,  # 30 min per binary
    ):
        """
        Args:
            ghidra_home: Path to Ghidra installation (default: GHIDRA_HOME env or /opt/ghidra)
            project_name: Name for the temporary Ghidra project
            timeout_seconds: Max time per binary analysis
        """
        self.ghidra_home = ghidra_home or os.environ.get("GHIDRA_HOME", DEFAULT_GHIDRA_HOME)
        self.headless = os.path.join(self.ghidra_home, GHIDRA_HEADLESS)
        self.project_name = project_name
        self.timeout = timeout_seconds

        if not os.path.exists(self.headless):
            logger.warning(
                f"Ghidra headless not found at {self.headless}. "
                f"Set GHIDRA_HOME environment variable."
            )

    def analyze_binary(
        self,
        binary_path: str,
        binary_info: BinaryInfo,
        output_dir: str,
    ) -> AnalysisResult:
        """
        Run Ghidra Headless analysis on a single binary.

        Args:
            binary_path: Path to the ELF binary to analyze
            binary_info: BinaryInfo metadata
            output_dir: Directory for analysis output

        Returns:
            AnalysisResult with functions, callgraph, and strings
        """
        start_time = time.time()

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        binary_name = Path(binary_path).name
        functions_json = out_path / f"{binary_name}_functions.json"

        logger.info(f"Analyzing {binary_name} ({binary_info.arch}, {binary_info.bits}-bit)")

        # Validate binary exists
        if not os.path.exists(binary_path):
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error=f"Binary not found: {binary_path}",
            )

        # Step 1: Create Ghidra export Java script
        script_path = self._write_export_script()

        # Step 2: Create temporary Ghidra project directory
        project_dir = out_path / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        # Step 3: Run Ghidra Headless
        success = False
        error_msg = None

        try:
            cmd = [
                self.headless,
                str(project_dir),
                self.project_name,
                "-import", binary_path,
                "-scriptPath", str(script_path.parent),
                "-postScript", script_path.name,
                str(functions_json),
                "-deleteProject",
            ]

            logger.debug(f"Running Ghidra: {' '.join(cmd[:5])}...")

            # Detect JAVA_HOME if not set (Ghidra requires it)
            env = {**os.environ, "JAVA_OPTS": "-Xmx4G"}
            if "JAVA_HOME" not in os.environ:
                java_bin = shutil.which("java")
                if java_bin:
                    java_home = Path(java_bin).resolve().parent.parent
                    env["JAVA_HOME"] = str(java_home)
                    logger.debug(f"Auto-detected JAVA_HOME={java_home}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )

            if result.returncode != 0:
                error_msg = f"Ghidra returned {result.returncode}: {result.stderr[:500]}"
                logger.error(error_msg)
            elif not functions_json.exists():
                error_msg = "Functions JSON not created by Ghidra"
                logger.error(error_msg)
            else:
                success = True
                logger.info(
                    f"Ghidra analysis completed for {binary_name} "
                    f"in {time.time() - start_time:.1f}s"
                )

        except subprocess.TimeoutExpired:
            error_msg = f"Ghidra analysis timed out after {self.timeout}s"
            logger.error(error_msg)
        except FileNotFoundError:
            error_msg = f"Ghidra headless not found at {self.headless}"
            logger.error(error_msg)

        # Step 4: Parse results
        if not success:
            return AnalysisResult(
                binary=binary_info,
                success=False,
                error=error_msg,
                analysis_time_seconds=time.time() - start_time,
            )

        functions, callgraph = self._parse_functions_json(
            str(functions_json), binary_info
        )

        return AnalysisResult(
            binary=binary_info,
            success=True,
            functions=functions,
            callgraph=callgraph,
            analysis_time_seconds=time.time() - start_time,
        )

    def _write_export_script(self) -> Path:
        """Write the Ghidra Java export script to a temp file."""
        script_dir = Path(tempfile.mkdtemp(prefix="ghidra_script_"))
        script_file = script_dir / "ExportFunctions.java"

        with open(script_file, "w") as f:
            f.write(GHIDRA_EXPORT_SCRIPT)

        return script_file

    def _parse_functions_json(
        self, json_path: str, binary_info: BinaryInfo
    ) -> tuple:
        """
        Parse Ghidra-exported functions JSON into FunctionInfo list and CallGraph.

        Returns:
            Tuple of (List[FunctionInfo], CallGraph)
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        functions = []
        raw_functions = data.get("functions", [])

        # Known dangerous function names
        DANGEROUS_FUNCTIONS = {
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
            "memcpy", "memmove", "bcopy", "read", "recv", "recvfrom",
            "system", "popen", "execve", "execvp", "execl", "execlp",
            "printf", "fprintf", "snprintf", "vprintf", "syslog",
        }

        for func_data in raw_functions:
            callees = func_data.get("callees", [])
            dangerous = [c for c in callees if c in DANGEROUS_FUNCTIONS]

            fi = FunctionInfo(
                name=func_data.get("name", ""),
                address=func_data.get("address", 0),
                pseudo_code=func_data.get("pseudo_code", ""),
                assembly="",  # Ghidra script above doesn't export assembly
                callers=func_data.get("callers", []),
                callees=callees,
                parameters=func_data.get("parameter_count", 0),
                has_unsafe_calls=len(dangerous) > 0,
                dangerous_funcs=dangerous,
                arch=binary_info.arch,
                binary_path=binary_info.path,
            )
            functions.append(fi)

        # Build call graph
        builder = CallGraphBuilder()
        callgraph = builder.build(functions, binary_path=binary_info.path)

        logger.info(
            f"Parsed {len(functions)} functions "
            f"({sum(1 for f in functions if f.has_unsafe_calls)} with unsafe calls)"
        )

        return functions, callgraph
