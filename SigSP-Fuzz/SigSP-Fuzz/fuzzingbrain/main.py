"""
FuzzingBrain v2 - Main Entry Point

This module is the Python entry point for FuzzingBrain.
It is called by FuzzingBrain.sh as: python3 -m fuzzingbrain.main <args>

Four entry modes:
1. REST API Mode (default): Start REST API server
2. MCP Server Mode (--mcp): Start MCP server for AI systems
3. JSON Mode (--config): Load task configuration from JSON file
4. Local Mode (--workspace): Run task on local workspace
"""

import argparse
import atexit
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from .core import (
    Config,
    Task,
    JobType,
    ScanMode,
    setup_logging,
    setup_celery_logging,
    setup_console_only,
)
from .db import MongoDB, RepositoryManager, init_repos


# =============================================================================
# Terminal Cleanup
# =============================================================================


def reset_terminal():
    """Reset terminal to sane state on exit"""
    try:
        # Reset ANSI attributes
        sys.stdout.write("\033[0m")
        sys.stdout.flush()
        # Reset terminal settings (handles raw mode, echo, etc.)
        os.system("stty sane 2>/dev/null")
    except Exception:
        pass


# Register cleanup on exit
atexit.register(reset_terminal)


# =============================================================================
# Signal Handling
# =============================================================================

_shutdown_requested = False
_current_task_id: Optional[str] = None


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested, _repos, _current_task_id
    if _shutdown_requested:
        # Second Ctrl+C - force exit
        print("\n\033[0;31m[FORCE]\033[0m Forcing shutdown...")
        reset_terminal()
        sys.exit(1)

    _shutdown_requested = True
    print(
        "\n\033[1;33m[INTERRUPT]\033[0m Shutting down gracefully... (Press Ctrl+C again to force)"
    )

    # If no task was started, exit immediately
    if not _repos or not _current_task_id:
        reset_terminal()
        sys.exit(0)

    # Mark workers and task as cancelled (scoped to current task only)
    try:
        from bson import ObjectId as _ObjectId

        task_oid = (
            _ObjectId(_current_task_id)
            if len(_current_task_id) == 24
            else _current_task_id
        )

        # Update workers for THIS task only
        result = _repos.workers.collection.update_many(
            {
                "task_id": task_oid,
                "status": {"$in": ["pending", "building", "running"]},
            },
            {
                "$set": {
                    "status": "failed",
                    "error_msg": "Cancelled by user (Ctrl+C)",
                }
            },
        )
        worker_count = result.modified_count

        # Update THIS task only
        task_result = _repos.tasks.collection.update_one(
            {
                "_id": task_oid,
                "status": {"$in": ["pending", "running"]},
            },
            {
                "$set": {
                    "status": "cancelled",
                    "error_msg": "Cancelled by user (Ctrl+C)",
                }
            },
        )
        task_count = task_result.modified_count

        # Cancel in-memory agents for this task
        try:
            from .agents.context import get_all_agent_contexts, force_cleanup_agents
            from .db import get_database

            for ctx in get_all_agent_contexts().values():
                if ctx.task_id == _current_task_id and ctx.status == "running":
                    try:
                        ctx.cancel()
                    except Exception:
                        pass

            # Force-cleanup zombie agents in DB
            try:
                db = get_database()
            except Exception:
                db = None
            if db is not None:
                force_cleanup_agents(_current_task_id, db)
        except Exception:
            pass

        if worker_count > 0 or task_count > 0:
            print(
                f"\033[1;33m[INTERRUPT]\033[0m Marked {worker_count} worker(s) and {task_count} task(s) as cancelled"
            )

        # Display summary for current task
        try:
            from .core.logging import create_final_summary
            from datetime import datetime

            recent_task = _repos.tasks.collection.find_one({"_id": task_oid})
            if recent_task:
                task_id = str(
                    recent_task.get("task_id") or recent_task.get("_id") or "unknown"
                )
                project_name = recent_task.get("project_name", "unknown")

                # Get workers for this task
                workers = list(_repos.workers.collection.find({"task_id": task_oid}))
                worker_results = []
                for w in workers:
                    started = w.get("started_at")
                    finished = w.get("finished_at") or datetime.now()
                    duration_sec = (
                        (finished - started).total_seconds() if started else 0
                    )
                    fuzzer = w.get("fuzzer", "N/A")
                    sanitizer = w.get("sanitizer", "N/A")

                    # Query SP count from database
                    sp_count = _repos.suspicious_points.count(
                        {
                            "task_id": task_oid,
                            "sources": {
                                "$elemMatch": {
                                    "harness_name": fuzzer,
                                    "sanitizer": sanitizer,
                                }
                            },
                        }
                    )

                    # Query POV count from database
                    worker_sp_ids = [
                        str(sp.get("suspicious_point_id") or sp.get("_id"))
                        for sp in _repos.suspicious_points.collection.find(
                            {
                                "task_id": task_oid,
                                "sources": {
                                    "$elemMatch": {
                                        "harness_name": fuzzer,
                                        "sanitizer": sanitizer,
                                    }
                                },
                            },
                            {"suspicious_point_id": 1, "_id": 1},
                        )
                    ]
                    pov_count = 0
                    if worker_sp_ids:
                        sp_oids = []
                        for x in worker_sp_ids:
                            try:
                                sp_oids.append(_ObjectId(x))
                            except Exception:
                                sp_oids.append(x)
                        pov_count = _repos.povs.count(
                            {
                                "task_id": task_oid,
                                "suspicious_point_id": {"$in": sp_oids},
                                "is_successful": True,
                            }
                        )
                    # Also count fuzzer-discovered POVs
                    fuzzer_pov_count = _repos.povs.count(
                        {
                            "task_id": task_oid,
                            "harness_name": fuzzer,
                            "sanitizer": sanitizer,
                            "suspicious_point_id": {"$in": ["", None]},
                            "is_successful": True,
                        }
                    )
                    pov_count += fuzzer_pov_count

                    worker_results.append(
                        {
                            "fuzzer": fuzzer,
                            "sanitizer": sanitizer,
                            "status": w.get("status", "cancelled"),
                            "duration_str": f"{duration_sec / 60:.1f}m",
                            "sps_found": sp_count,
                            "pov_generated": pov_count,
                            "patch_generated": w.get("patch_generated", 0),
                        }
                    )

                # Read cost from database
                total_cost = recent_task.get("llm_cost", 0.0)
                budget_limit = recent_task.get("budget_limit", 0.0)

                # Calculate elapsed time
                created_at = recent_task.get("created_at", datetime.now())
                elapsed_minutes = (datetime.now() - created_at).total_seconds() / 60

                summary = create_final_summary(
                    project_name=project_name,
                    task_id=task_id,
                    workers=worker_results,
                    total_elapsed_minutes=elapsed_minutes,
                    use_color=True,
                    total_cost=total_cost,
                    budget_limit=budget_limit,
                    exit_reason="cancelled",
                )
                print(summary)
        except Exception as e:
            print(f"\033[0;31m[ERROR]\033[0m Failed to generate summary: {e}")

    except Exception as e:
        print(f"\033[0;31m[ERROR]\033[0m Failed to update status: {e}")

    # Close LLM clients before stopping infrastructure
    # (prevents SSL transport errors when event loop closes)
    try:
        from .llms import LLMClient

        LLMClient.close_all()
    except Exception:
        pass

    # Stop infrastructure
    try:
        from .core.infrastructure import InfrastructureManager

        if InfrastructureManager._instance:
            InfrastructureManager._instance.stop()
    except Exception:
        pass

    reset_terminal()
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# =============================================================================
# Global State
# =============================================================================

# Global Repository Manager - initialized in init_database()
_repos: Optional[RepositoryManager] = None


def get_repos() -> RepositoryManager:
    """Get global RepositoryManager instance"""
    global _repos
    if _repos is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _repos


def init_database(config: Config) -> RepositoryManager:
    """
    Initialize database connection (global singleton)

    Called once at application startup, then shared by all components.
    """
    global _repos

    if _repos is not None:
        return _repos

    print_info("Connecting to MongoDB...")
    try:
        db = MongoDB.connect(config.mongodb_url, config.mongodb_db)
        _repos = init_repos(db)
        print_info(f"Connected to database: {config.mongodb_db}")
        return _repos
    except Exception as e:
        print_error(f"Failed to connect to MongoDB: {e}")
        print_error("Make sure MongoDB is running (check: docker ps)")
        sys.exit(1)


# =============================================================================
# Terminal Output
# =============================================================================


class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    ORANGE = "\033[38;5;208m"
    NC = "\033[0m"


def print_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")


def print_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def print_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def print_step(msg: str):
    print(f"{Colors.CYAN}[STEP]{Colors.NC} {msg}")


# =============================================================================
# Argument Parsing
# =============================================================================


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="FuzzingBrain v2 - Autonomous Cyber Reasoning System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection
    parser.add_argument("--mcp", action="store_true", help="Start MCP server mode")
    parser.add_argument("--api", action="store_true", help="Start REST API server mode")
    parser.add_argument("--config", type=str, help="JSON configuration file path")
    parser.add_argument(
        "--firmware", type=str, help="Firmware binary path (firmware vuln discovery mode)"
    )

    # Task identification
    parser.add_argument(
        "--task-id", type=str, help="Task ID (auto-generated if not provided)"
    )

    # Project info (required for CLI mode)
    parser.add_argument("--repo-url", type=str, help="Git repository URL")
    parser.add_argument("--project", type=str, help="Project name (e.g., libpng)")
    parser.add_argument(
        "--ossfuzz-project",
        type=str,
        help="OSS-Fuzz project name (if different from --project)",
    )

    # Workspace
    parser.add_argument("--workspace", type=str, help="Workspace directory path")
    parser.add_argument(
        "--in-place", action="store_true", help="Run without copying workspace"
    )

    # Task configuration
    parser.add_argument(
        "--task-type",
        type=str,
        choices=["pov", "patch", "pov-patch", "harness"],
        default="pov",
    )
    parser.add_argument(
        "--scan-mode",
        type=str,
        choices=["full", "delta"],
        default="full",
        help="Scan mode: full or delta",
    )
    parser.add_argument(
        "--sanitizers", type=str, default="address", help="Comma-separated sanitizers"
    )
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in minutes")
    parser.add_argument(
        "--pov-count",
        type=int,
        default=1,
        help="Stop after N verified POVs (0 = unlimited)",
    )
    parser.add_argument(
        "--fuzzers",
        type=str,
        help="Comma-separated list of fuzzers to use (empty = all)",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=50.0,
        help="Budget limit in dollars (0 = unlimited)",
    )

    # Commit configuration
    parser.add_argument("--target-commit", type=str, help="Target commit for full scan")
    parser.add_argument("--base-commit", type=str, help="Base commit for delta scan")
    parser.add_argument("--delta-commit", type=str, help="Delta commit for delta scan")

    # Fuzz tooling
    parser.add_argument(
        "--fuzz-tooling-url", type=str, help="Custom fuzz-tooling repository URL"
    )
    parser.add_argument("--fuzz-tooling-ref", type=str, help="Fuzz-tooling branch/tag")

    # Prebuild (advanced)
    parser.add_argument("--work-id", type=str, help="Work ID for prebuild data")
    parser.add_argument(
        "--prebuild-dir", type=str, help="Path to prebuild data directory"
    )

    # Patch mode specific
    parser.add_argument("--gen-blob", type=str, help="Generator blob for patch mode")
    parser.add_argument(
        "--input-blob", type=str, help="Input blob (base64) for patch mode"
    )

    # Harness mode specific
    parser.add_argument(
        "--targets", type=str, help="Target functions as JSON array for harness mode"
    )
    parser.add_argument(
        "--targets-file", type=str, help="Path to JSON file containing targets"
    )

    # Fuzzer sources (complex type, JSON format)
    parser.add_argument(
        "--fuzzer-sources",
        type=str,
        help="Fuzzer sources as JSON object: {name: [paths]}",
    )
    parser.add_argument(
        "--fuzzer-sources-file",
        type=str,
        help="Path to JSON file containing fuzzer sources",
    )

    # Firmware vulnerability discovery mode
    parser.add_argument(
        "--firmware-name",
        type=str,
        help="Firmware name for reporting (auto-derived from filename if not set)",
    )
    parser.add_argument(
        "--ghidra",
        type=str,
        help="Path to Ghidra analyzeHeadless (default: GHIDRA_HOME env or /opt/ghidra)",
    )
    parser.add_argument(
        "--firmae",
        type=str,
        help="Path to FirmAE installation directory",
    )
    parser.add_argument(
        "--qemu-dir",
        type=str,
        default="/usr/bin",
        help="Path to QEMU binaries directory (default: /usr/bin)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results",
        help="Output directory for results and checkpoints (default: results/)",
    )
    parser.add_argument(
        "--phase3-scope",
        type=str,
        choices=["all", "high_priority"],
        default="all",
        help="Phase 3 analysis scope (default: all)",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not resume from checkpoints — rerun all phases",
    )
    parser.add_argument(
        "--phases",
        type=str,
        help="Comma-separated phases to run: phase1,phase2,phase3,phase4 (default: all)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        help="Firmware profile YAML path or registered name (e.g. 'DVRF' or 'profiles/DVRF.yaml')",
    )

    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> Config:
    """Create Config from parsed arguments"""
    # Start with environment config
    config = Config.from_env()

    # MCP server mode
    if args.mcp:
        config.mcp_mode = True
        return config

    # JSON mode - load from file
    if args.config:
        config = Config.from_json(args.config)
        # Infrastructure config from environment (not from JSON)
        config.mongodb_url = os.environ.get("MONGODB_URL", "mongodb://localhost:27017")
        config.mongodb_db = os.environ.get("MONGODB_DB", "fuzzingbrain")
        config.redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        return config

    # CLI mode - apply all arguments
    # Project info
    if args.repo_url:
        config.repo_url = args.repo_url
    if args.project:
        config.project_name = args.project
    if args.ossfuzz_project:
        config.ossfuzz_project_name = args.ossfuzz_project

    # Task identification
    if args.task_id:
        config.task_id = args.task_id

    # Workspace
    if args.workspace:
        config.workspace = args.workspace
    if args.in_place:
        config.in_place = args.in_place

    # Task configuration
    if args.task_type:
        config.task_type = args.task_type
    if args.scan_mode:
        config.scan_mode = args.scan_mode
    if args.sanitizers:
        config.sanitizers = args.sanitizers.split(",")
    if args.timeout:
        config.timeout_minutes = args.timeout
    if args.pov_count is not None:
        config.pov_count = args.pov_count
    if args.fuzzers:
        config.fuzzer_filter = [f.strip() for f in args.fuzzers.split(",") if f.strip()]
    if args.budget:
        config.budget_limit = args.budget

    # Commit configuration
    if args.target_commit:
        config.target_commit = args.target_commit
    if args.base_commit:
        config.base_commit = args.base_commit
    if args.delta_commit:
        config.delta_commit = args.delta_commit

    # Fuzz tooling
    if args.fuzz_tooling_url:
        config.fuzz_tooling_url = args.fuzz_tooling_url
    if args.fuzz_tooling_ref:
        config.fuzz_tooling_ref = args.fuzz_tooling_ref

    # Prebuild
    if args.work_id:
        config.work_id = args.work_id
    if args.prebuild_dir:
        config.prebuild_dir = args.prebuild_dir

    # Patch mode specific
    if args.gen_blob:
        config.gen_blob = args.gen_blob
    if args.input_blob:
        config.input_blob = args.input_blob

    # Harness mode specific (JSON format or file)
    if args.targets:
        import json

        config.targets = json.loads(args.targets)
    elif args.targets_file:
        import json

        with open(args.targets_file, "r") as f:
            config.targets = json.load(f)

    # Fuzzer sources (JSON format or file)
    if args.fuzzer_sources:
        import json

        config.fuzzer_sources = json.loads(args.fuzzer_sources)
    elif args.fuzzer_sources_file:
        import json

        with open(args.fuzzer_sources_file, "r") as f:
            config.fuzzer_sources = json.load(f)

    return config


# =============================================================================
# Shared Business Logic
# =============================================================================


def process_task(task: Task, config: Config) -> dict:
    """
    Process a task - shared logic for all entry modes.

    This is the core business logic that:
    1. Parses and validates the workspace
    2. Sets up repository and fuzz-tooling
    3. Discovers fuzzers
    4. Builds fuzzers
    5. Dispatches workers via Celery
    6. Monitors and collects results
    """
    global _current_task_id
    _current_task_id = task.task_id

    # Setup logging for this task
    project_name = config.project_name or "unknown"
    log_dir = setup_logging(
        project_name,
        task.task_id,
        metadata={
            "Task Type": task.task_type.value,
            "Scan Mode": task.scan_mode.value,
            "Workspace": config.workspace,
            "Sanitizers": ", ".join(config.sanitizers),
            "Timeout": f"{config.timeout_minutes} minutes",
            "Base Commit": config.base_commit,
            "Delta Commit": config.delta_commit,
        },
    )
    # Setup celery.log for Celery process logs
    setup_celery_logging()
    print_info(f"Logs: {log_dir}")

    print_info(f"Task ID: {task.task_id}")
    print_info(f"Task Type: {task.task_type.value}")
    print_info(f"Scan Mode: {task.scan_mode.value}")
    print("")

    print_step("Starting task processing pipeline...")

    from .core.task_processor import process_task as run_processor

    result = run_processor(task, config, get_repos())

    # Display result
    print("")
    if result["status"] == "error":
        print_error(f"Task failed: {result['message']}")
    else:
        print_info(f"Status: {result['status']}")
        print_info(f"Message: {result['message']}")
        if "workspace" in result:
            print_info(f"Workspace: {result['workspace']}")
        if "fuzzers" in result and result["fuzzers"]:
            print_info(f"Fuzzers: {', '.join(result['fuzzers'])}")

    return result


def create_task_from_config(config: Config) -> Task:
    """Create a Task object from Config"""
    from bson import ObjectId

    task_id = config.task_id or str(ObjectId())

    return Task(
        task_id=task_id,
        task_type=JobType(config.task_type),
        scan_mode=ScanMode(config.scan_mode),
        task_path=config.workspace,
        src_path=f"{config.workspace}/repo" if config.workspace else None,
        fuzz_tooling_path=f"{config.workspace}/fuzz-tooling"
        if config.workspace
        else None,
        diff_path=f"{config.workspace}/diff"
        if config.workspace and config.scan_mode == "delta"
        else None,
        repo_url=config.repo_url,
        project_name=config.project_name,
        ossfuzz_project_name=config.ossfuzz_project_name,
        sanitizers=config.sanitizers,
        timeout_minutes=config.timeout_minutes,
        pov_count=config.pov_count,
        budget_limit=config.budget_limit,
        target_commit=config.target_commit,
        base_commit=config.base_commit,
        delta_commit=config.delta_commit,
        fuzz_tooling_url=config.fuzz_tooling_url,
        fuzz_tooling_ref=config.fuzz_tooling_ref,
        is_fuzz_tooling_provided=config.fuzz_tooling_path is not None,
    )


# =============================================================================
# Entry Mode: MCP Server
# =============================================================================


def run_mcp_server(config: Config):
    """
    Start MCP server mode.

    Exposes FuzzingBrain as MCP tools for external AI systems.
    """
    setup_console_only("INFO")
    print_step("Starting FuzzingBrain MCP Server...")
    print_info(f"Host: {config.mcp_host}")
    print_info(f"Port: {config.mcp_port}")
    print("")
    print_info("Available MCP Tools:")
    print_info("  - fuzzingbrain_find_pov")
    print_info("  - fuzzingbrain_generate_patch")
    print_info("  - fuzzingbrain_pov_patch")
    print_info("  - fuzzingbrain_get_status")
    print_info("  - fuzzingbrain_generate_harness")
    print("")

    from .mcp_server import run_server as start_mcp_server

    start_mcp_server(config)


# =============================================================================
# Entry Mode: REST API
# =============================================================================


def run_api(config: Config):
    """
    Start REST API server mode.

    Exposes FuzzingBrain as REST API endpoints.
    """
    setup_console_only("INFO")
    print_step("Starting FuzzingBrain REST API Server...")
    print_info(f"Host: {config.api_host}")
    print_info(f"Port: {config.api_port}")
    print("")
    print_info("Available API Endpoints:")
    print_info("  POST /api/v1/pov         - Find vulnerabilities")
    print_info("  POST /api/v1/patch       - Generate patches")
    print_info("  POST /api/v1/pov-patch   - POV + Patch combo")
    print_info("  POST /api/v1/harness     - Generate harnesses")
    print_info("  GET  /api/v1/status/{id} - Get task status")
    print_info("  GET  /docs               - API documentation")
    print("")

    from .api_server import run_api_server

    run_api_server(host=config.api_host, port=config.api_port)


# =============================================================================
# Workspace Setup
# =============================================================================


def setup_workspace(config: Config) -> Config:
    """
    Setup workspace directory with repo and fuzz-tooling.

    This ensures the workspace has:
    1. A workspace directory
    2. A cloned repository (if repo_url provided)
    3. fuzz-tooling from OSS-Fuzz or custom URL

    Returns updated config with workspace path set.
    """
    from bson import ObjectId
    import subprocess
    import shutil
    import tempfile

    script_dir = Path(__file__).parent.parent
    workspace_base = Path(
        os.environ.get("FUZZINGBRAIN_WORKSPACE_BASE", str(script_dir / "workspace"))
    )

    # Generate task ID if not provided
    task_id = config.task_id or str(ObjectId())
    config.task_id = task_id

    # Determine project name
    project_name = config.project_name
    if not project_name and config.repo_url:
        # Extract from repo URL
        project_name = config.repo_url.rstrip("/").rstrip(".git").split("/")[-1]
        config.project_name = project_name

    # Create workspace if not provided
    if not config.workspace:
        workspace_name = f"{project_name}_{task_id}" if project_name else task_id
        config.workspace = str(workspace_base / workspace_name)

    workspace = Path(config.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # Clone repository if needed
    repo_path = workspace / "repo"
    if not repo_path.exists() and config.repo_url:
        print_step("Cloning repository...")
        print_info(f"URL: {config.repo_url}")
        try:
            result = subprocess.run(
                ["git", "clone", config.repo_url, str(repo_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print_error(f"Failed to clone repository: {result.stderr}")
                sys.exit(1)
            print_info("Repository cloned successfully")

            # Checkout target commit if specified (Full Scan mode)
            if config.target_commit:
                print_info(f"Checking out commit: {config.target_commit}")
                subprocess.run(
                    ["git", "checkout", config.target_commit],
                    cwd=str(repo_path),
                    capture_output=True,
                )
            # Checkout delta commit for Delta Scan mode
            elif config.scan_mode == "delta" and config.delta_commit:
                print_info(f"Checking out delta commit: {config.delta_commit}")
                subprocess.run(
                    ["git", "checkout", config.delta_commit],
                    cwd=str(repo_path),
                    capture_output=True,
                )
            elif (
                config.scan_mode == "delta"
                and config.base_commit
                and not config.delta_commit
            ):
                # If no delta_commit specified, use HEAD (default behavior is fine)
                print_info("Delta scan: using HEAD as delta commit")
        except Exception as e:
            print_error(f"Failed to clone repository: {e}")
            sys.exit(1)
    elif repo_path.exists():
        # Repo already exists, ensure correct commit is checked out
        if config.scan_mode == "delta" and config.delta_commit:
            print_info(f"Ensuring delta commit is checked out: {config.delta_commit}")
            subprocess.run(
                ["git", "checkout", config.delta_commit],
                cwd=str(repo_path),
                capture_output=True,
            )
        elif config.target_commit:
            print_info(f"Ensuring target commit is checked out: {config.target_commit}")
            subprocess.run(
                ["git", "checkout", config.target_commit],
                cwd=str(repo_path),
                capture_output=True,
            )

    # Setup fuzz-tooling if needed
    fuzz_tooling_path = workspace / "fuzz-tooling"
    if not fuzz_tooling_path.exists() or not any(fuzz_tooling_path.iterdir()):
        print_step("Setting up fuzz-tooling...")

        # Determine OSS-Fuzz project name
        ossfuzz_project = config.ossfuzz_project_name or project_name

        if config.fuzz_tooling_url:
            # Use custom fuzz-tooling URL
            print_info(f"Using custom fuzz-tooling: {config.fuzz_tooling_url}")
            try:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    clone_args = ["git", "clone", "--depth", "1"]
                    if config.fuzz_tooling_ref:
                        clone_args.extend(["--branch", config.fuzz_tooling_ref])
                    clone_args.extend([config.fuzz_tooling_url, tmp_dir])

                    result = subprocess.run(clone_args, capture_output=True, text=True)
                    if result.returncode != 0:
                        print_error(f"Failed to clone fuzz-tooling: {result.stderr}")
                    else:
                        # Copy relevant directories
                        fuzz_tooling_path.mkdir(parents=True, exist_ok=True)

                        # Look for project directory
                        projects_dir = Path(tmp_dir) / "projects"
                        if projects_dir.exists() and ossfuzz_project:
                            project_dir = _find_ossfuzz_project(
                                projects_dir, ossfuzz_project
                            )
                            if project_dir:
                                dest = fuzz_tooling_path / "projects" / project_dir.name
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copytree(project_dir, dest)
                                print_info(f"Found project: {project_dir.name}")

                        # Copy infra directory if exists
                        infra_dir = Path(tmp_dir) / "infra"
                        if infra_dir.exists():
                            shutil.copytree(infra_dir, fuzz_tooling_path / "infra")

                        print_info("Custom fuzz-tooling setup complete")
            except Exception as e:
                print_warn(f"Failed to setup custom fuzz-tooling: {e}")
        else:
            # Use google/oss-fuzz
            print_info("Fetching from google/oss-fuzz...")
            try:
                with tempfile.TemporaryDirectory() as tmp_dir:
                    result = subprocess.run(
                        [
                            "git",
                            "clone",
                            "--depth",
                            "1",
                            "https://github.com/google/oss-fuzz.git",
                            tmp_dir,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        print_warn(f"Failed to clone oss-fuzz: {result.stderr}")
                    else:
                        projects_dir = Path(tmp_dir) / "projects"
                        if projects_dir.exists() and ossfuzz_project:
                            project_dir = _find_ossfuzz_project(
                                projects_dir, ossfuzz_project
                            )
                            if project_dir:
                                fuzz_tooling_path.mkdir(parents=True, exist_ok=True)
                                dest = fuzz_tooling_path / "projects" / project_dir.name
                                dest.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copytree(project_dir, dest)
                                print_info(
                                    f"Found OSS-Fuzz project: {project_dir.name}"
                                )

                                # Copy infra directory
                                infra_dir = Path(tmp_dir) / "infra"
                                if infra_dir.exists():
                                    shutil.copytree(
                                        infra_dir, fuzz_tooling_path / "infra"
                                    )
                            else:
                                print_warn(
                                    f"No matching OSS-Fuzz project found for: {ossfuzz_project}"
                                )
                                print_warn(
                                    "Use 'ossfuzz_project_name' in config to specify manually"
                                )
            except Exception as e:
                print_warn(f"Failed to fetch from oss-fuzz: {e}")
    else:
        print_info("Using existing fuzz-tooling")

    # Setup diff directory for delta scan
    if config.scan_mode == "delta" and config.base_commit:
        diff_path = workspace / "diff"
        diff_path.mkdir(parents=True, exist_ok=True)

        diff_file = diff_path / "ref.diff"
        if not diff_file.exists() and repo_path.exists():
            print_step("Generating diff for delta scan...")
            delta_commit = config.delta_commit or "HEAD"
            try:
                result = subprocess.run(
                    [
                        "git",
                        "diff",
                        f"{config.base_commit}..{delta_commit}",
                        "--",
                        ".",
                        ":!.aixcc",
                        ":!*/.aixcc",
                    ],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    diff_file.write_text(result.stdout)
                    print_info(
                        f"Generated diff: {config.base_commit[:8]}..{delta_commit[:8] if delta_commit != 'HEAD' else 'HEAD'}"
                    )
            except Exception as e:
                print_warn(f"Failed to generate diff: {e}")

    return config


def _find_ossfuzz_project(projects_dir: Path, project_name: str) -> Optional[Path]:
    """
    Find OSS-Fuzz project directory by name.

    Tries various name variations to match the project.
    """
    # Direct match
    direct = projects_dir / project_name
    if direct.exists():
        return direct

    # Lowercase
    lower = projects_dir / project_name.lower()
    if lower.exists():
        return lower

    # Remove common prefixes/suffixes
    import re

    stripped = re.sub(r"^(lib|py|go|rust)-?", "", project_name, flags=re.IGNORECASE)
    stripped = re.sub(r"-?(lib|py|go|rust)$", "", stripped, flags=re.IGNORECASE)
    if stripped != project_name:
        stripped_path = projects_dir / stripped
        if stripped_path.exists():
            return stripped_path
        stripped_lower = projects_dir / stripped.lower()
        if stripped_lower.exists():
            return stripped_lower

    # Remove afc- prefix (AIxCC repos)
    if project_name.lower().startswith("afc-"):
        afc_stripped = project_name[4:]
        afc_path = projects_dir / afc_stripped
        if afc_path.exists():
            return afc_path
        afc_lower = projects_dir / afc_stripped.lower()
        if afc_lower.exists():
            return afc_lower

    return None


# =============================================================================
# Entry Mode: JSON Config
# =============================================================================


def run_json_mode(config: Config):
    """
    Run from JSON configuration file.

    All task parameters are loaded from the JSON file.
    """
    print_step("Starting FuzzingBrain from JSON config...")

    # Setup workspace (clone repo, download fuzz-tooling)
    config = setup_workspace(config)

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print_error(error)
        sys.exit(1)

    # Print configuration summary
    print_info(f"Scan Mode: {config.scan_mode}")
    print_info(f"Task Type: {config.task_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.repo_url:
        print_info(f"Repository: {config.repo_url}")
    if config.workspace:
        print_info(f"Workspace: {config.workspace}")
    if config.scan_mode == "delta":
        print_info(
            f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}"
        )

    print("")

    # Create and process task
    task = create_task_from_config(config)
    result = process_task(task, config)

    return result


# =============================================================================
# Entry Mode: Local Workspace
# =============================================================================


def run_local_mode(config: Config):
    """
    Run on local workspace.

    Uses an existing workspace directory with repo and fuzz-tooling.
    """
    print_step("Starting FuzzingBrain Local Mode...")

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print_error(error)
        sys.exit(1)

    # Print configuration summary
    print_info(f"Workspace: {config.workspace}")
    print_info(f"Scan Mode: {config.scan_mode}")
    print_info(f"Task Type: {config.task_type}")
    print_info(f"Sanitizers: {', '.join(config.sanitizers)}")
    print_info(f"Timeout: {config.timeout_minutes} minutes")

    if config.scan_mode == "delta":
        print_info(
            f"Delta: {config.base_commit[:8]}..{(config.delta_commit or 'HEAD')[:8] if config.delta_commit else 'HEAD'}"
        )

    print("")

    # Verify workspace structure
    workspace = Path(config.workspace)
    if not workspace.exists():
        print_error(f"Workspace does not exist: {config.workspace}")
        sys.exit(1)

    repo_path = workspace / "repo"
    if not repo_path.exists():
        print_warn("No repo directory found in workspace")

    fuzz_tooling = workspace / "fuzz-tooling"
    if fuzz_tooling.exists():
        print_info("Fuzz-tooling found")
    else:
        print_warn("No fuzz-tooling directory found")

    print("")

    # Create and process task
    task = create_task_from_config(config)
    result = process_task(task, config)

    # Show expected output structure
    print("")
    print_step("Expected output structure:")
    print_info(f"  {config.workspace}/results/")
    if "pov" in config.task_type:
        print_info("  ├── povs/")
    if "patch" in config.task_type:
        print_info("  ├── patches/")
    if config.task_type == "harness":
        print_info("  ├── harnesses/")
    print_info("  └── report.json")

    return result


# =============================================================================
# Entry Mode: Firmware Vulnerability Discovery
# =============================================================================


def run_firmware_mode(args: argparse.Namespace):
    """
    Run the firmware vulnerability discovery pipeline.

    firmware.bin → Phase 1 (static) → Phase 2 (attack surface) →
    Phase 3 (SP analysis) → Phase 4 (dynamic verify) → Report.
    """
    setup_console_only("INFO")
    print_step("Starting Firmware Vulnerability Discovery Pipeline...")
    print(f"")

    firmware_path = args.firmware
    if not firmware_path:
        print_error("--firmware is required for firmware mode")
        sys.exit(1)

    from pathlib import Path as _Path
    if not _Path(firmware_path).exists():
        print_error(f"Firmware file not found: {firmware_path}")
        sys.exit(1)

    # Parse phases
    phases = None
    if args.phases:
        from .firmware_pipeline import FirmwarePipeline
        phases = {
            p.strip() for p in args.phases.split(",") if p.strip()
        }
        invalid = phases - FirmwarePipeline.VALID_PHASES
        if invalid:
            print_error(
                f"Invalid phases: {sorted(invalid)}. "
                f"Must be one of: {sorted(FirmwarePipeline.VALID_PHASES)}"
            )
            sys.exit(1)

    # Load firmware profile if specified
    firmware_profile = None
    if args.profile:
        from .firmware_profile import load_profile
        try:
            firmware_profile = load_profile(args.profile)
            print_info(f"Loaded firmware profile: {firmware_profile.name} v{firmware_profile.version}")
            print_info(f"  Architecture: {firmware_profile.architecture.cpu} {firmware_profile.architecture.bits}-bit {firmware_profile.architecture.endian}")
            if firmware_profile.has_entry_points:
                print_info(f"  Entry Points: {len(firmware_profile.known_entry_points)} known")
            if firmware_profile.has_ground_truth:
                print_info(f"  Ground Truth CVEs: {len(firmware_profile.known_cves)} known")
        except Exception as e:
            print_error(f"Failed to load firmware profile: {e}")
            sys.exit(1)

    # Print configuration
    print_info(f"Firmware: {firmware_path}")
    if args.firmware_name:
        print_info(f"Firmware Name: {args.firmware_name}")
    print_info(f"Output Dir: {args.output}")
    print_info(f"Phase 3 Scope: {args.phase3_scope}")
    print_info(f"Resume: {'No' if args.no_resume else 'Yes'}")
    if phases:
        print_info(f"Phases: {', '.join(sorted(phases))}")
    if args.ghidra:
        print_info(f"Ghidra: {args.ghidra}")
    if args.firmae:
        print_info(f"FirmAE: {args.firmae}")
    print(f"")

    # Build and run pipeline
    from .firmware_pipeline import FirmwarePipeline

    pipeline = FirmwarePipeline(
        binwalk_bin="binwalk",
        ghidra_headless=args.ghidra,
        firmae_dir=args.firmae,
        qemu_dir=args.qemu_dir,
        output_dir=args.output,
        phase3_scope=args.phase3_scope,
        firmware_profile=firmware_profile,
    )

    try:
        report = pipeline.run(
            firmware_path=firmware_path,
            firmware_name=args.firmware_name,
            resume=not args.no_resume,
            phases=phases,
        )

        # Print summary
        print(f"")
        print_step("Pipeline Complete!")
        print_info(f"Total vulnerabilities found: {report.count}")
        print_info(
            f"Confirmed (dynamic): {report.statistics.dynamic_full_verified + report.statistics.dynamic_user_verified}"
        )
        print_info(
            f"Static high confidence: {report.statistics.static_high_reserved}"
        )
        print_info(f"Verification rate: {report.statistics.verification_rate}")
        print_info(f"Unique crashes: {report.statistics.unique_crashes}")
        print(f"")

        # List top vulnerabilities
        if report.vulnerabilities:
            print_step("Top Vulnerabilities:")
            for i, v in enumerate(report.vulnerabilities[:5], 1):
                icon = (
                    "\033[0;31m🔴\033[0m" if v.priority == "P0"
                    else "\033[0;33m🟡\033[0m" if v.priority == "P1"
                    else "\033[0;36m🔵\033[0m"
                )
                print(
                    f"  {icon} {v.cwe} — {v.title[:80]} "
                    f"({v.verification_level}, conf={v.confidence:.0%})"
                )
            if report.count > 5:
                print(f"  ... and {report.count - 5} more")

        # Report paths
        output_dir = _Path(args.output) / (args.firmware_name or _Path(firmware_path).stem)
        print(f"")
        print_info(f"JSON report: {output_dir / 'final_report.json'}")
        print_info(f"Markdown report: {output_dir / 'final_report.md'}")

        # Ground truth cross-reference
        if firmware_profile and firmware_profile.has_ground_truth:
            print(f"")
            print_step("Ground Truth Cross-Reference:")
            match_data = report.ground_truth_match or {}
            recall = match_data.get("recall", 0)
            found = match_data.get("found_count", 0)
            total = match_data.get("total_known", 0)
            extra = len(match_data.get("extra", []))
            bar = "█" * int(min(recall * 20, 20))
            print_info(f"  Detection Rate: {bar} {recall:.0%} ({found}/{total} known CVEs found)")
            if extra:
                print_info(f"  New discoveries: {extra} SP(s) beyond known CVEs")
            unmatched = match_data.get("unmatched_cves", [])
            if unmatched:
                print_warn(f"  Missed: {len(unmatched)} known CVE(s) not discovered:")
                for cve in unmatched[:5]:
                    if isinstance(cve, dict):
                        print(f"    - {cve.get('cve_id', '?')}: {cve.get('function_name', '?')}")
                    else:
                        print(f"    - {cve.cve_id}: {cve.function_name}")

    except KeyboardInterrupt:
        print_warn("\nPipeline interrupted by user. Checkpoints saved for resume.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Main entry point - routes to appropriate mode"""
    args = parse_args()
    config = create_config_from_args(args)

    if config.budget_limit > 0:
        print(f"\033[0;36m[CONFIG]\033[0m Budget limit: ${config.budget_limit:.2f}")
    if config.pov_count > 0:
        print(f"\033[0;36m[CONFIG]\033[0m POV count limit: {config.pov_count}")

    # Show fuzzer filter if specified
    if config.fuzzer_filter:
        print(
            f"\033[0;36m[CONFIG]\033[0m Fuzzer filter: {', '.join(config.fuzzer_filter)}"
        )

    # Check for API mode from args
    if hasattr(args, "api") and args.api:
        config.api_mode = True

    # =========================================================================
    # Check if firmware mode (standalone, no MongoDB needed)
    # =========================================================================
    if args.firmware:
        run_firmware_mode(args)
        return

    # =========================================================================
    # Initialize database connection (shared by all other modes)
    # =========================================================================
    repos = init_database(config)

    # =========================================================================
    # Route to corresponding mode
    # =========================================================================
    if config.mcp_mode:
        # Mode 1: MCP Server
        run_mcp_server(config)
    elif config.api_mode:
        # Mode 2: REST API Server
        run_api(config)
    elif args.config:
        # Mode 3: JSON Config
        run_json_mode(config)
    else:
        # Mode 4: Local Workspace
        run_local_mode(config)


if __name__ == "__main__":
    main()
