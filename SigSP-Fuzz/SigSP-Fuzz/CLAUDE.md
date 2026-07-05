# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests (uses mongomock, no external services needed)
pytest tests/ -v

# Run a single test file
pytest tests/test_models.py -v

# Run a specific test
pytest tests/test_models.py::test_function_name -v

# Lint
ruff check .

# Start infrastructure (MongoDB + Redis)
docker compose up -d fb-mongo fb-redis

# Run the CLI (local mode)
./FuzzingBrain.sh <github_url_or_local_path>

# Start REST API server
./FuzzingBrain.sh --api

# Start MCP server
./FuzzingBrain.sh --mcp

# Run from JSON config
./FuzzingBrain.sh --config config.json

# Full Docker deployment
docker compose --profile task up
```

## Architecture Overview

FuzzingBrain is an AI-driven autonomous vulnerability discovery system combining LLMs with fuzzing. Its key innovation is the **Suspicious Point (SP)** abstraction — LLM agents identify potential vulnerabilities semantically, then target fuzzers verify them mechanically, eliminating LLM hallucination false positives.

### Four-Layer Architecture

1. **Application Layer** (`main.py`, `api_server.py`, `mcp_server.py`) — Four entry modes: REST API (FastAPI on 8080), MCP Server (FastMCP for AI integration), JSON Config (batch), Local Mode (CLI). All modes share the same `process_task()` core logic.

2. **Agent Layer** (`agents/`) — Specialized LLM agents communicate through MongoDB collections using claim-based scheduling:
   - **Direction Planning** — Partitions codebase into logical "directions" (groups of related functions) with prioritized pools
   - **Function Analysis (SP Generators)** — Deep per-function vulnerability review, creates SPs
   - **SP Verifier** — Validates SP feasibility, adjusts confidence scores, filters false positives
   - **POV Agent** — Generates trigger inputs (POV blobs) to make vulnerabilities crash
   - **Seed Agent** — Generates high-quality fuzzing seeds for the Global Fuzzer

3. **Analysis Service Layer** (`analyzer/`, `analysis/`) — Static analysis via Unix domain socket RPC: tree-sitter function extraction, OSS-Fuzz Introspector call graphs, LLVM coverage collection. The Analysis Server runs as a long-lived subprocess per task; Workers/Agents query it via `AnalysisClient`.

4. **Infrastructure Layer** (`core/infrastructure.py`, `worker/`) — MongoDB (document storage), Redis (Celery broker + function cache), Celery (distributed task execution).

### Core Concepts

- **Suspicious Point (SP)**: A potential vulnerability with structured metadata — control-flow location (not line numbers), CWE type, trigger conditions, confidence score (0–1). Sits between function-level and line-level granularity.
- **Direction**: A logical partition of the codebase (3–8 per project), each with `core_functions` (must analyze), `entry_functions` (fuzzer entry points), and `big_pool` (all reachable functions).
- **Two-Level Function Pool**: Small Pool (Direction Agent priorities, must be fully analyzed) vs Big Pool (all reachable, best-effort).
- **Dual-Layer Fuzzer**: Global Fuzzer (fork=2, breadth exploration with Seed Agent seeds) + per-SP Fuzzer Pool (fork=1 each, depth exploration with POV Agent blobs). CrashMonitor watches all crash directories and creates POV records via callback.

### Pipeline Flow

```
Direction Planning → SP Generation (claim-based, 5 concurrent) →
SP Verification (claim-based, 5 concurrent) → POV Generation (claim-based, 5 concurrent)
```

Each stage uses atomic MongoDB `find_one_and_update` claims. The pipeline runs inside Celery workers as an async event loop. The Dispatcher (`core/dispatcher.py`) polls for completion conditions: timeout, budget exceeded, POV target reached, or all workers completed.

### Key Module Map

| Module | Purpose |
|--------|---------|
| `core/config.py` | Configuration from env/JSON/CLI args |
| `core/models.py` | Task, Worker, SP, POV, Direction dataclasses |
| `core/task_processor.py` | Workspace setup, fuzzer discovery, pipeline orchestration |
| `core/dispatcher.py` | Worker dispatch, completion polling, graceful shutdown |
| `core/infrastructure.py` | Redis/Celery lifecycle management (auto-start for CLI mode) |
| `core/sp_dedup.py` | SP deduplication logic |
| `agents/base.py` | Base agent class with LLM conversation loop, tool dispatch |
| `agents/context.py` | Isolated runtime context per agent (MongoDB-backed, in-memory registry) |
| `agents/sp_generators.py` | Function analysis agents (Full, LargeFull, Delta variants) |
| `agents/sp_verifier.py` | SP verification agent |
| `agents/pov_agent.py` | POV generation agent |
| `analyzer/server.py` | Long-lived analysis server (Unix socket JSON-RPC) |
| `analyzer/client.py` | Thread-safe client for querying the analysis server |
| `analyzer/tasks.py` | Celery tasks for building fuzzers, running introspector |
| `worker/pipeline.py` | Async pipeline orchestrating agents within a Celery worker |
| `worker/executor.py` | Worker execution strategy selection (delta vs fullscan) |
| `worker/context.py` | Worker lifecycle context with DB persistence and status guards |
| `tools/analyzer.py` | MCP tool definitions for code analysis queries |
| `tools/directions.py` | MCP tool definitions for direction management |
| `db/repository.py` | Repository pattern for all MongoDB collections |

### Testing

Tests use `mongomock` for MongoDB and require no external services. The `conftest.py` provides `mock_db` and `repos` fixtures. Tests follow the pattern in `tests/TEST_PLAN.md` with graduated priorities (P0–P3). Key test areas include model serialization, agent isolation, worker lifecycle, pipeline chain correctness, and stopping conditions.

Test files should run in < 5 seconds each. Mocking strategy: `mongomock` for DB, `fakeredis` for Redis, `unittest.mock.patch` on `litellm.acompletion` for LLM, mock sockets for analyzer.

### Important Patterns

- **Agent isolation**: Each agent has its own `AgentContext` with a MongoDB ObjectId, stored in a global in-memory registry. Tools use `contextvars` for agent-scoped state. Direction IDs must be cleared when agents transition between pipeline phases.
- **Status transition guards**: `WorkerContext.update_status()` enforces monotonic ordering (pending→running→completed/failed). `__exit__` is idempotent (won't overwrite terminal status).
- **Claim-based scheduling**: All pipeline stages use atomic MongoDB claims. `finally` blocks must release claims to prevent orphaned SPs/Directions. `pov_attempted_by` must be cleaned on claim release for retry to work.
- **Circular import avoidance**: `core/__init__.py` does NOT export `TaskProcessor` or `WorkerDispatcher` — import them directly from their modules.
