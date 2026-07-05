#!/usr/bin/env python3
"""Run Phase 3 with 1 direction to test the pipeline speed."""
import sys, json, time
sys.path.insert(0, '.')
from pathlib import Path

from fuzzingbrain.static.models import FunctionInfo
from fuzzingbrain.attack_surface.models import AttackSurface, DirectionResult
from fuzzingbrain.agents.firmware.pipeline import Phase3Pipeline
from fuzzingbrain.llms import LLMClient
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="INFO")

# Load Phase 1 functions
with open('results/TEW-657BRM-1001/phase1_result.json') as f:
    p1 = json.load(f)
functions = []
for fn in p1['functions']:
    functions.append(FunctionInfo(
        name=fn['name'], address=fn.get('address', 0),
        pseudo_code=fn.get('pseudo_code', ''),
        binary_path=fn.get('binary_path', ''),
        callees=fn.get('callees', []), callers=fn.get('callers', []),
        dangerous_funcs=fn.get('dangerous_funcs', []),
        has_unsafe_calls=fn.get('has_unsafe_calls', False),
        strings_used=fn.get('strings_used', []),
        arch=fn.get('arch', 'mips'),
        complexity=fn.get('complexity', 0),
    ))
logger.info(f"Loaded {len(functions)} functions")

# Load directions using proper deserialization
with open('results/TEW-657BRM-1001/phase2_directions.json') as f:
    dirs_data = json.load(f)
direction_result = DirectionResult.from_dict(dirs_data)

# Keep only the first (highest priority) direction
direction_result.directions = direction_result.directions[:1]
logger.info(f"Testing with 1 direction: {direction_result.directions[0].name}")

# Load attack surfaces
with open('results/TEW-657BRM-1001/phase2_attack_surfaces.json') as f:
    as_data = json.load(f)
attack_surfaces = []
for a in as_data.get('attack_surfaces', []):
    attack_surfaces.append(AttackSurface(
        name=a.get('name', ''),
        category=a.get('category', 'other'),
        entry_functions=a.get('entry_functions', []),
        protocol=a.get('protocol', ''),
    ))
logger.info(f"Loaded {len(attack_surfaces)} attack surfaces")

# Run Phase 3 (high_priority, single direction)
pipeline = Phase3Pipeline(
    llm_client=LLMClient(),
    scope='high_priority',
    temperature=0.3,
    max_tokens=8000,
)

logger.info("Starting Phase 3...")
start = time.time()
try:
    result = pipeline.run(
        directions=direction_result,
        functions=functions,
        attack_surfaces=attack_surfaces,
    )
    elapsed = time.time() - start
    logger.info(f"Phase 3 complete in {elapsed:.0f}s")
    logger.info(f"  Raw SPs: {result.statistics.total_raw_sps}")
    logger.info(f"  Verified: {result.statistics.after_verification}")
    for sp in result.verified_sps:
        logger.info(f"  [{sp.priority}] {sp.title}: {sp.cwe} (conf={sp.confidence:.2f})")
except Exception as e:
    elapsed = time.time() - start
    logger.error(f"Phase 3 ERROR ({elapsed:.0f}s): {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
