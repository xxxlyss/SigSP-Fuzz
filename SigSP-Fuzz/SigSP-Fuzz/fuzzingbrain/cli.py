"""
FuzzingBrain — AI-Driven Firmware Vulnerability Discovery CLI

Complete pipeline: firmware.bin → Phase1(Static) → Phase2(AttackSurface) →
Phase3(SP Analysis) → Phase4(PoC Verification) → Report

Usage examples:
  # Full pipeline (all 4 phases)
  python -m fuzzingbrain.cli full-pipeline --firmware router.bin --arch arm

  # Phase 3 SP analysis on existing Phase 1-2 results
  python -m fuzzingbrain.cli phase3-analyze --data results/DVRF/

  # Phase 4 PoC verification on existing Phase 3 results
  python -m fuzzingbrain.cli phase4-verify --data results/DVRF/ --qemu-dir /usr/bin

  # Test a single SP with QEMU
  python -m fuzzingbrain.cli test-sp --sp-id DVRF-STACK-BOF-01 --binary ./stack_bof_01 \\
      --arch mips --mode argv --payload $(python3 -c "print('A'*300)")

  # List MCP tools
  python -m fuzzingbrain.cli tools list
"""

import argparse
import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn,
    )
    from rich.panel import Panel
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# =============================================================================
# Console Helpers
# =============================================================================

_console = Console() if RICH_AVAILABLE else None

def _print_header(title: str):
    if RICH_AVAILABLE:
        _console.print(Panel(title, style="bold blue"))
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")

def _print_table(title: str, rows: List[tuple], columns: List[str]):
    if RICH_AVAILABLE:
        table = Table(title=title)
        for col in columns:
            table.add_column(col, style="cyan")
        for row in rows:
            table.add_row(*[str(c) for c in row])
        _console.print(table)
    else:
        print(f"\n{title}")
        print("  " + "\t".join(columns))
        for row in rows:
            print("  " + "\t".join(str(c) for c in row))

def _print_success(msg: str):
    msg_str = f"  ✓ {msg}"
    if RICH_AVAILABLE:
        _console.print(f"  [green]✓[/green] {msg}")
    else:
        print(msg_str)

def _print_error(msg: str):
    if RICH_AVAILABLE:
        _console.print(f"  [red]✗[/red] {msg}")
    else:
        print(f"  ✗ {msg}")

def _print_warning(msg: str):
    if RICH_AVAILABLE:
        _console.print(f"  [yellow]⚠[/yellow] {msg}")
    else:
        print(f"  ⚠ {msg}")


# =============================================================================
# Phase 3: SP Analysis
# =============================================================================

def _cmd_phase3(args):
    """Run Phase 3 SP cross-examination analysis."""
    _print_header("Phase 3: Suspicious Point Analysis")

    data_dir = Path(args.data)
    if not data_dir.exists():
        _print_error(f"Data directory not found: {data_dir}")
        sys.exit(1)

    p1_path = data_dir / "phase1_result.json"
    p2_as_path = data_dir / "phase2_attack_surfaces.json"
    p2_dir_path = data_dir / "phase2_directions.json"

    if not p1_path.exists():
        _print_error(f"Phase 1 result not found: {p1_path}")
        _print_warning("Run 'phase1-extract' first or provide --data with phase1_result.json")
        sys.exit(1)

    _print_success(f"Loading Phase 1: {p1_path}")
    _print_success(f"Loading Phase 2: {p2_as_path}" if p2_as_path.exists() else "Phase 2 attack surfaces: auto-detect")
    _print_success(f"Output: {data_dir / 'phase3_result.json'}")

    try:
        from .agents.firmware.pipeline import Phase3Pipeline

        pipeline = Phase3Pipeline(
            output_dir=str(data_dir),
            temperature=args.temperature,
        )
        result = pipeline.run(
            p1_path=str(p1_path),
            attack_surfaces_path=str(p2_as_path) if p2_as_path.exists() else None,
            directions_path=str(p2_dir_path) if p2_dir_path.exists() else None,
        )

        print(f"\n{'='*60}")
        print(f"Phase 3 Complete")
        print(f"{'='*60}")
        print(f"  Raw SPs:       {result.statistics.total_raw_sps}")
        print(f"  After dedup:   {result.statistics.after_dedup}")
        print(f"  Verified:      {result.statistics.after_verification}")
        print(f"  High conf:     {result.statistics.high_confidence_sps}")
        print(f"  False pos:     {result.statistics.discarded_as_false_positive}")
        print(f"  Needs verify:  {result.statistics.needs_dynamic_verification}")

        # Save
        pipeline.save(result, data_dir / "phase3_result.json")
        _print_success(f"Saved: {data_dir / 'phase3_result.json'}")

    except Exception as e:
        _print_error(f"Phase 3 failed: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


# =============================================================================
# Phase 4: PoC Verification
# =============================================================================

def _cmd_phase4(args):
    """Run Phase 4 PoC verification with QEMU."""
    _print_header("Phase 4: PoC Verification")

    data_dir = Path(args.data)
    if not data_dir.exists():
        _print_error(f"Data directory not found: {data_dir}")
        sys.exit(1)

    p3_path = data_dir / "phase3_result.json"
    p1_path = data_dir / "phase1_result.json"
    p2_path = data_dir / "phase2_attack_surfaces.json"

    if not p3_path.exists():
        _print_error(f"Phase 3 result not found: {p3_path}")
        sys.exit(1)

    _print_success(f"Loading Phase 3 SPs: {p3_path}")
    _print_success(f"QEMU dir: {args.qemu_dir}")
    _print_success(f"RootFS: {args.rootfs or 'auto-detect'}")
    _print_success(f"FirmAE: {args.firmae_dir or 'not configured (skip L1)'}")
    _print_success(f"Static threshold: {args.static_threshold}")

    # Load data
    with open(p3_path) as f:
        p3 = json.load(f)
    sps = p3.get('verified_sps', [])

    if not sps:
        _print_warning("No verified SPs found — Phase 3 may need to be re-run")
        sys.exit(1)

    p0_count = sum(1 for s in sps if s.get('priority') == 'P0')
    _print_success(f"SPs: {len(sps)} total, {p0_count} P0")

    try:
        from .agents.firmware.sp_models import VerifiedSP, AnalystConsensus, ExploitabilityAssessment
        from .static.models import FunctionInfo, CallGraph, CallGraphNode
        from .attack_surface.models import AttackSurface, PortInfo
        from .verifier.pipeline import Phase4Pipeline

        # Convert dict SPs to VerifiedSP objects
        verified_sps = []
        for sp_dict in sps:
            ea_dict = sp_dict.get('exploitability', {}) or {}
            consensus_dict = sp_dict.get('analyst_consensus', {}) or {}
            verified_sps.append(VerifiedSP(
                sp_id=sp_dict['sp_id'], cwe=sp_dict['cwe'], title=sp_dict['title'],
                description=sp_dict.get('description', ''),
                function_name=sp_dict['function_name'],
                vulnerable_code_snippet=sp_dict.get('vulnerable_code_snippet', ''),
                control_flow=sp_dict.get('control_flow', ''),
                trigger_condition=sp_dict.get('trigger_condition', ''),
                root_cause=sp_dict.get('root_cause', ''),
                exploitability=ExploitabilityAssessment(
                    attack_vector=ea_dict.get('attack_vector', 'network'),
                    difficulty=ea_dict.get('difficulty', 'moderate'),
                    reliability=ea_dict.get('reliability', 'medium'),
                    impact=ea_dict.get('impact', 'RCE'),
                ),
                confidence=sp_dict['confidence'],
                severity=sp_dict.get('severity', 'high'),
                analyst_type=sp_dict.get('analyst_type', 'memory_corruption'),
                binary_offset=sp_dict.get('binary_offset', ''),
                input_vector=sp_dict.get('input_vector', 'http_post'),
                priority=sp_dict['priority'],
                analyst_consensus=AnalystConsensus(
                    analyst_a=consensus_dict.get('analyst_a', 'confirmed'),
                    analyst_b=consensus_dict.get('analyst_b', 'confirmed'),
                    analyst_c=consensus_dict.get('analyst_c', 'confirmed'),
                    votes_confirmed=consensus_dict.get('votes_confirmed', 3),
                    votes_refuted=consensus_dict.get('votes_refuted', 0),
                    votes_uncertain=consensus_dict.get('votes_uncertain', 0),
                    final_vote=consensus_dict.get('final_vote', 'confirmed'),
                ),
            ))

        # Load Phase 1 functions if available
        functions = []
        if p1_path.exists():
            with open(p1_path) as f:
                p1 = json.load(f)
            for fn_dict in p1.get('functions', []):
                functions.append(FunctionInfo(
                    name=fn_dict['name'], address=fn_dict.get('address', 0),
                    binary_path=fn_dict.get('binary_path', ''),
                    pseudo_code=fn_dict.get('pseudo_code', ''),
                    callees=fn_dict.get('callees', []), callers=fn_dict.get('callers', []),
                    dangerous_funcs=fn_dict.get('dangerous_funcs', []),
                    arch=fn_dict.get('arch', args.arch or 'arm'),
                ))

        # Load attack surfaces if available
        attack_surfaces = []
        if p2_path.exists():
            with open(p2_path) as f:
                p2 = json.load(f)
            for a in p2.get('attack_surfaces', []):
                pi = a.get('port_info')
                attack_surfaces.append(AttackSurface(
                    name=a.get('name', ''), category=a.get('category', 'other'),
                    entry_functions=a.get('entry_functions', []),
                    protocol=a.get('protocol', ''),
                    port_info=PortInfo(port=pi['port'], protocol_type=pi.get('protocol_type', 'TCP'),
                                       certainty=pi.get('certainty', 'possible')) if pi else None,
                ))

        # Build callgraph if available
        callgraph = None
        if p1_path.exists():
            with open(p1_path) as f:
                p1 = json.load(f)
            cg_data = p1.get('callgraph', {})
            nodes = {}
            for name, nd in cg_data.get('nodes', {}).items():
                nodes[name] = CallGraphNode(
                    function_name=nd.get('function_name', name),
                    address=nd.get('address', 0),
                    callees=nd.get('callees', []), callers=nd.get('callers', []),
                )
            if nodes:
                callgraph = CallGraph(binary_path='', nodes=nodes)

        # Run Phase 4 pipeline
        pipeline = Phase4Pipeline(
            qemu_dir=args.qemu_dir,
            rootfs_dir=args.rootfs or '',
            firmae_dir=args.firmae_dir,
            output_dir=str(data_dir / 'phase4'),
            static_threshold=args.static_threshold,
            temperature=args.temperature,
        )

        _print_success("Running Phase 4 pipeline...")
        result = pipeline.run(
            verified_sps=verified_sps,
            functions=functions,
            attack_surfaces=attack_surfaces,
            callgraph=callgraph,
            firmware_path=args.firmware or '',
            firmware_name=args.firmware_name or Path(data_dir).parent.name,
        )

        # Display results
        print(f"\n{'='*60}")
        print(f"Phase 4 Complete")
        print(f"{'='*60}")
        print(f"  P0 SPs:          {result.statistics.total_p0_sps}")
        print(f"  PoCs generated:   {result.statistics.poc_generated}")
        print(f"  L1 (FirmAE):      {result.statistics.dynamic_full_verified}")
        print(f"  L2 (QEMU):        {result.statistics.dynamic_user_verified}")
        print(f"  L3 (StaticHigh):  {result.statistics.static_high_reserved}")
        print(f"  Discarded:        {result.statistics.discarded}")
        print(f"  Unique crashes:   {result.statistics.unique_crashes}")
        print(f"  Verification:     {result.statistics.verification_rate}")
        print(f"\n  Per-SP results:")
        for vr in result.verified_results:
            icon = "💥" if vr.crashed else ("📋" if vr.verification_level == "static_high" else "🗑️")
            crash_info = ""
            if vr.crash_info:
                crash_info = f"  {vr.crash_info.crash_type} @ {vr.crash_info.crash_address}"
            print(f"  {icon} {vr.sp_id:45s} {vr.verification_level:15s}{crash_info}")

        # Save
        pipeline.save(result, data_dir / "phase4_result.json")
        _print_success(f"Saved: {data_dir / 'phase4_result.json'}")
        if result.statistics.poc_generated > 0:
            _print_success(f"PoCs saved: {data_dir / 'phase4/pocs/'}")

    except Exception as e:
        _print_error(f"Phase 4 failed: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


# =============================================================================
# Single SP Test
# =============================================================================

def _cmd_test_sp(args):
    """Test a single SP with QEMU user-mode."""
    _print_header("Single SP QEMU Test")

    binary_path = args.binary
    if not os.path.exists(binary_path):
        _print_error(f"Binary not found: {binary_path}")
        sys.exit(1)

    _print_success(f"Binary: {binary_path}")
    _print_success(f"Arch: {args.arch}")
    _print_success(f"Mode: {args.mode}")
    _print_success(f"Payload: {args.payload[:60]}{'...' if len(args.payload) > 60 else ''}")

    try:
        from .verifier.qemu_runner import QEMURunner, InputMode
        from .verifier.models import PoC, PoCTarget
        from .agents.firmware.sp_models import VerifiedSP, AnalystConsensus, ExploitabilityAssessment

        mode_map = {
            'stdin': InputMode.STDIN, 'argv': InputMode.ARGV, 'network': InputMode.NETWORK,
        }
        mode = mode_map.get(args.mode, InputMode.ARGV)

        sp = VerifiedSP(
            sp_id=args.sp_id or 'test-sp', cwe='CWE-121', title='Manual SP Test',
            description='', function_name='main', vulnerable_code_snippet='',
            control_flow='', trigger_condition='', root_cause='',
            exploitability=ExploitabilityAssessment(
                attack_vector='network', difficulty='trivial', reliability='reliable', impact='RCE'),
            confidence=1.0, severity='critical', analyst_type='memory_corruption',
            binary_offset='',
            input_vector='argv' if mode == InputMode.ARGV else 'network_packet',
            priority='P0',
            analyst_consensus=AnalystConsensus(
                analyst_a='confirmed', analyst_b='confirmed', analyst_c='confirmed',
                votes_confirmed=3, votes_refuted=0, votes_uncertain=0, final_vote='confirmed'),
        )

        poc = PoC(
            sp_id=sp.sp_id, poc_type='stdin_input',
            poc_content=args.payload, poc_explanation=f'Manual test: {args.mode}',
            poc_target=PoCTarget(host='127.0.0.1', port=args.port or 8888),
        )

        runner = QEMURunner(
            qemu_dir=args.qemu_dir,
            rootfs_dir=args.rootfs or '',
            timeout=args.timeout,
            daemon_startup_timeout=args.daemon_timeout,
        )

        result = runner.verify(sp, poc, binary_path, args.arch)

        if result.crashed:
            ci = result.crash_info
            _print_success(f"💥 CRASH! {ci.crash_type} signal={ci.signal_number}")
            if ci.crash_address:
                _print_success(f"   Address: {ci.crash_address}")
            if ci.backtrace:
                _print_success(f"   Backtrace: {ci.backtrace[:3]}")
        else:
            print(f"  ○ No crash: {result.output[:200]}")

    except Exception as e:
        _print_error(f"Test failed: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


# =============================================================================
# QEMU System-Mode Boot
# =============================================================================

def _cmd_qemu_boot(args):
    """Boot firmware in QEMU system-mode for testing."""
    _print_header("QEMU System-Mode Firmware Boot")

    kernel = args.kernel
    rootfs = args.rootfs
    initrd = args.initrd

    if not kernel or not os.path.exists(kernel):
        _print_error(f"Kernel not found: {kernel}")
        sys.exit(1)

    qemu_bin = {
        'arm': 'qemu-system-arm', 'mips': 'qemu-system-mips',
        'mipsel': 'qemu-system-mipsel', 'x86_64': 'qemu-system-x86_64',
    }.get(args.arch, 'qemu-system-arm')

    # Build QEMU command
    cmd = [qemu_bin, '-m', str(args.memory), '-M', args.machine, '-cpu', args.cpu]

    if initrd:
        cmd += ['-kernel', kernel, '-initrd', initrd]
    else:
        cmd += ['-kernel', kernel]
        if rootfs:
            cmd += ['-drive', f'if=none,file={rootfs},format=raw,id=rootfs',
                    '-device', 'virtio-blk-device,drive=rootfs']

    if args.port_forward:
        host_port, guest_port = args.port_forward.split(':')
        cmd += ['-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{host_port}-:{guest_port}',
                '-device', 'virtio-net-device,netdev=net0']

    cmd += ['-append', args.kernel_args]
    if args.nographic:
        cmd.append('-nographic')

    _print_success(f"Kernel: {kernel}")
    _print_success(f"Arch: {args.arch} | Machine: {args.machine} | CPU: {args.cpu}")
    _print_success(f"Memory: {args.memory}MB")
    if args.port_forward:
        _print_success(f"Port forward: {args.port_forward}")
    _print_warning(f"Command: {' '.join(cmd)}")

    try:
        import subprocess
        import signal as sig

        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )

        _print_success(f"QEMU started (PID: {proc.pid})")
        print("  Waiting for firmware to boot... (Ctrl+C to stop)")

        try:
            for line in proc.stdout:
                if any(kw in line for kw in ['Listening', 'listen', 'httpd', 'boa', 'ready']):
                    print(f"  [FIRMWARE] {line.strip()}")
                if args.verbose:
                    if not line.startswith('['):
                        print(f"  {line.strip()}")
                if proc.poll() is not None:
                    break
        except KeyboardInterrupt:
            _print_warning("Interrupted — stopping QEMU")
        finally:
            proc.send_signal(sig.SIGTERM)
            proc.wait(timeout=5)
            _print_success("QEMU stopped")

    except FileNotFoundError:
        _print_error(f"QEMU binary not found: {qemu_bin}. Install: sudo apt install qemu-system-{args.arch}")
    except Exception as e:
        _print_error(f"QEMU boot failed: {e}")


# =============================================================================
# Full Pipeline
# =============================================================================

def _cmd_full_pipeline(args):
    """Run the complete Phase 1→2→3→4 pipeline."""
    _print_header("FuzzingBrain: Full Pipeline (Phase 1→2→3→4)")

    firmware_path = os.path.abspath(args.firmware)
    if not os.path.exists(firmware_path):
        _print_error(f"Firmware not found: {firmware_path}")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    phases = args.phases.split(',') if args.phases else ['1', '2', '3', '4']

    _print_success(f"Firmware: {firmware_path}")
    _print_success(f"Arch: {args.arch or 'auto'}")
    _print_success(f"Phases: {phases}")
    _print_success(f"Output: {output_dir}")

    total_start = time.time()

    try:
        # Phase 1+2: Static Analysis
        if any(p in phases for p in ['1', '2', 'all']):
            _print_header("Phase 1+2: Static Analysis + Attack Surface")
            try:
                from .firmware_pipeline import FirmwarePipeline
                pipeline = FirmwarePipeline(output_dir=str(output_dir))
                pipeline.run(
                    firmware_path=firmware_path,
                    firmware_name=Path(firmware_path).stem,
                    phases=['phase1', 'phase2'],
                    resume=args.resume,
                )
                _print_success(f"Phase 1+2 complete ({time.time() - total_start:.0f}s)")
            except ImportError:
                _print_warning("Phase 1+2 modules not available — skipping")
            except Exception as e:
                _print_error(f"Phase 1+2 failed: {e}")

        # Phase 3: SP Analysis
        if any(p in phases for p in ['3', 'all']):
            _print_header("Phase 3: SP Cross-Examination")
            try:
                from .agents.firmware.pipeline import Phase3Pipeline
                p3_pipeline = Phase3Pipeline(output_dir=str(output_dir))
                p3_result = p3_pipeline.run(
                    p1_path=str(output_dir / 'phase1_result.json'),
                    attack_surfaces_path=str(output_dir / 'phase2_attack_surfaces.json'),
                    directions_path=str(output_dir / 'phase2_directions.json'),
                )
                p3_pipeline.save(p3_result, output_dir / 'phase3_result.json')
                _print_success(f"Phase 3 complete: {p3_result.statistics.after_verification} SPs verified")
            except ImportError:
                _print_warning("Phase 3 modules not available — skipping")
            except Exception as e:
                _print_error(f"Phase 3 failed: {e}")

        # Phase 4: PoC Verification
        if any(p in phases for p in ['4', 'all']):
            _print_header("Phase 4: PoC Verification")
            try:
                args.data = str(output_dir)
                args.qemu_dir = getattr(args, 'qemu_dir', '/usr/bin')
                args.rootfs = getattr(args, 'rootfs', '')
                args.firmae_dir = getattr(args, 'firmae_dir', None)
                args.static_threshold = getattr(args, 'static_threshold', 0.75)
                args.temperature = getattr(args, 'temperature', 0.3)
                _cmd_phase4(args)
            except Exception as e:
                _print_error(f"Phase 4 failed: {e}")

    except KeyboardInterrupt:
        _print_warning("Pipeline interrupted — checkpoint saved")

    elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"Pipeline Complete ({elapsed:.0f}s)")
    print(f"{'='*60}")
    _print_success(f"Results: {output_dir}")


# =============================================================================
# Tools
# =============================================================================

def _cmd_tools(args):
    """List available MCP tools."""
    _print_header("FuzzingBrain MCP Tools")

    try:
        from .tools.firmware_mcp import get_registry
        registry = get_registry()
    except Exception:
        _print_warning("MCP registry not available")
        return

    if args.command2 == 'list':
        grouped = registry.list_by_category()
        for cat, names in grouped.items():
            print(f"\n[{cat.upper()}] ({len(names)} tools)")
            for name in names:
                tool = registry.get(name)
                if tool:
                    print(f"  {name}: {tool.description[:100]}...")
    elif args.command2 == 'schema':
        schemas = registry.get_function_schemas()
        print(json.dumps(schemas, indent=2, ensure_ascii=False))


# =============================================================================
# Main CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog='fuzzingbrain',
        description='FuzzingBrain — AI-driven Firmware Vulnerability Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full 4-phase pipeline
  python -m fuzzingbrain.cli full-pipeline --firmware router.bin --arch arm

  # Phase 3 only (needs Phase 1-2 data)
  python -m fuzzingbrain.cli phase3-analyze --data results/DVRF/

  # Phase 4 only (needs Phase 3 data)
  python -m fuzzingbrain.cli phase4-verify --data results/DVRF/ --qemu-dir /usr/bin

  # Test a single SP
  python -m fuzzingbrain.cli test-sp --binary ./stack_bof_01 --arch mips \\
      --mode argv --payload "$(python3 -c "print('A'*300)")"

  # Boot firmware in QEMU system-mode
  python -m fuzzingbrain.cli qemu-boot --kernel vmlinuz --initrd initramfs.cpio.gz \\
      --arch arm --port-forward 9999:80
        """,
    )

    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    subparsers = parser.add_subparsers(dest='command')

    # --- full-pipeline ---
    full = subparsers.add_parser('full-pipeline', help='Complete Phase 1→2→3→4 pipeline')
    full.add_argument('--firmware', '-f', required=True, help='Firmware binary (.bin)')
    full.add_argument('--arch', '-a', default=None, help='CPU architecture (arm/mips/mipsel)')
    full.add_argument('--output', '-o', default='results/', help='Output directory')
    full.add_argument('--phases', default='all', help='Phases: 1,2,3,4 or all')
    full.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    full.add_argument('--qemu-dir', default='/usr/bin', help='QEMU binary directory')
    full.add_argument('--rootfs', default='', help='Extracted rootfs for QEMU')
    full.add_argument('--firmae-dir', default=None, help='FirmAE installation path')
    full.add_argument('--static-threshold', type=float, default=0.75, help='L3 confidence threshold')
    full.add_argument('--temperature', type=float, default=0.3, help='LLM temperature')

    # --- phase3-analyze ---
    p3 = subparsers.add_parser('phase3-analyze', help='Phase 3: SP cross-examination analysis')
    p3.add_argument('--data', '-d', required=True, help='Directory with phase1+2 results')
    p3.add_argument('--temperature', type=float, default=0.3, help='LLM temperature')

    # --- phase4-verify ---
    p4 = subparsers.add_parser('phase4-verify', help='Phase 4: PoC verification with QEMU')
    p4.add_argument('--data', '-d', required=True, help='Directory with phase3 results')
    p4.add_argument('--qemu-dir', default='/usr/bin', help='QEMU binary directory')
    p4.add_argument('--rootfs', default='', help='Extracted firmware rootfs path')
    p4.add_argument('--firmae-dir', default=None, help='FirmAE installation path')
    p4.add_argument('--arch', default='arm', help='CPU architecture')
    p4.add_argument('--firmware', help='Original firmware binary (for FirmAE)')
    p4.add_argument('--firmware-name', help='Firmware name for report')
    p4.add_argument('--static-threshold', type=float, default=0.75, help='L3 confidence threshold')
    p4.add_argument('--temperature', type=float, default=0.3, help='LLM temperature')

    # --- test-sp ---
    tsp = subparsers.add_parser('test-sp', help='Test a single SP with QEMU user-mode')
    tsp.add_argument('--sp-id', default='test-sp', help='SP identifier')
    tsp.add_argument('--binary', '-b', required=True, help='Target binary path')
    tsp.add_argument('--arch', '-a', default='mips', help='CPU architecture')
    tsp.add_argument('--mode', '-m', default='argv', help='Input mode: stdin/argv/network')
    tsp.add_argument('--payload', '-p', required=True, help='PoC payload content')
    tsp.add_argument('--port', type=int, default=8888, help='Target port (network mode)')
    tsp.add_argument('--qemu-dir', default='/usr/bin', help='QEMU binary directory')
    tsp.add_argument('--rootfs', default='', help='Extracted rootfs path')
    tsp.add_argument('--timeout', type=int, default=10, help='Execution timeout (seconds)')
    tsp.add_argument('--daemon-timeout', type=int, default=5, help='Daemon startup timeout')

    # --- qemu-boot ---
    qboot = subparsers.add_parser('qemu-boot', help='Boot firmware in QEMU system-mode')
    qboot.add_argument('--kernel', '-k', required=True, help='Kernel image path')
    qboot.add_argument('--initrd', '-i', help='Initramfs (cpio.gz) path')
    qboot.add_argument('--rootfs', help='Root filesystem image path')
    qboot.add_argument('--arch', '-a', default='arm', help='CPU architecture')
    qboot.add_argument('--machine', '-M', default='virt', help='QEMU machine type')
    qboot.add_argument('--cpu', default='cortex-a15', help='QEMU CPU model')
    qboot.add_argument('--memory', '-m', type=int, default=256, help='Memory in MB')
    qboot.add_argument('--port-forward', help='Port forward (host:guest, e.g. 9999:80)')
    qboot.add_argument('--kernel-args', default='console=ttyAMA0 rw', help='Kernel command line')
    qboot.add_argument('--nographic', action='store_true', default=True, help='No GUI')

    # --- tools ---
    tools_parser = subparsers.add_parser('tools', help='MCP tools')
    tools_sub = tools_parser.add_subparsers(dest='command2')
    tools_sub.add_parser('list', help='List all tools')
    tools_sub.add_parser('schema', help='Show OpenAI function schemas')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Setup logging
    logger.remove()
    logger.add(sys.stderr, level='DEBUG' if args.verbose else 'INFO',
               format='<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | <level>{message}</level>')

    # Dispatch
    handlers = {
        'full-pipeline': _cmd_full_pipeline,
        'phase3-analyze': _cmd_phase3,
        'phase4-verify': _cmd_phase4,
        'test-sp': _cmd_test_sp,
        'qemu-boot': _cmd_qemu_boot,
        'tools': _cmd_tools,
    }

    handler = handlers.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
