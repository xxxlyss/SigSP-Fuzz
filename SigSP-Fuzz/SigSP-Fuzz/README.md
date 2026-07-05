# FuzzingBrain V2 — AI-Driven Firmware Vulnerability Discovery

[![Tests](https://img.shields.io/badge/tests-89%20passed-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()

**No source code required.** Uses LLM semantic analysis + QEMU dynamic verification to automatically discover, verify, and report vulnerabilities in embedded firmware binaries.

---

## Quick Start

```bash
# Install
pip install -r requirements.txt
sudo apt install qemu-user qemu-system-arm qemu-system-mips binwalk

# Configure LLM
cp fuzzingbrain/llm_config.yaml fuzzingbrain/llm_config.local.yaml
# Edit: add API key + set default_model

# Run full pipeline
python -m fuzzingbrain.cli full-pipeline --firmware firmware/DVRF_v03.bin --arch mips

# Or test a single SP
python -m fuzzingbrain.cli test-sp --binary ./stack_bof_01 --arch mips \
  --mode argv --payload "$(python3 -c "print('A'*300)")"
```

---

## Pipeline

```
firmware.bin
  ├── Phase 1: binwalk + Ghidra/objdump → functions, callgraph
  ├── Phase 2: LLM attack surface + direction planning
  ├── Phase 3: 3× LLM analysts → cross-review → verified SPs
  └── Phase 4: PoC (LLM) → QEMU (stdin/argv/network) → crash/RCE
```

## CLI Reference

```bash
python -m fuzzingbrain.cli <command> [options]
```

| Command | Description |
|---------|-------------|
| `full-pipeline` | Complete Phase 1→2→3→4 |
| `phase3-analyze` | SP cross-examination (needs phase1+2 data) |
| `phase4-verify` | PoC verification with QEMU (needs phase3 data) |
| `test-sp` | Single SP test with QEMU user-mode |
| `qemu-boot` | Boot firmware in QEMU system-mode |
| `tools list/schema` | List MCP tools |

### Examples

```bash
# Full pipeline
python -m fuzzingbrain.cli full-pipeline -f router.bin -a arm -o results/

# Phase 4 only
python -m fuzzingbrain.cli phase4-verify -d results/DVRF/ --qemu-dir /usr/bin

# Single SP
python -m fuzzingbrain.cli test-sp -b ./stack_bof_01 -a mips -m argv \
  -p "$(python3 -c "print('A'*300)")"

# QEMU system-mode boot
python -m fuzzingbrain.cli qemu-boot -k vmlinuz -i initramfs.cpio.gz \
  -a arm --port-forward 9999:80

# Full pipeline with all options
python -m fuzzingbrain.cli full-pipeline \
  -f firmware/router.bin -a arm -o results/ \
  --qemu-dir /usr/bin --rootfs ./squashfs-root \
  --static-threshold 0.75 --phases all
```

---

## Tested Firmware

| Firmware | Arch | Status |
|----------|------|--------|
| **DVRF v0.3** | MIPS LE | ✅ 4/4 P0 verified (3 crashes + 1 RCE) |
| **Tenda AC9 v15** | ARM LE | ⚠️ httpd boots, TCP accepts (CFM pending) |
| **D-Link DWR-M920** | MIPS LE | ⏳ Boa server (simpler, pending) |

---

## Configuration

### LLM (`fuzzingbrain/llm_config.local.yaml`)

```yaml
api_keys:
  deepseek: "sk-xxx"
default_model: deepseek-v4-pro
agent_routing:
  poc_agent: deepseek-v4-pro
  default: deepseek-v4-pro
```

### Firmware Profile (`profiles/<name>.yaml`)

```yaml
name: Tenda AC9
architecture: { cpu: arm, endian: little, bits: 32 }
known_entry_points:
  - { name: HTTP Server, binary: bin/httpd, protocol: HTTP, port: 80 }
known_cves:
  - { cve_id: CVE-2018-14558, function_name: formSetUsbUnload, cwe: CWE-78 }
```

---

## Requirements

| Component | Purpose |
|-----------|---------|
| Python 3.10+ | Runtime |
| QEMU user-mode | L2 verification (`qemu-user`) |
| QEMU system-mode | Full-system boot (`qemu-system-arm/mips`) |
| binwalk | Firmware extraction |
| LLM API key | PoC generation + SP analysis |

---

## Architecture

```
fuzzingbrain/
├── cli.py                    ← CLI entry point
├── agents/firmware/          ← Phase 3: SP analysis
│   ├── sp_analysts.py        ← 3× specialist LLM agents
│   ├── cross_reviewer.py     ← Adversarial review
│   └── sp_verifier.py        ← Voting verification
├── verifier/                 ← Phase 4: Dynamic verification
│   ├── poc_agent.py          ← LLM PoC generation
│   ├── qemu_runner.py        ← QEMU (stdin/argv/network)
│   ├── firmae_runner.py      ← L1 FirmAE (optional)
│   ├── crash_monitor.py      ← Crash dedup
│   ├── static_assessor.py    ← L3 fallback
│   └── pipeline.py           ← Orchestrator
├── attack_surface/           ← Phase 2
├── static/                   ← Phase 1
├── tools/firmware_mcp/       ← MCP tools
├── reporter/                 ← Report generation
└── llms/                     ← LLM client
```

---

## Testing

```bash
# Phase 4 tests (89 passed)
pytest tests/test_phase4_pipeline.py tests/test_poc_agent.py \
       tests/test_crash_monitor.py tests/test_static_assessor.py \
       tests/test_verifier_models.py -v

# Full suite
pytest tests/ -v
```

---

## Key Features

1. **Zero hallucination** — LLM finds candidates, QEMU verifies mechanically
2. **Three-mode QEMURunner** — auto-detects stdin/argv/network delivery
3. **SP metadata fallback** — handles stripped binaries where Ghidra callgraph is incomplete
4. **CFM protocol RE** — captured and emulated Tenda proprietary config IPC
5. **Pure-ioctl networking** — creates br0 inside QEMU without shell tools

---

## Documentation

| File | Content |
|------|---------|
| `docs/Phase4_PoC_Verification_Report.md` | DVRF test report |
| `results/phase4_archive/PHASE4_FINAL_REPORT.md` | Full archive |
| `results/phase4_archive/CODE_CHANGES.md` | Code changes |
| `profiles/` | Firmware profiles |
