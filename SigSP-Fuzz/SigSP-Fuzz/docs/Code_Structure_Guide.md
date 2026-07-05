# FuzzingBrain V2 代码结构详解

> 面向讲解和二次开发，覆盖软件 Fuzzing (原始) + 固件漏洞发现 (新增) 两条管线

---

## 一、全景图

```
FuzzingBrain-V2/
│
├── fuzzingbrain/           # ⭐ 核心源码 (128 .py, ~34万行)
│   │
│   ├── main.py             # CLI 入口 (固件模式 + 软件模式)
│   ├── api_server.py        # REST API 入口 (FastAPI)
│   ├── mcp_server.py        # MCP 协议入口 (AI Agent 集成)
│   ├── firmware_pipeline.py # 🆕 固件管线主入口 (Phase 1→4 + Report)
│   ├── firmware_profile.py  # 🆕 固件 Profile YAML 机制
│   │
│   ├── static/              # Phase 1: 静态提取层
│   ├── attack_surface/      # Phase 2: 攻击面识别 + 方向规划
│   ├── agents/firmware/     # Phase 3: 多 Agent SP 分析
│   ├── verifier/            # Phase 4: 动态验证
│   ├── reporter/            # 报告生成
│   │
│   ├── agents/              # 软件 Fuzzing 的 Agent (原始)
│   ├── core/                # 核心基础设施 + 任务调度
│   ├── llms/                # LLM 客户端 + 模型管理
│   ├── db/                  # MongoDB 数据库层
│   ├── worker/              # Celery 分布式 Worker
│   ├── fuzzer/              # Fuzzer 管理 (AFL++/libFuzzer)
│   ├── analyzer/            # 分析服务 RPC (tree-sitter/OSS-Fuzz)
│   ├── analysis/            # 代码解析器
│   └── tools/               # MCP 工具定义
│
├── tests/                   # 测试 (702 tests)
├── firmware/                # 固件镜像目录
├── profiles/                # 固件 Profile YAML
├── results/                 # 分析结果输出
├── docs/                    # 文档
│
├── FuzzingBrain.sh          # 主启动脚本
├── docker-compose.yml       # Docker 部署
└── requirements.txt         # Python 依赖
```

---

## 二、分层架构 (4 层)

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Application (入口层)                          │
│  main.py / api_server.py / mcp_server.py                │
│  → 4 种入口模式，共享 process_task() 核心逻辑            │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Agent (智能体层)                               │
│  agents/ + attack_surface/ + verifier/                  │
│  → 所有 LLM 调用都在这一层                               │
│  → Agent 间通过 MongoDB 的 claim 机制调度                │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Analysis Service (分析服务层)                  │
│  static/ + analyzer/ + analysis/                        │
│  → Unix domain socket RPC 长连接                        │
│  → Ghidra/objdump/binwalk 工具调用                       │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Infrastructure (基础设施层)                    │
│  core/ + db/ + worker/ + llms/ + fuzzer/                │
│  → MongoDB + Redis + Celery                             │
└─────────────────────────────────────────────────────────┘
```

---

## 三、核心模块详解

### 3.1 入口层 (`main.py` / `api_server.py` / `mcp_server.py`)

| 入口 | 文件 | 说明 |
|------|------|------|
| CLI 本地模式 | `main.py` | `./FuzzingBrain.sh <github_url>` |
| CLI 固件模式 | `main.py` | `--firmware firmware.bin --profile profiles/X.yaml` |
| REST API | `api_server.py` | FastAPI, 端口 8080 |
| MCP Server | `mcp_server.py` | FastMCP, AI Agent 集成 |
| JSON 批量 | `main.py` | `--config config.json` |

**main.py 核心函数**:

```
main()
├── run_software_mode()     # 原有软件 Fuzzing
│   └── process_task()      # 4 阶段管线
│       └── WorkerDispatcher.dispatch()
│           └── Celery workers 并行执行
│
└── run_firmware_mode()     # 🆕 固件漏洞发现
    └── FirmwarePipeline.run()
        ├── _run_phase1()   # binwalk + objdump/Ghidra
        ├── _run_phase2()   # 攻击面 + 方向规划
        ├── Phase3Pipeline.run()  # 多 Agent 分析
        ├── Phase4Pipeline.run()  # 动态验证
        └── _build_final_report() # 报告 + ground truth
```

---

### 3.2 Layer 2: 固件管线详细结构

#### Phase 1: `static/` — 静态提取

```
static/
├── models.py          # BinaryInfo, FunctionInfo, CallGraph, AnalysisResult
├── extractor.py       # FirmwareExtractor (binwalk -e 解包)
├── objdump_analyzer.py # 🆕 Ghidra-free 分析 (objdump/readelf/strings)
├── ghidra_analyzer.py  # Ghidra headless 反编译
├── callgraph.py        # CallGraphBuilder + CallGraphAnalyzer
└── strings_analyzer.py # 字符串提取 + 分类 (URL/端口/凭证/路径)
```

**数据流**:
```
firmware.bin
  → FirmwareExtractor.extract()
    → binwalk -e -M → squashfs-root/
    → 遍历 ELF magic → BinaryInfo[] (arch/bits/endian/path)
  → AnalyzerFactory.create()
    → GhidraAnalyzer (优先) 或 ObjdumpAnalyzer (回退)
    → analyze_binary() → AnalysisResult
      ├── readelf -s -W → 函数符号 (name/addr/size)
      ├── objdump -t → *UND* 导入符号 (静态链接地址解析)
      ├── objdump -d → 反汇编 (pseudo_code = 汇编文本)
      ├── callee 提取 (jal/bl → 直接调用, lw t9; jalr t9 → MIPS GOT)
      ├── DANGEROUS_FUNCTIONS 匹配 (23 个危险函数)
      └── strings → StringRef[] (分类标注)
  → CallGraphBuilder.build()
    → per-function callers/callees → 全局 CallGraph
```

#### Phase 2: `attack_surface/` — 攻击面识别

```
attack_surface/
├── models.py           # AttackSurface, AttackSurfaceResult,
│                       #   Direction, DirectionResult,
│                       #   PortInfo, AnalysisOrder
├── identifier.py       # AttackSurfaceIdentifier
│                       #   输入: 500 FunctionInfo + CallGraph
│                       #   输出: AttackSurfaceResult (12-14 surfaces)
│                       #   LLM: DeepSeek/Claude, 1 次调用
└── direction_planner.py # DirectionPlanner
                         #   输入: AttackSurfaceResult + CallGraph
                         #   输出: DirectionResult (3-8 directions)
                         #   LLM: DeepSeek/Claude, 1 次调用
```

**核心概念**:
- **AttackSurface**: 固件的可攻击入口 (HTTP/Telnet/UPnP/CGI端点)
- **Direction**: 逻辑分析分区，含 core_functions + entry_functions

#### Phase 3: `agents/firmware/` — 多 Agent SP 分析

```
agents/firmware/
├── sp_models.py       # FirmwareSP, CrossReviewVerdict, VerifiedSP,
│                      #   Phase3Result, Phase3Statistics
│                      #   ExploitabilityAssessment, AnalystConsensus
├── sp_analysts.py     # 3 个专业 LLM 分析师
│                      #   Agent A: memory_corruption (栈/堆溢出)
│                      #   Agent B: logic_flaw (认证绕过/逻辑漏洞)
│                      #   Agent C: injection (命令注入/格式字符串)
├── cross_reviewer.py  # 3 个交叉审查员
│                      #   互相审查其他分析师的 SP (4 维度)
│                      #   维度: reachability, input_feasibility,
│                      #         mitigation_bypass, alt_explanations
├── sp_verifier.py     # SPVerifier 终审
│                      #   算法投票 + LLM 终审 + P0-P3 优先级
├── sp_dedup.py        # SP 去重
├── pipeline.py        # Phase3Pipeline 编排
│                      #   _run_analysts_serial() → _run_cross_reviews()
│                      #   → verifier.verify() → dedup
└── prompts/           # Prompt 模板
    └── __init__.py    # get_analyst_prompt(), get_reviewer_prompt(),
                       #   get_verifier_prompt(), get_direction_prompt()
```

**执行流程**:
```
Direction[] (排序, priority 降序)
  │
  ├── Direction 1 (P5)
  │   ├── Analyst A → [SP1, SP2, ...]
  │   ├── Analyst B → [SP3, SP4, ...]
  │   └── Analyst C → [SP5, ...]
  │   └── Cross Review:
  │       ├── Reviewer A 审查 B+C 的 SP
  │       ├── Reviewer B 审查 C+A 的 SP
  │       └── Reviewer C 审查 A+B 的 SP
  │
  ├── Direction 2 (P5)
  │   └── ... (同上)
  │
  └── SPVerifier.verify(all_sps, all_reviews)
      ├── 自动通过: 3/3 confirmed → P0
      ├── 自动拒绝: ≥2 refuted → 丢弃
      └── LLM 终审: 争议 SP → 分批 × 20/批 → 最终裁决
```

#### Phase 4: `verifier/` — 动态验证

```
verifier/
├── models.py           # PoC, VerificationResult, CrashInfo,
│                       #   Phase4Result, Phase4Statistics, FinalReport
├── pipeline.py         # Phase4Pipeline 编排
├── poc_agent.py        # PoCAgent (LLM 生成触发输入)
├── firmae_runner.py    # L1: FirmAE 全系统模拟验证
├── qemu_runner.py      # L2: QEMU user-mode 模拟验证
├── crash_monitor.py    # 崩溃去重
└── static_assessor.py  # L3: 纯静态评估 (无动态环境时的降级)
```

**三层降级验证**:
```
P0 SP → L1 FirmAE (全系统) → 失败? → L2 QEMU (用户态) → 失败? → L3 Static
          ✅ 直接确认               ✅ 直接确认                ⚠️ 置信度保留
```

#### Report: `reporter/`

```
reporter/
├── __init__.py
└── generator.py        # ReportGenerator
                        #   to_json(FinalReport)  → final_report.json
                        #   to_markdown(FinalReport) → final_report.md
```

---

### 3.3 软件 Fuzzing 管线 (原始)

```
agents/
├── base.py                    # Agent 基类 (LLM 对话循环 + 工具分发)
├── context.py                 # AgentContext (MongoDB 隔离运行时)
├── direction_planning_agent.py # 方向规划 Agent (原版)
├── sp_generators.py           # SP 生成 Agent (Full/LargeFull/Delta)
├── sp_verifier.py             # SP 验证 Agent (原版)
├── pov_agent.py               # POV 生成 Agent
└── pov_report_agent.py        # POV 报告 Agent

core/
├── config.py                  # 全局配置 (env/JSON/CLI)
├── task_processor.py          # 任务设置 + 管线编排 (软件模式)
├── dispatcher.py              # Worker 调度 + 完成轮询
├── infrastructure.py          # Redis/Celery 生命周期管理
├── sp_dedup.py                # SP 去重 (原版)
├── fuzzer_builder.py          # Fuzzer 编译构建
├── pov_packager.py            # POV 打包
├── models/                    # 核心数据模型
│   ├── task.py                # Task
│   ├── worker.py              # Worker
│   ├── suspicious_point.py    # SuspiciousPoint
│   ├── pov.py                 # POV
│   ├── direction.py           # Direction
│   ├── function.py            # Function
│   ├── fuzzer.py              # Fuzzer
│   └── callgraph.py           # CallGraph
└── utils.py                   # 工具函数

worker/
├── pipeline.py                # Worker 内异步管线
├── executor.py                # 执行策略 (delta vs fullscan)
├── context.py                 # WorkerContext (状态机)
├── tasks.py                   # Celery 任务定义
└── strategies/                # 执行策略
    ├── pov_fullscan.py        # POV 全量扫描
    ├── pov_delta.py           # POV 增量
    └── patch_strategy.py      # Patch 策略
```

---

### 3.4 LLM 客户端层

```
llms/
├── models.py          # ModelInfo, Provider, 全部模型定义
│                      #   Anthropic: Claude Opus/Sonnet/Haiku
│                      #   OpenAI: GPT-5.2/5.1/O3
│                      #   DeepSeek: V4 Pro
│                      #   Qwen: 3.6 Plus
│                      #   Google: Gemini 3/2.5
│                      #   回退链: FALLBACK_CHAINS
├── client.py          # LLMClient (同步 + 异步)
│                      #   call() / acall() / stream()
│                      #   _call_with_fallback() — 重试 + 回退
│                      #   _handle_error() — 错误分类
│                      #   已知bug: _atry_fallback 异步死循环
├── config.py          # LLMConfig (YAML → 配置加载)
│                      #   优先级: 代码 > 环境变量 > YAML > 默认
├── exceptions.py      # 15 种 LLM 异常类型
├── buffer.py          # Worker 缓冲区 (LLM 调用记录)
└── distributor.py     # 模型分发器 (任务类型 → 推荐模型)
```

**LLM 调用链路**:
```
AnalystAgent.analyze()
  → LLMClient.call(messages, model=DEEPSEEK_V4_PRO)
    → _get_model_id() → "deepseek/deepseek-v4-pro"
    → _call_with_fallback()
      ├── 重试循环 (max 3 次, 指数退避 1s→2s→4s)
      │   └── litellm.completion(timeout=120)
      ├── 重试耗尽 → _tried_models.add(model_id)
      └── _try_fallback()
          └── get_fallback_chain() → 下一个模型
              └── 递归 _call_with_fallback()
```

---

### 3.5 数据库层 + 基础服务

```
db/
├── connection.py      # MongoDB 连接管理
└── repository.py      # Repository 模式
                       #   TaskRepo, WorkerRepo, SPRepo,
                       #   POVRepo, DirectionRepo, FuzzerRepo

analyzer/              # 分析服务 RPC
├── server.py          # 长连接 Unix socket JSON-RPC 服务端
├── client.py          # 线程安全客户端
├── tasks.py           # Celery 任务 (build fuzzer, run introspector)
├── builder.py         # Fuzzer 构建
├── importer.py        # OSS-Fuzz 导入
└── protocol.py        # RPC 协议定义

analysis/              # 代码分析工具
├── function_extraction.py  # tree-sitter 函数提取
├── introspector_parser.py  # OSS-Fuzz Introspector 解析
├── diff_parser.py          # Git diff 解析
└── parsers/c_parser.py     # C 代码解析器

fuzzer/                # Fuzzer 管理
├── manager.py         # FuzzerManager (AFL++/libFuzzer)
├── instance.py        # Fuzzer 实例
├── monitor.py         # 崩溃监控
├── seed_agent.py      # Seed Agent (LLM 生成高质量种子)
├── seed_tools.py      # 种子工具
└── models.py          # Fuzzer 模型
```

---

## 四、新增固件模块 vs 原始软件模块 对照表

| 功能 | 软件 Fuzzing (原始) | 固件漏洞发现 (新增) |
|------|-------------------|-------------------|
| 源码/二进制提取 | tree-sitter + OSS-Fuzz | `static/extractor.py` (binwalk) |
| 反编译/反汇编 | 源码分析 (AST) | `static/objdump_analyzer.py` + `static/ghidra_analyzer.py` |
| 函数调用图 | `analysis/introspector_parser.py` | `static/callgraph.py` (objdump/Ghidra → CallGraph) |
| 攻击面识别 | `agents/direction_planning_agent.py` | `attack_surface/identifier.py` + `direction_planner.py` |
| SP 生成 | `agents/sp_generators.py` | `agents/firmware/sp_analysts.py` (3 专业 Agent) |
| SP 验证 | `agents/sp_verifier.py` | `agents/firmware/sp_verifier.py` + `cross_reviewer.py` |
| 动态验证 | Fuzzer (AFL++/libFuzzer) | `verifier/` (FirmAE → QEMU → Static) |
| 报告 | POV Report | `reporter/generator.py` (JSON + Markdown + ground truth) |
| 配置 | `core/config.py` | `firmware_profile.py` (YAML profile 机制) |

---

## 五、数据流全景

```
                          firmware.bin
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 1: Static Extraction                                      │
│                                                                  │
│  binwalk -e                                                     │
│    ↓                                                             │
│  squashfs-root/ → 遍历 ELF magic → BinaryInfo[]                 │
│    ↓                                                             │
│  ObjdumpAnalyzer / GhidraAnalyzer                               │
│    ↓                                                             │
│  FunctionInfo[] + CallGraph + StringRef[]                        │
│    ↓                                                             │
│  CAP 500 函数 + pseudo_code 截断 2000 字符                       │
│    ↓                                                             │
│  💾 phase1_result.json                                           │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 2: Attack Surface + Direction Planning                    │
│                                                                  │
│  AttackSurfaceIdentifier.identify(functions, callgraph, strings) │
│    → LLM 调用 1 次                                               │
│    → AttackSurfaceResult (6-14 攻击面)                           │
│    → 💾 phase2_attack_surfaces.json                              │
│                                                                  │
│  DirectionPlanner.plan(attack_surfaces, callgraph, functions)    │
│    → LLM 调用 1 次                                               │
│    → DirectionResult (3-8 方向, 每个方向 P0-P5)                  │
│    → 💾 phase2_directions.json                                   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 3: Multi-Agent Cross-Examination                          │
│                                                                  │
│  每个 Direction (串行):                                           │
│    ├── Analyst A (Memory Corruption)  → FirmwareSP[]             │
│    ├── Analyst B (Logic Flaw)         → FirmwareSP[]             │
│    └── Analyst C (Injection)          → FirmwareSP[]             │
│                                                                  │
│  交叉审查:                                                        │
│    ├── Reviewer A 审查 B+C 的 SPs  → CrossReviewVerdict[]        │
│    ├── Reviewer B 审查 C+A 的 SPs  → CrossReviewVerdict[]        │
│    └── Reviewer C 审查 A+B 的 SPs  → CrossReviewVerdict[]        │
│                                                                  │
│  SPVerifier.verify(all_sps, all_reviews)                         │
│    → 投票 + LLM 终审 + P0-P3 优先级                              │
│    → VerifiedSP[] (已去重)                                       │
│    → 💾 phase3_result.json                                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 4: Layered Dynamic Verification                           │
│                                                                  │
│  P0 SPs → PoCAgent.generate() → PoC[]                            │
│                                                                  │
│  对每个 PoC+SP:                                                   │
│    L1: FirmAE 全系统模拟 → ✅ crash ? → CrashInfo                 │
│    L2: QEMU user-mode  → ✅ crash ? → CrashInfo                   │
│    L3: Static Assessor → ⚠️ high confidence ? → reserved          │
│                                                                  │
│  💾 phase4_result.json                                           │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Report Generation                                               │
│                                                                  │
│  _build_final_report()                                           │
│    ├── 汇总 VerifiedSP → VulnerabilityEntry[]                    │
│    ├── 统计 Phase4Statistics                                     │
│    ├── Ground Truth Cross-Reference (如果 profile 有 known_cves) │
│    └── ReportGenerator                                           │
│        ├── to_json()  → 💾 final_report.json                     │
│        └── to_markdown() → 💾 final_report.md                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 六、关键设计模式

### 6.1 Checkpoint/Resume 机制

每个 Phase 完成后保存 JSON checkpoint。管线重启时自动跳过已完成的阶段:

```python
# firmware_pipeline.py
phase1_path = task_dir / "phase1_result.json"
if "phase1" in phases_to_run and not (resume and phase1_path.exists()):
    functions, callgraph = self._run_phase1(firmware_path, task_dir)
    # save checkpoint...
elif phase1_path.exists():
    functions = load_checkpoint(phase1_path)  # 直接加载
```

### 6.2 Analyzer Factory 模式

自动选择最佳分析器:

```python
# static/objdump_analyzer.py
class AnalyzerFactory:
    @staticmethod
    def create(ghidra_home=None, **kwargs):
        if ghidra_headless_exists:
            return GhidraAnalyzer(...)     # 优先
        return ObjdumpAnalyzer(...)        # 回退
```

### 6.3 LLM Fallback Chain

```python
# llms/models.py
FALLBACK_CHAINS = {
    DEEPSEEK_V4_PRO.id: [CLAUDE_SONNET_4_5, CLAUDE_HAIKU_4_5],
    # ...
}
# 每种模型都有预定义的 fallback 链
# 同步路径: 耗尽后 raise RuntimeError
# 异步路径: 耗尽后死循环 (已知 bug)
```

### 6.4 Agent 隔离 + Claim 调度

所有 Agent 共享 MongoDB 作为唯一通信媒介:
- 每个 Agent 有独立 `AgentContext` (MongoDB ObjectId)
- 使用 `find_one_and_update` 原子 claim 任务
- `finally` 块释放 claim 防止孤儿 SP

---

## 七、依赖关系图

```
                    ┌─────────────┐
                    │   main.py   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
    ┌────────────┐ ┌────────────┐ ┌──────────────┐
    │ firmware_  │ │ api_server │ │ mcp_server   │
    │ pipeline   │ └────────────┘ └──────────────┘
    └─────┬──────┘
          │
    ┌─────┼──────────┬───────────┬──────────┐
    ▼     ▼          ▼           ▼          ▼
  static  attack_   agents/    verifier   reporter
          surface   firmware
    │     │          │           │          │
    └─────┼──────────┼───────────┼──────────┘
          │          │           │
          └──────────┼───────────┘
                     │
                     ▼
              ┌──────────┐
              │   llms   │  ← LLMClient, 所有 Agent 共享
              └──────────┘
```

---

## 八、测试结构

```
tests/
├── test_models.py                # 核心数据模型
├── test_agents.py                # Agent 基类 + 隔离
├── test_sp_analysts.py           # SP 分析师 (原版)
├── test_sp_verifier.py           # SP 验证器 (原版)
├── test_pov_agent.py             # POV 生成 Agent
├── test_cross_reviewer.py        # 交叉审查 Agent
├── test_phase3_pipeline.py       # Phase 3 管线
├── test_firmware_pipeline.py     # 🆕 固件管线集成 (21 tests)
├── test_firmware_profile.py      # 🆕 Profile 机制 (75 tests)
├── test_llms_*.py                # LLM 客户端测试
├── test_worker_*.py              # Worker 生命周期
├── test_db_*.py                  # 数据库层
└── conftest.py                   # mock_db, repos fixtures
```

---

## 九、快速定位指南

| 你想... | 去看这个文件 |
|---------|------------|
| 修改固件管线 Phase 1 | `static/objdump_analyzer.py` |
| 添加新架构支持 | `static/objdump_analyzer.py:CROSS_PREFIX_MAP` |
| 修改攻击面识别 prompt | `attack_surface/identifier.py` |
| 修改方向规划 prompt | `agents/firmware/prompts/__init__.py` |
| 添加新 Analyst 类型 | `agents/firmware/sp_analysts.py` |
| 修改 SP 投票逻辑 | `agents/firmware/sp_verifier.py` |
| 添加新验证引擎 | `verifier/` (新建 runner) |
| 修改 LLM 回退链 | `llms/models.py:FALLBACK_CHAINS` |
| 修改 LLM 配置 | `fuzzingbrain/llm_config.local.yaml` |
| 添加新的固件 profile | `profiles/` 下新建 YAML |
| 理解 FirmwareProfile 机制 | `firmware_profile.py` |
| 修改报告格式 | `reporter/generator.py` |
| CLI 参数 | `main.py` (argparse 部分) |
| 数据库操作 | `db/repository.py` |
