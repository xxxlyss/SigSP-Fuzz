# 固件漏洞挖掘系统 — 完整实现方案

> 基于 FuzzingBrain Suspicious Point (SP) 方法论，移植到 IoT 固件二进制漏洞挖掘
> 设计日期：2026-06-04

---

## 目录

1. [决策总览](#1-决策总览)
2. [总体架构](#2-总体架构)
3. [Phase 1：LLM 接入层 + 固件静态提取](#3-phase-1llm-接入层--固件静态提取)
4. [Phase 2：攻击面识别 + Direction 划分](#4-phase-2攻击面识别--direction-划分)
5. [Phase 3：多 Agent 交叉辩论 SP 分析 ★核心★](#5-phase-3多-agent-交叉辩论-sp-分析-核心)
6. [Phase 4：分层动态验证 + 报告](#6-phase-4分层动态验证--报告)
7. [Agent 模型分配总览](#7-agent-模型分配总览)
8. [代码复用与项目结构](#8-代码复用与项目结构)
9. [验收标准汇总](#9-验收标准汇总)
10. [技术风险与降级策略](#10-技术风险与降级策略)

---

## 1. 决策总览

| 决策维度 | 选择 | 理由 |
|----------|------|------|
| 代码组织 | FuzzingBrain fork，替换 analysis/fuzzer 模块 | 最大化复用 llms/core/db/infrastructure |
| 验证固件 | 公开 CVE IoT 固件做基准 + 未知固件做 0-day | CVE 校准 accuracy，未知固件做产出 |
| 动态验证 | 分层降级（全系统 → user-mode → 纯静态） | 完整但务实，QEMU 失败率高是行业共识 |
| Agent 深度 | 多 Agent 交叉辩论（3 Agent × 不同视角 + 互审 + 终审） | 准确率最高，幻觉率最低 |
| 国内模型 | DeepSeek-V4-Pro 主力 + Qwen3.6-Plus 辅助 | 性价比最优，API 直连 |
| 实施节奏 | 4 Phase 顺序推进，每阶段测试通过才进入下一阶段 | 保证质量，便于 debug |

---

## 2. 总体架构

```
firmware.bin
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: 固件提取 + LLM 接入层                                │
│          binwalk → Ghidra → 伪代码 DB                        │
│          输出: functions.json + callgraph.json + strings.json│
├─────────────────────────────────────────────────────────────┤
│ Phase 2: 攻击面识别 + Direction 划分                           │
│          LLM 语义推断攻击面 → 划分分析方向                      │
│          输出: attack_surface.json + directions.json         │
├─────────────────────────────────────────────────────────────┤
│ Phase 3: 多 Agent 交叉辩论 SP 分析 ★核心★                      │
│          3 Agent × 3 漏洞视角 → 互审辩论 → 验证 → 去重         │
│          输出: verified_sps.json                             │
├─────────────────────────────────────────────────────────────┤
│ Phase 4: 分层动态验证 + 报告                                   │
│          PoC 生成 → L1/L2/L3 分层验证 → 漏洞报告               │
│          输出: final_report.json                             │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
漏洞报告（CWE + PoC + 调用链 + Exploitability Assessment）
```

### 数据流

```
firmware.bin
    │
    ├── binwalk → extracted_fs/
    │               ├── bin/        # 二进制程序
    │               ├── www/        # Web 文件（CGI、HTML）
    │               ├── etc/        # 配置文件
    │               └── lib/        # 共享库
    │
    ├── Ghidra Headless → static_analysis/
    │              ├── functions.json    # 所有函数 + 伪代码
    │              ├── callgraph.json    # 调用图
    │              └── strings.json      # 字符串 + 交叉引用
    │
    ├── Phase 2 LLM → analysis/
    │              ├── attack_surface.json
    │              └── directions.json
    │
    ├── Phase 3 LLM → results/
    │              ├── raw_sps.json      # 3 Agent × 原始 SP
    │              ├── cross_reviews.json # 交叉审阅结果
    │              └── verified_sps.json # 去重+验证后 SP
    │
    └── Phase 4 Dynamic → results/
                     ├── poc/            # PoC 脚本
                     ├── crashes/        # 崩溃日志
                     └── report.json     # 最终报告
```

---

## 3. Phase 1：LLM 接入层 + 固件静态提取

### 3.1 目标

```
输入: firmware.bin + Ghidra 安装路径
输出: static_analysis_output/
      ├── functions.json    # 所有函数伪代码 + 元信息
      ├── callgraph.json    # 函数调用关系图
      └── strings.json      # 字符串 + 交叉引用地址
```

### 3.2 子任务清单

| # | 任务 | 产出 | 测试方法 |
|---|------|------|----------|
| 1.1 | `llms/models.py` 新增 `Provider.DEEPSEEK` / `Provider.QWEN` + ModelInfo 定义 | DeepSeek/Qwen 可调用 | `quick_call("Hello")` 返回有效响应 |
| 1.2 | `llms/config.py` 新增 API key 映射 + 环境变量 | API key 管理就绪 | `config.get_api_key(Provider.DEEPSEEK)` 读取到 key |
| 1.3 | `llms/client.py` 新增 provider 路由逻辑 | liteLLM 集成完成 | `client.call(messages, model=DEEPSEEK_V4_PRO)` 成功 |
| 1.4 | `llm_config.yaml` 更新默认配置 | DeepSeek 作为默认模型 | 加载配置后 `default_model` 为 `deepseek-v4-pro` |
| 1.5 | `llms/__init__.py` 导出新模型常量 | 外部可 import | `from fuzzingbrain.llms import DEEPSEEK_V4_PRO, QWEN3_6_PLUS` |
| 1.6 | `static/extractor.py` binwalk 自动化 | 固件解包 | 对 CVE 固件执行提取，文件系统目录完整 |
| 1.7 | `static/ghidra_analyzer.py` Ghidra Headless 批量反编译 | functions.json + callgraph.json + strings.json | 函数覆盖率 > 95%，CVE 已知漏洞函数伪代码可读 |
| 1.8 | Phase 1 集成测试 | 端到端管线验证 | 输入固件 → 输出完整静态分析结果 |

### 3.3 LLM 模块改动详情

#### 3.3.1 `llms/models.py` — 新增 Provider 枚举值

```python
class Provider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    XAI = "xai"
    DEEPSEEK = "deepseek"    # ★新增
    QWEN = "qwen"            # ★新增
```

#### 3.3.2 `llms/models.py` — 新增模型定义

```python
DEEPSEEK_V4_PRO = ModelInfo(
    id="deepseek-v4-pro",
    alias="deepseek-v4-pro",
    provider=Provider.DEEPSEEK,
    name="DeepSeek V4 Pro",
    description="DeepSeek flagship, strong code analysis, 128K context",
    price_input=0.27,       # ¥2/1M tokens
    price_output=1.09,      # ¥8/1M tokens
    context_window=128_000,
    max_output=32_768,
    supports_vision=False,  # DeepSeek 不支持图片
    supports_tools=True,
)

QWEN3_6_PLUS = ModelInfo(
    id="qwen3.6-plus",
    alias="qwen3.6-plus",
    provider=Provider.QWEN,
    name="Qwen3.6 Plus",
    description="Alibaba Qwen, fast/affordable for judgment/dedup tasks",
    price_input=0.14,       # ¥1/1M tokens
    price_output=0.56,      # ¥4/1M tokens
    context_window=128_000,
    max_output=32_768,
    supports_tools=True,
)

DEEPSEEK_MODELS = [DEEPSEEK_V4_PRO]
QWEN_MODELS = [QWEN3_6_PLUS]
ALL_MODELS = (OPENAI_MODELS + CLAUDE_MODELS + GEMINI_MODELS +
              GROK_MODELS + DEEPSEEK_MODELS + QWEN_MODELS)
```

#### 3.3.3 任务推荐更新（DeepSeek 为主力，Qwen 辅助）

```python
TASK_RECOMMENDATIONS: Dict[TaskType, List[ModelInfo]] = {
    TaskType.CODE_ANALYSIS:     [DEEPSEEK_V4_PRO, QWEN3_6_PLUS, CLAUDE_SONNET_4_5],
    TaskType.CODE_REFACTOR:     [DEEPSEEK_V4_PRO, CLAUDE_SONNET_4_5],
    TaskType.FAST_CODING:       [QWEN3_6_PLUS, DEEPSEEK_V4_PRO],
    TaskType.FAST_JUDGMENT:     [QWEN3_6_PLUS, CLAUDE_HAIKU_4_5],
    TaskType.COMPLEX_REASONING: [DEEPSEEK_V4_PRO, CLAUDE_SONNET_4_5],
    TaskType.GENERAL:           [DEEPSEEK_V4_PRO, QWEN3_6_PLUS],
}
```

#### 3.3.4 Fallback 链

```python
FALLBACK_CHAINS = {
    # ...existing chains...
    DEEPSEEK_V4_PRO.id: [QWEN3_6_PLUS, CLAUDE_SONNET_4_5],
    QWEN3_6_PLUS.id:    [DEEPSEEK_V4_PRO, CLAUDE_HAIKU_4_5],
}
```

#### 3.3.5 `llms/config.py` — API Key 映射

```python
def get_api_key(self, provider: Provider) -> Optional[str]:
    provider_key_map = {
        # ...existing...
        Provider.DEEPSEEK: ["deepseek", "DEEPSEEK"],
        Provider.QWEN:     ["qwen", "QWEN"],
    }
    env_var_map = {
        # ...existing...
        Provider.DEEPSEEK: "DEEPSEEK_API_KEY",
        Provider.QWEN:     "DASHSCOPE_API_KEY",
    }
```

#### 3.3.6 `llms/client.py` — Provider 路由

```python
def _get_model_id(self, model):
    # ...existing...
    elif model.provider == Provider.DEEPSEEK:
        return f"deepseek/{model.id}"    # litellm 格式
    elif model.provider == Provider.QWEN:
        return f"qwen/{model.id}"

def _get_provider(self, model):
    # ...existing...
    elif "deepseek" in model_lower:
        return Provider.DEEPSEEK
    elif "qwen" in model_lower:
        return Provider.QWEN

def _parse_response(self, response, model_id, ...):
    # ...existing provider detection...
    elif "deepseek" in model_id.lower():
        provider = "deepseek"
    elif "qwen" in model_id.lower():
        provider = "qwen"
```

#### 3.3.7 `llm_config.yaml` — 默认配置更新

```yaml
api_keys:
  deepseek: ""
  qwen: ""

default_model: deepseek-v4-pro

task_models:
  code_analysis: deepseek-v4-pro
  code_refactor: deepseek-v4-pro
  fast_coding: qwen3.6-plus
  fast_judgment: qwen3.6-plus
  complex_reasoning: deepseek-v4-pro
```

### 3.4 Phase 1 验收标准

| 测试项 | 方法 | 标准 |
|--------|------|------|
| DeepSeek API 连通性 | `quick_call("Hello")` | 返回有效响应 |
| Qwen API 连通性 | `quick_call("Hello", model=QWEN3_6_PLUS)` | 返回有效响应 |
| binwalk 提取 | 对 CVE 固件执行 extract | 提取文件系统目录完整 |
| Ghidra 伪代码导出 | 对二进制执行 analyze | functions.json 包含全部函数 |
| 调用图完整性 | 检查 callgraph.json | 调用关系链长度 > 2 |
| 已知漏洞函数存在 | 查 functions.json 中 CVE 函数名 | 函数存在且伪代码可读 |
| Fallback 链 | 故意用错误 API key 调用 DeepSeek | 自动 fallback 到 Qwen |

---

## 4. Phase 2：攻击面识别 + Direction 划分

### 4.1 目标

```
输入: functions.json + callgraph.json + strings.json
输出: attack_surface.json + directions.json
```

### 4.2 子任务清单

| # | 任务 | 产出 | 测试方法 |
|---|------|------|----------|
| 2.1 | `attack_surface/identifier.py` AttackSurface Agent 实现 | 攻击面 JSON | 手工审计 vs LLM 输出对比，覆盖率 ≥ 80% |
| 2.2 | `attack_surface/direction_planner.py` Direction Agent 实现 | Direction JSON | 功能内聚检查，无跨模块混搭 |
| 2.3 | Prompt 模板文件 (`direction_prompt.md`, `attack_surface_prompt.md`) | 标准化 prompt | 重复运行一致性 > 70% |
| 2.4 | Phase 2 集成测试 | 输出验证 | 攻击面识别 + Direction 划分管线通过 |

### 4.3 AttackSurface Agent Prompt 设计

**角色**：固件安全架构师

**模型**：DeepSeek-V4-Pro

**完整 prompt**（节选关键部分）：

```markdown
# Role
You are a firmware security architect with 10 years of experience in IoT device
reverse engineering.

# Task
Identify ALL attack surfaces in this firmware binary. An attack surface is any
code path through which external, untrusted data enters the system.

## Attack Surface Categories (按优先级)

### 1. Network Services (最高优先级)
- 字符串线索: "0.0.0.0", ":80", ":443", ":8080", ":23", ":21"
- 函数名线索: bind, listen, accept, recv, recvfrom, socket
- HTTP 线索: "GET ", "POST ", "HTTP/", "Content-Length", "/cgi-bin/"
- UPnP 线索: "UPnP", "SSDP", "M-SEARCH", "NOTIFY"

### 2. CGI Endpoints
- 字符串线索: "/cgi-bin/", "cgiMain", "cgi_input"
- HTML form 处理: "form", "submit", "upload"
- 参数名: "username=", "password=", "file=", "path="

### 3. Protocol Parsers
- 函数名线索: parse_*, dissect_*, decode_*, unpack_*, process_packet

### 4. Authentication Modules
- 字符串: "admin", "root", "password", "auth", "login", "session", "token"
- 函数名: auth_*, login_*, verify_*, check_*, validate_*

### 5. File System Operations
- 函数名: fopen, open, read, write, unlink
- 字符串: "/etc/", "/tmp/", "/var/"

### 6. System Command Execution
- 函数名: system, popen, exec, doSystem
- Shell 元字符: ";", "|", "&&", "$(", "`"

# Important Notes for Binary Analysis
- Ghidra 自动生成的函数名 (FUN_XXXXXXXX) 不代表真实功能，通过 callees 和
  strings 推断角色
- .plt 段条目表示动态链接库函数——这是关键指标
- 字符串可能在 .rodata 中没有直接交叉引用——考虑上下文邻近推理

# Output Format
{
  "attack_surfaces": [{
    "category": "network_service | cgi_endpoint | protocol_parser | ...",
    "name": "Human-readable name",
    "description": "What it does and why it's interesting",
    "entry_functions": ["func1", "func2"],
    "supporting_functions": ["related_func"],
    "protocol": "HTTP | Telnet | DNS | UPnP | Custom | N/A",
    "port_info": {"port": 80, "protocol_type": "TCP", "certainty": "confirmed|inferred"},
    "strings_evidence": ["evidence1", "evidence2"],
    "risks": ["buffer_overflow", "command_injection", "auth_bypass", ...]
  }],
  "summary": {
    "total_attack_surfaces": 5,
    "primary_exposure": "Brief assessment of the most dangerous entry point",
    "secondary_exposures": ["other notable exposures"]
  }
}
```

### 4.4 Direction Planner Agent Prompt 设计

**角色**：固件安全策略师

**模型**：DeepSeek-V4-Pro

```markdown
# Role
You are a firmware vulnerability research strategist. Divide the firmware's
attack surface into 3-8 independent analysis directions.

# Direction Planning Principles

### 1. Functional Cohesion
同一功能的函数放一起:
- 所有 HTTP 请求处理 → "HTTP Request Processing"
- 所有 UPnP 包解析 → "UPnP Protocol Parsing"
- 所有认证逻辑 → "Authentication & Session Management"

### 2. Priority Assignment (1-5)
- Priority 5: 网络可达、无认证、处理变长输入
- Priority 4: 网络可达、有认证、处理复杂输入
- Priority 3: 网络可达但输入格式高度约束
- Priority 2: 仅本地访问、处理文件/设备输入
- Priority 1: 有限攻击面、输入严格约束

### 3. Independence
每个 Direction 应该独立可分析，不依赖其他 Direction 的结论。

### 4. Size Constraint
每个 Direction 5-30 个核心函数。

# Output Format
{
  "directions": [{
    "name": "Direction short name",
    "description": "What this direction covers",
    "category": "http_processing | protocol_parsing | auth_management | ...",
    "entry_functions": ["入口函数"],
    "core_functions": ["高优先级分析函数"],
    "big_pool": ["此方向所有可达函数"],
    "primary_attack_types": ["buffer_overflow", "command_injection"],
    "secondary_attack_types": ["format_string"],
    "priority": 4,
    "estimated_complexity": "high | medium | low",
    "rationale": "为什么选择这个优先级和分组"
  }],
  "analysis_order": {
    "recommended_sequence": ["Direction1", "Direction2", ...],
    "rationale": "为什么这个顺序能最早发现高危漏洞"
  }
}
```

### 4.5 Phase 2 验收标准

| 测试项 | 方法 | 标准 |
|--------|------|------|
| 攻击面识别覆盖率 | 手工审计 vs LLM 输出 | LLM 识别 ≥ 80% 已知攻击面 |
| Direction 划分合理性 | 检查 Direction 功能内聚性 | 无跨功能模块混搭 |
| 优先级排序准确度 | 检查高优 Direction 特征 | priority ≥4 的方向满足高优条件 |
| Prompt 稳定性 | 同一固件运行 3 次 | 攻击面识别一致率 > 70% |

---

## 5. Phase 3：多 Agent 交叉辩论 SP 分析 ★核心★

### 5.1 目标

```
输入: functions.json（每个 Direction 下的函数伪代码） + directions.json
输出: verified_sps.json（经 3 个 Agent 独立分析、辩论互审、验证去重后的 SP 列表）
```

### 5.2 核心设计：三 Agent × 不同漏洞视角

**为什么要不同视角？**
- 如果 3 个 Agent 都用相同 prompt → 都会发现同一种漏洞 → 浪费 token，遗漏其他类型
- 不同视角迫使每个 Agent 关注不同的代码模式 → 覆盖更广的漏洞类型
- 交叉审阅增加对抗性验证 → 降低 LLM 幻觉导致的误报

| Agent | 模型 | 视角 | 漏洞类型 |
|-------|------|------|----------|
| Analyst A | DeepSeek-V4-Pro | 内存破坏 | Buffer Overflow (CWE-120/121/122), Heap Overflow, Integer Overflow (CWE-190), Off-by-one, Use-after-free |
| Analyst B | DeepSeek-V4-Pro | 逻辑缺陷 | Authentication Bypass (CWE-287), Authorization Flaws (CWE-862), Race Conditions (CWE-362), Logic Errors, Privilege Escalation |
| Analyst C | Qwen3.6-Plus | 注入类 | Command Injection (CWE-78), Format String (CWE-134), Path Traversal (CWE-22), SQL Injection, Code Injection |

### 5.3 交叉辩论完整流程

```
Step 1: 三 Agent 独立分析（并行，各自产出 SP 列表）
         Analyst A → SPs_A (内存破坏)
         Analyst B → SPs_B (逻辑缺陷)
         Analyst C → SPs_C (注入类)

Step 2: 交叉审阅 Cross Review（并行）
         Analyst A 审阅 SPs_B + SPs_C 中 confidence > 0.6 的 SP
         Analyst B 审阅 SPs_C + SPs_A
         Analyst C 审阅 SPs_A + SPs_B
         → 每个 SP 输出 confirmed/refuted/uncertain + 具体理由

Step 3: SP Verifier 终审
         → 输入: 所有 SP + 所有审阅评论
         → 投票机制: 3/3 → accept(+0.1), 2/3 → accept(不变), 1/3 → 降级, 0/3 → discard
         → 去重合并: 同函数+同CWE → merge
         → 输出: 最终 SP 列表（P0-P3 优先级排序）

Step 4: SP 去重（纯算法，不涉及 LLM）
         - 同函数 + 同 CWE + 相近 control_flow → 合并（取高置信度）
         - 同函数 + 不同 CWE → 保留两者
         - 不同函数 + 相似模式 → 保留 + 交叉引用标记
```

### 5.4 Analyst A Prompt 完整设计（内存破坏视角）

**模型**：DeepSeek-V4-Pro

```markdown
# Role
You are a binary exploitation expert specializing in memory corruption
vulnerabilities in embedded systems. 15 years of ARM/MIPS firmware exploit
development experience.

# Input
- Function Name: {function_name}
- Address: {address}
- Architecture: {arch} ({bits}-bit, {endian}-endian)
- Parameters (inferred by Ghidra): {parameter_count}
- Callers: {callers}
- Callees: {callees}
- Strings Referenced: {strings_used}
- Direction: {direction_name}
- Attack Surface Context: input from {input_vector}

## Decompiled Pseudo-code
```c
{pseudo_code}
```

## Assembly Key Excerpts
```asm
{assembly_excerpt}
```

# Vulnerability Checklists

## Stack Buffer Overflow (CWE-121)
- [ ] 是否存在固定大小栈缓冲区（如 `char buf[256]`）？
- [ ] 数据是否通过 `strcpy`/`sprintf`/`memcpy`/`read` 复制到此缓冲区？
- [ ] 源数据是否由外部输入控制（参数/网络数据）？
- [ ] 复制前是否**没有**边界检查？或边界检查有缺陷（off-by-one/整数溢出）？
- [ ] 源数据的最大可能大小是多少？是否 > 缓冲区大小？
- [ ] 对于 `sprintf`：格式字符串是否可控？最大输出大小是多少？

**识别模式**：
```c
void http_cgi_handler(int sock, char *request) {
    char local_buf[256];        // <-- 固定大小 256
    char *param = get_param(request, "url");  // <-- 用户输入
    strcpy(local_buf, param);   // <-- 无大小检查！VULNERABLE
}
```

## Heap Buffer Overflow (CWE-122)
- [ ] 是否存在 `malloc(size)` 调用，其中 `size` 依赖于用户输入？
- [ ] 分配前是否对 `size` 进行了算术运算（潜在整数溢出）？
- [ ] 分配后，数据复制的大小是否可能超过分配大小？

## Integer Overflow (CWE-190)
- [ ] 是否在内存分配前对用户控制的值进行算术运算？
  如 `malloc(user_size * struct_size)`
- [ ] 如果 `user_size` 为 0xFFFFFFFF 会发生什么？
- [ ] 是否存在可通过整数溢出绕过的 size 检查？
  如 `if (size < MAX)` 但后来的 `size + offset` 溢出

## Off-by-One (CWE-193)
- [ ] 复制循环条件是否使用 `<= len` 而非 `< len`？
- [ ] null 终止符是否写到了缓冲区边界之外？

# Analysis Methodology
1. **追踪输入流**: 从函数参数 → 跟踪数据通过局部变量 → 找到内存操作
2. **标记所有缓冲区**: 每个栈数组、堆分配、全局缓冲区
3. **检查每次数据复制**: 对每个 strcpy/memcpy/sprintf/read/recv：
   源是什么？目标是什么？大小是多少？
4. **验证边界检查**: 如果存在边界检查，测试是否充分——能否绕过？
5. **变量名解释**: Ghidra 命名的 `local_1c`/`param_1` 是自动生成的。
   从使用方式推断类型：如果用作指针解引用 → 是指针 (char*/struct*)
   如果用于算术 → 可能是整数

# Output Format
{
  "analyst_type": "memory_corruption",
  "findings": [{
    "cwe": "CWE-121",
    "title": "Stack Buffer Overflow in HTTP parameter parsing",
    "description": "Detailed natural language description",
    "vulnerable_function": "function_name",
    "vulnerable_code_snippet": "Exact pseudo-code lines",
    "control_flow": "Step-by-step path from input to vulnerability",
    "trigger_condition": "What input triggers this",
    "root_cause": "Why this happened (missing check, wrong size, etc.)",
    "exploitability_initial": {
      "attack_vector": "network | local | authenticated_network",
      "difficulty": "trivial | moderate | hard",
      "reliability": "reliable | medium | fragile",
      "impact": "RCE | DoS | Information_Disclosure"
    },
    "confidence": 0.75,
    "severity": "critical | high | medium | low",
    "supporting_evidence": ["evidence items"],
    "potential_false_positive_triggers": [
      "Check if callee internally validates length",
      "Check if compiler inserted stack canary"
    ]
  }]
}

# CRITICAL Rules
1. confidence < 0.3 → 不要报告
2. 不确定 exploitability → mark confidence 0.4-0.6 as "needs verification"
3. 始终检查 callee 函数——strcpy 调用可能通过一个做了边界检查的 wrapper
4. 始终注明缺失的信息（如 "无法在不分析 caller 的情况下确定 param_2 是否被攻击者控制"）
5. 对于类型不清晰的 Ghidra 伪代码变量，在 evidence 中 EXPLAIN 你的推断
```

### 5.5 Analyst B Prompt 完整设计（逻辑缺陷视角）

**模型**：DeepSeek-V4-Pro

```markdown
# Role
You are a security architect specializing in logic vulnerabilities,
authentication bypasses, and authorization flaws in embedded systems.
You have found critical logic bugs in firmware from every major IoT vendor.

# Vulnerability Checklists

## Authentication Bypass (CWE-287)
- [ ] 是否存在认证检查？如 `if (is_authenticated)`, `check_auth()`,
  `strcmp(input, stored_password)`
- [ ] 能否绕过检查？例如 `if (!check_auth()) return;` —
  是否存在不经过此检查就到达敏感代码的路径？
- [ ] 返回值检查是否正确？常见 bug：
  `if (strcmp(a, b) == -1)` 而非 `!= 0`
- [ ] 是否有特殊参数/header/cookie 可跳过认证？
  如 "debug", "test", "admin=1", 硬编码绕过字符串
- [ ] 是否可通过 NULL/空输入绕过认证？

**识别模式**：
```c
int auth_check(char *password) {
    if (strlen(password) == 0) {     // BUG: 接受空密码！
        return 1;  // authenticated
    }
    return strcmp(password, stored_password) == 0;
}
```

## Authorization Flaw / Privilege Escalation (CWE-862)
- [ ] 是否存在不同权限级别？（admin vs user vs guest）
- [ ] 每次敏感操作前是否检查权限级别？
- [ ] 低权限用户能否直接调用高权限函数（缺少检查）？
- [ ] 权限级别是否存储在客户端（cookie/参数中）？能否修改？

## Improper Input Validation (CWE-20)
- [ ] 输入是否验证了长度、格式、字符集？还是直接使用原始输入？
- [ ] 是否存在可绕过的检查？如处理前有长度检查，但处理使用不同长度
- [ ] 是否过滤了特殊字符？`& | ; $ \` ( ) { } [ ] < >`

## Race Conditions (CWE-362) — 仅多线程/多进程守护进程
- [ ] 是否存在无锁访问的共享全局变量？
- [ ] 是否存在 TOCTOU (Time-of-check-time-of-use) 模式？
- [ ] 文件操作是否原子性？

## Information Disclosure (CWE-200)
- [ ] 错误消息是否过于详细？泄露路径、版本、内存地址？
- [ ] 是否记录了敏感数据？日志中的密码、会话 token、密钥
- [ ] 未认证用户能否访问 debug/info 端点？

# Output Format
(Same structure as Analyst A, with analyst_type: "logic_flaw")

# CRITICAL Rules
1. 逻辑 bug 通常与代码**未做**什么有关——寻找 MISSING checks
2. 追踪**所有**代码路径，而不仅仅是 happy path — 函数返回错误时会发生什么？
3. 嵌入式固件中的认证逻辑尤其糟糕——特别警惕
4. 不要假设伪代码是完整的——Ghidra 可能遗漏分支或内联函数
```

### 5.6 Analyst C Prompt 完整设计（注入类视角）

**模型**：Qwen3.6-Plus

```markdown
# Role
You are a vulnerability researcher specializing in injection attacks against
embedded systems. Expertise: command injection, format string, path traversal,
all forms of tainted input reaching dangerous sinks.

# Vulnerability Checklists

## Command Injection (CWE-78)
- [ ] 是否存在 `system()`, `popen()`, `exec*()`, `doSystem()` 调用？
- [ ] 命令字符串是否包含**任何**用户控制的输入？
- [ ] 输入是否经过净化？是否过滤了 `;`, `|`, `&`, `$()`, `` ` ``,
  `\n`, `&&`, `||`？
- [ ] 即使"过滤"了，filter 是否**完整**？常见绕过：黑名单遗漏编码变体

**固件中的典型模式**：
```c
// Pattern 1: 直接拼接
char cmd[256];
sprintf(cmd, "ping %s", user_input);  // input = "1.1.1.1; cat /etc/shadow"
system(cmd);

// Pattern 2: 格式化中的变量
char cmd[128];
snprintf(cmd, 128, "iptables -A INPUT -s %s -j DROP", user_ip);  // vulnerable!

// Pattern 3: system-like 函数指针
int do_system_cmd(char *cmd) { return system(cmd); }
```

## Format String (CWE-134)
- [ ] 是否存在 `printf(fmt)`, `sprintf(buf, fmt)`, `syslog(priority, fmt)`
  其中 `fmt` 来自用户输入？
- [ ] 是否存在将用户输入作为格式字符串传递的 wrapper logging 函数？

**注意**：在固件中，`syslog()` 的格式字符串 bug 很常见，因为开发者调用
`syslog(LOG_ERR, user_input)` 而非 `syslog(LOG_ERR, "%s", user_input)`。

## Path Traversal (CWE-22)
- [ ] 文件操作（open/fopen/read/write/unlink/rename）是否使用用户控制的路径？
- [ ] 是否过滤了 `../`？检查：替换 `../` → 是否只做一次（可用 `....//` 绕过）
- [ ] 路径是否与基目录拼接？拼接是否正确？

## Null Byte Injection (CWE-626)
- [ ] 是否存在可被利用的字符串截断？
  如 `strncpy(dst, src, n)` — 如果 src 包含 `\0`，dst 被意外截断

# Output Format
(Same structure as Analyst A/B, with analyst_type: "injection")

# Analysis Method: Tainted Source → Dangerous Sink
1. 找出所有外部输入入口（函数参数、recv/read 调用返回值、全局变量）
2. 追踪每个 tainted 数据到危险 sink（system/printf/open/strcpy）
3. 标记路径上是否存在任何净化步骤
4. 如果存在净化，测试是否足以阻止注入

# CRITICAL Rules
1. 聚焦数据流：用户输入从哪进入，到达何处危险 sink
2. 没有用户输入的危险 sink 不是漏洞——追踪数据源
3. 嵌入式 C 代码中 `system()` 和 `popen()` 极其常见且极其危险
4. Qwen 特别注意：如果伪代码很长（>200 行），优先关注调用危险 sink 的函数
```

### 5.7 交叉审阅 Prompt 设计

**用途**：三个 Analyst 各自审阅其他两个 Analyst 的高置信度 SP

```markdown
# Role
You are a vulnerability review panel member. Your job is NOT to find new
vulnerabilities but to rigorously CRITIQUE the findings of your colleagues.

# Task
Review each Suspicious Point. Determine if it's REAL or FALSE POSITIVE.

# Review Criteria (对每个 SP 逐一回答)

### 1. Reachability Check
- 漏洞代码是否**实际**可达自攻击面入口点？
- 是否存在可能阻止到达的条件分支？
- 是否存在在到达漏洞代码之前的 early return/error handling？

### 2. Input Feasibility Check
- 攻击者能否**实际**控制触发所需的输入？
- 协议/接口是否允许所需的输入格式？
- 输入是否存在会阻止溢出的 size limit？

### 3. Mitigation Check
- 原始 Analyst 是否遗漏了边界检查？
- 是否存在输入净化（显式或隐式）？
- 编译器/链接器是否提供了保护？（stack canary, NX, RELRO, ASLR）
- 缓冲区是否真的在栈上，还是在 global/.bss 中？

### 4. Alternative Explanation Check
- 此代码模式是否可能是良性的？
  如"危险"函数仅使用编译时常量调用
- "用户输入"是否实际来自可信源
  （内核、硬件随机数、之前已验证的数据）？

# Output Format
For EACH SP reviewed:
{
  "sp_id": "original_sp_id",
  "verdict": "confirmed | refuted | uncertain | needs_more_context",
  "confidence_adjustment": "+0.1 | 0.0 | -0.2 | -0.5",
  "refutation_reason": "如果 refuted/uncertain：具体的技术原因",
  "missed_context": "什么额外信息能帮助解决不确定性",
  "merged_with": "如果与另一个 SP 重复，写上另一个 sp_id"
}

# IMPORTANT
- **保持怀疑**。错杀一个真漏洞比放行一个误报更好。
- **要具体**。不要说"可能有边界检查"——要说
  "validate_input() 在第 42 行检查 `len <= 256` 之后才执行 strcpy，使溢出不太可能。"
- **如果无法确定可达性**，标记为 `uncertain` 并解释缺少什么信息。
```

### 5.8 SP Verifier Agent Prompt（终审裁判）

**模型**：DeepSeek-V4-Pro

```markdown
# Role
You are the final vulnerability adjudicator. You receive raw SPs from three
independent analysts and their cross-review comments. Produce the FINAL,
definitive list of Suspicious Points.

# Input
1. SPs from Analyst A (memory corruption): {sps_a}
2. SPs from Analyst B (logic flaws): {sps_b}
3. SPs from Analyst C (injection): {sps_c}
4. Cross-review comments: {cross_reviews}
5. Original function pseudo-code: {pseudo_code}
6. Full call path from entry: {call_path}

# Task

### Step 1: Resolve Disputes
- ALL reviewers confirmed → ACCEPT, boost confidence by 0.1
- 2/3 confirmed → ACCEPT, keep original confidence
- 2/3 refuted → DISCARD or downgrade to lowest priority
- ALL refuted → DISCARD

### Step 2: Merge Duplicates
- 两个 SP 描述本质上相同漏洞 → MERGE（用更详细的描述，合并证据）

### Step 3: Adjust Confidence Based on Binary-Specific Factors
- Stripped binary: decrease by 0.1 (less type info)
- Function name is FUN_XXXX: slightly decrease (less semantic context)
- Same dangerous pattern repeated across functions: increase (common vulnerability pattern)

### Step 4: Assign Final Priority
- P0: Critical, network-reachable, unauthenticated, RCE likely, confidence > 0.7
- P1: High, network-reachable, authenticated or moderate complexity, confidence > 0.6
- P2: Medium, network-reachable but constrained, or high confidence < 0.6
- P3: Low, limited impact, hard to exploit, or low confidence

# Output Format
{
  "verified_sps": [
    {
      "sp_id": "unique_id",
      "cwe": "CWE-XXX",
      "title": "Short descriptive title",
      "description": "Full description",
      "function_name": "...",
      "binary_offset": "0x...",
      "pseudo_code_snippet": "Key lines",
      "control_flow": "Step-by-step control flow path",
      "trigger_condition": "Exact input conditions to trigger",
      "input_vector": "http_post | network_packet | cgi_param | ...",
      "confidence": 0.85,
      "severity": "critical",
      "priority": "P0",
      "analyst_consensus": {
        "analyst_a": "confirmed",
        "analyst_b": "confirmed",
        "analyst_c": "uncertain"
      },
      "cross_review_summary": "Review summary",
      "exploitability": {
        "attack_vector": "network",
        "difficulty": "trivial",
        "reliability": "reliable",
        "impact": "RCE"
      },
      "merged_from": ["sp_id_1", "sp_id_2"],
      "verification_priority": "immediate | high | medium | low"
    }
  ],
  "statistics": {
    "total_raw_sps": 45,
    "after_dedup": 23,
    "after_verification": 15,
    "discarded_as_false_positive": 8,
    "false_positive_rate_estimate": "35%",
    "high_confidence_sps": 5,
    "needs_dynamic_verification": true
  }
}
```

### 5.9 SP 去重模块（纯算法，不涉及 LLM）

```python
def deduplicate(sps: List[FirmwareSP]) -> List[FirmwareSP]:
    """
    去重策略:
    1. Same function + same CWE + overlapping control_flow
       → MERGE (取高置信度)
    2. Same function + different CWE
       → KEEP BOTH (可能是多处不同漏洞)
    3. Different functions + similar pattern
       → KEEP BOTH, add cross-reference note
    4. Same trigger_condition within 80% text similarity
       → likely same finding, MERGE
    """
```

### 5.10 Phase 3 验收标准

| 测试项 | 方法 | 标准 |
|--------|------|------|
| 已知漏洞召回率 | 对 CVE 已知固件分析 | 召回 ≥ 60% 的已知漏洞 |
| 误报率 | 手动验证所有 P0/P1 SP | 误报率 < 50%（动态验证前可接受） |
| 辩论有效性 | 对比有无辩论轮的 SP 质量 | 辩论后误报显著减少 |
| 交叉审阅减轻幻觉 | 统计 refuted SP 的实际误报情况 | 被 refuted 的 SP > 80% 确实是误报 |
| Token 成本可控 | 单函数分析成本统计 | 平均 < 50K tokens/函数（含辩论） |
| Qwen3.6-Plus 质量 | Analyst C vs A/B 的 SP 准确率对比 | Analyst C 准确率 ≥ Analyst A/B 的 80% |
| 去重准确性 | 人工检查去重结果 | 无误合并/误拆分 |

---

## 6. Phase 4：分层动态验证 + 报告

### 6.1 目标

```
输入: verified_sps.json
输出: final_report.json（含 PoC + 验证结果 + CWE + 修复建议）
```

### 6.2 分层验证架构

```
SP
  │
  ▼
PoC Agent (DeepSeek-V4-Pro) 构造触发输入
  │
  ├── L1: FirmAE 全系统仿真
  │    └── 成功触发崩溃 → CONFIRMED (verification_level=dynamic_full)
  │    └── 未触发 → 进入 L2
  │
  ├── L2: QEMU user-mode + stdin/网络注入
  │    └── 成功触发崩溃 → CONFIRMED (verification_level=dynamic_user)
  │    └── 未触发 → 进入 L3
  │
  └── L3: 纯静态置信度判定
       └── confidence ≥ 0.85 + 调用链完整
            → RESERVED (verification_level=static_high)
       └── 否则 → DISCARDED (verification_level=static_low)
```

### 6.3 验证等级定义

```python
class VerificationLevel:
    DYNAMIC_FULL = "dynamic_full"     # L1: FirmAE 中实际触发崩溃
    DYNAMIC_USER = "dynamic_user"     # L2: QEMU user-mode 中触发崩溃
    SYMBOLIC = "symbolic"             # (未来) 符号执行确认路径可达
    STATIC_HIGH = "static_high"       # L3: 静态 + LLM 高置信度 + 路径可达
    STATIC_LOW = "static_low"         # 被丢弃

# 报告中只报告 dynamic_full + dynamic_user + static_high
```

### 6.4 PoC Agent Prompt 设计

**模型**：DeepSeek-V4-Pro

```markdown
# Role
You are an exploit proof-of-concept developer. Given a confirmed Suspicious Point,
construct the minimal input needed to trigger the vulnerability.

# Input
- SP: {sp_json}
- Attack Surface Info: {attack_surface_for_this_sp}
- Target Function Pseudo-code: {pseudo_code_snippet}
- Architecture: {arch}

# PoC Construction Strategy by Input Vector

### For HTTP-based vulnerabilities
1. Identify HTTP method (GET/POST) and endpoint path from attack surface info
2. Include required headers (Host, Content-Length, Content-Type, Cookie if auth)
3. Craft payload in the appropriate field:
   - Buffer overflow in URL param: `GET /cgi-bin/vuln?param=AAAA...<overflow>`
   - Buffer overflow in POST body: `param=AAAA...<overflow>`
   - Command injection: `param=;cat /etc/shadow`
   - Format string: `param=%x.%x.%x.%n`

### Payload Construction Principles
1. **Overflow**: Use cyclical pattern "AAAABBBBCCCC...ZZZZ" →
   easy to identify which offset controls crash
2. **Format string**: Start with `%x.%x.%x` to verify before crafting `%n`
3. **Command injection**: Start with benign commands (`id`, `ls`) before exploitation
4. **Path traversal**: Start with `../../etc/passwd` before complex paths
5. **Always include** a "safe" version to test reachability without crashing

# Output Format
{
  "sp_id": "...",
  "poc_type": "http_request | http_response | udp_packet | tcp_stream | ...",
  "poc_target": {
    "host": "target_ip_or_localhost",
    "port": 80,
    "path": "/cgi-bin/vuln",
    "method": "POST"
  },
  "poc_content": "AAAA...raw content here",
  "poc_content_hex": "hex for non-printable bytes",
  "poc_explanation": "Why this payload triggers the vulnerability",
  "expected_behavior": {
    "expected_crash_type": "SIGSEGV | SIGABRT | SIGILL | heap_corruption",
    "expected_register_state": "PC=0x41414141 (if stack overflow)",
    "success_indicator": "QEMU exits with signal 11 (SIGSEGV)"
  },
  "alternate_payloads": [{
    "description": "Variation if first payload doesn't work",
    "poc_content": "..."
  }]
}
```

### 6.5 动态验证执行器

```python
class DynamicVerifier:
    """
    分层验证执行器
    L1: FirmAE 全系统仿真
    L2: QEMU user-mode
    L3: 静态置信度判定
    """

    def verify(self, sp: FirmwareSP, poc: PoC) -> VerificationResult:
        # L1: 尝试全系统仿真
        result = self._try_firmae(sp, poc)
        if result.crashed:
            return result  # verification_level = dynamic_full

        # L2: 降级到 user-mode
        result = self._try_qemu_user(sp, poc)
        if result.crashed:
            return result  # verification_level = dynamic_user

        # L3: 降级到纯静态
        return self._static_confidence_assessment(sp)
```

### 6.6 子任务清单

| # | 任务 | 产出 |
|---|------|------|
| 4.1 | `verifier/poc_agent.py` PoC 生成 Agent | PoC JSON |
| 4.2 | `verifier/firmae_runner.py` FirmAE 全系统仿真执行器 | L1 验证器 |
| 4.3 | `verifier/qemu_runner.py` QEMU user-mode 执行器 | L2 验证器 |
| 4.4 | `verifier/crash_monitor.py` 崩溃捕获与分类 | 崩溃去重 |
| 4.5 | `verifier/static_assessor.py` 静态置信度评估 | L3 降级 |
| 4.6 | `reporter/generator.py` 报告生成模块 | CWE + PoC + 修复建议 |
| 4.7 | Phase 4 集成测试 | 端到端验证管线 |

### 6.7 Phase 4 验收标准

| 测试项 | 方法 | 标准 |
|--------|------|------|
| PoC 触发已知漏洞 | 对 CVE 固件已知漏洞生成 PoC 并验证 | ≥ 50% 已知漏洞 PoC 能触发崩溃 |
| 分层降级正确性 | 故意让 FirmAE 失败测试降级链 | 降级逻辑正确，不丢失中间结果 |
| 崩溃去重 | 同一漏洞多次触发合并 | 崩溃去重准确率 > 90% |
| 报告完整性 | 最终报告包含所有必要字段 | CWE + PoC + 调用链 + Exploitability |

---

## 7. Agent 模型分配总览

| 阶段 | Agent | 模型 | 关键能力要求 |
|------|-------|------|-------------|
| Phase 2 | AttackSurface Identifier | DeepSeek-V4-Pro | 跨字符串/函数/调用图语义关联 |
| Phase 2 | Direction Planner | DeepSeek-V4-Pro | 功能模块划分 + 优先级判断 |
| Phase 3 | Analyst A (内存破坏) | DeepSeek-V4-Pro | 深度 C 代码理解 + 内存模型推理 |
| Phase 3 | Analyst B (逻辑缺陷) | DeepSeek-V4-Pro | 多路径分析 + 缺失检查推断 |
| Phase 3 | Analyst C (注入类) | **Qwen3.6-Plus** | 数据流追踪 + 模式匹配 |
| Phase 3 | Cross Reviewer A→B,C | DeepSeek-V4-Pro | 质疑验证 + 反例构造 |
| Phase 3 | Cross Reviewer B→C,A | DeepSeek-V4-Pro | 质疑验证 + 反例构造 |
| Phase 3 | Cross Reviewer C→A,B | **Qwen3.6-Plus** | 质疑验证 + 反例构造 |
| Phase 3 | SP Verifier | DeepSeek-V4-Pro | 综合裁决 + 统计汇总 |
| Phase 4 | PoC Constructor | DeepSeek-V4-Pro | 协议理解 + 输入构造 |

**设计理由**：
- DeepSeek-V4-Pro 承担需要深度推理的任务（代码理解、逻辑分析、综合裁决）
- Qwen3.6-Plus 承担需要快速大量处理的任务（模式匹配、注入检测、交叉审阅辅助）
- Cross Reviewer 各自审阅与自己不同视角的 SP 产出（互补盲区）

---

## 8. 代码复用与项目结构

### 8.1 复用 FuzzingBrain 的模块（不动或微调）

| FuzzingBrain 模块 | 复用方式 | 改造量 |
|---|---|---|
| `fuzzingbrain/llms/` | 扩展 DeepSeek/Qwen 模型 | 小（~100 行新增） |
| `fuzzingbrain/core/config.py` | 直接使用 | 无 |
| `fuzzingbrain/core/infrastructure.py` | 直接使用 | 无 |
| `fuzzingbrain/db/` | 直接使用（collection schema 微调） | 小 |
| `fuzzingbrain/agents/base.py` | 参考复用 | 中（适配固件场景） |
| `fuzzingbrain/agents/context.py` | 直接使用 | 无 |
| `fuzzingbrain/worker/` | 参考架构模式 | 中 |

### 8.2 新增的包（固件特有）

```
fuzzingbrain/
├── static/                    # ★新增★ 替代 fuzzingbrain/analysis/
│   ├── __init__.py
│   ├── extractor.py           # binwalk 固件提取
│   ├── ghidra_analyzer.py     # Ghidra Headless 集成
│   ├── callgraph.py           # 调用图构建
│   └── strings.py             # 字符串提取
│
├── attack_surface/            # ★新增★
│   ├── __init__.py
│   ├── identifier.py          # AttackSurface Agent
│   └── direction_planner.py   # Direction Agent
│
├── agents/
│   └── firmware/              # ★新增★ 固件专用 Agent
│       ├── __init__.py
│       ├── prompts/
│       │   ├── attack_surface_prompt.md
│       │   ├── direction_prompt.md
│       │   ├── analyst_a_prompt.md       # 内存破坏视角
│       │   ├── analyst_b_prompt.md       # 逻辑缺陷视角
│       │   ├── analyst_c_prompt.md       # 注入类视角
│       │   ├── cross_review_prompt.md    # 交叉审阅
│       │   ├── verifier_prompt.md        # SP 终审
│       │   └── poc_prompt.md             # PoC 生成
│       ├── sp_generators.py   # 三 Analyst Agent 实现
│       ├── cross_reviewer.py  # 交叉审阅逻辑
│       ├── sp_verifier.py     # SP 终审 Agent
│       └── poc_agent.py       # PoC 生成 Agent
│
├── verifier/                  # ★新增★ 替代 fuzzingbrain/fuzzer/
│   ├── __init__.py
│   ├── firmae_runner.py       # L1: FirmAE 全系统仿真
│   ├── qemu_runner.py         # L2: QEMU user-mode
│   ├── crash_monitor.py       # 崩溃捕获与分类
│   └── static_assessor.py     # L3: 静态置信度评估
│
└── reporter/                  # ★新增★
    ├── __init__.py
    └── generator.py           # 报告生成
```

---

## 9. 验收标准汇总

### Phase 1 验收

| # | 测试项 | 标准 |
|---|--------|------|
| 1 | DeepSeek API 连通性 | `quick_call("Hello")` 返回有效响应 |
| 2 | Qwen API 连通性 | `quick_call("Hello", model=QWEN3_6_PLUS)` 有效 |
| 3 | binwalk 提取完整性 | 文件系统目录结构完整 |
| 4 | Ghidra 伪代码覆盖率 | functions.json 包含所有函数，已知 CVE 函数伪代码可读 |
| 5 | 调用图完整性 | 调用关系链长度 > 2 |
| 6 | Fallback 链 | DeepSeek 失败后自动 fallback 到 Qwen |

### Phase 2 验收

| # | 测试项 | 标准 |
|---|--------|------|
| 1 | 攻击面识别覆盖率 | LLM 识别 ≥ 80% 已知攻击面 |
| 2 | Direction 划分合理性 | 无跨功能模块混搭 |
| 3 | 优先级准确度 | priority ≥4 的方向满足高优条件 |
| 4 | Prompt 稳定性 | 同一固件 3 次运行一致率 > 70% |

### Phase 3 验收

| # | 测试项 | 标准 |
|---|--------|------|
| 1 | 已知漏洞召回率 | 召回 ≥ 60% 的已知 CVE 漏洞 |
| 2 | 误报率 | 手动验证 P0/P1 SP，误报 < 50%（动态验证前） |
| 3 | 辩论有效性 | 辩论后误报显著低于辩论前 |
| 4 | 交叉审阅准确性 | refuted SP > 80% 确实是误报 |
| 5 | Token 成本 | 平均 < 50K tokens/函数（含辩论） |
| 6 | Qwen 质量 | Analyst C 准确率 ≥ A/B 的 80% |
| 7 | 去重准确性 | 无误合并/误拆分 |

### Phase 4 验收

| # | 测试项 | 标准 |
|---|--------|------|
| 1 | PoC 触发率 | ≥ 50% 已知漏洞 PoC 触发崩溃 |
| 2 | 分层降级逻辑 | 降级链正确，不丢失中间结果 |
| 3 | 崩溃去重 | 去重准确率 > 90% |
| 4 | 报告完整性 | CWE + PoC + 调用链 + Exploitability 齐全 |

---

## 10. 技术风险与降级策略

### 10.1 风险清单

| 风险 | 影响 | 概率 | 应对 |
|------|------|------|------|
| Ghidra 反编译质量差 | 伪代码不可读，LLM 误判高 | 中 | 增加汇编上下文；对关键函数提供汇编 |
| 固件依赖缺失，QEMU 跑不起来 | 动态验证无法执行 | 高 | 分层降级: FirmAE → user-mode → 纯静态 |
| 大二进制文件 Ghidra 内存溢出 | 分析中断 | 中 | 分模块分析；只分析攻击面相关函数 |
| LLM 对伪代码理解差于源码 | SP 准确率下降 | 中 | prompt 中加入变量推断提示；提供更多上下文 |
| PoC 构造失败 | 无法动态验证 | 高 | 多候选 PoC；L3 静态降级兜底 |
| DeepSeek/Qwen API 不稳定 | Agent 调用失败 | 中 | 自动 fallback 到对方 + Claude 备用 |
| 误报率过高 | 报告不可信 | 高 | 三 Agent 交叉辩论 + SP Verifier 严格过滤 |

### 10.2 分层降级策略

```
理想路径: FirmAE 全系统仿真 → 网络交互 → 确认漏洞
     ↓ (仿真失败)
降级1:   QEMU user-mode → 直接运行目标二进制 → stdin/网络注入
     ↓ (user-mode 失败)
降级2:   [未来] angr 符号执行 → 验证路径可达性
     ↓ (符号执行超时)
降级3:   纯静态验证 → SP Verifier 严格审查
     ↓
最终:    报告中标注验证等级 (dynamic_full / dynamic_user / static_high)
```

### 10.3 关键成功因素

1. **Ghidra 伪代码质量** — 决定了 LLM 能不能看懂
2. **Prompt 质量** — 固件逆向 prompt 和源码分析差异很大
3. **攻击面识别准确率** — 第一步错，后面全错
4. **交叉辩论的质量** — 对抗性审阅是降低幻觉的关键
5. **QEMU 仿真成功率** — 决定动态验证可信度
6. **误报控制** — 宁可漏报，不要大量误报

---

## 附录：提示词工程原则总结

在整个 Prompt 设计中遵循以下原则：

### 1. 分视角避免盲区
- 3 个 Analyst 给**不同的漏洞模式 checklist**（内存破坏 vs 逻辑缺陷 vs 注入）
- 避免 3 个 Agent 都找同一种漏洞 → 浪费 token

### 2. 伪代码变量名问题
- 明确告诉 LLM `local_xx`/`param_x` 是 Ghidra 自动命名的
- 要求从上下文推断含义
- 提供汇编片段作为补充验证

### 3. 结构化输出
- 所有 Agent 输出强制性 JSON schema
- 避免 LLM 输出模糊的自然语言断言
- 便于后续的自动化处理和统计

### 4. 辩论机制设计
- 只进行 1 轮交叉审阅（多轮 token 消耗太大，边际效益递减）
- 要求**具体反驳理由**，禁止笼统说"不一定对"
- 投票机制保护真阳性，同时有效过滤误报

### 5. 模型任务匹配
- 深度推理任务 → DeepSeek-V4-Pro（高性价比 + 强代码理解）
- 快速模式匹配任务 → Qwen3.6-Plus（快速 + 成本低）
- 终审裁决 → DeepSeek-V4-Pro（综合能力最强）
