# Firmware-SP: 基于 FuzzingBrain 思路的固件漏洞分析框架

## 设计手册 v1.0

---

## 目录

1. [背景与动机](#1-背景与动机)
2. [FuzzingBrain 核心思路拆解](#2-fuzzingbrain-核心思路拆解)
3. [固件分析与源码分析的本质差异](#3-固件分析与源码分析的本质差异)
4. [整体架构设计](#4-整体架构设计)
5. [核心模块详细设计](#5-核心模块详细设计)
6. [数据结构设计](#6-数据结构设计)
7. [工具链集成](#7-工具链集成)
8. [多 Agent 设计](#8-多-agent-设计)
9. [分阶段实施路线](#9-分阶段实施路线)
10. [与 FuzzingBrain 代码复用分析](#10-与-fuzzingbrain-代码复用分析)
11. [技术风险与应对](#11-技术风险与应对)

---

## 1. 背景与动机

### 1.1 为什么是固件

IoT 设备固件是漏洞的重灾区：
- 大量使用未经审查的 C 代码
- 网络服务默认暴露攻击面（HTTP/Telnet/UPnP）
- 生命周期长、更新慢，一个漏洞影响数百万设备
- 传统 fuzzing 难以直接应用（闭源、无源码、依赖硬件）

### 1.2 为什么借鉴 FuzzingBrain

FuzzingBrain 的核心创新是 **Suspicious Point (SP) 抽象层**：

```
传统 Fuzzing:                    FuzzingBrain:
随机变异输入 → 等待崩溃            LLM 语义分析 → 定位可疑点 → 定向验证
                                   ↓
                              效率高 N 倍，能发现深层逻辑漏洞
```

这个思路完全适用于固件：
- **固件逆向极耗时** — LLM 读 Ghidra 伪代码比人工快 100 倍
- **传统 fuzzing 难应用** — QEMU 仿真慢，随机变异覆盖不了深层逻辑
- **LLM + 静态分析** 先定位，再定向 fuzzing，效率远高于盲测

### 1.3 目标

```
输入:  固件二进制文件（ARM/MIPS/RISC-V）
输出:  已验证的漏洞报告（CWE 分类 + PoC + 触发路径）
```

---

## 2. FuzzingBrain 核心思路拆解

### 2.1 三层工作流

```
┌──────────────────────────────────────────────────────────┐
│ Layer 1: 静态发现                                          │
│   源码解析 → 调用图 → 可达函数 → 函数级分析 → 生成 SP        │
├──────────────────────────────────────────────────────────┤
│ Layer 2: 多 Agent 验证                                     │
│   Direction Agent → Function Agent → SP Verify Agent      │
├──────────────────────────────────────────────────────────┤
│ Layer 3: 动态确认                                          │
│   POV Agent 构造输入 → Fuzzer 执行 → Crash Monitor 确认    │
└──────────────────────────────────────────────────────────┘
```

### 2.2 关键抽象：Suspicious Point

SP 是 FuzzingBrain 最核心的抽象。它不是"这里有漏洞"的判断，而是：

```python
class SuspiciousPoint:
    location: str      # 控制流描述："if(size > limit) → buffer overflow"
    cwe: str           # 漏洞类型："CWE-122 Heap Buffer Overflow"
    trigger: str       # 触发条件："input length > 256 bytes"
    confidence: float  # 置信度：0.0 - 1.0
    function: str      # 所在函数名
    file: str          # 所在文件
```

SP 的价值在于：
- **比函数级精确** — 不浪费时间在"整个函数可能有漏洞"这种模糊判断上
- **比行号级宽容** — 允许 LLM 不确定性，用控制流描述代替精确行号
- **结构化** — 便于去重、排序、优先级分配

### 2.3 关键机制：动态验证消除幻觉

```
LLM 说:"这里可能有溢出" → 静态无法确认
     ↓
构造输入触发该路径 → Fuzzer 实际执行 → 真的崩溃 = 确认漏洞
                                → 没崩溃 = False Positive
```

这一步是整个系统的**可信度保证**。没有它，LLM 找到的 SP 准确率可能只有 20-40%。

---

## 3. 固件分析与源码分析的本质差异

| 维度 | FuzzingBrain（源码） | Firmware-SP（二进制） |
|------|----------------------|------------------------|
| **输入格式** | C/C++ 源代码 | ARM/MIPS/RISC-V 二进制 |
| **函数提取** | Tree-sitter AST 解析 | Ghidra/IDA 反编译伪代码 |
| **调用图** | OSS-Fuzz Introspector | Ghidra Call Graph / angr |
| **变量名** | 原始变量名（`buf_size`） | 重命名后（`local_1c`, `param_1`） |
| **类型信息** | 完整类型系统 | 反编译推断，可能不准确 |
| **字符串** | 代码中直接可见 | 需要从 `.rodata` 段提取 |
| **入口点** | `LLVMFuzzerTestOneInput` | 网络端口、CGI、设备驱动 |
| **动态执行** | 本地编译运行 | QEMU 仿真或真实硬件 |
| **Fuzzer** | AFL++ | Boofuzz/AFLNet（协议 fuzzing） |
| **Crash 监控** | 本地 core dump | QEMU 异常/段错误捕获 |

### 3.1 核心挑战：攻击面识别

```
源码分析:  从已知的 fuzzer 入口开始追踪调用链
固件分析:  首先要找到"哪里能输入"

固件的攻击面来源:
├── 网络服务监听端口（bind/listen）
├── Web 服务器的 CGI 脚本
├── 协议解析器（HTTP/DNS/UPnP/Telnet）
├── 设备驱动 ioctl 入口
├── 配置文件解析
└── 认证/加密模块
```

这是固件分析独有的问题，也是第一步要解决的。

---

## 4. 整体架构设计

### 4.1 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    Firmware-SP 分析框架                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Phase A: 固件预处理                                  │   │
│  │                                                     │   │
│  │  固件.bin → binwalk 解包 → 文件系统提取               │   │
│  │           → Ghidra Headless 反编译 → 伪代码 JSON      │   │
│  │           → 字符串提取 → 交叉引用分析                 │   │
│  │           → 调用图构建                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Phase B: 攻击面识别                                  │   │
│  │                                                     │   │
│  │  字符串找端口/协议 → 网络函数调用链 → CGI 入口        │   │
│  │  → 输出: 攻击面清单（入口点 + 类型 + 协议）            │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Phase C: LLM 多 Agent 分析（核心）                    │   │
│  │                                                     │   │
│  │  AttackSurface Agent → 按功能划分 Direction           │   │
│  │       ↓                                              │   │
│  │  Function Analysis Agent → 分析伪代码，生成 SP         │   │
│  │       ↓                                              │   │
│  │  SP Verify Agent → 验证路径可达性 + 输入约束           │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Phase D: 动态验证                                    │   │
│  │                                                     │   │
│  │  PoC Agent → 构造网络请求/协议报文                    │   │
│  │       ↓                                              │   │
│  │  QEMU 仿真执行 → Crash Monitor → 确认/排除            │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Phase E: 报告生成                                    │   │
│  │                                                     │   │
│  │  漏洞清单 + CWE 分类 + PoC + 修复建议 + 影响评估      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 数据流

```
firmware.bin
    │
    ├── binwalk → extracted_fs/
    │               ├── bin/        # 二进制程序
    │               ├── www/        # Web 文件（CGI、HTML）
    │               ├── etc/        # 配置文件
    │               └── lib/        # 共享库
    │
    ├── Ghidra → analysis/
    │              ├── functions.json    # 所有函数 + 伪代码
    │              ├── callgraph.json    # 调用图
    │              ├── strings.json      # 字符串 + 交叉引用
    │              └── attack_surface.json # 攻击面清单
    │
    ├── LLM Analysis → results/
    │                    ├── directions.json   # 分析方向
    │                    ├── suspicious_points.json  # SP 列表
    │                    └── verified_sps.json   # 验证后的 SP
    │
    └── Dynamic Verification → results/
                                 ├── poc/         # PoC 脚本
                                 ├── crashes/     # 崩溃日志
                                 └── report.json  # 最终报告
```

---

## 5. 核心模块详细设计

### 5.1 模块一：固件提取（FirmwareExtractor）

```python
class FirmwareExtractor:
    """
    固件解包与文件系统提取

    输入: 固件二进制文件
    输出: 提取的文件系统目录结构
    """

    def extract(self, firmware_path: str, output_dir: str) -> ExtractResult:
        """
        使用 binwalk 提取固件
        """
        # 1. binwalk -e 提取
        # 2. 识别文件系统类型（squashfs/jffs2/cramfs）
        # 3. 挂载或解压
        # 4. 分类文件: binary/web/config/library
        # 5. 返回 ExtractResult

    def identify_binaries(self, extracted_dir: str) -> List[BinaryInfo]:
        """
        识别关键二进制文件
        - ELF 文件头检测
        - 架构识别（ARM/MIPS/RISC-V）
        - 文件角色（web server/daemon/CGI/library）
        """
```

**关键输出**：`BinaryInfo`

```python
@dataclass
class BinaryInfo:
    path: str              # 文件路径
    arch: str              # 架构: arm/mips/riscv
    bits: int              # 32/64
    endian: str            # little/big
    file_type: str         # web_server/daemon/cgi/library
    stripped: bool         # 是否 stripped
    entry_point: int       # 入口地址
    sections: List[str]    # 段名列表
```

### 5.2 模块二：静态分析（StaticAnalyzer）

```python
class StaticAnalyzer:
    """
    Ghidra Headless 批量反编译

    输入: 提取的二进制文件
    输出: 函数伪代码 + 调用图 + 字符串信息
    """

    def analyze_binary(self, binary: BinaryInfo, output_dir: str) -> AnalysisResult:
        """
        使用 Ghidra Headless 分析单个二进制
        """
        # 1. 生成 Ghidra Headless 分析脚本
        # 2. 执行分析（批量）
        # 3. 导出结果

    def extract_functions(self) -> List[FunctionInfo]:
        """提取所有函数"""
        # - 函数名（符号表中有的保留，没有的 FUN_xxxx）
        # - 伪代码（Decompiler 输出）
        # - 汇编代码
        # - 参数数量（推断）
        # - 交叉引用

    def build_callgraph(self) -> CallGraph:
        """构建调用图"""
        # - Ghidra 内置 Call Graph
        # - 或使用 angr 构建

    def extract_strings(self) -> List[StringRef]:
        """提取字符串及交叉引用"""
        # - 从 .rodata 段提取
        # - 记录每个字符串的引用位置
        # - 标记关键字符串（IP/端口/协议/路径/密码）

    def identify_attack_surface(self) -> AttackSurface:
        """
        识别攻击面（固件特有）

        方法:
        1. 字符串匹配: "0.0.0.0", ":80", "/cgi-bin/", "admin"
        2. 函数调用: bind(), listen(), recv(), strcpy(), sprintf()
        3. 网络协议: HTTP/DNS/UPnP/Telnet/FTP 特征
        4. Web 文件: 从提取的文件系统中找 CGI/HTML
        """
```

**关键输出**：`FunctionInfo`

```python
@dataclass
class FunctionInfo:
    name: str                    # 函数名
    address: int                 # 二进制偏移地址
    pseudo_code: str             # Ghidra 反编译伪代码
    assembly: str                # 汇编代码（可选）
    callers: List[str]           # 调用者
    callees: List[str]           # 被调用者
    parameters: int              # 参数数量（推断）
    complexity: int              # 圈复杂度
    has_unsafe_calls: bool       # 是否调用危险函数
    dangerous_funcs: List[str]   # 调用的危险函数列表
    strings_used: List[str]      # 使用的字符串
    arch: str                    # 架构
    section: str                 # 所在段
```

### 5.3 模块三：攻击面识别（AttackSurfaceIdentifier）

```python
class AttackSurfaceIdentifier:
    """
    固件攻击面识别

    回答核心问题: "哪里能输入？"
    """

    def identify(self, analysis_result: AnalysisResult) -> AttackSurface:
        """
        识别所有潜在攻击入口
        """

    def _find_network_services(self) -> List[NetworkService]:
        """
        找网络服务: bind/listen/accept 调用链
        """

    def _find_cgi_endpoints(self) -> List[CGIEndpoint]:
        """
        找 CGI 入口: /cgi-bin/ 路径 + 参数解析
        """

    def _find_protocol_parsers(self) -> List[ProtocolParser]:
        """
        找协议解析器: HTTP/DNS/UPnP/Telnet 解析函数
        """

    def _find_auth_weaknesses(self) -> List[AuthInfo]:
        """
        找认证相关: 硬编码密码、弱加密、认证绕过
        """

    def _find_file_operations(self) -> List[FileOp]:
        """
        找文件操作: open/read/write/系统命令注入
        """
```

**关键输出**：`AttackSurface`

```python
@dataclass
class AttackSurface:
    network_services: List[NetworkService]   # 监听的网络服务
    cgi_endpoints: List[CGIEndpoint]          # Web CGI 入口
    protocol_parsers: List[ProtocolParser]    # 协议解析器
    auth_modules: List[AuthInfo]              # 认证模块
    file_operations: List[FileOp]             # 文件操作入口
    entry_points: List[str]                   # 所有入口函数名
```

```python
@dataclass
class NetworkService:
    entry_function: str    # 入口函数
    port: int              # 监听端口
    protocol: str          # TCP/UDP
    binary: str            # 所属二进制
    description: str       # 描述

@dataclass
class CGIEndpoint:
    path: str              # CGI 路径
    method: str            # GET/POST
    entry_function: str    # 处理函数
    params: List[str]      # 解析的参数名
    binary: str            # 所属二进制
```

### 5.4 模块四：LLM 分析引擎（LLMAnalyzer）

```python
class LLMAnalyzer:
    """
    多 Agent LLM 分析引擎

    这是核心模块，参考 FuzzingBrain 的 Agent 架构
    """

    def run_analysis(self, attack_surface: AttackSurface,
                     functions: List[FunctionInfo]) -> AnalysisResult:
        """
        运行完整分析管线
        """
        # 1. Direction Agent: 划分分析方向
        directions = self.direction_agent.plan(attack_surface)

        # 2. Function Analysis Agent: 每个方向并行分析
        all_sps = []
        for direction in directions:
            funcs = self.get_direction_functions(direction)
            sps = self.function_agent.analyze(funcs, direction)
            all_sps.extend(sps)

        # 3. SP Dedup: 去重
        deduped_sps = self.deduplicate(all_sps)

        # 4. SP Verify Agent: 验证每个 SP
        verified_sps = []
        for sp in deduped_sps:
            result = self.verify_agent.verify(sp)
            if result.is_feasible:
                verified_sps.append(sp)

        return AnalysisResult(suspicious_points=verified_sps)
```

### 5.5 模块五：动态验证（DynamicVerifier）

```python
class DynamicVerifier:
    """
    QEMU + Fuzzer 动态验证

    输入: 验证后的 SP
    输出: 确认的漏洞 + PoC
    """

    def verify_sp(self, sp: FirmwareSP) -> VerificationResult:
        """
        验证单个 SP
        """
        # 1. PoC Agent 构造触发输入
        poc = self.poc_agent.construct(sp)

        # 2. QEMU 仿真执行
        crash = self.qemu_runner.run(sp.binary, poc)

        # 3. 判断是否真的触发
        if crash and self._is_related_to_sp(crash, sp):
            return VerificationResult(
                confirmed=True, poc=poc, crash_log=crash
            )
        return VerificationResult(confirmed=False)

    def _setup_emulation(self, binary: BinaryInfo) -> QEMUConfig:
        """
        配置 QEMU 仿真环境
        - 架构匹配（qemu-arm/qemu-mips）
        - 网络端口映射
        - 依赖库路径（-L chroot）
        """
```

### 5.6 模块六：报告生成（ReportGenerator）

```python
class ReportGenerator:
    """
    生成最终漏洞报告
    """

    def generate(self, verified_sps: List[FirmwareSP],
                 crash_logs: List[CrashLog]) -> Report:
        """
        输出结构化报告
        """
```

---

## 6. 数据结构设计

### 6.1 核心数据模型：FirmwareSP

```python
@dataclass
class FirmwareSP:
    """
    固件可疑点 — 核心抽象

    对比 FuzzingBrain 的 SuspiciousPoint:
    - 增加 binary_offset（二进制偏移）
    - 增加 arch（架构信息）
    - 增加 input_vector（输入向量）
    - 增加 pseudo_code_snippet（伪代码片段）
    """

    # === 基本信息（同 FuzzingBrain）===
    sp_id: str                    # 唯一标识
    cwe: str                      # CWE 编号
    description: str              # 漏洞描述
    confidence: float             # 置信度 0.0-1.0
    severity: str                 # critical/high/medium/low

    # === 位置信息 ===
    function_name: str            # 函数名（可能是 FUN_xxxx）
    binary_offset: int            # 函数在二进制中的偏移
    pseudo_code_snippet: str      # 关键伪代码片段
    control_flow: str             # 控制流描述

    # === 固件特有信息 ===
    arch: str                     # ARM/MIPS/RISC-V
    binary_path: str              # 所属二进制文件
    section: str                  # .text/.data 等

    # === 触发信息 ===
    trigger_condition: str        # 触发条件描述
    input_vector: str             # 输入来源: http/telnet/cgi/ioctl/config
    input_constraints: str        # 输入约束（如 "Content-Length > 256"）

    # === 可达性信息 ===
    entry_point: str              # 攻击面入口函数
    call_path: List[str]          # 从入口到目标函数的调用链
    is_reachable: bool            # 静态分析是否可达

    # === 验证信息 ===
    is_verified: bool = False     # 是否经过动态验证
    poc: Optional[str] = None     # PoC 内容
    crash_log: Optional[str] = None  # 崩溃日志

    # === 去重信息 ===
    merged_from: List[str] = field(default_factory=list)  # 合并的相似 SP
```

### 6.2 Direction（分析方向）

```python
@dataclass
class Direction:
    """
    分析方向 — 代码的逻辑分区

    固件版按功能模块划分，而非调用图分区
    """
    direction_id: str
    name: str                    # 如 "HTTP Server", "UPnP Service"
    description: str             # 方向描述
    entry_points: List[str]      # 入口函数列表
    related_functions: List[str]  # 相关函数列表
    attack_type: str             # 攻击类型: overflow/injection/auth_bypass/etc.
    priority: int                # 优先级 1-5
```

### 6.3 验证结果

```python
@dataclass
class VerificationResult:
    sp_id: str
    confirmed: bool              # 是否确认
    poc: Optional[str]           # PoC 内容
    crash_type: Optional[str]    # 崩溃类型
    crash_log: Optional[str]     # 崩溃日志
    qemu_output: Optional[str]   # QEMU 输出
    error: Optional[str]         # 错误信息
    verification_time: float     # 验证耗时(秒)
```

---

## 7. 工具链集成

### 7.1 工具清单

| 阶段 | 工具 | 用途 | 替代方案 |
|------|------|------|----------|
| 解包 | `binwalk` | 固件提取 | `firmware-mod-kit` |
| 反编译 | `Ghidra Headless` | 批量反编译 | IDA Pro / Binary Ninja |
| 符号执行 | `angr` | 路径可达性验证 | `Triton` / `Manticore` |
| 仿真 | `QEMU` (user-mode) | 单程序仿真 | `Unicorn Engine` |
| 仿真 | `FirmAE` | 完整固件仿真 | `Firmadyne` / `Firmadyne-ng` |
| 协议 Fuzzing | `Boofuzz` | 网络协议 fuzzing | `AFLNet` / `Peach` |
| 调用图 | `Ghidra Call Graph` | 函数调用关系 | `angr CFG` / `radare2` |

### 7.2 Ghidra Headless 集成

```python
import subprocess
import json

class GhidraAnalyzer:
    """
    Ghidra Headless 自动化
    """

    GHIDRA_HEADLESS = "/opt/ghidra/support/analyzeHeadless"
    PROJECT_NAME = "firmware_analysis"

    def analyze(self, binary_path: str, output_dir: str) -> AnalysisResult:
        """
        执行 Ghidra Headless 分析
        """
        # 1. 创建/打开 Ghidra 项目
        subprocess.run([
            self.GHIDRA_HEADLESS,
            output_dir,           # 项目目录
            self.PROJECT_NAME,    # 项目名
            "-import", binary_path,  # 导入二进制
            "-scriptPath", "/path/to/scripts",
            "-postScript", "ExtractFunctions.java",
            "-postScript", "ExtractCallGraph.java",
            "-postScript", "ExtractStrings.java",
            "-deleteProject",
        ])

        # 2. 读取导出结果
        return self._parse_results(output_dir)
```

**Ghidra Java 脚本示例**（ExtractFunctions.java）：

```java
// ExportFunctions.java - Ghidra 脚本
// 导出所有函数的伪代码为 JSON

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import com.google.gson.*;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        JsonObject result = new JsonObject();
        JsonArray functions = new JsonArray();

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        for (Function func : iter) {
            DecompileResults decompiled = decompiler.decompileFunction(func, 60, monitor);
            if (decompiled.decompileCompleted()) {
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().toString());
                funcObj.addProperty("pseudo_code", decompiled.getDecompiledFunction().getC());
                funcObj.addProperty("parameter_count", func.getParameterCount());
                functions.add(funcObj);
            }
        }

        result.add("functions", functions);

        // 输出到文件
        String outputPath = getScriptArgs()[0];
        java.nio.file.Files.writeString(
            java.nio.file.Path.of(outputPath),
            result.toString()
        );
    }
}
```

### 7.3 QEMU 仿真集成

```python
import subprocess
import signal
import time

class QEMURunner:
    """
    QEMU 用户态仿真 + 崩溃捕获
    """

    QEMU_MAP = {
        "arm": "qemu-arm-static",
        "armeb": "qemu-armeb-static",
        "mips": "qemu-mips-static",
        "mipsel": "qemu-mipsel-static",
        "mips64": "qemu-mips64-static",
        "mips64el": "qemu-mips64el-static",
        "riscv32": "qemu-riscv32-static",
        "riscv64": "qemu-riscv64-static",
    }

    def run(self, binary_path: str, poc_input: bytes,
            arch: str, lib_path: str = None,
            timeout: int = 30) -> CrashResult:
        """
        在 QEMU 中运行二进制，注入 PoC 输入

        参数:
            binary_path: 目标二进制文件
            poc_input: PoC 输入数据
            arch: 目标架构
            lib_path: 共享库路径（chroot）
            timeout: 超时时间(秒)
        """
        qemu_binary = self.QEMU_MAP.get(arch)
        if not qemu_binary:
            raise ValueError(f"Unsupported architecture: {arch}")

        cmd = [qemu_binary]
        if lib_path:
            cmd.extend(["-L", lib_path])
        cmd.append(binary_path)

        # 方式1: 通过 stdin 注入
        # 方式2: 通过网络端口注入
        # 方式3: 通过文件注入（取决于输入向量）

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            stdout, stderr = proc.communicate(
                input=poc_input, timeout=timeout
            )

            if proc.returncode != 0:
                # 捕获段错误或其他异常
                return CrashResult(
                    crashed=True,
                    return_code=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    crash_type=self._classify_crash(stderr),
                )

            return CrashResult(crashed=False)

        except subprocess.TimeoutExpired:
            proc.kill()
            return CrashResult(crashed=False, timed_out=True)

    def run_with_network(self, binary_path: str, poc_request: bytes,
                         arch: str, port: int,
                         lib_path: str = None) -> CrashResult:
        """
        通过网络端口注入 PoC

        1. 在 QEMU 中启动服务（后台）
        2. 等待服务就绪
        3. 发送 PoC 请求
        4. 检查是否崩溃
        """
        # 启动 QEMU + 端口映射
        qemu_cmd = [self.QEMU_MAP[arch]]
        if lib_path:
            qemu_cmd.extend(["-L", lib_path])
        qemu_cmd.extend([
            "-g", "1234",  # 可选: 启动 GDB stub
            binary_path,
        ])

        proc = subprocess.Popen(
            qemu_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 等待服务启动
        time.sleep(3)

        # 发送 PoC 请求
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", port))
            sock.send(poc_request)
            response = sock.recv(4096)
            sock.close()
        except Exception as e:
            pass

        # 检查进程状态
        time.sleep(2)
        return_code = proc.poll()

        if return_code and return_code < 0:
            # 负返回值表示被信号杀死（如 SIGSEGV）
            stderr = proc.stderr.read().decode()
            return CrashResult(
                crashed=True,
                return_code=return_code,
                stderr=stderr,
                crash_type=self._classify_crash(stderr),
            )

        proc.kill()
        return CrashResult(crashed=False)
```

### 7.4 协议 Fuzzing 集成

```python
class ProtocolFuzzer:
    """
    基于 Boofuzz 的协议 Fuzzing

    用于对验证后的 SP 进行深度 fuzzing
    """

    def fuzz_http(self, target_host: str, target_port: int,
                  sp: FirmwareSP) -> FuzzResult:
        """
        HTTP 协议 fuzzing
        """
        from boofuzz import Session, Target, TCPSocketConnection
        from boofuzz import s_get, s_string, s_static

        # 根据 SP 的 input_constraints 构建 fuzzing 模板
        session = Session(
            target=Target(
                connection=TCPSocketConnection(target_host, target_port)
            )
        )

        # 构建 HTTP 请求模板
        s_initialize("HTTP_REQUEST")
        s_string("GET", fuzzable=True)
        s_static(" ")
        s_string("/vulnerable_path", fuzzable=True)
        s_static("\r\n")
        s_string("Host", fuzzable=True)
        s_static(": ")
        s_string("target", fuzzable=True)
        s_static("\r\n\r\n")

        session.connect(s_get("HTTP_REQUEST"))
        session.fuzz()

    def fuzz_custom_protocol(self, sp: FirmwareSP) -> FuzzResult:
        """
        自定义协议 fuzzing

        根据 SP 描述构建协议 fuzzing 模板
        """
        # 1. 从 SP 提取协议格式
        # 2. 构建 fuzzing 会话
        # 3. 运行 fuzzing
        # 4. 监控崩溃
        pass
```

---

## 8. 多 Agent 设计

### 8.1 Agent 角色对照表

| FuzzingBrain Agent | Firmware-SP Agent | 核心职责变化 |
|---|---|---|
| Direction Planning | AttackSurface Direction | 按功能模块划分 vs 按调用图划分 |
| Function Analysis | PseudoCode Analysis | 看反编译伪代码 vs 看 C 源码 |
| SP Verify | Path Reachability Verify | QEMU/angr 验证 vs 纯静态验证 |
| POV Agent | PoC Construct Agent | 生成网络请求 vs 生成 fuzzing 输入 |
| Seed Agent | Protocol Seed Agent | 解析协议规范 vs 生成 fuzzing 种子 |

### 8.2 Agent 1: 攻击面方向规划 Agent

```
Prompt 核心:
"""
你是一个固件安全架构师。

给定固件的攻击面清单（网络服务、CGI 入口、协议解析器），
请将其划分为多个逻辑分析方向。

划分原则:
1. 按功能模块: Web 服务 / 协议服务 / 认证模块 / 文件系统
2. 每个方向包含: 入口函数 + 相关处理函数
3. 优先考虑: 网络可达、无认证、处理外部输入的路径

输出每个方向:
- 方向名称（如 "HTTP CGI Handler"）
- 入口函数列表
- 相关函数列表
- 可能的攻击类型
- 优先级（1-5）
"""
```

### 8.3 Agent 2: 伪代码分析 Agent

```
Prompt 核心:
"""
你是一个二进制逆向工程师和安全研究员。

你将收到:
1. 函数的 Ghidra 反编译伪代码
2. 该函数的调用上下文（调用者、被调用者）
3. 攻击面信息（数据如何流入此函数）

你的任务:
- 识别可能的漏洞模式:
  * 缓冲区溢出: strcpy/sprintf/memcpy 无边界检查
  * 格式化字符串: printf(user_input)
  * 整数溢出: 未检查的算术运算
  * 命令注入: system() 拼接用户输入
  * 路径遍历: 未净化的文件路径
  * 认证绕过: 逻辑缺陷

- 为每个发现创建 Suspicious Point (SP):
  * 描述控制流路径
  * 指定 CWE 类型
  * 描述触发条件
  * 给出置信度

约束:
- 伪代码中的变量名（local_xxx, param_xxx）是 Ghidra 自动分配的
- 类型信息可能不准确，需要结合上下文推断
- 优先考虑网络可达的路径
"""
```

### 8.4 Agent 3: SP 验证 Agent

```
Prompt 核心:
"""
你是一个二进制漏洞验证专家。

给定一个 Suspicious Point (SP)，请验证其可行性:

1. 路径可达性:
   - 从攻击面入口到目标函数的调用链是否完整？
   - 是否存在条件分支可能跳过目标代码？

2. 输入约束:
   - 触发条件是否实际可满足？
   - 输入数据格式是否与协议/接口匹配？

3. 误报排除:
   - 是否有边界检查在别处执行？
   - 是否有编译器保护（canary/RELRO）？
   - 输入长度是否被前置函数截断？

输出: feasible / infeasible + 原因
"""
```

### 8.5 Agent 4: PoC 构造 Agent

```
Prompt 核心:
"""
你是一个漏洞利用开发工程师。

给定一个已验证的 Suspicious Point (SP)，构造 Proof of Concept (PoC):

输入:
- SP 描述（漏洞类型、触发条件、目标函数）
- 攻击面信息（协议类型、端口、入口路径）
- 伪代码片段

输出:
- PoC 内容（HTTP 请求 / 协议报文 / 命令行输入）
- 预期行为（应该触发什么崩溃）
- 验证方法（如何确认漏洞被触发）

示例:
对于 HTTP 缓冲区溢出:
```
POST /cgi-bin/vulnerable.cgi HTTP/1.1
Host: target
Content-Length: 9999

{overflow_payload}
```
"""
```

### 8.6 Agent 工作流

```
┌─────────────────────────────────────────────────────────┐
│  AttackSurface Direction Agent                           │
│  输入: 攻击面清单 + 函数列表                               │
│  输出: N 个分析方向                                       │
└────────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ↓                ↓                ↓
  ┌───────────┐   ┌───────────┐   ┌───────────┐
  │ Direction 1│   │ Direction 2│   │ Direction 3│
  │            │   │            │   │            │
  │ PseudoCode │   │ PseudoCode │   │ PseudoCode │
  │ Agent ×5   │   │ Agent ×5   │   │ Agent ×5   │
  │ (并行)     │   │ (并行)     │   │ (并行)     │
  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
        │               │               │
        └───────────────┼───────────────┘
                        ↓
              ┌───────────────────┐
              │  SP Dedup Agent    │
              │  去重 + 合并        │
              └────────┬──────────┘
                       ↓
              ┌───────────────────┐
              │  SP Verify Agent   │
              │  可行性验证          │
              └────────┬──────────┘
                       ↓
              ┌───────────────────┐
              │  PoC Agent         │
              │  构造 PoC           │
              └────────┬──────────┘
                       ↓
              ┌───────────────────┐
              │  QEMU Verifier     │
              │  动态验证            │
              └────────┬──────────┘
                       ↓
              ┌───────────────────┐
              │  Report            │
              │  最终报告            │
              └───────────────────┘
```

---

## 9. 分阶段实施路线

### Phase 1: 固件解包 + 静态分析（2-3 周）

**目标**: 固件 → Ghidra 伪代码 + 调用图 + 攻击面清单

```
任务:
├── [ ] 固件解包模块 (binwalk 集成)
├── [ ] Ghidra Headless 自动化
│     ├── Java 脚本编写（函数/调用图/字符串导出）
│     ├── 批量处理管线
│     └── JSON 输出格式定义
├── [ ] 攻击面识别模块
│     ├── 字符串特征匹配
│     ├── 网络函数调用链追踪
│     ├── CGI 入口识别
│     └── 协议解析器识别
└── [ ] 数据模型定义
      ├── FunctionInfo
      ├── BinaryInfo
      └── AttackSurface

验收标准:
- 输入任意固件，输出结构化分析结果 JSON
- 攻击面识别准确率 > 80%（人工验证）
```

### Phase 2: LLM 静态分析（2-3 周）

**目标**: 伪代码 → LLM 分析 → SP 列表

```
任务:
├── [ ] LLM 基础设施搭建
│     ├── LiteLLM 集成（复用 FuzzingBrain）
│     ├── Token 统计与成本控制
│     └── 多 Provider 支持
├── [ ] Agent Prompt 设计
│     ├── Direction Planning Prompt
│     ├── PseudoCode Analysis Prompt
│     └── SP Verify Prompt
├── [ ] Agent 工作流引擎
│     ├── 并发执行框架
│     ├── SP 去重逻辑
│     └── 结果聚合
└── [ ] Prompt 迭代优化
      ├── 用已知漏洞样本测试
      └── 调整 Prompt 降低误报率

验收标准:
- 对已知漏洞固件，能复现至少 60% 的漏洞
- SP 去重后，单个固件 SP 数量 < 50
- 误报率 < 70%（静态阶段，预期较高）
```

### Phase 3: 动态验证（3-4 周）

**目标**: SP → PoC → QEMU 验证 → 确认漏洞

```
任务:
├── [ ] QEMU 仿真环境
│     ├── 多架构支持（ARM/MIPS/RISC-V）
│     ├── 网络端口映射
│     ├── 依赖库处理（chroot）
│     └── 崩溃捕获与分类
├── [ ] PoC 生成模块
│     ├── HTTP PoC 模板
│     ├── 自定义协议 PoC
│     └── 基于 SP 描述的自动生成
├── [ ] 协议 Fuzzing 集成
│     ├── Boofuzz 集成
│     └── 针对确认 SP 的定向 fuzzing
└── [ ] 验证管线
      ├── SP → PoC → QEMU → 结果判断
      └── 超时与资源管理

验收标准:
- 对已知漏洞，PoC 能稳定触发崩溃
- 误报率降至 < 30%
- 单个 SP 验证时间 < 5 分钟
```

### Phase 4: 系统集成 + 工程化（2-3 周）

**目标**: 完整端到端管线 + CLI + API

```
任务:
├── [ ] CLI 工具
│     ├── 命令行参数解析
│     ├── 进度显示
│     └── 报告输出
├── [ ] REST API
│     ├── FastAPI 服务
│     ├── 任务提交
│     └── 状态查询
├── [ ] 数据库存储
│     ├── MongoDB 存储分析结果
│     └── 历史对比
├── [ ] 报告生成
│     ├── HTML 报告
│     ├── JSON 导出
│     └── CVE 格式输出
└── [ ] 文档
      ├── 使用手册
      └── 已知漏洞测试报告

验收标准:
- 一条命令完成完整分析
- 报告包含漏洞详情 + PoC + 修复建议
```

### 总体时间线

```
Phase 1: ██░░░░░░░░  2-3 周  固件解包 + 静态分析
Phase 2: ████░░░░░░░  2-3 周  LLM 静态分析
Phase 3: ██████░░░░░  3-4 周  动态验证
Phase 4: ████████░░░  2-3 周  系统集成
         ───────────
         总计: 9-13 周
```

---

## 10. 与 FuzzingBrain 代码复用分析

### 10.1 可直接复用的模块

| FuzzingBrain 模块 | 复用方式 | 改造量 |
|---|---|---|
| `fuzzingbrain/llms/` | 直接使用 | 无 |
| `fuzzingbrain/core/config.py` | 直接使用 + 扩展字段 | 小 |
| `fuzzingbrain/core/models/` | 参考结构，新建 FirmwareSP | 中 |
| `fuzzingbrain/db/` | 直接使用 | 小（改 collection schema） |
| `fuzzingbrain/core/logging.py` | 直接使用 | 无 |
| `fuzzingbrain/core/infrastructure.py` | 直接使用 | 无 |
| 整体 Agent 框架 | 参考架构模式 | 中（改 prompt） |

### 10.2 需要重写的模块

| FuzzingBrain 模块 | 替换为 | 原因 |
|---|---|---|
| `fuzzingbrain/analysis/` | `firmware_sp/static/` | Tree-sitter → Ghidra |
| `fuzzingbrain/analyzer/` | `firmware_sp/analyzer/` | 构建管线完全不同 |
| `fuzzingbrain/fuzzer/` | `firmware_sp/verifier/` | AFL++ → QEMU+Boofuzz |
| `fuzzingbrain/agents/prompts/` | `firmware_sp/prompts/` | 源码 prompt → 伪代码 prompt |
| `fuzzingbrain/worker/strategies/` | `firmware_sp/strategies/` | 策略完全不同 |

### 10.3 推荐的项目结构

```
firmware-sp/
├── README.md
├── requirements.txt          # 继承 + 新增 (angr, boofuzz, etc.)
├── firmware_sp/
│   ├── __init__.py
│   ├── main.py               # 入口（参考 FuzzingBrain main.py）
│   ├── config.py             # 配置（扩展 FuzzingBrain Config）
│   │
│   ├── static/               # === 替换 FuzzingBrain analysis ===
│   │   ├── extractor.py      # binwalk 固件提取
│   │   ├── ghidra.py         # Ghidra Headless 集成
│   │   ├── callgraph.py      # 调用图构建
│   │   ├── strings.py        # 字符串提取
│   │   └── attack_surface.py # 攻击面识别
│   │
│   ├── agents/               # === 参考 FuzzingBrain agents ===
│   │   ├── direction_agent.py
│   │   ├── pseudocode_agent.py
│   │   ├── verify_agent.py
│   │   ├── poc_agent.py
│   │   └── prompts/
│   │       ├── direction_prompt.md
│   │       ├── pseudocode_analysis_prompt.md
│   │       ├── verify_prompt.md
│   │       └── poc_prompt.md
│   │
│   ├── verifier/             # === 替换 FuzzingBrain fuzzer ===
│   │   ├── qemu_runner.py    # QEMU 仿真
│   │   ├── protocol_fuzzer.py # Boofuzz 集成
│   │   ├── crash_monitor.py  # 崩溃捕获
│   │   └── crash_dedup.py    # 崩溃去重
│   │
│   ├── core/                 # === 复用 FuzzingBrain core ===
│   │   ├── models/
│   │   │   ├── sp.py         # FirmwareSP 数据模型
│   │   │   ├── direction.py
│   │   │   ├── binary.py
│   │   │   └── task.py
│   │   ├── config.py
│   │   ├── dispatcher.py
│   │   ├── sp_dedup.py       # SP 去重
│   │   └── logging.py
│   │
│   ├── llms/                 # === 直接复用 ===
│   │   ├── client.py
│   │   ├── config.py
│   │   ├── buffer.py
│   │   └── models.py
│   │
│   ├── db/                   # === 复用 ===
│   │   ├── connection.py
│   │   └── repository.py
│   │
│   ├── api_server.py         # === 参考复用 ===
│   ├── celery_app.py         # === 参考复用 ===
│   └── worker/
│       ├── tasks.py
│       ├── executor.py
│       └── strategies/       # 固件分析策略
│
├── examples/
│   ├── sample_firmware.bin   # 测试固件
│   └── run_analysis.sh
│
└── docs/
    └── architecture.md
```

---

## 11. 技术风险与应对

### 11.1 风险清单

| 风险 | 影响 | 概率 | 应对 |
|------|------|------|------|
| Ghidra 反编译质量差 | 伪代码不可读，LLM 误判高 | 中 | 增加汇编上下文；对关键函数提供汇编 |
| 固件依赖缺失，QEMU 跑不起来 | 动态验证无法执行 | 高 | 多级降级: 完整仿真 → user-mode → 符号执行 → 纯静态 |
| 大二进制文件 Ghidra 内存溢出 | 分析中断 | 中 | 分模块分析；只分析攻击面相关函数 |
| LLM 对伪代码理解差于源码 | SP 准确率下降 | 中 | 在 prompt 中加入变量推断提示；提供更多上下文 |
| PoC 构造失败 | 无法动态验证 | 高 | 人工辅助模式；降低验证要求，接受静态 + 高置信度 |
| 误报率过高 | 报告不可信 | 高 | 多 Agent 交叉验证；SP 验证 Agent 严格过滤 |

### 11.2 降级策略

```
理想路径: 完整固件仿真 → QEMU 网络验证 → 确认漏洞
     ↓ (仿真失败)
降级1:  QEMU user-mode → 直接运行目标二进制 → 注入输入
     ↓ (user-mode 失败)
降级2:  angr 符号执行 → 验证路径可达性
     ↓ (符号执行超时)
降级3:  纯静态验证 → SP Verify Agent 严格审查
     ↓
最终: 报告中标注验证等级 (dynamic / symbolic / static)
```

### 11.3 验证等级定义

```python
class VerificationLevel:
    DYNAMIC = "dynamic"       # QEMU 中实际触发崩溃
    SYMBOLIC = "symbolic"     # 符号执行确认路径可达
    STATIC_HIGH = "static_high"  # 静态分析 + LLM 高置信度 + 路径可达
    STATIC_MED = "static_med"    # 静态分析 + 中等置信度

# 报告中只报告 dynamic + symbolic + static_high
```

### 11.4 关键成功因素

1. **攻击面识别准确率** — 这是第一步，错了后面全错
2. **Ghidra 伪代码质量** — 决定了 LLM 能不能看懂
3. **Prompt 质量** — 固件逆向的 prompt 和源码分析差异很大
4. **QEMU 仿真成功率** — 动态验证的可信度基础
5. **误报控制** — 宁可漏报，不要大量误报

---

## 附录 A: Prompt 模板示例

### A.1 攻击面方向规划 Prompt

```markdown
# Role
You are a firmware security architect with expertise in IoT devices.

# Task
Analyze the firmware attack surface and divide it into logical analysis directions.

# Input
- Attack surface: {attack_surface}
- Binary list: {binaries}
- Function list: {functions}

# Analysis Framework

1. **Network Services**: Services listening on network ports
2. **Web Interfaces**: HTTP servers, CGI scripts, web management
3. **Protocol Parsers**: UPnP, DNS, Telnet, FTP, custom protocols
4. **Authentication Modules**: Login, password handling, token validation
5. **File System Operations**: Config read/write, file upload/download
6. **System Commands**: shell execution, process management

# Output Format

For each direction:
- name: Direction name
- description: What this direction covers
- entry_functions: Functions that receive external input
- related_functions: Functions called by entry functions
- attack_types: Expected vulnerability types
- priority: 1-5

# Constraints
- Maximum 10 directions
- Each direction should be analyzable independently
- Prioritize network-reachable code paths
- Focus on code that processes untrusted input
```

### A.2 伪代码分析 Prompt

```markdown
# Role
You are a binary reverse engineer and vulnerability researcher.

# Task
Analyze the decompiled pseudo-code to identify potential vulnerabilities.

# Input
- Function: {function_name}
- Architecture: {arch}
- Pseudo-code:
```c
{pseudo_code}
```
- Callers: {callers}
- Callees: {callees}
- Strings used: {strings}
- Attack surface context: {attack_context}

# Vulnerability Patterns to Look For

## Buffer Overflow (CWE-120)
- `strcpy(dst, src)` without length check
- `sprintf(buf, format, user_input)`
- `memcpy(dst, src, unchecked_size)`
- Array indexing with user-controlled index

## Format String (CWE-134)
- `printf(user_input)` or `sprintf(format, user_input)`

## Command Injection (CWE-78)
- `system(string_concat(user_input))`
- `popen(user_input)`

## Path Traversal (CWE-22)
- `open(user_input)` without sanitization
- Missing `../` filtering

## Integer Overflow (CWE-190)
- Unchecked arithmetic before allocation
- `malloc(a * b)` without overflow check

## Authentication Bypass (CWE-287)
- Logic flaws in auth checks
- Hardcoded credentials

# SP Output Format

For each finding:
- cwe: CWE-XXX
- description: What the issue is
- control_flow: The code path that leads to the issue
- trigger_condition: What input triggers this
- confidence: 0.0-1.0
- severity: critical/high/medium/low

# Important Notes
- Variable names like `local_1c` are Ghidra auto-assigned — infer meaning from context
- Type information may be inaccurate — verify against usage patterns
- Focus on paths reachable from external input
- Do not report issues in unreachable code
```

### A.3 SP 验证 Prompt

```markdown
# Role
You are a vulnerability verification expert specializing in binary analysis.

# Task
Verify if the reported Suspicious Point (SP) is actually exploitable.

# Input
- SP Description: {sp_description}
- Target Function Pseudo-code:
```c
{pseudo_code}
```
- Full Call Path from Entry: {call_path}
- Input Vector: {input_vector}

# Verification Steps

1. **Reachability**: Can the execution actually reach the vulnerable code?
   - Are there conditional branches that might skip it?
   - Is there early return/error handling?

2. **Input Feasibility**: Can an attacker actually provide the required input?
   - Is the input path network-reachable?
   - Does the protocol allow the required input format?

3. **Mitigation Check**: Is there any protection that prevents exploitation?
   - Size checks before the vulnerable call?
   - Input sanitization?
   - Compiler protections (canary, NX)?

# Output
- feasible: true/false
- reason: Detailed explanation
- recommended_action: poc_generation / discard / needs_manual_review
```

---

## 附录 B: 推荐依赖清单

```txt
# === 继承自 FuzzingBrain ===
loguru>=0.7.0
typing-extensions>=4.8.0
litellm>=1.0.0
python-dotenv>=1.0.0
pydantic>=2.0.0
rich>=13.0.0

# === REST API & Task Queue ===
fastapi>=0.109.0
uvicorn>=0.27.0
celery>=5.3.0
redis>=5.0.0

# === Database ===
pymongo>=4.6.0
motor>=3.3.0

# === 新增: 固件分析 ===
# Ghidra 通过命令行调用，不需要 Python 包

# angr - 符号执行
angr>=9.2.0

# 二进制解析
pyelftools>=0.29
lief>=0.13.0

# 固件仿真交互
pexpect>=4.8.0

# === 新增: 协议 Fuzzing ===
boofuzz>=0.4.0
scapy>=2.5.0

# === 新增: 网络交互 ===
httpx>=0.27.0
aiohttp>=3.9.0

# === 新增: 固件解包 ===
binwalk  # 通过系统包管理器安装
```