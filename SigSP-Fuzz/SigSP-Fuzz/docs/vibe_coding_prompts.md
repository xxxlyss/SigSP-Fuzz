# Vibe Coding 提示词指南：FuzzingBrain V2 固件移植

本文提供可直接复制给大模型（Claude/GPT-4/Qwen-Coder）的提示词模板，分两步实现核心移植：**MCP工具链**和**双层Fuzzing**。

---

## 前置准备：给大模型的项目上下文

在正式开始前，先把你的项目结构告诉大模型。创建一个叫 `PROJECT_CONTEXT.md` 的文件，贴入以下内容：

```markdown
# 项目上下文

## 现有代码结构
```
├── fuzzingbrain/
│   ├── __init__.py
│   ├── analyzer.py          # 主分析器（LLM Agent调度）
│   ├── sp_generator.py      # Suspicious Point生成
│   ├── validator.py         # SP验证（PoC确认）
│   ├── fuzzer_manager.py    # Fuzzer管理（当前是libFuzzer封装）
│   ├── report_generator.py  # 报告生成
│   └── models.py            # 数据模型（SP, Direction, PoC等）
├── scripts/
│   └── ghidra_export.py     # Ghidra Java导出脚本
├── tests/
│   └── test_analyzer.py
├── requirements.txt
└── README.md
```

## 当前技术栈
- Python 3.10+
- OpenAI API / Anthropic API（LLM调用）
- libFuzzer（当前Fuzzing后端）
- MongoDB（数据存储）
- Redis（任务队列）

## 目标
将FuzzingBrain V2从源码级漏洞分析移植到固件二进制分析，
核心替换：libFuzzer → QEMU-AFL，源码SAST → Ghidra二进制SAST。
```

**使用方式**：每个提示词开头都附上这份上下文。

---

## 第一步：MCP工具链 —— 让LLM Agent能调用Ghidra和QEMU

### 提示词 1.1：创建MCP服务器框架

```
基于以下项目上下文，我需要实现一个MCP（Model Context Protocol）服务器，
让LLM Agent能够通过统一接口调用Ghidra和QEMU工具。

请创建文件 mcp_server/firmware_tools.py，实现以下内容：

1. 一个基类 FirmwareTool，所有工具继承它
2. 工具注册机制：用装饰器 @register_tool 自动注册
3. 至少实现以下工具：

   SAST工具（调用Ghidra）：
   - decompile_function(binary_path: str, func_addr: int) -> str
     反编译指定地址的函数，返回类C伪代码
   - get_callers(binary_path: str, func_addr: int) -> list[int]
     获取调用该函数的函数地址列表
   - get_callees(binary_path: str, func_addr: int) -> list[int]
     获取该函数调用的函数地址列表
   - find_string_xrefs(binary_path: str, target_string: str) -> list[int]
     查找引用目标字符串的代码地址
   - get_function_bounds(binary_path: str, addr: int) -> dict
     识别包含该地址的函数边界 {start, end, name}

   DAST工具（调用QEMU）：
   - start_emulator(firmware_path: str, arch: str, machine: str) -> str
     启动QEMU仿真器，返回实例ID
   - stop_emulator(instance_id: str) -> bool
     停止指定仿真器实例
   - inject_input(instance_id: str, data: bytes, interface: str) -> dict
     向仿真设备注入输入（network/uart/file），返回覆盖率
   - get_coverage(instance_id: str) -> dict
     获取当前覆盖率数据 {edges, total_edges, coverage_percent}
   - read_memory(instance_id: str, addr: int, size: int) -> bytes
     读取仿真器内存
   - set_breakpoint(instance_id: str, addr: int) -> bool
     在目标地址设置断点

4. 每个工具要有：
   - 清晰的docstring（LLM靠这个理解工具用途）
   - 输入参数类型注解
   - 错误处理（工具失败时返回结构化错误信息）
   - 执行超时保护（默认30秒）

5. 在模块底部创建一个 ToolRegistry 类：
   - list_tools() -> 返回所有注册工具的列表（含名称、描述、参数schema）
   - execute_tool(name: str, params: dict) -> 执行指定工具

这个ToolRegistry的输出格式要兼容OpenAI Function Calling格式。

请确保代码：
- 类型注解完整
- 有适当的日志记录（使用loguru）
- 单元测试覆盖每个工具的基础调用
```

### 提示词 1.2：实现Ghidra桥接

```
现在我需要实现Ghidra桥接层，让Python能调用Ghidra进行二进制分析。

请创建文件 mcp_server/ghidra_bridge.py，实现 GhidraBridge 类：

核心设计：
1. Ghidra运行在headless模式，通过JSON文件交换数据
2. Python端写入请求文件 → 触发Ghidra分析 → 读取结果JSON

具体实现：

class GhidraBridge:
    def __init__(self, ghidra_home: str, project_dir: str):
        """初始化Ghidra桥接"""
    
    def analyze_binary(self, binary_path: str) -> str:
        """
        对二进制进行完整分析，导入Ghidra项目，反编译所有函数。
        返回分析项目的路径。
        """
    
    def decompile_function(self, binary_path: str, func_addr: int) -> str:
        """
        反编译指定地址的函数。
        内部流程：
        1. 检查该binary是否已分析，未分析则调用analyze_binary
        2. 生成Ghidra headless命令，运行导出脚本
        3. 读取反编译结果
        返回：类C伪代码字符串
        """
    
    def export_call_graph(self, binary_path: str) -> dict:
        """
        导出调用图。
        返回：{func_addr: {"callers": [...], "callees": [...], "name": ...}}
        """
    
    def export_strings(self, binary_path: str) -> list[dict]:
        """
        导出二进制中所有字符串及其交叉引用。
        返回：[{"string": "...", "address": 0x..., "xrefs": [0x...]}]
        """
    
    def _run_ghidra_headless(self, binary_path: str, script_name: str, 
                             script_args: list[str]) -> dict:
        """
        运行Ghidra headless模式的内部方法。
        使用subprocess调用，带超时保护（默认5分钟）。
        返回解析后的JSON结果。
        """

关键要求：
1. 要有Ghidra Java导出脚本的模板（内嵌在Python中，运行时写入临时文件）
2. 分析结果缓存：同一个binary的分析结果缓存30分钟
3. 并发安全：多线程调用时通过文件锁防止Ghidra冲突
4. 大二进制处理：如果binary > 50MB，只分析.text段中的函数
5. 错误处理：Ghidra崩溃时返回清晰的错误信息

请同时更新 mcp_server/firmware_tools.py 中的SAST工具，
让它们实际调用GhidraBridge而不是返回mock数据。
```

### 提示词 1.3：实现QEMU桥接

```
接下来实现QEMU桥接层，用于固件仿真和动态分析。

请创建文件 mcp_server/qemu_bridge.py，实现 QEMUBridge 类：

核心设计：
1. 每个固件启动一个独立的QEMU进程
2. 通过QEMU monitor（UNIX socket）控制
3. 覆盖率通过QEMU的TCG插件收集

class QEMUInstance:
    """单个QEMU仿真实例"""
    def __init__(self, firmware_path: str, arch: str, machine: str = None):
        self.instance_id = uuid.uuid4().hex[:8]
        self.firmware_path = firmware_path
        self.arch = arch  # "mips", "arm", "x86_64"等
        self.machine = machine
        self.process = None
        self.monitor_socket = None
        self.snapshot_path = None
        
    def start(self) -> bool:
        """启动QEMU进程，配置网络、磁盘、覆盖率追踪"""
    
    def stop(self) -> bool:
        """优雅关闭QEMU"""
    
    def create_snapshot(self, name: str) -> bool:
        """创建VM快照（用于Worker快速恢复）"""
    
    def restore_snapshot(self, name: str) -> bool:
        """从快照恢复"""
    
    def inject_network(self, data: bytes, 
                       proto: str = "tcp", 
                       target_host: str = "10.0.2.15",
                       target_port: int = 80) -> dict:
        """通过网络接口注入输入"""
    
    def inject_uart(self, data: bytes) -> dict:
        """通过UART串口注入输入"""
    
    def get_coverage(self) -> dict:
        """获取当前TCG覆盖率"""
        return {
            "edges": int,           # 已覆盖的边数
            "total_edges": int,     # 总边数
            "coverage_percent": float,
            "new_edges_this_run": int
        }
    
    def read_memory(self, addr: int, size: int) -> bytes:
        """读取Guest物理内存"""
    
    def write_memory(self, addr: int, data: bytes) -> bool:
        """写入Guest物理内存"""
    
    def set_breakpoint(self, addr: int) -> bool:
        """设置软件断点"""

class QEMUBridge:
    """QEMU实例管理器"""
    def __init__(self, max_instances: int = 4):
        self.instances: dict[str, QEMUInstance] = {}
        self.max_instances = max_instances
    
    def create_instance(self, firmware_path: str, 
                        arch: str, machine: str = None) -> str:
        """创建新实例，返回instance_id"""
    
    def destroy_instance(self, instance_id: str) -> bool:
        """销毁实例"""
    
    def get_instance(self, instance_id: str) -> QEMUInstance:
        """获取实例对象"""
    
    def list_instances(self) -> list[dict]:
        """列出所有运行中的实例"""

关键要求：
1. 架构支持：MIPS（malta/mipssim）、ARM（vexpress-a9）、x86_64（pc）
2. 自动检测arch：通过binwalk/readelf识别固件架构
3. 覆盖率追踪：使用QEMU的tcg-plugin或afl-qemu-mode
4. 快照管理：快照存储在/tmp/qemu_snapshots/，自动清理过期快照
5. 网络配置：使用user mode networking，SLiRP
6. 内存限制：每个QEMU实例最多512MB RAM
7. 健康检查：定期ping QEMU monitor，无响应时自动重启

请同时更新 mcp_server/firmware_tools.py 中的DAST工具，
让它们实际调用QEMUBridge。
```

### 提示词 1.4：让Agent能实际调用工具（ReAct循环）

```
现在我需要让LLM Agent能够自主调用这些工具。

请修改 fuzzingbrain/analyzer.py，实现带工具调用的ReAct循环：

class FirmwareAnalyzer:
    """固件分析器 — 带工具调用的LLM Agent"""
    
    def __init__(self, llm_client, tool_registry: ToolRegistry):
        self.llm = llm_client
        self.tools = tool_registry
        self.memory = []  # 对话历史/记忆
    
    async def analyze_firmware(self, firmware_path: str) -> AnalysisReport:
        """
        主分析流程：
        1. 提取固件文件系统（binwalk）
        2. 识别关键二进制（web服务器、协议处理器等）
        3. 对每个关键binary：
           a. 用Direction Agent识别业务功能/攻击面
           b. 用SP Generator生成Suspicious Points
           c. 用Validator验证SP（通过QEMU Fuzzing）
        4. 汇总报告
        """
    
    async def _react_loop(self, task: str, context: dict, 
                          max_iterations: int = 10) -> dict:
        """
        ReAct循环：
        
        Thought → Action → Observation → ... → Answer
        
        每轮：
        1. 构建prompt（任务描述 + 当前context + 可用工具列表 + 历史记忆）
        2. 调用LLM，让它决定：
           - Thought: 思考下一步该做什么
           - Action: 调用哪个工具，传入什么参数
           - 或 Answer: 直接给出结论
        3. 如果Action：执行工具，获取Observation
        4. 将Thought/Action/Observation加入记忆
        5. 进入下一轮
        
        终止条件：
        - LLM输出Answer
        - 达到max_iterations
        - 连续3轮工具调用无新信息
        """
    
    def _build_tool_prompt(self, task: str, context: dict) -> str:
        """
        构建给LLM的prompt，包含：
        - 当前任务
        - 已收集的信息
        - 可用工具列表（含名称、描述、参数schema）
        - 调用格式示例
        """
        # 格式示例：
        # {
        #   "thought": "我需要先反编译这个函数来理解它的逻辑",
        #   "action": {
        #     "tool": "decompile_function",
        #     "params": {"binary_path": "/tmp/fw/httpd", "func_addr": 134512340}
        #   }
        # }

关键要求：
1. Prompt中要清晰描述每个工具的用途和使用场景（LLM靠prompt理解工具）
2. 工具调用失败时，将错误信息反馈给LLM，让它决定重试或换工具
3. 记忆管理：防止context window溢出，超过阈值时摘要旧记忆
4. 并行工具调用：独立工具可同时执行（如同时反编译多个函数）
5. 超时保护：单轮ReAct最多60秒，整个分析最多30分钟

请确保ReAct循环的日志清晰可读，每轮打印：
[Round N] Thought: ...
[Round N] Action: tool_name(params)
[Round N] Observation: ... (truncated to 200 chars)
```

---

## 第二步：双层Fuzzing —— QEMU-AFL + 快照恢复

### 提示词 2.1：创建固件Fuzzer基类

```
基于已完成的MCP工具链，现在我需要实现双层Fuzzing架构。

请创建文件 fuzzingbrain/firmware_fuzzer.py，实现以下内容：

1. FirmwareFuzzer 抽象基类：

class FirmwareFuzzer(ABC):
    """固件Fuzzer抽象基类"""
    
    @abstractmethod
    def start(self, binary_path: str, attack_surface: dict) -> str:
        """启动Fuzzer，返回fuzzer_id"""
    
    @abstractmethod
    def stop(self, fuzzer_id: str) -> bool:
        """停止Fuzzer"""
    
    @abstractmethod
    def get_coverage(self, fuzzer_id: str) -> dict:
        """获取覆盖率"""
    
    @abstractmethod
    def get_crashes(self, fuzzer_id: str) -> list[CrashInfo]:
        """获取崩溃列表"""
    
    @abstractmethod
    def inject_seed(self, fuzzer_id: str, seed: bytes) -> bool:
        """注入种子输入"""

2. CrashInfo 数据类：

@dataclass
class CrashInfo:
    crash_id: str
    input_data: bytes          # 触发崩溃的输入
    crash_type: str            # "heap-buffer-overflow", "stack-buffer-overflow", 
                               # "use-after-free", "null-deref"等
    crash_address: int         # 崩溃地址
    sanitizer_output: str      # Sanitizer完整输出
    stack_trace: list[int]     # 调用栈（地址列表）
    func_where: str            # 崩溃所在函数
    poc_guidance: str = ""     # LLM生成的PoC指导

3. 覆盖率数据类：

@dataclass  
class CoverageInfo:
    edges: int
    total_edges: int
    coverage_percent: float
    new_edges_last_minute: int
    bitmap_file: str           # AFL bitmap文件路径
```

### 提示词 2.2：实现Global Fuzzer（基于QEMU-AFL）

```
请创建文件 fuzzingbrain/global_fuzzer.py，实现 GlobalFirmwareFuzzer 类：

class GlobalFirmwareFuzzer(FirmwareFuzzer):
    """
    Global Fuzzer — 持续运行的覆盖率引导Fuzzing。
    
    职责：
    - 快速覆盖固件中的大量代码路径
    - 发现"浅层"漏洞（无需复杂输入构造）
    - 为SP Fuzzer提供基线覆盖率数据
    """
    
    def start(self, binary_path: str, attack_surface: dict) -> str:
        """
        启动Global Fuzzer：
        
        1. 识别固件架构和入口点
        2. 构造初始种子集（基于attack_surface）：
           - HTTP: 标准GET/POST请求
           - UPnP: SSDP M-SEARCH消息
           - Telnet: 连接协商序列
        3. 启动QEMU-AFL：
           afl-fuzz -Q -i seeds/ -o finds/ -- qemu-mipsel ./httpd @@
        4. 持续运行，定期报告覆盖率
        
        返回fuzzer_id
        """
    
    def get_coverage_trend(self, fuzzer_id: str, 
                           minutes: int = 10) -> list[dict]:
        """
        获取覆盖率变化趋势。
        返回：[{"timestamp": ..., "edges": ..., "coverage": ...}]
        用于判断Fuzzing是否进入平台期。
        """
    
    def is_plateaued(self, fuzzer_id: str, 
                     window_minutes: int = 5,
                     threshold: float = 0.01) -> bool:
        """
        判断Fuzzing是否进入平台期：
        - 最近window_minutes内新边增长 < threshold
        - 如果是，可以停止或切换策略
        """
    
    def get_hotspots(self, fuzzer_id: str, top_n: int = 20) -> list[dict]:
        """
        获取覆盖率热点 — 被频繁执行但尚未触发崩溃的代码区域。
        这些是SP Generator应重点关注的区域。
        
        返回：[{"func_addr": ..., "func_name": ..., 
                "hit_count": ..., "covered_edges": ...}]
        """

关键要求：
1. 架构自动检测：通过readelf/binwalk识别MIPS/ARM/x86
2. 多架构AFL：使用afl-qemu-mode或unicorn-afl
3. 种子生成：根据attack_surface自动生成协议特定的初始种子
4. 持续监控：每30秒采集一次覆盖率，存储在Redis
5. 资源限制：单个Global Fuzzer最多运行30分钟
6. 优雅退出：停止时保存当前语料库（corpus），供SP Fuzzer复用
```

### 提示词 2.3：实现SP Fuzzer（定向Fuzzing）

```
请创建文件 fuzzingbrain/sp_fuzzer.py，实现 SPFirmwareFuzzer 类：

class SPFirmwareFuzzer(FirmwareFuzzer):
    """
    SP Fuzzer — 针对Suspicious Point的定向深度Fuzzing。
    
    职责：
    - 在Global Fuzzer发现的SP附近进行深度探索
    - 构造精确触发条件的输入（需要LLM Agent辅助）
    - 专门攻克跨函数复杂依赖的漏洞
    
    与Global Fuzzer的核心区别：
    - Global：随机变异，广泛探索
    - SP：基于LLM对SP的理解，生成语义有效的输入
    """
    
    def start(self, binary_path: str, 
              suspicious_point: SuspiciousPoint,
              global_corpus_path: str = None) -> str:
        """
        启动SP Fuzzer：
        
        1. 从SP中提取关键信息：
           - 目标函数地址
           - 触发条件描述（LLM生成的自然语言）
           - 所需输入类型（HTTP/UPnP/UART）
        
        2. 创建仿真器快照（从Global Fuzzer的状态恢复）
        
        3. LLM Agent生成定向输入模板：
           基于SP的描述，LLM生成"应该能触发该代码路径"的输入结构
           
        4. 基于模板的结构化Fuzzing：
           - 保持输入结构不变
           - 变异关键字段（长度、特殊字符、边界值）
           
        5. 断点引导：
           - 在SP的代码地址设断点
           - Fuzzer优先奖励到达断点的输入
        
        6. 持续运行直到：
           - 触发崩溃（ASan报警）
           - 到达迭代上限（默认1000轮）
           - 确认SP不可触发（误报）
        """
    
    async def _generate_input_template(self, sp: SuspiciousPoint) -> dict:
        """
        调用LLM Agent，基于SP描述生成输入模板。
        
        例如对于SP：
        "在HTTP POST请求处理中，Content-Length头的值被直接用于
         memcpy的目标大小，未验证是否小于缓冲区256字节"
        
        LLM生成模板：
        {
          "method": "POST",
          "path": "/cgi-bin/config",
          "headers": {
            "Content-Length": "{{MUTATE: range(0, 1024)}}",
            "Content-Type": "application/x-www-form-urlencoded"
          },
          "body": "{{MUTATE: length_from_Content_Length}}"
        }
        """
    
    def _reward_breakpoint_hit(self, fuzzer_id: str, 
                                bp_addr: int) -> None:
        """
        当输入到达断点时，给予额外奖励（增加在corpus中的权重）。
        这引导Fuzzer向SP方向深入。
        """
    
    def verify_sp(self, fuzzer_id: str, 
                  sp: SuspiciousPoint) -> VerificationResult:
        """
        验证SP是否为真实漏洞：
        
        1. 如果能触发崩溃 → CONFIRMED_VULN
        2. 如果能到达SP但无崩溃 → NEEDS_MANUAL_REVIEW
        3. 如果无法到达SP → FALSE_POSITIVE
        
        返回VerificationResult，包含：
        - 验证状态
        - 触发输入（如有）
        - Sanitizer输出
        - LLM生成的PoC指导
        """

@dataclass
class VerificationResult:
    status: str  # "CONFIRMED" | "NEEDS_REVIEW" | "FALSE_POSITIVE"
    crash_info: Optional[CrashInfo]
    poc_input: Optional[bytes]
    poc_guidance: str
    verification_time: float
```

### 提示词 2.4：快照恢复系统

```
请创建文件 fuzzingbrain/snapshot_manager.py，实现 SnapshotManager 类：

这是双层Fuzzing性能的关键 — Global Fuzzer的状态需要快速传递给SP Fuzzer。

class SnapshotManager:
    """
    QEMU仿真器快照管理器。
    
    核心功能：
    - Global Fuzzer运行一段时间后创建快照
    - SP Fuzzer从快照恢复，跳过漫长的启动过程
    - 支持多级快照（基线 → 特定攻击面 → 特定SP）
    """
    
    def __init__(self, snapshot_dir: str = "/tmp/qemu_snapshots"):
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
    
    def create_snapshot(self, instance_id: str, 
                        snapshot_name: str,
                        metadata: dict = None) -> str:
        """
        为指定QEMU实例创建快照。
        
        流程：
        1. 通过QEMU monitor发送 "savevm name" 命令
        2. 等待快照完成
        3. 记录metadata（创建时间、覆盖率状态、关联的binary/SP）
        4. 返回快照文件路径
        """
    
    def restore_snapshot(self, instance_id: str,
                         snapshot_name: str) -> bool:
        """
        从快照恢复QEMU实例。
        
        目标恢复时间 < 5秒（vs 冷启动30-60秒）。
        """
    
    def get_or_create_baseline(self, binary_path: str,
                                arch: str,
                                attack_surface: dict) -> str:
        """
        获取或创建基线快照。
        
        基线快照 = 固件启动完成 + 基本服务就绪 + 初始覆盖率收集
        这是Global Fuzzer的起始状态。
        
        如果已存在该binary的基线快照（24小时内），直接复用。
        """
    
    def create_sp_snapshot(self, baseline_snapshot: str,
                           sp: SuspiciousPoint,
                           global_corpus: str) -> str:
        """
        为SP Fuzzer创建专用快照。
        
        从基线快照恢复后：
        1. 注入Global Fuzzer的语料库（达到基线覆盖）
        2. 在SP地址设置断点
        3. 保存为新的SP专用快照
        
        SP Fuzzer从此快照启动，立即拥有Global Fuzzer的覆盖成果。
        """
    
    def cleanup_old_snapshots(self, max_age_hours: int = 24):
        """清理过期快照，防止磁盘占满"""
    
    def list_snapshots(self, binary_path: str = None) -> list[dict]:
        """列出可用快照"""

关键性能指标：
- 创建快照时间： < 10秒
- 恢复快照时间： < 5秒
- 快照文件大小： < 原始固件的2倍
- 并发支持：同时管理20+快照
```

### 提示词 2.5：Fuzzer编排器（整合Global + SP）

```
最后，请创建文件 fuzzingbrain/fuzzer_orchestrator.py，
整合Global Fuzzer和SP Fuzzer，实现完整的双层Fuzzing编排：

class FuzzerOrchestrator:
    """
    Fuzzer编排器 — 协调Global Fuzzer和SP Fuzzer的协作。
    
    工作流程：
    1. 启动Global Fuzzer，进行广泛探索（5-10分钟）
    2. 收集覆盖率热点，生成初始Suspicious Points
    3. 对每个SP启动SP Fuzzer进行定向验证
    4. 汇总结果，生成最终报告
    """
    
    def __init__(self, global_fuzzer: GlobalFirmwareFuzzer,
                 sp_fuzzer: SPFirmwareFuzzer,
                 snapshot_manager: SnapshotManager,
                 sp_generator: SPGenerator,
                 max_parallel_sp: int = 4):
        self.global_fuzzer = global_fuzzer
        self.sp_fuzzer = sp_fuzzer
        self.snapshot_mgr = snapshot_manager
        self.sp_generator = sp_generator
        self.max_parallel_sp = max_parallel_sp
        self.results = []
    
    async def run(self, firmware_path: str, 
                  attack_surfaces: list[dict]) -> FuzzingReport:
        """
        主编排流程：
        
        Phase 1: 全局探索（Global Fuzzing）
        ─────────────────────────────────────
        1. 对每个attack_surface启动Global Fuzzer
        2. 并行运行5-10分钟
        3. 收集覆盖率热点和崩溃
        
        Phase 2: SP生成（静态分析 + LLM推理）
        ─────────────────────────────────────
        4. Global Fuzzer的覆盖率热点 → SP Generator
        5. Ghidra反编译热点函数 → LLM Agent分析 → 生成SP列表
        6. 去重、排序
        
        Phase 3: 定向验证（SP Fuzzing）
        ─────────────────────────────────────
        7. 创建基线快照（Global Fuzzer的最佳状态）
        8. 对每个SP（最多max_parallel_sp个并行）：
           a. 从基线快照恢复
           b. 启动SP Fuzzer
           c. 收集验证结果
        
        Phase 4: 报告生成
        ─────────────────────────────────────
        9. 汇总所有CONFIRMED的漏洞
        10. 生成带PoC的漏洞报告
        """
    
    async def _run_global_phase(self, firmware_path: str,
                                 attack_surfaces: list[dict],
                                 duration_minutes: int = 10) -> GlobalResult:
        """Phase 1实现"""
    
    async def _run_sp_generation_phase(self, 
                                        global_result: GlobalResult) -> list[SuspiciousPoint]:
        """Phase 2实现"""
    
    async def _run_sp_verification_phase(self,
                                          firmware_path: str,
                                          sp_list: list[SuspiciousPoint],
                                          baseline_snapshot: str) -> list[VerificationResult]:
        """Phase 3实现 — 使用asyncio.gather并行运行多个SP Fuzzer"""
    
    def _generate_report(self, 
                         verified_sps: list[VerificationResult]) -> FuzzingReport:
        """Phase 4实现"""

@dataclass
class FuzzingReport:
    firmware_path: str
    analysis_duration: float
    global_coverage: CoverageInfo
    total_sps_generated: int
    total_sps_verified: int
    confirmed_vulns: list[VerificationResult]
    needs_review: list[VerificationResult]
    false_positives: list[VerificationResult]
    summary: str  # LLM生成的自然语言摘要

关键要求：
1. 进度可视化：每阶段打印进度条和ETA
2. 故障隔离：单个SP Fuzzer崩溃不影响其他SP
3. 资源管理：严格控制同时运行的QEMU实例数
4. 中断恢复：支持Ctrl+C中断，下次从断点恢复
5. 报告格式：兼容SARIF标准，可导入其他安全工具
```

---

## 第三步：整合与测试

### 提示词 3.1：主入口整合

```
请更新项目的入口文件，整合MCP工具链和双层Fuzzing：

1. 创建 fuzzingbrain/cli.py — 命令行入口：

$ python -m fuzzingbrain analyze-firmware \
    --firmware router_firmware.bin \
    --arch mips \
    --attack-surfaces http,upnp,telnet \
    --output report.json \
    --timeout 3600

2. 创建 docker-compose.yml：
   - fuzzingbrain 服务（Python应用）
   - ghidra 服务（headless模式）
   - redis 服务（任务队列）
   - mongodb 服务（数据存储）

3. 创建 Dockerfile：
   - 基于 ubuntu:22.04
   - 安装Ghidra、QEMU、AFL++、binwalk
   - 安装Python依赖
   - 暴露API端口

4. 更新 README.md，包含：
   - 快速开始（Docker一键启动）
   - 架构说明
   - 配置选项
   - 示例输出
```

### 提示词 3.2：端到端测试

```
请创建 tests/test_firmware_pipeline.py，实现端到端测试：

使用一个公开的有漏洞的固件样本（如Damn Vulnerable Router Firmware），
验证完整pipeline：

1. 固件提取 → 文件系统识别
2. 关键binary发现 → httpd
3. Ghidra分析 → 反编译函数
4. Direction生成 → HTTP请求处理
5. SP生成 → 识别strcpy缓冲区溢出
6. Global Fuzzing → 覆盖率提升
7. SP Fuzzing → 触发崩溃
8. 报告生成 → 包含PoC

每个测试用例断言：
- 发现的SP数量 > 0
- 确认的漏洞数量 > 0
- 报告包含有效的PoC输入
- 总分析时间 < 30分钟
```

---

## 使用建议

### 推荐的vibe coding流程

```
Round 1: 提示词 1.1 → 1.2 → 1.3（MCP基础框架）
    ↓ 测试：decompile_function 能正确调用Ghidra
Round 2: 提示词 1.4（ReAct循环）
    ↓ 测试：Agent能自主决定反编译哪个函数
Round 3: 提示词 2.1 → 2.2（Global Fuzzer）
    ↓ 测试：QEMU-AFL能在固件上运行并产生覆盖率
Round 4: 提示词 2.3 → 2.4（SP Fuzzer + 快照）
    ↓ 测试：SP Fuzzer从快照恢复 < 5秒
Round 5: 提示词 2.5（编排器）
    ↓ 测试：完整pipeline端到端
Round 6: 提示词 3.1 → 3.2（整合 + 测试）
```

### 每轮验证 checklist

- [ ] 新代码能导入无报错
- [ ] 单元测试通过
- [ ] 与已有代码无冲突
- [ ] 日志输出清晰可读
- [ ] 错误处理完善（不抛裸异常）

### 常见问题的修复提示词

**如果Agent不调用工具，只是文本回复：**
```
Agent没有正确调用工具，而是在文本中描述要做什么。
请检查：
1. tool prompt中是否包含清晰的调用格式示例
2. LLM的function calling模式是否正确配置
3. 是否在system prompt中强制要求使用工具
```

**如果QEMU启动太慢：**
```
QEMU启动固件需要60秒以上，请优化：
1. 实现预创建基线快照机制（analyze时创建，fuzz时恢复）
2. 使用快照恢复替代冷启动
3. 并行管理多个快照实例
```

**如果Ghidra分析大固件超时：**
```
分析50MB+的固件时Ghidra超时，请优化：
1. 只分析.text段中的函数
2. 增量分析：已分析的binary跳过
3. 增加超时到10分钟
4. 大binary使用简化分析模式
```
