# FuzzingBrain v3 — 固件漏洞发现管线改进设计

> 基于 v2 对 DVRF + Tenda AC9 的实战分析总结  
> 日期：2026-06-07  
> v2 累计发现：12 个 Verified SP + 9 个手工确认命令注入（0% 来自原 Direction 机制）

---

## 一、v2 的核心问题

### 问题 1：Phase 2 方向机制导致 94% 函数被跳过

```
Ghidra 提取 1639 个函数
    ↓ Phase 1 截断：500 上限
    ↓ Phase 2 Direction：每方向 5-30 core_functions，6 方向 ≈ 100
    ↓ Phase 3 实际分析：~100 个
    ↓
    被跳过：1539 个函数（94%）
```

**根因**：FuzzingBrain 原始设计针对有源码的软件分析，Direction Planer 的假设是"LLM 能从函数摘要表中挑出最重要的 30 个"。但固件中：
- 二进制 stripped（函数名 `FUN_00001234`，无语义）
- LLM 盲猜的函数名与 objdump 的函数名不匹配
- 真实漏洞函数恰好不在 LLM 选出的 `core_functions` 中

**后果**：管线 LLM 语义分析发现 12 个 SP（仅占 100 个被分析函数的 12%），手工 PLT 模式扫描额外发现 9 个命令注入（全在 Phase 2 未覆盖的函数中）。

### 问题 2：Phase 2+3 函数名匹配断裂

Phase 2 LLM 根据字符串/调用模式推断出语义化函数名（如 `httpd_handler`、`cgi_execute`），但这些名字在 stripped binary 的 Phase 1 输出中不存在，导致 Phase 3 匹配失败。

### 问题 3：动态验证缺席

Phase 4 依赖 FirmAE（需全系统模拟）或 QEMU user-mode（网络服务不可用），实际运行率 0%。angr 符号执行更轻量但未集成。

---

## 二、v3 架构设计

### 核心变更：双通道并行分析

```
Phase 1: 静态提取 (Ghidra/objdump)
    │
    ├── 通道 A：LLM 语义分析（保留）─────────┐
    │   Phase 2: 攻击面识别 + 方向规划         │
    │   Phase 3: 多 Agent 交叉分析              │ 适用于：有符号/类 C 伪代码的函数
    │   改进：方向扩大到 100 functions/dir      │
    │                                          │
    ├── 通道 B：模式匹配扫描（新增）─────────┐
    │   PatternMatcher: 直接扫描 PLT 调用链      │
    │   - snprintf→doSystemCmd                 │ 适用于：所有函数，不依赖 LLM
    │   - strcpy→sprintf→system                │
    │   - recv→strcpy→none                      │
    │   输出：PatternMatchResult (确定性证据)     │
    │                                          │
    └── Phase 4: 交叉验证 ─────────────────────┘
        通道 A 的 SP + 通道 B 的匹配 = 互补证据
        ↓
        Reviewer 阶段嵌入 angr 符号执行
        ↓
        最终 VerifiedSP (含动态证据)
```

### 2.1 通道 B：PatternMatcher 设计

不依赖 LLM，直接扫描所有函数的 PLT 调用链：

```python
class PatternMatcher:
    """扫描 ELF 二进制中的所有函数，匹配危险 PLT 调用模式"""
    
    PATTERNS = {
        # 模式名 → (危险函数链, CWE, 最小指令距离)
        "CMD_INJECT_SNPRINTF": (
            ["snprintf", "doSystemCmd"], CWE_78, 20
        ),
        "CMD_INJECT_SPRINTF": (
            ["sprintf", "system"], CWE_78, 20
        ),
        "STACK_BOF_STRCPY": (
            ["recv", "strcpy"], CWE_121, 15
        ),
        "CMD_INJECT_POPEN": (
            ["recv", "popen"], CWE_78, 15
        ),
        "FORMAT_STRING": (
            ["recv", "printf"], CWE_134, 10
        ),
    }
    
    def scan_binary(self, elf_path: str) -> List[PatternMatch]:
        """
        1. 解析 PLT 符号表
        2. 对每个函数，检查其 PLT 调用序列
        3. 如果匹配 PATTERNS 中的任一模式 + 中间无过滤函数
           → 记录为 PatternMatch
        """
        pass
```

**优势**：
- 覆盖 100% 函数（不受 Phase 2 方向限制）
- 确定性结果（无 LLM 随机性）
- 成本极低（纯 Python，< 10 秒/二进制）
- 证据可复现（PLT 地址 + 指令偏移）

### 2.2 通道 A 改进：扩大 Direction 覆盖

| 参数 | v2 | v3 |
|------|:---:|:---:|
| 每方向 core_functions 上限 | 30 | **100** |
| 方向数量上限 | 8 | **15** |
| Phase 1 函数截断 | 500 | **2000**（或按 PLT 危险度过滤） |
| Phase 3 分析模式 | 串行 | **并行**（3 方向同时跑） |

### 2.3 Phase 4 动态验证增强方案（核心改进区）

> 当前 v2 Phase 4 只做最简单的 QEMU 运行+信号捕获，覆盖率几乎为 0。
> 以下 8 个改进维度构成完整的动态验证增强路线图。

---

#### 改进 1：动态反馈闭环（Feedback Loop）

**现状**：Phase 3 → Phase 4 是单向的。LLM 生成 PoC → QEMU 跑一次 → 成功/失败。失败了没有反馈。

**改进**：建立 LLM ↔ 执行引擎之间的闭环

```
LLM 生成 PoC 输入
    │
    ▼
执行引擎（QEMU/Unicorn/FirmAE）
    │
    ├── trace:  每条执行过的指令地址序列
    ├── coverage: 哪些 basic block 被覆盖了（位图）
    ├── crash:  崩溃时的寄存器快照、栈回溯、内存 dump
    └── symbolic hints: angr 符号执行 → 到 sink 还需满足什么约束？
    │
    ▼
反馈编码器 → 自然语言描述
    "输入在第 128 字节处被 strncmp 检查拦截，没有到达 strcpy。
     修改第 128 字节为 \x00 可能绕过长度检查。"
    │
    ▼
LLM 迭代生成改进 PoC（最多 3 轮）
```

**概念解释**：

| 概念 | 含义 | 在这个项目里的用途 |
|------|------|-------------------|
| **Trace** | CPU 执行过的指令序列（地址级别） | 判断 PoC 是否真的走到了危险函数附近 |
| **Coverage** | 代码覆盖率位图（AFL 风格，每个 basic block 一个 bit） | 量化 PoC 对程序的探索深度；指导变异方向 |
| **Crash Log** | 崩溃信号、寄存器快照、栈回溯 | 崩溃去重、根因定位 |
| **Symbolic Hints** | angr 符号执行输出的路径约束 | 告诉 LLM "差什么条件才能走到 sink" |

**实现优先级**：P0（效果最显著，一次反馈循环可让触发率翻倍）
**工作量**：3-4 天

---

#### 改进 2：False Positive 再利用（FP → Seed）

**核心洞察**：被 Verifier 判为 FP 的 SP，往往代表"接近危险但被保护的代码路径"。

**应用场景**：
- SP 判为 FP 因为 "strcpy 的目标在 .data 段，不是栈" → 但它确实是用户可控的写原语
- SP 判为 FP 因为 "输入经过了长度检查" → 但检查本身可能有 off-by-one
- SP 判为 FP 因为 "需要认证" → 但认证绕过可能就是另一个漏洞

**改进**：
```python
class FPSeedGenerator:
    """从 FP 区域生成高质量 fuzzing 种子"""
    
    def generate(self, fp_sp: VerifiedSP, binary: str) -> List[Seed]:
        """
        1. 提取 FP SP 的入口函数 + 参数约束（从 LLM 分析中获取）
        2. 构造半有效的输入（满足检查条件但故意溢出/截断/注入）
        3. 将种子喂入 Global Fuzzer 或 per-SP fuzzer
        4. 目标：探索 FP 周围的代码路径，发现被 LLM 误判的漏洞
        """
```

**价值**：曾有一个被判 FP 的 SP，换一个角度看就是真实的 off-by-one（CWE-193），这在 DVRF 和 Tenda AC9 的实战中都出现过。

**优先级**：P1，工作量 2 天

---

#### 改进 3：固件 Fuzzing 可行性 & 方案

**固件能不能做 fuzz？可以，但比软件 fuzz 更麻烦。**

| 差异维度 | 软件 Fuzzing (AFL/libFuzzer) | 固件 Fuzzing |
|---------|---------------------------|-------------|
| 运行环境 | 本地 x86 进程 | 需要 MIPS/ARM 仿真 |
| 覆盖率收集 | 编译器插桩 (afl-clang) | 需要**二进制插桩**或仿真器级 hook |
| 输入投递 | 文件/stdin/参数 | 网络协议 / 共享内存 / 文件系统 |
| 崩溃检测 | OS 信号 (SIGSEGV) | 仿真器信号 + 内存访问监控 |
| 速度 | 200-1000 exec/s | 50-200 exec/s (QEMU user-mode) |

**三条可行路线**：

```
路线 A: AFL++ QEMU mode (已有基础设施)
  afl-fuzz -Q -m none -- qemu-mipsel-static -L <rootfs> <binary> @@
  优势: 开箱即用，AFL++ 自带 QEMU user-mode 覆盖率收集
  劣势: 只支持 stdin/file 输入，不支持网络协议

路线 B: UnicornEngine 裁剪仿真 (轻量)
  用 Unicorn (纯 Python CPU 仿真器) 只跑目标函数区间
  优势: 极轻量，无需全系统，可精确控制内存布局
  劣势: 需要手动处理 syscall stub、外设访问

路线 C: FirmAE 全系统快照 Fuzzing (重量)
  FirmAE 启动全系统快照 → 投递网络输入 → 收集覆盖率 → 回滚快照
  优势: 可以 fuzz 网络服务 (httpd/dnsmasq/telnetd)
  劣势: 慢 (1-5 exec/s)，需要大量内存
```

**推荐组合**：
- CLI 二进制 → 路线 A (AFL++ QEMU mode)
- 网络 daemon → 路线 C (FirmAE) 或路线 B (Unicorn 裁剪 + socket stub)

**优先级**：P0（路线 A，工作量 1 天）；P1（路线 B+C，工作量 3-5 天）

---

#### 改进 4：二进制分析与插桩（Binary Rewriting）

**概念解释**：

| 技术 | 含义 | 工具 |
|------|------|------|
| **反汇编** | 二进制 → 汇编指令 | objdump, Capstone (已实现) |
| **函数恢复** | 从 stripped binary 中识别函数边界 | Ghidra, angr CFGFast, Rizin |
| **类型恢复** | 推断函数参数类型和结构体布局 | Ghidra decompiler, angr SimType |
| **二进制 Patch** | 修改二进制指令（NOP 掉检查、替换函数调用） | LIEF, Keystone assembler |
| **Instrumentation** | 在二进制中插入监控代码（覆盖率/asan） | AFL++ QEMU mode, DynamoRIO, Frida |

**本项目的改进方向**：

```python
class BinaryInstrumentor:
    """对固件二进制做 fuzzing 友好的插桩"""
    
    def instrument(self, elf_path: str, arch: str) -> str:
        """
        1. 用 LIEF 解析 ELF
        2. 找到所有危险 sink (strcpy/system/popen)
        3. 在 sink 前插入 magic-byte 检查 (AFL 风格: __afl_area_ptr[cur_loc ^ prev_loc]++)
        4. 注入 ASAN-lite: 在 memcpy/strcpy 前插入栈 canary 检查
        5. 返回 patched ELF
        """
    
    def patch_bypass_protection(self, elf_path: str, target_func: str):
        """
        对已知保护做临时 patch:
        - NOP 掉 strncmp/strcmp 检查 → 让 fuzzer 探到深层路径
        - 替换 alarm() → 避免 fuzzer 超时
        - 替换 fork() → 改回单进程模式加速
        """
```

**优先级**：P1，工作量 3 天（集成 LIEF + Keystone）

---

#### 改进 5：自动 Harness 生成 + 多引擎适配

**问题**：当前 PoCAgent 生成的 PoC 是一个字符串 blob，但不知道怎么喂给二进制：
- CLI 程序需要 `argv[1]`
- 网络 daemon 需要 `send()` 到 socket
- CGI 需要环境变量 `QUERY_STRING`

**改进**：LLM 驱动的自动 harness 生成 + 多引擎统一接口

```python
class HarnessGenerator:
    """让 LLM 为每个 SP 生成对应的 harness 代码"""
    
    ENGINES = {
        "qemu_user": QEMUHarness,    # qemu-mipsel -L rootfs binary <input>
        "unicorn":   UnicornHarness,  # Python Unicorn 脚本
        "firmae":    FirmAEHarness,   # FirmAE scratch 脚本
        "afl":       AFLHarness,      # AFL ++ @@ stdin harness
    }
    
    def generate(self, sp: VerifiedSP, engine: str) -> str:
        """
        返回可执行的 harness 脚本/命令。
        LLM 根据:
        - SP 的 entry_function 签名（参数数量/类型）
        - attack_surface 的 protocol (stdin/TCP/UDP/HTTP/CGI)
        - binary 的 arch (mips/arm/x86)
        生成对应引擎的启动命令或 Python wrapper。
        """
```

**引擎入口配置对比**：

| 引擎 | 适用场景 | 速度 | 网络支持 | 覆盖率 |
|------|---------|:---:|:---:|:---:|
| QEMU user-mode | CLI 二进制 | 100-200/s | ❌ | ✅ (AFL++ QEMU) |
| Unicorn | 函数级仿真 | 500-2000/s | ❌ (需 stub) | ✅ (手动) |
| FirmAE | 网络 daemon | 1-5/s | ✅ | ✅ (QEMU system) |
| Firmadyne | 网络 daemon (旧) | 1-3/s | ✅ | ❌ (无覆盖率) |

**优先级**：P0 (QEMU harness)，P1 (Unicorn)，P2 (FirmAE/Firmadyne)
**工作量**：QEMU 1天，Unicorn 2天，FirmAE 3天

---

#### 改进 6：崩溃监控增强（Hook-based Oracle）

**当前问题**：QEMURunner 只检测 SIGSEGV/SIGABRT 等硬崩溃，漏掉了：
- 内存越界写但没有触发缺页（写到了合法但错误的地址）
- 命令注入成功执行但程序没有崩溃（`system("reboot")` 不会 segfault）
- 格式化字符串泄露了栈数据但没有崩溃

**改进**：多层次 Oracle 堆栈

```
Layer 1: 信号监控（现有）
  SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL
  → 硬崩溃，确定性最高

Layer 2: 内存访问监控（新增）
  Hook 每次 strcpy/memcpy → 检查 dest 是否溢出
  Hook 每次 free() → 检查 double-free / UAF
  → 需要 Unicorn hook 或 QEMU TCG plugin

Layer 3: 语义 Oracle（新增，LLM 辅助）
  system() 被调用？参数是什么？
  popen() 的参数包含用户输入？
  → LLM 判断是否构成真正的命令注入

Layer 4: 内存异常检测（新增）
  Canary 被覆盖？（插桩检测）
  返回地址被覆盖？（ASAN-lite）
  → 需要编译时或二进制插桩
```

```python
class HookBasedOracle:
    """在 QEMU/Unicorn 中 hook 关键函数，做运行时安全检查"""
    
    HOOKS = {
        "strcpy":  self._check_stack_overflow,
        "memcpy":  self._check_buffer_overflow,
        "system":  self._check_command_injection,
        "popen":   self._check_command_injection,
        "free":    self._check_double_free,
        "sprintf": self._check_format_string,
    }
    
    def _check_stack_overflow(self, cpu, dest, src):
        """检查 dest 是否在栈上 + src_len > buffer_size"""
        sp = cpu.read_register("SP")
        if dest < sp and dest + len(src) > sp:
            self.report_crash("STACK_OVERFLOW_DETECTED", dest, src)
```

**优先级**：P0 (Layer 1 已有)，P1 (Layer 2 Unicorn hooks，2天)，P2 (Layer 3 LLM oracle，1天)

---

#### 改进 7：多阶段 PoC + 会话级 Fuzzing

**问题**：当前 PoC 是单次输入 blob。但很多真实漏洞需要多步交互：
- HTTP 登录 → 获取 session token → 发送恶意请求
- TCP 握手 → 发送长度字段 → 发送 payload（分片）
- UPnP 发现 → 订阅 → 触发溢出

**改进**：状态机恢复 + 会话级 fuzzing

```python
class SessionFuzzer:
    """
    恢复协议状态机，生成多阶段 PoC 序列
    """
    
    def recover_state_machine(self, binary, attack_surface) -> StateMachine:
        """
        方法 1: 静态分析
          - 从 recv()/send() 调用序列推断状态转换
          - angr 符号执行探索不同路径

        方法 2: LLM 推断
          - 给 LLM 看反汇编 → 推断协议状态机
          - "这个 httpd 在调用 do_cgi 前经过: 
             recv_headers → parse_http → auth_check → cgi_dispatch"
        
        方法 3: 动态 Trace
          - QEMU -d exec 记录所有 recv/send 调用
          - 从 trace 中自动提取状态序列
        """
    
    def multi_stage_poc(self, sm: StateMachine) -> List[PoCStage]:
        """
        为状态机的每条边生成对应的输入
        PoC = [login_request, evil_cgi_request] 而不是单个 blob
        """
```

**优先级**：P2（需要先完成 P0/P1 的基础设施）
**工作量**：状态机恢复 2天，多阶段 PoC 2天

---

#### 改进 8：跨架构仿真增强

**问题**：QEMU user-mode 在处理固件二进制时经常挂：
- 依赖 `/dev/mem`、`/dev/gpio` 等硬件外设
- 调用 `ioctl()`、`mmap()` 访问硬件寄存器
- uClibc 静态链接的二进制依赖特定的内核接口

**改进**：Syscall Stub + 外设模型

```python
class SyscallStub:
    """为固件中常见但 QEMU 不支持的 syscall 提供 stub"""
    
    STUBS = {
        # syscall号 → stub 行为
        "ioctl":    "return 0 (假装成功)",
        "mmap":     "分配匿名内存",
        "socket":   "返回虚拟 fd",
        "bind":     "返回 0",
        "listen":   "返回 0",
        "accept":   "返回虚拟 fd (连接回 QEMU 外部)",
        "setsockopt": "返回 0",
        "fcntl":    "返回 0",
    }

class PeripheralModel:
    """模拟固件常见外设寄存器"""
    
    PERIPHERALS = {
        # 地址范围 → 行为
        (0x18000000, 0x18001000): "UART (忽略写入，返回 0x60=就绪)",
        (0x10000000, 0x10000100): "GPIO (读写内存，不做实际操作)",
        (0x1E000000, 0x1E000100): "Flash 控制寄存器 (返回 0=空闲)",
    }
```

**跨架构适配矩阵**：

| 架构 | 用户态仿真 | 全系统仿真 | 覆盖率收集 | 主要问题 |
|------|:---:|:---:|:---:|------|
| MIPS LE | ✅ qemu-mipsel | ✅ | ✅ AFL++ QEMU | uClibc 静态链接 syscall |
| ARM LE | ✅ qemu-arm | ✅ | ✅ AFL++ QEMU | Thumb 模式切换 |
| MIPS BE | ✅ qemu-mips | ✅ | ✅ AFL++ QEMU | 大端序数据解析 |
| ARM BE | ⚠️ qemu-armeb | ⚠️ | ❌ | 罕见，工具链不完善 |
| RISC-V | ⚠️ qemu-riscv64 | ✅ | ❌ | 生态不成熟 |
| PPC | ✅ qemu-ppc | ✅ | ❌ | 老旧设备，工具链缺失 |

**优先级**：P1 (syscall stub)，P2 (外设模型)
**工作量**：syscall stub 2天，外设 3-5天（需要逐设备适配）

---

## 三、证据等级体系（升级版）

| 等级 | 证据组合 | 置信度 | 适用场景 |
|:----:|---------|:---:|------|
| **L5** | LLM 语义 + PLT 模式 + angr 可达 + **AFL++ 触发 crash** | 🔴🔴🔴🔴🔴 | CVE 提交终极标准 |
| **L4** | LLM 语义 + PLT 模式 + angr 可达 | 🔴🔴🔴🔴 | CVE 提交（无真机时） |
| **L3** | LLM 语义 + PLT 模式 + **QEMU 硬崩溃** | 🔴🔴🔴 | 高置信度报告 |
| **L2** | 仅 PLT 模式匹配 + **LLM 反馈迭代 3 轮** | 🔴🔴 | 快速批量扫描 |
| **L1** | 仅 LLM 语义分析 | 🔴 | 需要人工复核 |

---

## 三-B、动态验证改进优先级总览

| 优先级 | 改进项 | 核心能力 | 预期效果 | 工作量 |
|:---:|------|------|------|:---:|
| **P0** | 反馈闭环 (改进1) | trace/crash → LLM → 改进 PoC | PoC 触发率 0% → 40%+ | 3天 |
| **P0** | AFL++ QEMU fuzzing (改进3-路线A) | 固件 fuzzing 开箱即用 | 每个 SP 可自动 fuzz | 1天 |
| **P0** | Auto harness (改进5-QEMU) | 自动生成 QEMU 启动命令 | 消除手工配置瓶颈 | 1天 |
| **P1** | Hook Oracle (改进6) | 捕获非崩溃类漏洞 | 命令注入/格式化字符串可检测 | 2天 |
| **P1** | FP→Seed 复用 (改进2) | FP 区域作为种子 | 覆盖 +10-20% 代码路径 | 2天 |
| **P1** | Binary Instrumentation (改进4) | 二进制插桩/patcher | 覆盖率收集 + 保护绕过 | 3天 |
| **P1** | Unicorn 裁剪仿真 (改进3-路线B) | 函数级精确仿真 | 500-2000 exec/s | 2天 |
| **P1** | Syscall Stub (改进8) | 外设/syscall stub | 固件兼容性 +50% | 2天 |
| **P2** | 多阶段 PoC (改进7) | 状态机恢复+会话fuzz | 覆盖有状态协议 | 4天 |
| **P2** | FirmAE 全系统 (改进3-路线C) | 网络 daemon fuzz | 覆盖 httpd/dnsmasq | 3天 |
| **P2** | 外设模型 (改进8) | 硬件寄存器模拟 | 裸机固件可仿真 | 3-5天 |
| **P2** | Unicorn harness (改进5) | Python harness 生成 | 深度定制仿真 | 2天 |

**P0 总计**: 5 天 → 动态验证基础能力建立
**P0+P1 总计**: 15 天 → 接近软件 fuzzing 的验证水平
**全部**: ~25 天 → 完整的固件动态验证平台

---

## 四、LLM 鲁棒性改进

### 4.1 通用 JSON 解析层

所有 LLM 输出点统一使用一个带自动修复的解析器：

```python
def safe_parse_json(llm_response: str, schema: type, max_tokens: int) -> dict:
    """多层回退：1.直接解析 2.去fence 3.修复截断 4.修复括号 5.降级数组"""
```

### 4.2 模型输出字段容错

- `ExploitabilityAssessment.impact` → 接受模糊匹配（`Unauthorized_Access` → 映射为 `Information_Disclosure`）
- `AnalystConsensus` 投票 → 自动归一化 `needs_more_context` → `uncertain`

### 4.3 函数名归一化

Phase 2 LLM 生成的函数名与 Phase 1 objdump/Ghidra 函数名之间建立模糊匹配层：
- 地址匹配（优先）
- 子串匹配
- PLT 调用特征匹配

---

## 五、环境部署优化

### 5.1 交叉工具链自动检测

```bash
# 启动时自动检查并安装缺失的交叉工具
for arch in arm mips mipsel; do
    check_or_install_binutils $arch
done
```

### 5.2 Ghidra 自动配置

- 自动检测 JAVA_HOME 和 JDK 版本
- 首次运行下载 JDK 21（如不存在）
- Ghidra 反编译结果缓存（同一二进制不重复分析）

### 5.3 FirmAE 降级方案

FirmAE 需要 PostgreSQL +完整系统模拟，作为可选项。默认使用：
1. angr 符号执行（轻量级路径验证）
2. QEMU user-mode + chroot（简单可执行文件验证）
3. FirmAE（全系统模拟，仅在固件兼容时）

---

## 六、实现优先级

| 优先级 | 改进项 | 预期效果 | 工作量 |
|:---:|------|------|:---:|
| **P0** | PatternMatcher（通道 B） | 函数覆盖从 6% → 100% | 2 天 |
| **P0** | Phase 2 方向扩大（500→2000 函数） | 减少过滤损失 | 半天 |
| **P1** | 通用 JSON 修复层 | 消除 LLM 输出解析失败 | 1 天 |
| **P1** | 函数名模糊匹配 | 解决 stripped binary 匹配断裂 | 1 天 |
| **P2** | angr 符号执行 Reviewer | 补上动态验证短板 | 3 天 |
| **P2** | Phase 3 并行化 | 分析时间缩短 3-6x | 2 天 |
| **P3** | Ghidra 部署自动化 | 减少环境配置时间 | 1 天 |
| **P3** | 交叉工具链自动安装 | 减少手动配置 | 半天 |

---

## 七、v2 vs v3 预期对比

| 指标 | v2 (AC9 实测) | v3 (目标) |
|------|:---:|:---:|
| Phase 3 分析函数数 | ~100 (6%) | **全部 1639 (100%)** |
| 命令注入发现数 | 2 (管线) | **11 (管线 + 模式)** |
| LLM 调用量 | ~120 次 | ~200 次（方向扩大） |
| JSON 解析失败率 | 40% (3/7 管道点) | **< 5%** |
| 动态验证覆盖率 | 0% | **> 50%**（angr 集成） |
| 单固件总耗时 | ~90 分钟 | ~60 分钟（Phase 3 并行化） |
| CVE 级证据率 | 2/12 | **> 80%**（L4 标准） |
