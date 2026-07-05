# Phase 4 PoC 动态验证 — 最终测试报告

> 日期: 2026-06-13 | 测试固件: DVRF v0.3 (MIPS LE) | QEMU: qemu-mipsel v6.2.0

---

## 一、验证架构

```
Phase 3 SPs → Phase 4 Pipeline
                  │
                  ├── 1. PoCAgent (DeepSeek-V4-Pro) → 生成 PoC
                  ├── 2. QEMURunner → 投递 PoC → 检测崩溃/RCE
                  │       ├── stdin 模式: 管道输入 (CLI 二进制)
                  │       ├── argv 模式: 命令行参数 (stack_bof_01)
                  │       └── network 模式: TCP 连接 (socket_bof)
                  ├── 3. CrashMonitor → 去重 + 分类
                  ├── 4. StaticAssessor → L3 降级 (调用链 + 置信度)
                  └── 5. ReportGenerator → JSON + Markdown 报告
```

## 二、测试结果总览

| SP ID | CWE | 输入模式 | PoC | 崩溃 | 详情 |
|-------|-----|---------|-----|------|------|
| DVRF-STACK-BOF-01 | CWE-121 | argv: 300×'A' | ✅ | 💥 SIGSEGV | 栈溢出覆盖返回地址 |
| DVRF-STACK-BOF-02 | CWE-121 | argv: 800×'A' | ✅ | 💥 SIGSEGV | 更大缓冲区，800字节触发 |
| DVRF-SOCKET-BOF-01 | CWE-121 | network: 2000×'A' | ✅ | 💥 SIGSEGV | TCP发送溢出，远程触发 |
| DVRF-SOCKET-CMDI-01 | CWE-78 | network: `;id;` | ✅ | 🔴 RCE! | execve(/bin/sh) 执行任意命令 |

**结果: 4/4 (100%) SP 动态验证成功**

- 3 个内存破坏 → 崩溃确认 (SIGSEGV)
- 1 个命令注入 → RCE 确认 (fork + execve)

## 三、各 SP 详细结果

### 3.1 DVRF-STACK-BOF-01 — argv 模式

```
二进制: pwnable/Intro/stack_bof_01 (MIPS LE, 200字节栈缓冲)
PoC:    300 个 'A' 作为 argv[1]
命令:   qemu-mipsel -L rootfs -strace stack_bof_01 AAAAAA...
结果:   SIGSEGV @ 0x41414140 (用户可控PC)
QEMU:   "uncaught target signal 11 (Segmentation fault) - core dumped"
验证:   ✅ dynamic_user (L2)
```

### 3.2 DVRF-STACK-BOF-02 — argv 模式

```
二进制: pwnable/ShellCode_Required/stack_bof_02 (MIPS LE)
PoC:    800 个 'A' 作为 argv[1] (缓冲区 >500 字节)
命令:   qemu-mipsel -L rootfs stack_bof_02 AAAAAA...
结果:   SIGSEGV — 栈溢出覆盖返回地址
验证:   ✅ dynamic_user (L2)
注:     500 字节不足以触发，800 字节才溢出
```

### 3.3 DVRF-SOCKET-BOF-01 — network 模式

```
二进制: pwnable/ShellCode_Required/socket_bof
PoC:    2000 个 'A' 通过 TCP 发送到 127.0.0.1:8888
流程:   1. qemu-mipsel socket_bof 8888 (后台启动)
        2. bind(0.0.0.0:8888) + listen(2) → 进程存活
        3. nc 127.0.0.1 8888 < payload → accept → read 溢出
结果:   SIGSEGV — 远程栈溢出
验证:   ✅ dynamic_user (L2)
修复:   端口探测改为进程存活检查(不消耗 accept)
```

### 3.4 DVRF-SOCKET-CMDI-01 — network 模式 (RCE)

```
二进制: pwnable/ShellCode_Required/socket_cmd
PoC:    ;id; 通过 TCP 发送到 127.0.0.1:8888
流程:   1. qemu-mipsel socket_cmd 8888 (后台启动)
        2. nc 发送 ";id;" → accept → read → fork → execve(/bin/sh)
结果:   execve("/bin/sh", {"sh", "-c", "echo ;id;\n"})
        实际执行: uid=1000(yxhueimie) gid=1000(yxhueimie) ...
验证:   🔴 RCE 确认 (命令注入成功，非崩溃类)
检测:   QEMU strace 中 fork + execve 序列
```

## 四、关键技术实现

### 4.1 QEMURunner 输入模式

| 模式 | 机制 | 适用场景 | 验证方法 |
|------|------|---------|---------|
| **stdin** | `subprocess.run(input=payload)` | 管道读取的 CLI 工具 | 进程崩溃检测 |
| **argv** | `cmd.append(payload)` 作为参数 | argv[1] 读取的二进制 | 进程崩溃检测 |
| **network** | Popen 后台 + nc/tcp 投递 | 网络守护进程 | 进程崩溃 + strace 分析 |

### 4.2 崩溃检测

```python
# 检测路径(按优先级):
# 1. exit code = signal_number (QEMU 旧版)
# 2. exit code = 128 + signal_number (shell 惯例)
# 3. exit code = 0 + stderr "uncaught target signal N" (QEMU 新版 with -strace)
# 4. stderr 文本匹配 "Segmentation fault" / "SIGSEGV" 等
```

### 4.3 关键修复记录

| 问题 | 根因 | 修复 |
|------|------|------|
| AC9 httpd 无法 bind | NVRAM 未初始化 | → 改用 DVRF (uClibc 兼容) |
| stack_bof 不崩溃 | 用了 stdin 而非 argv | → 添加 InputMode.ARGV |
| mips→mipsel 映射 | ARCH_TO_QEMU['mips']=qemu-mips(大端) | → 改为 qemu-mipsel(小端) |
| -strace 下崩溃检测失败 | exit code=0,"uncaught target signal" | → 正则匹配 stderr |
| 网络模式端口探测 | connect() 消耗了 daemon 的 accept() | → 改为进程存活检查 |
| PoC JSON 解析失败 | LLM 输出缺逗号等格式错误 | → 自动修复 + poc_type 别名 |

## 五、Phase 4 完整数据流

```
Phase 3 SP → PoCAgent.generate()
               │ LLM prompt: SP描述 + 攻击面 + 函数反编译
               │ ~30-100s per PoC (DeepSeek-V4-Pro)
               ▼
            PoC 对象 (JSON)
               │
               ▼
            QEMURunner.verify()
               │ detect_input_mode() → 选择合适的投递方式
               │ subprocess.run / Popen
               │ 投递 PoC payload
               │
               ▼
            CrashInfo
               │ crash_type, crash_address, signal_number
               │ backtrace, register_state
               │
               ▼
            CrashMonitor.deduplicate()
               │ 签名匹配 + ASLR 容差
               │
               ▼
            VerificationResult
               │ dynamic_user / dynamic_full / static_high / static_low
               │
               ▼
            Phase4Result → ReportGenerator → JSON + Markdown 报告
```

## 六、已知限制与改进方向

| 限制 | 影响 | 计划 |
|------|------|------|
| 网络模式仅 TCP | UDP 未实现 | 添加 `_deliver_udp` |
| AC9 httpd 需 FirmAE | ARM 固件无法验证 | 安装 FirmAE 或编译 uClibc hook |
| 命令注入需 strace 解析 | CWE-78 无法通过崩溃确认 | 添加 execve/fork 检测 |
| PoC 生成依赖 LLM | ~70s/个, 有速率限制 | 缓存 + 批量 + prompt 压缩 |
| 无并发 | 逐个 SP 串行 | ThreadPoolExecutor |

## 七、环境依赖

```
QEMU:     qemu-mipsel v6.2.0 (apt install qemu-user)
MIPS LE:  /lib/ld-uClibc.so.0 (固件自带)
Python:   3.10+ with subprocess, dataclasses
LLM:      DeepSeek-V4-Pro via Bailian (llm_config.local.yaml)
无其他依赖: 不需要 FirmAE, PostgreSQL, Docker, Chrome
```
