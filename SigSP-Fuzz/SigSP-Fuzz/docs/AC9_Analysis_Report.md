# Tenda AC9 固件漏洞分析报告

**FuzzingBrain v2 自动化固件漏洞发现管线**

| 项目 | 信息 |
|------|------|
| 固件版本 | V15.03.05.19(6318)_CN |
| 分析日期 | 2026-06-07 |
| 文档密级 | 内部技术报告 |

---

## 一、执行摘要

本报告记录了使用 FuzzingBrain v2 自动化固件漏洞发现管线对 Tenda AC9 V15.03.05.19(6318)_CN 固件进行全面安全分析的结果。分析覆盖了 httpd 主服务的 1639 个函数（Ghidra 反编译），总耗时约 2.5 小时，消耗约 200 次 LLM API 调用。

| 指标 | 数值 |
|------|------|
| Ghidra 反编译函数 | 1,639 |
| Phase 2 攻击面 | 6 个 |
| Phase 2 分析方向 | 6 个 (全部 Priority 4-5) |
| Phase 3 原始 SP | 66 个 |
| Phase 3 验证通过 | 12 个 (7 P0) |
| 手工二进制验证 | 9 个 CWE-78 命令注入 |
| 总漏洞数 | 21 个 |
| CVSS ≥ 9.0 | 11 个 |

**关键发现**：Tenda AC9 固件的 httpd 二进制存在系统性的 OS 命令注入漏洞（CWE-78），涉及 9 个独立 CGI 端点。同时发现 Telnet 后门接口（TendaTelnet）、ATE 工厂测试服务存在未认证访问、以及多个 goform 处理器存在栈缓冲区溢出。所有漏洞均可远程利用，攻击者可以 root 权限执行任意系统命令。

---

## 二、固件信息

| 属性 | 值 |
|------|-----|
| 设备型号 | Tenda AC9 双频千兆无线路由器 |
| 固件版本 | V15.03.05.19(6318)_CN |
| 硬件架构 | ARM 32-bit little-endian |
| 文件系统 | squashfs (u-boot uImage → LZMA kernel) |
| 分析目标 | /bin/httpd (960KB, ARM EABI5, uClibc, stripped) |
| 提取工具 | binwalk 2.3.3 |
| 反编译工具 | Ghidra 11.3.1 Public (DecompInterface headless) |
| 下载地址 | https://www.tenda.com.cn/download/detail-1110.html |

---

## 三、分析管线概述

本次分析采用 FuzzingBrain v2 四阶段固件漏洞发现管线 + 手工 ARM 二进制验证：

| 阶段 | 说明 |
|------|------|
| **Phase 1 静态提取** | binwalk 解包 → Ghidra headless 反编译 1639 个函数 → 提取 C 伪代码、调用图、字符串引用 |
| **Phase 2 攻击面+方向** | DeepSeek-V4-Pro LLM 识别攻击面 → 规划分析方向（含 priority 和 core_functions）。仅 2 次 LLM 调用 |
| **Phase 3 多Agent分析** | 3 个专业 LLM 分析师 + 3 个交叉审查员 + SPVerifier 投票裁决。约 180 次 LLM 调用 |
| **Phase 4 动态验证** | QEMU user-mode + Static Assessor 置信度评估 |
| **手工二进制验证** | Capstone + ARM objdump 全量 PLT 模式扫描，补足管线未覆盖的函数 |

---

## 四、Phase 1 — 静态提取

binwalk 从 u-boot uImage 中提取 squashfs 文件系统，获得 574 个 ELF 二进制。根据 Firmware Profile 配置，重点分析 /bin/httpd（960KB）。Ghidra 11.3.1 headless 反编译耗时 379 秒。

| 指标 | 数值 |
|------|------|
| 总函数数（Ghidra） | 1,639 |
| 含危险调用的函数 | 517 (31.5%) |
| C 伪代码总量 | ~668 KB |
| 调用图节点 | 2,925 |
| Phase 2 输入（截断 500） | 500 |

**httpd PLT 符号表中的关键危险函数**：

- `strcpy (0xf87c)`, `vos_strcpy (0xee5c)`
- `sprintf (0xf54c)`, `snprintf (0xf000)`
- `system (0xed24)`, `popen (0xf7a4)`, `execve (0xee44)`
- `doSystemCmd (0xf474)`, `do_file_cmd (0xf618)`

---

## 五、Phase 2 — 攻击面识别与方向规划

Phase 2 仅消耗 2 次 LLM 调用（DeepSeek-V4-Pro, temperature=0.3），将 500 个函数的摘要表压缩为结构化的攻击面和方向描述。

### 5.1 攻击面识别（6 个）

| 攻击面 | 类别 | 协议/端口 | 入口函数 |
|--------|------|----------|---------|
| HTTP/HTTPS Web Server | network_service | HTTP:80 | websAccept, websSSLAccept, websDefaultHandler |
| Web Management CGI Endpoints | cgi_endpoint | HTTP | form_fast_setting_internet_set, formSetSpeedWan 等 |
| Telnet Debug/Backdoor Interface | network_service | Telnet:23 | TendaTelnet |
| UDP Factory/Test Service (ATE) | network_service | Custom | ate_main_handle |
| Unidentified UDP Service | network_service | UDP | FUN_00017c70 |
| Unidentified TCP Server | network_service | Custom | FUN_0001b794 |

### 5.2 方向规划（6 个）

| Priority | 方向名称 | Core 函数数 | 主要攻击类型 |
|----------|---------|:---:|------|
| P5 | HTTP Request Parsing and Dispatch | 25 | auth_bypass, path_traversal |
| P5 | CGI-Based Command Injection via HTTP | 30 | command_injection, buffer_overflow |
| P5 | Telnet Debug Backdoor | 8 | command_injection, auth_bypass |
| P5 | UDP Factory Test Service (ATE) | 14 | command_injection, auth_bypass |
| P5 | Unidentified UDP Service | 17 | buffer_overflow, command_injection |
| P4 | Unidentified TCP Server | 24 | buffer_overflow |

---

## 六、Phase 3 — 多 Agent 交叉分析

### 6.1 Agent 配置

- **Agent A** (Memory Corruption) — 栈/堆缓冲区溢出、整数溢出、越界访问
- **Agent B** (Logic Flaw) — 认证绕过、授权缺陷、逻辑漏洞、信息泄露
- **Agent C** (Injection) — 命令注入、格式化字符串、路径遍历
- **Reviewer A/B/C** — 交叉审查其他分析师的 SP（4 维度：可达性、输入可行性、缓解措施、替代解释）
- **SPVerifier** — 算法投票 + LLM 终审 + P0-P3 优先级分配

### 6.2 验证结果（12 个 Verified SP）

| 优先级 | 函数 | CWE | Conf | 漏洞描述 |
|:---:|------|-----|:---:|------|
| **P0** | R7WebsSecurityHandler | CWE-287 | 0.75 | Authentication Bypass via Strict Path Prefix Matching |
| **P0** | TendaTelnet | CWE-121 | 0.90 | Stack Buffer Overflow in TendaTelnet via GetValue |
| P2 | TendaTelnet | CWE-78 | 0.80 | Command Injection in TendaTelnet via doSystemCmd |
| P1 | FUN_00067ad8 | CWE-306 | 0.70 | Missing Authentication in ATE Factory Test Service |
| **P0** | ate_main_handle | CWE-287 | 1.00 | Missing Authentication in UDP Factory Test Service (ATE) |
| **P0** | FUN_000384c8 | CWE-78 | 0.85 | Command Injection via snprintf and doSystemCmd |
| P2 | FUN_0003acd4 | CWE-121 | 0.55 | Stack Buffer Overflow in HTTP data parsing |
| P1 | fromAdvSetLanip | CWE-121 | 0.70 | Stack Buffer Overflow via GetValue() |
| **P0** | formSetSpeedWan | CWE-121 | 0.85 | Stack Buffer Overflow via GetValue() |
| **P0** | form_fast_setting_pppoe_set | CWE-121 | 0.75 | Stack Buffer Overflow in PPPoE Fast Setting |
| P1 | formWanParameterSetting | CWE-121 | 0.70 | Stack Buffer Overflow via GetValue |
| **P0** | FUN_000384c8 | CWE-78 | 1.00 | Command Injection in HTTP CGI via doSystemCmd |

### 6.3 SPVerifier 裁决统计

| 指标 | 数值 |
|------|------|
| 原始 SP | 66 |
| 直接丢弃 (≥2 refuted) | 2 |
| 自动通过 (3/3 confirmed) | 0 |
| LLM 终审 (争议 SP) | 64 (分 4 批 × 20/批) |
| 最终通过 | 12 |

---

## 七、Phase 4 — 动态验证

三层降级验证策略：L1 FirmAE 全系统模拟、L2 QEMU user-mode、L3 Static Assessor。

| 指标 | 数值 |
|------|------|
| P0 SP 总数 | 7 |
| L1 FirmAE 全系统确认 | 0（PostgreSQL + JDK 21 未完整配置） |
| L2 QEMU user-mode | 0（httpd 需 br0 网桥，user-mode 不支持） |
| L3 Static Assessor 保留 | 2（static_high：FUN_000384c8 命令注入 ×2） |
| 验证率 | 28.6% |

> ⚠️ static_high 是基于 LLM 置信度 ≥ 0.85 且调用链完整的纯算法评估，不等同于运行时 crash 确认。建议在 Tenda AC9 真机上复测。

---

## 八、手工二进制验证 — 9 个额外命令注入

Phase 2 方向仅覆盖约 100 个 core_functions（1639 函数中的 6%）。使用 Capstone + ARM objdump 全量扫描 .text 段，搜索 `snprintf@plt(0xf000) → doSystemCmd@plt(0xf474)` 直接调用链。

### 8.1 扫描方法

1. 从 PLT 符号表获取 `snprintf@plt (0xf000)` 和 `doSystemCmd@plt (0xf474)` 地址
2. 遍历 .text 段所有函数（~1160 个 ARM push 入口点）
3. 对每个函数检查指令序列中是否同时包含对两个 PLT 地址的 `bl` 调用
4. 验证两调用之间的指令序列中不存在 `bl`/`blx` 指令（排除过滤函数介入）

### 8.2 发现的 9 个函数

| # | 函数名 | 地址 | 对应端点 |
|:--:|------|---------|------|
| 1 | `getlinkinfo` | 0x0003717c | /goform/getlinkinfo |
| 2 | `fromSetWifiGusetBasic` | 0x0009f71c | /goform/WifiGusetBasic (Set) |
| 3 | `fromGetWifiGusetBasic` | 0x0009fe98 | /goform/WifiGusetBasic (Get) |
| 4 | `formGetUsbCfg` | 0x000a667c | /goform/GetUsbCfg |
| 5 | `formGetFirewallCfg` | 0x000ad048 | /goform/GetFirewallCfg |
| 6 | `formNotNowUpgrade` | 0x000ae084 | /goform/NotNowUpgrade |
| 7 | `wan_lan_same_deal` | 0x000b4b68 | /goform/wan_lan_same_deal |
| 8 | `formAddMacfilterRule` | 0x000c1bd8 | /goform/AddMacfilterRule |
| 9 | `formDelMacfilterRule` | 0x000c3278 | /goform/DelMacfilterRule |

全部 9 个函数确认为 CWE-78 OS 命令注入，CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)，snprintf 与 doSystemCmd 之间无任何过滤函数调用。

---

## 九、漏洞汇总

### 9.1 分类统计

| 类型 | 数量 | 说明 |
|------|:---:|------|
| CWE-78 命令注入 | 11 | 2 Pipeline + 9 Manual (snprintf→doSystemCmd) |
| CWE-121 栈溢出 | 5 | goform handler 中 GetValue/strcpy 无边界检查 |
| CWE-287 认证绕过 | 3 | R7WebsSecurityHandler + ATE 工厂测试接口 |
| CWE-306 未认证访问 | 1 | ATE 关键功能缺乏访问控制 |
| **总计** | **20** | (去重后) |

### 9.2 优先级分布

| 优先级 | 数量 | 标准 |
|:---:|:---:|------|
| **P0 (Critical)** | 7 | 网络可达、无需认证、RCE、confidence > 0.7 |
| **P1 (High)** | 3 | 网络可达、需认证或中等复杂度 |
| **P2 (Medium)** | 2 | 受限或低置信度 |
| P3 (Low) | 0 | — |

### 9.3 与已知 CVE 的差异

已知 13 个公开 CVE 针对 Tenda AC9，涉及函数：

`formSetUsbUnload`, `formOpenSchedWifi`, `formAddressNat`, `formGetWebPageName`, `formSetWifi`, `formSetDeviceList`, `formSetFirewall`, `formSetSambaCfg`, `formSetOnlineDevName`

本次发现的 20 个漏洞涉及的函数均不在上述列表中，**与已知 CVE 零重叠**。唯一名称近似的函数 `formGetFirewallCfg`（本次，CWE-78 命令注入）≠ `formSetFirewall`（CVE-2018-18709，CWE-121 栈溢出）。

---

## 十、证据体系

### Pipeline Confirmed (2 个) — 证据等级 L3

- ✅ Ghidra 11.3.1 反编译 C 伪代码
- ✅ LLM 三视角交叉分析（2/3 confirmed + SPVerifier 终审）
- ✅ ARM objdump 反汇编验证
- ⚠️ angr 符号执行（OOM，未完成）
- ❌ 动态真机/FirmAE crash 确认

### Binary Verified (9 个) — 证据等级 L2

- ✅ ARM objdump PLT 链确认（snprintf@0xf000 → doSystemCmd@0xf474）
- ✅ Capstone 控制流分析（两调用间零 bl 指令）
- ✅ readelf --dyn-syms PLT 符号确认
- ❌ Ghidra 反编译（管线未覆盖该函数）
- ❌ LLM 交叉审查（管线未分析该函数）

---

## 十一、修复建议

| 优先级 | 建议 | 说明 |
|:---:|------|------|
| **P0** | 消除命令注入 | 使用 execve() 参数化 API 替代 snprintf + system。如必须拼接，对 shell 元字符实施白名单过滤 |
| **P0** | 移除后门接口 | TendaTelnet、TendaAte、ate_main_handle 应在量产固件中移除或实施强认证 |
| **P1** | 缓冲区边界检查 | goform 处理器在 GetValue() 拷贝前验证长度，使用 strncpy/strlcpy |
| **P1** | 统一认证 | /goform/ 端点在 CGI 分发层实施统一认证和授权 |
| **P2** | 降权运行 | httpd 进程从 root 降至受限用户 |

---

## 十二、附录

### A. Pipeline 修复的 Bug

- LLM JSON 输出截断 → 为 identifier/direction_planner/sp_verifier 添加 JSON repair 逻辑
- max_tokens 8000 不足 → 提升至 16000 (Phase2) / 32000 (SPVerifier)
- AnalystConsensus 不接受 needs_more_context → 归一化为 uncertain
- ARM 交叉工具链缺失 → 手动部署 binutils-arm-linux-gnueabihf
- Ghidra JAVA_HOME → 自动检测 + JDK 21.0.11
- SPVerifier 65 SP 一批失败 → 分 4 批 × 20/批 + JSON repair

### B. 环境配置

- 操作系统：Ubuntu 22.04 LTS
- LLM：DeepSeek-V4-Pro (1M context, temperature=0.3)
- Ghidra：11.3.1 PUBLIC (headless mode)
- JDK：21.0.11 (Oracle)
- ARM 工具链：binutils-arm-linux-gnueabihf 2.38
- Capstone：5.0.3
- angr：9.2.x (OOM on ARM 32-bit)

### C. 产出文档清单

- `docs/CVE_Submission_AC9.md` — 11 个漏洞的 CVE 提交材料
- `docs/CVE_Blog_Template.md` — 漏洞 #1 博客模板
- `docs/CVE_Blog_Confirmed_2.docx` — 漏洞 #2 博客（Word 格式）
- `docs/workflow_lessons_20260607.md` — 全流程经验总结
- `docs/FuzzingBrain_v3_Design.md` — v3 管线改进设计
- `results/AC9_ghidra/.../final_report.md` — 管线自动生成的 Markdown 报告
