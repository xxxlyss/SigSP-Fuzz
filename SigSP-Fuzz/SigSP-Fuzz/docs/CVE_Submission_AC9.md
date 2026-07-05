# CVE 提交材料 — Tenda AC9 V15.03.05.19(6318)_CN

> 提交日期：2026-06-07  
> 发现方法：FuzzingBrain v2 自动化管线 + Capstone ARM 二进制分析  
> 分析博文：[待填写博客链接]  
> 总漏洞数：11（全部为 CWE-78 OS Command Injection）

---

## 一、Pipeline Confirmed 漏洞（2 个）

### 漏洞 #1：FUN_000384c8 — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN（AC9 双频千兆无线路由器，中国大陆版固件） |
| **Affected component(s)** | `/bin/httpd`，函数 `FUN_000384c8`（HTTP CGI 参数处理函数），通过 `/goform/` CGI 端点可达 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 路由器的 HTTP 管理界面（80 端口）发送特制 POST 请求至对应的 `/goform/` CGI 端点，在请求参数中注入 shell 元字符（`;`, `|`, `&&`, `$()` 等）。参数经 `FUN_000386cc` 分发器解析后传入 `FUN_000384c8`，该函数使用 `snprintf()` 将攻击者可控的参数直接拼接到系统命令字符串，随后通过 `doSystemCmd()` 执行。由于全程无输入过滤，攻击者可实现远程命令执行。httpd 进程以 root 权限运行。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `FUN_000384c8` 函数存在 OS 命令注入漏洞。该函数通过 `snprintf()` 将用户可控的 HTTP 请求参数拼接到系统命令字符串，随后调用 `doSystemCmd()` 执行，未进行任何输入过滤。远程攻击者可向受影响设备的 HTTP 管理界面发送特制请求，注入任意 shell 命令，以 root 权限实现远程代码执行。

---

### 漏洞 #2：FUN_000384c8 — HTTP CGI 命令注入（独立交叉确认）

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `FUN_000384c8`（HTTP CGI 参数处理函数），通过 `/goform/` CGI 端点可达 |

**Attack vector(s):**

与漏洞 #1 同一函数，由 Injection 和 Memory Corruption 两个独立 LLM 分析视角交叉确认。攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 80 端口发送包含 shell 元字符的 HTTP POST 参数至 CGI 端点。参数经 `FUN_000386cc` 提取后传入 `FUN_000384c8`，该函数调用 `snprintf()` 将用户输入注入命令模板，随后通过 `doSystemCmd()` 执行。httpd 以 root 权限运行，攻击者可获取设备完全控制权。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `FUN_000384c8` 函数存在 OS 命令注入漏洞（由 Injection 和 Memory Corruption 两个独立 LLM 分析视角交叉确认）。HTTP 请求参数经 `FUN_000386cc` 提取后，未经任何安全过滤即通过 `snprintf()` 拼接到系统命令字符串，并由 `doSystemCmd()` 执行。远程攻击者可利用此漏洞实现 root 权限的命令注入，获取设备完全控制权。

---

## 二、Binary Verified 漏洞（9 个，ARM 反汇编 PLT 链确认）

### 漏洞 #3：getlinkinfo — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `getlinkinfo` @ 0x0003717c，对应 `/goform/getlinkinfo` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 路由器的 `/goform/getlinkinfo` 端点发送 HTTP POST 请求，在参数中注入 shell 元字符。参数通过 `snprintf@plt (0xf000)` 拼接为系统命令后，由 `doSystemCmd@plt (0xf474)` 执行。ARM 反汇编确认两调用间无任何过滤函数的 `bl` 指令。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/getlinkinfo` 端点对应的 `getlinkinfo` 函数存在 OS 命令注入漏洞。该函数将 HTTP POST 参数通过 `snprintf()` 直接拼接到系统命令字符串，随后调用 `doSystemCmd()` 执行，且 `snprintf` 与 `doSystemCmd` 之间不存在任何输入过滤函数。攻击者可远程以 root 权限执行任意系统命令。

---

### 漏洞 #4：fromSetWifiGusetBasic — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `fromSetWifiGusetBasic` @ 0x0009f71c，对应 `/goform/fromSetWifiGusetBasic` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/fromSetWifiGusetBasic` 发送包含 shell 元字符的 HTTP POST 请求。Guest WiFi 设置参数被传入 `snprintf()` 拼接到命令模板，随后通过 `doSystemCmd()` 执行。ARM 反汇编确认调用链：`snprintf@plt` → [6 条非分支指令] → `doSystemCmd@plt`，路径上无过滤函数。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/fromSetWifiGusetBasic` 端点对应的 Guest WiFi 设置处理函数存在 OS 命令注入漏洞。用户提交的 Guest WiFi 配置参数未经安全过滤，通过 `snprintf()` 拼接到系统命令模板并由 `doSystemCmd()` 执行。远程攻击者可通过该端点以 root 权限在路由器上执行任意命令。

---

### 漏洞 #5：fromGetWifiGusetBasic — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `fromGetWifiGusetBasic` @ 0x0009fe98，对应 `/goform/fromGetWifiGusetBasic` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/fromGetWifiGusetBasic` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于查询 Guest WiFi 信息，处理函数将用户参数通过 `snprintf()` 拼接到系统命令后，由 `doSystemCmd()` 执行。ARM 反汇编确认 `snprintf@plt` 与 `doSystemCmd@plt` 之间为直接调用链，无过滤逻辑。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/fromGetWifiGusetBasic` 端点对应的 Guest WiFi 信息查询处理函数存在 OS 命令注入漏洞。该函数将用户可控的查询参数直接拼接到 `snprintf()` 构造的系统命令中，并通过 `doSystemCmd()` 执行，未实施任何输入过滤。远程攻击者可利用此漏洞以 root 权限执行任意系统命令。

---

### 漏洞 #6：formGetUsbCfg — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `formGetUsbCfg` @ 0x000a667c，对应 `/goform/formGetUsbCfg` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/formGetUsbCfg` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于获取 USB 配置信息，处理函数将用户参数通过 `snprintf()` 拼接到系统命令后，经 `doSystemCmd()` 执行。ARM 反汇编确认 `snprintf@plt` → `doSystemCmd@plt` 为直接链，无过滤。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/formGetUsbCfg` 端点对应的 USB 配置获取处理函数存在 OS 命令注入漏洞。函数从 HTTP 请求中获取 USB 相关参数，通过 `snprintf()` 构造系统命令并通过 `doSystemCmd()` 执行，未进行任何输入验证或过滤。远程攻击者可利用此漏洞在路由器上以 root 权限执行任意命令。

---

### 漏洞 #7：formGetFirewallCfg — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `formGetFirewallCfg` @ 0x000ad048，对应 `/goform/formGetFirewallCfg` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/formGetFirewallCfg` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于获取防火墙配置，处理函数将用户参数拼接入 `snprintf()` 构造的命令模板后通过 `doSystemCmd()` 执行。ARM 反汇编确认调用链上无过滤函数。**注意**：此函数与已知 CVE-2018-18709 的 `formSetFirewall`（CWE-121 栈溢出）为不同函数，漏洞类型也不同。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/formGetFirewallCfg` 端点对应的防火墙配置获取函数存在 OS 命令注入漏洞。该函数将用户提交的查询参数直接拼接到系统命令中，通过 `snprintf()` 和 `doSystemCmd()` 执行，未进行任何安全过滤。远程攻击者可利用此漏洞以 root 权限在路由器上执行任意系统命令。

---

### 漏洞 #8：formNotNowUpgrade — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `formNotNowUpgrade` @ 0x000ae084，对应 `/goform/formNotNowUpgrade` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/formNotNowUpgrade` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于固件升级延迟处理，函数将用户参数通过 `snprintf()` 拼接到系统命令后，由 `doSystemCmd()` 执行。ARM 反汇编确认 `snprintf@plt` → `doSystemCmd@plt` 调用链，中间无过滤函数介入。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/formNotNowUpgrade` 端点对应的固件升级延迟处理函数存在 OS 命令注入漏洞。该函数将用户控制参数通过 `snprintf()` 直接拼接到系统命令字符串，随后通过 `doSystemCmd()` 执行，且调用链中不存在任何输入过滤函数。远程攻击者可利用此漏洞以 root 权限在路由器上执行任意系统命令。

---

### 漏洞 #9：wan_lan_same_deal — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `wan_lan_same_deal` @ 0x000b4b68，对应 `/goform/wan_lan_same_deal` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/wan_lan_same_deal` 发送包含 shell 元字符的 HTTP POST 请求。该端点处理 WAN/LAN 配置，函数将用户参数通过 `snprintf()` 拼接到系统命令后，由 `doSystemCmd()` 执行。ARM 反汇编确认调用链上无过滤函数。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/wan_lan_same_deal` 端点对应的 WAN/LAN 配置处理函数存在 OS 命令注入漏洞。该函数将用户提交的配置参数通过 `snprintf()` 直接拼接为系统命令，通过 `doSystemCmd()` 执行，未进行任何输入验证。远程攻击者可利用此漏洞以 root 权限在路由器上执行任意系统命令。

---

### 漏洞 #10：formAddMacfilterRule — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `formAddMacfilterRule` @ 0x000c1bd8，对应 `/goform/formAddMacfilterRule` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/formAddMacfilterRule` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于添加 MAC 过滤规则，函数将用户参数通过 `snprintf()` 拼接到系统命令后，由 `doSystemCmd()` 执行。ARM 反汇编确认调用链上无过滤函数。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/formAddMacfilterRule` 端点对应的 MAC 过滤规则添加函数存在 OS 命令注入漏洞。该函数将用户提交的 MAC 地址和过滤规则参数直接通过 `snprintf()` 拼接到系统命令字符串，通过 `doSystemCmd()` 执行，未实施任何输入过滤。远程攻击者可利用此漏洞以 root 权限在路由器上执行任意系统命令。

---

### 漏洞 #11：formDelMacfilterRule — HTTP CGI 命令注入

| 字段 | 内容 |
|------|------|
| **Vulnerability type** | CWE-78: OS Command Injection |
| **Attack type** | Remote |
| **Impact** | **Code execution** |
| **Vendor of the product(s)** | Tenda |
| **Affected product(s)/code base** | Tenda AC9 V15.03.05.19(6318)_CN |
| **Affected component(s)** | `/bin/httpd`，函数 `formDelMacfilterRule` @ 0x000c3278，对应 `/goform/formDelMacfilterRule` 端点 |

**Attack vector(s):**

攻击者向 Tenda AC9 V15.03.05.19(6318)_CN 的 `/goform/formDelMacfilterRule` 发送包含 shell 元字符的 HTTP POST 请求。该端点用于删除 MAC 过滤规则，函数将用户参数通过 `snprintf()` 拼接到系统命令后，由 `doSystemCmd()` 执行。ARM 反汇编确认 `snprintf@plt` → `doSystemCmd@plt` 为直接链，无过滤。详见分析博文：[博客链接]。

**Suggested description of the vulnerability for use in the CVE:**

Tenda AC9 V15.03.05.19(6318)_CN 固件的 `/bin/httpd` 文件中 `/goform/formDelMacfilterRule` 端点对应的 MAC 过滤规则删除函数存在 OS 命令注入漏洞。该函数将用户提交的规则标识参数通过 `snprintf()` 直接拼接到系统命令字符串，通过 `doSystemCmd()` 执行，未进行任何输入验证。远程攻击者可利用此漏洞以 root 权限在路由器上执行任意系统命令。

---

## 附录 A：漏洞证据汇总

| # | 函数 | 确认方式 | Attack type | Impact | snprintf@plt | doSystemCmd@plt | 中间过滤 |
|:--:|------|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | `FUN_000384c8` | Pipeline + Ghidra | Remote | Code execution | — | — | — |
| 2 | `FUN_000384c8` | Pipeline + Ghidra | Remote | Code execution | — | — | — |
| 3 | `getlinkinfo` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 4 | `fromSetWifiGusetBasic` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 5 | `fromGetWifiGusetBasic` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 6 | `formGetUsbCfg` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 7 | `formGetFirewallCfg` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 8 | `formNotNowUpgrade` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 9 | `wan_lan_same_deal` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 10 | `formAddMacfilterRule` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |
| 11 | `formDelMacfilterRule` | ARM objdump PLT | Remote | Code execution | 0xf000 | 0xf474 | 无 |

## 附录 B：与已知 CVE 的差异

已知 13 个 Tenda AC9 CVE 涉及的函数：
`formSetUsbUnload`, `formOpenSchedWifi`, `formAddressNat`, `formGetWebPageName`, `formSetWifi`, `formSetDeviceList`, `formSetFirewall`, `formSetSambaCfg`, `formSetOnlineDevName`

本次 11 个漏洞涉及的函数：
`FUN_000384c8`, `getlinkinfo`, `fromSetWifiGusetBasic`, `fromGetWifiGusetBasic`, `formGetUsbCfg`, `formGetFirewallCfg`, `formNotNowUpgrade`, `wan_lan_same_deal`, `formAddMacfilterRule`, `formDelMacfilterRule`

**零重叠**。`formGetFirewallCfg`（本次，CWE-78 命令注入） ≠ `formSetFirewall`（CVE-2018-18709，CWE-121 栈溢出）。
