---
name: iptv-capture-extract
description: 从抓包文件（Wireshark/tshark 的 pcap/pcapng）中提取电信 IPTV 机顶盒认证配置参数（UserID、STBID、MAC、机顶盒 IP、STBType、templateName、areaId、Authenticator、EDS 入口地址等）。当用户提到抓包提取 IPTV 配置、机顶盒认证参数、EDS/EPG 入口、pcapng/pcap 分析电信 IPTV、IPTV-channels/luci-app-iptv-channels 配置获取时使用本技能。
agent_created: true
---

# IPTV 抓包配置提取

## Overview

从电信 IPTV 机顶盒的认证抓包文件中提取全部配置参数，用于填充
luci-app-iptv-channels（或原版 mytv-android/IPTV-channels）的配置。
核心流程：用 tshark 解析 HTTP 认证请求 → 正则抽取字段 → 输出 JSON。
**源码出处**：字段含义与认证链路整理自 luci-app-iptv-channels 项目，
该项目移植自 https://github.com/mytv-android/IPTV-channels 。

## 前置条件

- 抓包文件：`.pcap` / `.pcapng`（用户通过 @ 引用或给出路径）
- tshark：优先 `shutil.which("tshark")`；Windows 常见位置
  `C:\Program Files\Wireshark\tshark.exe`（脚本已内置探测）

## 工作流

### 第 1 步：运行提取脚本（首选）

```sh
python <skill_dir>/scripts/extract_iptv_params.py <capture.pcapng>
python <skill_dir>/scripts/extract_iptv_params.py <capture.pcapng> --json   # 纯 JSON
```

脚本自动完成：遍历 HTTP 请求/302 响应 → 定位含 `AuthenticationURL` 的请求 →
抽取 UserID/STBID/MAC/STBType/STBVersion/templateName/areaId/Authenticator/
User-Agent → 认证请求源 IP 即机顶盒 IP → Host 头即 EDS 入口候选。

### 第 2 步：核对结果并向用户汇报

- 按 `params` 逐项列出，直接对照 LuCI 设置页字段名（机顶盒 IP / UserID /
  MAC 地址 / STBID / 8 位加密 Key / EPG 认证服务器 / STBType /
  STBVersion / templateName / areaId / User-Agent）；
- `missing` 中缺 `key` 属正常（key 不在明文报文中，见第 3 步）；
  其余缺失字段建议用户重启机顶盒重新抓包，或按 `references/field-reference.md`
  第三节的 GUI 步骤人工核对。

### 第 3 步：Authenticator → key（仅当用户需要）

- 明文报文中没有 8 位加密 key；`Authenticator=` 首字段是"声明 key"，
  实际加密 key 可能与之不同；
- 需要时对 Authenticator 做 3DES-ECB 的 8 位数字 key 爆破，以解密结果
  含合法 UserID/STBID 为命中判据（参考 luci-app-iptv-channels 项目的
  `crack_key.py`，多进程约 2 分钟/全空间）；
- 爆破需要 python3 + pycryptodome，且必须经用户确认后再执行（耗时长）。

### 无 tshark 或脚本失败时的降级

按 `references/field-reference.md` 第二节的 tshark 命令手工分步提取；
仍不可用时按第三节指导用户在 Wireshark GUI 中 Follow HTTP Stream，
由用户粘贴内容、助手代为解析。

## 注意事项

- 参数值一律先 URL 解码（`Authenticator` 常被编码）；
- MAC 有两种形态：`XX:XX:…` 分隔式，或 STBID 末 12 位 hex 无分隔式，
  可交叉校验；
- EDS 入口有 302 跟随机制：请求入口 → 302 Location → 真实 EPG 节点，
  两者都记录；入口会轮换，配置里同时保留历史节点便于失效后探测；
- 抓包文件可能包含用户账号隐私，提取结果只写入用户指定的配置，不要
  外发或写入公开文件。

## Resources

- `scripts/extract_iptv_params.py` — 一键提取脚本（tshark 依赖，输出 JSON）
- `references/field-reference.md` — 字段参考表、tshark/GUI 命令、抓包要点、
  key 爆破说明（含源码出处）
