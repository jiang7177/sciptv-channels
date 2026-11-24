#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从抓包文件 (pcap/pcapng) 中提取电信 IPTV 机顶盒认证配置参数。
依赖: tshark (Wireshark CLI)。用法:
    python extract_iptv_params.py <capture.pcapng> [--json]
输出: JSON, 含 params(已提取参数) / missing(缺失字段) / auth_requests(认证请求线索) / eds_candidates(EDS 入口候选)。
出处: 工作流整理自 luci-app-iptv-channels 项目, 移植自 https://github.com/mytv-android/IPTV-channels
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote, urlsplit

FIELD_KEYS = [
    ("user_id",      re.compile(r"(?:^|[?&;\s])UserID=([^&\s\"']+)", re.I), True),
    ("stbid",        re.compile(r"(?:^|[?&;\s])STBID=([^&\s\"']+)", re.I), True),
    ("stb_type",     re.compile(r"(?:^|[?&;\s])STBType=([^&\s\"']+)", re.I), True),
    ("stb_version",  re.compile(r"(?:^|[?&;\s])STBVersion=([^&\s\"']+)", re.I), True),
    ("template_name", re.compile(r"(?:^|[?&;\s])templateName=([^&\s\"']+)", re.I), True),
    ("area_id",      re.compile(r"(?:^|[?&;\s])area(?:_?id)?=([^&\s\"']+)", re.I), True),
    ("authenticator", re.compile(r"(?:^|[?&;\s])Authenticator=([^&\s\"']+)", re.I), True),
]
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
STBID_MAC_RE = re.compile(r"([0-9A-Fa-f]{12})$")
AUTH_URL_RE = re.compile(r"/EDS/jsp/AuthenticationURL|/EPG/jsp/AuthenticationURL|AuthenticationURL", re.I)


def find_tshark():
    p = shutil.which("tshark")
    if p:
        return p
    for cand in (r"C:\Program Files\Wireshark\tshark.exe",
                 r"C:\Program Files (x86)\Wireshark\tshark.exe",
                 "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"):
        if os.path.exists(cand):
            return cand
    sys.exit("错误: 未找到 tshark, 请安装 Wireshark 或将其加入 PATH")


def run_tshark(tshark, pcap, fields, display_filter):
    cmd = [tshark, "-r", pcap, "-Y", display_filter, "-T", "fields",
           "-E", "separator=|", "-E", "quote=d", "-E", "occurrence=a"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        sys.exit("tshark 失败: " + r.stderr.strip()[:500])
    rows = []
    for line in r.stdout.splitlines():
        parts = line.split("|")
        row = {f: (parts[i] if i < len(parts) and parts[i] != '""' else "")
               for i, f in enumerate(fields)}
        for f in row:
            row[f] = row[f].strip('"')
        rows.append(row)
    return rows


def harvest(text, params, hits):
    if not text:
        return
    text = unquote(text)
    for key, rx, dec in FIELD_KEYS:
        if key in params:
            continue
        m = rx.search(text)
        if m:
            params[key] = m.group(1)
            hits.add(key)
    if "mac" not in params:
        m = MAC_RE.search(text)
        if m:
            params["mac"] = m.group(0).replace("-", ":").upper()
            hits.add("mac")
    # STBID 末 12 位 hex 即 MAC (无分隔符), 可交叉补全
    if "stbid" in params and "mac" not in params:
        m = STBID_MAC_RE.search(params["stbid"])
        if m:
            h = m.group(1).upper()
            params["mac"] = ":".join(h[i:i+2] for i in range(0, 12, 2))
            hits.add("mac")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--json", action="store_true", help="仅输出 JSON")
    args = ap.parse_args()
    if not os.path.exists(args.pcap):
        sys.exit("错误: 文件不存在: " + args.pcap)
    tshark = find_tshark()

    req_fields = ["frame.number", "ip.src", "ip.dst", "http.host",
                  "http.request.method", "http.request.uri",
                  "http.user_agent", "http.file_data"]
    resp_fields = ["frame.number", "ip.src", "http.response.code",
                   "http.location", "http.file_data"]

    reqs = run_tshark(tshark, args.pcap, req_fields, "http.request")
    resps = run_tshark(tshark, args.pcap, resp_fields, "http.response.code == 302 or http.response.code == 301")

    params, hits = {}, set()
    auth_requests, eds_candidates = [], set()

    for r in reqs:
        uri = r.get("http.request.uri", "")
        body = r.get("http.file_data", "")
        is_auth = bool(AUTH_URL_RE.search(uri) or AUTH_URL_RE.search(body))
        if is_auth:
            host = r.get("http.host", "")
            entry = f"http://{host}" if host and not host.startswith("http") else host
            if entry:
                eds_candidates.add(entry)
            auth_requests.append({
                "frame": r.get("frame.number"), "src": r.get("ip.src"),
                "method": r.get("http.request.method"), "host": r.get("http.host"),
                "uri": uri[:300],
            })
            # 认证请求源 IP 即机顶盒 IP
            if r.get("ip.src") and "ip" not in params:
                params["ip"] = r.get("ip.src")
                hits.add("ip")
        for text in (uri, body):
            harvest(text, params, hits)
        ua = r.get("http.user_agent", "")
        if ua and "user_agent" not in params:
            params["user_agent"] = ua
            hits.add("user_agent")

    for r in resps:
        loc = r.get("http.location", "")
        harvest(loc, params, hits)
        if loc:
            eds_candidates.add(loc.split("?")[0])

    # 无直接认证请求时, host 兜底候选
    if not eds_candidates:
        for r in reqs:
            h = r.get("http.host", "")
            if h and re.search(r":808[0-9]|:800[0-9]", h):
                eds_candidates.add(f"http://{h}")

    result = {
        "params": params,
        "missing": [k for k, _, _ in FIELD_KEYS if k not in params] + [k for k in ("ip", "mac", "user_agent") if k not in params],
        "auth_requests": auth_requests[:20],
        "eds_candidates": sorted(eds_candidates),
        "notes": [
            "key (8位3DES加密key) 通常不在明文报文中: Authenticator 首字段为声明 key, 实际加密 key 需用 Authenticator 爆破获得",
            "缺失字段可尝试: 重启机顶盒后重新抓包 / 在 Wireshark 中 Follow HTTP Stream 人工核对",
        ],
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("== 提取结果 ==")
        for k, v in sorted(params.items()):
            print(f"  {k:16s} = {v}")
        if result["missing"]:
            print("== 缺失字段 ==")
            print("  " + ", ".join(result["missing"]))
        if auth_requests:
            print(f"== 认证请求 ({len(auth_requests)} 条) ==")
            for a in auth_requests[:5]:
                print(f"  #{a['frame']} {a['method']} {a['host']}{a['uri'][:120]}")
        if eds_candidates:
            print("== EDS 入口候选 ==")
            for e in result["eds_candidates"]:
                print("  " + e)
        print("\nJSON 输出加 --json 参数")
        print("出处: luci-app-iptv-channels 工作流 | 移植自 https://github.com/mytv-android/IPTV-channels")


if __name__ == "__main__":
    main()
