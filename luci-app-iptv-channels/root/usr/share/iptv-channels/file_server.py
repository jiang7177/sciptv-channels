#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iptv-channels 免登录文件服务 (v1.2.5)

安全设计:
- 仅提供输出目录下白名单文件 (sctv.txt / sctv.m3u / epg.xml), 其他一律 404
- 请求路径规范化后再校验白名单, 杜绝路径穿越; 不读取输出目录以外的任何文件
- 可选来源网段白名单 (UCI server_allow_cidr, 空格分隔多个网段, 留空允许所有来源)
- 不解析任何请求头中的来源字段 (如 X-Forwarded-For), 仅信任 TCP 对端地址

UCI 配置 (iptv-channels.main):
  server_enabled   是否启用 (1/0)
  server_port      监听端口 (默认 5141)
  server_bind      监听地址 (默认 0.0.0.0; 建议如 192.168.123.0/24 所在网口地址)
  server_allow_cidr 来源网段白名单 (默认空 = 不限制)

用法: python3 file_server.py [--bind 0.0.0.0] [--port 5141]
"""
import argparse
import logging
import os
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote

OUT_DIR = "/etc/iptv-channels/output"

# 文件白名单: 名称 -> (Content-Type, 说明)
WHITELIST = {
    "sctv.txt": ("text/plain; charset=utf-8", "DIYP 频道列表"),
    "sctv.m3u": ("audio/x-mpegurl", "M3U 频道列表 (含时移回看地址)"),
    "epg.xml": ("application/xml", "XMLTV EPG 节目单"),
}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("file-server")


def uci(name: str, default: str = "") -> str:
    try:
        r = subprocess.run(["uci", "-q", "get", "iptv-channels.main." + name],
                           capture_output=True, timeout=5)
        v = r.stdout.decode("utf-8", "replace").strip()
        return v if v else default
    except Exception:
        return default


def ip_to_int(ip: str):
    """点分 IPv4 -> 整数, 非法返回 None"""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not p.isdigit() or (p != "0" and p[0] == "0"):
            return None
        v = int(p)
        if v > 255:
            return None
        n = (n << 8) | v
    return n


def allowed(client_ip: str, cidrs) -> bool:
    """来源网段白名单校验; cidrs 为空表示不限制"""
    if not cidrs:
        return True
    ci = ip_to_int(client_ip)
    if ci is None:
        return False
    for c in cidrs:
        if "/" in c:
            net, bits = c.split("/", 1)
        else:
            net, bits = c, "32"
        ni = ip_to_int(net.strip())
        if ni is None:
            continue
        try:
            bits = int(bits)
        except ValueError:
            continue
        if not 0 <= bits <= 32:
            continue
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
        if (ci & mask) == (ni & mask):
            return True
    return False


class FileServer(ThreadingHTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "iptv-channels-file-server/1.2.5"
    protocol_version = "HTTP/1.1"

    # allow_cidrs 由 main() 挂到 server 对象上
    @property
    def allow_cidrs(self):
        return getattr(self.server, "allow_cidrs", [])

    def log_message(self, fmt, *args):
        log.info("%s - %s" % (self.client_address[0], fmt % args))

    def _client_allowed(self) -> bool:
        try:
            return allowed(self.client_address[0], self.allow_cidrs)
        except Exception:
            return False

    def _resolve_target(self, raw_path):
        """解析并校验请求目标; 返回 (文件名或 None, 是否目录首页)"""
        path = unquote(urlsplit(raw_path).path or "/")
        if path in ("/", "/index.html", "/index.htm"):
            return None, True
        name = path.lstrip("/")
        # 规范化校验: 禁止任何形式的路径构造 (穿越/子目录/反斜杠)
        if not name or "/" in name or "\\" in name or ".." in name \
                or "\x00" in name:
            return None, False
        if name not in WHITELIST:
            return None, False
        return name, False

    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8",
              extra=None, head_only=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only and body:
            self.wfile.write(body)

    def _serve(self, head_only=False):
        if not self._client_allowed():
            log.warning("拒绝未授权来源: %s GET %s"
                        % (self.client_address[0], self.path))
            self._send(403, b"forbidden\n", head_only=head_only)
            return
        name, is_index = self._resolve_target(self.path)
        if not is_index and name is None:
            self._send(404, b"not found\n", head_only=head_only)
            return
        if is_index:
            rows = []
            for fn, (ctype, desc) in sorted(WHITELIST.items()):
                fp = os.path.join(OUT_DIR, fn)
                if os.path.isfile(fp):
                    st = os.stat(fp)
                    mt = time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(st.st_mtime))
                    rows.append('<tr><td><a href="/%s">%s</a></td>'
                                '<td>%s</td><td>%.1f MB</td><td>%s</td></tr>'
                                % (fn, fn, desc, st.st_size / 1048576.0, mt))
                else:
                    rows.append('<tr><td>%s</td><td colspan="3">尚未生成'
                                '</td></tr>' % fn)
            cidr_note = ("来源限制: %s" % " ".join(self.allow_cidrs)
                         if self.allow_cidrs else "来源限制: 未启用 (所有来源可访问)")
            html = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<title>iptv-channels 文件服务</title></head><body>"
                    "<h2>iptv-channels 输出文件</h2><table border='1' "
                    "cellpadding='4'>%s</table><p>%s</p>"
                    "<p>播放器可直接订阅: http://路由器IP:%d/sctv.m3u 或 "
                    "/sctv.txt, EPG: /epg.xml</p></body></html>"
                    % ("".join(rows), cidr_note, self.server.server_port))
            self._send(200, html.encode("utf-8"),
                       "text/html; charset=utf-8", head_only=head_only)
            return
        fp = os.path.join(OUT_DIR, name)
        try:
            if not os.path.isfile(fp):
                self._send(404, b"not generated yet\n", head_only=head_only)
                return
            st = os.stat(fp)
            with open(fp, "rb") as f:
                body = f.read()
            mt = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                               time.gmtime(st.st_mtime))
            log.info("提供文件: %s -> %s (%d bytes)"
                     % (self.client_address[0], name, len(body)))
            self._send(200, body, WHITELIST[name][0],
                       {"Last-Modified": mt}, head_only=head_only)
        except Exception as e:
            log.error("读取文件失败 %s: %s" % (name, e))
            self._send(500, b"internal error\n", head_only=head_only)

    def do_GET(self):
        self._serve(head_only=False)

    def do_HEAD(self):
        self._serve(head_only=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default=None)
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args()

    if uci("server_enabled", "1") != "1":
        log.info("server_enabled=0, 文件服务退出")
        sys.exit(0)

    bind = args.bind or uci("server_bind", "0.0.0.0")
    port = args.port or int(uci("server_port", "5141"))
    cidrs = [x for x in uci("server_allow_cidr", "").replace(",", " ").split()
             if x]

    srv = FileServer((bind, port), Handler)
    srv.allow_cidrs = cidrs
    log.info("免登录文件服务已启动: http://%s:%d/ (来源限制: %s)"
             % (bind, port, " ".join(cidrs) if cidrs else "不限制"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
