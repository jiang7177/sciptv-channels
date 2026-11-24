#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
四川电信 IPTV 组播地址 / 回放地址 / EPG 获取脚本（OpenWrt LuCI 版后端）

移植自 https://github.com/mytv-android/IPTV-channels
修改说明:
  - 配置不再读取 config.json，改为读取 UCI 配置 /etc/config/iptv-channels
  - 去除 Flask / BeautifulSoup / socketio 依赖（bs4 在原版中实际未被使用）
  - 3DES-ECB 加密优先使用 pycryptodome（python3-pycryptodome），
    未安装时自动回退到 openssl-util 命令行
  - 输出目录固定为 /etc/iptv-channels/output，
    输出文件经 LuCI 频道页下载 (rpcd download 分块读取, 不依赖 /www 可写)
  - 去除交互式 input()，便于无人值守的 cron / LuCI 调用
  - 支持手动 / 自动双模式: auto 模式通过 tcpdump 混杂嗅探 IPTV 网口上
    机顶盒的明文 HTTP 认证报文，自动获取 UserID / 机顶盒 IP / MAC /
    STBID / STBType / STBVersion / templateName / areaId / EDS 入口地址
    并写回 UCI；EDS 变更时重新嗅探即可自动跟随，无需重新抓包
  - 自动模式下通过 ip route get 自动检测并跟随 EDS 出口网口
  - 嗅探到 Authenticator 且未配置 key 时，可开启多进程爆破
    (校验解密结果中的 UserID/STBID 字段，并恢复声明的 key)

依赖: python3-light python3-requests openssl-util
      auto 模式需要: tcpdump (opkg install tcpdump)
      可选: python3-pycryptodome, git
"""

import os
import re
import sys
import json
import time
import random
import select
import logging
import socket
import struct
import subprocess
import shutil
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Callable
from urllib.parse import urlparse, unquote

import requests

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
BASE_DIR = "/etc/iptv-channels"
OUT_DIR = os.path.join(BASE_DIR, "output")
# 日志写入 /tmp (tmpfs 内存盘), 避免频繁写 flash 缩短存储寿命; 重启后清空
LOG_DIR = "/tmp/iptv-channels/log"

UCI_SECTION = "iptv-channels.main"

X_Requested_With = "com.skyworth.iptv"
DEFAULT_RTP2HTTPD = "http://192.168.5.1:8888"
# EDS 认证入口默认为空 (空白配置), 需从机顶盒抓包获取或由自动发现写入
DEFAULT_AUTH_IP = ""

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)

logger = logging.getLogger("iptv-channels")
logger.setLevel(logging.INFO)
_formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
_fh = RotatingFileHandler(
    os.path.join(LOG_DIR, "iptv.log"),
    maxBytes=2 * 1024 * 1024,
    backupCount=2,
    encoding="utf-8",
)
_fh.setFormatter(_formatter)
_sh = logging.StreamHandler()
_sh.setFormatter(_formatter)
logger.addHandler(_fh)
logger.addHandler(_sh)

# ---------------------------------------------------------------------------
# UCI 配置读取
# ---------------------------------------------------------------------------
def uci_get(name: str, default: str = "") -> str:
    """从 /etc/config/iptv-channels 的 main 段读取配置项"""
    try:
        r = subprocess.run(
            ["uci", "-q", "get", "%s.%s" % (UCI_SECTION, name)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if r.returncode == 0:
            return r.stdout.decode("utf-8", "replace").strip()
    except Exception as e:
        logger.error("读取 UCI 配置 %s 失败: %s" % (name, e))
    return default


def uci_set(name: str, value: str) -> None:
    """写回 UCI 配置项并提交（用于回填破解出的 key）"""
    try:
        subprocess.run(["uci", "set", "%s.%s=%s" % (UCI_SECTION, name, value)],
                       check=True, timeout=5)
        subprocess.run(["uci", "commit", "iptv-channels"], check=True, timeout=5)
        logger.info("已将 %s 写回 UCI 配置" % name)
    except Exception as e:
        logger.error("写入 UCI 配置 %s 失败: %s" % (name, e))


# ---------------------------------------------------------------------------
# 3DES-ECB 加解密（与原版 crypt_1.py 行为一致）
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import DES3  # pycryptodome
    HAVE_PYCRYPTO = True
except Exception:
    HAVE_PYCRYPTO = False


def _key24(key: str) -> bytes:
    """将密钥规范化为 24 字节: 8 字节密钥重复 3 次, 不足时以 '0' 补齐"""
    kb = key.encode("utf-8")
    if len(kb) == 8:
        return kb * 3
    return kb.ljust(24, b"0")


def _pkcs5_pad(data: bytes) -> bytes:
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len]) * pad_len


def _des3_cipher(key: str, single_des_mode=None):
    """
    构建 DES3 cipher; 8 字节 key 重复 3 次 (K1=K2=K3) 会退化成单 DES,
    pycryptodome 对此抛 ValueError, 此时等价改用单 DES (与 openssl
    des-ede3 的 K1K1K1 行为一致)。
    """
    k24 = _key24(key)
    try:
        return DES3.new(k24, DES3.MODE_ECB)
    except ValueError:
        from Crypto.Cipher import DES
        return DES.new(k24[:8], DES.MODE_ECB)


def des3_ecb_encrypt(key: str, text: str) -> str:
    """3DES-ECB 加密, 输出十六进制字符串"""
    data = _pkcs5_pad(text.encode("utf-8"))
    if HAVE_PYCRYPTO:
        return _des3_cipher(key).encrypt(data).hex()
    r = subprocess.run(
        ["openssl", "enc", "-des-ede3-ecb", "-K", _key24(key).hex(),
         "-nosalt", "-nopad"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return r.stdout.hex()


def des3_ecb_decrypt(key: str, hex_text: str) -> bytes:
    """3DES-ECB 解密十六进制字符串, 返回原始字节"""
    data = bytes.fromhex(hex_text)
    if HAVE_PYCRYPTO:
        return _des3_cipher(key).decrypt(data)
    r = subprocess.run(
        ["openssl", "enc", "-d", "-des-ede3-ecb", "-K", _key24(key).hex(),
         "-nosalt", "-nopad"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return r.stdout


def find_key(authenticator: str) -> List[str]:
    """
    遍历 00000000-99999999 八位数字 key 破解 Authenticator。
    注意: 纯 Python 实现每次解密需调用 openssl 子进程, 速度过慢,
    该功能仅在已安装 python3-pycryptodome 时可用。
    """
    if len(authenticator) < 10:
        logger.error("Authenticator 长度不足 10 位")
        return []
    if not HAVE_PYCRYPTO:
        logger.error(
            "Authenticator 破解功能需要 python3-pycryptodome, "
            "请安装后在 LuCI 中重新运行, 或直接在配置中填写 key"
        )
        return []

    keys: List[str] = []
    logger.info("开始遍历 00000000-99999999 搜索 key, Authenticator 长度: %d"
                % len(authenticator))
    ee = b""
    for x in range(100000000):
        key = "%08d" % x
        if x % 500000 == 0:
            logger.info("已经搜索至: -- %s --" % key)
        try:
            ee = _des3_cipher(key).decrypt(bytes.fromhex(authenticator))
            infos = ee.replace(b"\x08", b"").decode("utf-8", "ignore").split("$")
            if len(infos) > 7 and infos[0]:
                logger.info(
                    "找到 key: %s, 解密后: %s\n 随机数:%s\n TOKEN:%s\n USERID:%s\n"
                    " STBID:%s\n ip:%s\n mac:%s\n 运营商:%s"
                    % (key, ee, infos[0], infos[1], infos[2],
                       infos[3], infos[4], infos[5], infos[7])
                )
                keys.append(key)
                if len(keys) > 19:
                    break
        except Exception:
            pass

    try:
        with open(os.path.join(LOG_DIR, "key.txt"), "w", encoding="utf-8") as f:
            f.write("%s\n共找到 KEY: %s 个, 分别为: %s\n解密信息: %s\n" % (
                datetime.now(), len(keys), ",".join(keys), str(ee)))
    except Exception:
        pass
    return keys


# ---------------------------------------------------------------------------
# 加载配置
# ---------------------------------------------------------------------------
key = uci_get("key")
# 认证串首字段声明的 key (部分平台加密 key 与声明 key 不一致,
# 即声明 key 仅是标识, 实际 3DES 加密用的是另一个 key)
declared_key = uci_get("key_declared") or key
Authenticator = uci_get("authenticator")

if not key and Authenticator:
    try:
        _keys = find_key(Authenticator)
        if _keys:
            key = random.choice(_keys)
            logger.info("从 Authenticator 破解结果中随机选择 key: %s" % key)
            uci_set("key", key)
    except Exception as e:
        logger.error("解密 Authenticator 时发生错误: %s" % str(e))

UserID = uci_get("user_id")
mac = uci_get("mac")
STBID = uci_get("stbid")
ip = uci_get("ip")
STBType = uci_get("stb_type")
STBVersion = uci_get("stb_version")
UserAgent = uci_get(
    "user_agent",
    "Mozilla/5.0 (X11; Android x86_64; ChromiumBrowser) AppleWebKit/534.24 "
    "(KHTML, like Gecko) Safari/534.24 SkWebKit-SC-CTC",
)
templateName = uci_get("template_name")
areaId = uci_get("area_id")
RTP2HTTPD = uci_get("rtp2httpd", DEFAULT_RTP2HTTPD)
AuthenticationIP = uci_get("authentication_ip", DEFAULT_AUTH_IP)
# 上游接口: 绑定所有 EPG/认证请求的出口网口 (如 eth2.49),
# 避免请求被路由表引导到错误的出口 (电信 EPG 通常仅 IPTV 内网可达)
upstream_interface = uci_get("upstream_interface")
# 运行模式: manual=手动填写参数 / auto=嗅探机顶盒流量自动获取参数
mode = uci_get("mode", "manual")
# 嗅探网口 (auto 模式): 留空时自动检测
sniff_interface_cfg = uci_get("sniff_interface")
# 嗅探时长 (秒)
sniff_timeout_cfg = int(uci_get("sniff_timeout", "30") or 30)
# 嗅探到 Authenticator 后是否自动爆破 key (路由器上耗时可能较长, 默认关闭)
auto_bruteforce_cfg = uci_get("auto_bruteforce", "0") == "1"


def validate_required() -> None:
    """校验必填配置项, 缺失时退出 (auto 模式下嗅探在调用本函数之前执行)"""
    _required = {"key": key, "UserID": UserID, "mac": mac, "STBID": STBID, "ip": ip}
    missing = [_name for _name, _val in _required.items() if not _val]
    # EDS 入口: authentication_url (自动探测写入) 或 authentication_ip 二选一
    if not uci_get("authentication_url") and not AuthenticationIP:
        missing.append("EDS入口地址(authentication_ip)")
    if missing:
        logger.error(
            "缺少必要配置项: %s (自动模式会尝试通过嗅探获取, "
            "也可在 LuCI 设置页中手动填写)" % ", ".join(missing)
        )
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# 上游接口绑定
# ---------------------------------------------------------------------------
try:
    import fcntl  # Linux only
    HAVE_FCNTL = True
except Exception:
    HAVE_FCNTL = False


def get_iface_ip(ifname: str) -> Optional[str]:
    """通过 SIOCGIFADDR 获取网口的 IPv4 地址 (直接读网卡, 不经路由表)"""
    if not HAVE_FCNTL or not ifname:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            data = fcntl.ioctl(
                s.fileno(), 0x8915,  # SIOCGIFADDR
                struct.pack("256s", ifname[:15].encode("utf-8")))
            return socket.inet_ntoa(data[20:24])
        finally:
            s.close()
    except Exception as e:
        logger.warning("获取网口 %s 的 IPv4 地址失败: %s" % (ifname, e))
        return None


class _SourceAddressAdapter(requests.adapters.HTTPAdapter):
    """将请求的本地出口绑定到指定 IP (source_address)"""

    def __init__(self, source_address, **kwargs):
        self._source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False,
                         **pool_kwargs):
        pool_kwargs["source_address"] = self._source_address
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["source_address"] = self._source_address
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _build_session() -> requests.Session:
    """构建 requests Session; 配置了 upstream_interface 时绑定其出口 IP"""
    sess = requests.Session()
    if upstream_interface:
        src_ip = get_iface_ip(upstream_interface)
        if src_ip:
            _adapter = _SourceAddressAdapter((src_ip, 0))
            sess.mount("http://", _adapter)
            sess.mount("https://", _adapter)
            logger.info("上游接口: %s, 已绑定出口 IP: %s"
                        % (upstream_interface, src_ip))
        else:
            logger.warning(
                "网口 %s 未获取到 IPv4 地址, 请求将走系统默认路由"
                % upstream_interface)
    return sess


SESSION = _build_session()


def reload_config() -> None:
    """重新从 UCI 加载配置 (自动发现写回参数后调用), 并重建 Session"""
    global key, declared_key, Authenticator, UserID, mac, STBID, ip
    global STBType, STBVersion, UserAgent, templateName, areaId
    global RTP2HTTPD, AuthenticationIP, upstream_interface
    key = uci_get("key")
    declared_key = uci_get("key_declared") or key
    Authenticator = uci_get("authenticator")
    UserID = uci_get("user_id")
    mac = uci_get("mac")
    STBID = uci_get("stbid")
    ip = uci_get("ip")
    STBType = uci_get("stb_type")
    STBVersion = uci_get("stb_version")
    UserAgent = uci_get(
        "user_agent",
        "Mozilla/5.0 (X11; Android x86_64; ChromiumBrowser) AppleWebKit/534.24 "
        "(KHTML, like Gecko) Safari/534.24 SkWebKit-SC-CTC",
    )
    templateName = uci_get("template_name")
    areaId = uci_get("area_id")
    RTP2HTTPD = uci_get("rtp2httpd", DEFAULT_RTP2HTTPD)
    AuthenticationIP = uci_get("authentication_ip", DEFAULT_AUTH_IP)
    upstream_interface = uci_get("upstream_interface")
    SESSION = _build_session()
    logger.info("已重新加载 UCI 配置")


# ---------------------------------------------------------------------------
# 自动发现 (嗅探模式): 被动捕获机顶盒与 EPG 服务器的 HTTP 交互
#
# 机顶盒开机/换台时会向 EDS 发送明文 HTTP 认证请求, 路由器在 IPTV 网口
# 上以混杂模式即可完整截获, 从中提取全部认证参数:
#   - /EDS/jsp/AuthenticationURL / /EDS/authurl 请求 → EDS 入口地址
#   - authLoginHWCTC.jsp 响应        → EncryptToken
#   - ValidAuthenticationHWCTC.jsp POST → UserID / Authenticator / STBID /
#     MAC / STBType / STBVersion / templateName / areaId / userToken
#   - 请求源 IP                        → 机顶盒 IP
# 无论 EDS 地址如何变化, 嗅探到的参数始终与机顶盒当前实际使用的平台一致。
# ---------------------------------------------------------------------------
UCI_FIELD_MAP = {
    "user_id": "user_id",
    "ip": "ip",
    "mac": "mac",
    "stbid": "stbid",
    "stb_type": "stb_type",
    "stb_version": "stb_version",
    "template_name": "template_name",
    "area_id": "area_id",
    "authentication_ip": "authentication_ip",
}

# 嗅探提前结束所需的完整字段集合
REQUIRED_DISCOVER_FIELDS = (
    "user_id", "ip", "mac", "stbid", "stb_type",
    "stb_version", "template_name", "area_id", "authentication_ip",
)


class SniffParser:
    """逐行解析 tcpdump -A 输出, 提取机顶盒认证参数"""

    # 同时兼容 "IP src.port > dst.port" (无 -e) 与
    # "ethertype IPv4 (0x0800), length N: src.port > dst.port" (-e) 两种报文头
    RE_HEADER = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)\s*>\s*"
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)")
    RE_REQUEST = re.compile(r"^(?:GET|POST)\s+(\S+)\s+HTTP/", re.I)
    RE_HOST = re.compile(r"^\s*Host:\s*([^\s\r\n]+)", re.I)
    # EDS 入口请求路径 (按优先级)
    EDS_ENTRY_MARKERS = (
        "/EDS/jsp/AuthenticationURL",
        "/EDS/authurl",
        "/UICloudAuthClient/api/authurl",
    )
    RE_USERID = re.compile(r"UserID=([A-Za-z0-9_.%+-]+)", re.I)
    # INFO XML blob: <userId>xxx</userId> (URL 编码, 必须带起始标签避免误配闭合标签)
    RE_USERID2 = re.compile(r"(?:%3C|<)userId(?:%3E|>)([A-Za-z0-9_.%+-]+?)(?:%3C|<)", re.I)
    RE_STBID = re.compile(r"STBID=([0-9A-Fa-f]{20,})", re.I)
    RE_STBID2 = re.compile(r"(?:%3C|<)stbId(?:%3E|>)([0-9A-Fa-f]{20,})", re.I)
    RE_MAC = re.compile(
        r"(?:mac(?:%3D|=)|(?:%3C|<)mac(?:%3E|>))(?:%22|\")?("
        r"[0-9A-Fa-f]{12}|(?:[0-9A-Fa-f]{2}(?:%3A|:|-)){5}[0-9A-Fa-f]{2})", re.I)
    RE_STBTYPE = re.compile(r"STBType=([A-Za-z0-9_.\-]+)", re.I)
    RE_STBVER = re.compile(r"STBVersion=([A-Za-z0-9_.\-]+)", re.I)
    RE_TEMPLATE = re.compile(r"templateName=([A-Za-z0-9_.\-]+)", re.I)
    RE_AREA = re.compile(r"areaId=(\d+)", re.I)
    # INFO blob 中的 CrmArea 与认证用 areaId 一致, areaCode 是另一套编号
    RE_AREA2 = re.compile(r"(?:CrmArea(?:%3D|=)|(?:%3C|<)CrmArea(?:%3E|>))(\d+)", re.I)
    RE_AREA3 = re.compile(r"(?:%3C|<)areaCode(?:%3E|>)(\d+)", re.I)
    RE_USER_TOKEN = re.compile(r"userToken(?:%3D|=)?(?:%22|\")?([0-9A-Fa-f]{16,40})", re.I)
    RE_AUTHENTICATOR = re.compile(r"Authenticator=([0-9A-Fa-f]{40,})", re.I)
    RE_ENCRYPT_TOKEN = re.compile(
        r"EncryptToken\s*=\s*[\"']([0-9A-Fa-f]{8,64})[\"']", re.I)

    def __init__(self):
        self.found: Dict[str, str] = {}
        self.evidence: List[str] = []
        self._src = self._dst = None
        self._dport = None
        self._uri = ""
        self._host = ""

    def _mark(self, field: str, value: Optional[str], line: str) -> None:
        if not value:
            return
        value = value.strip()
        if not value:
            return
        old = self.found.get(field)
        if old == value:
            return
        # user_id: 带 @ 的完整账号 (如 ABC1234567@ITV) 质量更高, 可覆盖不带 @ 的
        better = (field == "user_id" and "@" in value
                  and old and "@" not in old)
        if old and not better:
            return  # 首次发现的值优先, 避免后续截断报文覆盖正确值
        self.found[field] = value
        self.evidence.append("[发现 %s = %s]\n  %s" % (field, value, line.strip()[:200]))
        # 记录参数来源报文的源 IP (即机顶盒 IP)
        if self._src and field in ("user_id", "authenticator", "stbid"):
            self.found.setdefault("ip", self._src)

    def _scan_payload(self, text: str) -> None:
        for m in self.RE_AUTHENTICATOR.finditer(text):
            self._mark("authenticator", m.group(1).upper(), text)
        for m in self.RE_USERID.finditer(text):
            self._mark("user_id", unquote(m.group(1)), text)
        for m in self.RE_USERID2.finditer(text):
            self._mark("user_id", unquote(m.group(1)), text)
        for m in self.RE_STBID.finditer(text):
            self._mark("stbid", m.group(1).upper(), text)
        for m in self.RE_STBID2.finditer(text):
            self._mark("stbid", m.group(1).upper(), text)
        for m in self.RE_MAC.finditer(text):
            self._mark("mac", unquote(m.group(1)), text)
        for m in self.RE_STBTYPE.finditer(text):
            self._mark("stb_type", m.group(1), text)
        for m in self.RE_STBVER.finditer(text):
            self._mark("stb_version", m.group(1), text)
        for m in self.RE_TEMPLATE.finditer(text):
            self._mark("template_name", m.group(1), text)
        for m in self.RE_AREA.finditer(text):
            self._mark("area_id", m.group(1), text)
        for m in self.RE_AREA2.finditer(text):
            self._mark("area_id", m.group(1), text)
        for m in self.RE_AREA3.finditer(text):
            self._mark("area_id", m.group(1), text)
        for m in self.RE_USER_TOKEN.finditer(text):
            self.found.setdefault("user_token", m.group(1))
        for m in self.RE_ENCRYPT_TOKEN.finditer(text):
            self.found.setdefault("encrypt_token", m.group(1).upper())

    def feed(self, line: str) -> None:
        try:
            m = self.RE_HEADER.search(line)
            if m:
                self._src = m.group(1)
                self._dst = m.group(3)
                self._dport = m.group(4)
                self._uri = ""
                self._host = ""
                return
            stripped = line.rstrip("\r\n")
            if not stripped.strip():
                return
            m = self.RE_REQUEST.match(stripped.strip())
            if m:
                self._uri = m.group(1)
                self._scan_payload(self._uri)
                return
            m = self.RE_HOST.match(stripped)
            if m:
                self._host = m.group(1)
                if self._uri and any(x in self._uri for x in self.EDS_ENTRY_MARKERS):
                    self._mark("authentication_ip", self._host, stripped)
                return
            self._scan_payload(stripped)
        except Exception:
            pass

    def all_found(self) -> bool:
        return all(f in self.found for f in REQUIRED_DISCOVER_FIELDS)


def detect_sniff_interface() -> str:
    """自动检测嗅探网口: 优先路由到 EDS 的网口, 其次 10.x IPTV 内网网口"""
    if sniff_interface_cfg:
        return sniff_interface_cfg
    if AuthenticationIP:
        try:
            host = urlparse(AuthenticationIP).hostname or ""
            if host:
                r = subprocess.run(
                    ["ip", "route", "get", host],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
                m = re.search(r"\bdev\s+(\S+)", r.stdout.decode("utf-8", "replace"))
                if m:
                    return m.group(1)
        except Exception:
            pass
    try:
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        best = ""
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].startswith("10."):
                name = parts[2]
                if name == "lo":
                    continue
                if "." in name:  # VLAN 子口 (如 eth2.49) 通常即 IPTV 线路
                    return name
                best = best or name
        return best
    except Exception:
        return ""


def auto_sync_upstream(auth_host: str) -> None:
    """自动模式: 通过 ip route get 同步 EDS 出口网口到 upstream_interface"""
    if not auth_host:
        return
    try:
        r = subprocess.run(
            ["ip", "route", "get", auth_host],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        m = re.search(r"\bdev\s+(\S+)", r.stdout.decode("utf-8", "replace"))
        if not m:
            return
        dev = m.group(1)
        old = uci_get("upstream_interface")
        if dev != old:
            logger.info("自动检测到 EDS 出口网口: %s (原配置: %s)"
                        % (dev, old or "无"))
            uci_set("upstream_interface", dev)
    except Exception as e:
        logger.warning("自动检测 EDS 出口网口失败: %s" % e)


def sniff_discover(iface: str, timeout: int) -> SniffParser:
    """在指定网口嗅探机顶盒认证流量"""
    if not shutil.which("tcpdump"):
        raise RuntimeError("未找到 tcpdump, 请先执行: opkg install tcpdump")
    cmd = ["tcpdump", "-i", iface, "-n", "-e", "-A", "-s0", "-l", "tcp"]
    parser = SniffParser()
    logger.info("嗅探网口: %s, 最长 %d 秒 (机顶盒开机/刷新时才会产生认证流量)"
                % (iface, timeout))
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            remain = max(0.1, deadline - time.time())
            try:
                ready, _, _ = select.select([proc.stdout], [], [], min(remain, 2.0))
            except Exception:
                ready = [proc.stdout]
            if ready:
                line = proc.stdout.readline()
                if not line:
                    break
                parser.feed(line.decode("utf-8", "replace"))
            if parser.all_found():
                logger.info("已捕获全部必需参数, 提前结束嗅探")
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    return parser


def apply_discovered(found: Dict[str, str]) -> List[str]:
    """将嗅探到的参数写回 UCI, 返回发生变化的字段列表"""
    changed: List[str] = []
    for field, uci_name in UCI_FIELD_MAP.items():
        val = found.get(field)
        if not val:
            continue
        if field == "authentication_ip" and not val.startswith("http"):
            val = "http://" + val
        old = uci_get(uci_name)
        if old != val:
            uci_set(uci_name, val)
            changed.append(uci_name)
    return changed


def _crack_chunk(args) -> List[Tuple[str, str]]:
    """多进程分片: 暴力搜索与嗅探 Authenticator 匹配的 key"""
    start, end, target, user_id, stbid = args
    out: List[Tuple[str, str]] = []
    if not HAVE_PYCRYPTO:
        return out
    try:
        cipher_data = bytes.fromhex(target)
    except Exception:
        return out
    for x in range(start, end):
        key = "%08d" % x
        try:
            ee = _des3_cipher(key).decrypt(cipher_data)
            pad = ee[-1] if ee else 0
            if 1 <= pad <= 8 and ee.endswith(bytes([pad]) * pad):
                ee = ee[:-pad]
            parts = ee.decode("utf-8", "ignore").split("$")
            if len(parts) > 5 and parts[2] == user_id and parts[3] == stbid:
                out.append((key, parts[0]))
        except Exception:
            pass
    return out


def crack_key_sniff(authenticator_hex: str, user_id: str,
                    stbid: str) -> List[Tuple[str, str]]:
    """
    用嗅探到的 Authenticator 爆破 8 位数字 key。
    校验条件: 解密结果的 UserID/STBID 字段与嗅探值一致 (比 find_key 更严格可靠),
    同时返回解密首字段 (声明的 key)。
    """
    if not HAVE_PYCRYPTO:
        raise RuntimeError("key 爆破需要 python3-pycryptodome")
    try:
        from multiprocessing import Pool
    except Exception as e:
        raise RuntimeError("不支持多进程: %s" % e)
    workers = min(os.cpu_count() or 2, 8)
    total = 100000000
    chunk = total // workers
    tasks = [
        (i * chunk, (i + 1) * chunk if i < workers - 1 else total,
         authenticator_hex.upper(), user_id, stbid)
        for i in range(workers)
    ]
    keys: List[Tuple[str, str]] = []
    logger.info("key 爆破开始: %d 进程并行, 目标 Authenticator 长度 %d"
                % (workers, len(authenticator_hex)))
    with Pool(workers) as pool:
        done = 0
        for res in pool.imap_unordered(_crack_chunk, tasks):
            done += 1
            keys.extend(res)
            logger.info("进度: 分片 %d/%d 完成, 累计命中 %d"
                        % (done, workers, len(keys)))
    return keys


# ---------------------------------------------------------------------------
# EDS 入口探测与扫描 (主策略: 不依赖嗅探, 任何拓扑可用)
#
# 实测: 经典认证入口 (如 http://<EDS-IP>:8082/EDS/jsp/AuthenticationURL)
# 以 302 方式指向当前 EPG 节点, 节点会轮换, 但入口域名/IP 可探测。
# 策略: 每次运行前探测当前入口 → 失效则遍历历史可用节点 (eds_history)
# → 仍失败可选并发扫描 182.138.0.0/16 的 8082/8001 端口找到新入口。
# ---------------------------------------------------------------------------
EDS_ENTRY_PATHS = ("/EDS/jsp/AuthenticationURL", "/EPG/jsp/AuthenticationURL")


def probe_entry(base_url: str, user_id: str, timeout: int = 6) -> Optional[str]:
    """
    探测 EDS/EPG 认证入口是否可用。
    判定: HTTP 30x (Location 指向 EDS/EPG) 或 200 且响应包含 EDS 认证特征。
    成功返回规范化入口 URL (不含查询串), 失败返回 None。
    """
    if not base_url:
        return None
    base = base_url.strip().rstrip("&")
    url = "%s?UserID=%s&Action=Login" % (base, user_id)
    headers = {"User-Agent": UserAgent, "X-Requested-With": X_Requested_With}
    try:
        r = SESSION.get(url, headers=headers, timeout=timeout,
                        allow_redirects=False)
    except Exception:
        return None
    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("Location", "")
        if "/EDS/" in loc or "/EPG/" in loc:
            return base
        return None
    if r.status_code == 200:
        body_head = r.text[:8000]
        if any(m in body_head for m in
               ("EDS", "AuthenticationURL", "authform", "authLoginHWCTC")):
            return base
    return None


def scan_eds_hosts(cidr: str = "182.138.0.0/16",
                   ports: Tuple[int, ...] = (8082, 8001),
                   timeout: float = 2.5, batch: int = 900) -> List[str]:
    """
    并发扫描网段中开放指定端口的 EDS 候选主机 (单线程非阻塞 socket + select)。
    仅作为入口全部失效时的兜底手段。
    """
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        logger.error("扫描网段无效: %s" % e)
        return []
    targets = []
    for a in net.hosts():
        ip = str(a)
        for p in ports:
            targets.append((ip, p))
    logger.info("EDS 扫描: %s, 共 %d 个目标 (端口 %s)"
                % (cidr, len(targets), ",".join(map(str, ports))))
    open_list: List[str] = []
    total = len(targets)
    for i in range(0, total, batch):
        chunk = targets[i:i + batch]
        pending: Dict[socket.socket, Tuple[str, int]] = {}
        for ip, p in chunk:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                rc = s.connect_ex((ip, p))
            except Exception:
                s.close()
                continue
            if rc == 0:
                open_list.append("%s:%d" % (ip, p))
                s.close()
            elif rc in (115, 114):  # EINPROGRESS / EALREADY
                pending[s] = (ip, p)
            else:
                s.close()
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            try:
                _r, w, _x = select.select([], list(pending.keys()), [], 0.5)
            except Exception:
                break
            for s in w:
                item = pending.pop(s, None)
                try:
                    s.getpeername()
                    if item:
                        open_list.append("%s:%d" % item)
                except Exception:
                    pass
                s.close()
        for s in list(pending):
            s.close()
            del pending[s]
        done = min(i + batch, total)
        if done % (batch * 10) < batch:
            logger.info("EDS 扫描进度: %d/%d, 已发现 %d 个开放端口"
                        % (done, total, len(open_list)))
    logger.info("EDS 扫描完成: %d 个开放端口" % len(open_list))
    return open_list


def _iptv_route_nets() -> List[str]:
    """EPG 网段路由列表 (UCI epg_routes 可覆盖, 空格分隔)"""
    default = "182.136.0.0/13 182.144.0.0/14 118.122.0.0/16"
    return [x for x in uci_get("epg_routes", default).split() if x]


def _detect_iptv_gateway(iface: str) -> Optional[str]:
    """取 IPTV 接口的 DHCP 网关: 依次查 ubus 各接口的活动/非活动路由"""
    try:
        r = subprocess.run(["ubus", "list"], capture_output=True, timeout=5)
        names = [l.strip() for l in r.stdout.decode("utf-8", "replace").splitlines()
                 if l.startswith("network.interface.")]
        for name in names:
            r = subprocess.run(["ubus", "call", name, "status"],
                               capture_output=True, timeout=5)
            st = json.loads(r.stdout.decode("utf-8", "replace") or "{}")
            if st.get("l3_device") != iface and st.get("device") != iface:
                continue
            routes = list(st.get("route") or [])
            inactive = st.get("inactive") or {}
            routes += list(inactive.get("route") or [])
            for rt in routes:
                nh = rt.get("nexthop")
                if nh:
                    return nh
    except Exception:
        pass
    return None


def _route_dev(net: str) -> str:
    """查询当前去往 net 的路由出口网口 (查不到返回空串)"""
    try:
        r = subprocess.run(["ip", "route", "show", "match", net],
                           capture_output=True, timeout=5)
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            if line.strip().startswith(net):
                m = re.search(r"dev\s+(\S+)", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""


def ensure_iptv_routes() -> None:
    """
    自检 EPG 网段路由是否指向 IPTV 口网关, 缺失/错误时自动补齐。

    背景: IPTV 线路为 DHCP 接入且地址池会变化 (如 10.58.96.0/20 与
    10.252.96.0/19 之间摆动), 静默 renew 不会触发 iface hotplug 事件,
    hotplug 钩子加的网段路由会丢失, 导致 EDS/EPG 请求被默认路由甩往
    WAN 口而全部超时。每次运行前幂等自检可完全自愈。
    """
    nets = _iptv_route_nets()
    if not nets:
        return
    iface = upstream_interface
    if not iface:
        # 未配置上游接口时, 探测持有 10.x 地址的非 LAN 网口 (IPTV 内网惯例)
        try:
            r = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                               capture_output=True, timeout=5)
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[1] in ("lo", "br-lan"):
                    continue
                if parts[3].startswith("10."):
                    iface = parts[1]
                    break
        except Exception:
            pass
    if not iface:
        logger.warning("路由自检: 未找到 IPTV 网口, 跳过 (可配置上游接口)")
        return

    gw = _detect_iptv_gateway(iface)
    if not gw:
        logger.warning("路由自检: 未能获取 %s 的 DHCP 网关, 跳过" % iface)
        return

    added = 0
    for net in nets:
        if _route_dev(net) == iface:
            continue  # 路由已正确指向 IPTV 口
        try:
            r = subprocess.run(
                ["ip", "route", "replace", net, "via", gw, "dev", iface],
                capture_output=True, timeout=5)
            if r.returncode == 0:
                added += 1
                logger.info("路由自检: %s via %s dev %s (新增/修正)"
                            % (net, gw, iface))
            else:
                logger.warning("路由自检: 添加 %s 失败: %s"
                               % (net, r.stderr.decode("utf-8", "replace").strip()))
        except Exception as e:
            logger.warning("路由自检异常: %s" % e)
    if added:
        logger.info("路由自检: 共补齐 %d 条 EPG 网段路由" % added)


def ensure_eds_entry(scan: bool = False) -> Optional[str]:
    """
    确保 EDS 认证入口可用:
    1. 探测当前入口 (authentication_url / authentication_ip)
    2. 遍历 eds_history 历史可用节点
    3. 全部失败且 scan=True 时扫描网段
    成功则将入口完整 URL 写入 authentication_url 并返回。
    """
    user_id = uci_get("user_id")
    cur = uci_get("authentication_url")

    candidates: List[str] = []
    if cur:
        candidates.append(cur)
    auth_ip = uci_get("authentication_ip")
    if auth_ip:
        for p in EDS_ENTRY_PATHS:
            candidates.append(auth_ip.rstrip("/") + p)
    for h in uci_get("eds_history").split():
        for p in EDS_ENTRY_PATHS:
            candidates.append("http://%s%s" % (h, p))

    seen = set()
    ordered = [c for c in candidates if not (c in seen or seen.add(c))]

    for cand in ordered:
        ok = probe_entry(cand, user_id)
        if ok:
            if ok != cur:
                logger.info("EDS 入口变更: %s -> %s" % (cur or "(未配置)", ok))
                uci_set("authentication_url", ok)
            # 记录历史可用节点
            host = urlparse(ok).netloc
            hist = uci_get("eds_history").split()
            if host not in hist:
                hist.insert(0, host)
                uci_set("eds_history", " ".join(hist[:12]))
            return ok

    if scan:
        cidr = uci_get("eds_scan_cidr", "182.138.0.0/16")
        ports = tuple(int(x) for x in
                      (uci_get("eds_scan_ports", "8082,8001") or "8082,8001").split(",")
                      if x.strip().isdigit())
        hosts = scan_eds_hosts(cidr, ports)
        for h in hosts:
            for p in ("/EDS/jsp/AuthenticationURL",):
                ok = probe_entry("http://%s%s" % (h, p), user_id, timeout=8)
                if ok:
                    logger.info("扫描发现可用 EDS 入口: %s" % ok)
                    uci_set("authentication_url", ok)
                    hist = uci_get("eds_history").split()
                    if h not in hist:
                        hist.insert(0, h)
                        uci_set("eds_history", " ".join(hist[:12]))
                    return ok

    logger.warning("所有 EDS 入口探测失败 (历史节点 %d 个)"
                   % len(uci_get("eds_history").split()))
    return None


def run_discovery(timeout: Optional[int] = None,
                  scan: Optional[bool] = None) -> Dict:
    """执行一次自动发现: 嗅探 → 解析 → 写回 UCI → EDS 入口探测 → 返回结果"""
    iface = sniff_interface_cfg or detect_sniff_interface()
    if not iface:
        raise RuntimeError("无法自动确定嗅探网口, 请在 LuCI 设置页指定")
    if timeout is None:
        timeout = sniff_timeout_cfg
    parser = sniff_discover(iface, timeout)
    found = dict(parser.found)

    try:
        with open(os.path.join(LOG_DIR, "discover_evidence.txt"), "w",
                  encoding="utf-8") as f:
            f.write("嗅探网口: %s\n时间: %s\n\n发现参数:\n%s\n\n--- 证据 ---\n%s\n" % (
                iface, datetime.now(),
                json.dumps(found, ensure_ascii=False, indent=2),
                "\n".join(parser.evidence[:500])))
    except Exception:
        pass

    changed: List[str] = []
    if found:
        changed = apply_discovered(found)
        auth_host = found.get("authentication_ip", "")
        if auth_host:
            auto_sync_upstream(urlparse(
                auth_host if "://" in auth_host else "http://" + auth_host
            ).hostname or auth_host.split(":")[0])
        if not uci_get("key") and found.get("authenticator") \
                and found.get("user_id") and found.get("stbid"):
            if auto_bruteforce_cfg:
                try:
                    res = crack_key_sniff(
                        found["authenticator"], found["user_id"],
                        found["stbid"])
                    if res:
                        k, declared = res[0]
                        uci_set("key", k)
                        if declared:
                            uci_set("key_declared", declared)
                        logger.info("key 爆破成功: 加密 key=%s, 声明 key=%s"
                                    % (k, declared))
                    else:
                        logger.warning("key 爆破未命中, 请手动填写 key")
                except Exception as e:
                    logger.error("key 爆破失败: %s" % e)
            else:
                logger.info(
                    "嗅探到 Authenticator 但未配置 key, "
                    "可在 LuCI 中开启 '自动爆破 key' (耗时较长) 或手动填写")

    # EDS 入口探测 (不依赖嗅探, 主策略)
    eds_scan_flag = scan if scan is not None else (uci_get("eds_scan", "0") == "1")
    eds_entry = None
    try:
        eds_entry = ensure_eds_entry(scan=eds_scan_flag)
    except Exception as e:
        logger.warning("EDS 入口探测异常: %s" % e)

    result = {
        "found": bool(found.get("user_id") or found.get("authentication_ip")),
        "sniff_interface": iface,
        "params": found,
        "changed_fields": changed,
        "eds_entry": eds_entry,
    }
    try:
        with open(os.path.join(LOG_DIR, "discover_result.json"), "w",
                  encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    if changed:
        logger.info("已更新 UCI 配置项: %s" % ", ".join(changed))
    else:
        logger.info("嗅探完成, 配置无需变更" if found else "嗅探未捕获到认证流量")
    return result


# ---------------------------------------------------------------------------
# 认证
# ---------------------------------------------------------------------------
def get_auth(max_retries: int = 3) -> Optional[Tuple[str, dict, str, str]]:
    """
    获取认证信息
    :return: (host, cookies, user_token, stbid) 或 None
    """
    retry_count = 0
    while retry_count < max_retries:
        try:
            # 第一步: 获取 EPG 服务器 host
            # 优先使用自动探测保存的完整入口 URL (路径可能是 /EDS/jsp 或 /EPG/jsp)
            entry_url = uci_get("authentication_url")
            if entry_url:
                url = "%s?UserID=%s&Action=Login" % (entry_url, UserID)
            else:
                url = "%s/EDS/jsp/AuthenticationURL?UserID=%s&Action=Login" % (
                    AuthenticationIP, UserID)
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;"
                          "q=0.9,image/webp,*/*;q=0.8",
                "User-Agent": UserAgent,
                "X-Requested-With": X_Requested_With,
            }
            logger.info("尝试获取认证信息 (尝试 %d/%d)" % (retry_count + 1, max_retries))
            response = SESSION.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            with open(os.path.join(LOG_DIR, "AuthenticationURL.jsp"), "w",
                      encoding="utf-8") as f:
                f.write(response.text)

            host = urlparse(response.url).netloc
            logger.info("解析得到服务器地址: %s" % host)
            # 302 跳转后的真实 EPG 节点记入历史候选:
            # 入口失效时 ensure_eds_entry 可直接尝试这些曾用节点
            if host and host != urlparse(url).netloc:
                hist = uci_get("eds_history").split()
                if host not in hist:
                    hist.insert(0, host)
                    uci_set("eds_history", " ".join(hist[:12]))
                    logger.info("EPG 节点 %s 已加入历史候选" % host)

            # 第二步: 获取 EncryptToken / userToken
            auth_url = "http://%s/EPG/jsp/authLoginHWCTC.jsp" % host
            auth_headers = {
                "User-Agent": UserAgent,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "http://%s/EPG/jsp/AuthenticationURL?"
                           "UserID=%s&Action=Login" % (host, UserID),
                "X-Requested-With": X_Requested_With,
            }
            auth_response = SESSION.post(
                auth_url, headers=auth_headers,
                data={"UserID": UserID, "VIP": ""}, timeout=10)
            auth_response.raise_for_status()
            with open(os.path.join(LOG_DIR, "authLoginHWCTC.jsp"), "w",
                      encoding="utf-8") as f:
                f.write(auth_response.text)

            encrypt_match = re.search(r'var EncryptToken = "([^"]+)"',
                                      auth_response.text)
            if not encrypt_match:
                raise ValueError("无法找到 EncryptToken")
            EncryptToken = encrypt_match.group(1)

            user_token_match = re.search(
                r'document\.authform\.userToken\.value = "([^"]+)"',
                auth_response.text)
            if not user_token_match:
                raise ValueError("无法找到 userToken")
            userToken = user_token_match.group(1)

            # 第三步: 生成 Authenticator (3DES-ECB)
            auth_str = "%s$%s$%s$%s$%s$%s$$CTC" % (
                declared_key, EncryptToken, UserID, STBID, ip, mac)
            logger.info("加密前字符串: %s" % auth_str)
            authenc = des3_ecb_encrypt(key, auth_str)
            logger.info("加密后 Authenticator: %s" % authenc)

            # 第四步: 验证认证
            valid_url = "http://%s/EPG/jsp/ValidAuthenticationHWCTC.jsp" % host
            valid_headers = {
                "User-Agent": UserAgent,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "http://%s/EPG/jsp/authLoginHWCTC.jsp" % host,
                "X-Requested-With": X_Requested_With,
            }
            valid_data = {
                "UserID": UserID,
                "Lang": "0",
                "SupportHD": "1",
                "NetUserID": "",
                "Authenticator": authenc,
                "STBType": STBType,
                "STBVersion": STBVersion,
                "conntype": "dhcp",
                "STBID": STBID,
                "templateName": templateName,
                "areaId": areaId,
                "userToken": userToken,
                "userGroupId": "1",
                "productPackageId": "",
                "mac": mac,
                "UserField": "",
                "SoftwareVersion": "",
                "IsSmartStb": "",
                "desktopId": "",
                "stbmaker": "",
                "XMPPCapability": "",
                "ChipID": "",
                "VIP": "",
            }
            valid_response = SESSION.post(
                valid_url, headers=valid_headers, data=valid_data, timeout=10)
            valid_response.raise_for_status()

            cookies = valid_response.cookies
            logger.info("JSESSIONID: %s" % cookies.get("JSESSIONID"))

            if valid_response.headers.get("Content-Type", "").startswith(
                    "text/html"):
                html_content = valid_response.text
                with open(os.path.join(LOG_DIR, "ValidAuthenticationHWCTC.jsp"),
                          "w", encoding="utf-8") as f:
                    f.write(html_content)

                m1 = re.search(r'name="UserToken"\s*value="([^"]+)"',
                               html_content)
                user_token = m1.group(1) if m1 else None
                m2 = re.search(r'name="stbid"\s*value="([^"]+)"', html_content)
                stbid = m2.group(1) if m2 else None

                if not user_token or not stbid:
                    logger.error("无法从 HTML 中提取 UserToken 或 stbid")
                    return None, None, None, None

                logger.info("从 HTML 中提取到 UserToken: %s" % user_token)
                logger.info("从 HTML 中提取到 stbid: %s" % stbid)
                return host, cookies, user_token, stbid

        except requests.exceptions.RequestException as e:
            logger.error("请求失败: %s" % str(e))
            retry_count += 1
            if retry_count < max_retries:
                logger.info("等待 5 秒后重试...")
                time.sleep(5)
            continue
    return None, None, None, None


# ---------------------------------------------------------------------------
# 频道列表
# ---------------------------------------------------------------------------
def process_channel_data(
        channels: List[Tuple[str, ...]]) -> Dict[str, List[str]]:
    """处理频道数据, 生成 sctv.txt / sctv.m3u 与频道信息映射"""
    channel_info: Dict[str, List[str]] = {}
    channel_ids: List[List[str]] = []

    # 过滤无效频道
    channels = [ch for ch in channels
                if "画中画" not in ch[1] and "单音轨" not in ch[1]]

    with open(os.path.join(OUT_DIR, "sctv.txt"), "w", encoding="utf-8") as ftxt, \
            open(os.path.join(OUT_DIR, "sctv.m3u"), "w", encoding="utf-8") as fm3u:
        ftxt.write("央视频道,#genre#\n")
        fm3u.write("#EXTM3U\n")

        def write_channel(category: str, condition: Callable[[str], bool]):
            for channel in channels:
                if condition(channel[1]):
                    name = "CCTV-14高清" if channel[1] == "CCTV-少儿高清" \
                        else channel[1]
                    rtp2httpd = RTP2HTTPD or DEFAULT_RTP2HTTPD
                    url = "%s/rtp/%s" % (rtp2httpd, channel[3])
                    append = False
                    if channel[7] == "2":  # 使用 FCC
                        url = "%s?fcc=%s:%s" % (url, channel[8], channel[9])
                        append = True
                    if channel[10] and channel[10] != "0":  # 使用 FEC
                        if append:
                            url = "%s&fec=%s" % (url, channel[10])
                        else:
                            url = "%s?fec=%s" % (url, channel[10])
                    timeshift = (
                        "&r2h-seek-mode=range(%s)" % channel[5]
                        if channel[4] == "1" else "")
                    # 写入 txt 文件 (DIYP 格式)
                    rtsp_url = None
                    if channel[4] == "1":
                        rtsp_url = channel[6].replace(
                            "rtsp://", "%s/rtsp/" % rtp2httpd
                        )
                        # EPG 返回的 RTSP URL 自带查询串 (?rrsip=...&accountinfo=...),
                        # playseek 必须用 & 追加; 若误用 ? 会产生两个查询起点,
                        # rtp2httpd 解析错乱, 上游 RTSP 服务器返回 457
                        sep = "&" if "?" in rtsp_url else "?"
                        rtsp_url += (
                            sep
                            + "playseek=${(b)yyyyMMddHHmmss}-${(e)yyyyMMddHHmmss}"
                            + timeshift
                        )
                    if rtsp_url:
                        ftxt.write("%s,%s#%s\n" % (name, rtsp_url, url))
                    else:
                        ftxt.write("%s,%s\n" % (name, url))
                    # 写入 m3u 文件
                    play_fmt = ('catchup="default" catchup-source="%s"'
                                % rtsp_url) if rtsp_url else ""
                    fm3u.write('#EXTINF:-1 group-title="%s" %s, %s\n%s\n' % (
                        category, play_fmt, name, url))
                    channel_ids.append([channel[0], name, channel[2]])

        write_channel("央视频道",
                      lambda name: any(x in name for x in ["CCTV", "CHC", "CGTN"]))
        ftxt.write("卫视频道,#genre#\n")
        write_channel("卫视频道", lambda name: "卫视" in name)
        ftxt.write("数字频道,#genre#\n")
        write_channel("数字频道", lambda name: "专区" in name)
        ftxt.write("其他频道,#genre#\n")
        write_channel("其他频道",
                      lambda name: not any(x in name for x in
                                           ["专区", "卫视", "CCTV", "CHC", "CGTN"]))

    for i, channel in enumerate(channels):
        channel_info[channel_ids[i][0]] = [channel_ids[i][1], channel_ids[i][2]]

    return channel_info


def get_channel_list(host: str, cookies: dict, user_token: str,
                     stbid: str) -> Dict[str, List[str]]:
    """获取频道列表"""
    channel_url = "http://%s/EPG/jsp/getchannellistHWCTC.jsp" % host
    channel_data = {
        "conntype": "dhcp",
        "UserToken": user_token,
        "tempKey": "",
        "stbid": stbid,
        "SupportHD": "1",
        "UserID": UserID,
        "Lang": "1",
    }
    headers = {
        "User-Agent": UserAgent,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "http://%s/EPG/jsp/ValidAuthenticationHWCTC.jsp" % host,
        "X-Requested-With": X_Requested_With,
    }
    response = SESSION.post(channel_url, headers=headers, cookies=cookies,
                            data=channel_data, timeout=20)
    response.raise_for_status()
    with open(os.path.join(LOG_DIR, "getchannellistHWCTC.jsp"), "w",
              encoding="utf-8") as f:
        f.write(response.text)

    pattern = re.compile(
        r'ChannelID\=\"(\d+)\",'
        r'ChannelName\=\"(.+?)\",'
        r'UserChannelID\=\"(\d+)\",'
        r'ChannelURL=\"igmp://(.+?)\".+?'
        r'TimeShift\=\"(\d+)\",'
        r'TimeShiftLength\=\"(\d+)\".+?,'
        r'TimeShiftURL\=\"(.+?)\".+?'
        r'FCCEnable\=\"(\d+)\",'
        r'ChannelFCCIP=\"(.*?)\",'
        r'ChannelFCCPort=\"(.*?)\",'
        r'ChannelFECPort=\"(.*?)\"'
    )
    channels = pattern.findall(response.text)
    logger.info("共解析到 %d 个频道" % len(channels))
    return process_channel_data(channels)


# ---------------------------------------------------------------------------
# EPG
# ---------------------------------------------------------------------------
def format_xmltv_time(timestamp: str) -> str:
    dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
    return dt.strftime("%Y%m%d%H%M%S")


def process_epg_data(channel_id: str, channel_name: List[str],
                     response_text: str) -> Optional[List[Dict[str, str]]]:
    """处理 EPG 数据"""
    match = re.search(r"parent\.jsonBackLookStr\s*=\s*(\[.*?\]);",
                      response_text)
    if not match:
        logger.debug("无法从 EPG 响应中提取 JSON 数据, 跳过频道 %s" % channel_id)
        return None

    try:
        epg_data = json.loads(match.group(1))
        if not epg_data or not isinstance(epg_data, list) or len(epg_data) < 2:
            logger.debug("EPG 数据为空或不完整, 跳过频道 %s" % channel_id)
            return None

        day_list = epg_data[0] if epg_data[0] and isinstance(epg_data[0], list) \
            else []
        program_groups = epg_data[1] if isinstance(epg_data[1], list) else []

        programs_data: List[Dict[str, str]] = []
        for group_index, programs in enumerate(program_groups):
            day_index = 0
            if group_index < len(day_list):
                day_info = day_list[group_index]
                if isinstance(day_info, dict):
                    day_index = day_info.get("index",
                                             day_info.get("dateIndex", 0)) or 0

            # 只保留今天和明天
            if day_index not in (0, 1):
                continue

            if isinstance(programs, list):
                for program in programs:
                    if not isinstance(program, dict):
                        continue

                    begin = program.get("beginTimeFormat", "")
                    end = program.get("endTimeFormat", "")
                    pname = program.get("programName", "未知节目")
                    if not begin or not end:
                        logger.debug("节目时间格式无效, 跳过: %s" % pname)
                        continue

                    start_time = format_xmltv_time(begin)
                    end_time = format_xmltv_time(end)
                    if not start_time or not end_time:
                        continue

                    pname = pname.replace("<", "《").replace(">", "》")
                    pname = pname.replace("&", "&amp;")
                    programs_data.append({
                        "channel_name": channel_name[0],
                        "start_time": start_time,
                        "end_time": end_time,
                        "program_name": pname,
                    })

        return programs_data

    except (ValueError, json.JSONDecodeError, KeyError) as e:
        logger.error("解析 EPG JSON 数据失败: %s" % str(e))
        return None


def write_epg_file(channel_info: Dict[str, List[str]],
                   epg_data: Dict[str, List[Dict[str, str]]]):
    """写入 EPG 文件 (XMLTV 格式)"""
    with open(os.path.join(OUT_DIR, "epg.xml"), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write("<tv>\n")
        for _cid, channel_name in channel_info.items():
            f.write('  <channel id="%s">\n' % channel_name[0])
            f.write('    <display-name lang="zh">%s</display-name>\n'
                    % channel_name[0])
            f.write("  </channel>\n")
        for _cid, programs in epg_data.items():
            for program in programs:
                f.write('  <programme channel="%s" start="%s +0800" '
                        'stop="%s +0800">\n' % (program["channel_name"],
                                                program["start_time"],
                                                program["end_time"]))
                f.write('    <title lang="zh">%s</title>\n'
                        % program["program_name"])
                f.write('    <desc lang="zh"></desc>\n')
                f.write("  </programme>\n")
        f.write("</tv>\n")


def get_epg(host: str, cookies: dict, channel_info: Dict[str, List[str]],
            user_token: str, stbid: str):
    """获取 EPG 数据"""
    epg_data: Dict[str, List[Dict[str, str]]] = {}

    for channel_id, channel_name in channel_info.items():
        logger.info("正在获取频道 %s 的 EPG 数据" % channel_name[0])
        epg_url = ("http://%s/EPG/jsp/tools/aged/getTvodData.jsp"
                   "?channelId=%s" % (host, channel_id))
        headers = {
            "User-Agent": UserAgent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "http://%s/EPG/jsp/tools/aged/getTvodData.jsp" % host,
        }
        data = {
            "conntype": "",
            "UserToken": user_token,
            "tempKey": "",
            "stbid": stbid,
            "SupportHD": "1",
            "UserID": UserID,
            "Lang": "1",
        }
        try:
            response = SESSION.post(epg_url, headers=headers, data=data,
                                    cookies=cookies, timeout=10)
            response.raise_for_status()
            programs = process_epg_data(channel_id, channel_name,
                                        response.text)
            if programs:
                epg_data[channel_id] = programs
        except requests.exceptions.RequestException as e:
            logger.error("获取频道 %s 的 EPG 数据失败: %s"
                         % (channel_name[0], str(e)))
            continue

    write_epg_file(channel_info, epg_data)
    logger.info("epg.xml, sctv.m3u, sctv.txt 已保存到 %s" % OUT_DIR)


# ---------------------------------------------------------------------------
# EPG Git 同步
# ---------------------------------------------------------------------------
def sync_epg():
    """同步 EPG 到 Git 仓库 (可选, 需要路由器安装 git)"""
    epg_git_repo = uci_get("epg_git_repo")
    epg_git_private_token = uci_get("epg_git_token")

    if not epg_git_repo or not epg_git_private_token:
        logger.warning("未配置 EPG Git 仓库信息, 跳过同步")
        return

    git_dir = os.path.join(BASE_DIR, "epg_repo")
    try:
        if epg_git_repo.startswith("https://"):
            repo_url = epg_git_repo.replace(
                "https://", "https://%s@" % epg_git_private_token)
        else:
            raise ValueError("目前仅支持 HTTPS 格式的 Git 仓库 URL")

        if os.path.exists(git_dir):
            shutil.rmtree(git_dir)

        logger.info("正在克隆仓库...")
        subprocess.run(["git", "clone", repo_url, git_dir], check=True,
                       capture_output=True, timeout=120)
        subprocess.run(["git", "config", "user.name", "iptv-bot"],
                       cwd=git_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "iptv-bot@local"],
                       cwd=git_dir, check=True, capture_output=True)

        src_file = os.path.join(OUT_DIR, "epg.xml")
        if not os.path.exists(src_file):
            logger.error("源文件 %s 不存在" % src_file)
            return
        shutil.copy2(src_file, os.path.join(git_dir, "epg.xml"))

        subprocess.run(["git", "add", "."], cwd=git_dir, check=True,
                       capture_output=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subprocess.run(["git", "commit", "-m", "Update EPG %s" % timestamp],
                       cwd=git_dir, check=True, capture_output=True)

        logger.info("正在推送到远程仓库...")
        subprocess.run(["git", "push", repo_url, "-f"], cwd=git_dir,
                       check=True, capture_output=True, timeout=120)
        logger.info("EPG 数据同步成功")

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode() if e.stderr else str(e)
        if epg_git_private_token in err_msg:
            err_msg = err_msg.replace(epg_git_private_token, "******")
        logger.error("Git 操作失败: %s" % err_msg)
    except Exception as e:
        logger.error("同步 EPG 数据失败: %s" % str(e))
    finally:
        if os.path.exists(git_dir):
            try:
                shutil.rmtree(git_dir)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # --discover-only: 仅执行嗅探发现并输出结果 JSON (供 LuCI "立即发现"按钮调用)
    if "--discover-only" in sys.argv:
        _t = sniff_timeout_cfg
        if "--timeout" in sys.argv:
            try:
                _t = int(sys.argv[sys.argv.index("--timeout") + 1])
            except Exception:
                pass
        try:
            result = run_discovery(_t)
            result["success"] = True
        except Exception as e:
            result = {"success": False, "msg": str(e)}
        print(json.dumps(result, ensure_ascii=False))
        raise SystemExit(0 if result.get("success") and result.get("found") else 1)

    try:
        if mode == "auto":
            try:
                logger.info("自动模式: 先嗅探机顶盒流量获取最新参数")
                run_discovery()
                reload_config()
            except Exception as e:
                logger.warning("自动发现失败, 使用现有配置继续: %s" % e)

        validate_required()

        # 网段路由自检: DHCP 静默 renew 换地址池后路由会丢, 运行前自动补齐
        try:
            ensure_iptv_routes()
        except Exception as e:
            logger.warning("路由自检异常: %s" % e)

        # EDS 入口探测/跟随: 失效时遍历历史节点 (自动模式可按需扫描网段)
        try:
            ensure_eds_entry(
                scan=(mode == "auto" and uci_get("eds_scan", "0") == "1"))
            reload_config()
        except Exception as e:
            logger.warning("EDS 入口探测异常: %s" % e)

        host, cookies, user_token, stbid = get_auth()
        logger.info("认证结果: host=%s, user_token=%s" % (host, user_token))

        if not host and mode == "auto":
            # EDS 可能已变更: 重新嗅探 + 强制扫描网段后重试一次
            logger.info("认证失败, 重新发现 EDS 入口后重试")
            try:
                run_discovery(scan=True)
                reload_config()
                host, cookies, user_token, stbid = get_auth()
                logger.info("重试认证结果: host=%s" % host)
            except Exception as e:
                logger.warning("重试发现失败: %s" % e)

        if not host:
            logger.error("认证失败, 无法获取 host 地址")
            raise SystemExit(1)

        channel_info = get_channel_list(host, cookies, user_token, stbid)
        get_epg(host, cookies, channel_info, user_token, stbid)
        sync_epg()
        logger.info("全部任务完成")
    except SystemExit:
        raise
    except Exception as e:
        logger.error("执行失败: %s" % str(e))
        raise SystemExit(1)
