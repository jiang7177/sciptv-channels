# 电信 IPTV 抓包字段参考（四川电信 EPG / EDS 认证）

整理自 luci-app-iptv-channels 项目实战经验；该项目移植自
[mytv-android/IPTV-channels](https://github.com/mytv-android/IPTV-channels)，
字段含义与认证链路以原项目为出处。

## 一、要提取的目标字段

| 配置项 | 报文中位置 | 说明 / 示例形态 |
|---|---|---|
| `ip`（机顶盒 IP） | 认证请求的源 IP（`ip.src`） | IPTV 内网地址，如 10.x.x.x |
| `user_id` | 请求 URI / POST body 的 `UserID=` | 电话号码@ITV，如 `LZPxxxxxxx@ITV` |
| `mac` | 报文中的 MAC 正则；或由 STBID 末 12 位 hex 推出 | `8C:5F:AD:xx:xx:xx` |
| `stbid` | `STBID=` | 32 位 hex，末 12 位即 MAC（无分隔符） |
| `stb_type` | `STBType=` | 机顶盒型号，如 `HG680-KA` |
| `stb_version` | `STBVersion=` | 如 `FHV181225P0004` |
| `template_name` | `templateName=` | 如 `epg30stzx` |
| `area_id` | `areaId=` / `area_id=` | 如 `10406` |
| `authenticator` | `Authenticator=`（URL 编码，需 unquote） | 首字段为"声明 key"，整体可爆破出真实加密 key |
| `authentication_ip` | 认证请求的 `Host` 头 | 如 `182.138.18.41:8082` → 填 `http://182.138.18.41:8082` |
| `authentication_url` | 含 `AuthenticationURL` 的完整 URI | 如 `/EDS/jsp/AuthenticationURL` |
| `user_agent` | `http.user_agent` 头 | 四川电信定制 UA 含 `SkWebKit-SC-CTC` |
| `key` | **不在明文报文中** | 8 位数字 3DES key；Authenticator 首字段是"声明 key"，实际加密 key 可能不同，需爆破校验 |

## 二、tshark 常用命令

```sh
# 1. 浏览全部 HTTP 请求（找 AuthenticationURL / EPG 域名）
tshark -r capture.pcapng -Y http.request -T fields \
  -e frame.number -e ip.src -e http.host -e http.request.uri -E quote=d

# 2. 只看认证请求
tshark -r capture.pcapng -Y 'http.request.uri contains "AuthenticationURL"' \
  -T fields -e ip.src -e http.host -e http.request.uri -E quote=d

# 3. 302 重定向（EDS 入口 → 真实 EPG 节点, Location 即节点地址）
tshark -r capture.pcapng -Y 'http.response.code == 302' \
  -T fields -e http.location -E quote=d

# 4. POST body 中的参数（部分平台认证参数在 body）
tshark -r capture.pcapng -Y 'http.request.method == "POST"' \
  -T fields -e http.file_data -E quote=d

# 5. User-Agent
tshark -r capture.pcapng -Y http.request -T fields -e http.user_agent | sort -u
```

## 三、Wireshark GUI 步骤（无 tshark 时）

1. 打开 pcapng，过滤栏输入 `http.request`；
2. 找 URI 含 `AuthenticationURL` 的请求 → 右键 **Follow → HTTP Stream**；
3. 请求行 + 头 + body 里按上表逐项抄参数（注意 URL 解码）；
4. 过滤 `http.response.code == 302` 看 Location，确定当前 EPG 节点；
5. 机顶盒 IP = 该认证流量的源 IP。

## 四、抓包要点

- 机顶盒**开机 / 主页刷新 / 换台**才发认证请求，空闲时段抓不到；
- 镜像口：光猫 IPTV 口 → 交换机镜像 → 抓包机；或路由器 LAN 侧抓机顶盒与
  EDS 的流量（若机顶盒经路由器出网）；
- 光猫交换芯片常不转发机顶盒单播帧到镜像口，抓不到时换在路由器
  IPTV VLAN 子接口上抓（`tcpdump -i eth2.49 -w /tmp/c.pcap`）；
- 抓包时间覆盖机顶盒完整开机流程（≥60 秒），文件放用户目录外更稳妥（避免权限问题）。

## 五、拿到 Authenticator 之后

声明 key ≠ 实际加密 key 时（罕见但存在），用 3DES-ECB 对 Authenticator
爆破 8 位数字 key，以解密结果中出现合法 `UserID` / `STBID` 为命中判据。
参考实现见 luci-app-iptv-channels 项目的 `crack_key.py`（MIT，源码出处：
https://github.com/mytv-android/IPTV-channels 及其移植版 luci-app-iptv-channels）。
