# luci-app-iptv-channels

四川电信 IPTV 组播地址 / 回放地址 / EPG 节目单获取工具的 **OpenWrt LuCI 版本**。

移植自 [mytv-android/IPTV-channels](https://github.com/bf963/IPTV-channels)（原版为 Docker + Flask + Python Web 应用），本版本将核心抓取逻辑移植到 OpenWrt 路由器上，以 UCI 管理配置、LuCI 提供管理界面、crontab 提供定时更新，**无需 Docker、无需常驻 Flask 服务**。

## 功能

- 通过 IPTV 线路向电信 EPG 服务器认证并抓取频道列表（组播地址、时移回放、FCC/FEC 参数）
- 生成 DIYP 格式 `sctv.txt`、`sctv.m3u` 及 XMLTV 格式 `epg.xml`
- 输出文件在 LuCI **频道列表页直接下载**（rpcd 分块读取 `/etc/iptv-channels/output`，
  不依赖 `/www` 目录可写，不受固件权限限制）
- LuCI 设置页：填配置、一键更新、实时查看运行日志
- LuCI 频道页：查看解析后的频道列表
- crontab 定时自动更新（如每天凌晨 5 点）
- 可选：EPG 自动同步到 Git 仓库（需安装 `git`）
- 3DES 认证加密默认使用路由器自带的 `openssl`；安装 `python3-pycryptodome` 后支持根据 Authenticator 自动破解 8 位 key
- **手动 / 自动双模式**：自动模式通过嗅探机顶盒明文认证流量自动获取全部认证参数（含 EDS 入口、机顶盒 IP 等）并写回配置，EDS 变更后重新嗅探即可自动跟随；LuCI 支持"立即发现参数"一键嗅探

## 目录结构

```
luci-app-iptv-channels/
├── Makefile                                    # OpenWrt 包定义 (luci.mk)
├── htdocs/luci-static/resources/
│   ├── icons/iptv-channels.svg
│   └── view/iptv-channels/
│       ├── settings.js                         # 设置页 (认证/高级/定时 + 日志)
│       └── channels.js                         # 频道列表页
└── root/
    ├── etc/config/iptv-channels                # UCI 默认配置 (空白, 不含任何账号参数)
    ├── etc/hotplug.d/iface/90-iptv-channels-routes  # IPTV 网段路由自动跟随
    ├── etc/init.d/iptv-channels                # init 脚本 (目录 + crontab 管理)
    └── usr/
        ├── libexec/rpcd/iptv-channels          # rpcd ubus 后端
        ├── share/iptv-channels/iptv_channels.py # 抓取脚本 (合并原 crypt_1.py)
        ├── share/luci/menu.d/luci-app-iptv-channels.json
        └── share/rpcd/acl.d/luci-app-iptv-channels.json
```

## 编译

将本目录复制到 LuCI feed 的 applications 目录后编译：

```sh
# 假设已安装好 OpenWrt feeds
cp -r luci-app-iptv-channels feeds/luci/applications/
./scripts/feeds update luci 2>/dev/null; ./scripts/feeds install -a 2>/dev/null  # 或直接重复编译流程
make menuconfig   # LuCI -> Applications -> luci-app-iptv-channels
make package/luci-app-iptv-channels/compile V=s
```

生成的 ipk 在 `bin/packages/<arch>/` 下，`opkg install` 安装即可。

### CI 自动编译（GitHub Actions）

仓库内置工作流（`.github/workflows/build.yml`），**仅手动触发**（无 push / PR /
定时等任何自动构建）：在 GitHub 仓库的 Actions 页面选择该工作流，点
"Run workflow" 即产出双格式安装包（Artifacts 中的 `packages`）：

- **`.ipk`** — opkg 固件（OpenWrt 24.10 及更早），`opkg install xxx.ipk`
- **`.apk`** — apk 固件（OpenWrt 25.x / snapshot，apk-tools 3），安装：
  ```sh
  apk add --allow-untrusted ./luci-app-iptv-channels_x.y.z-rN_all.apk
  ```
  （apk 未签名，需 `--allow-untrusted`；或自行用 `apk 生成密钥` 签名）

工作流自包含、不依赖本地脚本，且自动识别两种仓库布局
（源码在子目录 / 源码即仓库根）。

> 依赖会自动安装：`luci-base`、`python3-light`、`python3-requests`、`python3-logging`、`openssl-util`。
> 可选增强：`python3-pycryptodome`（Authenticator 破解 key）、`git`（EPG Git 同步）、`rtp2httpd`（组播转 HTTP 播放）。

> **执行位说明**：1.0.1 起包内自带 postinst 安装后自动 `chmod 0755` 修复
> `/etc/init.d/iptv-channels` 与 `/usr/libexec/rpcd/iptv-channels`，
> 从 Windows 环境打包源码也不会再出现安装时 "Permission denied"。

> **自动模式依赖**：`opkg install tcpdump`。嗅探原理：机顶盒与路由器同处
> IPTV VLAN 广播域，tcpdump 混杂模式可在 IPTV 网口上捕获机顶盒发给 EDS 的
> 全部明文 HTTP 认证报文。
> 1.0.0 及更早版本如遇到该报错，手动执行：
> `chmod 755 /etc/init.d/iptv-channels /usr/libexec/rpcd/iptv-channels` 即可。

## 使用

1. 安装后在 **服务 → IPTV 频道获取** 打开设置页；
2. 填入机顶盒抓包获得的参数（必填：机顶盒 IP、UserID、MAC、STBID、8 位 key）；
3. 确认路由器 IPTV 口已正确接入（机顶盒 IP 可达），点击 **保存并立即更新**；
4. 观察日志输出，成功后到 **频道列表** 页核对并下载输出文件（页面内"下载"按钮），
   播放器里加载下载得到的 `sctv.m3u` 与 EPG `epg.xml`；
5. 在"定时更新"标签中启用 crontab 定时任务并点 **应用定时任务**。

### 认证参数的获取方法

本插件**出厂不带任何账号参数**，需要针对自己的线路获取一次：

- **抓包法（通用）**：在光猫与机顶盒之间的链路抓包（Wireshark / 路由器
  tcpdump），机顶盒开机或重新认证时会发出**明文 HTTP** 认证报文
  （`/EDS/jsp/AuthenticationURL`、`ValidAuthenticationHWCTC.jsp` 等），
  URL 与表单里包含 UserID、MAC、STBID、STBType、templateName、areaId、
  EDS 入口地址等全部参数；8 位 key 可从机顶盒配置或认证串爆破获得
  （安装 `python3-pycryptodome` 后填写 Authenticator 即可自动尝试破解）。
- **自动嗅探（LuCI 内置）**：若机顶盒流量经过路由器（如同桥接在同一
  广播域），设置页"自动模式"的 **立即发现参数（嗅探）** 按钮可直接在
  路由器上完成上述嗅探与解析并写回配置。注意部分光猫交换芯片不转发
  机顶盒单播帧，此时嗅探抓不到，请用抓包法手动填写。
- **EDS 入口失效**：账号参数只需填一次；EDS 节点轮换后入口探测会自动
  跟随，无需重新抓包。

### 播放说明

频道地址形如 `http://192.168.5.1:8888/rtp/239.94.0.60:5140`，指向 rtp2httpd 组播转单播服务器。
需要在 IPTV 口所在网段部署 rtp2httpd（或其他组播转 HTTP 工具），并把设置页中的
"RTP2HTTPD 服务器地址"改成实际地址。

## 更新日志

### 1.2.3 (2026-11-24)

- **修复 RTSP 时移（回看）503**：EPG 返回的 RTSP URL 自带查询串
  （`?rrsip=...&accountinfo=...`），生成 catchup-source 模板时误用 `?` 追加
  `playseek`，导致 URL 出现两个查询起点——rtp2httpd 解析错乱，上游 RTSP
  服务器返回 457，播放器报 503。现改为 `&playseek=` 追加（URL 无查询串时仍用 `?`）。
  实机验证：Range Seek 窗口内与 Playseek 透传两条路径均恢复 200 且稳定出流。

### 1.2.2 (2026-11-23)

- **EPG 网段路由自检（治本修复）**：实测发现 IPTV 线路 DHCP 静默 renew
  换地址池（如 10.58.96.0/20 → 10.252.96.0/19）时**不触发** iface hotplug
  事件，hotplug 钩子加的网段路由会静默丢失，导致 EDS/EPG 请求全部超时
  （入口探测"全部失败"其实是路由问题）。现脚本每次运行前幂等自检
  `epg_routes` 网段路由（默认 182.136.0.0/13、182.144.0.0/14、118.122.0.0/16），
  缺失/错误时自动经 IPTV 口 DHCP 网关补齐，从此完全自愈。
- **日志改写到内存盘**：运行日志与调试转储从 `/etc/iptv-channels/log`（flash）
  移到 `/tmp/iptv-channels/log`（tmpfs），避免每次更新写数万行日志磨损
  闪存；重启后日志自动清空，输出文件仍持久保存在 `/etc/iptv-channels/output`。
- **EDS 恢复增强**：认证时 302 跳转得到的真实 EPG 节点（如
  `182.146.x.x:33200`）会自动记入 `eds_history`；入口失效时除历史入口外
  还会尝试这些曾用节点，恢复成功率显著提升（此前只记录入口本身，
  入口下线后历史列表为空导致无法自愈）。

### 1.2.1 (2026-11-23)

- **移除"发布到 Web 目录"功能**：原实现将输出文件复制到 `/www/iptv-channels`
  供局域网直接访问，但部分固件 `/www` 挂载只读或权限受限（复制报
  Permission denied），且 Web 目录无认证保护。
  现改为在 **LuCI 频道列表页** 内直接下载：rpcd 新增 `download` 方法
  （文件白名单 + 分块 base64 读取 `/etc/iptv-channels/output`），前端分块
  拉取后经 Blob 保存到本机，不依赖 `/www` 可写，下载走 LuCI 登录会话。
- 移除 `publish_www` 配置项（升级后自动忽略残留值）。

### 1.2.0 (2026-11-23)

新增**手动 / 自动双模式**，解决 EDS 等平台参数变化导致的失效问题（实机验证：
EDS 节点会轮换，入口以 302 指向当前 EPG 节点；频道组播地址本身不随 EDS 变化）：

- **EDS 入口自动探测（主策略，任何拓扑可用）**：每次更新前探测当前认证入口，
  失效时自动遍历历史可用节点（`eds_history`），找到即自动写入
  `authentication_url` 并跟随（`/EDS/jsp` 与 `/EPG/jsp` 两种入口路径均支持）。
  实机验证：将入口改为不可达地址后，自动恢复到真实可用节点。
- **EDS 网段扫描（兜底，可选）**：所有已知入口都不可达时，并发扫描
  `182.138.0.0/16` 的 8082/8001 端口寻找新入口（`eds_scan` 开关，默认关闭）。
- **嗅探发现（机顶盒流量经过路由器时可用）**：auto 模式通过 tcpdump 混杂嗅探
  IPTV 网口上机顶盒的明文 HTTP 认证报文，自动提取 UserID、机顶盒 IP、MAC、
  STBID、STBType、STBVersion、templateName、areaId、EDS 入口并写回 UCI。
  注意：光猫交换芯片不转发机顶盒单播帧的拓扑下嗅探会一无所获（实测如此），
  此时 EDS 入口探测仍然有效，账号参数只需手动/抓包填写一次。
  - LuCI 设置页新增"自动模式"标签页（运行模式 / 嗅探网口 / 嗅探时长 /
    自动爆破 key / EDS 扫描开关）
  - 新增"立即发现参数（嗅探）"按钮：后台嗅探 + 实时轮询展示结果
  - 认证失败自动重新发现并重试一次；出口网口（upstream_interface）随 EDS 自动跟随
  - 嗅探依赖：`opkg install tcpdump`
- **嗅探 Authenticator 爆破 key（可选）**：同时嗅探 EncryptToken 与机顶盒
  POST 的 Authenticator，未配置 key 时可开启自动爆破（多进程校验解密结果中的
  UserID/STBID 字段，同时恢复声明的 key；默认关闭）。
- **修复 8 位 key 的 3DES 退化问题**：8 字节 key 重复 3 次（K1=K2=K3）在
  pycryptodome 中抛 "Triple DES key degenerates to single DES"，
  现自动回退等价的单 DES（与 openssl des-ede3 行为一致）。
- rpcd 新增 `discover` 方法（start/poll），status 新增运行模式字段。

### 1.1.1 (2026-11-23)

实机调试（四川电信机顶盒抓包）发现的两个关键修复：

- **新增"认证串声明 Key"**：实测发现部分平台 Authenticator 的实际 3DES 加密 key
  与首字段声明的 key **不一致**（声明 key 只是账号标识，加密用的是另一个 key）。
  新增 `key_declared` 配置项分离二者；用错误的加密 key 会导致 EPG 返回
  `ComInfoDisplay.jsp?ERROR_TYPE=2&ERROR_ID=02`、UserToken=null。
- **新增 IPTV 网段路由 hotplug 钩子**：`/etc/hotplug.d/iface/90-iptv-channels-routes`，
  IPTV 口每次获取 DHCP 租约时自动将电信 EPG 网段（182.136.0.0/13、
  182.144.0.0/14、118.122.0.0/16）路由指向当前 DHCP 网关。原因：
  ① 电信地址池会变化（10.252.96.0/19 → 10.58.96.0/20），静态网关会失效；
  ② EDS 认证入口每次重定向到不同节点/网段，主机路由无法穷举。
  设置页同步新增"认证串声明 Key"输入框。

### 1.1.0 (2026-11-23)

- **新增"上游接口"功能**（参考 stackia/rtp2httpd 的 `upstream-interface`）：
  设置页"高级选项"新增上游接口下拉框（动态列出网口名称/状态/IP）。配置后
  抓取脚本的所有 EPG/认证 HTTP 请求通过 `source_address` 绑定到该网口的
  IPv4 地址发出，避免请求被路由表引导到错误的出口——电信 EPG 服务器通常
  仅 IPTV 内网可达，此时必须绑定 IPTV 口（如 `eth2.49`）。留空则走系统
  默认路由；网口无 IPv4 地址时自动回退默认路由并记录日志。
  实现细节：脚本经 `SIOCGIFADDR` 直接读网卡 IP（不经路由表），requests
  Session 挂载自定义 `HTTPAdapter`，代理场景同样生效。

### 1.0.2 (2026-11-23)

- **视图 tab 选项修复**：`settings.js` 中表单选项改用 `s.taboption(tab名, ...)`
  显式指定所属标签页。此前 `s.option(...)` 未绑定 tab（该固件 form.js 无
  "声明 tab 后自动归属"机制），导致所有 tab 面板为空，页面报
  `TypeError: Cannot read properties of undefined (reading 'classList')`
  （ui.js initTabGroup）并卡在"正在载入视图…"。

### 1.0.1 (2026-11-23)

修复 1.0.0 实机部署（QWRT 25.12.2 / rpcd 2024-09-17）中发现的问题：

- **rpcd 新协议兼容**：rpcd 2024-09 起调用后端脚本的协议为 `$1=call, $2=方法名`
  （旧版为 `$1=方法名`），导致 LuCI 调用全部落入"未知方法"兜底分支。
  现已双协议兼容，新旧 rpcd 均可正常工作。
- **status 输出 JSON 修复**：`status` 方法输出缺少最外层闭合大括号，
  会导致 ubus/LuCI 端 JSON 解析失败。
- **postinst 自动修正执行位**：包内新增自定义 postinst，安装后自动
  `chmod 0755` init.d 与 rpcd 后端脚本，规避源码在 Windows 下打包丢失
  执行位导致的安装报错（"Permission denied"）。
- 新增 `/etc/config/iptv-channels` 为 conffiles，升级时保留用户配置。

### 1.0.0 (2026-11-23)

首个版本：Flask/Web 版移植为 LuCI 应用（UCI 配置、rpcd 后端、init.d 定时、JS 视图）。

## 与原版的差异

| 项目 | 原版 (Docker) | LuCI 版 |
|------|---------------|---------|
| 配置 | `/app/config/config.json` | UCI `/etc/config/iptv-channels` |
| 界面 | Flask + SocketIO Web 页 | LuCI JS 视图（无常驻 Web 服务） |
| 定时 | 应用内 crontab | 系统 crontab，init.d 管理 |
| 3DES | pycryptodome | 优先 pycryptodome，缺省用 openssl-util |
| 输出 | `/app/output` | `/etc/iptv-channels/output` + LuCI 页面内下载 |
| 依赖 | Flask/bs4/socketio 等大量包 | python3-light + python3-requests + openssl-util |

## 源码出处

本项目移植自 **[mytv-android/IPTV-channels](https://github.com/mytv-android/IPTV-channels)**
（四川电信 IPTV 频道获取工具，原版为 Docker + Flask + Python Web 应用）：

- 核心的认证流程（EDS 入口探测 → 3DES 认证 → 频道/EPG 抓取）与 DIYP/XMLTV
  输出格式均来自原项目；
- 认证加密相关逻辑源自原项目的 `crypt_1.py`，移植时合并进
  `usr/share/iptv-channels/iptv_channels.py`；
- 字段含义、认证链路（含抓包提取配置参数的方法）的整理与说明见
  [mytv-android/IPTV-channels](https://github.com/mytv-android/IPTV-channels) 仓库文档。

感谢原作者的开源工作。本仓库的 LuCI 适配层（UCI/rpcd/init.d/JS 视图）为独立编写，
同样以 MIT 协议开源。

## 免责声明

本项目仅用于**个人已订阅 IPTV 服务**的自有线路调试与研究（获取自己机顶盒
产生的频道列表与节目单），不提供任何破解运营商计费/授权的能力，不含任何
账号、key 或服务器地址。请遵守当地法律法规与运营商服务协议，不得用于
商业用途或公开分发所获取的频道内容。使用本项目产生的一切后果由使用者
自行承担。

## 许可

MIT
