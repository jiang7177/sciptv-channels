include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-iptv-channels
PKG_VERSION:=1.2.3
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for IPTV-channels (四川电信 IPTV 组播/EPG 获取)
LUCI_DESCRIPTION:=移植自 mytv-android/IPTV-channels。通过 IPTV 线路自动获取电信 IPTV 组播地址、回放地址及官方 EPG 节目单，生成 DIYP 格式 sctv.txt / sctv.m3u 与 XMLTV 格式 epg.xml。
LUCI_DEPENDS:=+luci-base +python3-light +python3-requests +python3-logging +openssl-util
LUCI_PKGARCH:=all

PKG_LICENSE:=MIT
PKG_MAINTAINER:=

define Package/$(PKG_NAME)/conffiles
/etc/config/iptv-channels
endef

# 自定义 postinst:
# 1. 强制修正脚本执行位 —— 源码若在 Windows 下编辑/打包, init.d 与 rpcd 脚本
#    可能丢失 +x 位, 导致安装时报 "Permission denied" (1.0.0 实际踩坑)
# 2. 复现 luci.mk 默认 postinst 行为 (清 LuCI 缓存 + 重载 rpcd)
define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod 0755 "$${IPKG_INSTROOT}/etc/init.d/iptv-channels" \
	"$${IPKG_INSTROOT}/usr/libexec/rpcd/iptv-channels" 2>/dev/null || :
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload 2>/dev/null
	exit 0
}
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
