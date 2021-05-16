# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021 xiaorouji
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall
PKG_VERSION:=4
PKG_RELEASE:=22
PKG_DATE:=20210505

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/config
menu "Configuration"
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client
	bool "Include Shadowsocks Libev Client"
	default y
	select PACKAGE_shadowsocks-libev-ss-redir
	select PACKAGE_shadowsocks-libev-ss-local
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server
	bool "Include Shadowsocks Libev Server"
	default y
	select PACKAGE_shadowsocks-libev-ss-server
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	bool "Include Shadowsocks Rust Client"
	depends on aarch64||arm||i386||mips||mipsel||x86_64
	default n
	select PACKAGE_shadowsocks-rust-sslocal
	
config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
	bool "Include ShadowsocksR Libev Client"
	default y
	select PACKAGE_shadowsocksr-libev-ssr-local
	select PACKAGE_shadowsocksr-libev-ssr-redir

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server"
	default y
	select PACKAGE_shadowsocksr-libev-ssr-server
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Xray
	bool "Include Xray"
	default y if i386||x86_64||arm||aarch64
	select PACKAGE_xray-core
	select PACKAGE_xray-geodata

config PACKAGE_$(PKG_NAME)_INCLUDE_Trojan_Plus
	bool "Include Trojan_Plus"
	default y
	select PACKAGE_trojan-plus
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Trojan_GO
	bool "Include Trojan_GO"
	default n
	select PACKAGE_trojan-go
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Brook
	bool "Include Brook"
	default n
	select PACKAGE_brook
	
config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
	bool "Include NaiveProxy"
	default n
	select PACKAGE_naiveproxy
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Kcptun
	bool "Include Kcptun"
	default n
	select PACKAGE_kcptun-client

config PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy
	bool "Include Haproxy"
	default y
	select PACKAGE_haproxy
	
config PACKAGE_$(PKG_NAME)_INCLUDE_ChinaDNS_NG
	bool "Include ChinaDNS-NG"
	default n
	select PACKAGE_chinadns-ng
	
config PACKAGE_$(PKG_NAME)_INCLUDE_Dns2socks
	bool "Include Dns2socks"
	default y
	select PACKAGE_dns2socks
	
config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray-plugin
	bool "Include V2ray-plugin (Shadowsocks plugin)"
	default y if i386||x86_64||arm||aarch64
	select PACKAGE_v2ray-plugin

config PACKAGE_$(PKG_NAME)_INCLUDE_Simple-obfs
	bool "Include Simple-obfs (Shadowsocks plugin)"
	default y if i386||x86_64||arm||aarch64
	select PACKAGE_simple-obfs
	
config PACKAGE_$(PKG_NAME)_INCLUDE_PDNSD
	bool "Include PDNSD"
	default y
	select PACKAGE_pdnsd-alt

endmenu
endef

define Package/$(PKG_NAME)
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for PassWall
  PKGARCH:=all
  DEPENDS:=+libmbedtls +iptables-mod-tproxy +ip +ipset +coreutils +coreutils-base64 +coreutils-nohup +luci-lib-jsonc \
  +curl +ca-certificates +resolveip +unzip +dnsmasq-full +tcping +libuci-lua \
  +ipt2socks +microsocks
endef

define Build/Prepare
endef
 
define Build/Configure
endef
 
define Build/Compile
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall
/etc/config/passwall_server
/usr/share/passwall/rules/direct_host
/usr/share/passwall/rules/direct_ip
/usr/share/passwall/rules/proxy_host
/usr/share/passwall/rules/proxy_ip
/usr/share/passwall/rules/block_host
/usr/share/passwall/rules/block_ip
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./root/etc/config/passwall $(1)/etc/config/passwall
	$(INSTALL_CONF) ./root/etc/config/passwall_server $(1)/etc/config/passwall_server
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./root/etc/init.d/passwall $(1)/etc/init.d/passwall
	$(INSTALL_BIN) ./root/etc/init.d/passwall_server $(1)/etc/init.d/passwall_server
	
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_CONF) ./root/etc/uci-defaults/* $(1)/etc/uci-defaults
	
	$(INSTALL_DIR) $(1)/usr/share/passwall
	cp -pR ./root/usr/share/passwall/* $(1)/usr/share/passwall
	$(INSTALL_CONF) ./root/etc/config/passwall $(1)/usr/share/passwall/config.default
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	cp -pR ./root/usr/share/rpcd/acl.d/* $(1)/usr/share/rpcd/acl.d
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./luasrc/* $(1)/usr/lib/lua/luci/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	po2lmo ./po/zh-cn/passwall.po $(1)/usr/lib/lua/luci/i18n/passwall.zh-cn.lmo
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod a+x $${IPKG_INSTROOT}/usr/share/passwall/* >/dev/null 2>&1
chmod a+x $${IPKG_INSTROOT}/usr/lib/lua/luci/model/cbi/passwall/server/api/app.lua >/dev/null 2>&1
touch $${IPKG_INSTROOT}/etc/config/passwall_show >/dev/null 2>&1
exit 0
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
