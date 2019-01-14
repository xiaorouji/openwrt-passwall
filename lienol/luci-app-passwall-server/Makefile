# Copyright (C) 2018 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall-server
PKG_VERSION:=1.0
PKG_RELEASE:=8-20190114

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PO2LMO:=$(BUILD_DIR)/luci-base/po2lmo
 
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/config
menu "Configuration"
	depends on PACKAGE_$(PKG_NAME)
	
config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server (ssr-server)"
	default y
	
config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Python_Server
	bool "Include ShadowsocksR Python Server"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Server
	bool "Include V2ray Server"
	default n

endmenu
endef

define Package/$(PKG_NAME)
  CATEGORY:=LuCI for Lienol
  SUBMENU:=3. Applications
  TITLE:=LuCI support for PassWall Server By Lienol
  PKGARCH:=all
  DEPENDS:= \
  +PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server:shadowsocksr-libev-server \
  +PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Server:v2ray
endef

define Build/Prepare
endef
 
define Build/Configure
endef
 
define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_CONF) ./root/etc/config/passwall_server $(1)/etc/config/passwall_server
	$(INSTALL_CONF) ./root/etc/uci-defaults/* $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/init.d/passwall_server $(1)/etc/init.d/passwall_server
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./luasrc/* $(1)/usr/lib/lua/luci/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(PO2LMO) ./po/zh-cn/passwall_server.po $(1)/usr/lib/lua/luci/i18n/passwall_server.zh-cn.lmo
	
ifdef CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Python_Server
	$(INSTALL_DIR) $(1)/usr/share/ssr
	cp -pR ./root/usr/share/ssr/* $(1)/usr/share/ssr/
endif

endef

$(eval $(call BuildPackage,$(PKG_NAME)))