# Copyright (C) 2018 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-server-center
PKG_VERSION:=1.0
PKG_RELEASE:=32-20190407

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PO2LMO:=./po2lmo
 
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/config
menu "Configuration"
	
config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Python_Server
	bool "Include ShadowsocksR Python Server"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server (ssr-server)"
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Server
	bool "Include V2ray Server"
	default n

endmenu
endef

define Package/$(PKG_NAME)
  CATEGORY:=LuCI for Lienol
  SUBMENU:=3. Applications
  TITLE:=LuCI support for Server Center By Lienol
  PKGARCH:=all
  DEPENDS:=+libsodium +luci-lib-jsonc \
  +python \
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
	$(INSTALL_CONF) ./root/etc/config/server_center $(1)/etc/config/server_center
	$(INSTALL_CONF) ./root/etc/uci-defaults/* $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/init.d/server_center $(1)/etc/init.d/server_center
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./luasrc/* $(1)/usr/lib/lua/luci/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	chmod 755 $(PO2LMO)
	$(PO2LMO) ./po/zh-cn/server_center.po $(1)/usr/lib/lua/luci/i18n/server_center.zh-cn.lmo
	
ifdef CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Python_Server
	$(INSTALL_DIR) $(1)/usr/share/ssr_python
	cp -pR ./root/usr/share/ssr_python/* $(1)/usr/share/ssr_python/
endif
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod a+x $${IPKG_INSTROOT}/usr/share/ssr_python/* >/dev/null 2>&1
exit 0
endef

$(eval $(call BuildPackage,$(PKG_NAME)))