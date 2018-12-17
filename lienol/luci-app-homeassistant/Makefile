# Copyright (C) 2018 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-homeassistant
PKG_VERSION:=1.0
PKG_RELEASE:=5-20181217

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
 
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  CATEGORY:=LuCI for Lienol
  SUBMENU:=3. Applications
  TITLE:=LuCI support for HomeAssistant
  PKGARCH:=all
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
	$(INSTALL_DIR) $(1)/usr/share/homeassistant
	$(INSTALL_CONF) ./root/etc/config/homeassistant $(1)/etc/config/homeassistant
	$(INSTALL_CONF) ./root/etc/uci-defaults/* $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/init.d/homeassistant $(1)/etc/init.d/homeassistant
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	cp -pR ./luasrc/* $(1)/usr/lib/lua/luci/
	cp -pR ./root/usr/share/homeassistant/* $(1)/usr/share/homeassistant
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod a+x $${IPKG_INSTROOT}/usr/share/homeassistant/* >/dev/null 2>&1
exit 0
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

# call BuildPackage - OpenWrt buildroot signature


