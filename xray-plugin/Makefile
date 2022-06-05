# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=xray-plugin
PKG_VERSION:=1.5.7
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/teddysun/xray-plugin/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=55f72a44a4089eb211ab0e35f064723c028854243e8388d0fcc5d8524aa5fb6b

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/teddysun/xray-plugin

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/xray-plugin
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=SIP003 plugin for Shadowsocks, based on Xray
  URL:=https://github.com/teddysun/xray-plugin
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/xray-plugin/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/xray-plugin $(1)/usr/bin/xray-plugin
endef

$(eval $(call GoBinPackage,xray-plugin))
$(eval $(call BuildPackage,xray-plugin))
