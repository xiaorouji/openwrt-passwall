# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=2023.03.06
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/zfl9/chinadns-ng/tar.gz/$(PKG_VERSION)?
PKG_HASH:=a0bfc73cae1cd14058da09b28325ca8d3e04c66a9e7b21f31fc65e0828aea6a2

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=pexcn <i@pexcn.me>

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/chinadns-ng
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=ChinaDNS next generation, refactoring with epoll and ipset.
  URL:=https://github.com/zfl9/chinadns-ng
  DEPENDS:=+ipset
endef

define Package/chinadns-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/chinadns-ng $(1)/usr/bin
endef

$(eval $(call BuildPackage,chinadns-ng))
