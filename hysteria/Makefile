# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria
PKG_VERSION:=1.2.1
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/HyNetwork/hysteria/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=cdac1f149651ca5eaa77ea69ee913d0f1391a07da681ad4908a60a6603307543

PKG_LICENSE:=MIT
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/HyNetwork/hysteria
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd
GO_PKG_LDFLAGS_X:=main.appVersion=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/hysteria
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A feature-packed network utility optimized for networks of poor quality
  URL:=https://github.com/tobyxdd/hysteria
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/hysteria/description
  Hysteria is a feature-packed network utility optimized for networks
  of poor quality (e.g. satellite connections, congested public Wi-Fi,
  connecting from China to servers abroad) powered by a custom version
  of QUIC protocol.
endef

define Package/hysteria/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))

	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/cmd $(1)/usr/bin/hysteria
endef

$(eval $(call GoBinPackage,hysteria))
$(eval $(call BuildPackage,hysteria))
