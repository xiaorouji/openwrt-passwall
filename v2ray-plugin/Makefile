# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2020 SharerMax
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=v2ray-plugin
PKG_VERSION:=4.43.0
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/teddysun/v2ray-plugin/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=2de15ec4b66ee401fe83e31ad78d5d4c6d9f7b242b8fe7d8af5ce4f19bdf565a

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=madeye <max.c.lv@gmail.com>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/shadowsocks/v2ray-plugin
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=main.VERSION=v$(PKG_VERSION)

PKG_CONFIG_DEPENDS := \
	CONFIG_V2RAY_PLUGIN_INCLUDE_GOPROXY \
	CONFIG_V2RAY_PLUGIN_COMPRESS_UPX

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/v2ray-plugin/config
config V2RAY_PLUGIN_INCLUDE_GOPROXY
	bool "Compiling with GOPROXY proxy"
	default n

config V2RAY_PLUGIN_COMPRESS_UPX
	bool "Compress executable files with UPX"
	depends on !mips64
	default y
endef

ifeq ($(CONFIG_V2RAY_PLUGIN_INCLUDE_GOPROXY),y)
export GO111MODULE=on
export GOPROXY=https://goproxy.io
#export GOPROXY=https://mirrors.aliyun.com/goproxy/
endif

define Package/v2ray-plugin
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=SIP003 plugin for shadowsocks, based on v2ray
  URL:=https://github.com/teddysun/v2ray-plugin
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Build/Compile
	$(call GoPackage/Build/Compile)
ifneq ($(CONFIG_V2RAY_PLUGIN_COMPRESS_UPX),)
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(GO_PKG_BUILD_BIN_DIR)/v2ray-plugin
endif
endef

define Package/v2ray-plugin/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/v2ray-plugin $(1)/usr/bin/v2ray-plugin
endef

$(eval $(call GoBinPackage,v2ray-plugin))
$(eval $(call BuildPackage,v2ray-plugin))
