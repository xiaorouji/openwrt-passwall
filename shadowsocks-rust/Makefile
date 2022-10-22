# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-rust
PKG_VERSION:=1.15.0-alpha.9
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE_HEADER:=shadowsocks-v$(PKG_VERSION)
PKG_SOURCE_BODY:=unknown-linux-musl
PKG_SOURCE_FOOTER:=tar.xz
PKG_SOURCE_URL:=https://github.com/shadowsocks/shadowsocks-rust/releases/download/v$(PKG_VERSION)/

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).aarch64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=bb5a88f8732f1e804ff8533e50ad5b7e4cc72bb780240886df64c3d709413002
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabi.$(PKG_SOURCE_FOOTER)
    PKG_HASH:=493577b1193c980b1471231f9e5b3d124700fc7845edfec39660719cc62d2828
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabihf.$(PKG_SOURCE_FOOTER)
    PKG_HASH:=076b8987dcd9ec9e3d5386469d7efc8eefd0dd1c5267d6f5694ec5f191969e47
  endif
else ifeq ($(ARCH),i386)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).i686-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=72b96c5c0ab4eaad12f14970c3882e311f5f0e75df1bf8c8e9bb8e7825a3bb89
else ifeq ($(ARCH),mips)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mips-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=f3ae1d678a0e5d1566542a3be30c97b8412fb07e569691c7642498333db1b1ec
else ifeq ($(ARCH),mipsel)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mipsel-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=86bb6943a1f4bd3b61c9f43ddd7977065461915e963ee872de9edb57b2517225
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).x86_64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=b29f9e623bb3d74717159f5d999eed41d7f89317ca3adaed84cef5012e0f4308
# Set the default value to make OpenWrt Package Checker happy
else
  PKG_SOURCE:=dummy
  PKG_HASH:=dummy
endif

PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

TAR_CMD:=$(HOST_TAR) -C $(PKG_BUILD_DIR) $(TAR_OPTIONS)

define Package/shadowsocks-rust/Default
  define Package/shadowsocks-rust-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=shadowsocks-rust $(1)
    URL:=https://github.com/shadowsocks/shadowsocks-rust
    DEPENDS:=@USE_MUSL @(aarch64||arm||i386||mips||mipsel||x86_64) @!(TARGET_x86_geode||TARGET_x86_legacy)
  endef

  define Package/shadowsocks-rust-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_BUILD_DIR)/$(1) $$(1)/usr/bin
  endef
endef

SHADOWSOCKS_COMPONENTS:=sslocal ssmanager ssserver ssurl ssservice
define shadowsocks-rust/templates
  $(foreach component,$(SHADOWSOCKS_COMPONENTS),
    $(call Package/shadowsocks-rust/Default,$(component))
  )
endef
$(eval $(call shadowsocks-rust/templates))

define Build/Compile
endef

$(foreach component,$(SHADOWSOCKS_COMPONENTS), \
  $(eval $(call BuildPackage,shadowsocks-rust-$(component))) \
)
