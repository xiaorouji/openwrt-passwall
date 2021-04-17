#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
#
# Copyright (C) 2021 ImmortalWrt
# <https://immortalwrt.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-rust
PKG_VERSION:=1.10.5
PKG_RELEASE:=1

PKG_SOURCE_HEADER:=shadowsocks-v$(PKG_VERSION)
PKG_SOURCE_BODY:=unknown-linux-musl
PKG_SOURCE_FOOTER:=tar.xz
PKG_SOURCE_URL:=https://github.com/shell-script/openwrt-shadowsocks-rust/releases/download/v$(PKG_VERSION)/

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).aarch64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=edf48c3035efa5a27d7c7e26fc4f9531391bbf0cbb189072de0fb7b5c99570f9
else ifeq ($(ARCH),arm)
  # Referred to golang/golang-values.mk
  ARM_CPU_FEATURES:=$(word 2,$(subst +,$(space),$(call qstrip,$(CONFIG_CPU_TYPE))))
  ifeq ($(ARM_CPU_FEATURES),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabi.$(PKG_SOURCE_FOOTER)
    PKG_HASH:=acefd212c71697c4ebad48e9ea8f63815a24d6698842b8815b979085356479a4
  else ifneq ($(filter $(ARM_CPU_FEATURES),vfp vfpv2),)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).arm-$(PKG_SOURCE_BODY)eabihf.$(PKG_SOURCE_FOOTER)
    PKG_HASH:=8ade88e98d4a278d40519f37e83f481b188a5e286b633636ce92e96538d17a21
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).armv7-$(PKG_SOURCE_BODY)eabihf.$(PKG_SOURCE_FOOTER)
    PKG_HASH:=54b3db3cdb1c70db4cd6d7e5844a792bc90fffe69d61e035c45d03560a6f2c5a
  endif
else ifeq ($(ARCH),i386)
  ifeq ($(CONFIG_TARGET_x86_geode)$(CONFIG_TARGET_x86_legacy),y)
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).i586-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=b4042f48a85fd419edd165edeb138a8a1b6ec543da3e9dce01f3bf1fe77e49d2
  else
    PKG_SOURCE:=$(PKG_SOURCE_HEADER).i686-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
    PKG_HASH:=239875027c7e744f0661e6ff3106a6b90d276f7dce0c144af741dc1577b1363c
  endif
else ifeq ($(ARCH),mips)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mips-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=8e1b97a482e4f5312d84aab21ea03a38623591564b3a5c226a50373bd0673746
else ifeq ($(ARCH),mipsel)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).mipsel-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=7f3e2bbdbc548accef0f8519df14df83ccba0067c76570c0d840a0c4e8a3b62a
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=$(PKG_SOURCE_HEADER).x86_64-$(PKG_SOURCE_BODY).$(PKG_SOURCE_FOOTER)
  PKG_HASH:=e916732923daed05fc5e2878dbd36ff1444b157128e80a57d12b688a8844ad31
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
    DEPENDS:=@(aarch64||arm||i386||mips||mipsel||x86_64) @USE_MUSL
  endef

  define Package/shadowsocks-rust-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_BUILD_DIR)/$(1) $$(1)/usr/bin
  endef
endef

SHADOWSOCKS_COMPONENTS:=sslocal ssmanager ssserver ssurl
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