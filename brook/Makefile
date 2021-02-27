# Copyright (C) 2020 xiaorouji
#
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=brook
PKG_VERSION:=20210214
PKG_RELEASE:=1

ifeq ($(ARCH),i386)
	PKG_ARCH:=386
endif
ifeq ($(ARCH),x86_64)
	PKG_ARCH:=amd64
endif
ifeq ($(ARCH),mipsel)
	PKG_ARCH:=mipsle
endif
ifeq ($(ARCH),mips)
	PKG_ARCH:=mips
endif
ifeq ($(ARCH),arm)
	PKG_ARCH:=arm7
endif
ifeq ($(BOARD),bcm53xx)
	PKG_ARCH:=arm6
endif
ifeq ($(BOARD),kirkwood)
	PKG_ARCH:=arm5
endif
ifeq ($(ARCH),arm64)
	PKG_ARCH:=arm64
endif
ifeq ($(ARCH),aarch64)
	PKG_ARCH:=arm64
endif

PKG_FILE:=$(PKG_NAME)_$(PKG_VERSION)_$(PKG_ARCH)
PKG_URL:=https://github.com/txthinking/brook/releases/download/v$(PKG_VERSION)/$(PKG_NAME)_linux_$(PKG_ARCH)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_VERSION)
PKG_HASH:=skip

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Brook is a cross-platform proxy software
	DEPENDS:=
	URL:=https://github.com/txthinking/brook
endef

define Package/$(PKG_NAME)/description
  Brook is a cross-platform proxy software
endef

define Build/Prepare
	if [ ! -f $(DL_DIR)/$(PKG_FILE) ] ; then \
		curl -f --connect-timeout 20 --retry 5 --location --insecure $(PKG_URL) -o $(DL_DIR)/$(PKG_FILE); \
	fi
	rm -r $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	cp -f $(DL_DIR)/$(PKG_FILE) $(PKG_BUILD_DIR)/$(PKG_NAME)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin/brook
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
