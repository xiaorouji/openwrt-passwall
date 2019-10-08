# Copyright (C) 2018-2019 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-v2ray-server
LUCI_TITLE:=LuCI support for V2ray Server
LUCI_DEPENDS:=+libsodium +luci-lib-jsonc +nginx +unzip +v2ray 
LUCI_PKGARCH:=all
PKG_VERSION:=1.0
PKG_RELEASE:=13-20191008

define Package/$(PKG_NAME)/config
	select NGINX_SSL
endef

include ../luci_my.mk

# call BuildPackage - OpenWrt buildroot signature


