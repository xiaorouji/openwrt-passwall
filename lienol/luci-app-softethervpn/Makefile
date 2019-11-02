# Copyright (C) 2018-2019 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for SoftEtherVPN
LUCI_DEPENDS:=+zlib +libpthread +librt +libreadline +libncurses +libiconv-full +kmod-tun +libopenssl +softethervpn-bridge +softethervpn-client +softethervpn-server
LUCI_PKGARCH:=all
PKG_VERSION:=1.0
PKG_RELEASE:=9-20191102

include ../luci_my.mk

# call BuildPackage - OpenWrt buildroot signature


