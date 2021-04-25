include $(TOPDIR)/rules.mk

PKG_NAME:=chinadns-ng
PKG_VERSION:=1.0-beta.24
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/zfl9/chinadns-ng.git
PKG_MIRROR_HASH:=4b0a159e1ecd81392a67b31528b0430afa991bfceef5dd60d2d843edfccb6b12
PKG_SOURCE_VERSION:=df3bb7c6310df9b3c0f874b7a0c38ea5ce0996cb

PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=pexcn <i@pexcn.me>

include $(INCLUDE_DIR)/package.mk

define Package/chinadns-ng
	SECTION:=net
	CATEGORY:=Network
	TITLE:=ChinaDNS next generation, refactoring with epoll and ipset
	URL:=https://github.com/zfl9/chinadns-ng
	DEPENDS:=+ipset
endef

define Package/chinadns-ng/description
ChinaDNS next generation, refactoring with epoll and ipset.
endef

define Package/chinadns-ng/conffiles
endef

define Package/chinadns-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/chinadns-ng $(1)/usr/bin
endef

$(eval $(call BuildPackage,chinadns-ng))
