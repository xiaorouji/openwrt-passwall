include $(TOPDIR)/rules.mk

PKG_NAME:=cdns
PKG_VERSION:=1c3dce7
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/semigodking/cdns.git
PKG_SOURCE_VERSION:=1c3dce73afcc6c614298e0eed9c08436d6346b93
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION)
PKG_SOURCE:=$(PKG_SOURCE_SUBDIR).tar.gz
PKG_BUILD_DEPENDS:=argp-standalone

PKG_LICENSE:=Apache 2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Zhuofei Wang <semigodking@gmail.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	TITLE:=CureDNS is an experimental tool to cure your poisoned DNS.
	URL:=https://github.com/semigodking/cdns
	DEPENDS:=+libevent2
endef

define Package/$(PKG_NAME)/conffiles
#/etc/cdns.json
endef

define Package/$(PKG_NAME)/description
cdns is an experimental tool to cure your poisoned DNS.
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cdns $(1)/usr/bin
	#$(INSTALL_DIR) $(1)/etc
	#$(INSTALL_CONF) ./files/cdns.json $(1)/etc/cdns.json
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
