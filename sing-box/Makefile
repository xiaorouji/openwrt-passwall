#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sing-box
PKG_VERSION:=1.1
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/SagerNet/sing-box/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=156d717b46eec252a4a1042b41a3aa5c0fbd5ab684de4f535ceedb542fb99ef6

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILE:=LICENSE

PKG_CONFIG_DEPENDS:= \
	CONFIG_SING_BOX_BUILD_ACME \
	CONFIG_SING_BOX_BUILD_CLASH_API \
	CONFIG_SING_BOX_BUILD_ECH \
	CONFIG_SING_BOX_BUILD_GVISOR \
	CONFIG_SING_BOX_BUILD_GRPC \
	CONFIG_SING_BOX_BUILD_QUIC \
	CONFIG_SING_BOX_BUILD_SHADOWSOCKSR \
	CONFIG_SING_BOX_BUILD_UTLS \
	CONFIG_SING_BOX_BUILD_V2RAY_API \
	CONFIG_SING_BOX_BUILD_WIREGUARD

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/sagernet/sing-box
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/sing-box
GO_PKG_LDFLAGS_X:=$(GO_PKG)/constant.Version=v$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/$(PKG_NAME)
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=The universal proxy platform.
  URL:=https://sing-box.sagernet.org
  DEPENDS:=$(GO_ARCH_DEPENDS) \
    +ca-bundle \
    +kmod-inet-diag \
    +kmod-netlink-diag \
    +kmod-tun
endef

GO_PKG_TARGET_VARS:=$(filter-out CGO_ENABLED=%,$(GO_PKG_TARGET_VARS)) CGO_ENABLED=0

define Package/$(PKG_NAME)/config
  menu "Customizing build tags"

    config SING_BOX_BUILD_ACME
      bool "Build with ACME TLS certificate issuer support"
      default n

    config SING_BOX_BUILD_CLASH_API
      bool "Build with Clash API support (EXPERIMENTAL!!!)"
      default y

    config SING_BOX_BUILD_ECH
      bool "Build with TLS ECH extension support"
      default n

    config SING_BOX_BUILD_GRPC
      bool "Build with standard gRPC support"
      default n
      help
      sing-box has better performance gun-lite gRPC built-in by default.
      This standard gRPC has better compatibility but poor performance.

    config SING_BOX_BUILD_GVISOR
      bool "Build with gVisor support"
      default n

    config SING_BOX_BUILD_QUIC
      bool "Build with QUIC support"
      default y
      help
        Required by HTTP3 DNS transports, Naive inbound,
        Hysteria inbound / outbound, and v2ray QUIC transport.

    config SING_BOX_BUILD_SHADOWSOCKSR
      bool "Build with ShadowsockR support"
      default n

    config SING_BOX_BUILD_UTLS
      bool "Build with uTLS support"
      default y

    config SING_BOX_BUILD_V2RAY_API
      bool "Build with V2Ray API support (EXPERIMENTAL!!!)"
      default n

    config SING_BOX_BUILD_WIREGUARD
      bool "Build with WireGuard support"
      default y

  endmenu
endef

PKG_BUILD_TAGS:=
ifneq ($(CONFIG_SING_BOX_BUILD_ACME),)
  PKG_BUILD_TAGS+=with_acme
endif
ifneq ($(CONFIG_SING_BOX_BUILD_CLASH_API),)
  PKG_BUILD_TAGS+=with_clash_api
endif
ifneq ($(CONFIG_SING_BOX_BUILD_ECH),)
  PKG_BUILD_TAGS+=with_ech
endif
ifneq ($(CONFIG_SING_BOX_BUILD_GRPC),)
  PKG_BUILD_TAGS+=with_grpc
endif
ifneq ($(CONFIG_SING_BOX_BUILD_GVISOR),)
  PKG_BUILD_TAGS+=with_gvisor
endif
ifneq ($(CONFIG_SING_BOX_BUILD_QUIC),)
  PKG_BUILD_TAGS+=with_quic
endif
ifneq ($(CONFIG_SING_BOX_BUILD_SHADOWSOCKSR),)
  PKG_BUILD_TAGS+=with_shadowsocksr
endif
ifneq ($(CONFIG_SING_BOX_BUILD_UTLS),)
  PKG_BUILD_TAGS+=with_utls
endif
ifneq ($(CONFIG_SING_BOX_BUILD_V2RAY_API),)
  PKG_BUILD_TAGS+=with_v2ray_api
endif
ifneq ($(CONFIG_SING_BOX_BUILD_WIREGUARD),)
  PKG_BUILD_TAGS+=with_wireguard
endif
GO_PKG_TAGS:=$(subst $(space),$(comma),$(strip $(PKG_BUILD_TAGS)))

define Package/$(PKG_NAME)/conffiles
/etc/sing-box/config.json
endef

define Package/$(PKG_NAME)/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/sing-box.init $(1)/etc/init.d/sing-box

	$(INSTALL_DIR) $(1)/etc/sing-box
	$(INSTALL_DATA) ./files/config.json.example $(1)/etc/sing-box/config.json.example
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh

# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/sing-box stop >/dev/null 2>&1
	/etc/init.d/sing-box disable >/dev/null 2>&1
fi
exit 0
endef

$(eval $(call GoBinPackage,sing-box))
$(eval $(call BuildPackage,sing-box))
