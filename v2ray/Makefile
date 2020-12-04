#
# Copyright (C) 2019-2020 Xingwang Liao
# Copyright (C) 2019-2021 Mattraks
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=v2ray
PKG_VERSION:=4.33.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/v2ray-core-$(PKG_VERSION)

PKG_SOURCE:=v2ray-core-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/v2fly/v2ray-core/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=ce456df0a798e1ed76ec014cb619e89c508bfb812c689260067575ee94e18c76

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Xingwang Liao <kuoruan@gmail.com>

PKG_CONFIG_DEPENDS:= \
	CONFIG_V2RAY_JSON_V2CTL \
	CONFIG_V2RAY_JSON_INTERNAL \
	CONFIG_V2RAY_JSON_NONE \
	CONFIG_V2RAY_EXCLUDE_V2CTL \
	CONFIG_V2RAY_EXCLUDE_ASSETS \
	CONFIG_V2RAY_COMPRESS_GOPROXY \
	CONFIG_V2RAY_COMPRESS_UPX \
	CONFIG_V2RAY_CUSTOM_FEATURES \
	CONFIG_V2RAY_WITHOUT_DNS \
	CONFIG_V2RAY_WITHOUT_LOG \
	CONFIG_V2RAY_WITHOUT_TLS \
	CONFIG_V2RAY_WITHOUT_UDP \
	CONFIG_V2RAY_WITHOUT_POLICY \
	CONFIG_V2RAY_WITHOUT_REVERSE \
	CONFIG_V2RAY_WITHOUT_ROUTING \
	CONFIG_V2RAY_WITHOUT_STATISTICS \
	CONFIG_V2RAY_WITHOUT_BLACKHOLE_PROTO \
	CONFIG_V2RAY_WITHOUT_DNS_PROXY \
	CONFIG_V2RAY_WITHOUT_DOKODEMO_PROTO \
	CONFIG_V2RAY_WITHOUT_FREEDOM_PROTO \
	CONFIG_V2RAY_WITHOUT_MTPROTO_PROXY \
	CONFIG_V2RAY_WITHOUT_HTTP_PROTO \
	CONFIG_V2RAY_WITHOUT_SHADOWSOCKS_PROTO \
	CONFIG_V2RAY_WITHOUT_SOCKS_PROTO \
	CONFIG_V2RAY_WITHOUT_VMESS_PROTO \
	CONFIG_V2RAY_WITHOUT_TCP_TRANS \
	CONFIG_V2RAY_WITHOUT_MKCP_TRANS \
	CONFIG_V2RAY_WITHOUT_WEBSOCKET_TRANS \
	CONFIG_V2RAY_WITHOUT_HTTP2_TRANS \
	CONFIG_V2RAY_WITHOUT_DOMAIN_SOCKET_TRANS \
	CONFIG_V2RAY_WITHOUT_QUIC_TRANS

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=v2ray.com/core
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG).version=$(PKG_VERSION) \
	$(GO_PKG).codename=OpenWrt

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/$(PKG_NAME)
  TITLE:=A platform for building proxies
  URL:=https://www.v2fly.org
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Project V
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-certificates
endef

define Package/$(PKG_NAME)/config
	source "$(SOURCE)/Config.in"
endef

define Package/$(PKG_NAME)/description
Project V is a set of network tools that help you to build your own computer network.
It secures your network connections and thus protects your privacy.

  This package contains v2ray, v2ctl, geoip.dat and geosite.dat.
endef

ifeq ($(CONFIG_V2RAY_COMPRESS_GOPROXY),y)
export GO111MODULE=on
export GOPROXY=https://goproxy.io
#export GOPROXY=https://mirrors.aliyun.com/goproxy/
endif

V2RAY_SED_ARGS:=

ifeq ($(CONFIG_V2RAY_JSON_INTERNAL),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/main/json",// &,; \
	s,// \(_ "$(GO_PKG)/main/jsonem"\),\1,;
else ifeq ($(CONFIG_V2RAY_JSON_NONE),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/main/json",// &,;
endif

ifeq ($(CONFIG_V2RAY_CUSTOM_FEATURES),y)

ifeq ($(CONFIG_V2RAY_WITHOUT_DNS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/dns",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_LOG),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/log",// &,; \
	s,_ "$(GO_PKG)/app/log/command",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_TLS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/tls",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_UDP),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/udp",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_POLICY),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/policy",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_REVERSE),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/reverse",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_ROUTING),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/router",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_STATISTICS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/app/stats",// &,; \
	s,_ "$(GO_PKG)/app/stats/command",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_BLACKHOLE_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/blackhole",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_DNS_PROXY),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/dns",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_DOKODEMO_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/dokodemo",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_FREEDOM_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/freedom",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_MTPROTO_PROXY),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/mtproto",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_HTTP_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/http",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_SHADOWSOCKS_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/shadowsocks",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_SOCKS_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/socks",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_VMESS_PROTO),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/proxy/vmess/inbound",// &,; \
	s,_ "$(GO_PKG)/proxy/vmess/outbound",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_TCP_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/tcp",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_MKCP_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/kcp",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_WEBSOCKET_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/websocket",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_HTTP2_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/http",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/http",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_DOMAIN_SOCKET_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/domainsocket",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_QUIC_TRANS),y)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/quic",// &,;
endif

ifeq ($(CONFIG_V2RAY_WITHOUT_MKCP_TRANS)$(CONFIG_V2RAY_WITHOUT_QUIC_TRANS),yy)
V2RAY_SED_ARGS += \
	s,_ "$(GO_PKG)/transport/internet/headers/noop",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/srtp",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/tls",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/utp",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/wechat",// &,; \
	s,_ "$(GO_PKG)/transport/internet/headers/wireguard",// &,;
endif

endif # custom features

GEOIP_VER:=latest
GEOIP_FILE:=geoip-$(GEOIP_VER).dat

define Download/geoip.dat
  URL:=https://github.com/v2fly/geoip/releases/$(GEOIP_VER)/download
  URL_FILE:=geoip.dat
  FILE:=$(GEOIP_FILE)
  HASH:=skip
endef

GEOSITE_VER:=latest
GEOSITE_FILE:=geosite-$(GEOSITE_VER).dat

define Download/geosite.dat
  URL:=https://github.com/v2fly/domain-list-community/releases/$(GEOSITE_VER)/download
  URL_FILE:=dlc.dat
  FILE:=$(GEOSITE_FILE)
  HASH:=skip
endef

define Build/Prepare
	$(call Build/Prepare/Default)

ifneq ($(CONFIG_V2RAY_EXCLUDE_ASSETS),y)
	# move file to make sure download new file every build
	mv -f $(DL_DIR)/$(GEOIP_FILE) $(PKG_BUILD_DIR)/geoip.dat
	mv -f $(DL_DIR)/$(GEOSITE_FILE) $(PKG_BUILD_DIR)/geosite.dat
endif

ifneq ($(V2RAY_SED_ARGS),)
	( \
		$(SED) \
			'$(V2RAY_SED_ARGS)' \
			$(PKG_BUILD_DIR)/main/distro/all/all.go ; \
	)
endif
endef

define Build/Compile
	$(eval GO_PKG_BUILD_PKG:=$(GO_PKG)/main)
	$(call GoPackage/Build/Compile)
	mv -f $(GO_PKG_BUILD_BIN_DIR)/main $(GO_PKG_BUILD_BIN_DIR)/v2ray

ifeq ($(CONFIG_V2RAY_COMPRESS_UPX),y)
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(GO_PKG_BUILD_BIN_DIR)/v2ray || true
endif

ifneq ($(CONFIG_V2RAY_EXCLUDE_V2CTL),y)
	$(eval GO_PKG_BUILD_PKG:=$(GO_PKG)/infra/control/main)
	$(call GoPackage/Build/Compile)
	mv -f $(GO_PKG_BUILD_BIN_DIR)/main $(GO_PKG_BUILD_BIN_DIR)/v2ctl

ifeq ($(CONFIG_V2RAY_COMPRESS_UPX),y)
	$(STAGING_DIR_HOST)/bin/upx --lzma --best $(GO_PKG_BUILD_BIN_DIR)/v2ctl || true
endif
endif
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin/

	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/v2ray $(1)/usr/bin

ifneq ($(CONFIG_V2RAY_EXCLUDE_V2CTL),y)
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/v2ctl $(1)/usr/bin
endif

ifneq ($(CONFIG_V2RAY_EXCLUDE_ASSETS),y)
	$(INSTALL_DIR) $(1)/usr/share/v2ray
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/{geoip,geosite}.dat $(1)/usr/share/v2ray
endif
endef

ifneq ($(CONFIG_V2RAY_EXCLUDE_ASSETS),y)
$(eval $(call Download,geoip.dat))
$(eval $(call Download,geosite.dat))
endif

$(eval $(call GoBinPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)))
