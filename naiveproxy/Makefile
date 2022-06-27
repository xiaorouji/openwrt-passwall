# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=naiveproxy
PKG_VERSION:=103.0.5060.53-1
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/klzgrad/naiveproxy/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=ffafe4cd5bc5a79b659520f071514db3d78531b5004c441d4b3da16c9c371ff1

PKG_LICENSE:=BSD 3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

ifneq ($(wildcard $(TOPDIR)/feeds/packages/devel/ninja/ninja.mk),)
PKG_BUILD_DEPENDS+= ninja/host
endif
NINJA ?= ninja
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

ifneq ($(CONFIG_CPU_TYPE)," ")
  CPU_TYPE:=$(word 1, $(subst +," ,$(CONFIG_CPU_TYPE)))
  CPU_SUBTYPE:=$(word 2, $(subst +, ",$(CONFIG_CPU_TYPE)))
  ifeq ($(CPU_SUBTYPE),)
    CPU_SUBTYPE:=""
  endif
else
  CPU_TYPE:=""
  CPU_SUBTYPE:=""
endif

include $(INCLUDE_DIR)/package.mk

define Package/naiveproxy/Default
  URL:=https://github.com/klzgrad/naiveproxy
  DEPENDS:=@!(arc||armeb||mips||mips64||powerpc||TARGET_gemini) +libatomic
endef

define Package/naiveproxy
  $(call Package/naiveproxy/Default)
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Make a fortune quietly
endef

define Package/libcronet
  $(call Package/naiveproxy/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=The Chromium network stack library
endef

define Package/naiveproxy/description
  NaïveProxy uses Chrome's network stack to camouflage traffic with strong
  censorship resistance and low detectability. Reusing Chrome's stack also
  ensures best practices in performance and security.
endef

define Package/libcronet/description
  Cronet is the Chromium network stack made available to Android apps as a library.

  Cronet takes advantage of multiple technologies that reduce the latency and
  increase the throughput of the network requests that your app needs to work.
endef

ifneq ($(CONFIG_CCACHE),)
  export CCACHE_SLOPPINESS=time_macros
  export CCACHE_BASEDIR=$(PKG_BUILD_DIR)/src
  export CCACHE_CPP2=yes
  export naive_ccache_flags=cc_wrapper="$(CCACHE)"
endif

CLANG_VER:=15-init-10168-gc2a7904a-1
CLANG_FILE:=clang-llvmorg-$(CLANG_VER).tgz
define Download/CLANG
	URL:=https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64
	URL_FILE:=$(CLANG_FILE)
	FILE:=$(CLANG_FILE)
	HASH:=9b19d831249a6328f4d8e52de269cb925b9a868e628ee2e30fc4462a77be52f7
endef

GN_VER:=578a7fe4c3c6b0bc2ae1fd2e37f14857d09895bf
GN_FILE:=gn-git_revision-$(GN_VER).zip
define Download/GN_TOOL
	URL:=https://chrome-infra-packages.appspot.com/dl/gn/gn/linux-amd64/+
	URL_FILE:=git_revision:$(GN_VER)
	FILE:=$(GN_FILE)
	HASH:=9b43714dc93695deef6a7c84aec284601da9277422cf94faff46ffa278100cde
endef

PGO_VER:=5060-1655228597-bbe06f169cac6956903f78358c30d94a01938b2e
PGO_FILE:=chrome-linux-$(PGO_VER).profdata
define Download/PGO_PROF
	URL:=https://storage.googleapis.com/chromium-optimization-profiles/pgo_profiles
	URL_FILE:=$(PGO_FILE)
	FILE:=$(PGO_FILE)
	HASH:=67d472fc1be1a08288d985138e8af92fc33fd60d8e253a5b04158a2b9d2d01ea
endef

define Build/Prepare
	$(call Build/Prepare/Default)

	( \
		cd $(PKG_BUILD_DIR)/src ; \
		mkdir -p "chrome/build/pgo_profiles" ; \
		$(CP) "$(DL_DIR)/$(PGO_FILE)" "chrome/build/pgo_profiles" ; \
		mkdir -p "third_party/llvm-build/Release+Asserts" ; \
		$(TAR) -xzf "$(DL_DIR)/$(CLANG_FILE)" -C "third_party/llvm-build/Release+Asserts" ; \
		mkdir -p "gn/out" ; \
		unzip -o "$(DL_DIR)/$(GN_FILE)" -d "gn/out" ; \
	)
endef

define Build/Configure
	( \
		pushd "$(PKG_BUILD_DIR)/src" ; \
		. ../init_env.sh "$(ARCH)" $(CPU_TYPE) $(CPU_SUBTYPE) "$(TOOLCHAIN_DIR)" ; \
		export naive_flags+=" $$$${naive_ccache_flags}" ; \
		mkdir -p "out" ; \
		./gn/out/gn gen "out/Release" --args="$$$${naive_flags}" --script-executable="$(PYTHON)" ; \
		popd ; \
	)
endef

define Build/Compile
	$(if $(CONFIG_PACKAGE_naiveproxy), \
		+$(NINJA) -C "$(PKG_BUILD_DIR)/src/out/Release" naive)
	$(if $(CONFIG_PACKAGE_libcronet), \
		+$(NINJA) -C "$(PKG_BUILD_DIR)/src/out/Release" cronet)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) \
		$(PKG_BUILD_DIR)/src/components/grpc_support/include/bidirectional_stream_c.h \
		$(PKG_BUILD_DIR)/src/components/cronet/native/generated/cronet.idl_c.h \
		$(PKG_BUILD_DIR)/src/components/cronet/native/include/cronet_c.h \
		$(PKG_BUILD_DIR)/src/components/cronet/native/include/cronet_export.h \
		$(1)/usr/include/
endef

define Package/naiveproxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/out/Release/naive $(1)/usr/bin/naive
endef

define Package/libcronet/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/out/Release/libcronet.so $(1)/usr/lib/
endef

$(eval $(call Download,CLANG))
$(eval $(call Download,GN_TOOL))
$(eval $(call Download,PGO_PROF))

$(eval $(call BuildPackage,naiveproxy))
$(eval $(call BuildPackage,libcronet))
