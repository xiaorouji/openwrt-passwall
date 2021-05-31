# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=naiveproxy
PKG_VERSION:=91.0.4472.77-1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/klzgrad/naiveproxy/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=01c660efd162859a2cabdf336cf889c191449fbd63883fc5a7b1be1348005fe1

PKG_LICENSE:=BSD 3-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=ninja/host python3/host
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

define Package/naiveproxy/config
	depends on !(arc||armeb||mips||mips64||powerpc)
endef

define Package/naiveproxy
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  URL:=https://github.com/klzgrad/naiveproxy
  TITLE:=Make a fortune quietly
  DEPENDS:=+libatomic
endef

define Package/naiveproxy/description
  NaïveProxy uses Chrome's network stack to camouflage traffic with strong
  censorship resistance and low detectability. Reusing Chrome's stack also
  ensures best practices in performance and security.
endef

ifneq ($(CONFIG_CCACHE),)
	export CCACHE_SLOPPINESS=time_macros
	export CCACHE_BASEDIR=$(PKG_BUILD_DIR)/src
	export CCACHE_CPP2=yes
	export naive_ccache_flags=cc_wrapper="$(CCACHE)"
endif

CLANG_VER:=llvmorg-13-init-6429-g0e92cbd6-2
CLANG_FILE:=clang-$(CLANG_VER).tgz
define Download/CLANG
	URL:=https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64
	URL_FILE:=$(CLANG_FILE)
	FILE:=$(CLANG_FILE)
	HASH:=3355d81f43412c1664babdafc2051b9154aaca8d86077829107cc4eae28b018c
endef

GN_VER:=dba01723a441c358d843a575cb7720d54ddcdf92
GN_FILE:=gn-git_revision-$(GN_VER).zip
define Download/GN_TOOL
	URL:=https://chrome-infra-packages.appspot.com/dl/gn/gn/linux-amd64/+
	URL_FILE:=git_revision:$(GN_VER)
	FILE:=$(GN_FILE)
	HASH:=bc2d2bc6a8aa1930f796cf4a247ae026858fd8e0623e4fd010eff16c322d298a
endef

PGO_VER:=4472-1621756476-ebad7a91210ae5a7ae94aabb1dd5a349fcc91380
PGO_FILE:=chrome-linux-$(PGO_VER).profdata
define Download/PGO_PROF
	URL:=https://storage.googleapis.com.cnpmjs.org/chromium-optimization-profiles/pgo_profiles \
	     https://storage.googleapis.com/chromium-optimization-profiles/pgo_profiles
	URL_FILE:=$(PGO_FILE)
	FILE:=$(PGO_FILE)
	HASH:=0550e44d41cbdafcd4fd02a4a40515da167dc2033437ddfc7ed5ff264fe8129f
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

define Build/Compile
( \
	cd "$(PKG_BUILD_DIR)/src" ; \
	. ../init_env.sh "$(ARCH)" "$(BOARD)" $(CPU_TYPE) $(CPU_SUBTYPE) "$(TOOLCHAIN_DIR)" ; \
	export naive_flags="$$$${naive_flags} $$$${naive_ccache_flags}" ; \
	mkdir -p "out" ; \
	./gn/out/gn gen "out/Release" --args="$$$${naive_flags}" --script-executable="$(STAGING_DIR_HOSTPKG)/bin/python3" ; \
	$(STAGING_DIR_HOSTPKG)/bin/ninja -C "out/Release" naive ; \
)
endef

define Package/naiveproxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/out/Release/naive $(1)/usr/bin/naive
endef

$(eval $(call Download,CLANG))
$(eval $(call Download,GN_TOOL))
$(eval $(call Download,PGO_PROF))

$(eval $(call BuildPackage,naiveproxy))
