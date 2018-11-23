CDNS for OpenWrt/LEDE
===

简介
---

 本项目是 [cdns][1] 在 OpenWrt/LEDE 上的移植

编译
---

 - 从 OpenWrt 的 [SDK][S] 编译

   ```bash
   # 以 ar71xx 平台为例
   tar xjf OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2.tar.bz2
   cd OpenWrt-SDK-ar71xx-*
   git clone https://github.com/Hill-98/openwrt-cdns package/cdns
   # 选择要编译的包 Network -> cdns
   make menuconfig
   # 开始编译
   make package/cdns/compile V=99
   ```
 - 可手动修改 Makefile 的 PKG_SOURCE_VERSION 值为 [cdns][1] 最新的 commit 来编译最新版本

[1]: https://github.com/semigodking/cdns
[S]: https://wiki.openwrt.org/doc/howto/obtain.firmware.sdk