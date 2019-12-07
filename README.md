# openwrt-package
因为已有官方(https://github.com/openwrt/openwrt) 和大雕Lean(https://github.com/coolsnowwolf/lede) 在维护OpenWRT项目，本人就不搞OpenWRT源码了，只做一些Luci包玩玩。

本源码兼容官方和大雕的OpenWRT源码

一些实用的OpenWRT Luci包

使用方法：

添加 src-git lienol https://github.com/Lienol/openwrt-package 到 OpenWRT源码根目录feeds.conf.default文件
然后执行
```bash
./scripts/feeds update -a
./scripts/feeds install -a
```
或者你可以把该源码手动下载或Git Clone下载放到OpenWRT源码的Package目录里面，然后编译。
如果你使用的是Luci19，请编译时选上"luci","luci-compat","luci-lib-ipkg"后编译

Some OpenWrt/LEDE LuCI for Commonly Used Package

Add "src-git lienol https://github.com/Lienol/openwrt-package" to feeds.conf.default.

```bash
./scripts/feeds update -a
./scripts/feeds install -a
```

Or download it yourself and put it in the package folder.
make after enjoy...

If you use Luci-19, Please selected the "luci-compat" and "luci-lib-ipkg" before compile
