# openwrt-package

[OpenWRT-Actions](https://github.com/Lienol/openwrt-actions/actions)

请使用[基于官方openwrt源码](https://github.com/Lienol/openwrt) 和 [基于大雕源码](https://github.com/Lienol/openwrt/tree/dev-lean-lede)源码编译

使用方法：

添加 src-git lienol https://github.com/Lienol/openwrt-package 到 OpenWRT源码根目录feeds.conf.default文件

使用上面源码请忽略上一步

然后执行
```bash
./scripts/feeds clean
./scripts/feeds update -a
./scripts/feeds install -a
```
或者你可以把该源码手动下载或Git Clone下载放到OpenWRT源码的Package目录里面，然后编译。
如果你使用的是Luci19或更高，请编译时选上"luci","luci-compat","luci-lib-ipkg"后编译

Add "src-git lienol https://github.com/Lienol/openwrt-package" to feeds.conf.default.

```bash
./scripts/feeds clean
./scripts/feeds update -a
./scripts/feeds install -a
```

Or download it yourself and put it in the package folder.
make after enjoy...

If you use Luci-19 or higher, Please selected the "luci-compat" and "luci-lib-ipkg" before compile
