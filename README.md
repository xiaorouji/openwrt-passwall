# openwrt-package

[OpenWRT-Actions](https://github.com/Lienol/openwrt-actions/actions)

This source code is only guaranteed to compile successfully on [myopenwrt](https://github.com/Lienol/openwrt), if you are using other source code compilation, error please solve yourself.

Please do not send junk issue and junk PR, otherwise direct ban.

When send issue, please say in detail and operating steps. If it's important information, please send email.

If you don't like it, please uninstall it.

Add "src-git lienol https://github.com/Lienol/openwrt-package" to feeds.conf.default.

```bash
./scripts/feeds clean
./scripts/feeds update -a
./scripts/feeds install -a
```

Or download it yourself and put it in the package folder.
make after enjoy...

If you use Luci-19 or higher, Please selected the "luci-compat" and "luci-lib-ipkg" before compile
