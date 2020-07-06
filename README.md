# openwrt-package

[OpenWRT-Actions](https://github.com/Lienol/openwrt-actions/actions)

Add "src-git lienol https://github.com/Lienol/openwrt-package" to feeds.conf.default.

```bash
./scripts/feeds clean
./scripts/feeds update -a
./scripts/feeds install -a
```

Or download it yourself and put it in the package folder.
make after enjoy...

If you use Luci-19 or higher, Please selected the "luci-compat" and "luci-lib-ipkg" before compile
