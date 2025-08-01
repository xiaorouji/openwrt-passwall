## :mega:注意
由于 Sing-box 在 1.12.0 版本中移除 Geo 只保留规则集（[详情](https://sing-box.sagernet.org/zh/deprecated/#geoip)），Passwall 为适应这一变更，同时兼容 Xray 和 Sing-box 的分流方式，从 25.3.9 版起，Sing-box 分流将依赖 Geoview 从 Geofile 生成规则集。**未安装 Geoview 将无法使用 Sing-box 分流**。  

## 📌如何能编译到最新代码？

在 `./scripts/feeds install -a` 操作完成后，执行以下命令：

```shell
# 移除 openwrt feeds 自带的核心库
rm -rf feeds/packages/net/{xray-core,v2ray-geodata,sing-box,chinadns-ng,dns2socks,hysteria,ipt2socks,microsocks,naiveproxy,shadowsocks-libev,shadowsocks-rust,shadowsocksr-libev,simple-obfs,tcping,trojan-plus,tuic-client,v2ray-plugin,xray-plugin,geoview,shadow-tls}
git clone https://github.com/xiaorouji/openwrt-passwall-packages package/passwall-packages

# 移除 openwrt feeds 过时的luci版本
rm -rf feeds/luci/applications/luci-app-passwall
git clone https://github.com/xiaorouji/openwrt-passwall package/passwall-luci

# 更新 golang 1.25 版本
rm -rf feeds/packages/lang/golang
git clone https://github.com/sbwml/packages_lang_golang -b 25.x feeds/packages/lang/golang
```
