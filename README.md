## :mega:注意
由于 Sing-box 在 1.12.0 版本中移除 Geo 只保留规则集（[详情](https://sing-box.sagernet.org/zh/deprecated/#geoip)），Passwall 为适应这一变更，同时兼容 Xray 和 Sing-box 的分流方式，从 25.3.9 版起，Sing-box 分流将依赖 Geoview 从 Geofile 生成规则集。**未安装 Geoview 将无法使用 Sing-box 分流**。  

### 另外：
由于 Geoview v0.1.9 及之前版本在转换规则时的一些问题，**请务必将 Geoview 更新到 v0.1.10 版**。
