## 声明：
1. KoolProxy 是一个免费软件，著作权归属 KoolProxy.com，用户可以非商业性地复制和使用 KoolProxy，但禁止将 KoolProxy 用于商业用途。
2. KoolProxy 可以对 https 网络数据进行识别代理，使用 https 功能的用户需要自己提供相关证书，本程序提供的证书生成脚本仅供用户参考，证书的保密工作由用户自行负责。
3. 使用本软件的风险由用户自行承担，在适用法律允许的最大范围内，对因使用本产品所产生的损害及风险，包括但不限于直接或间接的个人损害、商业赢利的丧失、贸易中断、商业信息的丢失或任何其它经济损失，KoolProxy.com 不承担任何责任。

koolproxy更新日志：
http://koolshare.cn/thread-64086-1-1.html

koolproxy性能测试：
http://koolshare.cn/thread-80772-1-1.html


## 准备工作：
<font color=red>
先运行：</br>
`opkg install openssl-util  ipset dnsmasq-full diffutils iptables-mod-nat-extra wget ca-bundle ca-certificates libustream-openssl`</br>
手动安装以上依赖包</br>

如果以上文字很难复制，请到这里去复制：https://github.com/koolshare/firmware/blob/master/binary/KoolProxy/luci/README.md</br>

* 如果没有 **openssl** ，就不能正常生成证书，导致https过滤失败！
* 如果没有 **ipset, dnsmasq-full, diffutils**，黑名单模式也会出现问题！（ipset 需要版本6）,如果你的固件的busybox带有支持diff支持，那么diffutils包可以不安装
* 如果没有 **iptables-mod-nat-extra** ，会导致mac过滤失效！
* 如果没有 **wget, ca-bundle, ca-certificates, libustream-openssl** ，会导致规则文件更新失败，host规则条数变为0,如果你的固件的busybox带有支持https的wget，那么这几个包可以不安装
</br></font></br>

## 开始安装：
请使用cat /proc/cpuinfo查询自己路由器的cpu架构，注意ar系列基本都是mips，mtk的都是mipsel，然后根据自己的cpu架构选择对应的安装方式：</br>
请使用putty或者其它SSH工具登陆到路由器，然后在联网状态下运行：</br>
mips：		opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-app-koolproxy_mips.ipk </br>
mipsel：	opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-app-koolproxy_mipsel.ipk </br>
arm：		opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-app-koolproxy_arm.ipk </br>
i386：		opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-app-koolproxy_i386.ipk </br>
x86_64：	opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-app-koolproxy_x86_64.ipk </br>

如果需要中文翻译，还需要运行</br>
opkg install http://firmware.koolshare.cn/binary/KoolProxy/luci/luci-i18n-koolproxy-zh-cn.ipk

## 注意事项：
1. 首次运行koolproxy的时候，保存并提交速度较慢，因为会生成证书。
2. 使用koolshare论坛fw867发布的LEDE固件的朋友，不建议安装此luci，虽然也能使用（需要卸载掉自带的koolproxy再安装），但是部分代码和原固件集成的有差别，建议使用F大固件的朋友仅仅更新二进制文件即可
3. 此版本在网件WNDR4300V1(mips) OpenWrt Chaos Calmer 15.05.1上测试通过，其它机型暂时未经过测试，如果遇到问题，请到以下渠道进行反馈:
* QQ群：https://jq.qq.com/?_wv=1027&k=445DYpV </br>
* TG群：https://t.me/joinchat/AAAAAD-tO7GPvfOU131_vg

## LUCI更新日志：
2017年03月31日 17:01, koolproxy 3.3.6


