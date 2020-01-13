openwrt-trojan
==============

Usage
---

1. copy these two folders to <openwrt-source-tree>/package.

2. install feeds from openwrt official package repository.

    ./scripts/feeds update -a
    ./scripts/feeds install -a

3. use 'make menuconfig' to select trojan package

4. the buildroot generate trojan binary linked to our openssl.
   You may use 'make package/trojan/{clean,compile} V=99' or
   whatever you like.

5. edit '/etc/config/trojan' file to enable it.
   The init script is disabled by default to avoid startup
   before configuration.

FAQ
---

Q: May I use openssl from openwrt?
A: As long as you don't need cutting-edge features, e.g. TLS 1.3.
   BTW, the Makefile doesn't depend on official openssl package.
