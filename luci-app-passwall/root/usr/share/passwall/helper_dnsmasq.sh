#!/bin/sh

copy_instance() {
	local listen_port dnsmasq_conf
	eval_set_val $@
	[ -s "/tmp/etc/dnsmasq.conf.${DEFAULT_DNSMASQ_CFGID}" ] && {
		cp -r /tmp/etc/dnsmasq.conf.${DEFAULT_DNSMASQ_CFGID} $dnsmasq_conf
		sed -i "/passwall/d" $dnsmasq_conf
		sed -i "/ubus/d" $dnsmasq_conf
		sed -i "/dhcp/d" $dnsmasq_conf
		sed -i "/port=/d" $dnsmasq_conf
		sed -i "/server=/d" $dnsmasq_conf
	}
	echo "port=${listen_port}" >> $dnsmasq_conf
}

DEFAULT_DNSMASQ_CFGID="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"

arg1=$1
shift
case $arg1 in
copy_instance)
	copy_instance $@
	;;
*) ;;
esac
