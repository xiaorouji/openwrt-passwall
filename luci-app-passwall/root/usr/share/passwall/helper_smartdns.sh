#!/bin/sh

restart() {
	local no_log
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$no_log" ] && LOG_FILE="/dev/null"
	rm -rf /tmp/smartdns.cache
	/etc/init.d/smartdns reload >/dev/null 2>&1
	LOG_FILE=${_LOG_FILE}
}

del() {
	rm -rf /tmp/etc/smartdns/passwall.conf
	sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1
	rm -rf /tmp/smartdns.cache
	/etc/init.d/smartdns reload >/dev/null 2>&1
}

arg1=$1
shift
case $arg1 in
del)
	del $@
	;;
restart)
	restart $@
	;;
*) ;;
esac
