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

add() {
	local FLAG SMARTDNS_CONF LOCAL_GROUP REMOTE_GROUP REMOTE_FAKEDNS TUN_DNS TCP_NODE PROXY_MODE NO_PROXY_IPV6 NO_LOGIC_LOG NFTFLAG
	eval_set_val $@
	lua $APP_PATH/helper_smartdns_add.lua -FLAG $FLAG -SMARTDNS_CONF $SMARTDNS_CONF -LOCAL_GROUP ${LOCAL_GROUP:-nil} -REMOTE_GROUP ${REMOTE_GROUP:-nil} -REMOTE_FAKEDNS ${REMOTE_FAKEDNS:-0} -TUN_DNS $TUN_DNS -TCP_NODE $TCP_NODE -PROXY_MODE $PROXY_MODE -NO_PROXY_IPV6 ${NO_PROXY_IPV6:-0} -NO_LOGIC_LOG ${NO_LOGIC_LOG:-0} -NFTFLAG ${NFTFLAG:-0}
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
add)
	add $@
	;;
del)
	del $@
	;;
restart)
	restart $@
	;;
*) ;;
esac
