#!/bin/sh

stretch() {
	#zhenduiluanshezhiDNSderen
	local dnsmasq_server=$(uci -q get dhcp.@dnsmasq[0].server)
	local dnsmasq_noresolv=$(uci -q get dhcp.@dnsmasq[0].noresolv)
	local _flag
	for server in $dnsmasq_server; do
		[ -z "$(echo $server | grep '\/')" ] && _flag=1
	done
	[ -z "$_flag" ] && [ "$dnsmasq_noresolv" = "1" ] && {
		uci -q delete dhcp.@dnsmasq[0].noresolv
		uci -q set dhcp.@dnsmasq[0].resolvfile="$RESOLVFILE"
		uci commit dhcp
	}
}

backup_servers() {
	DNSMASQ_DNS=$(uci show dhcp | grep "@dnsmasq" | grep ".server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' ',')
	if [ -n "${DNSMASQ_DNS}" ]; then
		uci -q set $CONFIG.@global[0].dnsmasq_servers="${DNSMASQ_DNS}"
		uci commit $CONFIG
	fi
}

restore_servers() {
	OLD_SERVER=$(uci -q get $CONFIG.@global[0].dnsmasq_servers | tr "," " ")
	for server in $OLD_SERVER; do
		uci -q del_list dhcp.@dnsmasq[0].server=$server
		uci -q add_list dhcp.@dnsmasq[0].server=$server
	done
	uci commit dhcp
	uci -q delete $CONFIG.@global[0].dnsmasq_servers
	uci commit $CONFIG
}

logic_restart() {
	local no_log
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$no_log" ] && LOG_FILE="/dev/null"
	if [ -f "$TMP_PATH/default_DNS" ]; then
		backup_servers
		#sed -i "/list server/d" /etc/config/dhcp >/dev/null 2>&1
		for server in $(uci -q get dhcp.@dnsmasq[0].server); do
			[ -n "$(echo $server | grep '\/')" ] || uci -q del_list dhcp.@dnsmasq[0].server="$server" 
		done
		/etc/init.d/dnsmasq restart >/dev/null 2>&1
		restore_servers
	else
		/etc/init.d/dnsmasq restart >/dev/null 2>&1
	fi
	echolog "重启 dnsmasq 服务"
	LOG_FILE=${_LOG_FILE}
}

restart() {
	local no_log
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$no_log" ] && LOG_FILE="/dev/null"
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	echolog "重启 dnsmasq 服务"
	LOG_FILE=${_LOG_FILE}
}

add() {
	local FLAG TMP_DNSMASQ_PATH DNSMASQ_CONF_FILE DEFAULT_DNS LOCAL_DNS TUN_DNS REMOTE_FAKEDNS CHINADNS_DNS TCP_NODE PROXY_MODE NO_PROXY_IPV6 NO_LOGIC_LOG
	eval_set_val $@
	lua $APP_PATH/helper_dnsmasq_add.lua -FLAG $FLAG -TMP_DNSMASQ_PATH $TMP_DNSMASQ_PATH -DNSMASQ_CONF_FILE $DNSMASQ_CONF_FILE -DEFAULT_DNS $DEFAULT_DNS -LOCAL_DNS $LOCAL_DNS -TUN_DNS $TUN_DNS -REMOTE_FAKEDNS ${REMOTE_FAKEDNS:-0} -CHINADNS_DNS ${CHINADNS_DNS:-0} -TCP_NODE $TCP_NODE -PROXY_MODE $PROXY_MODE -NO_PROXY_IPV6 ${NO_PROXY_IPV6:-0} -NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
}

del() {
	rm -rf /tmp/dnsmasq.d/dnsmasq-$CONFIG.conf
	rm -rf $DNSMASQ_PATH/dnsmasq-$CONFIG.conf
	rm -rf $TMP_DNSMASQ_PATH
}

arg1=$1
shift
case $arg1 in
stretch)
	stretch $@
	;;
add)
	add $@
	;;
del)
	del $@
	;;
restart)
	restart $@
	;;
logic_restart)
	logic_restart $@
	;;
*) ;;
esac
