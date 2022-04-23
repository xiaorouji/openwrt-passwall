#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
IPSET_LANIPLIST="laniplist"
IPSET_VPSIPLIST="vpsiplist"
IPSET_SHUNTLIST="shuntlist"
IPSET_GFW="gfwlist"
IPSET_CHN="chnroute"
IPSET_BLACKLIST="blacklist"
IPSET_WHITELIST="whitelist"
IPSET_BLOCKLIST="blocklist"

IPSET_LANIPLIST6="laniplist6"
IPSET_VPSIPLIST6="vpsiplist6"
IPSET_SHUNTLIST6="shuntlist6"
IPSET_GFW6="gfwlist6"
IPSET_CHN6="chnroute6"
IPSET_BLACKLIST6="blacklist6"
IPSET_WHITELIST6="whitelist6"
IPSET_BLOCKLIST6="blocklist6"

FORCE_INDEX=2

. /lib/functions/network.sh

ipt=$(command -v iptables-legacy || command -v iptables)
ip6t=$(command -v ip6tables-legacy || command -v ip6tables)

ipt_n="$ipt -t nat -w"
ipt_m="$ipt -t mangle -w"
ip6t_n="$ip6t -t nat -w"
ip6t_m="$ip6t -t mangle -w"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_nat')" ] && ip6t_n="eval #$ip6t_n"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_mangle')" ] && ip6t_m="eval #$ip6t_m"
FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment '$name'"
}

destroy_ipset() {
	for i in "$@"; do
		ipset -q -F $i
		ipset -q -X $i
	done
}

insert_rule_before() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | head -n 1 | awk '{print $1}')
	$ipt_tmp -I $chain $_index $rule
}

insert_rule_after() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | awk 'END {print}' | awk '{print $1}')
	_index=${_index:-0}
	_index=$((_index + 1))
	$ipt_tmp -I $chain $_index $rule
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（iptables），终止执行！"
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local list="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="-j REDIRECT"
	[ -n "$1" ] && {
		local s="$s --to-ports $1"
		[ "$2" == "MARK" ] && s="-j MARK --set-mark $1"
		[ "$2" == "TPROXY" ] && {
			local mark="-m mark --mark 1"
			s="${mark} -j TPROXY --tproxy-mark 1/1 --on-port $1"
		}
	}
	echo $s
}

get_ipset_ipt() {
	case "$1" in
	gfwlist)
		echo "$(dst $IPSET_GFW)"
		;;
	chnroute)
		echo "$(dst $IPSET_CHN !)"
		;;
	returnhome)
		echo "$(dst $IPSET_CHN)"
		;;
	esac
}

get_ipset_ip6t() {
	case "$1" in
	gfwlist)
		echo "$(dst $IPSET_GFW6)"
		;;
	chnroute)
		echo "$(dst $IPSET_CHN6 !)"
		;;
	returnhome)
		echo "$(dst $IPSET_CHN6)"
		;;
	esac
}

get_redirect_ipt() {
	case "$1" in
	disable)
		echo "-j RETURN"
		;;
	global)
		echo "$(REDIRECT $2 $3)"
		;;
	gfwlist)
		echo "$(dst $IPSET_GFW) $(REDIRECT $2 $3)"
		;;
	chnroute)
		echo "$(dst $IPSET_CHN !) $(REDIRECT $2 $3)"
		;;
	returnhome)
		echo "$(dst $IPSET_CHN) $(REDIRECT $2 $3)"
		;;
	direct/proxy)
		echo "-j RETURN"
		;;
	esac
}

get_redirect_ip6t() {
	case "$1" in
	disable)
		echo "-j RETURN"
		;;
	global)
		echo "$(REDIRECT $2 $3)"
		;;
	gfwlist)
		echo "$(dst $IPSET_GFW6) $(REDIRECT $2 $3)"
		;;
	chnroute)
		echo "$(dst $IPSET_CHN6 !) $(REDIRECT $2 $3)"
		;;
	returnhome)
		echo "$(dst $IPSET_CHN6) $(REDIRECT $2 $3)"
		;;
	direct/proxy)
		echo "-j RETURN"
		;;
	esac
}

get_action_chain_name() {
	case "$1" in
	disable)
		echo "不代理"
		;;
	global)
		echo "全局代理"
		;;
	gfwlist)
		echo "防火墙列表"
		;;
	chnroute)
		echo "中国列表以外"
		;;
	returnhome)
		echo "中国列表"
		;;
	direct/proxy)
		echo "仅使用直连/代理列表"
		;;
	esac
}

gen_laniplist() {
	cat $RULES_PATH/lanlist_ipv4 | tr -s '\n' | grep -v "^#"
}

gen_laniplist_6() {
	cat $RULES_PATH/lanlist_ipv6 | tr -s '\n' | grep -v "^#"
}

get_wan_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan NET_IF
	network_get_ipaddr NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

get_wan6_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan6 NET_IF
	network_get_ipaddr6 NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

load_acl() {
	local items=$(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	[ -n "$items" ] && {
		local item
		local socks_port redir_port dns_port dnsmasq_port
		local ipt_tmp msg msg2
		socks_port=11100
		redir_port=11200
		dns_port=11300
		dnsmasq_port=11400
		echolog "访问控制："
		for item in $items; do
			local enabled sid remarks sources tcp_proxy_mode udp_proxy_mode tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node dns_mode dns_forward v2ray_dns_mode dns_doh dns_client_ip
			local _ip _mac _iprange _ipset _ip_or_mac rule_list tcp_port udp_port tcp_node_remark udp_node_remark config_file _extra_param
			sid=$(uci -q show "${CONFIG}.${item}" | grep "=acl_rule" | awk -F '=' '{print $1}' | awk -F '.' '{print $2}')
			eval $(uci -q show "${CONFIG}.${item}" | cut -d'.' -sf 3-)
			[ "$enabled" = "1" ] || continue
			
			[ -z "${sources}" ] && continue
			for s in $sources; do
				is_iprange=$(lua_api "iprange(\"${s}\")")
				if [ "${is_iprange}" = "true" ]; then
					rule_list="${rule_list}\niprange:${s}"
				elif [ -n "$(echo ${s} | grep '^ipset:')" ]; then
					rule_list="${rule_list}\nipset:${s}"
				else
					_ip_or_mac=$(lua_api "ip_or_mac(\"${s}\")")
					if [ "${_ip_or_mac}" = "ip" ]; then
						rule_list="${rule_list}\nip:${s}"
					elif [ "${_ip_or_mac}" = "mac" ]; then
						rule_list="${rule_list}\nmac:${s}"
					fi
				fi
			done
			[ -z "${rule_list}" ] && continue
			
			tcp_proxy_mode=${tcp_proxy_mode:-default}
			udp_proxy_mode=${udp_proxy_mode:-default}
			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_proxy_drop_ports=${tcp_proxy_drop_ports:-default}
			udp_proxy_drop_ports=${udp_proxy_drop_ports:-default}
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			tcp_node=${tcp_node:-default}
			udp_node=${udp_node:-default}
			dns_mode=${dns_mode:-dns2socks}
			dns_forward=${dns_forward:-1.1.1.1}
			[ "$dns_mode" = "v2ray" -o "$dns_mode" = "xray" ] && {
				[ "$v2ray_dns_mode" = "doh" ] && dns_forward=${dns_doh:-https://cloudflare-dns.com/dns-query,1.1.1.1}
			}
			[ "$tcp_proxy_mode" = "default" ] && tcp_proxy_mode=$TCP_PROXY_MODE
			[ "$udp_proxy_mode" = "default" ] && udp_proxy_mode=$UDP_PROXY_MODE
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_proxy_drop_ports" = "default" ] && tcp_proxy_drop_ports=$TCP_PROXY_DROP_PORTS
			[ "$udp_proxy_drop_ports" = "default" ] && udp_proxy_drop_ports=$UDP_PROXY_DROP_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS
			[ "$tcp_node" != "nil" ] && {
				if [ "$tcp_node" = "default" ]; then
					tcp_node=$TCP_NODE
					tcp_port=$TCP_REDIR_PORT
				else
					[ "$(config_get_type $tcp_node nil)" = "nodes" ] && {
						run_dns() {
							local _dns_port
							[ -n $1 ] && _dns_port=$1
							[ -z ${_dns_port} ] && {
								dns_port=$(get_new_port $(expr $dns_port + 1))
								_dns_port=$dns_port
								if [ "$dns_mode" = "dns2socks" ]; then
									run_dns2socks flag=acl_${sid} socks_address=127.0.0.1 socks_port=$socks_port listen_address=0.0.0.0 listen_port=${_dns_port} dns=$dns_forward cache=1
								elif [ "$dns_mode" = "v2ray" -o "$dns_mode" = "xray" ]; then
									config_file=$TMP_ACL_PATH/${tcp_node}_SOCKS_${socks_port}_DNS.json
									run_v2ray flag=acl_${sid} type=$dns_mode dns_socks_address=127.0.0.1 dns_socks_port=$socks_port dns_listen_port=${_dns_port} dns_proto=${v2ray_dns_mode} dns_tcp_server=${dns_forward} doh="${dns_forward}" dns_client_ip=${dns_client_ip} dns_query_strategy=${DNS_QUERY_STRATEGY} config_file=$config_file
								fi
								eval node_${tcp_node}_$(echo -n "${dns_forward}" | md5sum | cut -d " " -f1)=${_dns_port}
							}

							dnsmasq_port=$(get_new_port $(expr $dnsmasq_port + 1))
							redirect_dns_port=$dnsmasq_port
							mkdir -p $TMP_ACL_PATH/$sid
							echo "port=${dnsmasq_port}" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							echo "conf-dir=${TMP_ACL_PATH}/${sid}/dnsmasq.d" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							d_server=127.0.0.1
							[ "$tcp_proxy_mode" = "global" ] && d_server=${d_server}#${_dns_port}
							echo "server=${d_server}" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							source $APP_PATH/helper_${DNS_N}.sh add FLAG=${sid} DNS_MODE=$dns_mode TMP_DNSMASQ_PATH=$TMP_ACL_PATH/$sid/dnsmasq.d DNSMASQ_CONF_FILE=/dev/null LOCAL_DNS=$LOCAL_DNS TUN_DNS=127.0.0.1#${_dns_port} TCP_NODE=$tcp_node PROXY_MODE=${tcp_proxy_mode} NO_LOGIC_LOG=1 NO_PROXY_IPV6=${filter_proxy_ipv6}
							ln_run "$(first_type dnsmasq)" "dnsmasq_${sid}" "/dev/null" -C $TMP_ACL_PATH/$sid/dnsmasq.conf -x $TMP_ACL_PATH/$sid/dnsmasq.pid
							eval node_${tcp_node}_$(echo -n "${tcp_proxy_mode}${dns_forward}" | md5sum | cut -d " " -f1)=${dnsmasq_port}
						}
						if [ "$tcp_node" = "$TCP_NODE" ]; then
							tcp_port=$TCP_REDIR_PORT
						else
							_redir_port=$(eval echo \${node_${tcp_node}_redir_port})
							_socks_port=$(eval echo \${node_${tcp_node}_socks_port})
							if [ -n "${_socks_port}" ] && [ -n "${_redir_port}" ]; then
								socks_port=${_socks_port}
								tcp_port=${_redir_port}
								_dnsmasq_port=$(eval echo \${node_${tcp_node}_$(echo -n "${tcp_proxy_mode}${dns_forward}" | md5sum | cut -d " " -f1)})
								if [ -z "${_dnsmasq_port}" ]; then
									_dns_port=$(eval echo \${node_${tcp_node}_$(echo -n "${dns_forward}" | md5sum | cut -d " " -f1)})
									run_dns ${_dns_port}
								else
									redirect_dns_port=${_dnsmasq_port}
								fi
							else
								socks_port=$(get_new_port $(expr $socks_port + 1))
								eval node_${tcp_node}_socks_port=$socks_port
								redir_port=$(get_new_port $(expr $redir_port + 1))
								eval node_${tcp_node}_redir_port=$redir_port
								tcp_port=$redir_port
								config_file="acl/${tcp_node}_SOCKS_${socks_port}.json"

								local type=$(echo $(config_n_get $tcp_node type) | tr 'A-Z' 'a-z')
								if [ -n "${type}" ] && ([ "${type}" = "v2ray" ] || [ "${type}" = "xray" ]); then
									config_file=$(echo $config_file | sed "s/SOCKS/TCP_UDP_SOCKS/g")
									_extra_param="socks_address=127.0.0.1 socks_port=$socks_port"
									if [ "$dns_mode" = "v2ray" -o "$dns_mode" = "xray" ]; then
										config_file=$(echo $config_file | sed "s/SOCKS_${socks_port}/DNS/g")
										dns_port=$(get_new_port $(expr $dns_port + 1))
										_dns_port=$dns_port
										_extra_param="dns_listen_port=${_dns_port} dns_proto=${v2ray_dns_mode} dns_tcp_server=${dns_forward} doh=${dns_forward} dns_client_ip=${dns_client_ip} dns_query_strategy=${DNS_QUERY_STRATEGY}"
									fi
									config_file="$TMP_PATH/$config_file"
									run_v2ray flag=$tcp_node node=$tcp_node tcp_redir_port=$redir_port ${_extra_param} config_file=$config_file
								else
									run_socks flag=$tcp_node node=$tcp_node bind=127.0.0.1 socks_port=$socks_port config_file=$config_file
									local log_file=$TMP_ACL_PATH/ipt2socks_${tcp_node}_${redir_port}.log
									log_file="/dev/null"
									run_ipt2socks flag=acl_${tcp_node} tcp_tproxy=${is_tproxy} local_port=$redir_port socks_address=127.0.0.1 socks_port=$socks_port log_file=$log_file
								fi
								run_dns ${_dns_port}
							fi
							filter_node $tcp_node TCP > /dev/null 2>&1 &
							filter_node $tcp_node UDP > /dev/null 2>&1 &
						fi
					}
				fi
				tcp_node_remark=$(config_n_get $tcp_node remarks)
			}
			[ "$udp_node" != "nil" ] && {
				[ "$udp_node" = "tcp" ] && udp_node=$tcp_node
				if [ "$udp_node" = "default" ]; then
					udp_node=$UDP_NODE
					[ "$TCP_UDP" = "1" ] && [ "$udp_node" = "nil" ] && udp_node=$TCP_NODE
					udp_port=$UDP_REDIR_PORT
				else
					[ "$(config_get_type $udp_node nil)" = "nodes" ] && {
						if [ "$udp_node" = "$UDP_NODE" ]; then
							udp_port=$UDP_REDIR_PORT
						else
							_redir_port=$(eval echo \${node_${udp_node}_redir_port})
							_socks_port=$(eval echo \${node_${udp_node}_socks_port})
							if [ -n "${_socks_port}" ] && [ -n "${_redir_port}" ]; then
								socks_port=${_socks_port}
								udp_port=${_redir_port}
							else
								socks_port=$(get_new_port $(expr $socks_port + 1))
								eval node_${udp_node}_socks_port=$socks_port
								redir_port=$(get_new_port $(expr $redir_port + 1))
								eval node_${udp_node}_redir_port=$redir_port
								udp_port=$redir_port
								config_file="acl/${udp_node}_SOCKS_${socks_port}.json"

								local type=$(echo $(config_n_get $udp_node type) | tr 'A-Z' 'a-z')
								if [ -n "${type}" ] && ([ "${type}" = "v2ray" ] || [ "${type}" = "xray" ]); then
									config_file=$(echo $config_file | sed "s/SOCKS/TCP_UDP_SOCKS/g")
									config_file="$TMP_PATH/$config_file"
									run_v2ray flag=$udp_node node=$udp_node udp_redir_port=$redir_port config_file=$config_file
								else
									run_socks flag=$udp_node node=$udp_node bind=127.0.0.1 socks_port=$socks_port config_file=$config_file
									local log_file=$TMP_ACL_PATH/ipt2socks_${udp_node}_${redir_port}.log
									log_file="/dev/null"
									run_ipt2socks flag=acl_${udp_node} local_port=$redir_port socks_address=127.0.0.1 socks_port=$socks_port log_file=$log_file
								fi
							fi
							filter_node $udp_node TCP > /dev/null 2>&1 &
							filter_node $udp_node UDP > /dev/null 2>&1 &
						fi
					}
				fi
				udp_node_remark=$(config_n_get $udp_node remarks)
				udp_flag=1
			}
			
			for i in $(echo -e ${rule_list}); do
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "-m iprange --src-range")
					msg="备注【$remarks】，IP range【${_iprange}】，"
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					_ipt_source="-m set --match-set ${_ipset} src"
					msg="备注【$remarks】，IPset【${_ipset}】，"
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "-s")
					msg="备注【$remarks】，IP【${_ip}】，"
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "-m mac --mac-source")
					msg="备注【$remarks】，MAC【${_mac}】，"
				else
					continue
				fi
				
				ipt_tmp=$ipt_n
				[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

				[ -n "$tcp_port" ] && {
					if [ "$tcp_proxy_mode" != "disable" ]; then
						[ -n "$redirect_dns_port" ] && $ipt_n -A PSW_REDIRECT $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $redirect_dns_port
						msg2="${msg}使用TCP节点[$tcp_node_remark] [$(get_action_chain_name $tcp_proxy_mode)]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${tcp_port})代理"
							ipt_tmp=$ipt_m
						else
							msg2="${msg2}(REDIRECT:${tcp_port})代理"
						fi
						
						[ "$accept_icmp" = "1" ] && {
							$ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
							$ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $IPSET_SHUNTLIST) $(REDIRECT)
							$ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(dst $IPSET_BLACKLIST) $(REDIRECT)
							$ipt_n -A PSW $(comment "$remarks") -p icmp ${_ipt_source} $(get_redirect_ipt $tcp_proxy_mode)
						}
						
						[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
							$ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $IPSET_SHUNTLIST6) $(REDIRECT) 2>/dev/null
							$ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(dst $IPSET_BLACKLIST6) $(REDIRECT) 2>/dev/null
							$ip6t_n -A PSW $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(get_redirect_ip6t $tcp_proxy_mode) 2>/dev/null
						}
						
						[ "$tcp_no_redir_ports" != "disable" ] && {
							$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN 2>/dev/null
							$ipt_tmp -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN
							msg2="${msg2}[$?]除${tcp_no_redir_ports}外的"
						}
						msg2="${msg2}所有端口"
						
						[ "$tcp_proxy_drop_ports" != "disable" ] && {
							[ "$PROXY_IPV6" == "1" ] && {
								$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j DROP 2>/dev/null
								$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j DROP 2>/dev/null
								[ "$tcp_proxy_mode" != "direct/proxy" ] && $ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(get_ipset_ip6t $tcp_proxy_mode) -j DROP 2>/dev/null
							}
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") -d $FAKE_IP -j DROP
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
							[ "$tcp_proxy_mode" != "direct/proxy" ] && $ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "-m multiport --dport") $(get_ipset_ipt $tcp_proxy_mode) -j DROP
							msg2="${msg2}[$?]，屏蔽代理TCP 端口：${tcp_proxy_drop_ports}"
						}
						
						if [ "${ipt_tmp}" = "${ipt_n}" ]; then
							$ipt_n -A PSW $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP $(REDIRECT $tcp_port)
							$ipt_n -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $tcp_port)
							$ipt_n -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $tcp_port)
							$ipt_n -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(get_redirect_ipt $tcp_proxy_mode $tcp_port)
						else
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP -j PSW_RULE
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(get_ipset_ipt $tcp_proxy_mode) -j PSW_RULE
							$ipt_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY)
						fi
						[ "$PROXY_IPV6" == "1" ] && {
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(get_ipset_ip6t $tcp_proxy_mode) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY) 2>/dev/null
						}
					else
						msg2="${msg}不代理TCP"
					fi
					echolog "  - ${msg2}"
				}

				$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null
				$ipt_tmp -A PSW $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN
				
				[ "$udp_proxy_drop_ports" != "disable" ] && {
					[ "$PROXY_IPV6" == "1" ] && {
						$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j DROP 2>/dev/null
						$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j DROP 2>/dev/null
						[ "$udp_proxy_mode" != "direct/proxy" ] && $ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(get_ipset_ip6t $udp_proxy_mode) -j DROP 2>/dev/null
					}
					$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") -d $FAKE_IP -j DROP
					$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
					$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
					[ "$udp_proxy_mode" != "direct/proxy" ] && $ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_proxy_drop_ports "-m multiport --dport") $(get_ipset_ipt $udp_proxy_mode) -j DROP
					msg2="${msg2}[$?]，屏蔽代理UDP 端口：${udp_proxy_drop_ports}"
				}

				[ -n "$udp_port" ] && {
					if [ "$udp_proxy_mode" != "disable" ]; then
						msg2="${msg}使用UDP节点[$udp_node_remark] [$(get_action_chain_name $udp_proxy_mode)]"
						msg2="${msg2}(TPROXY:${udp_port})代理"
						[ "$udp_no_redir_ports" != "disable" ] && {
							$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN 2>/dev/null
							$ipt_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN
							msg2="${msg2}[$?]除${udp_no_redir_ports}外的"
						}
						msg2="${msg2}所有端口"

						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP -j PSW_RULE
						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(get_ipset_ipt $udp_proxy_mode) -j PSW_RULE
						$ipt_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $udp_port TPROXY)

						[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(get_ipset_ip6t $udp_proxy_mode) -j PSW_RULE 2>/dev/null
							$ip6t_m -A PSW $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $udp_port TPROXY) 2>/dev/null
						}
					else
						msg2="${msg}不代理UDP"
					fi
					echolog "  - ${msg2}"
				}
				$ip6t_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
				$ipt_m -A PSW $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
			done
			unset enabled sid remarks sources tcp_proxy_mode udp_proxy_mode tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node dns_mode dns_forward v2ray_dns_mode dns_doh dns_client_ip
			unset _ip _mac _iprange _ipset _ip_or_mac rule_list tcp_port udp_port tcp_node_remark udp_node_remark config_file _extra_param
			unset ipt_tmp msg msg2
			unset redirect_dns_port
		done
		unset socks_port redir_port dns_port dnsmasq_port
		unset ipt_tmp msg msg2
	}

	#  加载TCP默认代理模式
	[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
		[ "$PROXY_IPV6" == "1" ] && {
			$ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j DROP
			$ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j DROP
			[ "$TCP_PROXY_MODE" != "direct/proxy" ] && $ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ip6t $TCP_PROXY_MODE) -j DROP
		}
		$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") -d $FAKE_IP -j DROP
		$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
		$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
		[ "$TCP_PROXY_MODE" != "direct/proxy" ] && $ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ipt $TCP_PROXY_MODE) -j DROP
	}

	if [ "$TCP_PROXY_MODE" != "disable" ]; then
		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ip6t_m -A PSW $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ipt_tmp -A PSW $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
		}
		[ "$TCP_NODE" != "nil" ] && {
			msg="TCP默认代理：使用TCP节点[$(config_n_get $TCP_NODE remarks)] [$(get_action_chain_name $TCP_PROXY_MODE)]"
			if [ -n "${is_tproxy}" ]; then
				msg="${msg}(TPROXY:${TCP_REDIR_PORT})代理"
			else
				msg="${msg}(REDIRECT:${TCP_REDIR_PORT})代理"
			fi
			
			[ "$TCP_NO_REDIR_PORTS" != "disable" ] && msg="${msg}除${TCP_NO_REDIR_PORTS}外的"
			msg="${msg}所有端口"
			
			[ "$accept_icmp" = "1" ] && {
				$ipt_n -A PSW $(comment "默认") -p icmp -d $FAKE_IP $(REDIRECT)
				$ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_SHUNTLIST) $(REDIRECT)
				$ipt_n -A PSW $(comment "默认") -p icmp $(dst $IPSET_BLACKLIST) $(REDIRECT)
				$ipt_n -A PSW $(comment "默认") -p icmp $(get_redirect_ipt $TCP_PROXY_MODE)
			}
			
			[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
				$ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_SHUNTLIST6) $(REDIRECT)
				$ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(dst $IPSET_BLACKLIST6) $(REDIRECT)
				$ip6t_n -A PSW $(comment "默认") -p ipv6-icmp $(get_redirect_ip6t $TCP_PROXY_MODE)
			}
			
			if [ "${ipt_tmp}" = "${ipt_n}" ]; then
				$ipt_n -A PSW $(comment "默认") -p tcp -d $FAKE_IP $(REDIRECT $TCP_REDIR_PORT)
				$ipt_n -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $TCP_REDIR_PORT)
				$ipt_n -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $TCP_REDIR_PORT)
				$ipt_n -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $TCP_PROXY_MODE $TCP_REDIR_PORT)
			else
				$ipt_m -A PSW $(comment "默认") -p tcp -d $FAKE_IP -j PSW_RULE
				$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
				$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
				$ipt_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ipt $TCP_PROXY_MODE) -j PSW_RULE
				$ipt_m -A PSW $(comment "默认") -p tcp $(REDIRECT $TCP_REDIR_PORT TPROXY)
			fi

			[ "$PROXY_IPV6" == "1" ] && {
				$ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ip6t $TCP_PROXY_MODE) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p tcp $(REDIRECT $TCP_REDIR_PORT TPROXY)
			}

			echolog "${msg}"
		}
	fi
	$ipt_n -A PSW $(comment "默认") -p tcp -j RETURN
	$ipt_m -A PSW $(comment "默认") -p tcp -j RETURN
	$ip6t_m -A PSW $(comment "默认") -p tcp -j RETURN

	#  加载UDP默认代理模式
	[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
		[ "$PROXY_IPV6" == "1" ] && {
			$ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j DROP
			$ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j DROP
			[ "$UDP_PROXY_MODE" != "direct/proxy" ] && $ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ip6t $UDP_PROXY_MODE) -j DROP
		}
		$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") -d $FAKE_IP -j DROP
		$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
		$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
		[ "$UDP_PROXY_MODE" != "direct/proxy" ] && $ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ipt $UDP_PROXY_MODE) -j DROP
	}
	if [ "$UDP_PROXY_MODE" != "disable" ]; then
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ip6t_m -A PSW $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ipt_m -A PSW $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
		}

		[ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ] && {
			[ "$TCP_UDP" = "1" ] && [ "$UDP_NODE" = "nil" ] && UDP_NODE=$TCP_NODE
			msg="UDP默认代理：使用UDP节点[$(config_n_get $UDP_NODE remarks)] [$(get_action_chain_name $UDP_PROXY_MODE)](TPROXY:${UDP_REDIR_PORT})代理"

			[ "$UDP_NO_REDIR_PORTS" != "disable" ] && msg="${msg}除${UDP_NO_REDIR_PORTS}外的"
			msg="${msg}所有端口"

			$ipt_m -A PSW $(comment "默认") -p udp -d $FAKE_IP -j PSW_RULE
			$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
			$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
			$ipt_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ipt $UDP_PROXY_MODE) -j PSW_RULE
			$ipt_m -A PSW $(comment "默认") -p udp $(REDIRECT $UDP_REDIR_PORT TPROXY)

			[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
				$ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ip6t $UDP_PROXY_MODE) -j PSW_RULE
				$ip6t_m -A PSW $(comment "默认") -p udp $(REDIRECT $UDP_REDIR_PORT TPROXY)
			}

			echolog "${msg}"
			udp_flag=1
		}
	fi
	$ipt_m -A PSW $(comment "默认") -p udp -j RETURN
	$ip6t_m -A PSW $(comment "默认") -p udp -j RETURN
}

filter_haproxy() {
	for item in ${haproxy_items}; do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		ipset -q add $IPSET_VPSIPLIST $ip
	done
	echolog "加入负载均衡的节点到ipset[$IPSET_VPSIPLIST]直连完成"
}

filter_vpsip() {
	uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSIPLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPSIPLIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	echolog "加入所有节点到ipset[$IPSET_VPSIPLIST]直连完成"
}

filter_node() {
	local proxy_node=${1}
	local stream=$(echo ${2} | tr 'A-Z' 'a-z')
	local proxy_port=${3}

	filter_rules() {
		local node=${1}
		local stream=${2}
		local _proxy=${3}
		local _port=${4}
		local _is_tproxy ipt_tmp msg msg2

		if [ -n "$node" ] && [ "$node" != "nil" ]; then
			local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
			local address=$(config_n_get $node address)
			local port=$(config_n_get $node port)
			ipt_tmp=$ipt_n
			_is_tproxy=${is_tproxy}
			[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
			if [ -n "${_is_tproxy}" ]; then
				ipt_tmp=$ipt_m
				msg="TPROXY"
			else
				msg="REDIRECT"
			fi
		else
			echolog "  - 节点配置不正常，略过"
			return 0
		fi

		local ADD_INDEX=$FORCE_INDEX
		for _ipt in 4 6; do
			[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
			[ "$_ipt" == "6" ] && _ipt=$ip6t_m
			$_ipt -n -L PSW_OUTPUT | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule="-j PSW_RULE"
				msg2="按规则路由(${msg})"
				[ "$_ipt" == "$ipt_m" -o "$_ipt" == "$ip6t_m" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="套娃使用(${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "$_ipt" PSW_OUTPUT "$IPSET_VPSIPLIST" $FORCE_INDEX)
					dst_rule=" -j RETURN"
					msg2="直连代理"
				}
				$_ipt -I PSW_OUTPUT $ADD_INDEX $(comment "${address}:${port}") -p $stream -d $address --dport $port $dst_rule 2>/dev/null
			else
				msg2="已配置过的节点，"
			fi
		done
		msg="[$?]$(echo ${2} | tr 'a-z' 'A-Z')${msg2}使用链${ADD_INDEX}，节点（${type}）：${address}:${port}"
		#echolog "  - ${msg}"
	}

	local proxy_protocol=$(config_n_get $proxy_node protocol)
	local proxy_type=$(echo $(config_n_get $proxy_node type nil) | tr 'A-Z' 'a-z')
	[ "$proxy_type" == "nil" ] && echolog "  - 节点配置不正常，略过！：${proxy_node}" && return 0
	if [ "$proxy_protocol" == "_balancing" ]; then
		#echolog "  - 多节点负载均衡（${proxy_type}）..."
		proxy_node=$(config_n_get $proxy_node balancing_node)
		for _node in $proxy_node; do
			filter_rules "$_node" "$stream"
		done
	elif [ "$proxy_protocol" == "_shunt" ]; then
		#echolog "  - 按请求目的地址分流（${proxy_type}）..."
		local default_node=$(config_n_get $proxy_node default_node _direct)
		local main_node=$(config_n_get $proxy_node main_node nil)
		if [ "$main_node" != "nil" ]; then
			filter_rules $main_node $stream
		else
			if [ "$default_node" != "_direct" ] && [ "$default_node" != "_blackhole" ]; then
				filter_rules $default_node $stream
			fi
		fi
:<<!
		local default_node_address=$(get_host_ip ipv4 $(config_n_get $default_node address) 1)
		local default_node_port=$(config_n_get $default_node port)

		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			#local shunt_proxy=$(config_n_get $proxy_node "${shunt_id}_proxy" 0)
			local shunt_proxy=0
			local shunt_node=$(config_n_get $proxy_node "${shunt_id}" nil)
			[ "$shunt_node" != "nil" ] && {
				[ "$shunt_proxy" == 1 ] && {
					local shunt_node_address=$(get_host_ip ipv4 $(config_n_get $shunt_node address) 1)
					local shunt_node_port=$(config_n_get $shunt_node port)
					[ "$shunt_node_address" == "$default_node_address" ] && [ "$shunt_node_port" == "$default_node_port" ] && {
						shunt_proxy=0
					}
				}
				filter_rules "$(config_n_get $proxy_node $shunt_id)" "$stream" "$shunt_proxy" "$proxy_port"
			}
		done
!
	else
		#echolog "  - 普通节点（${proxy_type}）..."
		filter_rules "$proxy_node" "$stream"
	fi
}

dns_hijack() {
	$ipt_n -I PSW -p udp --dport 53 -j REDIRECT --to-ports 53
	echolog "强制转发本机DNS端口 UDP/53 的请求[$?]"
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..."
	ipset -! create $IPSET_LANIPLIST nethash maxelem 1048576
	ipset -! create $IPSET_VPSIPLIST nethash maxelem 1048576
	ipset -! create $IPSET_SHUNTLIST nethash maxelem 1048576
	ipset -! create $IPSET_GFW nethash maxelem 1048576
	ipset -! create $IPSET_CHN nethash maxelem 1048576
	ipset -! create $IPSET_BLACKLIST nethash maxelem 1048576
	ipset -! create $IPSET_WHITELIST nethash maxelem 1048576
	ipset -! create $IPSET_BLOCKLIST nethash maxelem 1048576

	ipset -! create $IPSET_LANIPLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPSIPLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_SHUNTLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_GFW6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_CHN6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_BLACKLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_WHITELIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_BLOCKLIST6 nethash family inet6 maxelem 1048576

	local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')

	for shunt_id in $shunt_ids; do
		config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_SHUNTLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	done

	for shunt_id in $shunt_ids; do
		config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_SHUNTLIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	done

	cat $RULES_PATH/chnroute | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLACKLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_WHITELIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_BLOCKLIST &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R

	cat $RULES_PATH/chnroute6 | tr -s '\n' | grep -v "^#" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_CHN6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_BLACKLIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_WHITELIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
	cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_BLOCKLIST6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R

	ipset -! -R <<-EOF
		$(gen_laniplist | sed -e "s/^/add $IPSET_LANIPLIST /")
	EOF

	ipset -! -R <<-EOF
		$(gen_laniplist_6 | sed -e "s/^/add $IPSET_LANIPLIST6 /")
	EOF

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && ipset -! -R <<-EOF
			$(echo $lan_ip | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LANIPLIST /")
		EOF

		[ -n "$lan_ip6" ] && ipset -! -R <<-EOF
			$(echo $lan_ip6 | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_LANIPLIST6 /")
		EOF
	}

	local ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1)
	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			ipset -! add $IPSET_WHITELIST $ispip >/dev/null 2>&1 &
			#echolog "  - 追加到白名单：${ispip}"
		done
	}

	local ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}'| sort -u | grep -v -Fx ::1 | grep -v -Fx ::)
	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS; do
			ipset -! add $IPSET_WHITELIST6 $ispip6 >/dev/null 2>&1 &
			#echolog "  - 追加到白名单：${ispip6}"
		done
	}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	$ipt_n -N PSW
	$ipt_n -A PSW $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW $(dst $IPSET_WHITELIST) -j RETURN

	WAN_IP=$(get_wan_ip)
	[ ! -z "${WAN_IP}" ] && $ipt_n -A PSW $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW"

	$ipt_n -N PSW_OUTPUT
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW_OUTPUT $(dst $IPSET_WHITELIST) -j RETURN
	$ipt_n -A PSW_OUTPUT -m mark --mark 0xff -j RETURN

	$ipt_n -N PSW_REDIRECT
	$ipt_n -I PREROUTING 1 -j PSW_REDIRECT

	$ipt_m -N PSW_DIVERT
	$ipt_m -A PSW_DIVERT -j MARK --set-mark 1
	$ipt_m -A PSW_DIVERT -j ACCEPT

	$ipt_m -N PSW_RULE
	$ipt_m -A PSW_RULE -j CONNMARK --restore-mark
	$ipt_m -A PSW_RULE -m mark --mark 1 -j RETURN
	$ipt_m -A PSW_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ipt_m -A PSW_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ipt_m -A PSW_RULE -j CONNMARK --save-mark

	$ipt_m -N PSW
	$ipt_m -A PSW $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_WHITELIST) -j RETURN
	$ipt_m -A PSW $(dst $IPSET_BLOCKLIST) -j DROP
	
	[ ! -z "${WAN_IP}" ] && $ipt_m -A PSW $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	unset WAN_IP

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW"
	insert_rule_before "$ipt_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT"

	$ipt_m -I OUTPUT $(comment "PSW") -o lo -j RETURN
	$ipt_m -N PSW_OUTPUT
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_WHITELIST) -j RETURN
	$ipt_m -A PSW_OUTPUT -m mark --mark 0xff -j RETURN
	$ipt_m -A PSW_OUTPUT $(dst $IPSET_BLOCKLIST) -j DROP

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW
		$ip6t_n -A PSW $(dst $IPSET_LANIPLIST6) -j RETURN
		$ip6t_n -A PSW $(dst $IPSET_VPSIPLIST6) -j RETURN
		$ip6t_n -A PSW $(dst $IPSET_WHITELIST6) -j RETURN
		$ip6t_n -A PREROUTING -p ipv6-icmp -j PSW

		$ip6t_n -N PSW_OUTPUT
		$ip6t_n -A PSW_OUTPUT $(dst $IPSET_LANIPLIST6) -j RETURN
		$ip6t_n -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST6) -j RETURN
		$ip6t_n -A PSW_OUTPUT $(dst $IPSET_WHITELIST6) -j RETURN
		$ip6t_n -A PSW_OUTPUT -m mark --mark 0xff -j RETURN
	}

	$ip6t_m -N PSW_DIVERT
	$ip6t_m -A PSW_DIVERT -j MARK --set-mark 1
	$ip6t_m -A PSW_DIVERT -j ACCEPT

	$ip6t_m -N PSW_RULE
	$ip6t_m -A PSW_RULE -j CONNMARK --restore-mark
	$ip6t_m -A PSW_RULE -m mark --mark 1 -j RETURN
	$ip6t_m -A PSW_RULE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 1
	$ip6t_m -A PSW_RULE -p udp -m conntrack --ctstate NEW -j MARK --set-xmark 1
	$ip6t_m -A PSW_RULE -j CONNMARK --save-mark

	$ip6t_m -N PSW
	$ip6t_m -A PSW $(dst $IPSET_LANIPLIST6) -j RETURN
	$ip6t_m -A PSW $(dst $IPSET_VPSIPLIST6) -j RETURN
	$ip6t_m -A PSW $(dst $IPSET_WHITELIST6) -j RETURN
	$ip6t_m -A PSW $(dst $IPSET_BLOCKLIST6) -j DROP
	
	WAN6_IP=$(get_wan6_ip)
	[ ! -z "${WAN6_IP}" ] && $ip6t_m -A PSW $(comment "WAN6_IP_RETURN") -d ${WAN6_IP} -j RETURN
	unset WAN6_IP

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW"
	insert_rule_before "$ip6t_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT"

	$ip6t_m -N PSW_OUTPUT
	$ip6t_m -A PSW_OUTPUT -m mark --mark 0xff -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_LANIPLIST6) -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_VPSIPLIST6) -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_WHITELIST6) -j RETURN
	$ip6t_m -A PSW_OUTPUT $(dst $IPSET_BLOCKLIST6) -j DROP

	ip -6 rule add fwmark 1 table 100
	ip -6 route add local ::/0 dev lo table 100

	# 加载路由器自身代理 TCP
	if [ "$TCP_NODE" != "nil" ]; then
		echolog "加载路由器自身 TCP 代理..."

		[ "$accept_icmp" = "1" ] && {
			$ipt_n -A OUTPUT -p icmp -j PSW_OUTPUT
			$ipt_n -A PSW_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
			$ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_SHUNTLIST) $(REDIRECT)
			$ipt_n -A PSW_OUTPUT -p icmp $(dst $IPSET_BLACKLIST) $(REDIRECT)
			$ipt_n -A PSW_OUTPUT -p icmp $(get_redirect_ipt $TCP_PROXY_MODE )
		}

		[ "$accept_icmpv6" = "1" ] && {
			$ip6t_n -A OUTPUT -p ipv6-icmp -j PSW_OUTPUT
			$ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_SHUNTLIST6) $(REDIRECT)
			$ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(dst $IPSET_BLACKLIST6) $(REDIRECT)
			$ip6t_n -A PSW_OUTPUT -p ipv6-icmp $(get_redirect_ip6t $TCP_PROXY_MODE)
		}

		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && {
			echolog "  - 启用 TPROXY 模式"
			ipt_tmp=$ipt_m
		}

		_proxy_tcp_access() {
			[ -n "${2}" ] || return 0
			ipset -q test $IPSET_LANIPLIST ${2}
			[ $? -eq 0 ] && {
				echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
				return 0
			}
			if [ "${ipt_tmp}" = "${ipt_n}" ]; then
				$ipt_n -I PSW_OUTPUT -p tcp -d ${2} --dport ${3} $(REDIRECT $TCP_REDIR_PORT)
			else
				$ipt_m -I PSW_OUTPUT -p tcp -d ${2} --dport ${3} -j PSW_RULE
				$ipt_m -I PSW $(comment "本机") -p tcp -i lo -d ${2} --dport ${3} $(REDIRECT $TCP_REDIR_PORT TPROXY)
			fi
			echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 TCP 转发链"
		}

		[ "$use_tcp_node_resolve_dns" == 1 ] && hosts_foreach DNS_FORWARD _proxy_tcp_access 53
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_tmp -A PSW_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]不代理TCP 端口：$TCP_NO_REDIR_PORTS"
		}
		[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") -d $FAKE_IP -j DROP
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
			[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && $ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ipt $LOCALHOST_TCP_PROXY_MODE) -j DROP
			echolog "  - [$?]，屏蔽代理TCP 端口：$TCP_PROXY_DROP_PORTS"
		}

		if [ "${ipt_tmp}" = "${ipt_n}" ]; then
			$ipt_n -A PSW_OUTPUT -p tcp -d $FAKE_IP $(REDIRECT $TCP_REDIR_PORT)
			$ipt_n -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) $(REDIRECT $TCP_REDIR_PORT)
			$ipt_n -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) $(REDIRECT $TCP_REDIR_PORT)
			$ipt_n -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_redirect_ipt $LOCALHOST_TCP_PROXY_MODE $TCP_REDIR_PORT)
			$ipt_n -A OUTPUT -p tcp -j PSW_OUTPUT
		else
			$ipt_m -A PSW_OUTPUT -p tcp -d $FAKE_IP -j PSW_RULE
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
			$ipt_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ipt $LOCALHOST_TCP_PROXY_MODE) -j PSW_RULE
			$ipt_m -A PSW $(comment "本机") -p tcp -i lo $(REDIRECT $TCP_REDIR_PORT TPROXY)
			$ipt_m -A PSW $(comment "本机") -p tcp -i lo -j RETURN
			insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment PSW_OUTPUT_TCP) -p tcp -j PSW_OUTPUT"
			insert_rule_after "$ipt_m" "OUTPUT" "PSW_OUTPUT_TCP" "$(comment PSW) -p tcp -m mark --mark 1 -j RETURN"
		fi

		[ "$PROXY_IPV6" == "1" ] && {
			$ip6t_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE
			$ip6t_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE
			$ip6t_m -A PSW_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ip6t $LOCALHOST_TCP_PROXY_MODE) -j PSW_RULE
			$ip6t_m -A PSW $(comment "本机") -p tcp -i lo $(REDIRECT $TCP_REDIR_PORT TPROXY)
			$ip6t_m -A PSW $(comment "本机") -p tcp -i lo -j RETURN
			insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment PSW_OUTPUT_TCP) -p tcp -j PSW_OUTPUT"
			insert_rule_after "$ip6t_m" "OUTPUT" "PSW_OUTPUT_TCP" "$(comment PSW) -p tcp -m mark --mark 1 -j RETURN"
		}
	fi

	# 过滤Socks节点
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		#echolog "分析 Socks 服务所使用节点..."
		local id enabled node port msg num
		for id in $ids; do
			enabled=$(config_n_get $id enabled 0)
			[ "$enabled" == "1" ] || continue
			node=$(config_n_get $id node nil)
			port=$(config_n_get $id port 0)
			msg="Socks 服务 [:${port}]"
			if [ "$node" == "nil" ] || [ "$port" == "0" ]; then
				msg="${msg} 未配置完全，略过"
			elif [ "$(echo $node | grep ^tcp)" ]; then
				#eval "node=\${TCP_NODE}"
				#msg="${msg} 使用与 TCP 代理自动切换${num} 相同的节点，延后处理"
				continue
			else
				filter_node $node TCP > /dev/null 2>&1 &
				filter_node $node UDP > /dev/null 2>&1 &
			fi
			#echolog "  - ${msg}"
		done
	}

	# 处理轮换节点的分流或套娃
	local node port stream switch
	for stream in TCP UDP; do
		eval "node=\${${stream}_NODE}"
		eval "port=\${${stream}_REDIR_PORT}"
		#echolog "分析 $stream 代理自动切换..."
		[ "$node" == "tcp" ] && [ "$stream" == "UDP" ] && {
			eval "node=\${TCP_NODE}"
			eval "port=\${TCP_REDIR_PORT}"
		}
		if [ "$node" != "nil" ]; then
			filter_node $node $stream $port > /dev/null 2>&1 &
		fi
	done

	# 加载路由器自身代理 UDP
	[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") -d $FAKE_IP -j DROP
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j DROP
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j DROP
		[ "$LOCALHOST_UDP_PROXY_MODE" != "direct/proxy" ] && $ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_PROXY_DROP_PORTS "-m multiport --dport") $(get_ipset_ipt $LOCALHOST_UDP_PROXY_MODE) -j DROP
		echolog "  - [$?]，屏蔽代理UDP 端口：$UDP_PROXY_DROP_PORTS"
	}
	if [ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ]; then
		echolog "加载路由器自身 UDP 代理..."
		_proxy_udp_access() {
			[ -n "${2}" ] || return 0
			ipset -q test $IPSET_LANIPLIST ${2}
			[ $? == 0 ] && {
				echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
				return 0
			}
			$ipt_m -I PSW_OUTPUT -p udp -d ${2} --dport ${3} -j PSW_RULE
			$ipt_m -I PSW $(comment "本机") -p udp -i lo -d ${2} --dport ${3} $(REDIRECT $UDP_REDIR_PORT TPROXY)
			echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 UDP 转发链"
		}
		[ "$use_udp_node_resolve_dns" == 1 ] && hosts_foreach DNS_FORWARD _proxy_udp_access 53
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_m -A PSW_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]不代理 UDP 端口：$UDP_NO_REDIR_PORTS"
		}

		$ipt_m -A PSW_OUTPUT -p udp -d $FAKE_IP -j PSW_RULE
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST) -j PSW_RULE
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST) -j PSW_RULE
		$ipt_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ipt $LOCALHOST_UDP_PROXY_MODE) -j PSW_RULE
		$ipt_m -A PSW $(comment "本机") -p udp -i lo $(REDIRECT $UDP_REDIR_PORT TPROXY)
		$ipt_m -A PSW $(comment "本机") -p udp -i lo -j RETURN
		insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment PSW_OUTPUT_UDP) -p udp -j PSW_OUTPUT"
		insert_rule_after "$ipt_m" "OUTPUT" "PSW_OUTPUT_UDP" "$(comment PSW) -p udp -m mark --mark 1 -j RETURN"

		[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
			$ip6t_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_SHUNTLIST6) -j PSW_RULE
			$ip6t_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(dst $IPSET_BLACKLIST6) -j PSW_RULE
			$ip6t_m -A PSW_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(get_ipset_ip6t $LOCALHOST_UDP_PROXY_MODE) -j PSW_RULE
			$ip6t_m -A PSW $(comment "本机") -p udp -i lo $(REDIRECT $UDP_REDIR_PORT TPROXY)
			$ip6t_m -A PSW $(comment "本机") -p udp -i lo -j RETURN
			insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment PSW_OUTPUT_UDP) -p udp -j PSW_OUTPUT"
			insert_rule_after "$ip6t_m" "OUTPUT" "PSW_OUTPUT_UDP" "$(comment PSW) -p udp -m mark --mark 1 -j RETURN"
		}
	fi

	$ipt_m -A PSW -p udp --dport 53 -j RETURN
	$ip6t_m -A PSW -p udp --dport 53 -j RETURN
	#  加载ACLS
	load_acl

	# dns_hijack "force"

	[ -n "${is_tproxy}" -o -n "${udp_flag}" ] && {
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
	}
	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for ipt in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($ipt -nL $chain | grep -c PSW)); do
				local index=$($ipt --line-number -nL $chain | grep PSW | head -1 | awk '{print $1}')
				$ipt -D $chain $index 2>/dev/null
			done
		done
		for chain in "PSW" "PSW_OUTPUT" "PSW_DIVERT" "PSW_REDIRECT" "PSW_RULE"; do
			$ipt -F $chain 2>/dev/null
			$ipt -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_ipset $IPSET_LANIPLIST
	destroy_ipset $IPSET_VPSIPLIST
	#destroy_ipset $IPSET_SHUNTLIST
	#destroy_ipset $IPSET_GFW
	#destroy_ipset $IPSET_CHN
	#destroy_ipset $IPSET_BLACKLIST
	destroy_ipset $IPSET_BLOCKLIST
	destroy_ipset $IPSET_WHITELIST

	destroy_ipset $IPSET_LANIPLIST6
	destroy_ipset $IPSET_VPSIPLIST6
	#destroy_ipset $IPSET_SHUNTLIST6
	#destroy_ipset $IPSET_GFW6
	#destroy_ipset $IPSET_CHN6
	#destroy_ipset $IPSET_BLACKLIST6
	destroy_ipset $IPSET_BLOCKLIST6
	destroy_ipset $IPSET_WHITELIST6

	echolog "删除相关防火墙规则完成。"
}

flush_ipset() {
	del_firewall_rule
	destroy_ipset $IPSET_VPSIPLIST $IPSET_SHUNTLIST $IPSET_GFW $IPSET_CHN $IPSET_BLACKLIST $IPSET_BLOCKLIST $IPSET_WHITELIST $IPSET_LANIPLIST
	destroy_ipset $IPSET_VPSIPLIST6 $IPSET_SHUNTLIST6 $IPSET_GFW6 $IPSET_CHN6 $IPSET_BLACKLIST6 $IPSET_BLOCKLIST6 $IPSET_WHITELIST6 $IPSET_LANIPLIST6
	rm -rf /tmp/etc/passwall_tmp/smartdns*
	rm -rf /tmp/etc/passwall_tmp/dnsmasq*
	/etc/init.d/passwall reload
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	extract_rules() {
		local _ipt="${ipt}"
		[ "$1" == "6" ] && _ipt="${ip6t}"
		[ -z "${_ipt}" ] && return

		echo "*$2"
		${_ipt}-save -t $2 | grep "PSW" | grep -v "\-j PSW$" | grep -v "socket \-j PSW_DIVERT$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			$ipt-save -c | grep -v "PSW" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW")
			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT")

			WAN_IP=\$(${MY_PATH} get_wan_ip)

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_n" PSW WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_n -R PSW \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_m" PSW WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_m -R PSW \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			$ip6t-save -c | grep -v "PSW" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			[ "$accept_icmpv6" = "1" ] && $ip6t_n -A PREROUTING -p ipv6-icmp -j PSW

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW")
			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "PSW" "-p tcp -m socket -j PSW_DIVERT")

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ip6t_m" PSW WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN6_IP}" ] && $ip6t_m -R PSW \$PR_INDEX $(comment "WAN6_IP_RETURN") -d "\${WAN6_IP}" -j RETURN
			fi
		EOF
		)
	}
	cat <<-EOF >> $FWI
		${__ipt}
		
		${__ip6t}
	EOF
	return 0
}

get_ipt_bin() {
	echo $ipt
}

get_ip6t_bin() {
	echo $ip6t
}

start() {
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
flush_ipset)
	flush_ipset
	;;
get_ipt_bin)
	get_ipt_bin
	;;
get_ip6t_bin)
	get_ip6t_bin
	;;
get_wan_ip)
	get_wan_ip
	;;
get_wan6_ip)
	get_wan6_ip
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
