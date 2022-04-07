#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
IPSET_LANIPLIST="laniplist"
IPSET_VPSIPLIST="vpsiplist"

IPSET_LANIPLIST6="laniplist6"
IPSET_VPSIPLIST6="vpsiplist6"

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
FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
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
		[ "$2" == "TPROXY" ] && s="-j TPROXY --tproxy-mark 0x1/0x1 --on-port $1"
		[ "$2" == "MARK" ] && s="-j MARK --set-mark $1"
	}
	echo $s
}

get_redirect_ipt() {
	echo "$(REDIRECT $2 $3)"
}

get_redirect_ip6t() {
	echo "$(REDIRECT $2 $3)"
}

get_action_chain_name() {
	echo "全局代理"
}

gen_laniplist() {
	cat <<-EOF
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.168.0.0/16
		224.0.0.0/4
		240.0.0.0/4
	EOF
}

gen_laniplist_6() {
	cat <<-EOF
		::/128
		::1/128
		::ffff:0:0/96
		::ffff:0:0:0/96
		64:ff9b::/96
		100::/64
		2001::/32
		2001:20::/28
		2001:db8::/32
		2002::/16
		fc00::/7
		fe80::/10
		ff00::/8
	EOF
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
		local redir_port dns_port dnsmasq_port
		local ipt_tmp msg msg2
		redir_port=11200
		dns_port=11300
		dnsmasq_port=11400
		echolog "访问控制："
		for item in $items; do
			local enabled sid remarks sources tcp_no_redir_ports udp_no_redir_ports node dns_protocol dns_forward dns_doh dns_client_ip
			local _ip _mac _iprange _ipset _ip_or_mac rule_list redir_port node_remark config_file
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

			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_proxy_mode="global"
			udp_proxy_mode="global"
			node=${node:-default}
			dns_protocol=${dns_protocol:-tcp}
			dns_forward=${dns_forward:-1.1.1.1}
			[ "$dns_forward" = "doh" ] && dns_forward=${dns_doh:-https://cloudflare-dns.com/dns-query,1.1.1.1}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS
			[ "$node" != "nil" ] && {
				if [ "$node" = "default" ]; then
					node=$NODE
					redir_port=$REDIR_PORT
				else
					[ "$(config_get_type $node nil)" = "nodes" ] && {
						if [ "$node" = "$NODE" ]; then
							redir_port=$REDIR_PORT
						else
							redir_port=$(get_new_port $(expr $redir_port + 1))
							eval node_${node}_redir_port=$redir_port

							local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
							if [ -n "${type}" ] && ([ "${type}" = "v2ray" ] || [ "${type}" = "xray" ]); then
								config_file=$TMP_ACL_PATH/${node}_TCP_UDP_DNS_${redir_port}.json
								dns_port=$(get_new_port $(expr $dns_port + 1))
								run_v2ray flag=acl_$sid node=$node redir_port=$redir_port dns_local=${DEFAULT_DNS} dns_listen_port=${dns_port} dns_proto=${dns_protocol} dns_tcp_server=${dns_forward} doh="${dns_forward}" dns_client_ip=${dns_client_ip} dns_query_strategy=${DNS_QUERY_STRATEGY} config_file=${config_file}
							fi
							dnsmasq_port=$(get_new_port $(expr $dnsmasq_port + 1))
							redirect_dns_port=$dnsmasq_port
							mkdir -p $TMP_ACL_PATH/$sid
							echo "port=${dnsmasq_port}" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							#echo "conf-dir=${TMP_ACL_PATH}/${sid}/dnsmasq.d" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							echo "server=127.0.0.1#${dns_port}" >> $TMP_ACL_PATH/$sid/dnsmasq.conf
							#source $APP_PATH/helper_dnsmasq.sh add TMP_DNSMASQ_PATH=$TMP_ACL_PATH/$sid/dnsmasq.d DNSMASQ_CONF_FILE=/dev/null TUN_DNS=127.0.0.1#${dns_port} NO_LOGIC_LOG=1
							ln_run "$(first_type dnsmasq)" "dnsmasq_${sid}" "/dev/null" -C $TMP_ACL_PATH/$sid/dnsmasq.conf -x $TMP_ACL_PATH/$sid/dnsmasq.pid
							eval node_${node}_$(echo -n "${tcp_proxy_mode}${dns_forward}" | md5sum | cut -d " " -f1)=${dnsmasq_port}
							filter_node $node TCP > /dev/null 2>&1 &
							filter_node $node UDP > /dev/null 2>&1 &
						fi
					}
				fi
				node_remark=$(config_n_get $node remarks)
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

				[ -n "$redir_port" ] && {
					if [ "$tcp_proxy_mode" != "disable" ]; then
						[ -n "$redirect_dns_port" ] && $ipt_n -A PSW2_REDIRECT $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $redirect_dns_port
						msg2="${msg}使用TCP节点[$node_remark] [$(get_action_chain_name $tcp_proxy_mode)]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${redir_port})代理"
							ipt_tmp=$ipt_m
						else
							msg2="${msg2}(REDIRECT:${redir_port})代理"
						fi
						
						[ "$tcp_no_redir_ports" != "disable" ] && {
							$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN
							$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -m multiport --dport $tcp_no_redir_ports -j RETURN 2>/dev/null
							msg2="${msg2}[$?]除${tcp_no_redir_ports}外的"
						}
						msg2="${msg2}所有端口"
						
						$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP $(REDIRECT $redir_port $is_tproxy)
						$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(REDIRECT $redir_port $is_tproxy)

						[ "$accept_icmp" = "1" ] && {
							$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
							$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} $(REDIRECT)
						}

						if [ "$PROXY_IPV6" == "1" ]; then
							$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(factor $tcp_redir_ports "-m multiport --dport") $(REDIRECT $redir_port TPROXY) 2>/dev/null
							[ "$accept_icmpv6" = "1" ] && {
								$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(REDIRECT) 2>/dev/null
							}
						fi
					else
						msg2="${msg}不代理TCP"
					fi
					echolog "  - ${msg2}"
				}

				$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN
				$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null

				[ -n "$redir_port" ] && {
					if [ "$udp_proxy_mode" != "disable" ]; then
						msg2="${msg}使用UDP节点[$node_remark] [$(get_action_chain_name $udp_proxy_mode)]"
						msg2="${msg2}(TPROXY:${redir_port})代理"
						[ "$udp_no_redir_ports" != "disable" ] && {
							$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN
							$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -m multiport --dport $udp_no_redir_ports -j RETURN 2>/dev/null
							msg2="${msg2}[$?]除${udp_no_redir_ports}外的"
						}
						msg2="${msg2}所有端口"
						
						$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP $(REDIRECT $redir_port TPROXY)
						$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(REDIRECT $redir_port TPROXY)

						if [ "$PROXY_IPV6_UDP" == "1" ]; then
							$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(factor $udp_redir_ports "-m multiport --dport") $(REDIRECT $redir_port TPROXY) 2>/dev/null
						fi
					else
						msg2="${msg}不代理UDP"
					fi
					echolog "  - ${msg2}"
				}
				$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
				$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
			done
			unset enabled sid remarks sources tcp_no_redir_ports udp_no_redir_ports node dns_protocol dns_forward dns_doh dns_client_ip
			unset _ip _mac _iprange _ipset _ip_or_mac rule_list redir_port node_remark config_file
			unset ipt_tmp msg msg2
			unset redirect_dns_port
		done
		unset redir_port dns_port dnsmasq_port
		unset ipt_tmp msg msg2
	}

	#  加载默认代理模式
	if [ "$TCP_PROXY_MODE" != "disable" ]; then
		local ipt_tmp=$ipt_n
		[ "$NODE" != "nil" ] && {
			msg="TCP默认代理：使用节点[$(config_n_get $NODE remarks)] [$(get_action_chain_name $TCP_PROXY_MODE)]"
			if [ -n "${is_tproxy}" ]; then
				ipt_tmp=$ipt_m
				msg="${msg}(TPROXY:${REDIR_PORT})代理"
			else
				msg="${msg}(REDIRECT:${REDIR_PORT})代理"
			fi

			[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
				$ipt_tmp -A PSW2 $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
				$ip6t_m -A PSW2 $(comment "默认") -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
				msg="${msg}除${TCP_NO_REDIR_PORTS}外的"
			}
			msg="${msg}所有端口"

			$ipt_tmp -A PSW2 $(comment "默认") -p tcp -d $FAKE_IP $(REDIRECT $REDIR_PORT $is_tproxy)
			$ipt_tmp -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT $is_tproxy)

			[ "$accept_icmp" = "1" ] && {
				$ipt_n -A PSW2 $(comment "默认") -p icmp -d $FAKE_IP $(REDIRECT)
				$ipt_n -A PSW2 $(comment "默认") -p icmp $(REDIRECT)
			}

			if [ "$PROXY_IPV6" == "1" ]; then
				$ip6t_m -A PSW2 $(comment "默认") -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
				[ "$accept_icmpv6" = "1" ] && {
					$ip6t_n -A PSW2 $(comment "默认") -p ipv6-icmp $(REDIRECT)
				}
			fi

			echolog "${msg}"
		}
	fi
	$ipt_n -A PSW2 $(comment "默认") -p tcp -j RETURN
	$ipt_m -A PSW2 $(comment "默认") -p tcp -j RETURN
	$ip6t_m -A PSW2 $(comment "默认") -p tcp -j RETURN

	#  加载UDP默认代理模式
	if [ "$UDP_PROXY_MODE" != "disable" ]; then
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_m -A PSW2 $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2 $(comment "默认") -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
		}

		[ -n "1" ] && {
			msg="UDP默认代理：使用节点[$(config_n_get $NODE remarks)] [$(get_action_chain_name $UDP_PROXY_MODE)](TPROXY:${REDIR_PORT})代理"
			
			[ "$UDP_NO_REDIR_PORTS" != "disable" ] && msg="${msg}除${UDP_NO_REDIR_PORTS}外的"
			msg="${msg}所有端口"
			
			$ipt_m -A PSW2 $(comment "默认") -p udp -d $FAKE_IP $(REDIRECT $REDIR_PORT TPROXY)
			$ipt_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)

			if [ "$PROXY_IPV6_UDP" == "1" ]; then
				$ip6t_m -A PSW2 $(comment "默认") -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
			fi

			echolog "${msg}"
		}
	fi
	$ipt_m -A PSW2 $(comment "默认") -p udp -j RETURN
	$ip6t_m -A PSW2 $(comment "默认") -p udp -j RETURN
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
			$_ipt -n -L PSW2_OUTPUT | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule=$(REDIRECT 1 MARK)
				msg2="按规则路由(${msg})"
				[ "$_ipt" == "$ipt_m" -o "$_ipt" == "$ip6t_m" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="套娃使用(${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "$_ipt" PSW2_OUT_PUT "$IPSET_VPSIPLIST" $FORCE_INDEX)
					dst_rule=" -j RETURN"
					msg2="直连代理"
				}
				$_ipt -I PSW2_OUTPUT $ADD_INDEX $(comment "${address}:${port}") -p $stream -d $address --dport $port $dst_rule 2>/dev/null
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
	$ipt_n -I PSW2 -p udp --dport 53 -j REDIRECT --to-ports 53
	echolog "强制转发本机DNS端口 UDP/53 的请求[$?]"
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..."
	ipset -! create $IPSET_LANIPLIST nethash maxelem 1048576
	ipset -! create $IPSET_VPSIPLIST nethash maxelem 1048576

	ipset -! create $IPSET_LANIPLIST6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPSIPLIST6 nethash family inet6 maxelem 1048576

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
			ipset -! add $IPSET_LANIPLIST $ispip >/dev/null 2>&1 &
			#echolog "  - 追加到白名单：${ispip}"
		done
	}

	local ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}'| sort -u | grep -v -Fx ::1 | grep -v -Fx ::)
	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS; do
			ipset -! add $IPSET_LANIPLIST6 $ispip6 >/dev/null 2>&1 &
			#echolog "  - 追加到白名单：${ispip6}"
		done
	}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	$ipt_n -N PSW2
	$ipt_n -A PSW2 $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW2 $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW2 -m mark --mark 0xff -j RETURN

	WAN_IP=$(get_wan_ip)
	[ ! -z "${WAN_IP}" ] && $ipt_n -A PSW2 $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW2"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW2"

	$ipt_n -N PSW2_OUTPUT
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_n -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN

	$ipt_n -N PSW2_REDIRECT
	$ipt_n -I PREROUTING 1 -j PSW2_REDIRECT

	$ipt_m -N PSW2_DIVERT
	$ipt_m -A PSW2_DIVERT -j MARK --set-mark 1
	$ipt_m -A PSW2_DIVERT -j ACCEPT

	$ipt_m -N PSW2
	$ipt_m -A PSW2 $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW2 $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW2 -m mark --mark 0xff -j RETURN
	
	[ ! -z "${WAN_IP}" ] && $ipt_m -A PSW2 $(comment "WAN_IP_RETURN") -d "${WAN_IP}" -j RETURN
	unset WAN_IP

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW2"
	insert_rule_before "$ipt_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT"

	$ipt_m -N PSW2_OUTPUT
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_LANIPLIST) -j RETURN
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_VPSIPLIST) -j RETURN
	$ipt_m -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN
	$ipt_m -A OUTPUT -j PSW2_OUTPUT

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW2
		$ip6t_n -A PSW2 $(dst $IPSET_LANIPLIST6) -j RETURN
		$ip6t_n -A PSW2 $(dst $IPSET_VPSIPLIST6) -j RETURN
		$ip6t_n -A PSW2 -m mark --mark 0xff -j RETURN
		$ip6t_n -A PREROUTING -p ipv6-icmp -j PSW2

		$ip6t_n -N PSW2_OUTPUT
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_LANIPLIST6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_VPSIPLIST6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN
	}

	$ip6t_m -N PSW2_DIVERT
	$ip6t_m -A PSW2_DIVERT -j MARK --set-mark 1
	$ip6t_m -A PSW2_DIVERT -j ACCEPT

	$ip6t_m -N PSW2
	$ip6t_m -A PSW2 $(dst $IPSET_LANIPLIST6) -j RETURN
	$ip6t_m -A PSW2 $(dst $IPSET_VPSIPLIST6) -j RETURN
	$ip6t_m -A PSW2 -m mark --mark 0xff -j RETURN
	
	WAN6_IP=$(get_wan6_ip)
	[ ! -z "${WAN6_IP}" ] && $ip6t_m -A PSW2 $(comment "WAN6_IP_RETURN") -d ${WAN6_IP} -j RETURN
	unset WAN6_IP

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW2"
	insert_rule_before "$ip6t_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT"

	$ip6t_m -N PSW2_OUTPUT
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_LANIPLIST6) -j RETURN
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_VPSIPLIST6) -j RETURN
	$ip6t_m -A PSW2_OUTPUT -m mark --mark 0xff -j RETURN
	$ip6t_m -A OUTPUT -j PSW2_OUTPUT

	ip -6 rule add fwmark 1 table 100
	ip -6 route add local ::/0 dev lo table 100

	# 加载路由器自身代理 TCP
	if [ "$NODE" != "nil" ]; then
		local ipt_tmp=$ipt_n
		local blist_r=$(REDIRECT $REDIR_PORT)
		local p_r=$(get_redirect_ipt $LOCALHOST_TCP_PROXY_MODE $REDIR_PORT)
		echolog "加载路由器自身 TCP 代理..."

		if [ -n "${is_tproxy}" ]; then
			echolog "  - 启用 TPROXY 模式"
			ipt_tmp=$ipt_m
			blist_r=$(REDIRECT 1 MARK)
			p_r=$(get_redirect_ipt $LOCALHOST_TCP_PROXY_MODE 1 MARK)
		else
			$ipt_n -A OUTPUT -p tcp -j PSW2_OUTPUT
		fi

		[ "$accept_icmp" = "1" ] && {
			$ipt_n -A OUTPUT -p icmp -j PSW2_OUTPUT
			$ipt_n -A PSW2_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
			$ipt_n -A PSW2_OUTPUT -p icmp $(REDIRECT)
		}

		[ "$accept_icmpv6" = "1" ] && {
			$ip6t_n -A OUTPUT -p ipv6-icmp -j PSW2_OUTPUT
			$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp $(REDIRECT)
		}

		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_tmp -A PSW2_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ipt_tmp -A PSW2_OUTPUT -p tcp -m multiport --sport $TCP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p tcp -m multiport --dport $TCP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p tcp -m multiport --sport $TCP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]不代理TCP 端口：$TCP_NO_REDIR_PORTS"
		}

		$ipt_tmp -A PSW2_OUTPUT -p tcp -d $FAKE_IP $blist_r
		$ipt_tmp -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $blist_r
		$ipt_tmp -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $p_r

		if [ -n "${is_tproxy}" ]; then
			$ipt_m -A PSW2 $(comment "本机") -p tcp -i lo -d $FAKE_IP $(REDIRECT $REDIR_PORT TPROXY)
			$ipt_m -A PSW2 $(comment "本机") -p tcp -i lo $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
			$ipt_m -A PSW2 $(comment "本机") -p tcp -i lo -j RETURN
		fi

		if [ "$PROXY_IPV6" == "1" ]; then
			$ip6t_m -A PSW2_OUTPUT -p tcp $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(REDIRECT 1 MARK)

			$ip6t_m -A PSW2 $(comment "本机") -p tcp -i lo $(factor $TCP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
			$ip6t_m -A PSW2 $(comment "本机") -p tcp -i lo -j RETURN
		fi
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
			else
				filter_node $node TCP > /dev/null 2>&1 &
				filter_node $node UDP > /dev/null 2>&1 &
			fi
			#echolog "  - ${msg}"
		done
	}

	# 处理轮换节点的分流或套娃
	filter_node $NODE TCP > /dev/null 2>&1 &
	filter_node $NODE UDP > /dev/null 2>&1 &

	# 加载路由器自身代理 UDP
	if [ "$NODE" != "nil" ]; then
		echolog "加载路由器自身 UDP 代理..."
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			$ipt_m -A PSW2_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ipt_m -A PSW2_OUTPUT -p udp -m multiport --sport $UDP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p udp -m multiport --dport $UDP_NO_REDIR_PORTS -j RETURN
			$ip6t_m -A PSW2_OUTPUT -p udp -m multiport --sport $UDP_NO_REDIR_PORTS -j RETURN
			echolog "  - [$?]不代理 UDP 端口：$UDP_NO_REDIR_PORTS"
		}
		
		$ipt_m -A PSW2_OUTPUT -p udp -d $FAKE_IP $(REDIRECT 1 MARK)
		$ipt_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT 1 MARK)

		$ipt_m -A PSW2 $(comment "本机") -p udp -i lo -d $FAKE_IP $(REDIRECT $REDIR_PORT TPROXY)
		$ipt_m -A PSW2 $(comment "本机") -p udp -i lo $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
		$ipt_m -A PSW2 $(comment "本机") -p udp -i lo -j RETURN

		if [ "$PROXY_IPV6_UDP" == "1" ]; then
			$ip6t_m -A PSW2_OUTPUT -p udp $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT 1 MARK)

			$ip6t_m -A PSW2 $(comment "本机") -p udp -i lo $(factor $UDP_REDIR_PORTS "-m multiport --dport") $(REDIRECT $REDIR_PORT TPROXY)
			$ip6t_m -A PSW2 $(comment "本机") -p udp -i lo -j RETURN
		fi
	fi

	#  加载ACLS
	load_acl

	# dns_hijack "force"

	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for ipt in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($ipt -nL $chain | grep -c PSW2)); do
				local index=$($ipt --line-number -nL $chain | grep PSW2 | head -1 | awk '{print $1}')
				$ipt -D $chain $index 2>/dev/null
			done
		done
		for chain in "PSW2" "PSW2_OUTPUT" "PSW2_DIVERT" "PSW2_REDIRECT"; do
			$ipt -F $chain 2>/dev/null
			$ipt -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	echolog "删除相关防火墙规则完成。"
}

flush_ipset() {
	del_firewall_rule
	/etc/init.d/passwall2 reload
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
		${_ipt}-save -t $2 | grep "PSW2" | grep -v "\-j PSW2$" | grep -v "socket \-j PSW2_DIVERT$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			$ipt-save -c | grep -v "PSW2" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p icmp -j PSW2")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "-p tcp -j PSW2")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "-j PSW2")
			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT")

			WAN_IP=\$(${MY_PATH} get_wan_ip)

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_n" PSW2 WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_n -R PSW2 \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ipt_m" PSW2 WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				[ ! -z "\${WAN_IP}" ] && $ipt_m -R PSW2 \$PR_INDEX $(comment "WAN_IP_RETURN") -d "\${WAN_IP}" -j RETURN
			fi
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			$ip6t-save -c | grep -v "PSW2" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			[ "$accept_icmpv6" = "1" ] && $ip6t_n -A PREROUTING -p ipv6-icmp -j PSW2

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "-j PSW2")
			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "PSW2" "-p tcp -m socket -j PSW2_DIVERT")

			PR_INDEX=\$(${MY_PATH} RULE_LAST_INDEX "$ip6t_m" PSW2 WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN6_IP}" ] && $ip6t_m -R PSW2 \$PR_INDEX $(comment "WAN6_IP_RETURN") -d "\${WAN6_IP}" -j RETURN
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
