#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
NFTABLE_NAME="inet passwall"
NFTSET_LANLIST="passwall_lanlist"
NFTSET_VPSLIST="passwall_vpslist"
NFTSET_SHUNTLIST="passwall_shuntlist"
NFTSET_GFW="passwall_gfwlist"
NFTSET_CHN="passwall_chnroute"
NFTSET_BLACKLIST="passwall_blacklist"
NFTSET_WHITELIST="passwall_whitelist"
NFTSET_BLOCKLIST="passwall_blocklist"

NFTSET_LANLIST6="passwall_lanlist6"
NFTSET_VPSLIST6="passwall_vpslist6"
NFTSET_SHUNTLIST6="passwall_shuntlist6"
NFTSET_GFW6="passwall_gfwlist6"
NFTSET_CHN6="passwall_chnroute6"
NFTSET_BLACKLIST6="passwall_blacklist6"
NFTSET_WHITELIST6="passwall_whitelist6"
NFTSET_BLOCKLIST6="passwall_blocklist6"

FORCE_INDEX=0

. /lib/functions/network.sh

FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/15"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	# acl mac address
	elif [ -n "$(echo $1 | grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}')" ]; then
		echo "$2 {$1}"
	else
		echo "$2 {$(echo $1 | sed 's/:/-/g')}"
	fi
}

insert_rule_before() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

insert_rule_after() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "索引列举方式不正确（nftables），终止执行！"
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="counter redirect"
	[ -n "$1" ] && {
		local s="$s to :$1"
		[ "$2" == "MARK" ] && s="counter meta mark set $1"
		[ "$2" == "TPROXY" ] && {
			s="counter meta mark 1 tproxy to :$1"
		}
		[ "$2" == "TPROXY4" ] && {
			s="counter meta mark 1 tproxy ip to :$1"
		}
		[ "$2" == "TPROXY6" ] && {
			s="counter meta mark 1 tproxy ip6 to :$1"
		}

	}
	echo $s
}

destroy_nftset() {
	for i in "$@"; do
		nft flush set $NFTABLE_NAME $i 2>/dev/null
		nft delete set $NFTABLE_NAME $i 2>/dev/null
	done
}

gen_nft_tables() {
	if [ -z "$(nft list tables | grep 'inet passwall')" ]; then
		local nft_table_file="$TMP_PATH/PSW_TABLE.nft"
		# Set the correct priority to fit fw4
		cat > "$nft_table_file" <<-EOF
		table $NFTABLE_NAME {
			chain dstnat {
				type nat hook prerouting priority dstnat - 1; policy accept;
			}
			chain mangle_prerouting {
				type filter hook prerouting priority mangle - 1; policy accept;
			}
			chain mangle_output {
				type route hook output priority mangle - 1; policy accept;
			}
			chain nat_output {
				type nat hook output priority -1; policy accept;
			}
		}
		EOF

		nft -f "$nft_table_file"
		rm -rf "$nft_table_file"
	fi
}

insert_nftset() {
	local nftset_name="${1}"; shift
	local timeout_argument="${1}"; shift
	local defalut_timeout_argument="3650d"
	local nftset_elements

	[ -n "${1}" ] && {
		if [ "$timeout_argument" == "-1" ]; then
			nftset_elements=$(echo -e $@ | sed 's/\s/, /g')
		elif [ "$timeout_argument" == "0" ]; then
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $defalut_timeout_argument, /g" | sed "s/$/ timeout $defalut_timeout_argument/")
		else
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $timeout_argument, /g" | sed "s/$/ timeout $timeout_argument/")
		fi
		mkdir -p $TMP_PATH2/nftset
		cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
			define $nftset_name = {$nftset_elements}	
			add element $NFTABLE_NAME $nftset_name \$$nftset_name
		EOF
		nft -f "$TMP_PATH2/nftset/$nftset_name"
		rm -rf "$TMP_PATH2/nftset"
	}
}

gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	#  0 - don't set defalut timeout
	local timeout_argument_set="${1}"; shift
	#  0 - don't let element timeout(3650 days) when set's timeout parameters be seted
	# -1 - follow the set's timeout parameters
	local timeout_argument_element="${1}"; shift

	nft "list set $NFTABLE_NAME $nftset_name" &>/dev/null
	if [ $? -ne 0 ]; then
		if [ "$timeout_argument_set" == "0" ]; then
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $timeout_argument_set; auto-merge; }"
		fi
	fi
	[ -n "${1}" ] && insert_nftset $nftset_name $timeout_argument_element $@
}

get_jump_ipt() {
	case "$1" in
	direct)
		echo "mark != 1 counter return"
		;;
	proxy)
		if [ -n "$2" ] && [ -n "$(echo $2 | grep "^counter")" ]; then
			echo "$2"
		else
			echo "$(REDIRECT $2 $3)"
		fi
		;;
	esac
}

gen_lanlist() {
	cat $RULES_PATH/lanlist_ipv4 | tr -s '\n' | grep -v "^#"
}

gen_lanlist_6() {
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
	([ "$ENABLED_ACLS" == 1 ] || ([ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ])) && echolog "  - 访问控制："
	[ "$ENABLED_ACLS" == 1 ] && {
		acl_app
		for sid in $(ls -F ${TMP_ACL_PATH} | grep '/$' | awk -F '/' '{print $1}' | grep -v 'default'); do
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)

			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			use_global_config=${use_global_config:-0}
			tcp_proxy_drop_ports=${tcp_proxy_drop_ports:-default}
			udp_proxy_drop_ports=${udp_proxy_drop_ports:-default}
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			tcp_node=${tcp_node:-nil}
			udp_node=${udp_node:-nil}
			use_direct_list=${use_direct_list:-1}
			use_proxy_list=${use_proxy_list:-1}
			use_block_list=${use_block_list:-1}
			use_gfw_list=${use_gfw_list:-1}
			chn_list=${chn_list:-direct}
			tcp_proxy_mode=${tcp_proxy_mode:-proxy}
			udp_proxy_mode=${udp_proxy_mode:-proxy}
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_proxy_drop_ports" = "default" ] && tcp_proxy_drop_ports=$TCP_PROXY_DROP_PORTS
			[ "$udp_proxy_drop_ports" = "default" ] && udp_proxy_drop_ports=$UDP_PROXY_DROP_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS

			[ -s "${TMP_ACL_PATH}/${sid}/var_tcp_node" ] && tcp_node=$(cat ${TMP_ACL_PATH}/${sid}/var_tcp_node)
			[ -s "${TMP_ACL_PATH}/${sid}/var_udp_node" ] && udp_node=$(cat ${TMP_ACL_PATH}/${sid}/var_udp_node)
			[ -s "${TMP_ACL_PATH}/${sid}/var_tcp_port" ] && tcp_port=$(cat ${TMP_ACL_PATH}/${sid}/var_tcp_port)
			[ -s "${TMP_ACL_PATH}/${sid}/var_udp_port" ] && udp_port=$(cat ${TMP_ACL_PATH}/${sid}/var_udp_port)
			[ "$tcp_node" != "nil" ] && tcp_node_remark=$(config_n_get $tcp_node remarks)
			[ "$udp_node" != "nil" ] && udp_node_remark=$(config_n_get $udp_node remarks)
			[ "$udp_node" == "tcp" ] && udp_node_remark=$tcp_node_remark

			[ "${use_global_config}" = "1" ] && { 
				tcp_node_remark=$(config_n_get $TCP_NODE remarks)
				udp_node_remark=$(config_n_get $UDP_NODE remarks)
				use_direct_list=${USE_DIRECT_LIST}
				use_proxy_list=${USE_PROXY_LIST}
				use_block_list=${USE_BLOCK_LIST}
				use_gfw_list=${USE_GFW_LIST}
				chn_list=${CHN_LIST}
				tcp_proxy_mode=${TCP_PROXY_MODE}
				udp_proxy_mode=${UDP_PROXY_MODE}
			}

			_acl_list=${TMP_ACL_PATH}/${sid}/rule_list
			[ $use_interface = "1" ] && _acl_list=${TMP_ACL_PATH}/${sid}/interface_list

			for i in $(cat $_acl_list); do
				if [ $use_interface = "0" ]; then
					if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
						_iprange=$(echo ${i} | sed 's#iprange:##g')
						_ipt_source=$(factor ${_iprange} "ip saddr")
						msg="【$remarks】，IP range【${_iprange}】，"
					elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
						_ipset=$(echo ${i} | sed 's#ipset:##g')
						_ipt_source="ip daddr @${_ipset}"
						msg="【$remarks】，NFTset【${_ipset}】，"
					elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
						_ip=$(echo ${i} | sed 's#ip:##g')
						_ipt_source=$(factor ${_ip} "ip saddr")
						msg="【$remarks】，IP【${_ip}】，"
					elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
						_mac=$(echo ${i} | sed 's#mac:##g')
						_ipt_source=$(factor ${_mac} "ether saddr")
						msg="【$remarks】，MAC【${_mac}】，"
					else
						continue
					fi
				else
					[ -z "${i}" ] && continue
					_ifname="${i}"
					_ipt_source="iifname $_ifname"
					msg="【$remarks】，IF【${_ifname}】，"
				fi
				
				[ "$tcp_no_redir_ports" != "disable" ] && {
					if [ "$tcp_no_redir_ports" != "1:65535" ]; then
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ${_ipt_source} ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} meta l4proto tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						echolog "     - ${msg}不代理 TCP 端口[${tcp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						unset tcp_port
						echolog "     - ${msg}不代理所有 TCP 端口"
					fi
				}
				
				[ "$udp_no_redir_ports" != "disable" ] && {
					if [ "$udp_no_redir_ports" != "1:65535" ]; then
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\"" 2>/dev/null
						echolog "     - ${msg}不代理 UDP 端口[${udp_no_redir_ports}]"
					else
						#结束时会return，无需加多余的规则。
						unset udp_port
						echolog "     - ${msg}不代理所有 UDP 端口"
					fi
				}
				
				[ -n "$tcp_port" -o -n "$udp_port" ] && {
					[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ${_ipt_source} ip daddr @$NFTSET_WHITELIST counter return comment \"$remarks\""
					[ "${use_direct_list}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ${_ipt_source} ip daddr @$NFTSET_WHITELIST counter return comment \"$remarks\""
					[ "${use_block_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ${_ipt_source} ip daddr @$NFTSET_BLOCKLIST counter drop comment \"$remarks\""
					[ "${use_block_list}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ${_ipt_source} ip daddr @$NFTSET_BLOCKLIST counter drop comment \"$remarks\""
					[ "$PROXY_IPV6" == "1" ] && {
						[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} ip6 daddr @$NFTSET_WHITELIST6 counter return comment \"$remarks\""
						[ "${use_block_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ${_ipt_source} ip6 daddr @$NFTSET_BLOCKLIST6 counter drop comment \"$remarks\""
					}
					
					[ "$tcp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") counter drop comment \"$remarks\"" 2>/dev/null
						}
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\""
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"$remarks\""
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"$remarks\""
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_GFW counter drop comment \"$remarks\""
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\""
						[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") counter drop comment \"$remarks\""
						echolog "     - ${msg}屏蔽代理 TCP 端口[${tcp_proxy_drop_ports}]"
					}
					
					[ "$udp_proxy_drop_ports" != "disable" ] && {
						[ "$PROXY_IPV6" == "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") counter drop comment \"$remarks\"" 2>/dev/null
						}
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"$remarks\"" 2>/dev/null
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"$remarks\"" 2>/dev/null
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_GFW counter drop comment \"$remarks\"" 2>/dev/null
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter drop") comment \"$remarks\"" 2>/dev/null
						[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") counter drop comment \"$remarks\"" 2>/dev/null
						echolog "     - ${msg}屏蔽代理 UDP 端口[${udp_proxy_drop_ports}]"
					}
				}

				[ -n "$tcp_port" ] && {
					if [ -n "${tcp_proxy_mode}" ]; then
						[ -s "${TMP_ACL_PATH}/${sid}/var_redirect_dns_port" ] && nft "add rule $NFTABLE_NAME PSW_REDIRECT ip protocol udp ${_ipt_source} udp dport 53 counter redirect to $(cat ${TMP_ACL_PATH}/${sid}/var_redirect_dns_port) comment \"$remarks\""
						msg2="${msg}使用 TCP 节点[$tcp_node_remark]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${tcp_port})"
						else
							msg2="${msg2}(REDIRECT:${tcp_port})"
						fi
						
						[ "$accept_icmp" = "1" ] && {
							[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_WHITELIST counter return comment \"默认\""
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_SHUNTLIST $(REDIRECT) comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_BLACKLIST $(REDIRECT) comment \"$remarks\""
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_GFW $(REDIRECT) comment \"$remarks\""
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list}) comment \"$remarks\""
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(REDIRECT) comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
						}

						[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
							[ "${use_direct_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_WHITELIST6 counter return comment \"默认\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_SHUNTLIST6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_BLACKLIST6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_GFW6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list}) comment \"$remarks\"" 2>/dev/null
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
						}

						if [ -z "${is_tproxy}" ]; then
							nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT $tcp_port) comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST $(REDIRECT $tcp_port) comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST $(REDIRECT $tcp_port) comment \"$remarks\""
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_GFW $(REDIRECT $tcp_port) comment \"$remarks\""
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} $tcp_port) comment \"$remarks\""
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") $(REDIRECT $tcp_port) comment \"$remarks\""
						else
							nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW_RULE comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"$remarks\""
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"$remarks\" "
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_GFW counter jump PSW_RULE comment \"$remarks\" "
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\" "
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW_RULE comment \"$remarks\""
							nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY4) comment \"$remarks\""
						fi

						[ "$PROXY_IPV6" == "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\" "
							[ "${tcp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg}不代理 TCP"
					fi
					echolog "     - ${msg2}"
				}

				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ -n "$udp_port" ] && {
					if [ -n "${udp_proxy_mode}" ]; then
						msg2="${msg}使用 UDP 节点[$udp_node_remark]"
						msg2="${msg2}(TPROXY:${udp_port})"

						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW_RULE comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"$remarks\""
						[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"$remarks\""
						[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_GFW counter jump PSW_RULE comment \"$remarks\""
						[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\""
						[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW_RULE comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $udp_port TPROXY4) comment \"$remarks\""

						[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_proxy_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${use_gfw_list}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "${chn_list}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${chn_list} "counter jump PSW_RULE") comment \"$remarks\"" 2>/dev/null
							[ "${udp_proxy_mode}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(REDIRECT $udp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg}不代理 UDP"
					fi
					echolog "     - ${msg2}"
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null
			done
			unset enabled sid remarks sources use_global_config use_direct_list use_proxy_list use_block_list use_gfw_list chn_list tcp_proxy_mode udp_proxy_mode tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node use_interface interface
			unset _ip _mac _iprange _ipset _ip_or_mac rule_list tcp_port udp_port tcp_node_remark udp_node_remark _acl_list _ifname
			unset msg msg2
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && [ "$CLIENT_PROXY" == 1 ] && {
		msg="【默认】，"
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"默认\""
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "     - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset TCP_PROXY_MODE
				echolog "     - ${msg}不代理所有 TCP 端口"
			fi
		}

		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			nft "add $NFTABLE_NAME PSW_MANGLE_V6 counter meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"默认\""
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "     - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset UDP_PROXY_MODE
				echolog "     - ${msg}不代理所有 UDP 端口"
			fi
		}

		[ -n "${TCP_PROXY_MODE}" -o -n "${UDP_PROXY_MODE}" ] && {
			[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_WHITELIST counter return comment \"$remarks\""
			[ "${USE_DIRECT_LIST}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_WHITELIST counter return comment \"$remarks\""
			[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_BLOCKLIST counter drop comment \"$remarks\""
			[ "${USE_BLOCK_LIST}" = "1" ] && [ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_BLOCKLIST counter drop comment \"$remarks\""
			[ "$PROXY_IPV6" == "1" ] && {
				[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_WHITELIST6 counter return comment \"$remarks\""
				[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_BLOCKLIST6 counter drop comment \"$remarks\""
			}
			
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop comment \"默认\""
				}

				nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr $FAKE_IP counter drop comment \"默认\""
				nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_GFW counter drop comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
				[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop comment \"默认\""
				echolog "     - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_GFW6 counter drop comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
					[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop comment \"默认\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr $FAKE_IP counter drop comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_GFW counter drop comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter drop") comment \"默认\""
				[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop comment \"默认\""
				echolog "     - ${msg}屏蔽代理 UDP 端口[${UDP_PROXY_DROP_PORTS}]"
			}
		}

		#  加载TCP默认代理模式
		if [ -n "${TCP_PROXY_MODE}" ]; then
			[ "$TCP_NODE" != "nil" ] && {
				msg2="${msg}使用 TCP 节点[$(config_n_get $TCP_NODE remarks)]"
				if [ -n "${is_tproxy}" ]; then
					msg2="${msg2}(TPROXY:${TCP_REDIR_PORT})"
				else
					msg2="${msg2}(REDIRECT:${TCP_REDIR_PORT})"
				fi
				
				[ "$accept_icmp" = "1" ] && {
					[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_WHITELIST counter return comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr $FAKE_IP $(REDIRECT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_SHUNTLIST $(REDIRECT) comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_BLACKLIST $(REDIRECT) comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_GFW $(REDIRECT) comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST}) comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp $(REDIRECT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip protocol icmp return comment \"默认\""
				}

				[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
					[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_WHITELIST6 counter return comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNTLIST6 $(REDIRECT) comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACKLIST6 $(REDIRECT) comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_GFW6 $(REDIRECT) comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST}) comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 $(REDIRECT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT meta l4proto icmpv6 return comment \"默认\""
				}

				if [ -z "${is_tproxy}" ]; then
					nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp ip daddr $FAKE_IP $(REDIRECT $TCP_REDIR_PORT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST $(REDIRECT $TCP_REDIR_PORT) comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST $(REDIRECT $TCP_REDIR_PORT) comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_GFW $(REDIRECT $TCP_REDIR_PORT) comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} $TCP_REDIR_PORT) comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(REDIRECT $TCP_REDIR_PORT) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_NAT ip protocol tcp counter return comment \"默认\""
				else
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp ip daddr $FAKE_IP counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_GFW counter jump PSW_RULE comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp counter return comment \"默认\""
				fi

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
					[ "${TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp counter return comment \"默认\""
				}

				echolog "     - ${msg2}"
			}
		fi

		#  加载UDP默认代理模式
		if [ -n "${UDP_PROXY_MODE}" ]; then
			[ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ] && {
				msg2="${msg}使用 UDP 节点[$(config_n_get $UDP_NODE remarks)](TPROXY:${UDP_REDIR_PORT})"

				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"默认\""
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"默认\""
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_GFW counter jump PSW_RULE comment \"默认\""
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
				[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"默认\""
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp counter return comment \"默认\""

				[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"默认\""
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_GFW6 counter jump PSW_RULE comment \"默认\""
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE") comment \"默认\""
					[ "${UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"默认\""
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp counter return comment \"默认\""
				}

				echolog "     - ${msg2}"
				udp_flag=1
			}
		fi
	}
}

filter_haproxy() {
	for item in ${haproxy_items}; do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		insert_nftset $NFTSET_VPSLIST "-1" $ip
	done
	echolog "  - [$?]加入负载均衡的节点到nftset[$NFTSET_VPSLIST]直连完成"
}

filter_vps_addr() {
	for server_host in $@; do
		local vps_ip4=$(get_host_ip "ipv4" ${server_host})
		local vps_ip6=$(get_host_ip "ipv6" ${server_host})
		[ -n "$vps_ip4" ] && insert_nftset $NFTSET_VPSLIST "-1" $vps_ip4
		[ -n "$vps_ip6" ] && insert_nftset $NFTSET_VPSLIST6 "-1" $vps_ip6
	done
}

filter_vpsip() {
	insert_nftset $NFTSET_VPSLIST "-1" $(uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$" | sed -e "/^$/d")
	echolog "  - [$?]加入所有IPv4节点到nftset[$NFTSET_VPSLIST]直连完成"
	insert_nftset $NFTSET_VPSLIST6 "-1" $(uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d")
	echolog "  - [$?]加入所有IPv6节点到nftset[$NFTSET_VPSLIST6]直连完成"
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
		local _is_tproxy msg msg2

		if [ -n "$node" ] && [ "$node" != "nil" ]; then
			local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
			local address=$(config_n_get $node address)
			local port=$(config_n_get $node port)
			_is_tproxy=${is_tproxy}
			[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
			if [ -n "${_is_tproxy}" ]; then
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
			[ "$_ipt" == "4" ] && _ip_type=ip && _set_name=$NFTSET_VPSLIST
			[ "$_ipt" == "6" ] && _ip_type=ip6 && _set_name=$NFTSET_VPSLIST6
			nft "list chain $NFTABLE_NAME $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule="jump PSW_RULE"
				msg2="按规则路由(${msg})"
				[ -n "${is_tproxy}" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="套娃使用(${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "$NFTABLE_NAME" $nft_output_chain $_set_name $FORCE_INDEX)
					dst_rule="return"
					msg2="直连代理"
				}
				nft "insert rule $NFTABLE_NAME $nft_output_chain position $ADD_INDEX meta l4proto $stream $_ip_type daddr $address $stream dport $port $dst_rule comment \"${address}:${port}\"" 2>/dev/null
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
	[ $(config_t_get global dns_redirect "0") = "1" ] && {
		nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp tcp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp udp dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp tcp dport 53 counter return"
		nft insert rule $NFTABLE_NAME dstnat position 0 tcp dport 53 counter redirect to :53 comment \"PSW_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 udp dport 53 counter redirect to :53 comment \"PSW_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 meta nfproto {ipv6} tcp dport 53 counter redirect to :53 comment \"PSW_DNS_Hijack\" 2>/dev/null
		nft insert rule $NFTABLE_NAME dstnat position 0 meta nfproto {ipv6} udp dport 53 counter redirect to :53 comment \"PSW_DNS_Hijack\" 2>/dev/null
		uci -q set dhcp.@dnsmasq[0].dns_redirect='0' 2>/dev/null
		uci commit dhcp 2>/dev/null
		echolog "  - 开启 DNS 重定向"
	}
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..."
	gen_nft_tables
	gen_nftset $NFTSET_VPSLIST ipv4_addr 0 0
	gen_nftset $NFTSET_GFW ipv4_addr "2d" 0
	gen_nftset $NFTSET_LANLIST ipv4_addr 0 "-1" $(gen_lanlist)
	if [ -f $RULES_PATH/chnroute.nft ] && [ -s $RULES_PATH/chnroute.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute.nft) -ge 8 ]; then
		#echolog "使用缓存加载chnroute..."
		nft -f $RULES_PATH/chnroute.nft
	else
		gen_nftset $NFTSET_CHN ipv4_addr "2d" 0 $(cat $RULES_PATH/chnroute | tr -s '\n' | grep -v "^#")
	fi
	gen_nftset $NFTSET_BLACKLIST ipv4_addr "2d" 0 $(cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_WHITELIST ipv4_addr "2d" 0 $(cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_BLOCKLIST ipv4_addr "2d" 0 $(cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_SHUNTLIST ipv4_addr 0 0

	gen_nftset $NFTSET_VPSLIST6 ipv6_addr 0 0
	gen_nftset $NFTSET_GFW6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_LANLIST6 ipv6_addr 0 "-1" $(gen_lanlist_6)
	if [ -f $RULES_PATH/chnroute6.nft ] && [ -s $RULES_PATH/chnroute6.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute6.nft) -ge 8 ]; then
		#echolog "使用缓存加载chnroute6..."
		nft -f $RULES_PATH/chnroute6.nft
	else
		gen_nftset $NFTSET_CHN6 ipv6_addr "2d" 0 $(cat $RULES_PATH/chnroute6 | tr -s '\n' | grep -v "^#")
	fi
	gen_nftset $NFTSET_BLACKLIST6 ipv6_addr "2d" 0 $(cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_WHITELIST6 ipv6_addr "2d" 0 $(cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_BLOCKLIST6 ipv6_addr "2d" 0 $(cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_SHUNTLIST6 ipv6_addr 0 0

	local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')

	for shunt_id in $shunt_ids; do
		insert_nftset $NFTSET_SHUNTLIST "-1" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	done

	for shunt_id in $shunt_ids; do
		insert_nftset $NFTSET_SHUNTLIST6 "-1" $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	done

	# 忽略特殊IP段
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "本机IPv4网段互访直连：${lan_ip}"
		#echolog "本机IPv6网段互访直连：${lan_ip6}"

		[ -n "$lan_ip" ] && insert_nftset $NFTSET_LANLIST "-1" $(echo $lan_ip | sed -e "s/ /\n/g")
		[ -n "$lan_ip6" ] && insert_nftset $NFTSET_LANLIST6 "-1" $(echo $lan_ip6 | sed -e "s/ /\n/g")
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "处理 ISP DNS 例外..."
		for ispip in $ISP_DNS; do
			insert_nftset $NFTSET_WHITELIST 0 $ispip
			echolog "  - [$?]追加ISP IPv4 DNS到白名单：${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "处理 ISP IPv6 DNS 例外..."
		for ispip6 in $ISP_DNS6; do
			insert_nftset $NFTSET_WHITELIST6 0 $ispip6
			echolog "  - [$?]追加ISP IPv6 DNS到白名单：${ispip6}"
		done
	}

	#  过滤所有节点IP
	filter_vpsip > /dev/null 2>&1 &
	# filter_haproxy > /dev/null 2>&1 &
	# Prevent some conditions
	filter_vps_addr $(config_n_get $TCP_NODE address) $(config_n_get $UDP_NODE address) > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
		nft_prerouting_chain="PSW_NAT"
		nft_output_chain="PSW_OUTPUT_NAT"
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
		nft_prerouting_chain="PSW_MANGLE"
		nft_output_chain="PSW_OUTPUT_MANGLE"
	fi

	nft "add chain $NFTABLE_NAME PSW_DIVERT"
	nft "flush chain $NFTABLE_NAME PSW_DIVERT"
	nft "add rule $NFTABLE_NAME PSW_DIVERT meta l4proto tcp socket transparent 1 mark set 1 counter accept"

	nft "add chain $NFTABLE_NAME PSW_REDIRECT"
	nft "flush chain $NFTABLE_NAME PSW_REDIRECT"
	nft "add rule $NFTABLE_NAME dstnat jump PSW_REDIRECT"

	# for ipv4 ipv6 tproxy mark
	nft "add chain $NFTABLE_NAME PSW_RULE"
	nft "flush chain $NFTABLE_NAME PSW_RULE"
	nft "add rule $NFTABLE_NAME PSW_RULE meta mark set ct mark counter"
	nft "add rule $NFTABLE_NAME PSW_RULE meta mark 1 counter return"
	nft "add rule $NFTABLE_NAME PSW_RULE tcp flags &(fin|syn|rst|ack) == syn meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW_RULE meta l4proto udp ct state new meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule $NFTABLE_NAME PSW_RULE ct mark set mark counter"

	#ipv4 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW_MANGLE"
	nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr @$NFTSET_VPSLIST counter return"

	nft "add chain $NFTABLE_NAME PSW_OUTPUT_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW_OUTPUT_MANGLE"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_VPSLIST counter return"

	[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_WHITELIST counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta mark 0xff counter return"
	[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip daddr @$NFTSET_BLOCKLIST counter drop"

	# jump chains
	nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol udp counter jump PSW_MANGLE"
	[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME mangle_prerouting ip protocol tcp counter jump PSW_MANGLE"
	insert_rule_before "$NFTABLE_NAME" "mangle_prerouting" "PSW_MANGLE" "counter jump PSW_DIVERT"

	#ipv4 tcp redirect mode
	[ -z "${is_tproxy}" ] && {
		nft "add chain $NFTABLE_NAME PSW_NAT"
		nft "flush chain $NFTABLE_NAME PSW_NAT"
		nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW_NAT ip daddr @$NFTSET_VPSLIST counter return"
		nft "add rule $NFTABLE_NAME dstnat ip protocol tcp counter jump PSW_NAT"

		nft "add chain $NFTABLE_NAME PSW_OUTPUT_NAT"
		nft "flush chain $NFTABLE_NAME PSW_OUTPUT_NAT"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_VPSLIST counter return"
		[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_WHITELIST counter return"
		nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT meta mark 0xff counter return"
		[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip daddr @$NFTSET_BLOCKLIST counter drop"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain $NFTABLE_NAME PSW_ICMP_REDIRECT"
		nft "flush chain $NFTABLE_NAME PSW_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip daddr @$NFTSET_VPSLIST counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_LANLIST6 counter return"
			nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_VPSLIST6 counter return"
		}

		nft "add rule $NFTABLE_NAME dstnat meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME nat_output meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
	fi

	WAN_IP=$(get_wan_ip)
	if [ -n "${WAN_IP}" ]; then
		[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW_NAT ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\""
		nft "add rule $NFTABLE_NAME PSW_MANGLE ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\""
		echolog "  - [$?]追加WAN IP到nftables：${WAN_IP}"
	fi
	unset WAN_IP

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	#ipv6 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"

	nft "add chain $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
	[ "${USE_DIRECT_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_WHITELIST6 counter return"
	nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta mark 0xff counter return"
	[ "${USE_BLOCK_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_BLOCKLIST6 counter drop"

	[ -n "$IPT_APPEND_DNS" ] && {
		local local_dns dns_address dns_port
		for local_dns in $(echo $IPT_APPEND_DNS | tr ',' ' '); do
			dns_address=$(echo "$local_dns" | sed -E 's/(@|\[)?([0-9a-fA-F:.]+)(@|#|$).*/\2/')
			dns_port=$(echo "$local_dns" | sed -nE 's/.*#([0-9]+)$/\1/p')
			if echo "$dns_address" | grep -q -v ':'; then
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr ${dns_address} $(factor ${dns_port:-53} "udp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr ${dns_address} $(factor ${dns_port:-53} "tcp dport") counter return"
				echolog "  - [$?]追加直连DNS到nftables：${dns_address}:${dns_port:-53}"
			else
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr ${dns_address} $(factor ${dns_port:-53} "udp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr ${dns_address} $(factor ${dns_port:-53} "tcp dport") counter return"
				echolog "  - [$?]追加直连DNS到nftables：[${dns_address}]:${dns_port:-53}"
			fi
		done
	}

	# jump chains
	[ "$PROXY_IPV6" == "1" ] && {
		nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto {ipv6} counter jump PSW_MANGLE_V6"
		nft "add rule $NFTABLE_NAME mangle_output meta nfproto {ipv6} counter jump PSW_OUTPUT_MANGLE_V6 comment \"PSW_OUTPUT_MANGLE\""

		WAN6_IP=$(get_wan6_ip)
		[ -n "${WAN6_IP}" ] && nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ip6 daddr ${WAN6_IP} counter return comment \"WAN6_IP_RETURN\""
		unset WAN6_IP

		ip -6 rule add fwmark 1 table 100
		ip -6 route add local ::/0 dev lo table 100
	}
	
	[ "$TCP_UDP" = "1" ] && [ "$UDP_NODE" = "nil" ] && UDP_NODE=$TCP_NODE
	
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

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		# 处理轮换节点的分流或套娃
		local node port stream switch
		for stream in TCP UDP; do
			eval "node=\${${stream}_NODE}"
			eval "port=\${${stream}_REDIR_PORT}"
			#echolog "分析 $stream 代理自动切换..."
			[ "$stream" == "UDP" ] && [ "$node" == "tcp" ] && {
				eval "node=\${TCP_NODE}"
				eval "port=\${TCP_REDIR_PORT}"
			}
			if [ "$node" != "nil" ] && [ "$(config_get_type $node nil)" != "nil" ]; then
				filter_node $node $stream $port > /dev/null 2>&1 &
			fi
		done
		
		msg="【路由器本机】，"
		
		[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
			if [ "$TCP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 TCP 端口[${TCP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_TCP_PROXY_MODE
				echolog "  - ${msg}不代理所有 TCP 端口"
			fi
		}
		
		[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return"
			if [ "$UDP_NO_REDIR_PORTS" != "1:65535" ]; then
				echolog "  - ${msg}不代理 UDP 端口[${UDP_NO_REDIR_PORTS}]"
			else
				unset LOCALHOST_UDP_PROXY_MODE
				echolog "  - ${msg}不代理所有 UDP 端口"
			fi
		}
		
		[ -n "${LOCALHOST_TCP_PROXY_MODE}" -o -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
				nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr $FAKE_IP $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_SHUNTLIST $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${USE_PROXY_LIST}" = "1" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_BLACKLIST $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${USE_GFW_LIST}" = "1" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_GFW $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "${CHN_LIST}" != "0" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp ip daddr @$NFTSET_CHN $(factor $TCP_PROXY_DROP_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "counter drop")
				[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				echolog "  - ${msg}屏蔽代理 TCP 端口[${TCP_PROXY_DROP_PORTS}]"
			}
			
			[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
				nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNTLIST $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${USE_PROXY_LIST}" = "1" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACKLIST $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${USE_GFW_LIST}" = "1" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_GFW $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				[ "${CHN_LIST}" != "0" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_CHN $(factor $UDP_PROXY_DROP_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter drop")
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE counter ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
				echolog "  - ${msg}屏蔽代理 UDP 端口[${UDP_PROXY_DROP_PORTS}]"
			}
		}

		# 加载路由器自身代理 TCP
		if [ "$TCP_NODE" != "nil" ]; then
			_proxy_tcp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					nft "get element $NFTABLE_NAME $NFTSET_LANLIST {${2}}" &>/dev/null
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					if [ -z "${is_tproxy}" ]; then
						nft insert rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp ip daddr ${2} tcp dport ${3} $(REDIRECT $TCP_REDIR_PORT)
					else
						nft insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr ${2} tcp dport ${3} counter jump PSW_RULE
						nft insert rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo tcp dport ${3} ip daddr ${2} $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"本机\"
					fi
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 TCP 转发链"
				else
					nft "get element $NFTABLE_NAME $NFTSET_LANLIST6 {${2}}" &>/dev/null
					[ $? -eq 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 TCP 代理转发对该服务器 TCP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr ${2} tcp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo tcp dport ${3} ip6 daddr ${2} $(REDIRECT $TCP_REDIR_PORT TPROXY6) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 TCP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ "$use_tcp_node_resolve_dns" == 1 ] && hosts_foreach REMOTE_DNS _proxy_tcp_access 53

			[ "$accept_icmp" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_SHUNTLIST counter redirect"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_BLACKLIST counter redirect"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_GFW counter redirect"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST})"
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp counter redirect"
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo ip protocol icmp counter return"
			}

			[ "$accept_icmpv6" = "1" ] && {
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNTLIST6 counter redirect"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACKLIST6 counter redirect"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_GFW6 counter redirect"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_CHN6 $(get_jump_ipt ${CHN_LIST})"
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && [ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter redirect"
				nft "add rule $NFTABLE_NAME PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter return"
			}

			if [ -z "${is_tproxy}" ]; then
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp ip daddr $FAKE_IP $(REDIRECT $TCP_REDIR_PORT)"
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter $(REDIRECT $TCP_REDIR_PORT)"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter $(REDIRECT $TCP_REDIR_PORT)"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_GFW counter $(REDIRECT $TCP_REDIR_PORT)"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_CHN $(get_jump_ipt ${CHN_LIST} $TCP_REDIR_PORT)"
					[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter $(REDIRECT $TCP_REDIR_PORT)"
				}
				nft "add rule $NFTABLE_NAME nat_output ip protocol tcp counter jump PSW_OUTPUT_NAT"
			else
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr $FAKE_IP counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_SHUNTLIST $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_BLACKLIST $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_GFW $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_CHN $(factor $TCP_REDIR_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
					[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"本机\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol tcp iif lo counter return comment \"本机\""
				nft "add rule $NFTABLE_NAME mangle_output ip protocol tcp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
			fi

			[ "$PROXY_IPV6" == "1" ] && {
				[ -n "${LOCALHOST_TCP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_SHUNTLIST6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_BLACKLIST6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_GFW6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_CHN6 $(factor $TCP_REDIR_PORTS "tcp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
					[ "${LOCALHOST_TCP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"本机\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"本机\""
			}
		fi

		# 加载路由器自身代理 UDP
		if [ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ]; then
			_proxy_udp_access() {
				[ -n "${2}" ] || return 0
				if echo "${2}" | grep -q -v ':'; then
					nft "get element $NFTABLE_NAME $NFTSET_LANLIST {${2}}" &>/dev/null
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr ${2} udp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo ip daddr ${2} $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 ${2}:${3} 加入到路由器自身代理的 UDP 转发链"
				else
					nft "get element $NFTABLE_NAME $NFTSET_LANLIST6 {${2}}" &>/dev/null
					[ $? == 0 ] && {
						echolog "  - 上游 DNS 服务器 ${2} 已在直接访问的列表中，不强制向 UDP 代理转发对该服务器 UDP/${3} 端口的访问"
						return 0
					}
					nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr ${2} udp dport ${3} counter jump PSW_RULE"
					nft "insert rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto tcp iif lo ip6 daddr ${2} $(REDIRECT $UDP_REDIR_PORT TPROXY6) comment \"本机\""
					echolog "  - [$?]将上游 DNS 服务器 [${2}]:${3} 加入到路由器自身代理的 UDP 转发链，请确保您的节点支持IPv6，并开启IPv6透明代理！"
				fi
			}
			[ "$use_udp_node_resolve_dns" == 1 ] && hosts_foreach REMOTE_DNS _proxy_udp_access 53
			[ -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE"
				nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNTLIST $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACKLIST $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_GFW $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_CHN $(factor $UDP_REDIR_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
				[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"本机\""
			}
			nft "add rule $NFTABLE_NAME PSW_MANGLE ip protocol udp iif lo counter return comment \"本机\""
			nft "add rule $NFTABLE_NAME mangle_output ip protocol udp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""

			[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
				[ -n "${LOCALHOST_UDP_PROXY_MODE}" ] && {
					nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_SHUNTLIST6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${USE_PROXY_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_BLACKLIST6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${USE_GFW_LIST}" = "1" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_GFW6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "${CHN_LIST}" != "0" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_CHN6 $(factor $UDP_REDIR_PORTS "udp dport") $(get_jump_ipt ${CHN_LIST} "counter jump PSW_RULE")"
					[ "${LOCALHOST_UDP_PROXY_MODE}" != "disable" ] && nft "add rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"本机\""
				}
				nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto udp iif lo counter return comment \"本机\""
			}
		fi

		nft "add rule $NFTABLE_NAME mangle_output oif lo counter return comment \"PSW_OUTPUT_MANGLE\""
		nft "add rule $NFTABLE_NAME mangle_output meta mark 1 counter return comment \"PSW_OUTPUT_MANGLE\""

		dns_hijack
	}

	#  加载ACLS
	load_acl

	for iface in $(ls ${TMP_IFACE_PATH}); do
		nft "insert rule $NFTABLE_NAME $nft_output_chain oif $iface counter return"
		nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE_V6 oif $iface counter return"
	done

	[ -n "${is_tproxy}" -o -n "${udp_flag}" ] && {
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		echo -n $bridge_nf_ipt > $TMP_PATH/bridge_nf_ipt
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			echo -n $bridge_nf_ip6t > $TMP_PATH/bridge_nf_ip6t
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	}
	echolog "防火墙规则加载完成！"
}

del_firewall_rule() {
	for nft in "dstnat" "srcnat" "nat_output" "mangle_prerouting" "mangle_output"; do
        local handles=$(nft -a list chain $NFTABLE_NAME ${nft} 2>/dev/null | grep -E "PSW_" | awk -F '# handle ' '{print$2}')
		for handle in $handles; do
			nft delete rule $NFTABLE_NAME ${nft} handle ${handle} 2>/dev/null
		done
	done

	for handle in $(nft -a list chains | grep -E "chain PSW_" | grep -v "PSW_RULE" | awk -F '# handle ' '{print$2}'); do
		nft delete chain $NFTABLE_NAME handle ${handle} 2>/dev/null
	done

	# Need to be removed at the end, otherwise it will show "Resource busy"
	nft delete chain $NFTABLE_NAME handle $(nft -a list chains | grep -E "PSW_RULE" | awk -F '# handle ' '{print$2}') 2>/dev/null

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_nftset $NFTSET_LANLIST
	destroy_nftset $NFTSET_VPSLIST
	#destroy_nftset $NFTSET_SHUNTLIST
	#destroy_nftset $NFTSET_GFW
	#destroy_nftset $NFTSET_CHN
	#destroy_nftset $NFTSET_BLACKLIST
	destroy_nftset $NFTSET_BLOCKLIST
	destroy_nftset $NFTSET_WHITELIST

	destroy_nftset $NFTSET_LANLIST6
	destroy_nftset $NFTSET_VPSLIST6
	#destroy_nftset $NFTSET_SHUNTLIST6
	#destroy_nftset $NFTSET_GFW6
	#destroy_nftset $NFTSET_CHN6
	#destroy_nftset $NFTSET_BLACKLIST6
	destroy_nftset $NFTSET_BLOCKLIST6
	destroy_nftset $NFTSET_WHITELIST6

	$DIR/app.sh echolog "删除nftables防火墙规则完成。"
}

flush_nftset() {
	$DIR/app.sh echolog "清空 NFTSET。"
	for _name in $(nft -a list sets | grep -E "passwall" | awk -F 'set ' '{print $2}' | awk '{print $1}'); do
		destroy_nftset ${_name}
	done
}

flush_table() {
	nft flush table $NFTABLE_NAME
	nft delete table $NFTABLE_NAME
}

flush_nftset_reload() {
	del_firewall_rule
	flush_table
	rm -rf /tmp/singbox_passwall*
	rm -rf /tmp/etc/passwall_tmp/dnsmasq*
	/etc/init.d/passwall reload
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	local nft_chain_file=$TMP_PATH/PSW_RULE.nft
	echo '#!/usr/sbin/nft -f' > $nft_chain_file
	nft list table $NFTABLE_NAME >> $nft_chain_file

	local __nft=" "
	__nft=$(cat <<- EOF
		[ -z "\$(nft list chain $NFTABLE_NAME mangle_prerouting | grep PSW_DIVERT)" ] && nft -f ${nft_chain_file}
		[ -z "${is_tproxy}" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW_NAT WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW_NAT handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
			fi
		}

		PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW_MANGLE WAN_IP_RETURN -1)
		if [ \$PR_INDEX -ge 0 ]; then
			WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
			[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW_MANGLE handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
		fi

		[ "$PROXY_IPV6" == "1" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "$NFTABLE_NAME" PSW_MANGLE_V6 WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(sh ${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule $NFTABLE_NAME PSW_MANGLE_V6 handle \$PR_INDEX ip6 daddr "\${WAN6_IP}" counter return comment \"WAN6_IP_RETURN\""
			fi
		}
	EOF
	)

	cat <<-EOF >> $FWI
	${__nft}
	EOF
	return 0
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
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
flush_nftset)
	flush_nftset
	;;
flush_nftset_reload)
	flush_nftset_reload
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
