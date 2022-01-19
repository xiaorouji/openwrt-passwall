#!/bin/sh

restart() {
	local no_log
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$no_log" ] && LOG_FILE="/dev/null"
	rm -rf /tmp/smartdns.cache
	/etc/init.d/smartdns reload >/dev/null 2>&1
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	LOG_FILE=${_LOG_FILE}
}

gen_items() {
	local ipsets group address speed_check_mode outf
	eval_set_val $@

	awk -v ipsets="${ipsets}" -v group="${group}" -v speed_check_mode="${speed_check_mode}" -v address="${address}" -v outf="${outf}" '
		BEGIN {
			if(outf == "") outf="/dev/stdout";
			if(group != "") group=" -n " group;
			if(ipsets != "") ipsets=" -p " ipsets;
			if(speed_check_mode != "") speed_check_mode=" -c " speed_check_mode;
			if(address != "") address=" -a " address;
			fail=1;
		}
		! /^$/&&!/^#/ {
			fail=0
			printf("domain-rules /%s/ %s%s%s%s\n", $0, group, ipsets, address, speed_check_mode) >>outf;
		}
		END {fflush(outf); close(outf); exit(fail);}
	'
}

gen_address_items() {
	local address=${1}; shift 1
	local outf=${1}; shift 1

	awk -v address="${address}" -v outf="${outf}" '
		BEGIN {
			if(outf == "") outf="/dev/stdout";
			setaddress=length(address)>0;
			fail=1;
		}
		! /^$/&&!/^#/ {
			fail=0
			if(setaddress) printf("address /%s/%s\n", $0, address) >>outf;
		}
		END {fflush(outf); close(outf); exit(fail);}
	'
}

add() {
	local fwd_dns fwd_group item servers msg
	local DNS_MODE SMARTDNS_CONF DNSMASQ_CONF_FILE DEFAULT_DNS LOCAL_GROUP REMOTE_GROUP TUN_DNS TCP_NODE PROXY_MODE NO_LOGIC_LOG NO_PROXY_IPV6
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$NO_LOGIC_LOG" ] && LOG_FILE="/dev/null"
	global=$(echo "${PROXY_MODE}" | grep "global")
	returnhome=$(echo "${PROXY_MODE}" | grep "returnhome")
	chnlist=$(echo "${PROXY_MODE}" | grep "chnroute")
	gfwlist=$(echo "${PROXY_MODE}" | grep "gfwlist")
	touch ${SMARTDNS_CONF}
	count_hosts_str="!"
	[ -z "${REMOTE_GROUP}" ] && {
		REMOTE_GROUP="${CONFIG}_proxy"
		[ -n "${TUN_DNS}" ] && TUN_DNS="$(echo ${TUN_DNS} | sed 's/#/:/g')"
		echo "server ${TUN_DNS}  -group ${REMOTE_GROUP} -exclude-default-group" >> ${SMARTDNS_CONF}
	}

	#屏蔽列表
	[ -s "${RULES_PATH}/block_host" ] && {
		cat "${RULES_PATH}/block_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_address_items "-" "${SMARTDNS_CONF}"
	}

	#始终用国内DNS解析节点域名
	servers=$(uci show "${CONFIG}" | grep ".address=" | cut -d "'" -f 2)
	hosts_foreach "servers" host_from_url | grep '[a-zA-Z]$' | sort -u | gen_items ipsets="#4:vpsiplist,#6:vpsiplist6" group="${LOCAL_GROUP}" outf="${SMARTDNS_CONF}"
	echolog "  - [$?]节点列表中的域名(vpsiplist)使用分组：${LOCAL_GROUP}"

	#始终用国内DNS解析直连（白名单）列表
	[ -s "${RULES_PATH}/direct_host" ] && {
		cat "${RULES_PATH}/direct_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_items ipsets="#4:whitelist,#6:whitelist6" group="${LOCAL_GROUP}" outf="${SMARTDNS_CONF}"
		echolog "  - [$?]域名白名单(whitelist)使用分组：${LOCAL_GROUP}"
	}
	
	subscribe_list=""
	for item in $(get_enabled_anonymous_secs "@subscribe_list"); do
		host=$(host_from_url "$(config_n_get ${item} url)")
		subscribe_list="${subscribe_list}\n${host}"
	done
	[ -n "$subscribe_list" ] && {
		if [ "$(config_t_get global_subscribe subscribe_proxy 0)" = "0" ]; then
			#如果没有开启通过代理订阅
			echo -e "$subscribe_list" | sort -u | gen_items ipsets="#4:whitelist,#6:whitelist6" group="${LOCAL_GROUP}" outf="${SMARTDNS_CONF}"
			echolog "  - [$?]节点订阅域名(whitelist)使用分组：${LOCAL_GROUP}"
		else
			#如果开启了通过代理订阅
			echo -e "$subscribe_list" | sort -u | gen_items ipsets="blacklist,blacklist6" group="${REMOTE_GROUP}" speed_check_mode="none" outf="${SMARTDNS_CONF}"
			echolog "  - [$?]节点订阅域名(blacklist)使用分组：${REMOTE_GROUP}"
		fi
	}
	
	#始终使用远程DNS解析代理（黑名单）列表
	[ -s "${RULES_PATH}/proxy_host" ] && {
		local ipset_flag="#4:blacklist,#6:blacklist6"
		if [ "${NO_PROXY_IPV6}" = "1" ]; then
			ipset_flag="#4:blacklist"
			address="#6"
		fi
		cat "${RULES_PATH}/proxy_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_items ipsets="${ipset_flag}" group="${REMOTE_GROUP}" address="${address}" speed_check_mode="none" outf="${SMARTDNS_CONF}"
		echolog "  - [$?]代理域名表(blacklist)使用分组：${REMOTE_GROUP}"
	}

	#分流规则
	[ "$(config_n_get $TCP_NODE protocol)" = "_shunt" ] && {
		local default_node_id=$(config_n_get $TCP_NODE default_node _direct)
		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			local shunt_node_id=$(config_n_get $TCP_NODE ${shunt_id} nil)
			[ "$shunt_node_id" = "nil" ] && continue
			[ "$shunt_node_id" = "_default" ] && shunt_node_id=$default_node_id
			[ "$shunt_node_id" = "_blackhole" ] && continue
			local str=$(echo -n $(config_n_get $shunt_id domain_list | grep -v 'regexp:\|geosite:\|ext:' | sed 's/domain:\|full:\|//g' | tr -s "\r\n" "\n" | sort -u) | sed "s/ /|/g")
			[ -n "$str" ] && count_hosts_str="${count_hosts_str}|${str}"
			[ "$shunt_node_id" = "_direct" ] && {
				[ -n "$str" ] && echo $str | sed "s/|/\n/g" | gen_items ipsets="#4:whitelist,#6:whitelist6" group="${LOCAL_GROUP}" outf="${SMARTDNS_CONF}"
				msg_dns="${LOCAL_GROUP}"
				continue
			}
			local shunt_node=$(config_n_get $shunt_node_id address nil)
			[ "$shunt_node" = "nil" ] && continue

			local ipset_flag="#4:shuntlist,#6:shuntlist6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="#4:shuntlist"
				address="#6"
			fi
			[ -n "$str" ] && {
				echo $str | sed "s/|/\n/g" | gen_items ipsets="${ipset_flag}" group="${REMOTE_GROUP}" address="${address}" speed_check_mode="none" outf="${SMARTDNS_CONF}"
				msg_dns="${REMOTE_GROUP}"
			}
		done
		echolog "  - [$?]V2ray/Xray分流规则(shuntlist)：${msg_dns:-默认}"
	}
	
	[ -s "${RULES_PATH}/direct_host" ] && direct_hosts_str="$(echo -n $(cat ${RULES_PATH}/direct_host | tr -s '\n' | grep -v "^#" | sort -u) | sed "s/ /|/g")"
	[ -s "${RULES_PATH}/proxy_host" ] && proxy_hosts_str="$(echo -n $(cat ${RULES_PATH}/proxy_host | tr -s '\n' | grep -v "^#" | sort -u) | sed "s/ /|/g")"
	[ -n "$direct_hosts_str" ] && count_hosts_str="${count_hosts_str}|${direct_hosts_str}"
	[ -n "$proxy_hosts_str" ] && count_hosts_str="${count_hosts_str}|${proxy_hosts_str}"

	#如果没有使用回国模式
	if [ -z "${returnhome}" ]; then
		# GFW 模式
		[ -s "${RULES_PATH}/gfwlist" ] && {
			grep -v -E "$count_hosts_str" "${RULES_PATH}/gfwlist" > "${TMP_PATH}/gfwlist"
			
			local ipset_flag="#4:gfwlist,#6:gfwlist6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="#4:gfwlist"
				address="#6"
			fi
			sort -u "${TMP_PATH}/gfwlist" | gen_items ipsets="${ipset_flag}" group="${REMOTE_GROUP}" address="${address}" speed_check_mode="none" outf="${SMARTDNS_CONF}"
			echolog "  - [$?]防火墙域名表(gfwlist)使用分组：${REMOTE_GROUP}"
			rm -f "${TMP_PATH}/gfwlist"
		}
		
		# 中国列表以外 模式
		[ -s "${RULES_PATH}/chnlist" ] && [ -n "${chnlist}" ] && {
			grep -v -E "$count_hosts_str" "${RULES_PATH}/chnlist" | gen_items ipsets="#4:chnroute,#6:chnroute6" group="${LOCAL_GROUP}" outf="${SMARTDNS_CONF}"
			echolog "  - [$?]中国域名表(chnroute)使用分组：${LOCAL_GROUP}"
		}
	else
		#回国模式
		[ -s "${RULES_PATH}/chnlist" ] && {
			grep -v -E "$count_hosts_str" "${RULES_PATH}/chnlist" > "${TMP_PATH}/chnlist"
			
			local ipset_flag="#4:chnroute,#6:chnroute6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="#4:chnroute"
				address="#6"
			fi
			sort -u "${TMP_PATH}/chnlist" | gen_items ipsets="#4:chnroute,#6:chnroute6" group="${REMOTE_GROUP}" address="${address}" speed_check_mode="none" outf="${SMARTDNS_CONF}"
			echolog "  - [$?]中国域名表(chnroute)使用分组：${REMOTE_GROUP}"
			rm -f "${TMP_PATH}/chnlist"
		}
	fi
	
	echo "conf-file ${SMARTDNS_CONF}" >> /etc/smartdns/custom.conf
	echolog "  - 请让SmartDNS作为Dnsmasq的上游或重定向！"
	LOG_FILE=${_LOG_FILE}
}

del() {
	rm -rf /tmp/etc/smartdns/passwall.conf
	sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1
	rm -rf /tmp/smartdns.cache
	/etc/init.d/smartdns reload
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
