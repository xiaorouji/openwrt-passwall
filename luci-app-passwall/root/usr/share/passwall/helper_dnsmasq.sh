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

gen_items() {
	local ipsets dnss outf ipsetoutf
	eval_set_val $@
	
	awk -v ipsets="${ipsets}" -v dnss="${dnss}" -v outf="${outf}" -v ipsetoutf="${ipsetoutf}" '
		BEGIN {
			if(outf == "") outf="/dev/stdout";
			if(ipsetoutf == "") ipsetoutf=outf;
			split(dnss, dns, ","); setdns=length(dns)>0; setlist=length(ipsets)>0;
			if(setdns) for(i in dns) if(length(dns[i])==0) delete dns[i];
			fail=1;
		}
		! /^$/&&!/^#/ {
			fail=0
			if(setdns) for(i in dns) printf("server=/.%s/%s\n", $0, dns[i]) >>outf;
			if(setlist) printf("ipset=/.%s/%s\n", $0, ipsets) >>ipsetoutf;
		}
		END {fflush(outf); close(outf); fflush(ipsetoutf); close(ipsetoutf); exit(fail);}
	'
}

gen_address_items() {
	local address=${1}; shift 1
	local outf=${1}; shift 1

	awk -v address="${address}" -v outf="${outf}" '
		BEGIN {
			if(outf == "") outf="/dev/stdout";
			if(address == "") address="0.0.0.0,::";
			split(address, ad, ","); setad=length(ad)>0;
			if(setad) for(i in ad) if(length(ad[i])==0) delete ad[i];
			fail=1;
		}
		! /^$/&&!/^#/ {
			fail=0
			if(setad) for(i in ad) printf("address=/.%s/%s\n", $0, ad[i]) >>outf;
		}
		END {fflush(outf); close(outf); exit(fail);}
	'
}

ipset_merge() {
	awk '{gsub(/ipset=\//,""); gsub(/\//," ");key=$1;value=$2;if (sum[key] != "") {sum[key]=sum[key]","value} else {sum[key]=sum[key]value}} END{for(i in sum) print "ipset=/"i"/"sum[i]}' "${1}/ipset.conf" > "${1}/ipset.conf2"
	mv -f "${1}/ipset.conf2" "${1}/ipset.conf"
}

add() {
	local fwd_dns item servers msg
	local DNS_MODE TMP_DNSMASQ_PATH DNSMASQ_CONF_FILE DEFAULT_DNS LOCAL_DNS TUN_DNS REMOTE_FAKEDNS CHINADNS_DNS TCP_NODE PROXY_MODE NO_LOGIC_LOG NO_PROXY_IPV6
	eval_set_val $@
	_LOG_FILE=$LOG_FILE
	[ -n "$NO_LOGIC_LOG" ] && LOG_FILE="/dev/null"
	global=$(echo "${PROXY_MODE}" | grep "global")
	returnhome=$(echo "${PROXY_MODE}" | grep "returnhome")
	chnlist=$(echo "${PROXY_MODE}" | grep "chnroute")
	gfwlist=$(echo "${PROXY_MODE}" | grep "gfwlist")
	mkdir -p "${TMP_DNSMASQ_PATH}" "${DNSMASQ_PATH}" "/tmp/dnsmasq.d"
	count_hosts_str="!"

	#屏蔽列表
	[ -s "${RULES_PATH}/block_host" ] && {
		cat "${RULES_PATH}/block_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_address_items address="0.0.0.0" outf="${TMP_DNSMASQ_PATH}/00-block_host.conf"
	}

	#始终用国内DNS解析节点域名
	fwd_dns="${LOCAL_DNS}"
	servers=$(uci show "${CONFIG}" | grep ".address=" | cut -d "'" -f 2)
	hosts_foreach "servers" host_from_url | grep '[a-zA-Z]$' | sort -u | gen_items ipsets="vpsiplist,vpsiplist6" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/10-vpsiplist_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
	echolog "  - [$?]节点列表中的域名(vpsiplist)：${fwd_dns:-默认}"

	#始终用国内DNS解析直连（白名单）列表
	[ -s "${RULES_PATH}/direct_host" ] && {
		fwd_dns="${LOCAL_DNS}"
		#[ -n "$CHINADNS_DNS" ] && unset fwd_dns
		cat "${RULES_PATH}/direct_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_items ipsets="whitelist,whitelist6" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/11-direct_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
		echolog "  - [$?]域名白名单(whitelist)：${fwd_dns:-默认}"
	}
	
	subscribe_list=""
	for item in $(get_enabled_anonymous_secs "@subscribe_list"); do
		host=$(host_from_url "$(config_n_get ${item} url)")
		subscribe_list="${subscribe_list}\n${host}"
	done
	[ -n "$subscribe_list" ] && {
		if [ "$(config_t_get global_subscribe subscribe_proxy 0)" = "0" ]; then
			#如果没有开启通过代理订阅
			fwd_dns="${LOCAL_DNS}"
			echo -e "$subscribe_list" | sort -u | gen_items ipsets="whitelist,whitelist6" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/12-subscribe.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
			echolog "  - [$?]节点订阅域名(whitelist)：${fwd_dns:-默认}"
		else
			#如果开启了通过代理订阅
			fwd_dns="${TUN_DNS}"
			local ipset_flag="blacklist,blacklist6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="blacklist"
				echo -e "$subscribe_list" | sort -u | gen_address_items address="::" outf="${TMP_DNSMASQ_PATH}/91-subscribe-noipv6.conf"
			fi
			[ -n "${REMOTE_FAKEDNS}" ] && unset ipset_flag
			echo -e "$subscribe_list" | sort -u | gen_items ipsets="${ipset_flag}" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/91-subscribe.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
			echolog "  - [$?]节点订阅域名(blacklist)：${fwd_dns:-默认}"
		fi
	}
	
	#始终使用远程DNS解析代理（黑名单）列表
	[ -s "${RULES_PATH}/proxy_host" ] && {
		local ipset_flag="blacklist,blacklist6"
		if [ "${NO_PROXY_IPV6}" = "1" ]; then
			ipset_flag="blacklist"
			cat "${RULES_PATH}/proxy_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_address_items address="::" outf="${TMP_DNSMASQ_PATH}/97-proxy_host-noipv6.conf"
		fi
		fwd_dns="${TUN_DNS}"
		[ -n "${REMOTE_FAKEDNS}" ] && unset ipset_flag
		cat "${RULES_PATH}/proxy_host" | tr -s '\n' | grep -v "^#" | sort -u | gen_items ipsets="${ipset_flag}" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/97-proxy_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
		echolog "  - [$?]代理域名表(blacklist)：${fwd_dns:-默认}"
	}

	#分流规则
	[ "$(config_n_get $TCP_NODE protocol)" = "_shunt" ] && {
		fwd_dns="${TUN_DNS}"
		msg_dns="${fwd_dns}"
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
				[ -n "$str" ] && echo $str | sed "s/|/\n/g" | gen_items ipsets="whitelist,whitelist6" "${LOCAL_DNS}" "${TMP_DNSMASQ_PATH}/13-shunt_host.conf"
				msg_dns="${LOCAL_DNS}"
				continue
			}
			local shunt_node=$(config_n_get $shunt_node_id address nil)
			[ "$shunt_node" = "nil" ] && continue

			[ -n "$str" ] && {
				local ipset_flag="shuntlist,shuntlist6"
				if [ "${NO_PROXY_IPV6}" = "1" ]; then
					ipset_flag="shuntlist"
					echo $str | sed "s/|/\n/g" | gen_address_items address="::" outf="${TMP_DNSMASQ_PATH}/98-shunt_host-noipv6.conf"
				fi
				[ -n "${REMOTE_FAKEDNS}" ] && unset ipset_flag
				echo $str | sed "s/|/\n/g" | gen_items ipsets="${ipset_flag}" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/98-shunt_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
				msg_dns="${fwd_dns}"
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
			
			local ipset_flag="gfwlist,gfwlist6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="gfwlist"
				sort -u "${TMP_PATH}/gfwlist" | gen_address_items address="::" outf="${TMP_DNSMASQ_PATH}/99-gfwlist-noipv6.conf"
			fi
			fwd_dns="${TUN_DNS}"
			[ -n "$CHINADNS_DNS" ] && unset fwd_dns
			[ -n "${REMOTE_FAKEDNS}" ] && unset ipset_flag
			sort -u "${TMP_PATH}/gfwlist" | gen_items ipsets="${ipset_flag}" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/99-gfwlist.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
			echolog "  - [$?]防火墙域名表(gfwlist)：${fwd_dns:-默认}"
			rm -f "${TMP_PATH}/gfwlist"
		}
		
		# 中国列表以外 模式
		[ -n "${CHINADNS_DNS}" ] && {
			fwd_dns="${LOCAL_DNS}"
			[ -n "$CHINADNS_DNS" ] && unset fwd_dns
			[ -s "${RULES_PATH}/chnlist" ] && {
				grep -v -E "$count_hosts_str" "${RULES_PATH}/chnlist" | gen_items ipsets="chnroute,chnroute6" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/19-chinalist_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
				echolog "  - [$?]中国域名表(chnroute)：${fwd_dns:-默认}"
			}
		}
	else
		#回国模式
		[ -s "${RULES_PATH}/chnlist" ] && {
			grep -v -E "$count_hosts_str" "${RULES_PATH}/chnlist" > "${TMP_PATH}/chnlist"
			
			local ipset_flag="chnroute,chnroute6"
			if [ "${NO_PROXY_IPV6}" = "1" ]; then
				ipset_flag="chnroute"
				sort -u "${TMP_PATH}/chnlist" | gen_address_items address="::" outf="${TMP_DNSMASQ_PATH}/99-chinalist_host-noipv6.conf"
			fi
			fwd_dns="${TUN_DNS}"
			[ -n "${REMOTE_FAKEDNS}" ] && unset ipset_flag
			sort -u "${TMP_PATH}/chnlist" | gen_items ipsets="${ipset_flag}" dnss="${fwd_dns}" outf="${TMP_DNSMASQ_PATH}/99-chinalist_host.conf" ipsetoutf="${TMP_DNSMASQ_PATH}/ipset.conf"
			echolog "  - [$?]中国域名表(chnroute)：${fwd_dns:-默认}"
			rm -f "${TMP_PATH}/chnlist"
		}
	fi
	
	ipset_merge ${TMP_DNSMASQ_PATH}
	
	echo "conf-dir=${TMP_DNSMASQ_PATH}" > $DNSMASQ_CONF_FILE
	[ -n "${CHINADNS_DNS}" ] && {
		echo "${DEFAULT_DNS}" > $TMP_PATH/default_DNS
		cat <<-EOF >> $DNSMASQ_CONF_FILE
			server=${CHINADNS_DNS}
			all-servers
			no-poll
			no-resolv
		EOF
		echolog "  - [$?]以上所列以外及默认(ChinaDNS-NG)：${CHINADNS_DNS}"
	}
	echolog "  - PassWall必须依赖于Dnsmasq，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！"
	LOG_FILE=${_LOG_FILE}
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
