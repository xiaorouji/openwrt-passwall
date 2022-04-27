#!/bin/sh
# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2022 xiaorouji

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall
TMP_PATH=/tmp/etc/$CONFIG
TMP_BIN_PATH=$TMP_PATH/bin
TMP_SCRIPT_FUNC_PATH=$TMP_PATH/script_func
TMP_ID_PATH=$TMP_PATH/id
TMP_PORT_PATH=$TMP_PATH/port
TMP_ROUTE_PATH=$TMP_PATH/route
TMP_ACL_PATH=$TMP_PATH/acl
TMP_PATH2=/tmp/etc/${CONFIG}_tmp
DNSMASQ_PATH=/etc/dnsmasq.d
TMP_DNSMASQ_PATH=/tmp/dnsmasq.d/passwall
LOG_FILE=/tmp/log/$CONFIG.log
APP_PATH=/usr/share/$CONFIG
RULES_PATH=/usr/share/${CONFIG}/rules
DNS_N=dnsmasq
DNS_PORT=15353
TUN_DNS="127.0.0.1#${DNS_PORT}"
LOCAL_DNS=119.29.29.29
DEFAULT_DNS=
NO_PROXY=0
PROXY_IPV6=0
PROXY_IPV6_UDP=0
resolve_dns=0
use_tcp_node_resolve_dns=0
use_udp_node_resolve_dns=0
LUA_API_PATH=/usr/lib/lua/luci/model/cbi/$CONFIG/api
API_GEN_SS=$LUA_API_PATH/gen_shadowsocks.lua
API_GEN_V2RAY=$LUA_API_PATH/gen_v2ray.lua
API_GEN_V2RAY_PROTO=$LUA_API_PATH/gen_v2ray_proto.lua
API_GEN_TROJAN=$LUA_API_PATH/gen_trojan.lua
API_GEN_NAIVE=$LUA_API_PATH/gen_naiveproxy.lua
API_GEN_HYSTERIA=$LUA_API_PATH/gen_hysteria.lua

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$LOG_FILE
}

config_get_type() {
	local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null)
	echo "${ret:=$2}"
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
}

get_enabled_anonymous_secs() {
	uci -q show "${CONFIG}" | grep "${1}\[.*\.enabled='1'" | cut -d '.' -sf2
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=$host
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			isip=$(echo $host | cut -d '[' -f2 | cut -d ']' -f1)
		else
			isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	echo $ip
}

get_node_host_ip() {
	local ip
	local address=$(config_n_get $1 address)
	[ -n "$address" ] && {
		local use_ipv6=$(config_n_get $1 use_ipv6)
		local network_type="ipv4"
		[ "$use_ipv6" == "1" ] && network_type="ipv6"
		ip=$(get_host_ip $network_type $address)
	}
	echo $ip
}

get_ip_port_from() {
	local __host=${1}; shift 1
	local __ipv=${1}; shift 1
	local __portv=${1}; shift 1
	local __ucipriority=${1}; shift 1

	local val1 val2
	if [ -n "${__ucipriority}" ]; then
		val2=$(config_n_get ${__host} port $(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p'))
		val1=$(config_n_get ${__host} address "${__host%%${val2:+[:#]${val2}*}}")
	else
		val2=$(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p')
		val1="${__host%%${val2:+[:#]${val2}*}}"
	fi
	eval "${__ipv}=\"$val1\"; ${__portv}=\"$val2\""
}

host_from_url(){
	local f=${1}

	## Remove protocol part of url  ##
	f="${f##http://}"
	f="${f##https://}"
	f="${f##ftp://}"
	f="${f##sftp://}"

	## Remove username and/or username:password part of URL  ##
	f="${f##*:*@}"
	f="${f##*@}"

	## Remove rest of urls ##
	f="${f%%/*}"
	echo "${f%%:*}"
}

hosts_foreach() {
	local __hosts
	eval "__hosts=\$${1}"; shift 1
	local __func=${1}; shift 1
	local __default_port=${1}; shift 1
	local __ret=1

	[ -z "${__hosts}" ] && return 0
	local __ip __port
	for __host in $(echo $__hosts | sed 's/[ ,]/\n/g'); do
		get_ip_port_from "$__host" "__ip" "__port"
		eval "$__func \"${__host}\" \"\${__ip}\" \"\${__port:-${__default_port}}\" \"$@\""
		__ret=$?
		[ ${__ret} -ge ${ERROR_NO_CATCH:-1} ] && return ${__ret}
	done
}

check_host() {
	local f=${1}
	a=$(echo $f | grep "\/")
	[ -n "$a" ] && return 1
	# 判断是否包含汉字~
	local tmp=$(echo -n $f | awk '{print gensub(/[!-~]/,"","g",$0)}')
	[ -n "$tmp" ] && return 1
	return 0
}

get_first_dns() {
	local __hosts_val=${1}; shift 1
	__first() {
		[ -z "${2}" ] && return 0
		echo "${2}#${3}"
		return 1
	}
	eval "hosts_foreach \"${__hosts_val}\" __first \"$@\""
}

get_last_dns() {
	local __hosts_val=${1}; shift 1
	local __first __last
	__every() {
		[ -z "${2}" ] && return 0
		__last="${2}#${3}"
		__first=${__first:-${__last}}
	}
	eval "hosts_foreach \"${__hosts_val}\" __every \"$@\""
	[ "${__first}" ==  "${__last}" ] || echo "${__last}"
}

check_port_exists() {
	port=$1
	protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

get_new_port() {
	port=$1
	[ "$port" == "auto" ] && port=2082
	protocol=$(echo $2 | tr 'A-Z' 'a-z')
	result=$(check_port_exists $port $protocol)
	if [ "$result" != 0 ]; then
		temp=
		if [ "$port" -lt 65535 ]; then
			temp=$(expr $port + 1)
		elif [ "$port" -gt 1 ]; then
			temp=$(expr $port - 1)
		fi
		get_new_port $temp $protocol
	else
		echo $port
	fi
}

first_type() {
	local path_name=${1}
	type -t -p "/bin/${path_name}" -p "${TMP_BIN_PATH}/${path_name}" -p "${path_name}" "$@" | head -n1
}

eval_set_val() {
	for i in $@; do
		for j in $i; do
			eval $j
		done
	done
}

eval_unset_val() {
	for i in $@; do
		for j in $i; do
			eval unset j
		done
	done
}

ln_run() {
	local file_func=${1}
	local ln_name=${2}
	local output=${3}

	shift 3;
	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || echolog "  - $(readlink ${file_func}) 没有执行权限，无法启动：${file_func} $*"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || echolog "  - 找不到 ${ln_name}，无法启动..."
	${file_func:-echolog "  - ${ln_name}"} "$@" >${output} 2>&1 &
	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-echolog "  - ${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo "nil"
		return
	}
	echo $(lua -e "local api = require 'luci.model.cbi.passwall.api.api' print(api.${func})")
}

run_ipt2socks() {
	local flag proto tcp_tproxy local_port socks_address socks_port socks_username socks_password log_file
	local _extra_param=""
	eval_set_val $@
	[ -n "$log_file" ] || log_file="/dev/null"
	socks_address=$(get_host_ip "ipv4" ${socks_address})
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -a $socks_username -k $socks_password"
	[ -n "$tcp_tproxy" ] || _extra_param="${_extra_param} -R"
	case "$proto" in
	UDP)
		flag="${flag}_UDP"
		_extra_param="${_extra_param} -U"
	;;
	TCP)
		flag="${flag}_TCP"
		_extra_param="${_extra_param} -T"
	;;
	esac
	_extra_param="${_extra_param} -v"
	ln_run "$(first_type ipt2socks)" "ipt2socks_${flag}" $log_file -l $local_port -b 0.0.0.0 -s $socks_address -p $socks_port ${_extra_param}
}

run_v2ray() {
	local flag type node tcp_redir_port udp_redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port remote_dns_protocol remote_dns_udp_server remote_dns_tcp_server remote_dns_doh dns_client_ip dns_query_strategy dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file
	local _extra_param=""
	eval_set_val $@
	[ -z "$type" ] && {
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		if [ "$type" != "v2ray" ] && [ "$type" != "xray" ]; then
			local bin=$(first_type $(config_t_get global_app v2ray_file) v2ray)
			if [ -n "$bin" ]; then
				type="v2ray"
			else
				bin=$(first_type $(config_t_get global_app xray_file) xray)
				[ -n "$bin" ] && type="xray"
			fi
		fi
	}
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warning")
	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$node" ] && _extra_param="${_extra_param} -node $node"
	[ -n "$tcp_redir_port" ] && _extra_param="${_extra_param} -tcp_redir_port $tcp_redir_port"
	[ -n "$udp_redir_port" ] && _extra_param="${_extra_param} -udp_redir_port $udp_redir_port"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"
	[ -n "$dns_socks_address" ] && [ -n "$dns_socks_port" ] && _extra_param="${_extra_param} -dns_socks_address ${dns_socks_address} -dns_socks_port ${dns_socks_port}"
	[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
	[ -n "$dns_query_strategy" ] && _extra_param="${_extra_param} -dns_query_strategy ${dns_query_strategy}"
	[ -n "$dns_client_ip" ] && _extra_param="${_extra_param} -dns_client_ip ${dns_client_ip}"
	[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"
	local sniffing=$(config_t_get global_forwarding sniffing 1)
	[ "${sniffing}" = "1" ] && {
		_extra_param="${_extra_param} -sniffing 1"
		local route_only=$(config_t_get global_forwarding route_only 0)
		[ "${route_only}" = "1" ] && _extra_param="${_extra_param} -route_only 1"
	}
	local buffer_size=$(config_t_get global_forwarding buffer_size)
	[ -n "${buffer_size}" ] && _extra_param="${_extra_param} -buffer_size ${buffer_size}"
	case "$remote_dns_protocol" in
		tcp)
			local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
			local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
			local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
			_extra_param="${_extra_param} -remote_dns_server ${_dns_address} -remote_dns_port ${_dns_port} -remote_dns_tcp_server tcp://${_dns}"
		;;
		doh)
			local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
			local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
			#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
			local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
			local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
			local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
			[ -z "${_doh_port}" ] && _doh_port=443
			local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
			[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
			[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_server ${_doh_bootstrap}"
			_extra_param="${_extra_param} -remote_dns_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
		;;
		fakedns)
			_extra_param="${_extra_param} -remote_dns_fake 1"
		;;
	esac
	_extra_param="${_extra_param} -tcp_proxy_way $tcp_proxy_way"
	_extra_param="${_extra_param} -loglevel $loglevel"
	lua $API_GEN_V2RAY ${_extra_param} > $config_file
	ln_run "$(first_type $(config_t_get global_app ${type}_file) ${type})" ${type} $log_file run -c "$config_file"
}

run_dns2socks() {
	local flag socks socks_address socks_port socks_username socks_password listen_address listen_port dns cache log_file
	local _extra_param=""
	eval_set_val $@
	[ -n "$flag" ] && flag="_${flag}"
	[ -n "$log_file" ] || log_file="/dev/null"
	dns=$(get_first_dns dns 53 | sed 's/#/:/g')
	[ -n "$socks" ] && {
		socks=$(echo $socks | sed "s/#/:/g")
		socks_address=$(echo $socks | awk -F ':' '{print $1}')
		socks_port=$(echo $socks | awk -F ':' '{print $2}')
	}
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} /u $socks_username /p $socks_password"
	[ -z "$cache" ] && cache=1
	[ "$cache" = "0" ] && _extra_param="${_extra_param} /d"
	ln_run "$(first_type dns2socks)" "dns2socks${flag}" $log_file ${_extra_param} "${socks_address}:${socks_port}" "${dns}" "${listen_address}:${listen_port}"
}

run_socks() {
	local flag node bind socks_port config_file http_port http_config_file relay_port log_file
	eval_set_val $@
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	[ -n "$http_port" ] || http_port=0
	[ -n "$http_config_file" ] && [ -z "$(echo ${http_config_file} | grep $TMP_PATH)" ] && http_config_file=$TMP_PATH/$http_config_file
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=$TMP_PATH/$log_file
	else
		log_file="/dev/null"
	fi
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local port=$(config_n_get $node port)
	[ -n "$relay_port" ] && {
		server_host="127.0.0.1"
		port=$relay_port
	}
	local error_msg tmp

	if [ -n "$server_host" ] && [ -n "$port" ]; then
		check_host $server_host
		[ $? != 0 ] && {
			echolog "  - Socks节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
		tmp="${server_host}:${port}"
	else
		error_msg="某种原因，此 Socks 服务的相关配置已失联，启动中止！"
	fi

	if ([ "$type" == "v2ray" ] || [ "$type" == "xray" ]) && ([ -n "$(config_n_get $node balancing_node)" ] || [ "$(config_n_get $node default_node)" != "_direct" -a "$(config_n_get $node default_node)" != "_blackhole" ]); then
		unset error_msg
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动中止 ${bind}:${socks_port} ${error_msg}"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动 ${bind}:${socks_port}"

	case "$type" in
	socks)
		local bin=$(first_type $(config_t_get global_app v2ray_file) v2ray)
		if [ -n "$bin" ]; then
			type="v2ray"
		else
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && type="xray"
		fi
		[ -z "$type" ] && return 1
		local _socks_address=$(config_n_get $node address)
		local _socks_port=$(config_n_get $node port)
		local _socks_username=$(config_n_get $node username)
		local _socks_password=$(config_n_get $node password)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_port $http_port"
		}
		lua $API_GEN_V2RAY_PROTO -local_socks_port $socks_port ${_extra_param} -server_proto socks -server_address ${_socks_address} -server_port ${_socks_port} -server_username ${_socks_username} -server_password ${_socks_password} > $config_file
		ln_run "$bin" $type $log_file run -c "$config_file"
	;;
	v2ray|\
	xray)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _v2ray_args="http_port=$http_port"
		}
		run_v2ray flag=$flag node=$node socks_port=$socks_port config_file=$config_file log_file=$log_file ${_v2ray_args}
	;;
	trojan-go)
		lua $API_GEN_TROJAN -node $node -run_type client -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type $(config_t_get global_app trojan_go_file) trojan-go)" trojan-go $log_file -config "$config_file"
	;;
	trojan*)
		lua $API_GEN_TROJAN -node $node -run_type client -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
	;;
	naiveproxy)
		lua $API_GEN_NAIVE -node $node -run_type socks -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type naive)" naive $log_file "$config_file"
	;;
	brook)
		local protocol=$(config_n_get $node protocol client)
		local prefix=""
		[ "$protocol" == "wsclient" ] && {
			prefix="ws://"
			local brook_tls=$(config_n_get $node brook_tls 0)
			[ "$brook_tls" == "1" ] && {
				prefix="wss://"
				protocol="wssclient"
			}
			local ws_path=$(config_n_get $node ws_path "/ws")
		}
		server_host=${prefix}${server_host}
		ln_run "$(first_type $(config_t_get global_app brook_file) brook)" "brook_SOCKS_${flag}" $log_file "$protocol" --socks5 "$bind:$socks_port" -s "${server_host}:${port}${ws_path}" -p "$(config_n_get $node password)"
	;;
	ssr)
		lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss)
		lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $socks_port -server_host $server_host -server_port $port -mode tcp_and_udp > $config_file
		ln_run "$(first_type ss-local)" "ss-local" $log_file -c "$config_file" -v
	;;
	ss-rust)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_port $http_port"
		}
		lua $API_GEN_SS -node $node -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_port $http_port"
		}
		lua $API_GEN_HYSTERIA -node $node -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
	;;
	esac

	# http to socks
	[ -z "$http_flag" ] && [ "$http_port" != "0" ] && [ -n "$http_config_file" ] && [ "$type" != "v2ray" ] && [ "$type" != "xray" ] && [ "$type" != "socks" ] && {
		local bin=$(first_type $(config_t_get global_app v2ray_file) v2ray)
		if [ -n "$bin" ]; then
			type="v2ray"
		else
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && type="xray"
		fi
		[ -z "$type" ] && return 1
		lua $API_GEN_V2RAY_PROTO -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
		ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
	}
	unset http_flag
}

run_redir() {
	local node proto bind local_port config_file log_file
	eval_set_val $@
	local tcp_node_socks_flag tcp_node_http_flag
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=$TMP_PATH/$log_file
	else
		log_file="/dev/null"
	fi
	local proto=$(echo $proto | tr 'A-Z' 'a-z')
	local PROTO=$(echo $proto | tr 'a-z' 'A-Z')
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local close_log=$(config_t_get global close_log_${proto} 1)
	[ "$close_log" = "1" ] && log_file="/dev/null"
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local port=$(config_n_get $node port)
	[ -n "$server_host" ] && [ -n "$port" ] && {
		check_host $server_host
		[ $? != 0 ] && {
			echolog "${PROTO}节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
		[ "$bind" != "127.0.0.1" ] && echolog "${PROTO}节点：[$remarks]${server_host}:${port}，监听端口：$local_port"
	}
	eval ${PROTO}_NODE_PORT=$port

	case "$PROTO" in
	UDP)
		case "$type" in
		socks)
			local _socks_address=$(config_n_get $node address)
			_socks_address=$(get_host_ip "ipv4" ${_socks_address})
			local _socks_port=$(config_n_get $node port)
			local _socks_username=$(config_n_get $node username)
			local _socks_password=$(config_n_get $node password)
			[ -n "${_socks_username}" ] && [ -n "${_socks_password}" ] && local _extra_param="-a ${_socks_username} -k ${_socks_password}"
			ln_run "$(first_type ipt2socks)" "ipt2socks_UDP" $log_file -l $local_port -b 0.0.0.0 -s ${_socks_address} -p ${_socks_port} ${_extra_param} -U -v
		;;
		v2ray|\
		xray)
			run_v2ray flag=UDP node=$node udp_redir_port=$local_port config_file=$config_file log_file=$log_file
		;;
		trojan-go)
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $API_GEN_TROJAN -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel > $config_file
			ln_run "$(first_type $(config_t_get global_app trojan_go_file) trojan-go)" trojan-go $log_file -config "$config_file"
		;;
		trojan*)
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $API_GEN_TROJAN -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel > $config_file
			ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			echolog "Naiveproxy不支持UDP转发！"
		;;
		brook)
			local protocol=$(config_n_get $node protocol client)
			if [ "$protocol" == "wsclient" ]; then
				echolog "Brook的WebSocket不支持UDP转发！"
			else
				ln_run "$(first_type $(config_t_get global_app brook_file) brook)" "brook_UDP" $log_file tproxy -l ":$local_port" -s "$server_host:$port" -p "$(config_n_get $node password)" --doNotRunScripts
			fi
		;;
		ssr)
			lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(first_type ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v -U
		;;
		ss)
			lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $local_port -mode udp_only > $config_file
			ln_run "$(first_type ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			lua $API_GEN_SS -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria)
			lua $API_GEN_HYSTERIA -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
		;;
		esac
	;;
	TCP)
		if [ $PROXY_IPV6 == "1" ]; then
			echolog "开启实验性IPv6透明代理(TProxy)，请确认您的节点及类型支持IPv6！"
			if [ $type != "v2ray" ]; then
				PROXY_IPV6_UDP=1
			else
				echolog "节点类型：$type暂未支持IPv6 UDP代理！"
			fi
		fi

		if [ "$tcp_proxy_way" = "redirect" ]; then
			can_ipt=$(echo "$REDIRECT_LIST" | grep "$type")
		elif [ "$tcp_proxy_way" = "tproxy" ]; then
			can_ipt=$(echo "$TPROXY_LIST" | grep "$type")
		fi
		[ -z "$can_ipt" ] && type="socks"

		case "$type" in
		socks)
			_socks_flag=1
			_socks_address=$(config_n_get $node address)
			_socks_address=$(get_host_ip "ipv4" ${_socks_address})
			_socks_port=$(config_n_get $node port)
			_socks_username=$(config_n_get $node username)
			_socks_password=$(config_n_get $node password)
			[ -z "$can_ipt" ] && {
				local _config_file=$config_file
				_config_file="TCP_SOCKS_${node}.json"
				local _port=$(get_new_port 2080)
				run_socks flag="TCP" node=$node bind=127.0.0.1 socks_port=${_port} config_file=${_config_file}
				_socks_address=127.0.0.1
				_socks_port=${_port}
				unset _socks_username
				unset _socks_password
			}
		;;
		v2ray|\
		xray)
			local _flag="TCP"
			local _v2ray_args=""
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				_v2ray_args="${_v2ray_args} socks_port=${tcp_node_socks_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS_$tcp_node_socks_id/g")
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				_v2ray_args="${_v2ray_args} http_port=${tcp_node_http_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP_$tcp_node_http_id/g")
			}
			[ "$TCP_UDP" = "1" ] && {
				UDP_REDIR_PORT=$local_port
				UDP_NODE="nil"
				_flag="TCP_UDP"
				_v2ray_args="${_v2ray_args} udp_redir_port=${UDP_REDIR_PORT}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
			}
			[ "${DNS_MODE}" = "v2ray" -o "${DNS_MODE}" = "xray" ] && {
				resolve_dns=1
				config_file=$(echo $config_file | sed "s/.json/_DNS.json/g")
				_v2ray_args="${_v2ray_args} dns_query_strategy=${DNS_QUERY_STRATEGY}"
				local _dns_client_ip=$(config_t_get global dns_client_ip)
				[ -n "${_dns_client_ip}" ] && _v2ray_args="${_v2ray_args} dns_client_ip=${_dns_client_ip}"
				[ "${DNS_CACHE}" == "0" ] && _v2ray_args="${_v2ray_args} dns_cache=0"
				local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
				_v2ray_args="${_v2ray_args} remote_dns_protocol=${v2ray_dns_mode}"
				_v2ray_args="${_v2ray_args} dns_listen_port=${dns_listen_port}"
				case "$v2ray_dns_mode" in
					tcp)
						_v2ray_args="${_v2ray_args} remote_dns_tcp_server=${REMOTE_DNS}"
						echolog "  - 域名解析 DNS Over TCP..."
					;;
					doh)
						remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
						_v2ray_args="${_v2ray_args} remote_dns_doh=${remote_dns_doh}"
						echolog "  - 域名解析 DNS Over HTTPS..."
					;;
					fakedns)
						fakedns=1
						CHINADNS_NG=0
						echolog "  - 域名解析 Fake DNS..."
					;;
				esac
			}
			run_v2ray flag=$_flag node=$node tcp_redir_port=$local_port config_file=$config_file log_file=$log_file ${_v2ray_args}
		;;
		trojan-go)
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
			}
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $API_GEN_TROJAN -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel > $config_file
			ln_run "$(first_type $(config_t_get global_app trojan_go_file) trojan-go)" trojan-go $log_file -config "$config_file"
		;;
		trojan*)
			[ "$tcp_proxy_way" = "tproxy" ] && lua_tproxy_arg="-use_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
			}
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $API_GEN_TROJAN -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel $lua_tproxy_arg > $config_file
			ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			lua $API_GEN_NAIVE -node $node -run_type redir -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(first_type naive)" naive $log_file "$config_file"
		;;
		brook)
			local server_ip=$server_host
			local protocol=$(config_n_get $node protocol client)
			local prefix=""
			[ "$protocol" == "wsclient" ] && {
				prefix="ws://"
				local brook_tls=$(config_n_get $node brook_tls 0)
				[ "$brook_tls" == "1" ] && prefix="wss://"
				local ws_path=$(config_n_get $node ws_path "/ws")
			}
			server_ip=${prefix}${server_ip}
			ln_run "$(first_type $(config_t_get global_app brook_file) brook)" "brook_TCP" $log_file tproxy -l ":$local_port" -s "${server_ip}:${port}${ws_path}" -p "$(config_n_get $node password)" --doNotRunScripts
		;;
		ssr)
			[ "$tcp_proxy_way" = "tproxy" ] && lua_tproxy_arg="-tcp_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="-u"
			}
			lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_tproxy_arg > $config_file
			ln_run "$(first_type ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v ${_extra_param}
		;;
		ss)
			[ "$tcp_proxy_way" = "tproxy" ] && lua_tproxy_arg="-tcp_tproxy true"
			lua_mode_arg="-mode tcp_only"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				lua_mode_arg="-mode tcp_and_udp"
			}
			lua $API_GEN_SS -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_mode_arg $lua_tproxy_arg > $config_file
			ln_run "$(first_type ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			local _extra_param="-local_tcp_redir_port $local_port"
			[ "$tcp_proxy_way" = "tproxy" ] && _extra_param="${_extra_param} -tcp_tproxy true"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS_$tcp_node_socks_id/g")
				_extra_param="${_extra_param} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP_$tcp_node_http_id/g")
				_extra_param="${_extra_param} -local_http_port ${tcp_node_http_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			lua $API_GEN_SS -node $node ${_extra_param} > $config_file
			ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria)
			local _extra_param="-local_tcp_redir_port $local_port"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS_$tcp_node_socks_id/g")
				_extra_param="${_extra_param} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP_$tcp_node_http_id/g")
				_extra_param="${_extra_param} -local_http_port ${tcp_node_http_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			lua $API_GEN_HYSTERIA -node $node ${_extra_param} > $config_file
			ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
		;;
		esac
		if [ -n "${_socks_flag}" ]; then
			local _flag="TCP"
			local _extra_param="-T"
			[ "$TCP_UDP" = "1" ] && {
				_flag="TCP_UDP"
				_extra_param=""
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				UDP_NODE="nil"
			}
			local _socks_tproxy="-R"
			[ "$tcp_proxy_way" = "tproxy" ] && _socks_tproxy=""
			_extra_param="${_extra_param} ${_socks_tproxy}"
			[ -n "${_socks_username}" ] && [ -n "${_socks_password}" ] && _extra_param="-a ${_socks_username} -k ${_socks_password} ${_extra_param}"
			ln_run "$(first_type ipt2socks)" "ipt2socks_${_flag}" $log_file -l $local_port -b 0.0.0.0 -s ${_socks_address} -p ${_socks_port} ${_extra_param} -v
		fi

		[ -z "$tcp_node_socks_flag" ] && {
			[ "$tcp_node_socks" = "1" ] && {
				local port=$tcp_node_socks_port
				local config_file="SOCKS_$tcp_node_socks_id.json"
				local log_file="SOCKS_$tcp_node_socks_id.log"
				local http_port=0
				local http_config_file="HTTP2SOCKS_$tcp_node_http_id.json"
				[ "$tcp_node_http" = "1" ] && [ -z "$tcp_node_http_flag" ] && {
					http_port=$tcp_node_http_port
				}
				run_socks flag=$tcp_node_socks_id node=$node bind=0.0.0.0 socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file
			}
		}
	;;
	esac
	unset tcp_node_socks_flag tcp_node_http_flag
	return 0
}

node_switch() {
	local flag new_node shunt_logic log_output
	eval_set_val $@
	[ -n "$flag" ] && [ -n "$new_node" ] && {
		flag=$(echo $flag | tr 'A-Z' 'a-z')
		FLAG=$(echo $flag | tr 'a-z' 'A-Z')
		[ -n "$log_output" ] || LOG_FILE="/dev/null"
		local node=$2
		pgrep -af "${TMP_PATH}" | awk -v P1="${FLAG}" 'BEGIN{IGNORECASE=1}$0~P1 && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf $TMP_PATH/${FLAG}*
		local config_file="${FLAG}.json"
		local log_file="${FLAG}.log"
		local port=$(cat $TMP_PORT_PATH/${FLAG})
		
		[ "$SOCKS_ENABLED" = "1" ] && {
			local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
			for id in $ids; do
				[ "$(config_n_get $id enabled 0)" = "0" ] && continue
				[ "$(config_n_get $id node nil)" != "tcp" ] && continue
				local socks_port=$(config_n_get $id port)
				local http_port=$(config_n_get $id http_port 0)
				pgrep -af "${TMP_PATH}.*${id}" | awk 'BEGIN{IGNORECASE=1}/SOCKS/{print $1}' | xargs kill -9 >/dev/null 2>&1
				tcp_node_socks=1
				tcp_node_socks_port=$socks_port
				tcp_node_socks_id=$id
				[ "$http_port" != "0" ] && {
					tcp_node_http=1
					tcp_node_http_port=$http_port
					tcp_node_http_id=$id
				}
				break
			done
		}
		
		[ "$shunt_logic" != "0" ] && {
			local node=$(config_t_get global ${flag}_node nil)
			[ "$(config_n_get $node protocol nil)" = "_shunt" ] && {
				if [ "$shunt_logic" = "1" ]; then
					uci set $CONFIG.$node.default_node="$new_node"
				elif [ "$shunt_logic" = "2" ]; then
					uci set $CONFIG.$node.main_node="$new_node"
				fi
				uci commit $CONFIG
			}
			new_node=$node
		}

		run_redir node=$new_node proto=$FLAG bind=0.0.0.0 local_port=$port config_file=$config_file log_file=$log_file
		echo $new_node > $TMP_ID_PATH/${FLAG}

		[ "$shunt_logic" != "0" ] && [ "$(config_n_get $new_node protocol nil)" = "_shunt" ] && {
			echo $(config_n_get $new_node default_node nil) > $TMP_ID_PATH/${1}_default
			echo $(config_n_get $new_node main_node nil) > $TMP_ID_PATH/${1}_main
			uci commit $CONFIG
		}

		[ "$flag" = "tcp" ] && {
			[ "$(config_t_get global udp_node nil)" = "tcp" ] && [ "$UDP_REDIR_PORT" != "$TCP_REDIR_PORT" ] && {
				pgrep -af "$TMP_PATH" | awk 'BEGIN{IGNORECASE=1}/UDP/ && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
				UDP_NODE=$new_node
				start_redir UDP
			}
		}

		#uci set $CONFIG.@global[0].${flag}_node=$new_node
		#uci commit $CONFIG
		source $APP_PATH/helper_${DNS_N}.sh logic_restart no_log=1
	}
}

start_redir() {
	local proto=${1}
	eval node=\$${proto}_NODE
	if [ "$node" != "nil" ]; then
		TYPE=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		local config_file="${proto}.json"
		local log_file="${proto}.log"
		eval current_port=\$${proto}_REDIR_PORT
		local port=$(echo $(get_new_port $current_port $proto))
		eval ${proto}_REDIR=$port
		run_redir node=$node proto=${proto} bind=0.0.0.0 local_port=$port config_file=$config_file log_file=$log_file
		#eval ip=\$${proto}_NODE_IP
		echo $port > $TMP_PORT_PATH/${proto}
		echo $node > $TMP_ID_PATH/${proto}
		[ "$(config_n_get $node protocol nil)" = "_shunt" ] && {
			local default_node=$(config_n_get $node default_node nil)
			local main_node=$(config_n_get $node main_node nil)
			echo $default_node > $TMP_ID_PATH/${proto}_default
			echo $main_node > $TMP_ID_PATH/${proto}_main
		}
	else
		[ "${proto}" = "UDP" ] && [ "$TCP_UDP" = "1" ] && return
		echolog "${proto}节点没有选择或为空，不代理${proto}。"
	fi
}

start_socks() {
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		[ -n "$ids" ] && {
			echolog "分析 Socks 服务的节点配置..."
			for id in $ids; do
				local enabled=$(config_n_get $id enabled 0)
				[ "$enabled" == "0" ] && continue
				local node=$(config_n_get $id node nil)
				[ "$node" == "nil" ] && continue
				local port=$(config_n_get $id port)
				local config_file="SOCKS_${id}.json"
				local log_file="SOCKS_${id}.log"
				local http_port=$(config_n_get $id http_port 0)
				local http_config_file="HTTP2SOCKS_${id}.json"
				[ "$node" == "tcp" ] && {
					tcp_node_socks=1
					tcp_node_socks_port=$port
					tcp_node_socks_id=$id
					[ "$http_port" != "0" ] && {
						tcp_node_http=1
						tcp_node_http_port=$http_port
						tcp_node_http_id=$id
					}
					continue
				}
				run_socks flag=$id node=$node bind=0.0.0.0 socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file
				echo $node > $TMP_ID_PATH/SOCKS_${id}
			done
		}
	}
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "" > $LOG_FILE
		echolog "日志文件过长，清空处理！"
	}
}

clean_crontab() {
	touch /etc/crontabs/root
	#sed -i "/${CONFIG}/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "/etc/init.d/${CONFIG}" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/rule_update.lua log" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/subscribe.lua start" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
}

start_crontab() {
	clean_crontab
	[ "$ENABLED" != 1 ] && {
		/etc/init.d/cron restart
		return
	}
	auto_on=$(config_t_get global_delay auto_on 0)
	if [ "$auto_on" = "1" ]; then
		time_off=$(config_t_get global_delay time_off)
		time_on=$(config_t_get global_delay time_on)
		time_restart=$(config_t_get global_delay time_restart)
		[ -z "$time_off" -o "$time_off" != "nil" ] && {
			echo "0 $time_off * * * /etc/init.d/$CONFIG stop" >>/etc/crontabs/root
			echolog "配置定时任务：每天 $time_off 点关闭服务。"
		}
		[ -z "$time_on" -o "$time_on" != "nil" ] && {
			echo "0 $time_on * * * /etc/init.d/$CONFIG start" >>/etc/crontabs/root
			echolog "配置定时任务：每天 $time_on 点开启服务。"
		}
		[ -z "$time_restart" -o "$time_restart" != "nil" ] && {
			echo "0 $time_restart * * * /etc/init.d/$CONFIG restart" >>/etc/crontabs/root
			echolog "配置定时任务：每天 $time_restart 点重启服务。"
		}
	fi

	autoupdate=$(config_t_get global_rules auto_update)
	weekupdate=$(config_t_get global_rules week_update)
	dayupdate=$(config_t_get global_rules time_update)
	if [ "$autoupdate" = "1" ]; then
		local t="0 $dayupdate * * $weekupdate"
		[ "$weekupdate" = "7" ] && t="0 $dayupdate * * *"
		echo "$t lua $APP_PATH/rule_update.lua log > /dev/null 2>&1 &" >>/etc/crontabs/root
		echolog "配置定时任务：自动更新规则。"
	fi
	
	TMP_SUB_PATH=$TMP_PATH/sub_crontabs
	mkdir -p $TMP_SUB_PATH
	for item in $(uci show ${CONFIG} | grep "=subscribe_list" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		if [ "$(config_n_get $item auto_update 0)" = "1" ]; then
			cfgid=$(uci show ${CONFIG}.$item | head -n 1 | cut -d '.' -sf 2 | cut -d '=' -sf 1)
			remark=$(config_n_get $item remark)
			week_update=$(config_n_get $item week_update)
			time_update=$(config_n_get $item time_update)
			echo "$cfgid" >> $TMP_SUB_PATH/${week_update}_${time_update}
			echolog "配置定时任务：自动更新【$remark】订阅。"
		fi
	done
	
	[ -d "${TMP_SUB_PATH}" ] && {
		for name in $(ls ${TMP_SUB_PATH}); do
			week_update=$(echo $name | awk -F '_' '{print $1}')
			time_update=$(echo $name | awk -F '_' '{print $2}')
			local t="0 $time_update * * $week_update"
			[ "$week_update" = "7" ] && t="0 $time_update * * *"
			cfgids=$(echo -n $(cat ${TMP_SUB_PATH}/${name}) | sed 's# #,#g')
			echo "$t lua $APP_PATH/subscribe.lua start $cfgids > /dev/null 2>&1 &" >>/etc/crontabs/root
		done
		rm -rf $TMP_SUB_PATH
	}

	if [ "$NO_PROXY" == 0 ]; then
		start_daemon=$(config_t_get global_delay start_daemon 0)
		[ "$start_daemon" = "1" ] && $APP_PATH/monitor.sh > /dev/null 2>&1 &

		AUTO_SWITCH_ENABLE=$(config_t_get auto_switch enable 0)
		[ "$AUTO_SWITCH_ENABLE" = "1" ] && $APP_PATH/test.sh > /dev/null 2>&1 &
	else
		echolog "运行于非代理模式，仅允许服务启停的定时任务。"
	fi

	/etc/init.d/cron restart
}

stop_crontab() {
	clean_crontab
	/etc/init.d/cron restart
	#echolog "清除定时执行命令。"
}

start_dns() {
	TUN_DNS="127.0.0.1#${dns_listen_port}"

	echolog "过滤服务配置：准备接管域名解析..."
	local items=$(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	[ -n "$items" ] && {
		for item in $items; do
			[ "$(config_n_get $item enabled)" = "1" ] || continue
			[ "$(config_n_get $item tcp_node)" = "default" -o "$(config_n_get $item udp_node)" = "default" ] && {
				local item_tcp_proxy_mode=$(config_n_get $item tcp_proxy_mode default)
				local item_udp_proxy_mode=$(config_n_get $item udp_proxy_mode default)
				[ "$item_tcp_proxy_mode" = "default" ] && item_tcp_proxy_mode=$TCP_PROXY_MODE
				[ "$item_udp_proxy_mode" = "default" ] && item_udp_proxy_mode=$UDP_PROXY_MODE
				global=$(echo "${global}${item_tcp_proxy_mode}${item_udp_proxy_mode}" | grep "global")
				returnhome=$(echo "${returnhome}${item_tcp_proxy_mode}${item_udp_proxy_mode}" | grep "returnhome")
				chnlist=$(echo "${chnlist}${item_tcp_proxy_mode}${item_udp_proxy_mode}" | grep "chnroute")
				gfwlist=$(echo "${gfwlist}${item_tcp_proxy_mode}${item_udp_proxy_mode}" | grep "gfwlist")
				ACL_TCP_PROXY_MODE=${ACL_TCP_PROXY_MODE}${item_tcp_proxy_mode}
				ACL_UDP_PROXY_MODE=${ACL_UDP_PROXY_MODE}${item_udp_proxy_mode}
			}
		done
	}

	case "$DNS_MODE" in
	dns2socks)
		local dns2socks_socks_server=$(echo $(config_t_get global socks_server 127.0.0.1:1080) | sed "s/#/:/g")
		local dns2socks_forward=$(get_first_dns REMOTE_DNS 53 | sed 's/#/:/g')
		run_dns2socks socks=$dns2socks_socks_server listen_address=127.0.0.1 listen_port=${dns_listen_port} dns=$dns2socks_forward cache=$DNS_CACHE
		echolog "  - 域名解析：dns2socks(127.0.0.1:${dns_listen_port})，${dns2socks_socks_server} -> ${dns2socks_forward}"
	;;
	v2ray|\
	xray)
		[ "${resolve_dns}" == "0" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=$TMP_PATH/DNS.log
			local log_file=/dev/null
			local _v2ray_args="config_file=$config_file log_file=$log_file"
			[ "${DNS_CACHE}" == "0" ] && _v2ray_args="${_v2ray_args} dns_cache=0"
			_v2ray_args="${_v2ray_args} dns_query_strategy=${DNS_QUERY_STRATEGY}"
			local _dns_client_ip=$(config_t_get global dns_client_ip)
			[ -n "${_dns_client_ip}" ] && _v2ray_args="${_v2ray_args} dns_client_ip=${_dns_client_ip}"
			use_tcp_node_resolve_dns=1
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			_v2ray_args="${_v2ray_args} dns_listen_port=${dns_listen_port}"
			_v2ray_args="${_v2ray_args} remote_dns_protocol=${v2ray_dns_mode}"
			case "$v2ray_dns_mode" in
				tcp)
					_v2ray_args="${_v2ray_args} remote_dns_tcp_server=${REMOTE_DNS}"
					echolog "  - 域名解析 DNS Over TCP..."
				;;
				doh)
					remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
					_v2ray_args="${_v2ray_args} remote_dns_doh=${remote_dns_doh}"
					
					local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
					local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
					local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
					local _is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
					local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
					[ -z "${_doh_port}" ] && _doh_port=443
					local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
					[ "${_is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
					[ -n "${_doh_bootstrap}" ] && REMOTE_DNS=${_doh_bootstrap}:${_doh_port}
					unset _doh_url _doh_host_port _doh_host _is_ip _doh_port _doh_bootstrap
					echolog "  - 域名解析 DNS Over HTTPS..."
				;;
			esac
			run_v2ray ${_v2ray_args}
		}
	;;
	pdnsd)
		use_tcp_node_resolve_dns=1
		gen_pdnsd_config "${dns_listen_port}" "${REMOTE_DNS}" "${DNS_CACHE}"
		ln_run "$(first_type pdnsd)" pdnsd "/dev/null" --daemon -c "${TMP_PATH}/pdnsd/pdnsd.conf" -d
		echolog "  - 域名解析：pdnsd + 使用(TCP节点)解析域名..."
	;;
	udp)
		use_udp_node_resolve_dns=1
		TUN_DNS="$(echo ${REMOTE_DNS} | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')"
		echolog "  - 域名解析：使用UDP协议请求DNS（$TUN_DNS）..."
	;;
	esac

	[ "${use_tcp_node_resolve_dns}" = "1" ] && echolog "  * 请确认上游 DNS 支持 TCP 查询，如非直连地址，确保 TCP 代理打开，并且已经正确转发！"
	[ "${use_udp_node_resolve_dns}" = "1" ] && echolog "  * 要求代理 DNS 请求，如上游 DNS 非直连地址，确保 UDP 代理打开，并且已经正确转发！"
	
	case "$DNS_SHUNT" in
	smartdns)
		local group_domestic=$(config_t_get global group_domestic)
		CHINADNS_NG=0
		source $APP_PATH/helper_smartdns.sh add FLAG="default" DNS_MODE=$DNS_MODE SMARTDNS_CONF=/tmp/etc/smartdns/$CONFIG.conf REMOTE_FAKEDNS=$fakedns DEFAULT_DNS=$DEFAULT_DNS LOCAL_GROUP=$group_domestic TUN_DNS=$TUN_DNS TCP_NODE=$TCP_NODE PROXY_MODE=${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${ACL_TCP_PROXY_MODE} NO_PROXY_IPV6=${filter_proxy_ipv6}
		source $APP_PATH/helper_smartdns.sh restart
		echolog "  - 域名解析：使用SmartDNS，请确保配置正常。"
	;;
	esac

	[ -n "$chnlist" ] && [ "$CHINADNS_NG" = "1" ] && [ -n "$(first_type chinadns-ng)" ] && [ -s "${RULES_PATH}/chnlist" ] && {
		china_ng_listen_port=$(expr $dns_listen_port + 1)
		china_ng_listen="127.0.0.1#${china_ng_listen_port}"
		china_ng_chn=$(echo -n $(echo "${LOCAL_DNS}" | sed "s/,/\n/g" | head -n2) | tr " " ",")
		china_ng_gfw="${TUN_DNS}"
		echolog "  | - (chinadns-ng) 最高支持4级域名过滤..."

		local gfwlist_param="${TMP_PATH}/chinadns_gfwlist"
		[ -s "${RULES_PATH}/gfwlist" ] && cp -a "${RULES_PATH}/gfwlist" "${gfwlist_param}"
		local chnlist_param="${TMP_PATH}/chinadns_chnlist"
		[ -s "${RULES_PATH}/chnlist" ] && cp -a "${RULES_PATH}/chnlist" "${chnlist_param}"

		[ -s "${RULES_PATH}/proxy_host" ] && {
			cat "${RULES_PATH}/proxy_host" | tr -s '\n' | grep -v "^#" | sort -u >> "${gfwlist_param}"
			echolog "  | - [$?](chinadns-ng) 代理域名表合并到防火墙域名表"
		}
		[ -s "${RULES_PATH}/direct_host" ] && {
			cat "${RULES_PATH}/direct_host" | tr -s '\n' | grep -v "^#" | sort -u >> "${chnlist_param}"
			echolog "  | - [$?](chinadns-ng) 域名白名单合并到中国域名表"
		}
		chnlist_param=${chnlist_param:+-m "${chnlist_param}" -M}
		local log_path="${TMP_PATH}/chinadns-ng.log"
		log_path="/dev/null"
		ln_run "$(first_type chinadns-ng)" chinadns-ng "$log_path" -v -b 0.0.0.0 -l "${china_ng_listen_port}" ${china_ng_chn:+-c "${china_ng_chn}"} ${chnlist_param} ${china_ng_gfw:+-t "${china_ng_gfw}"} ${gfwlist_param:+-g "${gfwlist_param}"} -f
		echolog "  + 过滤服务：ChinaDNS-NG(:${china_ng_listen_port})：国内DNS：${china_ng_chn}，可信DNS：${china_ng_gfw}"
	}
	
	[ "$DNS_SHUNT" = "dnsmasq" ] && {
		source $APP_PATH/helper_dnsmasq.sh stretch
		source $APP_PATH/helper_dnsmasq.sh add FLAG="default" DNS_MODE=$DNS_MODE TMP_DNSMASQ_PATH=$TMP_DNSMASQ_PATH DNSMASQ_CONF_FILE=/tmp/dnsmasq.d/dnsmasq-passwall.conf REMOTE_FAKEDNS=$fakedns DEFAULT_DNS=$DEFAULT_DNS LOCAL_DNS=$LOCAL_DNS TUN_DNS=$TUN_DNS CHINADNS_DNS=$china_ng_listen TCP_NODE=$TCP_NODE PROXY_MODE=${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${ACL_TCP_PROXY_MODE} NO_PROXY_IPV6=${filter_proxy_ipv6}
	}
}

gen_pdnsd_config() {
	local listen_port=${1}
	local up_dns=${2}
	local cache=${3}
	local pdnsd_dir=${TMP_PATH}/pdnsd
	local perm_cache=2048
	local _cache="on"
	local query_method="tcp_only"
	local reject_ipv6_dns=
	[ "${cache}" = "0" ] && _cache="off" && perm_cache=0

	mkdir -p "${pdnsd_dir}"
	touch "${pdnsd_dir}/pdnsd.cache"
	chown -R root.nogroup "${pdnsd_dir}"
	if [ $PROXY_IPV6 == "0" ]; then
		reject_ipv6_dns=$(cat <<- 'EOF'

				reject = ::/0;
				reject_policy = negate;
		EOF
		)
	fi
	cat > "${pdnsd_dir}/pdnsd.conf" <<-EOF
		global {
			perm_cache = $perm_cache;
			cache_dir = "$pdnsd_dir";
			run_as = "root";
			server_ip = 127.0.0.1;
			server_port = ${listen_port};
			status_ctl = on;
			query_method = ${query_method};
			min_ttl = 1h;
			max_ttl = 1w;
			timeout = 10;
			par_queries = 2;
			neg_domain_pol = off;
			udpbufsize = 1024;
			proc_limit = 2;
			procq_limit = 8;
		}

	EOF
	echolog "  + [$?]Pdnsd (127.0.0.1:${listen_port})..."

	append_pdnsd_updns() {
		[ -z "${2}" ] && echolog "  | - 略过错误 : ${1}" && return 0
		cat >> $pdnsd_dir/pdnsd.conf <<-EOF
			server {
				label = "node-${2}_${3}";
				ip = ${2};
				edns_query = on;
				port = ${3};
				timeout = 4;
				interval = 10m;
				uptest = none;
				purge_cache = off;
				proxy_only = on;
				caching = $_cache;${reject_ipv6_dns}
			}
		EOF
		echolog "  | - [$?]上游DNS：${2}:${3}"
	}
	hosts_foreach up_dns append_pdnsd_updns 53
}

add_ip2route() {
	local ip=$(get_host_ip "ipv4" $1)
	[ -z "$ip" ] && {
		echolog "  - 无法解析[${1}]，路由表添加失败！"
		return 1
	}
	local remarks="${1}"
	[ "$remarks" != "$ip" ] && remarks="${1}(${ip})"
	
	. /lib/functions/network.sh
	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
	[ -z "${device}" ] && device="$2"
	
	if [ -n "${gateway}" ]; then
		route add -host ${ip} gw ${gateway} dev ${device} >/dev/null 2>&1
		echo "$ip" >> $TMP_ROUTE_PATH/${device}
		echolog "  - [${remarks}]添加到接口[${device}]路由表成功！"
	else
		echolog "  - [${remarks}]添加到接口[${device}]路由表失功！原因是找不到[${device}]网关。"
	fi
}

delete_ip2route() {
	[ -d "${TMP_ROUTE_PATH}" ] && {
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

start_haproxy() {
	local haproxy_path haproxy_file item items lport sort_items

	[ "$(config_t_get global_haproxy balancing_enable 0)" != "1" ] && return
	echolog "HAPROXY 负载均衡..."

	haproxy_path=${TMP_PATH}/haproxy
	mkdir -p "${haproxy_path}"
	haproxy_file=${haproxy_path}/config.cfg
	cat <<-EOF > "${haproxy_file}"
		global
		    log         127.0.0.1 local2
		    chroot      ${haproxy_path}
		    maxconn     60000
		    stats socket  ${haproxy_path}/haproxy.sock
		    daemon

		defaults
		    mode                    tcp
		    log                     global
		    option                  tcplog
		    option                  dontlognull
		    option http-server-close
		    #option forwardfor       except 127.0.0.0/8
		    option                  redispatch
		    retries                 2
		    timeout http-request    10s
		    timeout queue           1m
		    timeout connect         10s
		    timeout client          1m
		    timeout server          1m
		    timeout http-keep-alive 10s
		    timeout check           10s
		    maxconn                 3000

	EOF

	items=$(uci show ${CONFIG} | grep "=haproxy_config" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	for item in $items; do
		lport=$(config_n_get ${item} haproxy_port 0)
		[ "${lport}" = "0" ] && echolog "  - 丢弃1个明显无效的节点" && continue
		sort_items="${sort_items}${IFS}${lport} ${item}"
	done

	items=$(echo "${sort_items}" | sort -n | cut -d ' ' -sf 2)

	unset lport
	local haproxy_port lbss lbweight export backup remark
	local msg bip bport hasvalid bbackup failcount interface
	for item in ${items}; do
		unset haproxy_port bbackup

		eval $(uci -q show "${CONFIG}.${item}" | cut -d '.' -sf 3-)
		[ "$enabled" = "1" ] || continue
		get_ip_port_from "$lbss" bip bport 1

		[ -z "$haproxy_port" ] || [ -z "$bip" ] && echolog "  - 丢弃1个明显无效的节点" && continue
		[ "$backup" = "1" ] && bbackup="backup"
		remark=$(echo $bip | sed "s/\[//g" | sed "s/\]//g")

		[ "$lport" = "${haproxy_port}" ] || {
			hasvalid="1"
			lport=${haproxy_port}
			echolog "  + 入口 0.0.0.0:${lport}..."
			cat <<-EOF >> "${haproxy_file}"
				listen $lport
				    mode tcp
				    bind 0.0.0.0:$lport
			EOF
		}

		cat <<-EOF >> "${haproxy_file}"
			    server $remark:$bport $bip:$bport weight $lbweight check inter 1500 rise 1 fall 3 $bbackup
		EOF

		if [ "$export" != "0" ]; then
			add_ip2route ${bip} ${export} > /dev/null 2>&1 &
		fi

		haproxy_items="${haproxy_items}${IFS}${bip}:${bport}"
		echolog "  | - 出口节点：${bip}:${bport}，权重：${lbweight}"
	done

	# 控制台配置
	local console_port=$(config_t_get global_haproxy console_port)
	local console_user=$(config_t_get global_haproxy console_user)
	local console_password=$(config_t_get global_haproxy console_password)
	local auth=""
	[ -n "$console_user" ] && [ -n "$console_password" ] && auth="stats auth $console_user:$console_password"
	cat <<-EOF >> "${haproxy_file}"

		listen console
		    bind 0.0.0.0:$console_port
		    mode http
		    stats refresh 30s
		    stats uri /
		    stats admin if TRUE
		    $auth
	EOF

	[ "${hasvalid}" != "1" ] && echolog "  - 没有发现任何有效节点信息，不启动。" && return 0
	ln_run "$(first_type haproxy)" haproxy "/dev/null" -f "${haproxy_file}"
	echolog "  * 控制台端口：${console_port}/，${auth:-公开}"
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}

boot() {
	[ "$ENABLED" == 1 ] && {
		local delay=$(config_t_get global_delay start_delay 1)
		if [ "$delay" -gt 0 ]; then
			echolog "执行启动延时 $delay 秒后再启动!"
			sleep $delay && start >/dev/null 2>&1 &
		else
			start
		fi
	}
	return 0
}

start() {
	ulimit -n 65535
	start_haproxy
	start_socks

	[ "$NO_PROXY" == 1 ] || {
		if [ -z "$(command -v iptables-legacy || command -v iptables)" ] || [ -z "$(command -v ipset)" ]; then
			echolog "系统未安装iptables或ipset，无法透明代理！"
		else
			start_redir TCP
			start_redir UDP
			start_dns
			source $APP_PATH/iptables.sh start
			source $APP_PATH/helper_${DNS_N}.sh logic_restart
		fi
	}
	start_crontab
	echolog "运行完成！\n"
}

stop() {
	clean_log
	source $APP_PATH/iptables.sh stop
	delete_ip2route
	kill_all v2ray-plugin obfs-local
	pgrep -f "sleep.*(6s|9s|58s)" | xargs kill -9 >/dev/null 2>&1
	pgrep -af "${CONFIG}/" | awk '! /app\.sh|subscribe\.lua|rule_update\.lua/{print $1}' | xargs kill -9 >/dev/null 2>&1
	unset V2RAY_LOCATION_ASSET
	unset XRAY_LOCATION_ASSET
	stop_crontab
	source $APP_PATH/helper_smartdns.sh del
	source $APP_PATH/helper_dnsmasq.sh del
	source $APP_PATH/helper_dnsmasq.sh restart no_log=1
	rm -rf ${TMP_PATH}
	rm -rf /tmp/lock/${CONFIG}_script.lock
	echolog "清空并关闭相关程序和缓存完成。"
	/etc/init.d/sysctl restart
	exit 0
}

ENABLED=$(config_t_get global enabled 0)
SOCKS_ENABLED=$(config_t_get global socks_enabled 0)
TCP_REDIR_PORT=1041
TCP_NODE=$(config_t_get global tcp_node nil)
UDP_REDIR_PORT=1051
UDP_NODE=$(config_t_get global udp_node nil)
TCP_UDP=0
[ "$UDP_NODE" == "tcp" ] && {
	UDP_NODE=$TCP_NODE
	TCP_UDP=1
}
[ "$ENABLED" != 1 ] && NO_PROXY=1
[ "$TCP_NODE" == "nil" -a "$UDP_NODE" == "nil" ] && NO_PROXY=1
[ "$(config_get_type $TCP_NODE nil)" == "nil" -a "$(config_get_type $UDP_NODE nil)" == "nil" ] && NO_PROXY=1
tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
REDIRECT_LIST="socks ss ss-rust ssr v2ray xray trojan-plus trojan-go naiveproxy"
TPROXY_LIST="socks ss ss-rust ssr v2ray xray trojan-plus brook trojan-go hysteria"
RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto
TCP_REDIR_PORTS=$(config_t_get global_forwarding tcp_redir_ports '80,443')
UDP_REDIR_PORTS=$(config_t_get global_forwarding udp_redir_ports '1:65535')
TCP_NO_REDIR_PORTS=$(config_t_get global_forwarding tcp_no_redir_ports 'disable')
UDP_NO_REDIR_PORTS=$(config_t_get global_forwarding udp_no_redir_ports 'disable')
TCP_PROXY_DROP_PORTS=$(config_t_get global_forwarding tcp_proxy_drop_ports 'disable')
UDP_PROXY_DROP_PORTS=$(config_t_get global_forwarding udp_proxy_drop_ports '80,443')
TCP_PROXY_MODE=$(config_t_get global tcp_proxy_mode chnroute)
UDP_PROXY_MODE=$(config_t_get global udp_proxy_mode chnroute)
LOCALHOST_TCP_PROXY_MODE=$(config_t_get global localhost_tcp_proxy_mode default)
LOCALHOST_UDP_PROXY_MODE=$(config_t_get global localhost_udp_proxy_mode default)
[ "$LOCALHOST_TCP_PROXY_MODE" == "default" ] && LOCALHOST_TCP_PROXY_MODE=$TCP_PROXY_MODE
[ "$LOCALHOST_UDP_PROXY_MODE" == "default" ] && LOCALHOST_UDP_PROXY_MODE=$UDP_PROXY_MODE
global=$(echo "${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${UDP_PROXY_MODE}${LOCALHOST_UDP_PROXY_MODE}" | grep "global")
returnhome=$(echo "${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${UDP_PROXY_MODE}${LOCALHOST_UDP_PROXY_MODE}" | grep "returnhome")
chnlist=$(echo "${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${UDP_PROXY_MODE}${LOCALHOST_UDP_PROXY_MODE}" | grep "chnroute")
gfwlist=$(echo "${TCP_PROXY_MODE}${LOCALHOST_TCP_PROXY_MODE}${UDP_PROXY_MODE}${LOCALHOST_UDP_PROXY_MODE}" | grep "gfwlist")
DNS_SHUNT=$(config_t_get global dns_shunt dnsmasq)
[ -z "$(first_type $DNS_SHUNT)" ] && DNS_SHUNT="dnsmasq"
DNS_MODE=$(config_t_get global dns_mode pdnsd)
DNS_CACHE=$(config_t_get global dns_cache 0)
REMOTE_DNS=$(config_t_get global remote_dns 1.1.1.1:53 | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')
CHINADNS_NG=$(config_t_get global chinadns_ng 0)
filter_proxy_ipv6=$(config_t_get global filter_proxy_ipv6 0)
dns_listen_port=${DNS_PORT}

DEFAULT_DNS=$(uci show dhcp | grep "@dnsmasq" | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | head -2 | sed ':label;N;s/\n/,/;b label')
[ -z "${DEFAULT_DNS}" ] && DEFAULT_DNS=$(echo -n $(sed -n 's/^nameserver[ \t]*\([^ ]*\)$/\1/p' "${RESOLVFILE}" | grep -v -E "0.0.0.0|127.0.0.1|::" | head -2) | tr ' ' ',')
LOCAL_DNS="${DEFAULT_DNS:-119.29.29.29}"

PROXY_IPV6=$(config_t_get global_forwarding ipv6_tproxy 0)
DNS_QUERY_STRATEGY="UseIPv4"
[ "$PROXY_IPV6" = "1" ] && DNS_QUERY_STRATEGY="UseIP"

export V2RAY_LOCATION_ASSET=$(config_t_get global_rules v2ray_location_asset "/usr/share/v2ray/")
export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
mkdir -p /tmp/etc $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ID_PATH $TMP_PORT_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2

arg1=$1
shift
case $arg1 in
get_new_port)
	get_new_port $@
	;;
run_socks)
	run_socks $@
	;;
run_redir)
	run_redir $@
	;;
node_switch)
	node_switch $@
	;;
echolog)
	echolog $@
	;;
stop)
	stop
	;;
start)
	start
	;;
boot)
	boot
	;;
esac
