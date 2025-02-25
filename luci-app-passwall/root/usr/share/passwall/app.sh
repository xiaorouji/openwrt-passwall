#!/bin/sh
# Copyright (C) 2018-2020 L-WRT Team
# Copyright (C) 2021-2025 xiaorouji

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall
TMP_PATH=/tmp/etc/$CONFIG
TMP_BIN_PATH=$TMP_PATH/bin
TMP_SCRIPT_FUNC_PATH=$TMP_PATH/script_func
TMP_ROUTE_PATH=$TMP_PATH/route
TMP_ACL_PATH=$TMP_PATH/acl
TMP_IFACE_PATH=$TMP_PATH/iface
TMP_PATH2=/tmp/etc/${CONFIG}_tmp
GLOBAL_ACL_PATH=${TMP_ACL_PATH}/default
LOG_FILE=/tmp/log/$CONFIG.log
APP_PATH=/usr/share/$CONFIG
RULES_PATH=/usr/share/${CONFIG}/rules
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall
UTIL_SINGBOX=$LUA_UTIL_PATH/util_sing-box.lua
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua
UTIL_TROJAN=$LUA_UTIL_PATH/util_trojan.lua
UTIL_NAIVE=$LUA_UTIL_PATH/util_naiveproxy.lua
UTIL_HYSTERIA2=$LUA_UTIL_PATH/util_hysteria2.lua
UTIL_TUIC=$LUA_UTIL_PATH/util_tuic.lua

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

config_t_set() {
	local index=${4:-0}
	local ret=$(uci -q set "${CONFIG}.@${1}[${index}].${2}=${3}" 2>/dev/null)
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

check_depends() {
	local depends
	local tables=${1}
	local file_path="/usr/lib/opkg/info"
	local file_ext=".control"
	[ -d "/lib/apk/packages" ] && file_path="/lib/apk/packages" && file_ext=".list"
	if [ "$tables" == "iptables" ]; then
		for depends in "iptables-mod-tproxy" "iptables-mod-socket" "iptables-mod-iprange" "iptables-mod-conntrack-extra" "kmod-ipt-nat"; do
			[ -s "${file_path}/${depends}${file_ext}" ] || echolog "$tables透明代理基础依赖 $depends 未安装..."
		done
	else
		for depends in "kmod-nft-socket" "kmod-nft-tproxy" "kmod-nft-nat"; do
			[ -s "${file_path}/${depends}${file_ext}" ] || echolog "$tables透明代理基础依赖 $depends 未安装..."
		done
	fi
}

check_ver() {
	local version1="$1"
	local version2="$2"
	local i v1 v1_1 v1_2 v1_3 v2 v2_1 v2_2 v2_3
	IFS='.'; set -- $version1; v1_1=${1:-0}; v1_2=${2:-0}; v1_3=${3:-0}
	IFS='.'; set -- $version2; v2_1=${1:-0}; v2_2=${2:-0}; v2_3=${3:-0}
	IFS=
	for i in 1 2 3; do
		eval v1=\$v1_$i
		eval v2=\$v2_$i
		if [ "$v1" -gt "$v2" ]; then
			# $1 大于 $2
			echo 0
			return
		elif [ "$v1" -lt "$v2" ]; then
			# $1 小于 $2
			echo 1
			return
		fi
	done
	# $1 等于 $2
	echo 255
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
	[ "${output}" != "/dev/null" ] && [ "${ln_name}" != "chinadns-ng" ] && {
		local persist_log_path=$(config_t_get global persist_log_path)
		local sys_log=$(config_t_get global sys_log "0")
	}
	if [ -z "$persist_log_path" ] && [ "$sys_log" != "1" ]; then
		${file_func:-echolog " - ${ln_name}"} "$@" >${output} 2>&1 &
	else
		[ "${output: -1, -7}" == "TCP.log" ] && local protocol="TCP"
		[ "${output: -1, -7}" == "UDP.log" ] && local protocol="UDP"
		if [ -n "${persist_log_path}" ]; then
			mkdir -p ${persist_log_path}
			local log_file=${persist_log_path}/passwall_${protocol}_${ln_name}_$(date '+%F').log
			echolog "记录到持久性日志文件：${log_file}"
			${file_func:-echolog " - ${ln_name}"} "$@" >> ${log_file} 2>&1 &
			sys_log=0
		fi
		if [ "${sys_log}" == "1" ]; then
			echolog "记录 ${ln_name}_${protocol} 到系统日志"
			${file_func:-echolog " - ${ln_name}"} "$@" 2>&1 | logger -t PASSWALL_${protocol}_${ln_name} &
		fi
	fi
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
	echo $(lua -e "local api = require 'luci.passwall.api' print(api.${func})")
}

parse_doh() {
	local __doh=$1 __url_var=$2 __host_var=$3 __port_var=$4 __bootstrap_var=$5
	__doh=$(echo -e "$__doh" | tr -d ' \t\n')
	local __url=${__doh%%,*}
	local __bootstrap=${__doh#*,}
	local __host_port=$(lua_api "get_domain_from_url(\"${__url}\")")
	local __host __port
	if echo "${__host_port}" | grep -q '^\[.*\]:[0-9]\+$'; then
		__host=${__host_port%%]:*}]
		__port=${__host_port##*:}
	elif echo "${__host_port}" | grep -q ':[0-9]\+$'; then
		__host=${__host_port%:*}
		__port=${__host_port##*:}
	else
		__host=${__host_port}
		__port=443
	fi
	__host=${__host#[}
	__host=${__host%]}
	if [ "$(lua_api "is_ip(\"${__host}\")")" = "true" ]; then
		__bootstrap=${__host}
	fi
	__bootstrap=${__bootstrap#[}
	__bootstrap=${__bootstrap%]}
	eval "${__url_var}='${__url}' ${__host_var}='${__host}' ${__port_var}='${__port}' ${__bootstrap_var}='${__bootstrap}'"
}

get_geoip() {
	local geoip_code="$1"
	local geoip_type_flag=""
	local geoip_path="$(config_t_get global_rules v2ray_location_asset)"
	geoip_path="${geoip_path%*/}/geoip.dat"
	[ -s "$geoip_path" ] || { echo ""; return 1; }
	case "$2" in
		"ipv4") geoip_type_flag="-ipv6=false" ;;
		"ipv6") geoip_type_flag="-ipv4=false" ;;
	esac
	if type geoview &> /dev/null; then
		geoview -input "$geoip_path" -list "$geoip_code" $geoip_type_flag -lowmem=true
		return 0
	else
		echo ""
		return 1
	fi
}

set_cache_var() {
	local key="${1}"
	shift 1
	local val="$@"
	[ -n "${key}" ] && [ -n "${val}" ] && {
		sed -i "/${key}=/d" $TMP_PATH/var >/dev/null 2>&1
		echo "${key}=\"${val}\"" >> $TMP_PATH/var
		eval ${key}=\"${val}\"
	}
}

get_cache_var() {
	local key="${1}"
	[ -n "${key}" ] && [ -s "$TMP_PATH/var" ] && {
		echo $(cat $TMP_PATH/var | grep "^${key}=" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}')
	}
}

eval_cache_var() {
	[ -s "$TMP_PATH/var" ] && eval $(cat "$TMP_PATH/var")
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
	*)
		flag="${flag}_TCP_UDP"
	;;
	esac
	_extra_param="${_extra_param} -v"
	ln_run "$(first_type ipt2socks)" "ipt2socks_${flag}" $log_file -l $local_port -b 0.0.0.0 -s $socks_address -p $socks_port ${_extra_param}
}

run_singbox() {
	local flag type node tcp_redir_port tcp_proxy_way udp_redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy direct_dns_port direct_dns_udp_server direct_dns_tcp_server direct_dns_dot_server remote_dns_protocol remote_dns_udp_server remote_dns_tcp_server remote_dns_doh remote_dns_client_ip remote_fakedns remote_dns_query_strategy dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file server_host server_port
	local _extra_param=""
	eval_set_val $@
	[ -z "$type" ] && {
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		if [ "$type" != "sing-box" ]; then
			bin=$(first_type $(config_t_get global_app singbox_file) sing-box)
			[ -n "$bin" ] && type="sing-box"
		fi
	}
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	if [ "$log_file" = "/dev/null" ]; then
		_extra_param="${_extra_param} -log 0"
	else
		_extra_param="${_extra_param} -log 1 -logfile ${log_file}"
	fi
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warn")
	[ "$loglevel" = "warning" ] && loglevel="warn"
	_extra_param="${_extra_param} -loglevel $loglevel"

	_extra_param="${_extra_param} -tags $($(first_type $(config_t_get global_app singbox_file) sing-box) version | grep 'Tags:' | awk '{print $2}')"

	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$node" ] && _extra_param="${_extra_param} -node $node"
	[ -n "$server_host" ] && _extra_param="${_extra_param} -server_host $server_host"
	[ -n "$server_port" ] && _extra_param="${_extra_param} -server_port $server_port"
	[ -n "$tcp_redir_port" ] && _extra_param="${_extra_param} -tcp_redir_port $tcp_redir_port"
	[ -n "$tcp_proxy_way" ] && _extra_param="${_extra_param} -tcp_proxy_way $tcp_proxy_way"
	[ -n "$udp_redir_port" ] && _extra_param="${_extra_param} -udp_redir_port $udp_redir_port"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"
	[ -n "$dns_socks_address" ] && [ -n "$dns_socks_port" ] && _extra_param="${_extra_param} -dns_socks_address ${dns_socks_address} -dns_socks_port ${dns_socks_port}"
	[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
	[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"

	if [ -n "$direct_dns_udp_server" ]; then
		direct_dns_port=$(echo ${direct_dns_udp_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_udp_server $(echo ${direct_dns_udp_server} | awk -F '#' '{print $1}')"
	elif [ -n "$direct_dns_tcp_server" ]; then
		direct_dns_port=$(echo ${direct_dns_tcp_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_tcp_server $(echo ${direct_dns_tcp_server} | awk -F '#' '{print $1}')"
	elif [ -n "$direct_dns_dot_server" ]; then
		direct_dns_port=$(echo ${direct_dns_dot_server} | awk -F '#' '{print $2}')
		_extra_param="${_extra_param} -direct_dns_dot_server $(echo ${direct_dns_dot_server} | awk -F '#' '{print $1}')"
	else
		local local_dns=$(echo -n $(echo "${LOCAL_DNS}" | sed "s/,/\n/g" | head -n1) | tr " " ",")
		_extra_param="${_extra_param} -direct_dns_udp_server $(echo ${local_dns} | awk -F '#' '{print $1}')"
		direct_dns_port=$(echo ${local_dns} | awk -F '#' '{print $2}')
	fi
	_extra_param="${_extra_param} -direct_dns_port ${direct_dns_port:-53}"
	direct_dns_query_strategy=${direct_dns_query_strategy:-UseIP}
	_extra_param="${_extra_param} -direct_dns_query_strategy ${direct_dns_query_strategy}"

	[ -n "$remote_dns_query_strategy" ] && _extra_param="${_extra_param} -remote_dns_query_strategy ${remote_dns_query_strategy}"
	case "$remote_dns_protocol" in
		tcp)
			local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
			local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
			local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
			_extra_param="${_extra_param} -remote_dns_server ${_dns_address} -remote_dns_port ${_dns_port} -remote_dns_tcp_server tcp://${_dns}"
		;;
		doh)
			local _doh_url _doh_host _doh_port _doh_bootstrap
			parse_doh "$remote_dns_doh" _doh_url _doh_host _doh_port _doh_bootstrap
			[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_server ${_doh_bootstrap}"
			_extra_param="${_extra_param} -remote_dns_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
		;;
	esac
	[ -n "$remote_dns_client_ip" ] && _extra_param="${_extra_param} -remote_dns_client_ip ${remote_dns_client_ip}"
	[ "$remote_fakedns" = "1" ] && _extra_param="${_extra_param} -remote_dns_fake 1"
	lua $UTIL_SINGBOX gen_config ${_extra_param} > $config_file
	ln_run "$(first_type $(config_t_get global_app singbox_file) sing-box)" "sing-box" $log_file run -c "$config_file"
}

run_xray() {
	local flag type node tcp_redir_port tcp_proxy_way udp_redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy remote_dns_udp_server remote_dns_tcp_server remote_dns_doh remote_dns_client_ip remote_fakedns remote_dns_query_strategy dns_cache dns_socks_address dns_socks_port
	local loglevel log_file config_file server_host server_port
	local _extra_param=""
	eval_set_val $@
	[ -z "$type" ] && {
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		if [ "$type" != "xray" ]; then
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && type="xray"
		fi
	}
	[ -z "$type" ] && return 1
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_t_get global loglevel "warning")
	[ -n "$flag" ] && _extra_param="${_extra_param} -flag $flag"
	[ -n "$node" ] && _extra_param="${_extra_param} -node $node"
	[ -n "$server_host" ] && _extra_param="${_extra_param} -server_host $server_host"
	[ -n "$server_port" ] && _extra_param="${_extra_param} -server_port $server_port"
	[ -n "$tcp_redir_port" ] && _extra_param="${_extra_param} -tcp_redir_port $tcp_redir_port"
	[ -n "$tcp_proxy_way" ] && _extra_param="${_extra_param} -tcp_proxy_way $tcp_proxy_way"
	[ -n "$udp_redir_port" ] && _extra_param="${_extra_param} -udp_redir_port $udp_redir_port"
	[ -n "$socks_address" ] && _extra_param="${_extra_param} -local_socks_address $socks_address"
	[ -n "$socks_port" ] && _extra_param="${_extra_param} -local_socks_port $socks_port"
	[ -n "$socks_username" ] && [ -n "$socks_password" ] && _extra_param="${_extra_param} -local_socks_username $socks_username -local_socks_password $socks_password"
	[ -n "$http_address" ] && _extra_param="${_extra_param} -local_http_address $http_address"
	[ -n "$http_port" ] && _extra_param="${_extra_param} -local_http_port $http_port"
	[ -n "$http_username" ] && [ -n "$http_password" ] && _extra_param="${_extra_param} -local_http_username $http_username -local_http_password $http_password"
	[ -n "$dns_socks_address" ] && [ -n "$dns_socks_port" ] && _extra_param="${_extra_param} -dns_socks_address ${dns_socks_address} -dns_socks_port ${dns_socks_port}"
	[ -n "$dns_listen_port" ] && _extra_param="${_extra_param} -dns_listen_port ${dns_listen_port}"
	direct_dns_query_strategy=${direct_dns_query_strategy:-UseIP}
	_extra_param="${_extra_param} -direct_dns_query_strategy ${direct_dns_query_strategy}"
	[ -n "$remote_dns_query_strategy" ] && _extra_param="${_extra_param} -remote_dns_query_strategy ${remote_dns_query_strategy}"
	[ -n "$remote_dns_client_ip" ] && _extra_param="${_extra_param} -remote_dns_client_ip ${remote_dns_client_ip}"
	[ "$remote_fakedns" = "1" ] && _extra_param="${_extra_param} -remote_dns_fake 1"
	[ -n "$dns_cache" ] && _extra_param="${_extra_param} -dns_cache ${dns_cache}"
	[ -n "${remote_dns_tcp_server}" ] && {
		local _dns=$(get_first_dns remote_dns_tcp_server 53 | sed 's/#/:/g')
		local _dns_address=$(echo ${_dns} | awk -F ':' '{print $1}')
		local _dns_port=$(echo ${_dns} | awk -F ':' '{print $2}')
		_extra_param="${_extra_param} -remote_dns_tcp_server ${_dns_address} -remote_dns_tcp_port ${_dns_port}"
	}
	[ -n "${remote_dns_doh}" ] && {
		local _doh_url _doh_host _doh_port _doh_bootstrap
		parse_doh "$remote_dns_doh" _doh_url _doh_host _doh_port _doh_bootstrap
		[ -n "$_doh_bootstrap" ] && _extra_param="${_extra_param} -remote_dns_doh_ip ${_doh_bootstrap}"
		_extra_param="${_extra_param} -remote_dns_doh_port ${_doh_port} -remote_dns_doh_url ${_doh_url} -remote_dns_doh_host ${_doh_host}"
	}
	_extra_param="${_extra_param} -loglevel $loglevel"
	lua $UTIL_XRAY gen_config ${_extra_param} > $config_file
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

run_chinadns_ng() {
	local _flag _listen_port _dns_local _dns_trust _no_ipv6_trust _use_direct_list _use_proxy_list _gfwlist _chnlist _default_mode _default_tag _no_logic_log _tcp_node _remote_fakedns
	local _extra_param=""
	eval_set_val $@

	local _CONF_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.conf
	local _LOG_FILE="/dev/null"
	[ "$(config_t_get global log_chinadns_ng "0")" == "1" ] &&  _LOG_FILE=$TMP_ACL_PATH/$_flag/chinadns_ng.log

	_extra_param="-FLAG ${_flag} -TCP_NODE ${_tcp_node} -LISTEN_PORT ${_listen_port} -DNS_LOCAL ${_dns_local} -DNS_TRUST ${_dns_trust}"
	_extra_param="${_extra_param} -USE_DIRECT_LIST ${_use_direct_list} -USE_PROXY_LIST ${_use_proxy_list} -USE_BLOCK_LIST ${_use_block_list}"
	_extra_param="${_extra_param} -GFWLIST ${_gfwlist} -CHNLIST ${_chnlist} -NO_IPV6_TRUST ${_no_ipv6_trust} -DEFAULT_MODE ${_default_mode}"
	_extra_param="${_extra_param} -DEFAULT_TAG ${_default_tag} -NFTFLAG ${nftflag} -NO_LOGIC_LOG ${_no_logic_log} -REMOTE_FAKEDNS ${_remote_fakedns}"
	_extra_param="${_extra_param} -LOG_FILE ${_LOG_FILE}"

	lua $APP_PATH/helper_chinadns_add.lua ${_extra_param} > ${_CONF_FILE}
	ln_run "$(first_type chinadns-ng)" chinadns-ng "${_LOG_FILE}" -C ${_CONF_FILE}
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

	if [ "$type" == "sing-box" ] || [ "$type" == "xray" ]; then
		local protocol=$(config_n_get $node protocol)
		if [ "$protocol" == "_balancing" ] || [ "$protocol" == "_shunt" ] || [ "$protocol" == "_iface" ] || [ "$protocol" == "_urltest" ]; then
			unset error_msg
		fi
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动中止 ${bind}:${socks_port} ${error_msg}"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && echolog "  - Socks节点：[$remarks]${tmp}，启动 ${bind}:${socks_port}"

	case "$type" in
	socks)
		local _socks_address=$(config_n_get $node address)
		local _socks_port=$(config_n_get $node port)
		local _socks_username=$(config_n_get $node username)
		local _socks_password=$(config_n_get $node password)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		local bin=$(first_type $(config_t_get global_app singbox_file) sing-box)
		if [ -n "$bin" ]; then
			type="sing-box"
			lua $UTIL_SINGBOX gen_proto_config -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} -server_proto socks -server_address ${_socks_address} -server_port ${_socks_port} -server_username ${_socks_username} -server_password ${_socks_password} > $config_file
			ln_run "$bin" ${type} $log_file run -c "$config_file"
		else
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && {
				type="xray"
				lua $UTIL_XRAY gen_proto_config -local_socks_address $bind -local_socks_port $socks_port ${_extra_param} -server_proto socks -server_address ${_socks_address} -server_port ${_socks_port} -server_username ${_socks_username} -server_password ${_socks_password} > $config_file
				ln_run "$bin" ${type} $log_file run -c "$config_file"
			}
		fi
	;;
	sing-box)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _args="http_address=$bind http_port=$http_port"
		}
		[ -n "$relay_port" ] && _args="${_args} server_host=$server_host server_port=$port"
		run_singbox flag=$flag node=$node socks_address=$bind socks_port=$socks_port config_file=$config_file log_file=$log_file ${_args}
	;;
	xray)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _args="http_address=$bind http_port=$http_port"
		}
		[ -n "$relay_port" ] && _args="${_args} server_host=$server_host server_port=$port"
		run_xray flag=$flag node=$node socks_address=$bind socks_port=$socks_port config_file=$config_file log_file=$log_file ${_args}
	;;
	trojan*)
		lua $UTIL_TROJAN gen_config -node $node -run_type client -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
	;;
	naiveproxy)
		lua $UTIL_NAIVE gen_config -node $node -run_type socks -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type naive)" naive $log_file "$config_file"
	;;
	ssr)
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss)
		lua $UTIL_SS gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port -mode tcp_and_udp > $config_file
		ln_run "$(first_type ss-local)" "ss-local" $log_file -c "$config_file" -v
	;;
	ss-rust)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		lua $UTIL_SS gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	hysteria2)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file=$(echo $config_file | sed "s/SOCKS/HTTP_SOCKS/g")
			local _extra_param="-local_http_address $bind -local_http_port $http_port"
		}
		lua $UTIL_HYSTERIA2 gen_config -node $node -local_socks_address $bind -local_socks_port $socks_port -server_host $server_host -server_port $port ${_extra_param} > $config_file
		ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
	;;
	tuic)
		lua $UTIL_TUIC gen_config -node $node -local_addr $bind -local_port $socks_port -server_host $server_host -server_port $port > $config_file
		ln_run "$(first_type tuic-client)" "tuic-client" $log_file -c "$config_file"
	;;
	esac

	set_cache_var "node_${node}_socks_port" "${socks_port}"

	# http to socks
	[ -z "$http_flag" ] && [ "$http_port" != "0" ] && [ -n "$http_config_file" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && [ "$type" != "socks" ] && {
		local bin=$(first_type $(config_t_get global_app singbox_file) sing-box)
		if [ -n "$bin" ]; then
			type="sing-box"
			lua $UTIL_SINGBOX gen_proto_config -local_http_address $bind -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		else
			bin=$(first_type $(config_t_get global_app xray_file) xray)
			[ -n "$bin" ] && type="xray"
			[ -z "$type" ] && return 1
			lua $UTIL_XRAY gen_proto_config local_http_address $bind -local_http_port $http_port -server_proto socks -server_address "127.0.0.1" -server_port $socks_port -server_username $_username -server_password $_password > $http_config_file
			ln_run "$bin" ${type} /dev/null run -c "$http_config_file"
		fi
	}
	unset http_flag

	[ "${server_host}" != "127.0.0.1" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && echo "${node}" >> $TMP_PATH/direct_node_list
}

run_redir() {
	local node proto bind local_port config_file log_file
	eval_set_val $@
	local tcp_node_socks_flag tcp_node_http_flag
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=${GLOBAL_ACL_PATH}/${config_file}
	if [ -n "$log_file" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=${GLOBAL_ACL_PATH}/${log_file}
	else
		log_file="/dev/null"
	fi
	local proto=$(echo $proto | tr 'A-Z' 'a-z')
	local PROTO=$(echo $proto | tr 'a-z' 'A-Z')
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local enable_log=$(config_t_get global log_${proto} 1)
	[ "$enable_log" != "1" ] && log_file="/dev/null"
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local port=$(config_n_get $node port)
	[ -n "$server_host" ] && [ -n "$port" ] && {
		check_host $server_host
		[ $? != 0 ] && {
			echolog "${PROTO}节点：[$remarks]${server_host} 是非法的服务器地址，无法启动！"
			return 1
		}
	}
	[ "$bind" != "127.0.0.1" ] && echolog "${PROTO}节点：[$remarks]，监听端口：$local_port"

	case "$PROTO" in
	UDP)
		case "$type" in
		socks)
			local _socks_address=$(config_n_get $node address)
			local _socks_port=$(config_n_get $node port)
			local _socks_username=$(config_n_get $node username)
			local _socks_password=$(config_n_get $node password)
			run_ipt2socks flag=default proto=UDP local_port=${local_port} socks_address=${_socks_address} socks_port=${_socks_port} socks_username=${_socks_username} socks_password=${_socks_password} log_file=${log_file}
		;;
		sing-box)
			local protocol=$(config_n_get $node protocol)
			[ "$protocol" = "_shunt" ] && {
				local geoip_path="$(config_t_get global_singbox geoip_path)"
				local geosite_path="$(config_t_get global_singbox geosite_path)"
				if [ ! -s "$geoip_path" ] || [ ! -s "$geosite_path" ]; then
					echolog "* 缺少Geo规则文件，UDP Sing-Box分流节点无法正常使用！"
				fi
			}
			run_singbox flag=UDP node=$node udp_redir_port=$local_port config_file=$config_file log_file=$log_file
		;;
		xray)
			local protocol=$(config_n_get $node protocol)
			[ "$protocol" = "_shunt" ] && {
				local geo_path="$(config_t_get global_rules v2ray_location_asset)"
				local geoip_path="${geo_path%*/}/geoip.dat"
				local geosite_path="${geo_path%*/}/geosite.dat"
				if [ ! -s "$geoip_path" ] || [ ! -s "$geosite_path" ]; then
					echolog "* 缺少Geo规则文件，UDP Xray分流节点无法正常使用！"
				fi
			}
			run_xray flag=UDP node=$node udp_redir_port=$local_port config_file=$config_file log_file=$log_file
		;;
		trojan*)
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $UTIL_TROJAN gen_config -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel > $config_file
			ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			echolog "Naiveproxy不支持UDP转发！"
		;;
		ssr)
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(first_type ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v -U
		;;
		ss)
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port -mode udp_only > $config_file
			ln_run "$(first_type ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			lua $UTIL_SS gen_config -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria2)
			lua $UTIL_HYSTERIA2 gen_config -node $node -local_udp_redir_port $local_port > $config_file
			ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
		;;
		tuic)
			echolog "TUIC不支持UDP转发！"
		;;
		esac
	;;
	TCP)
		[ "$TCP_UDP" = "1" ] && echolog "UDP节点：与TCP节点相同"
		tcp_node_socks=1
		tcp_node_socks_bind_local=$(config_t_get global tcp_node_socks_bind_local 1)
		tcp_node_socks_bind="127.0.0.1"
		[ "${tcp_node_socks_bind_local}" != "1" ] && tcp_node_socks_bind="0.0.0.0"
		tcp_node_socks_port=$(get_new_port $(config_t_get global tcp_node_socks_port 1070))
		tcp_node_http_port=$(config_t_get global tcp_node_http_port 0)
		[ "$tcp_node_http_port" != "0" ] && tcp_node_http=1
		if [ $PROXY_IPV6 == "1" ]; then
			echolog "开启实验性IPv6透明代理(TProxy)，请确认您的节点及类型支持IPv6！"
		fi

		if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
			can_ipt=$(echo "$REDIRECT_LIST" | grep "$type")
		elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
			can_ipt=$(echo "$TPROXY_LIST" | grep "$type")
		fi
		[ -z "$can_ipt" ] && type="socks"

		case "$type" in
		socks)
			_socks_flag=1
			_socks_address=$(config_n_get $node address)
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
		sing-box)
			local _flag="TCP"
			local _args=""
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				_args="${_args} socks_address=${tcp_node_socks_bind} socks_port=${tcp_node_socks_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				_args="${_args} http_port=${tcp_node_http_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP/g")
			}
			[ "$TCP_UDP" = "1" ] && {
				UDP_REDIR_PORT=$local_port
				unset UDP_NODE
				_flag="TCP_UDP"
				_args="${_args} udp_redir_port=${UDP_REDIR_PORT}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
			}

			local protocol=$(config_n_get $node protocol)
			local default_node=$(config_n_get $node default_node)
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			[ "${DNS_MODE}" != "sing-box" ] && [ "${DNS_MODE}" != "udp" ] && [ "$protocol" = "_shunt" ] && [ "$default_node" = "_direct" ] && {
				DNS_MODE="sing-box"
				v2ray_dns_mode="tcp"
				echolog "* 当前TCP节点采用Sing-Box分流且默认节点为直连，远程DNS过滤模式将默认使用Sing-Box(TCP)，防止环回！"
			}

			[ "$protocol" = "_shunt" ] && {
				local geoip_path="$(config_t_get global_singbox geoip_path)"
				local geosite_path="$(config_t_get global_singbox geosite_path)"
				if [ ! -s "$geoip_path" ] || [ ! -s "$geosite_path" ]; then
					echolog "* 缺少Geo规则文件，TCP Sing-Box分流节点无法正常使用！"
				fi
			}

			[ "${DNS_MODE}" = "sing-box" ] && {
				NO_PLUGIN_DNS=1
				config_file=$(echo $config_file | sed "s/.json/_DNS.json/g")
				_args="${_args} remote_dns_query_strategy=${REMOTE_DNS_QUERY_STRATEGY}"
				DNSMASQ_FILTER_PROXY_IPV6=0
				local _remote_dns_client_ip=$(config_t_get global remote_dns_client_ip)
				[ -n "${_remote_dns_client_ip}" ] && _args="${_args} remote_dns_client_ip=${_remote_dns_client_ip}"
				[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
				resolve_dns_port=${NEXT_DNS_LISTEN_PORT}
				_args="${_args} dns_listen_port=${resolve_dns_port}"

				case "$(config_t_get global direct_dns_mode "auto")" in
					udp)
						_args="${_args} direct_dns_udp_server=$(config_t_get global direct_dns_udp 223.5.5.5 | sed 's/:/#/g')"
					;;
					tcp)
						_args="${_args} direct_dns_tcp_server=$(config_t_get global direct_dns_tcp 223.5.5.5 | sed 's/:/#/g')"
					;;
					dot)
						local tmp_dot_dns=$(config_t_get global direct_dns_dot "tls://1.12.12.12")
						local tmp_dot_ip=$(echo "$tmp_dot_dns" | sed -n 's/.*:\/\/\([^@#]*@\)*\([^@#]*\).*/\2/p')
						local tmp_dot_port=$(echo "$tmp_dot_dns" | sed -n 's/.*#\([0-9]\+\).*/\1/p')
						_args="${_args} direct_dns_dot_server=$tmp_dot_ip#${tmp_dot_port:-853}"
					;;
				esac

				_args="${_args} remote_dns_protocol=${v2ray_dns_mode}"
				case "$v2ray_dns_mode" in
					tcp)
						_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
						resolve_dns_log="Sing-Box DNS(127.0.0.1#${resolve_dns_port}) -> tcp://${REMOTE_DNS}"
					;;
					doh)
						remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
						_args="${_args} remote_dns_doh=${remote_dns_doh}"
						resolve_dns_log="Sing-Box DNS(127.0.0.1#${resolve_dns_port}) -> ${remote_dns_doh}"
					;;
				esac
				local remote_fakedns=$(config_t_get global remote_fakedns 0)
				[ "${remote_fakedns}" = "1" ] && {
					fakedns=1
					_args="${_args} remote_fakedns=1"
					resolve_dns_log="${resolve_dns_log} + FakeDNS"
				}
				NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
			}
			run_singbox flag=$_flag node=$node tcp_redir_port=$local_port tcp_proxy_way=$TCP_PROXY_WAY config_file=$config_file log_file=$log_file ${_args}
		;;
		xray)
			local _flag="TCP"
			local _args=""
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				_args="${_args} socks_address=${tcp_node_socks_bind} socks_port=${tcp_node_socks_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				_args="${_args} http_port=${tcp_node_http_port}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP/g")
			}
			[ "$TCP_UDP" = "1" ] && {
				UDP_REDIR_PORT=$local_port
				unset UDP_NODE
				_flag="TCP_UDP"
				_args="${_args} udp_redir_port=${UDP_REDIR_PORT}"
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
			}

			local protocol=$(config_n_get $node protocol)
			local default_node=$(config_n_get $node default_node)
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			[ "${DNS_MODE}" != "xray" ] && [ "${DNS_MODE}" != "udp" ] && [ "$protocol" = "_shunt" ] && [ "$default_node" = "_direct" ] && {
				DNS_MODE="xray"
				v2ray_dns_mode="tcp"
				echolog "* 当前TCP节点采用Xray分流且默认节点为直连，远程DNS过滤模式将默认使用Xray(TCP)，防止环回！"
			}

			[ "$protocol" = "_shunt" ] && {
				local geo_path="$(config_t_get global_rules v2ray_location_asset)"
				local geoip_path="${geo_path%*/}/geoip.dat"
				local geosite_path="${geo_path%*/}/geosite.dat"
				if [ ! -s "$geoip_path" ] || [ ! -s "$geosite_path" ]; then
					echolog "* 缺少Geo规则文件，TCP Xray分流节点无法正常使用！"
				fi
			}

			[ "${DNS_MODE}" = "xray" ] && {
				NO_PLUGIN_DNS=1
				config_file=$(echo $config_file | sed "s/.json/_DNS.json/g")
				_args="${_args} remote_dns_query_strategy=${REMOTE_DNS_QUERY_STRATEGY}"
				DNSMASQ_FILTER_PROXY_IPV6=0
				local _remote_dns_client_ip=$(config_t_get global remote_dns_client_ip)
				[ -n "${_remote_dns_client_ip}" ] && _args="${_args} remote_dns_client_ip=${_remote_dns_client_ip}"
				[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
				resolve_dns_port=${NEXT_DNS_LISTEN_PORT}
				_args="${_args} dns_listen_port=${resolve_dns_port}"
				_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
				if [ "$v2ray_dns_mode" = "tcp+doh" ]; then
					remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
					_args="${_args} remote_dns_doh=${remote_dns_doh}"
					resolve_dns_log="Xray DNS(127.0.0.1#${resolve_dns_port}) -> (${remote_dns_doh})(A/AAAA) + tcp://${REMOTE_DNS}"
				else
					resolve_dns_log="Xray DNS(127.0.0.1#${resolve_dns_port}) -> tcp://${REMOTE_DNS}"
				fi
				local remote_fakedns=$(config_t_get global remote_fakedns 0)
				[ "${remote_fakedns}" = "1" ] && {
					fakedns=1
					_args="${_args} remote_fakedns=1"
					resolve_dns_log="${resolve_dns_log} + FakeDNS"
				}
				NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
			}
			run_xray flag=$_flag node=$node tcp_redir_port=$local_port tcp_proxy_way=$TCP_PROXY_WAY config_file=$config_file log_file=$log_file ${_args}
		;;
		trojan*)
			[ "${TCP_PROXY_WAY}" = "tproxy" ] && lua_tproxy_arg="-use_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
			}
			local loglevel=$(config_t_get global trojan_loglevel "2")
			lua $UTIL_TROJAN gen_config -node $node -run_type nat -local_addr "0.0.0.0" -local_port $local_port -loglevel $loglevel $lua_tproxy_arg > $config_file
			ln_run "$(first_type ${type})" "${type}" $log_file -c "$config_file"
		;;
		naiveproxy)
			lua $UTIL_NAIVE gen_config -node $node -run_type redir -local_addr "0.0.0.0" -local_port $local_port > $config_file
			ln_run "$(first_type naive)" naive $log_file "$config_file"
		;;
		ssr)
			[ "${TCP_PROXY_WAY}" = "tproxy" ] && lua_tproxy_arg="-tcp_tproxy true"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
				_extra_param="-u"
			}
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_tproxy_arg > $config_file
			ln_run "$(first_type ssr-redir)" "ssr-redir" $log_file -c "$config_file" -v ${_extra_param}
		;;
		ss)
			[ "${TCP_PROXY_WAY}" = "tproxy" ] && lua_tproxy_arg="-tcp_tproxy true"
			lua_mode_arg="-mode tcp_only"
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
				lua_mode_arg="-mode tcp_and_udp"
			}
			lua $UTIL_SS gen_config -node $node -local_addr "0.0.0.0" -local_port $local_port $lua_mode_arg $lua_tproxy_arg > $config_file
			ln_run "$(first_type ss-redir)" "ss-redir" $log_file -c "$config_file" -v
		;;
		ss-rust)
			local _extra_param="-local_tcp_redir_port $local_port"
			[ "${TCP_PROXY_WAY}" = "tproxy" ] && _extra_param="${_extra_param} -tcp_tproxy true"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
				_extra_param="${_extra_param} -local_socks_address ${tcp_node_socks_bind} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP/g")
				_extra_param="${_extra_param} -local_http_port ${tcp_node_http_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			lua $UTIL_SS gen_config -node $node ${_extra_param} > $config_file
			ln_run "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
		;;
		hysteria2)
			local _extra_param="-local_tcp_redir_port $local_port"
			[ "$tcp_node_socks" = "1" ] && {
				tcp_node_socks_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_SOCKS/g")
				_extra_param="${_extra_param} -local_socks_address ${tcp_node_socks_bind} -local_socks_port ${tcp_node_socks_port}"
			}
			[ "$tcp_node_http" = "1" ] && {
				tcp_node_http_flag=1
				config_file=$(echo $config_file | sed "s/TCP/TCP_HTTP/g")
				_extra_param="${_extra_param} -local_http_port ${tcp_node_http_port}"
			}
			[ "$TCP_UDP" = "1" ] && {
				config_file=$(echo $config_file | sed "s/TCP/TCP_UDP/g")
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
				_extra_param="${_extra_param} -local_udp_redir_port $local_port"
			}
			_extra_param="${_extra_param} -tcp_proxy_way ${TCP_PROXY_WAY}"
			lua $UTIL_HYSTERIA2 gen_config -node $node ${_extra_param} > $config_file
			ln_run "$(first_type $(config_t_get global_app hysteria_file))" "hysteria" $log_file -c "$config_file" client
		;;
		esac
		if [ -n "${_socks_flag}" ]; then
			local _flag="TCP"
			[ "$TCP_UDP" = "1" ] && {
				_flag="TCP_UDP"
				UDP_REDIR_PORT=$TCP_REDIR_PORT
				unset UDP_NODE
			}
			local _socks_tproxy=""
			[ "${TCP_PROXY_WAY}" = "tproxy" ] && _socks_tproxy="1"
			run_ipt2socks flag=default proto=${_flag} tcp_tproxy=${_socks_tproxy} local_port=${local_port} socks_address=${_socks_address} socks_port=${_socks_port} socks_username=${_socks_username} socks_password=${_socks_password} log_file=${log_file}
		fi

		[ -z "$tcp_node_socks_flag" ] && {
			[ "$tcp_node_socks" = "1" ] && {
				local config_file="SOCKS_TCP.json"
				local log_file="SOCKS_TCP.log"
				local http_port=0
				local http_config_file="HTTP2SOCKS_TCP.json"
				[ "$tcp_node_http" = "1" ] && [ -z "$tcp_node_http_flag" ] && {
					http_port=$tcp_node_http_port
				}
				run_socks flag=TCP node=$node bind=$tcp_node_socks_bind socks_port=$tcp_node_socks_port config_file=$config_file http_port=$http_port http_config_file=$http_config_file
			}
		}

		[ "$tcp_node_socks" = "1" ] && {
			TCP_SOCKS_server="127.0.0.1:$tcp_node_socks_port"
			set_cache_var "GLOBAL_TCP_SOCKS_server" "${TCP_SOCKS_server}"
		}
	;;
	esac
	unset tcp_node_socks_flag tcp_node_http_flag
	[ "$type" != "sing-box" ] && [ "$type" != "xray" ] && echo "${node}" >> $TMP_PATH/direct_node_list
	[ -n "${redir_port}" ] && set_cache_var "node_${node}_${PROTO}_redir_port" "${local_port}"
}

start_redir() {
	local proto=${1}
	eval node=\$${proto}_NODE
	if [ -n "$node" ]; then
		TYPE=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		local config_file="${proto}.json"
		local log_file="${proto}.log"
		eval current_port=\$${proto}_REDIR_PORT
		local port=$(echo $(get_new_port $current_port $proto))
		eval ${proto}_REDIR=$port
		run_redir node=$node proto=${proto} bind=0.0.0.0 local_port=$port config_file=$config_file log_file=$log_file
		set_cache_var "ACL_GLOBAL_${proto}_node" "${node}"
		set_cache_var "ACL_GLOBAL_${proto}_redir_port" "${port}"
		[ "$TCP_UDP" = "1" ] && {
			set_cache_var "ACL_GLOBAL_UDP_node" "${node}"
			set_cache_var "ACL_GLOBAL_UDP_redir_port" "${port}"
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
				local node=$(config_n_get $id node)
				[ -z "$node" ] && continue
				local bind_local=$(config_n_get $id bind_local 0)
				local bind="0.0.0.0"
				[ "$bind_local" = "1" ] && bind="127.0.0.1"
				local port=$(config_n_get $id port)
				local config_file="SOCKS_${id}.json"
				local log_file="SOCKS_${id}.log"
				local log=$(config_n_get $id log 1)
				[ "$log" == "0" ] && log_file=""
				local http_port=$(config_n_get $id http_port 0)
				local http_config_file="HTTP2SOCKS_${id}.json"
				run_socks flag=$id node=$node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
				set_cache_var "socks_${id}" "$node"

				#自动切换逻辑
				local enable_autoswitch=$(config_n_get $id enable_autoswitch 0)
				[ "$enable_autoswitch" = "1" ] && $APP_PATH/socks_auto_switch.sh ${id} > /dev/null 2>&1 &
			done
		}
	}
}

socks_node_switch() {
	local flag new_node
	eval_set_val $@
	[ -n "$flag" ] && [ -n "$new_node" ] && {
		pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1 && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf $TMP_PATH/SOCKS_${flag}*
		rm -rf $TMP_PATH/HTTP2SOCKS_${flag}*

		for filename in $(ls ${TMP_SCRIPT_FUNC_PATH}); do
			cmd=$(cat ${TMP_SCRIPT_FUNC_PATH}/${filename})
			[ -n "$(echo $cmd | grep "${flag}")" ] && rm -f ${TMP_SCRIPT_FUNC_PATH}/${filename}
		done
		local bind_local=$(config_n_get $flag bind_local 0)
		local bind="0.0.0.0"
		[ "$bind_local" = "1" ] && bind="127.0.0.1"
		local port=$(config_n_get $flag port)
		local config_file="SOCKS_${flag}.json"
		local log_file="SOCKS_${flag}.log"
		local log=$(config_n_get $flag log 1)
		[ "$log" == "0" ] && log_file=""
		local http_port=$(config_n_get $flag http_port 0)
		local http_config_file="HTTP2SOCKS_${flag}.json"
		LOG_FILE="/dev/null"
		run_socks flag=$flag node=$new_node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
		set_cache_var "socks_${flag}" "$new_node"
		local USE_TABLES=$(get_cache_var "USE_TABLES")
		[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh filter_direct_node_list
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
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	touch /etc/crontabs/root
	#sed -i "/${CONFIG}/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "/etc/init.d/${CONFIG}" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/rule_update.lua log" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/subscribe.lua start" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1

	pgrep -af "${CONFIG}/" | awk '/tasks\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
	rm -rf /tmp/lock/${CONFIG}_tasks.lock
}

start_crontab() {
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		start_daemon=$(config_t_get global_delay start_daemon 0)
		[ "$start_daemon" = "1" ] && $APP_PATH/monitor.sh > /dev/null 2>&1 &
	fi

	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && {
		rm -rf "/tmp/lock/${CONFIG}_cron.lock"
		echolog "当前为计划任务自动运行，不重新配置定时任务。"
		return
	}

	clean_crontab

	[ "$ENABLED" != 1 ] && {
		/etc/init.d/cron restart
		return
	}

	stop_week_mode=$(config_t_get global_delay stop_week_mode)
	stop_time_mode=$(config_t_get global_delay stop_time_mode)
	if [ -n "$stop_week_mode" ]; then
		local t="0 $stop_time_mode * * $stop_week_mode"
		[ "$stop_week_mode" = "7" ] && t="0 $stop_time_mode * * *"
		if [ "$stop_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG stop > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动关闭服务。"
	fi
	start_week_mode=$(config_t_get global_delay start_week_mode)
	start_time_mode=$(config_t_get global_delay start_time_mode)
	if [ -n "$start_week_mode" ]; then
		local t="0 $start_time_mode * * $start_week_mode"
		[ "$start_week_mode" = "7" ] && t="0 $start_time_mode * * *"
		if [ "$start_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG start > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动开启服务。"
	fi
	restart_week_mode=$(config_t_get global_delay restart_week_mode)
	restart_time_mode=$(config_t_get global_delay restart_time_mode)
	if [ -n "$restart_week_mode" ]; then
		local t="0 $restart_time_mode * * $restart_week_mode"
		[ "$restart_week_mode" = "7" ] && t="0 $restart_time_mode * * *"
		if [ "$restart_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG restart > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		echolog "配置定时任务：自动重启服务。"
	fi

	autoupdate=$(config_t_get global_rules auto_update)
	weekupdate=$(config_t_get global_rules week_update)
	dayupdate=$(config_t_get global_rules time_update)
	if [ "$autoupdate" = "1" ]; then
		local t="0 $dayupdate * * $weekupdate"
		[ "$weekupdate" = "7" ] && t="0 $dayupdate * * *"
		if [ "$weekupdate" = "8" ]; then
			update_loop=1
		else
			echo "$t lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
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
			cfgids=$(echo -n $(cat ${TMP_SUB_PATH}/${name}) | sed 's# #,#g')
			local t="0 $time_update * * $week_update"
			[ "$week_update" = "7" ] && t="0 $time_update * * *"
			if [ "$week_update" = "8" ]; then
				update_loop=1
			else
				echo "$t lua $APP_PATH/subscribe.lua start $cfgids cron > /dev/null 2>&1 &" >>/etc/crontabs/root
			fi
		done
		rm -rf $TMP_SUB_PATH
	}

	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		[ "$update_loop" = "1" ] && {
			$APP_PATH/tasks.sh > /dev/null 2>&1 &
			echolog "自动更新：启动循环更新进程。"
		}
	else
		echolog "运行于非代理模式，仅允许服务启停的定时任务。"
	fi

	/etc/init.d/cron restart
}

stop_crontab() {
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	clean_crontab
	/etc/init.d/cron restart
	#echolog "清除定时执行命令。"
}

start_dns() {
	echolog "DNS域名解析："

	local chinadns_tls=$(chinadns-ng -V | grep -i wolfssl)
	local china_ng_local_dns=$(IFS=','; set -- $LOCAL_DNS; [ "${1%%[#:]*}" = "127.0.0.1" ] && echo "$1" || ([ -n "$2" ] && echo "$1,$2" || echo "$1"))
	local sing_box_local_dns=
	local direct_dns_mode=$(config_t_get global direct_dns_mode "auto")

	#获取访问控制节点所使用的DNS分流模式
	local ACL_RULE_DNSMASQ=0
	for acl_section in $(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		if [ "$(config_n_get $acl_section enabled)" = "1" ] && \
		   [ "$(config_n_get $acl_section dns_shunt)" = "dnsmasq" ]; then
			ACL_RULE_DNSMASQ=1
			break
		fi
	done

	case "$direct_dns_mode" in
		udp)
			LOCAL_DNS=$(config_t_get global direct_dns_udp 223.5.5.5 | sed 's/:/#/g')
			china_ng_local_dns=${LOCAL_DNS}
			sing_box_local_dns="direct_dns_udp_server=${LOCAL_DNS}"
		;;
		tcp)	
			local DIRECT_DNS=$(config_t_get global direct_dns_tcp 223.5.5.5 | sed 's/:/#/g')
			china_ng_local_dns="tcp://${DIRECT_DNS}"
			sing_box_local_dns="direct_dns_tcp_server=${DIRECT_DNS}"

			#当全局（包括访问控制节点）开启chinadns-ng时，不启动新进程。
			[ "$DNS_SHUNT" != "chinadns-ng" ] || [ "$ACL_RULE_DNSMASQ" = "1" ] && {
				LOCAL_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
				local china_ng_c_dns="tcp://$(get_first_dns DIRECT_DNS 53 | sed 's/:/#/g')"
				ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${NEXT_DNS_LISTEN_PORT} -c ${china_ng_c_dns} -d chn
				echolog "  - ChinaDNS-NG(${LOCAL_DNS}) -> ${china_ng_c_dns}"
				echolog "  * 请确保上游直连 DNS 支持 TCP 查询。"
				NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
			}
		;;
		dot)
			if [ "$chinadns_tls" != "nil" ]; then
				local DIRECT_DNS=$(config_t_get global direct_dns_dot "tls://1.12.12.12")
				china_ng_local_dns=${DIRECT_DNS}

				#当全局（包括访问控制节点）开启chinadns-ng时，不启动新进程。
				[ "$DNS_SHUNT" != "chinadns-ng" ] || [ "$ACL_RULE_DNSMASQ" = "1" ] && {
					LOCAL_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
					ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${NEXT_DNS_LISTEN_PORT} -c ${DIRECT_DNS} -d chn
					echolog "  - ChinaDNS-NG(${LOCAL_DNS}) -> ${DIRECT_DNS}"
					echolog "  * 请确保上游直连 DNS 支持 DoT 查询。"
					NEXT_DNS_LISTEN_PORT=$(expr $NEXT_DNS_LISTEN_PORT + 1)
				}

				local tmp_dot_ip=$(echo "$DIRECT_DNS" | sed -n 's/.*:\/\/\([^@#]*@\)*\([^@#]*\).*/\2/p')
				local tmp_dot_port=$(echo "$DIRECT_DNS" | sed -n 's/.*#\([0-9]\+\).*/\1/p')
				DIRECT_DNS=$tmp_dot_ip#${tmp_dot_port:-853}
				sing_box_local_dns="direct_dns_dot_server=${DIRECT_DNS}"
			else
				echolog "  - 你的ChinaDNS-NG版本不支持DoT，直连DNS将使用默认地址。"
			fi
		;;
		auto)
			#Automatic logic is already done by default
			:
		;;
	esac

	# 追加直连DNS到iptables/nftables
	[ "$(config_t_get global_haproxy balancing_enable 0)" != "1" ] && IPT_APPEND_DNS=
	add_default_port() {
		[ -z "$1" ] && echo "" || echo "$1" | awk -F',' '{for(i=1;i<=NF;i++){if($i !~ /#/) $i=$i"#53";} print $0;}' OFS=','
	}
	LOCAL_DNS=$(add_default_port "$LOCAL_DNS")
	IPT_APPEND_DNS=$(add_default_port "${IPT_APPEND_DNS:-$LOCAL_DNS}")
	echo "$IPT_APPEND_DNS" | grep -q -E "(^|,)$LOCAL_DNS(,|$)" || IPT_APPEND_DNS="${IPT_APPEND_DNS:+$IPT_APPEND_DNS,}$LOCAL_DNS"
	[ -n "$DIRECT_DNS" ] && {
		DIRECT_DNS=$(add_default_port "$DIRECT_DNS")
		echo "$IPT_APPEND_DNS" | grep -q -E "(^|,)$DIRECT_DNS(,|$)" || IPT_APPEND_DNS="${IPT_APPEND_DNS:+$IPT_APPEND_DNS,}$DIRECT_DNS"
	}
	# 排除127.0.0.1的条目
	IPT_APPEND_DNS=$(echo "$IPT_APPEND_DNS" | awk -F',' '{for(i=1;i<=NF;i++) if($i !~ /^127\.0\.0\.1/) printf (i>1?",":"") $i; print ""}' | sed 's/^,\|,$//g')

	TUN_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
	[ -n "${NO_PLUGIN_DNS}" ] && TUN_DNS="127.0.0.1#${resolve_dns_port}"

	case "$DNS_MODE" in
	dns2socks)
		local dns2socks_socks_server=$(echo $(config_t_get global socks_server 127.0.0.1:1080) | sed "s/#/:/g")
		local dns2socks_forward=$(get_first_dns REMOTE_DNS 53 | sed 's/#/:/g')
		run_dns2socks socks=$dns2socks_socks_server listen_address=127.0.0.1 listen_port=${NEXT_DNS_LISTEN_PORT} dns=$dns2socks_forward cache=$DNS_CACHE
		echolog "  - dns2socks(${TUN_DNS})，${dns2socks_socks_server} -> tcp://${dns2socks_forward}"
	;;
	sing-box)
		[ -z "${NO_PLUGIN_DNS}" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=$TMP_PATH/DNS.log
			local log_file=/dev/null
			local _args="type=$DNS_MODE config_file=$config_file log_file=$log_file"
			[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
			_args="${_args} direct_dns_query_strategy=${DIRECT_DNS_QUERY_STRATEGY}"
			_args="${_args} remote_dns_query_strategy=${REMOTE_DNS_QUERY_STRATEGY}"
			DNSMASQ_FILTER_PROXY_IPV6=0
			local _remote_dns_client_ip=$(config_t_get global remote_dns_client_ip)
			[ -n "${_remote_dns_client_ip}" ] && _args="${_args} remote_dns_client_ip=${_remote_dns_client_ip}"
			TCP_PROXY_DNS=1
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			_args="${_args} dns_listen_port=${NEXT_DNS_LISTEN_PORT}"
			_args="${_args} remote_dns_protocol=${v2ray_dns_mode}"
			case "$v2ray_dns_mode" in
				tcp)
					_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
					echolog "  - Sing-Box DNS(${TUN_DNS}) -> tcp://${REMOTE_DNS}"
				;;
				doh)
					remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
					_args="${_args} remote_dns_doh=${remote_dns_doh}"
					echolog "  - Sing-Box DNS(${TUN_DNS}) -> ${remote_dns_doh}"

					local _doh_url _doh_host _doh_port _doh_bootstrap
					parse_doh "$remote_dns_doh" _doh_url _doh_host _doh_port _doh_bootstrap
					[ -n "${_doh_bootstrap}" ] && REMOTE_DNS="${_doh_bootstrap}#${_doh_port}"
				;;
			esac
			_args="${_args} dns_socks_address=127.0.0.1 dns_socks_port=${tcp_node_socks_port}"
			[ -n "${sing_box_local_dns}" ] && _args="${_args} ${sing_box_local_dns}"
			run_singbox ${_args}
		}
	;;
	xray)
		[ -z "${NO_PLUGIN_DNS}" ] && {
			local config_file=$TMP_PATH/DNS.json
			local log_file=$TMP_PATH/DNS.log
			local log_file=/dev/null
			local _args="type=$DNS_MODE config_file=$config_file log_file=$log_file"
			[ "${DNS_CACHE}" == "0" ] && _args="${_args} dns_cache=0"
			_args="${_args} direct_dns_query_strategy=${DIRECT_DNS_QUERY_STRATEGY}"
			_args="${_args} remote_dns_query_strategy=${REMOTE_DNS_QUERY_STRATEGY}"
			DNSMASQ_FILTER_PROXY_IPV6=0
			local _remote_dns_client_ip=$(config_t_get global remote_dns_client_ip)
			[ -n "${_remote_dns_client_ip}" ] && _args="${_args} remote_dns_client_ip=${_remote_dns_client_ip}"
			TCP_PROXY_DNS=1
			_args="${_args} dns_listen_port=${NEXT_DNS_LISTEN_PORT}"
			_args="${_args} remote_dns_tcp_server=${REMOTE_DNS}"
			local v2ray_dns_mode=$(config_t_get global v2ray_dns_mode tcp)
			if [ "$v2ray_dns_mode" = "tcp+doh" ]; then
				remote_dns_doh=$(config_t_get global remote_dns_doh "https://1.1.1.1/dns-query")
				_args="${_args} remote_dns_doh=${remote_dns_doh}"
				echolog "  - Xray DNS(${TUN_DNS}) -> (${remote_dns_doh})(A/AAAA) + tcp://${REMOTE_DNS}"

				local _doh_url _doh_host _doh_port _doh_bootstrap
				parse_doh "$remote_dns_doh" _doh_url _doh_host _doh_port _doh_bootstrap
				[ -n "${_doh_bootstrap}" ] && REMOTE_DNS="${REMOTE_DNS},${_doh_bootstrap}#${_doh_port}"
			else
				echolog "  - Xray DNS(${TUN_DNS}) -> tcp://${REMOTE_DNS}"
			fi
			_args="${_args} dns_socks_address=127.0.0.1 dns_socks_port=${tcp_node_socks_port}"
			run_xray ${_args}
		}
	;;
	dot)
		TCP_PROXY_DNS=1
		if [ "$chinadns_tls" != "nil" ]; then
			local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
			local china_ng_trust_dns=$(config_t_get global remote_dns_dot "tls://1.1.1.1")
			local tmp_dot_ip=$(echo "$china_ng_trust_dns" | sed -n 's/.*:\/\/\([^@#]*@\)*\([^@#]*\).*/\2/p')
			local tmp_dot_port=$(echo "$china_ng_trust_dns" | sed -n 's/.*#\([0-9]\+\).*/\1/p')
			REMOTE_DNS="$tmp_dot_ip#${tmp_dot_port:-853}"
			[ "$DNS_SHUNT" != "chinadns-ng" ] && {
				[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0 && local no_ipv6_trust="-N"
				ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
				echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
			}
		else
			echolog "  - 你的ChinaDNS-NG版本不支持DoT，远程DNS将默认使用tcp://1.1.1.1"
			REMOTE_DNS="1.1.1.1"
			local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
			local china_ng_trust_dns="tcp://${REMOTE_DNS}"
			[ "$DNS_SHUNT" != "chinadns-ng" ] && {
				[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0 && local no_ipv6_trust="-N"
				ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
				echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
			}
		fi
	;;
	udp)
		UDP_PROXY_DNS=1
		local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
		local china_ng_trust_dns="udp://$(get_first_dns REMOTE_DNS 53 | sed 's/:/#/g')"
		if [ "$DNS_SHUNT" != "chinadns-ng" ] && [ "$FILTER_PROXY_IPV6" = "1" ]; then
			DNSMASQ_FILTER_PROXY_IPV6=0
			local no_ipv6_trust="-N"
			ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
			echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
		else
			TUN_DNS="$(echo ${REMOTE_DNS} | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')"
			echolog "  - udp://${TUN_DNS}"
		fi
	;;
	tcp)
		TCP_PROXY_DNS=1
		local china_ng_listen_port=${NEXT_DNS_LISTEN_PORT}
		local china_ng_trust_dns="tcp://$(get_first_dns REMOTE_DNS 53 | sed 's/:/#/g')"
		[ "$DNS_SHUNT" != "chinadns-ng" ] && {
			[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0 && local no_ipv6_trust="-N"
			ln_run "$(first_type chinadns-ng)" chinadns-ng "/dev/null" -b 127.0.0.1 -l ${china_ng_listen_port} -t ${china_ng_trust_dns} -d gfw ${no_ipv6_trust}
			echolog "  - ChinaDNS-NG(${TUN_DNS}) -> ${china_ng_trust_dns}"
		}
	;;
	esac

	[ -n "${resolve_dns_log}" ] && echolog "  - ${resolve_dns_log}"

	[ -n "${TCP_PROXY_DNS}" ] && echolog "  * 请确认上游 DNS 支持 TCP/DoT/DoH 查询，如非直连地址，确保 TCP 代理打开，并且已经正确转发！"
	[ -n "${UDP_PROXY_DNS}" ] && echolog "  * 请确认上游 DNS 支持 UDP 查询并已使用 UDP 节点，如上游 DNS 非直连地址，确保 UDP 代理打开，并且已经正确转发！"

	[ "${DNS_SHUNT}" = "smartdns" ] && {
		if command -v smartdns > /dev/null 2>&1; then
			rm -rf $TMP_PATH2/dnsmasq_default*
			local group_domestic=$(config_t_get global group_domestic)
			local smartdns_remote_dns=$(config_t_get global smartdns_remote_dns)
			if [ -n "${smartdns_remote_dns}" -a "${smartdns_remote_dns}" != "nil" ]; then
				smartdns_remote_dns=$(echo ${smartdns_remote_dns} | tr -s ' ' '|')
			else
				smartdns_remote_dns="tcp://1.1.1.1"
			fi
			lua $APP_PATH/helper_smartdns_add.lua -FLAG "default" -SMARTDNS_CONF "/tmp/etc/smartdns/$CONFIG.conf" \
				-LOCAL_GROUP ${group_domestic:-nil} -REMOTE_GROUP "passwall_proxy" -REMOTE_PROXY_SERVER ${TCP_SOCKS_server} -USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" \
				-REMOTE_DNS ${smartdns_remote_dns} -DNS_MODE ${DNS_MODE:-socks} -TUN_DNS ${TUN_DNS} -REMOTE_FAKEDNS ${fakedns:-0} \
				-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
				-TCP_NODE ${TCP_NODE} -DEFAULT_PROXY_MODE "${TCP_PROXY_MODE}" -NO_PROXY_IPV6 ${FILTER_PROXY_IPV6:-0} -NFTFLAG ${nftflag:-0} \
				-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
			source $APP_PATH/helper_smartdns.sh restart
			echolog "  - 域名解析：使用SmartDNS，请确保配置正常。"
			return
		else
			DNS_SHUNT="dnsmasq"
			echolog "  * 未安装SmartDNS，默认使用Dnsmasq进行域名解析！"
		fi
	}

	[ "$DNS_SHUNT" = "chinadns-ng" ] && [ -n "$(first_type chinadns-ng)" ] && {
		chinadns_ng_min=2024.04.13
		chinadns_ng_now=$(chinadns-ng -V | grep -i "ChinaDNS-NG " | awk '{print $2}')
		if [ $(check_ver "$chinadns_ng_now" "$chinadns_ng_min") = 1 ]; then
			echolog "  * 注意：当前 ChinaDNS-NG 版本为[ $chinadns_ng_now ]，请更新到[ $chinadns_ng_min ]或以上版本，否则 DNS 有可能无法正常工作！"
		fi

		[ "$FILTER_PROXY_IPV6" = "1" ] && DNSMASQ_FILTER_PROXY_IPV6=0
		[ -z "${china_ng_listen_port}" ] && local china_ng_listen_port=$(expr $NEXT_DNS_LISTEN_PORT + 1)
		local china_ng_listen="127.0.0.1#${china_ng_listen_port}"
		[ -z "${china_ng_trust_dns}" ] && local china_ng_trust_dns=${TUN_DNS}

		echolog "  - ChinaDNS-NG(${china_ng_listen})：直连DNS：${china_ng_local_dns}，可信DNS：${china_ng_trust_dns}"

		run_chinadns_ng \
			_flag="default" \
			_listen_port=${china_ng_listen_port} \
			_dns_local=${china_ng_local_dns} \
			_dns_trust=${china_ng_trust_dns} \
			_no_ipv6_trust=${FILTER_PROXY_IPV6} \
			_use_direct_list=${USE_DIRECT_LIST} \
			_use_proxy_list=${USE_PROXY_LIST} \
			_use_block_list=${USE_BLOCK_LIST} \
			_gfwlist=${USE_GFW_LIST} \
			_chnlist=${CHN_LIST} \
			_default_mode=${TCP_PROXY_MODE} \
			_default_tag=$(config_t_get global chinadns_ng_default_tag smart) \
			_no_logic_log=0 \
			_tcp_node=${TCP_NODE} \
			_remote_fakedns=${fakedns:-0}

		USE_DEFAULT_DNS="chinadns_ng"
	}

	[ "$USE_DEFAULT_DNS" = "remote" ] && {
		dnsmasq_version=$(dnsmasq -v | grep -i "Dnsmasq version " | awk '{print $3}')
		[ "$(expr $dnsmasq_version \>= 2.87)" == 0 ] && echolog "Dnsmasq版本低于2.87，有可能无法正常使用！！！"
	}

	local DNSMASQ_TUN_DNS=$(get_first_dns TUN_DNS 53 | sed 's/:/#/g')
	local RUN_NEW_DNSMASQ=1
	RUN_NEW_DNSMASQ=${DNS_REDIRECT}
	if [ "${RUN_NEW_DNSMASQ}" == "0" ]; then
		#The old logic will be removed in the future.
		#Run a copy dnsmasq instance, DNS hijack that don't need a proxy devices.
		[ "1" = "0" ] && {
			DIRECT_DNSMASQ_PORT=$(get_new_port 11400)
			DIRECT_DNSMASQ_CONF=${GLOBAL_ACL_PATH}/direct_dnsmasq.conf
			DIRECT_DNSMASQ_CONF_PATH=${GLOBAL_ACL_PATH}/direct_dnsmasq.d
			mkdir -p ${DIRECT_DNSMASQ_CONF_PATH}
			lua $APP_PATH/helper_dnsmasq.lua copy_instance -LISTEN_PORT ${DIRECT_DNSMASQ_PORT} -DNSMASQ_CONF ${DIRECT_DNSMASQ_CONF} -TMP_DNSMASQ_PATH ${DIRECT_DNSMASQ_CONF_PATH}
			ln_run "$(first_type dnsmasq)" "dnsmasq_direct" "/dev/null" -C ${DIRECT_DNSMASQ_CONF} -x ${GLOBAL_ACL_PATH}/direct_dnsmasq.pid
			echo "${DIRECT_DNSMASQ_PORT}" > ${GLOBAL_ACL_PATH}/direct_dnsmasq_port
		}
		
		#Rewrite the default DNS service configuration
		#Modify the default dnsmasq service
		lua $APP_PATH/helper_dnsmasq.lua stretch
		lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "default" -TMP_DNSMASQ_PATH ${GLOBAL_DNSMASQ_CONF_PATH} -DNSMASQ_CONF_FILE ${GLOBAL_DNSMASQ_CONF} \
			-DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS ${LOCAL_DNS} -TUN_DNS ${DNSMASQ_TUN_DNS} \
			-REMOTE_FAKEDNS ${fakedns:-0} -USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" -CHINADNS_DNS ${china_ng_listen:-0} \
			-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
			-TCP_NODE ${TCP_NODE} -DEFAULT_PROXY_MODE ${TCP_PROXY_MODE} -NO_PROXY_IPV6 ${DNSMASQ_FILTER_PROXY_IPV6:-0} -NFTFLAG ${nftflag:-0} \
			-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
		uci -q add_list dhcp.@dnsmasq[0].addnmount=${GLOBAL_DNSMASQ_CONF_PATH}
		uci -q commit dhcp
		lua $APP_PATH/helper_dnsmasq.lua logic_restart -LOG 1
	else
		#Run a copy dnsmasq instance, DNS hijack for that need proxy devices.
		GLOBAL_DNSMASQ_PORT=$(get_new_port 11400)
		GLOBAL_DNSMASQ_CONF=${GLOBAL_ACL_PATH}/dnsmasq.conf
		GLOBAL_DNSMASQ_CONF_PATH=${GLOBAL_ACL_PATH}/dnsmasq.d
		lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG "default" -TMP_DNSMASQ_PATH ${GLOBAL_DNSMASQ_CONF_PATH} -DNSMASQ_CONF_FILE ${GLOBAL_DNSMASQ_CONF} \
			-LISTEN_PORT ${GLOBAL_DNSMASQ_PORT} -DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS ${LOCAL_DNS} -TUN_DNS ${DNSMASQ_TUN_DNS} \
			-REMOTE_FAKEDNS ${fakedns:-0} -USE_DEFAULT_DNS "${USE_DEFAULT_DNS:-direct}" -CHINADNS_DNS ${china_ng_listen:-0} \
			-USE_DIRECT_LIST "${USE_DIRECT_LIST}" -USE_PROXY_LIST "${USE_PROXY_LIST}" -USE_BLOCK_LIST "${USE_BLOCK_LIST}" -USE_GFW_LIST "${USE_GFW_LIST}" -CHN_LIST "${CHN_LIST}" \
			-TCP_NODE ${TCP_NODE} -DEFAULT_PROXY_MODE ${TCP_PROXY_MODE} -NO_PROXY_IPV6 ${DNSMASQ_FILTER_PROXY_IPV6:-0} -NFTFLAG ${nftflag:-0} \
			-NO_LOGIC_LOG ${NO_LOGIC_LOG:-0}
		ln_run "$(first_type dnsmasq)" "dnsmasq_default" "/dev/null" -C ${GLOBAL_DNSMASQ_CONF} -x ${GLOBAL_ACL_PATH}/dnsmasq.pid
		set_cache_var "ACL_default_dns_port" "${GLOBAL_DNSMASQ_PORT}"
		DNS_REDIRECT_PORT=${GLOBAL_DNSMASQ_PORT}
	fi
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
		local interface
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

start_haproxy() {
	[ "$(config_t_get global_haproxy balancing_enable 0)" != "1" ] && return
	haproxy_path=$TMP_PATH/haproxy
	haproxy_conf="config.cfg"
	lua $APP_PATH/haproxy.lua -path ${haproxy_path} -conf ${haproxy_conf} -dns ${LOCAL_DNS}
	ln_run "$(first_type haproxy)" haproxy "/dev/null" -f "${haproxy_path}/${haproxy_conf}"
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}

acl_app() {
	local items=$(uci show ${CONFIG} | grep "=acl_rule" | cut -d '.' -sf 2 | cut -d '=' -sf 1)
	[ -n "$items" ] && {
		local item
		local socks_port redir_port dns_port dnsmasq_port chinadns_port
		local msg msg2
		socks_port=11100
		redir_port=11200
		dns_port=11300
		dnsmasq_port=${GLOBAL_DNSMASQ_PORT:-11400}
		chinadns_port=11500
		for item in $items; do
			sid=$(uci -q show "${CONFIG}.${item}" | grep "=acl_rule" | awk -F '=' '{print $1}' | awk -F '.' '{print $2}')
			eval $(uci -q show "${CONFIG}.${item}" | cut -d'.' -sf 3-)

			[ "$enabled" = "1" ] || continue

			if [ -n "${sources}" ]; then
				for s in $sources; do
					local s2
					is_iprange=$(lua_api "iprange(\"${s}\")")
					if [ "${is_iprange}" = "true" ]; then
						s2="iprange:${s}"
					elif [ -n "$(echo ${s} | grep '^ipset:')" ]; then
						s2="ipset:${s}"
					else
						_ip_or_mac=$(lua_api "ip_or_mac(\"${s}\")")
						if [ "${_ip_or_mac}" = "ip" ]; then
							s2="ip:${s}"
						elif [ "${_ip_or_mac}" = "mac" ]; then
							s2="mac:${s}"
						fi
					fi
					[ -n "${s2}" ] && source_list="${source_list}\n${s2}"
					unset s2
				done
			else
				source_list="any"
			fi

			local acl_path=${TMP_ACL_PATH}/$sid
			mkdir -p ${acl_path}
			[ -n "${source_list}" ] && echo -e "${source_list}" | sed '/^$/d' > ${acl_path}/source_list

			use_global_config=${use_global_config:-0}
			[ "${use_global_config}" = "1" ] && {
				tcp_node="default"
				udp_node="default"
			}
			tcp_no_redir_ports=${tcp_no_redir_ports:-${TCP_NO_REDIR_PORTS}}
			udp_no_redir_ports=${udp_no_redir_ports:-${UDP_NO_REDIR_PORTS}}
			if [ "$tcp_no_redir_ports" == "1:65535" ] && [ "$udp_no_redir_ports" == "1:65535" ]; then
				unset use_global_config
				unset tcp_node
				unset udp_node
			else
				use_direct_list=${use_direct_list:-1}
				use_proxy_list=${use_proxy_list:-1}
				use_block_list=${use_block_list:-1}
				use_gfw_list=${use_gfw_list:-1}
				chn_list=${chn_list:-direct}
				tcp_proxy_mode=${tcp_proxy_mode:-proxy}
				udp_proxy_mode=${udp_proxy_mode:-proxy}
				filter_proxy_ipv6=${filter_proxy_ipv6:-0}
				dnsmasq_filter_proxy_ipv6=${filter_proxy_ipv6}
				dns_shunt=${dns_shunt:-dnsmasq}
				dns_mode=${dns_mode:-dns2socks}
				remote_dns=${remote_dns:-1.1.1.1}
				use_default_dns=${use_default_dns:-direct}
				[ "$dns_mode" = "sing-box" ] && {
					[ "$v2ray_dns_mode" = "doh" ] && remote_dns=${remote_dns_doh:-https://1.1.1.1/dns-query}
				}
			fi

			[ -n "$tcp_node" ] && {
				local GLOBAL_TCP_NODE=$(get_cache_var "ACL_GLOBAL_TCP_node")
				[ -n "${GLOBAL_TCP_NODE}" ] && GLOBAL_TCP_redir_port=$(get_cache_var "ACL_GLOBAL_TCP_redir_port")
				if [ "$tcp_node" = "default" ]; then
					if [ -n "${GLOBAL_TCP_NODE}" ]; then
						set_cache_var "ACL_${sid}_tcp_node" "${GLOBAL_TCP_NODE}"
						set_cache_var "ACL_${sid}_tcp_redir_port" "${GLOBAL_TCP_redir_port}"
						set_cache_var "ACL_${sid}_dns_port" "${GLOBAL_DNSMASQ_PORT}"
						set_cache_var "ACL_${sid}_tcp_default" "1"
					else
						echolog "  - 全局节点未启用，跳过【${remarks}】"
					fi
				else
					[ "$(config_get_type $tcp_node)" = "nodes" ] && {
						if [ -n "${GLOBAL_TCP_NODE}" ] && [ "$tcp_node" = "${GLOBAL_TCP_NODE}" ]; then
							set_cache_var "ACL_${sid}_tcp_node" "${GLOBAL_TCP_NODE}"
							set_cache_var "ACL_${sid}_tcp_redir_port" "${GLOBAL_TCP_redir_port}"
							set_cache_var "ACL_${sid}_dns_port" "${GLOBAL_DNSMASQ_PORT}"
							set_cache_var "ACL_${sid}_tcp_default" "1"
						else
							run_dns() {
								local _dns_port
								[ -n $1 ] && _dns_port=$1
								[ -z ${_dns_port} ] && {
									dns_port=$(get_new_port $(expr $dns_port + 1))
									_dns_port=$dns_port
									if [ "$dns_mode" = "dns2socks" ]; then
										run_dns2socks flag=acl_${sid} socks_address=127.0.0.1 socks_port=$socks_port listen_address=0.0.0.0 listen_port=${_dns_port} dns=$remote_dns cache=1
									elif [ "$dns_mode" = "sing-box" -o "$dns_mode" = "xray" ]; then
										config_file=$TMP_ACL_PATH/${tcp_node}_SOCKS_${socks_port}_DNS.json
										[ "$dns_mode" = "xray" ] && [ "$v2ray_dns_mode" = "tcp+doh" ] && remote_dns_doh=${remote_dns_doh:-https://1.1.1.1/dns-query}
										local type=${dns_mode}
										[ "${dns_mode}" = "sing-box" ] && type="singbox"
										dnsmasq_filter_proxy_ipv6=0
										remote_dns_query_strategy="UseIP"
										[ "$filter_proxy_ipv6" = "1" ] && remote_dns_query_strategy="UseIPv4"
										run_${type} flag=acl_${sid} type=$dns_mode dns_socks_address=127.0.0.1 dns_socks_port=$socks_port dns_listen_port=${_dns_port} remote_dns_protocol=${v2ray_dns_mode} remote_dns_tcp_server=${remote_dns} remote_dns_doh="${remote_dns_doh}" remote_dns_query_strategy=${remote_dns_query_strategy} remote_dns_client_ip=${remote_dns_client_ip} config_file=$config_file
									fi
									set_cache_var "node_${tcp_node}_$(echo -n "${remote_dns}" | md5sum | cut -d " " -f1)" "${_dns_port}"
								}

								[ "$dns_shunt" = "chinadns-ng" ] && [ -n "$(first_type chinadns-ng)" ] && {
									chinadns_ng_min=2024.04.13
									chinadns_ng_now=$(chinadns-ng -V | grep -i "ChinaDNS-NG " | awk '{print $2}')
									if [ $(check_ver "$chinadns_ng_now" "$chinadns_ng_min") = 1 ]; then
										echolog "  * 注意：当前 ChinaDNS-NG 版本为[ $chinadns_ng_now ]，请更新到[ $chinadns_ng_min ]或以上版本，否则 DNS 有可能无法正常工作！"
									fi

									[ "$filter_proxy_ipv6" = "1" ] && dnsmasq_filter_proxy_ipv6=0
									chinadns_port=$(expr $chinadns_port + 1)
									_china_ng_listen="127.0.0.1#${chinadns_port}"

									_chinadns_local_dns=$(IFS=','; set -- $LOCAL_DNS; [ "${1%%[#:]*}" = "127.0.0.1" ] && echo "$1" || ([ -n "$2" ] && echo "$1,$2" || echo "$1"))
									_direct_dns_mode=$(config_t_get global direct_dns_mode "auto")
									case "${_direct_dns_mode}" in
										udp)
											_chinadns_local_dns=$(config_t_get global direct_dns_udp 223.5.5.5 | sed 's/:/#/g')
										;;
										tcp)
											_chinadns_local_dns="tcp://$(config_t_get global direct_dns_tcp 223.5.5.5 | sed 's/:/#/g')"
										;;
										dot)
											if [ "$(chinadns-ng -V | grep -i wolfssl)" != "nil" ]; then
												_chinadns_local_dns=$(config_t_get global direct_dns_dot "tls://1.12.12.12")
											fi
										;;
									esac

									run_chinadns_ng \
										_flag="$sid" \
										_listen_port=${chinadns_port} \
										_dns_local=${_chinadns_local_dns} \
										_dns_trust=127.0.0.1#${_dns_port} \
										_no_ipv6_trust=${filter_proxy_ipv6} \
										_use_direct_list=${use_direct_list} \
										_use_proxy_list=${use_proxy_list} \
										_use_block_list=${use_block_list} \
										_gfwlist=${use_gfw_list} \
										_chnlist=${chn_list} \
										_default_mode=${tcp_proxy_mode} \
										_default_tag=${chinadns_ng_default_tag:-smart} \
										_no_logic_log=1 \
										_tcp_node=${tcp_node} \
										_remote_fakedns=0

									use_default_dns="chinadns_ng"
								}

								dnsmasq_port=$(get_new_port $(expr $dnsmasq_port + 1))
								local dnsmasq_conf=${acl_path}/dnsmasq.conf
								local dnsmasq_conf_path=${acl_path}/dnsmasq.d
								lua $APP_PATH/helper_dnsmasq.lua add_rule -FLAG ${sid} -TMP_DNSMASQ_PATH ${dnsmasq_conf_path} -DNSMASQ_CONF_FILE ${dnsmasq_conf} \
									-LISTEN_PORT ${dnsmasq_port} -DEFAULT_DNS ${DEFAULT_DNS} -LOCAL_DNS $LOCAL_DNS \
									-USE_DIRECT_LIST "${use_direct_list}" -USE_PROXY_LIST "${use_proxy_list}" -USE_BLOCK_LIST "${use_block_list}" -USE_GFW_LIST "${use_gfw_list}" -CHN_LIST "${chn_list}" \
									-TUN_DNS "127.0.0.1#${_dns_port}" -REMOTE_FAKEDNS 0 -USE_DEFAULT_DNS "${use_default_dns:-direct}" -CHINADNS_DNS ${_china_ng_listen:-0} \
									-TCP_NODE $tcp_node -DEFAULT_PROXY_MODE ${tcp_proxy_mode} -NO_PROXY_IPV6 ${dnsmasq_filter_proxy_ipv6:-0} -NFTFLAG ${nftflag:-0} \
									-NO_LOGIC_LOG 1
								ln_run "$(first_type dnsmasq)" "dnsmasq_${sid}" "/dev/null" -C ${dnsmasq_conf} -x ${acl_path}/dnsmasq.pid
								set_cache_var "ACL_${sid}_dns_port" "${dnsmasq_port}"
								set_cache_var "node_${tcp_node}_$(echo -n "${tcp_proxy_mode}${remote_dns}" | md5sum | cut -d " " -f1)" "${dnsmasq_port}"
							}
							_redir_port=$(get_cache_var "node_${tcp_node}_redir_port")
							_socks_port=$(get_cache_var "node_${tcp_node}_socks_port")
							if [ -n "${_socks_port}" ] && [ -n "${_redir_port}" ]; then
								socks_port=${_socks_port}
								tcp_port=${_redir_port}
								_dnsmasq_port=$(get_cache_var "node_${tcp_node}_$(echo -n "${tcp_proxy_mode}${remote_dns}" | md5sum | cut -d " " -f1)")
								if [ -z "${_dnsmasq_port}" ]; then
									_dns_port=$(get_cache_var "node_${tcp_node}_$(echo -n "${remote_dns}" | md5sum | cut -d " " -f1)")
									run_dns ${_dns_port}
								else
									[ -n "${_dnsmasq_port}" ] && set_cache_var "ACL_${sid}_dns_port" "${_dnsmasq_port}"
								fi
							else
								socks_port=$(get_new_port $(expr $socks_port + 1))
								set_cache_var "node_${tcp_node}_socks_port" "${socks_port}"
								redir_port=$(get_new_port $(expr $redir_port + 1))
								set_cache_var "node_${tcp_node}_redir_port" "${redir_port}"
								tcp_port=$redir_port

								local type=$(echo $(config_n_get $tcp_node type) | tr 'A-Z' 'a-z')
								if [ -n "${type}" ] && ([ "${type}" = "sing-box" ] || [ "${type}" = "xray" ]); then
									config_file="acl/${tcp_node}_TCP_${redir_port}.json"
									_extra_param="socks_address=127.0.0.1 socks_port=$socks_port"
									_extra_param="${_extra_param} tcp_proxy_way=$TCP_PROXY_WAY"
									if [ "$dns_mode" = "sing-box" ] || [ "$dns_mode" = "xray" ]; then
										dns_port=$(get_new_port $(expr $dns_port + 1))
										_dns_port=$dns_port
										config_file=$(echo $config_file | sed "s/TCP_/DNS_${_dns_port}_TCP_/g")
										remote_dns_doh=${remote_dns}
										dnsmasq_filter_proxy_ipv6=0
										remote_dns_query_strategy="UseIP"
										[ "$filter_proxy_ipv6" = "1" ] && remote_dns_query_strategy="UseIPv4"
										[ "$dns_mode" = "xray" ] && [ "$v2ray_dns_mode" = "tcp+doh" ] && remote_dns_doh=${remote_dns_doh:-https://1.1.1.1/dns-query}
										_extra_param="dns_listen_port=${_dns_port} remote_dns_protocol=${v2ray_dns_mode} remote_dns_tcp_server=${remote_dns} remote_dns_doh=${remote_dns_doh} remote_dns_query_strategy=${remote_dns_query_strategy} remote_dns_client_ip=${remote_dns_client_ip}"
									fi
									[ -n "$udp_node" ] && ([ "$udp_node" = "tcp" ] || [ "$udp_node" = "$tcp_node" ]) && {
										config_file=$(echo $config_file | sed "s/TCP_/TCP_UDP_/g")
										_extra_param="${_extra_param} udp_redir_port=$redir_port"
									}
									config_file="$TMP_PATH/$config_file"
									[ "${type}" = "sing-box" ] && type="singbox"
									run_${type} flag=$tcp_node node=$tcp_node tcp_redir_port=$redir_port ${_extra_param} config_file=$config_file
								else
									config_file="acl/${tcp_node}_SOCKS_${socks_port}.json"
									run_socks flag=$tcp_node node=$tcp_node bind=127.0.0.1 socks_port=$socks_port config_file=$config_file
									local log_file=$TMP_ACL_PATH/ipt2socks_${tcp_node}_${redir_port}.log
									log_file="/dev/null"
									run_ipt2socks flag=acl_${tcp_node} tcp_tproxy=${is_tproxy} local_port=$redir_port socks_address=127.0.0.1 socks_port=$socks_port log_file=$log_file
								fi
								run_dns ${_dns_port}
							fi
							set_cache_var "ACL_${sid}_tcp_node" "${tcp_node}"
							set_cache_var "ACL_${sid}_tcp_redir_port" "${redir_port}"
						fi
					}
				fi
			}
			[ -n "$udp_node" ] && {
				if [ "$udp_node" = "default" ]; then
					local GLOBAL_UDP_NODE=$(get_cache_var "ACL_GLOBAL_UDP_node")
					[ -n "${GLOBAL_UDP_NODE}" ] && GLOBAL_UDP_redir_port=$(get_cache_var "ACL_GLOBAL_UDP_redir_port")
					if [ -n "${GLOBAL_UDP_NODE}" ]; then
						set_cache_var "ACL_${sid}_udp_node" "${GLOBAL_UDP_NODE}"
						set_cache_var "ACL_${sid}_udp_redir_port" "${GLOBAL_UDP_redir_port}"
						set_cache_var "ACL_${sid}_udp_default" "1"
					else
						echolog "  - 全局节点未启用，跳过【${remarks}】"
					fi
				elif [ "$udp_node" = "tcp" ]; then
					udp_node=$(get_cache_var "ACL_${sid}_tcp_node")
					udp_port=$(get_cache_var "ACL_${sid}_tcp_port")
					set_cache_var "ACL_${sid}_udp_node" "${udp_node}"
					set_cache_var "ACL_${sid}_udp_redir_port" "${udp_port}"
				else
					[ "$(config_get_type $udp_node)" = "nodes" ] && {
						if [ -n "${GLOBAL_UDP_NODE}" ] && [ "$udp_node" = "${GLOBAL_UDP_NODE}" ]; then
							set_cache_var "ACL_${sid}_udp_node" "${GLOBAL_UDP_NODE}"
							set_cache_var "ACL_${sid}_udp_redir_port" "${GLOBAL_UDP_redir_port}"
							set_cache_var "ACL_${sid}_udp_default" "1"
						else
							_redir_port=$(get_cache_var "node_${udp_node}_redir_port")
							_socks_port=$(get_cache_var "node_${udp_node}_socks_port")
							if [ -n "${_socks_port}" ] && [ -n "${_redir_port}" ]; then
								socks_port=${_socks_port}
								udp_port=${_redir_port}
							else
								socks_port=$(get_new_port $(expr $socks_port + 1))
								set_cache_var "node_${udp_node}_socks_port" "${socks_port}"
								redir_port=$(get_new_port $(expr $redir_port + 1))
								set_cache_var "node_${udp_node}_redir_port" "${redir_port}"
								udp_port=$redir_port

								local type=$(echo $(config_n_get $udp_node type) | tr 'A-Z' 'a-z')
								if [ -n "${type}" ] && ([ "${type}" = "sing-box" ] || [ "${type}" = "xray" ]); then
									config_file="acl/${udp_node}_UDP_${redir_port}.json"
									config_file="$TMP_PATH/$config_file"
									[ "${type}" = "sing-box" ] && type="singbox"
									run_${type} flag=$udp_node node=$udp_node udp_redir_port=$redir_port config_file=$config_file
								else
									config_file="acl/${udp_node}_SOCKS_${socks_port}.json"
									run_socks flag=$udp_node node=$udp_node bind=127.0.0.1 socks_port=$socks_port config_file=$config_file
									local log_file=$TMP_ACL_PATH/ipt2socks_${udp_node}_${redir_port}.log
									log_file="/dev/null"
									run_ipt2socks flag=acl_${udp_node} local_port=$redir_port socks_address=127.0.0.1 socks_port=$socks_port log_file=$log_file
								fi
							fi
							set_cache_var "ACL_${sid}_udp_node" "${udp_node}"
							set_cache_var "ACL_${sid}_udp_redir_port" "${redir_port}"
						fi
					}
				fi
			}
			unset enabled sid remarks sources interface tcp_no_redir_ports udp_no_redir_ports use_global_config tcp_node udp_node use_direct_list use_proxy_list use_block_list use_gfw_list chn_list tcp_proxy_mode udp_proxy_mode filter_proxy_ipv6 dns_mode remote_dns v2ray_dns_mode remote_dns_doh remote_dns_client_ip
			unset _ip _mac _iprange _ipset _ip_or_mac source_list tcp_port udp_port config_file _extra_param
			unset _china_ng_listen _chinadns_local_dns _direct_dns_mode chinadns_ng_default_tag dnsmasq_filter_proxy_ipv6
		done
		unset socks_port redir_port dns_port dnsmasq_port chinadns_port
	}
}

start() {
	mkdir -p /tmp/etc $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2
	get_config
	export V2RAY_LOCATION_ASSET=$(config_t_get global_rules v2ray_location_asset "/usr/share/v2ray/")
	export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
	export ENABLE_DEPRECATED_GEOSITE=true
	export ENABLE_DEPRECATED_GEOIP=true
	ulimit -n 65535
	start_haproxy
	start_socks
	nftflag=0
	local use_nft=$(config_t_get global_forwarding use_nft 0)
	local USE_TABLES
	if [ "$use_nft" == 0 ]; then
		if [ -n "$(command -v iptables-legacy || command -v iptables)" ] && [ -n "$(command -v ipset)" ] && [ -n "$(dnsmasq --version | grep 'Compile time options:.* ipset')" ]; then
			USE_TABLES="iptables"
		else
			echolog "系统未安装iptables或ipset或Dnsmasq没有开启ipset支持，无法使用iptables+ipset透明代理！"
			if [ -n "$(command -v fw4)" ] && [ -n "$(command -v nft)" ] && [ -n "$(dnsmasq --version | grep 'Compile time options:.* nftset')" ]; then
				echolog "检测到fw4，使用nftables进行透明代理。"
				USE_TABLES="nftables"
				nftflag=1
				config_t_set global_forwarding use_nft 1
				uci -q commit ${CONFIG}
			fi
		fi
	else
		if [ -n "$(dnsmasq --version | grep 'Compile time options:.* nftset')" ]; then
			USE_TABLES="nftables"
			nftflag=1
		else
			echolog "Dnsmasq软件包不满足nftables透明代理要求，如需使用请确保dnsmasq版本在2.87以上并开启nftset支持。"
		fi
	fi

	check_depends $USE_TABLES

	[ "$USE_TABLES" = "nftables" ] && {
		dnsmasq_version=$(dnsmasq -v | grep -i "Dnsmasq version " | awk '{print $3}')
		[ "$(expr $dnsmasq_version \>= 2.90)" == 0 ] && echolog "Dnsmasq版本低于2.90，建议升级至2.90及以上版本以避免部分情况下Dnsmasq崩溃问题！"
	}

	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect)" == "1" ] && {
			uci -q set ${CONFIG}.@global[0].dnsmasq_dns_redirect='1'
			uci -q commit ${CONFIG}
			uci -q set dhcp.@dnsmasq[0].dns_redirect='0'
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		}
	fi

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		mkdir -p ${GLOBAL_ACL_PATH}
		start_redir TCP
		start_redir UDP
		start_dns
	}
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh start
	set_cache_var "USE_TABLES" "$USE_TABLES"
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		set_cache_var "bak_bridge_nf_ipt" "$bridge_nf_ipt"
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			set_cache_var "bak_bridge_nf_ip6t" "$bridge_nf_ip6t"
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	fi
	
	start_crontab
	echolog "运行完成！\n"
}

stop() {
	clean_log
	eval_cache_var
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh stop
	delete_ip2route
	kill_all v2ray-plugin obfs-local
	pgrep -f "sleep.*(6s|9s|58s)" | xargs kill -9 >/dev/null 2>&1
	pgrep -af "${CONFIG}/" | awk '! /app\.sh|subscribe\.lua|rule_update\.lua|tasks\.sh|ujail/{print $1}' | xargs kill -9 >/dev/null 2>&1
	stop_crontab
	source $APP_PATH/helper_smartdns.sh del
	rm -rf $GLOBAL_DNSMASQ_CONF
	rm -rf $GLOBAL_DNSMASQ_CONF_PATH
	[ "1" = "1" ] && {
		#restore logic
		bak_dnsmasq_dns_redirect=$(config_t_get global dnsmasq_dns_redirect)
		[ -n "${bak_dnsmasq_dns_redirect}" ] && {
			uci -q set dhcp.@dnsmasq[0].dns_redirect="${bak_dnsmasq_dns_redirect}"
			uci -q commit dhcp
			uci -q delete ${CONFIG}.@global[0].dnsmasq_dns_redirect
			uci -q commit ${CONFIG}
		}
		if [ -z "${ACL_default_dns_port}" ] || [ -n "${bak_dnsmasq_dns_redirect}" ]; then
			uci -q del_list dhcp.@dnsmasq[0].addnmount="${GLOBAL_DNSMASQ_CONF_PATH}"
			uci -q commit dhcp
			lua $APP_PATH/helper_dnsmasq.lua restart -LOG 0
		fi
		[ -n "${bak_bridge_nf_ipt}" ] && sysctl -w net.bridge.bridge-nf-call-iptables=${bak_bridge_nf_ipt} >/dev/null 2>&1
		[ -n "${bak_bridge_nf_ip6t}" ] && sysctl -w net.bridge.bridge-nf-call-ip6tables=${bak_bridge_nf_ip6t} >/dev/null 2>&1
	}
	rm -rf $TMP_PATH
	rm -rf /tmp/lock/${CONFIG}_socks_auto_switch*
	echolog "清空并关闭相关程序和缓存完成。"
	exit 0
}

get_config() {
	ENABLED_DEFAULT_ACL=0
	TCP_REDIR_PORT=1041
	UDP_REDIR_PORT=1051
	ENABLED=$(config_t_get global enabled 0)
	SOCKS_ENABLED=$(config_t_get global socks_enabled 0)
	TCP_NODE=$(config_t_get global tcp_node)
	UDP_NODE=$(config_t_get global udp_node)
	TCP_UDP=0
	if [ "$UDP_NODE" == "tcp" ]; then
		UDP_NODE=$TCP_NODE
		TCP_UDP=1
	elif [ "$UDP_NODE" == "$TCP_NODE" ]; then
		TCP_UDP=1
	fi
	[ "$ENABLED" == 1 ] && {
		[ -n "$TCP_NODE" ] && [ "$(config_get_type $TCP_NODE)" == "nodes" ] && ENABLED_DEFAULT_ACL=1
		[ -n "$UDP_NODE" ] && [ "$(config_get_type $UDP_NODE)" == "nodes" ] && ENABLED_DEFAULT_ACL=1
	}
	ENABLED_ACLS=$(config_t_get global acl_enable 0)
	[ "$ENABLED_ACLS" == 1 ] && {
		[ "$(uci show ${CONFIG} | grep "@acl_rule" | grep "enabled='1'" | wc -l)" == 0 ] && ENABLED_ACLS=0
	}

	TCP_PROXY_WAY=$(config_t_get global_forwarding tcp_proxy_way redirect)
	PROXY_IPV6=$(config_t_get global_forwarding ipv6_tproxy 0)
	TCP_REDIR_PORTS=$(config_t_get global_forwarding tcp_redir_ports '80,443')
	UDP_REDIR_PORTS=$(config_t_get global_forwarding udp_redir_ports '1:65535')
	TCP_NO_REDIR_PORTS=$(config_t_get global_forwarding tcp_no_redir_ports 'disable')
	UDP_NO_REDIR_PORTS=$(config_t_get global_forwarding udp_no_redir_ports 'disable')
	TCP_PROXY_DROP_PORTS=$(config_t_get global_forwarding tcp_proxy_drop_ports 'disable')
	UDP_PROXY_DROP_PORTS=$(config_t_get global_forwarding udp_proxy_drop_ports '80,443')
	USE_DIRECT_LIST=$(config_t_get global use_direct_list 1)
	USE_PROXY_LIST=$(config_t_get global use_proxy_list 1)
	USE_BLOCK_LIST=$(config_t_get global use_block_list 1)
	USE_GFW_LIST=$(config_t_get global use_gfw_list 1)
	CHN_LIST=$(config_t_get global chn_list direct)
	TCP_PROXY_MODE=$(config_t_get global tcp_proxy_mode proxy)
	UDP_PROXY_MODE=$(config_t_get global udp_proxy_mode proxy)
	[ "${TCP_PROXY_MODE}" != "disable" ] && TCP_PROXY_MODE="proxy"
	[ "${UDP_PROXY_MODE}" != "disable" ] && UDP_PROXY_MODE="proxy"
	LOCALHOST_PROXY=$(config_t_get global localhost_proxy 1)
	[ "${LOCALHOST_PROXY}" == 1 ] && {
		LOCALHOST_TCP_PROXY_MODE=$TCP_PROXY_MODE
		LOCALHOST_UDP_PROXY_MODE=$UDP_PROXY_MODE
	}
	CLIENT_PROXY=$(config_t_get global client_proxy 1)
	DNS_SHUNT=$(config_t_get global dns_shunt dnsmasq)
	[ -z "$(first_type $DNS_SHUNT)" ] && DNS_SHUNT="dnsmasq"
	DNS_MODE=$(config_t_get global dns_mode tcp)
	[ "$DNS_SHUNT" = "smartdns" ] && DNS_MODE=$(config_t_get global smartdns_dns_mode socks)
	REMOTE_DNS=$(config_t_get global remote_dns 1.1.1.1:53 | sed 's/#/:/g' | sed -E 's/\:([^:]+)$/#\1/g')
	USE_DEFAULT_DNS=$(config_t_get global use_default_dns direct)
	FILTER_PROXY_IPV6=$(config_t_get global filter_proxy_ipv6 0)
	DNS_REDIRECT=$(config_t_get global dns_redirect 1)

	REDIRECT_LIST="socks ss ss-rust ssr sing-box xray trojan-plus naiveproxy hysteria2"
	TPROXY_LIST="socks ss ss-rust ssr sing-box xray trojan-plus hysteria2"

	NEXT_DNS_LISTEN_PORT=15353
	TUN_DNS="127.0.0.1#${NEXT_DNS_LISTEN_PORT}"
	DNS_CACHE=0
	DIRECT_DNS_QUERY_STRATEGY="UseIP"
	REMOTE_DNS_QUERY_STRATEGY="UseIP"
	[ "$FILTER_PROXY_IPV6" = "1" ] && REMOTE_DNS_QUERY_STRATEGY="UseIPv4"
	DNSMASQ_FILTER_PROXY_IPV6=${FILTER_PROXY_IPV6}
	
	RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
	[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto

	ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1)
	ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}'| sort -u | grep -v -Fx ::1 | grep -v -Fx ::)

	DEFAULT_DNS=$(uci show dhcp.@dnsmasq[0] | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | head -2 | sed ':label;N;s/\n/,/;b label')
	[ -z "${DEFAULT_DNS}" ] && [ "$(echo $ISP_DNS | tr ' ' '\n' | wc -l)" -le 2 ] && DEFAULT_DNS=$(echo -n $ISP_DNS | tr ' ' '\n' | head -2 | tr '\n' ',' | sed 's/,$//')
	LOCAL_DNS="${DEFAULT_DNS:-119.29.29.29,223.5.5.5}"
	IPT_APPEND_DNS=${LOCAL_DNS}

	DNSMASQ_CONF_DIR=/tmp/dnsmasq.d
	DEFAULT_DNSMASQ_CFGID="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"
	if [ -f "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID" ]; then
		DNSMASQ_CONF_DIR="$(awk -F '=' '/^conf-dir=/ {print $2}' "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID")"
		if [ -n "$DNSMASQ_CONF_DIR" ]; then
			DNSMASQ_CONF_DIR=${DNSMASQ_CONF_DIR%*/}
		else
			DNSMASQ_CONF_DIR="/tmp/dnsmasq.d"
		fi
	fi
	set_cache_var GLOBAL_DNSMASQ_CONF ${DNSMASQ_CONF_DIR}/dnsmasq-${CONFIG}.conf
	set_cache_var GLOBAL_DNSMASQ_CONF_PATH ${GLOBAL_ACL_PATH}/dnsmasq.d
}

arg1=$1
shift
case $arg1 in
add_ip2route)
	add_ip2route $@
	;;
echolog)
	echolog $@
	;;
get_new_port)
	get_new_port $@
	;;
get_cache_var)
	get_cache_var $@
	;;
set_cache_var)
	set_cache_var $@
	;;
run_socks)
	run_socks $@
	;;
socks_node_switch)
	socks_node_switch $@
	;;
start)
	start
	;;
stop)
	stop
	;;
esac
