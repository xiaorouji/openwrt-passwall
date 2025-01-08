#!/bin/sh

CONFIG=passwall
LOG_FILE=/tmp/log/$CONFIG.log

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	#echo -e "$d: $1"
	echo -e "$d: $1" >> $LOG_FILE
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo "nil"
		return
	}
	echo $(lua -e "local api = require 'luci.passwall.api' print(api.${func})")
}

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	curl --help all | grep "\-\-retry-all-errors" > /dev/null
	[ $? == 0 ] && extra_params="--retry-all-errors ${extra_params}"
	status=$(/usr/bin/curl -I -o /dev/null -skL $extra_params --connect-timeout ${timeout} --retry ${try} -w %{http_code} "$url")
	case "$status" in
		204|\
		200)
			status=200
		;;
	esac
	echo $status
}

test_proxy() {
	result=0
	status=$(test_url "https://www.google.com/generate_204" ${retry_num} ${connect_timeout})
	if [ "$status" = "200" ]; then
		result=0
	else
		status2=$(test_url "https://www.baidu.com" ${retry_num} ${connect_timeout})
		if [ "$status2" = "200" ]; then
			result=1
		else
			result=2
			ping -c 3 -W 1 223.5.5.5 > /dev/null 2>&1
			[ $? -eq 0 ] && {
				result=1
			}
		fi
	fi
	echo $result
}

url_test_node() {
	result=0
	local node_id=$1
	local _type=$(echo $(config_n_get ${node_id} type) | tr 'A-Z' 'a-z')
	[ -n "${_type}" ] && {
		if [ "${_type}" == "socks" ]; then
			local _address=$(config_n_get ${node_id} address)
			local _port=$(config_n_get ${node_id} port)
			[ -n "${_address}" ] && [ -n "${_port}" ] && {
				local curlx="socks5h://${_address}:${_port}"
				local _username=$(config_n_get ${node_id} username)
				local _password=$(config_n_get ${node_id} password)
				[ -n "${_username}" ] && [ -n "${_password}" ] && curlx="socks5h://${_username}:${_password}@${_address}:${_port}"
			}
		else
			local _tmp_port=$(/usr/share/${CONFIG}/app.sh get_new_port 61080 tcp)
			/usr/share/${CONFIG}/app.sh run_socks flag="url_test_${node_id}" node=${node_id} bind=127.0.0.1 socks_port=${_tmp_port} config_file=url_test_${node_id}.json
			local curlx="socks5h://127.0.0.1:${_tmp_port}"
		fi
		sleep 1s
		# 兼容 curl 8.6 time_starttransfer 错误
		local _cmd="-V 2>/dev/null | head -n 1 | awk '{print \$2}' | cut -d. -f1,2 | tr -d ' \\n'"
		local _curl="/usr/bin/curl"
		local curl_ver=$(lua_api "get_bin_version_cache(\"${_curl}\", \"${_cmd}\")")

		local curl_arg="-w %{http_code}:%{time_starttransfer} http://"
		[ "${curl_ver}" = "8.6" ] && curl_arg="-w %{http_code}:%{time_appconnect} https://"

		local chn_list=$(config_n_get @global[0] chn_list direct)
		local probeUrl="www.google.com/generate_204"
		[ "${chn_list}" = "proxy" ] && probeUrl="www.baidu.com"
		result=$(${_curl} --connect-timeout 3 -o /dev/null -I -skL -x ${curlx} ${curl_arg}${probeUrl})
		pgrep -af "url_test_${node_id}" | awk '! /test\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf "/tmp/etc/${CONFIG}/url_test_${node_id}.json"
	}
	echo $result
}

test_node() {
	local node_id=$1
	local _type=$(echo $(config_n_get ${node_id} type) | tr 'A-Z' 'a-z')
	[ -n "${_type}" ] && {
		if [ "${_type}" == "socks" ]; then
			local _address=$(config_n_get ${node_id} address)
			local _port=$(config_n_get ${node_id} port)
			[ -n "${_address}" ] && [ -n "${_port}" ] && {
				local curlx="socks5h://${_address}:${_port}"
				local _username=$(config_n_get ${node_id} username)
				local _password=$(config_n_get ${node_id} password)
				[ -n "${_username}" ] && [ -n "${_password}" ] && curlx="socks5h://${_username}:${_password}@${_address}:${_port}"
			}
		else
			local _tmp_port=$(/usr/share/${CONFIG}/app.sh get_new_port 61080 tcp)
			/usr/share/${CONFIG}/app.sh run_socks flag="test_node_${node_id}" node=${node_id} bind=127.0.0.1 socks_port=${_tmp_port} config_file=test_node_${node_id}.json
			local curlx="socks5h://127.0.0.1:${_tmp_port}"
		fi
		sleep 1s
		_proxy_status=$(test_url "https://www.google.com/generate_204" ${retry_num} ${connect_timeout} "-x $curlx")
		pgrep -af "test_node_${node_id}" | awk '! /test\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf "/tmp/etc/${CONFIG}/test_node_${node_id}.json"
		if [ "${_proxy_status}" -eq 200 ]; then
			return 0
		fi
	}
	return 1
}

arg1=$1
shift
case $arg1 in
test_url)
	test_url $@
	;;
url_test_node)
	url_test_node $@
	;;
esac
