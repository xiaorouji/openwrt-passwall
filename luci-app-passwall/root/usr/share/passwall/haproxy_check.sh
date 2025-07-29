#!/bin/sh

export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin
CONFIG=passwall

listen_address=$1
listen_port=$2
server_address=$3
server_port=$4

pgrep -af "${CONFIG}/" | awk '/app\.sh.*(start|stop)/ || /nftables\.sh/ || /iptables\.sh/ { found = 1 } END { exit !found }' && {
	# 特定任务执行中不检测
	exit 0
}

probe_file="/tmp/etc/passwall/haproxy/Probe_URL"
probeUrl="https://www.google.com/generate_204"
if [ -f "$probe_file" ]; then
	firstLine=$(head -n 1 "$probe_file" | tr -d ' \t\n')
	[ -n "$firstLine" ] && probeUrl="$firstLine"
fi

extra_params="-x socks5h://${server_address}:${server_port}"
if /usr/bin/curl --help all | grep -q "\-\-retry-all-errors"; then
	extra_params="${extra_params} --retry-all-errors"
fi

status=$(/usr/bin/curl -I -o /dev/null -skL ${extra_params} --connect-timeout 3 --retry 2 --max-time 10 -w "%{http_code}" "${probeUrl}")

case "$status" in
	200|204)
		exit 0
	;;
	*)
		exit 1
	;;
esac
