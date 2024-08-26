#!/bin/sh

listen_address=$1
listen_port=$2
server_address=$3
server_port=$4

probe_file="/tmp/etc/passwall/haproxy/Probe_URL"
probeUrl="https://www.google.com/generate_204"
if [ -f "$probe_file" ]; then
	firstLine=$(head -n 1 "$probe_file" | tr -d ' \t')
	if [ -n "$firstLine" ]; then
		probeUrl="$firstLine"
	fi
fi

status=$(/usr/bin/curl -I -o /dev/null -skL -x socks5h://${server_address}:${server_port} --connect-timeout 3 --retry 3 -w %{http_code} "${probeUrl}")
case "$status" in
	204|\
	200)
		status=200
	;;
esac
return_code=1
if [ "$status" = "200" ]; then
	return_code=0
fi
exit ${return_code}
