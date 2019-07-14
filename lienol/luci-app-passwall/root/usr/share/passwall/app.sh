#!/bin/sh
# Copyright (C) 2018-2019 Lienol <lawlienol@gmail.com>

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall
CONFIG_PATH=/var/etc/$CONFIG
RUN_PID_PATH=$CONFIG_PATH/pid
HAPROXY_FILE=$CONFIG_PATH/haproxy.cfg
CONFIG_TCP_FILE=$CONFIG_PATH/TCP.json
CONFIG_UDP_FILE=$CONFIG_PATH/UDP.json
CONFIG_SOCKS5_FILE=$CONFIG_PATH/SOCKS5.json
LOCK_FILE=$CONFIG_PATH/$CONFIG.lock
LOG_FILE=/var/log/$CONFIG.log
SS_PATH=/usr/share/$CONFIG
SS_PATH_RULE=$SS_PATH/rule
SS_PATH_DNSMASQ=$SS_PATH/dnsmasq.d
TMP_DNSMASQ_PATH=/var/etc/dnsmasq-passwall.d
DNSMASQ_PATH=/etc/dnsmasq.d
lanip=$(uci get network.lan.ipaddr)
IPSET_LANIPLIST="laniplist"
IPSET_VPSIPLIST="vpsiplist"
IPSET_ROUTER="router"	
IPSET_GFW="gfwlist"
IPSET_CHN="chnroute"
IPSET_BLACKLIST="blacklist"
IPSET_WHITELIST="whitelist"
iptables_nat="iptables -t nat"
iptables_mangle="iptables -t mangle"
ip6tables_nat="ip6tables -t nat"

get_date(){
	echo "$(date "+%Y-%m-%d %H:%M:%S")"
}

echolog()
{
	echo -e "$(get_date): $1" >> $LOG_FILE
}

find_bin(){
	bin_name=$1
	result=`find /usr/*bin -iname "$bin_name" -type f`
	if [ -z "$result" ]; then
		echo ""
		echolog "找不到$bin_name主程序，无法启动！"
	else
		echo "$result"
	fi
}

config_n_get() {
	local ret=$(uci get $CONFIG.$1.$2 2>/dev/null)
	echo ${ret:=$3}
}

config_t_get() {
	local index=0
	[ -n "$4" ] && index=$4
	local ret=$(uci get $CONFIG.@$1[$index].$2 2>/dev/null)
	echo ${ret:=$3}
}

factor(){
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

get_jump_mode(){
	case "$1" in
		disable)
			echo "j"
		;;
		*)
			echo "g"
		;;
	esac
}

get_ip_mark(){
	if [ -z "$1" ]; then
		echo ""
	else
		echo $1 | awk -F "." '{printf ("0x%02X", $1)} {printf ("%02X", $2)} {printf ("%02X", $3)} {printf ("%02X", $4)}'
	fi
}

get_action_chain() {
	case "$1" in
		disable)
			echo "RETURN"
		;;
		global)
			echo "SS_GLO"
		;;
		gfwlist)
			echo "SS_GFW"
		;;
		chnroute)
			echo "SS_CHN"
		;;
		gamemode)
			echo "SS_GAME"
		;;
		returnhome)
			echo "SS_HOME"
		;;
	esac
}

get_action_chain_name() {
	case "$1" in
		disable)
			echo "不代理"
		;;
		global)
			echo "全局"
		;;
		gfwlist)
			echo "GFW"
		;;
		chnroute)
			echo "大陆白名单"
		;;
		gamemode)
			echo "游戏"
		;;
		returnhome)
			echo "回国"
		;;
	esac
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

get_host_ip() {
	local network_type host isip
	network_type=$1
	host=$2
	isip=""
	ip=$host
	if [ "$network_type" == "ipv6" ]; then
		isip=`echo $host | grep -E "([[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7}])"`
		if [ -n "$isip" ];then
			isip=`echo $host | cut -d '[' -f2 | cut -d ']' -f1`
		else
			isip=`echo $host | grep -E "([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})"`
		fi
	else
		isip=`echo $host|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
	fi
	if [ -z "$isip" ];then
		vpsrip=""
		if [ "$use_ipv6" == "1" ];then
			vpsrip=`resolveip -6 -t 2 $host|awk 'NR==1{print}'`
			[ -z "$vpsrip" ] && vpsrip=`dig @208.67.222.222 $host AAAA 2>/dev/null |grep 'IN'|awk -F ' ' '{print $5}'|grep -E "([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})"|head -n1`
		else
			vpsrip=`resolveip -4 -t 2 $host|awk 'NR==1{print}'`
			[ -z "$vpsrip" ] && vpsrip=`dig @208.67.222.222 $host 2>/dev/null |grep 'IN'|awk -F ' ' '{print $5}'|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}"|head -n1`
		fi
		ip=$vpsrip
	fi
	echo $ip
}

SOCKS5_PROXY_SERVER=$(config_t_get global socks5_proxy_server nil)
TCP_REDIR_SERVER=$(config_t_get global tcp_redir_server nil)
UDP_REDIR_SERVER=$(config_t_get global udp_redir_server nil)
[ "$UDP_REDIR_SERVER" == "default" ] && UDP_REDIR_SERVER=$TCP_REDIR_SERVER

TCP_REDIR_SERVER_IP=""
UDP_REDIR_SERVER_IP=""
SOCKS5_PROXY_SERVER_IP=""
TCP_REDIR_SERVER_IPV6=""
UDP_REDIR_SERVER_IPV6=""
SOCKS5_PROXY_SERVER_IPV6=""
TCP_REDIR_SERVER_PORT=""
UDP_REDIR_SERVER_PORT=""
SOCKS5_PROXY_SERVER_PORT=""
TCP_REDIR_SERVER_TYPE=""
UDP_REDIR_SERVER_TYPE=""
SOCKS5_PROXY_SERVER_TYPE=""

BROOK_SOCKS5_CMD=""
BROOK_TCP_CMD=""
BROOK_UDP_CMD=""
AUTO_SWITCH_ENABLE=$(config_t_get auto_switch enable 0)
TCP_REDIR_PORTS=$(config_t_get global_forwarding tcp_redir_ports '80,443')
UDP_REDIR_PORTS=$(config_t_get global_forwarding udp_redir_ports '1:65535')
KCPTUN_REDIR_PORT=$(config_t_get global_proxy kcptun_port 11183)
PROXY_MODE=$(config_t_get global proxy_mode gfwlist)

load_config() {
	[ "$TCP_REDIR_SERVER" == "nil" -a "$UDP_REDIR_SERVER" == "nil" -a "$SOCKS5_PROXY_SERVER" == "nil" ] && {
		echolog "没有选择服务器！" 
		return 1
	}
	DNS_MODE=$(config_t_get global dns_mode ChinaDNS)
	UP_CHINADNS_MODE=$(config_t_get global up_chinadns_mode OpenDNS_1)
	process=1
	if [ "$(config_t_get global_forwarding process 0)" = "0" ] ;then
		process=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
	else
		process=$(config_t_get global_forwarding process)
	fi
	LOCALHOST_PROXY_MODE=$(config_t_get global localhost_proxy_mode default)
	DNS_FORWARD=$(config_t_get global_dns dns_forward 208.67.222.222:443)
	DNS_FORWARD_IP=$(echo "$DNS_FORWARD" | awk -F':' '{print $1}')
	DNS_FORWARD_PORT=$(echo "$DNS_FORWARD" | awk -F':' '{print $2}')
	DNS1=$(config_t_get global_dns dns_1)
	DNS2=$(config_t_get global_dns dns_2)
	TCP_REDIR_PORT=$(config_t_get global_proxy tcp_redir_port 1031)
	UDP_REDIR_PORT=$(config_t_get global_proxy udp_redir_port 1032)
	SOCKS5_PROXY_PORT=$(config_t_get global_proxy socks5_proxy_port 1033)
	PROXY_IPV6=$(config_t_get global_proxy proxy_ipv6 0)
	mkdir -p /var/etc $CONFIG_PATH $RUN_PID_PATH
	config_load $CONFIG
	[ "$TCP_REDIR_SERVER" != "nil" ] && {
		TCP_REDIR_SERVER_TYPE=`echo $(config_get $TCP_REDIR_SERVER server_type) | tr 'A-Z' 'a-z'`
		gen_config_file $TCP_REDIR_SERVER TCP
		echo "$TCP_REDIR_SERVER" > $CONFIG_PATH/tcp_server_id
	}
	[ "$UDP_REDIR_SERVER" != "nil" ] && {
		UDP_REDIR_SERVER_TYPE=`echo $(config_get $UDP_REDIR_SERVER server_type) | tr 'A-Z' 'a-z'`
		gen_config_file $UDP_REDIR_SERVER UDP
		echo "$UDP_REDIR_SERVER" > $CONFIG_PATH/udp_server_id
	}
	[ "$SOCKS5_PROXY_SERVER" != "nil" ] && {
		SOCKS5_PROXY_SERVER_TYPE=`echo $(config_get $SOCKS5_PROXY_SERVER server_type) | tr 'A-Z' 'a-z'`
		gen_config_file $SOCKS5_PROXY_SERVER Socks5
		echo "$SOCKS5_PROXY_SERVER" > $CONFIG_PATH/socks5_server_id
	}
	return 0
}

gen_ss_ssr_config_file() {
	local server_type local_port kcptun server configfile
	server_type=$1
	local_port=$2
	kcptun=$3
	server=$4
	configfile=$5
	local server_port encrypt_method
	server_port=$(config_get $server server_port)
	encrypt_method=$(config_get $server ss_encrypt_method)
	[ "$server_type" == "ssr" ] && encrypt_method=$(config_get $server ssr_encrypt_method)
	[ "$kcptun" == "1" ] && {
		server_ip=127.0.0.1
		server_host=127.0.0.1
		server_port=$KCPTUN_REDIR_PORT
	}
	cat <<-EOF >$configfile
	{
		"server": "$server_host",
		"_comment": "$server_ip",
		"server_port": $server_port,
		"local_address": "0.0.0.0",
		"local_port": $local_port,
		"password": "$(config_get $server password)",
		"timeout": $(config_get $server timeout),
		"method": "$encrypt_method",
		"fast_open": $(config_get $server fast_open),
		"reuse_port": true,
	EOF
	[ "$1" == "ssr" ] && {
		cat <<-EOF >>$configfile
		"protocol": "$(config_get $server protocol)",
		"protocol_param": "$(config_get $server protocol_param)",
		"obfs": "$(config_get $server obfs)",
		"obfs_param": "$(config_get $server obfs_param)"
		EOF
	}
	echo -e "}" >> $configfile
}

gen_config_file() {
	local server_host server_ip server_port server_type use_ipv6 network_type
	server_host=$(config_get $1 server)
	use_ipv6=$(config_get $1 use_ipv6)
	network_type="ipv4"
	[ "$use_ipv6" == "1" ] && network_type="ipv6"
	server_ip=$(get_host_ip $network_type $server_host)
	server_port=$(config_get $1 server_port)
	server_type=`echo $(config_get $1 server_type) | tr 'A-Z' 'a-z'`
	echolog "$2服务器IP地址:$server_ip"
	
	if [ "$2" == "Socks5" ]; then
		if [ "$network_type" == "ipv6" ];then
			SOCKS5_PROXY_SERVER_IPV6=$server_ip
		else
			SOCKS5_PROXY_SERVER_IP=$server_ip
		fi
		SOCKS5_PROXY_SERVER_PORT=$server_port
		if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
			gen_ss_ssr_config_file $server_type $SOCKS5_PROXY_PORT 0 $SOCKS5_PROXY_SERVER $CONFIG_SOCKS5_FILE
		fi
		if [ "$server_type" == "v2ray" ]; then
			lua /usr/lib/lua/luci/model/cbi/passwall/api/genv2rayconfig.lua $SOCKS5_PROXY_SERVER nil nil $SOCKS5_PROXY_PORT > $CONFIG_SOCKS5_FILE
		fi
		if [ "$server_type" == "brook" ]; then
			BROOK_SOCKS5_CMD="client -l 0.0.0.0:$SOCKS5_PROXY_PORT -i 0.0.0.0 -s $server_ip:$server_port -p $(config_get $SOCKS5_PROXY_SERVER password)"
		fi
	fi
	
	if [ "$2" == "UDP" ]; then
		if [ "$network_type" == "ipv6" ];then
			UDP_REDIR_SERVER_IPV6=$server_ip
		else
			UDP_REDIR_SERVER_IP=$server_ip
		fi
		UDP_REDIR_SERVER_PORT=$server_port
		if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
			gen_ss_ssr_config_file $server_type $UDP_REDIR_PORT 0 $UDP_REDIR_SERVER $CONFIG_UDP_FILE
		fi
		if [ "$server_type" == "v2ray" ]; then
			lua /usr/lib/lua/luci/model/cbi/passwall/api/genv2rayconfig.lua $UDP_REDIR_SERVER udp $UDP_REDIR_PORT nil > $CONFIG_UDP_FILE
		fi
		if [ "$server_type" == "brook" ]; then
			BROOK_UDP_CMD="tproxy -l 0.0.0.0:$UDP_REDIR_PORT -s $server_ip:$server_port -p $(config_get $UDP_REDIR_SERVER password)"
		fi
	fi
	
	if [ "$2" == "TCP" ]; then
		if [ "$network_type" == "ipv6" ];then
			TCP_REDIR_SERVER_IPV6=$server_ip
		else
			TCP_REDIR_SERVER_IP=$server_ip
		fi
		TCP_REDIR_SERVER_PORT=$server_port
		if [ "$server_type" == "v2ray" ]; then
			lua /usr/lib/lua/luci/model/cbi/passwall/api/genv2rayconfig.lua $TCP_REDIR_SERVER tcp $TCP_REDIR_PORT nil > $CONFIG_TCP_FILE
		else
			local kcptun_use kcptun_server_host kcptun_port kcptun_config
			kcptun_use=$(config_get $1 use_kcp)
			kcptun_server_host=$(config_get $1 kcp_server)
			kcptun_port=$(config_get $1 kcp_port)
			kcptun_config=$(config_get $1 kcp_opts)
			kcptun_path=""
			lbenabled=$(config_t_get global_haproxy balancing_enable 0)
			if [ "$kcptun_use" == "1" ] && ([ -z "$kcptun_port" ] || [ -z "$kcptun_config" ]); then
				echolog "【检测到启用KCP，但未配置KCP参数】，跳过~"
			fi
			if [ "$kcptun_use" == "1" -a -n "$kcptun_port" -a -n "$kcptun_config" -a "$lbenabled" == "1" ];then
				echolog "【检测到启用KCP，但KCP与负载均衡二者不能同时开启】，跳过~"
			fi
			
			if [ "$kcptun_use" == "1" ];then
				if [ -f "$(config_t_get global_kcptun kcptun_client_file)" ];then
					kcptun_path=$(config_t_get global_kcptun kcptun_client_file)
				else
					temp=$(find_bin kcptun_client)
					[ -n "$temp" ] && kcptun_path=$temp
				fi
			fi
			
			if [ "$kcptun_use" == "1" -a -z "$kcptun_path" ] && ([ -n "$kcptun_port" ] || [ -n "$kcptun_config" ]);then
				echolog "【检测到启用KCP，但未安装KCP主程序，请自行到自动更新下载KCP】，跳过~"
			fi
			
			if [ "$kcptun_use" == "1" -a -n "$kcptun_port" -a -n "$kcptun_config" -a "$lbenabled" == "0" -a -n "$kcptun_path" ];then
				if [ -z "$kcptun_server_host" ]; then
					start_kcptun "$kcptun_path" $server_ip $kcptun_port "$kcptun_config"
				else
					kcptun_use_ipv6=$(config_get $1 kcp_use_ipv6)
					network_type="ipv4"
					[ "$kcptun_use_ipv6" == "1" ] && network_type="ipv6"
					kcptun_server_ip=$(get_host_ip $network_type $kcptun_server_host)
					echolog "KCP服务器IP地址:$kcptun_server_ip"
					TCP_REDIR_SERVER_IP=$kcptun_server_ip
					start_kcptun "$kcptun_path" $kcptun_server_ip $kcptun_port "$kcptun_config"
				fi
				echolog "运行Kcptun..." 
				if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
					gen_ss_ssr_config_file $server_type $TCP_REDIR_PORT 1 $TCP_REDIR_SERVER $CONFIG_TCP_FILE
				fi
				if [ "$server_type" == "brook" ]; then
					BROOK_TCP_CMD="tproxy -l 0.0.0.0:$TCP_REDIR_PORT -s 127.0.0.1:$KCPTUN_REDIR_PORT -p $(config_get $TCP_REDIR_SERVER password)"
				fi
			else
				if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
					gen_ss_ssr_config_file $server_type $TCP_REDIR_PORT 0 $TCP_REDIR_SERVER $CONFIG_TCP_FILE
				fi
				if [ "$server_type" == "brook" ]; then
					BROOK_TCP_CMD="tproxy -l 0.0.0.0:$TCP_REDIR_PORT -s $server_ip:$server_port -p $(config_get $TCP_REDIR_SERVER password)"
				fi
			fi
		fi
	fi
	return 0
}

start_kcptun() {
	kcptun_bin=$1
	if [ -z "$kcptun_bin" ]; then
		echolog "找不到Kcptun客户端主程序，无法启用！！！" 
	else
		$kcptun_bin --log $CONFIG_PATH/kcptun -l 0.0.0.0:$KCPTUN_REDIR_PORT -r $2:$3 $4 >/dev/null 2>&1 &
	fi
}

start_tcp_redir() {
	if [ "$TCP_REDIR_SERVER" != "nil" ];then
		echolog "运行TCP透明代理..."
		if [ "$TCP_REDIR_SERVER_TYPE" == "v2ray" ]; then
			v2ray_path=$(config_t_get global_v2ray v2ray_client_file)
			if [ -f "${v2ray_path}/v2ray" ];then
				${v2ray_path}/v2ray -config=$CONFIG_TCP_FILE > /dev/null &
			else
				v2ray_bin=$(find_bin V2ray)
				[ -n "$v2ray_bin" ] && $v2ray_bin -config=$CONFIG_TCP_FILE > /dev/null &
			fi
		elif [ "$TCP_REDIR_SERVER_TYPE" == "brook" ]; then
			brook_bin=$(find_bin Brook)
			[ -n "$brook_bin" ] && $brook_bin $BROOK_TCP_CMD &>/dev/null &
		else
			ss_bin=$(find_bin "$TCP_REDIR_SERVER_TYPE"-redir)
			[ -n "$ss_bin" ] && {
				for i in $(seq 1 $process)
				do
					$ss_bin -c $CONFIG_TCP_FILE -f $RUN_PID_PATH/tcp_${TCP_REDIR_SERVER_TYPE}_$i > /dev/null 2>&1 &
				done
			}
		fi
	fi
}

start_udp_redir() {
	if [ "$UDP_REDIR_SERVER" != "nil" ];then
		echolog "运行UDP透明代理..." 
		if [ "$UDP_REDIR_SERVER_TYPE" == "v2ray" ]; then
			v2ray_path=$(config_t_get global_v2ray v2ray_client_file)
			if [ -f "${v2ray_path}/v2ray" ];then
				${v2ray_path}/v2ray -config=$CONFIG_UDP_FILE > /dev/null &
			else
				v2ray_bin=$(find_bin V2ray)
				[ -n "$v2ray_bin" ] && $v2ray_bin -config=$CONFIG_UDP_FILE > /dev/null &
			fi
		elif [ "$UDP_REDIR_SERVER_TYPE" == "brook" ]; then
			brook_bin=$(find_bin brook)
			[ -n "$brook_bin" ] && $brook_bin $BROOK_UDP_CMD &>/dev/null &
		else
			ss_bin=$(find_bin "$UDP_REDIR_SERVER_TYPE"-redir)
			[ -n "$ss_bin" ] && {
				$ss_bin -c $CONFIG_UDP_FILE -f $RUN_PID_PATH/udp_${UDP_REDIR_SERVER_TYPE}_1 -U > /dev/null 2>&1 &
			}
		fi
	fi
}

start_socks5_proxy() {
	if [ "$SOCKS5_PROXY_SERVER" != "nil" ];then
		echolog "运行Socks5代理..."
		if [ "$SOCKS5_PROXY_SERVER_TYPE" == "v2ray" ]; then
			v2ray_path=$(config_t_get global_v2ray v2ray_client_file)
			if [ -f "${v2ray_path}/v2ray" ];then
				${v2ray_path}/v2ray -config=$CONFIG_SOCKS5_FILE > /dev/null &
			else
				v2ray_bin=$(find_bin V2ray)
				[ -n "$v2ray_bin" ] && $v2ray_bin -config=$CONFIG_SOCKS5_FILE > /dev/null &
			fi
		elif [ "$SOCKS5_PROXY_SERVER_TYPE" == "brook" ]; then
			brook_bin=$(find_bin brook)
			[ -n "$brook_bin" ] && $brook_bin $BROOK_SOCKS5_CMD &>/dev/null &
		else
			ss_bin=$(find_bin "$SOCKS5_PROXY_SERVER_TYPE"-local)
			[ -n "$ss_bin" ] && $ss_bin -c $CONFIG_SOCKS5_FILE -b 0.0.0.0 > /dev/null 2>&1 &
		fi
	fi
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	if [ "$logsnum" -gt 300 ];then
		rm -f $LOG_FILE >/dev/null 2>&1 &
		echolog "日志文件过长，清空处理！" 
	fi
}

set_cru() {
	autoupdate=$(config_t_get global_rules auto_update)
	weekupdate=$(config_t_get global_rules week_update)
	dayupdate=$(config_t_get global_rules time_update)
	autoupdatesubscribe=$(config_t_get global_subscribe auto_update_subscribe)
	weekupdatesubscribe=$(config_t_get global_subscribe week_update_subscribe)
	dayupdatesubscribe=$(config_t_get global_subscribe time_update_subscribe)
	if [ "$autoupdate" = "1" ];then
		if [ "$weekupdate" = "7" ];then
			echo "0 $dayupdate * * * $SS_PATH/ssruleupdate.sh" >> /etc/crontabs/root
			echolog "设置自动更新GFWList规则在每天 $dayupdate 点。" 
		else
			echo "0 $dayupdate * * $weekupdate $SS_PATH/ssruleupdate.sh" >> /etc/crontabs/root
			echolog "设置自动更新GFWList规则在星期 $weekupdate 的 $dayupdate 点。" 
		fi
	else
		sed -i '/ssruleupdate.sh/d' /etc/crontabs/root >/dev/null 2>&1 &
	fi

	if [ "$autoupdatesubscribe" = "1" ];then
		if [ "$weekupdatesubscribe" = "7" ];then
			echo "0 $dayupdatesubscribe * * * $SS_PATH/subscription.sh" >> /etc/crontabs/root
			echolog "设置服务器订阅自动更新规则在每天 $dayupdatesubscribe 点。" 
		else
			echo "0 $dayupdatesubscribe * * $weekupdate $SS_PATH/subscription.sh" >> /etc/crontabs/root
			echolog "设置服务器订阅自动更新规则在星期 $weekupdate 的 $dayupdatesubscribe 点。" 
		fi
	else
		sed -i '/subscription.sh/d' /etc/crontabs/root >/dev/null 2>&1 &
	fi
}

start_crontab() {
	sed -i '/$CONFIG/d' /etc/crontabs/root >/dev/null 2>&1 &
	start_daemon=$(config_t_get global_delay start_daemon)
	if [ "$start_daemon" = "1" ];then
		echo "*/2 * * * * nohup $SS_PATH/monitor.sh > /dev/null 2>&1" >> /etc/crontabs/root
		echolog "已启动守护进程。" 
	fi
	
	auto_on=$(config_t_get global_delay auto_on)
	if [ "$auto_on" = "1" ];then
		time_off=$(config_t_get global_delay time_off)
		time_on=$(config_t_get global_delay time_on)
		time_restart=$(config_t_get global_delay time_restart)
		[ -z "$time_off" -o "$time_off" != "nil" ] && {
			echo "0 $time_off * * * /etc/init.d/$CONFIG stop" >> /etc/crontabs/root
			echolog "设置自动关闭在每天 $time_off 点。" 
		}
		[ -z "$time_on" -o "$time_on" != "nil" ] && {
			echo "0 $time_on * * * /etc/init.d/$CONFIG start" >> /etc/crontabs/root
			echolog "设置自动开启在每天 $time_on 点。" 
		}
		[ -z "$time_restart" -o "$time_restart" != "nil" ] && {
			echo "0 $time_restart * * * /etc/init.d/$CONFIG restart" >> /etc/crontabs/root
			echolog "设置自动重启在每天 $time_restart 点。" 
		}
	fi
	
	[ "$AUTO_SWITCH_ENABLE" = "1" ] && {
		testing_time=$(config_t_get auto_switch testing_time)
		[ -n "$testing_time" ] && {
			echo "*/$testing_time * * * * nohup $SS_PATH/test.sh > /dev/null 2>&1" >> /etc/crontabs/root
			echolog "设置每$testing_time分钟执行检测脚本。"
		}
	}
	/etc/init.d/cron restart
}

stop_crontab() {
	sed -i "/$CONFIG/d" /etc/crontabs/root >/dev/null 2>&1 &
	ps | grep "$SS_PATH/test.sh" | grep -v "grep" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	rm -f /var/lock/passwall_test.lock >/dev/null 2>&1 &
	/etc/init.d/cron restart
	echolog "清除定时执行命令。" 
}

start_dns() {
	case "$DNS_MODE" in
		dns2socks)
			dns2socks_bin=$(find_bin dns2socks)
			sslocal_bin=$(find_bin "$TCP_REDIR_SERVER_TYPE"-local)
			[ -n "$dns2socks_bin" -a -n "$sslocal_bin" ] && {
				nohup $sslocal_bin -c $CONFIG_TCP_FILE -l 3080 -f $RUN_PID_PATH/$TCP_REDIR_SERVER_TYPE-local.pid >/dev/null 2>&1 &
				nohup $dns2socks_bin 127.0.0.1:3080 $DNS_FORWARD 127.0.0.1:7913 >/dev/null 2>&1 &
				echolog "运行DNS转发模式：dns2socks+$TCP_REDIR_SERVER_TYPE-local..." 
			}
		;;
		Pcap_DNSProxy)
			Pcap_DNSProxy_bin=$(find_bin Pcap_DNSProxy)
			[ -n "$Pcap_DNSProxy_bin" ] && {
				nohup $Pcap_DNSProxy_bin -c /etc/pcap-dnsproxy >/dev/null 2>&1 &
				echolog "运行DNS转发模式：Pcap_DNSProxy..."
			}
		;;
		pdnsd)
			pdnsd_bin=$(find_bin pdnsd)
			[ -n "$pdnsd_bin" ] && {
				gen_pdnsd_config
				nohup $pdnsd_bin --daemon -c $CACHEDIR/pdnsd.conf -p $RUN_PID_PATH/pdnsd.pid -d >/dev/null 2>&1 &
				echolog "运行DNS转发模式：Pdnsd..." 
			}
		;;
		local_7913)
			echolog "运行DNS转发模式：使用本机7913端口DNS服务解析域名..." 
		;;
		chinadns)
			chinadns_bin=$(find_bin ChinaDNS)
			[ -n "$chinadns_bin" ] && {
				other=1
				echolog "运行DNS转发模式：ChinaDNS..." 
				dns1=$(config_t_get global_dns dns_1)
				[ "$dns1" = "dnsbyisp" ] && dns1=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" |sort -u |grep -v 0.0.0.0 |grep -v 127.0.0.1|sed -n '2P'`
				case "$UP_CHINADNS_MODE" in
					OpenDNS_1)
						other=0
						nohup $chinadns_bin -p 7913 -c $SS_PATH_RULE/chnroute -m -d -s $dns1,208.67.222.222:443,208.67.222.222:5353 >/dev/null 2>&1 &
						echolog "运行ChinaDNS上游转发模式：$dns1,208.67.222.222..." 
					;;
					OpenDNS_2)
						other=0
						nohup $chinadns_bin -p 7913 -c $SS_PATH_RULE/chnroute -m -d -s $dns1,208.67.220.220:443,208.67.220.220:5353 >/dev/null 2>&1 &
						echolog "运行ChinaDNS上游转发模式：$dns1,208.67.220.220..." 
					;;
					custom)
						other=0
						UP_CHINADNS_CUSTOM=$(config_t_get global up_chinadns_custom '114.114.114.114,208.67.222.222:5353')
						nohup $chinadns_bin -p 7913 -c $SS_PATH_RULE/chnroute -m -d -s $UP_CHINADNS_CUSTOM >/dev/null 2>&1 &
						echolog "运行ChinaDNS上游转发模式：$UP_CHINADNS_CUSTOM..." 
					;;
					dnsproxy)
						dnsproxy_bin=$(find_bin dnsproxy)
						[ -n "$dnsproxy_bin" ] && {
							nohup $dnsproxy_bin -d -T -p 7913 -R $DNS_FORWARD_IP -P $DNS_FORWARD_PORT >/dev/null 2>&1 &
							echolog "运行ChinaDNS上游转发模式：dnsproxy..." 
						}
					;;
					dns-forwarder)
						dnsforwarder_bin=$(find_bin dns-forwarder)
						[ -n "$dnsforwarder_bin" ] && {
							nohup $dnsforwarder_bin -p 7913 -s $DNS_FORWARD >/dev/null 2>&1 &
							echolog "运行ChinaDNS上游转发模式：dns-forwarder..." 
						}
					;;
				esac
				if [ "$other" = "1" ];then
					nohup $chinadns_bin -p 7923 -c $SS_PATH_RULE/chnroute -m -d -s $dns1,127.0.0.1:7913 >/dev/null 2>&1 &
				fi
			}
		;;
	esac
	echolog "若不正常，请尝试其他模式！" 
}

add_dnsmasq() {
	mkdir -p $TMP_DNSMASQ_PATH $DNSMASQ_PATH /var/dnsmasq.d
	local wirteconf dnsconf dnsport isp_dns isp_ip
	dnsport=$(config_t_get global_dns dns_port)
	[ -z "$dnsport" ] && dnsport=0
	if [ "$DNS1" = "dnsbyisp" -o "$DNS2" = "dnsbyisp" ]; then
		cat > /etc/dnsmasq.conf <<EOF
all-servers
no-poll
no-resolv
cache-size=2048
local-ttl=60
neg-ttl=3600
max-cache-ttl=1200
EOF
		echolog "生成Dnsmasq配置文件。" 
		
		if [ "$dnsport" != "0" ]; then
			isp_dns=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1`
			failcount=0
			while [ "$failcount" -lt "10" ]
			do
				interface=`ifconfig | grep "$dnsport" | awk '{print $1}'`
				if [ -z "$interface" ];then
					echolog "找不到出口接口：$dnsport，1分钟后再重试" 
					let "failcount++"
					[ "$failcount" -ge 10 ] && exit 0
					sleep 1m
				else
					[ -n "$isp_dns" ] && {
						for isp_ip in $isp_dns
						do
							echo server=$isp_ip >> /etc/dnsmasq.conf
							route add -host ${isp_ip} dev ${dnsport}
							echolog "添加运营商DNS出口路由表：$dnsport" 
						done
					}
					[ "$DNS1" != "dnsbyisp" ] && {
						route add -host ${DNS1} dev ${dnsport}
						echolog "添加DNS1出口路由表：$dnsport" 
						echo server=$DNS1 >> /etc/dnsmasq.conf
					}
					[ "$DNS2" != "dnsbyisp" ] && {
						route add -host ${DNS2} dev ${dnsport}
						echolog "添加DNS2出口路由表：$dnsport" 
						echo server=$DNS2 >> /etc/dnsmasq.conf
					}
					break
				fi
			done
		else
			isp_dns=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | grep -v 0.0.0.0 | grep -v 127.0.0.1`
			[ -n "$isp_dns" ] && {
				for isp_ip in $isp_dns
				do
					echo server=$isp_ip >> /etc/dnsmasq.conf
				done
			}
			[ "$DNS1" != "dnsbyisp" ] && {
				echo server=$DNS1 >> /etc/dnsmasq.conf
			}
			[ "$DNS2" != "dnsbyisp" ] && {
				echo server=$DNS2 >> /etc/dnsmasq.conf
			}
		fi
	else
		wirteconf=$(cat /etc/dnsmasq.conf 2>/dev/null | grep "server=$DNS1")
		dnsconf=$(cat /etc/dnsmasq.conf 2>/dev/null | grep "server=$DNS2")
		if [ "$dnsport" != "0" ]; then
			failcount=0
			while [ "$failcount" -lt "10" ]
			do
				interface=`ifconfig | grep "$dnsport" | awk '{print $1}'`
				if [ -z "$interface" ];then
					echolog "找不到出口接口：$dnsport，1分钟后再重试" 
					let "failcount++"
					[ "$failcount" -ge 10 ] && exit 0
					sleep 1m
				else
					route add -host ${DNS1} dev ${dnsport}
					echolog "添加DNS1出口路由表：$dnsport" 
					route add -host ${DNS2} dev ${dnsport}
					echolog "添加DNS2出口路由表：$dnsport" 
					break
				fi
			done
		fi
		if [ -z "$wirteconf" ] || [ -z "$dnsconf" ];then
			cat > /etc/dnsmasq.conf <<EOF
all-servers
no-poll
no-resolv
server=$DNS1
server=$DNS2
cache-size=2048
local-ttl=60
neg-ttl=3600
max-cache-ttl=1200
EOF
			echolog "生成Dnsmasq配置文件。" 
		fi
	fi
# if [ -n "cat /var/state/network |grep pppoe|awk -F '.' '{print $2}'" ]; then
	# sed -i '/except-interface/d' /etc/dnsmasq.conf >/dev/null 2>&1 &
	# for wanname in $(cat /var/state/network |grep pppoe|awk -F '.' '{print $2}')
	# do
		# echo "except-interface=$(uci get network.$wanname.ifname)" >>/etc/dnsmasq.conf
	# done
# fi

	subscribe_by_ss=$(config_t_get global_subscribe subscribe_by_ss)
	[ -z "$subscribe_by_ss" ] && subscribe_by_ss=0
	[ "$subscribe_by_ss" -eq 1 ] && {
		baseurl=$(config_t_get global_subscribe baseurl)
		[ -n "$baseurl" ] && {
			for url in $baseurl
			do
				if [ -n "`echo -n "$url" |grep "//"`" ]; then
					echo -n "$url" | awk -F'/' '{print $3}' | sed "s/^/server=&\/./g" | sed "s/$/\/127.0.0.1#7913/g" >> $TMP_DNSMASQ_PATH/subscribe.conf
					echo -n "$url" | awk -F'/' '{print $3}' | sed "s/^/ipset=&\/./g" | sed "s/$/\/router/g" >> $TMP_DNSMASQ_PATH/subscribe.conf
				else
					echo -n "$url" | awk -F'/' '{print $1}' | sed "s/^/server=&\/./g" | sed "s/$/\/127.0.0.1#7913/g" >> $TMP_DNSMASQ_PATH/subscribe.conf
					echo -n "$url" | awk -F'/' '{print $1}' | sed "s/^/ipset=&\/./g" | sed "s/$/\/router/g" >> $TMP_DNSMASQ_PATH/subscribe.conf
				fi
			done
		restdns=1
		}
	}

	if [ ! -f "$TMP_DNSMASQ_PATH/gfwlist.conf" ];then
		ln -s $SS_PATH_DNSMASQ/gfwlist.conf $TMP_DNSMASQ_PATH/gfwlist.conf
		restdns=1
	fi
	
	if [ ! -f "$TMP_DNSMASQ_PATH/blacklist_host.conf" ];then
		cat $SS_PATH_RULE/blacklist_host | awk '{print "server=/."$1"/127.0.0.1#7913\nipset=/."$1"/blacklist"}' >> $TMP_DNSMASQ_PATH/blacklist_host.conf
		restdns=1
	fi
	
	if [ ! -f "$TMP_DNSMASQ_PATH/whitelist_host.conf" ];then
		cat $SS_PATH_RULE/whitelist_host | sed "s/^/ipset=&\/./g" | sed "s/$/\/&whitelist/g" | sort | awk '{if ($0!=line) print;line=$0}' >$TMP_DNSMASQ_PATH/whitelist_host.conf
		restdns=1
	fi
	
	if [ ! -f "$TMP_DNSMASQ_PATH/router.conf" ];then
		cat $SS_PATH_RULE/router | awk '{print "server=/."$1"/127.0.0.1#7913\nipset=/."$1"/router"}' >> $TMP_DNSMASQ_PATH/router.conf
		restdns=1
	fi
	
	userconf=$(grep -c "" $SS_PATH_DNSMASQ/user.conf)
	if [ "$userconf" -gt 0  ];then
		ln -s $SS_PATH_DNSMASQ/user.conf $TMP_DNSMASQ_PATH/user.conf
		restdns=1
	fi
	
	backhome=$(config_t_get global proxy_mode gfwlist)
	if [ "$backhome" == "returnhome" ];then
		rm -rf $TMP_DNSMASQ_PATH/gfwlist.conf
		rm -rf $TMP_DNSMASQ_PATH/blacklist_host.conf
		rm -rf $TMP_DNSMASQ_PATH/whitelist_host.conf
		restdns=1
		echolog "生成回国模式Dnsmasq配置文件。" 
	fi
	
	echo "conf-dir=$TMP_DNSMASQ_PATH" > /var/dnsmasq.d/dnsmasq-$CONFIG.conf
	echo "conf-dir=$TMP_DNSMASQ_PATH" > $DNSMASQ_PATH/dnsmasq-$CONFIG.conf
	if [ "$restdns" == 1 ];then
		echolog "重启Dnsmasq。。。" 
		/etc/init.d/dnsmasq restart  2>/dev/null
	fi
}

gen_pdnsd_config() {
	CACHEDIR=/var/pdnsd
	CACHE=$CACHEDIR/pdnsd.cache
	if ! test -f "$CACHE"; then
		mkdir -p `dirname $CACHE`
		touch $CACHE
		chown -R root.nogroup $CACHEDIR
	fi
	cat > $CACHEDIR/pdnsd.conf <<-EOF
	global {
		perm_cache=1024;
		cache_dir="/var/pdnsd";
		run_as="root";
		server_ip = 127.0.0.1;
		server_port=7913;
		status_ctl = on;
		query_method=tcp_only;
		min_ttl=1d;
		max_ttl=1w;
		timeout=10;
		tcp_qtimeout=1;
		par_queries=2;
		neg_domain_pol=on;
		udpbufsize=1024;
		}
	server {
		label = "opendns";
		ip = 208.67.222.222, 208.67.220.220;
		edns_query=on;
		port = 5353;
		timeout = 4;
		interval=60;
		uptest = none;
		purge_cache=off;
		caching=on;
		}
	source {
		ttl=86400;
		owner="localhost.";
		serve_aliases=on;
		file="/etc/hosts";
		}
EOF
}

stop_dnsmasq() {
	if [ "$TCP_REDIR_SERVER" == "nil" ]; then
		rm -rf /var/dnsmasq.d/dnsmasq-$CONFIG.conf
		rm -rf $DNSMASQ_PATH/dnsmasq-$CONFIG.conf
		rm -rf $TMP_DNSMASQ_PATH
		/etc/init.d/dnsmasq restart  2>/dev/null
		echolog "没有选择服务器！" 
	fi
}

start_haproxy(){
	enabled=$(config_t_get global_haproxy balancing_enable 0)
	[ "$enabled" = "1" ] && {
		haproxy_bin=$(find_bin haproxy)
		[ -n "$haproxy_bin" ] && {
			bport=$(config_t_get global_haproxy haproxy_port)
			cat <<-EOF >$HAPROXY_FILE
global
    log         127.0.0.1 local2
    chroot      /usr/bin
    pidfile     $RUN_PID_PATH/haproxy.pid
    maxconn     60000
    stats socket  $RUN_PID_PATH/haproxy.sock
    user        root
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
listen shadowsocks
    bind 0.0.0.0:$bport
    mode tcp
EOF
			for i in $(seq 0 100)
			do
				bips=$(config_t_get balancing lbss '' $i)
				bports=$(config_t_get balancing lbort '' $i)
				bweight=$(config_t_get balancing lbweight '' $i)
				exports=$(config_t_get balancing export '' $i)
				bbackup=$(config_t_get balancing backup '' $i)
				if [ -z "$bips" ] || [ -z "$bports" ] ; then
					break
				fi
				if [ "$bbackup" = "1" ] ; then
					bbackup=" backup"
					echolog "添加故障转移备服务器$bips" 
				else
					bbackup=""
					echolog "添加负载均衡主服务器$bips" 
				fi
				si=`echo $bips|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
				if [ -z "$si" ];then      
					bips=`resolveip -4 -t 2 $bips|awk 'NR==1{print}'`
					if [ -z "$bips" ];then
						bips=`nslookup $bips localhost | sed '1,4d' | awk '{print $3}' | grep -v :|awk 'NR==1{print}'`
					fi
					echolog "服务器IP为：$bips"
				fi
				echo "    server ss$i $bips:$bports weight $bweight check inter 1500 rise 1 fall 3 $bbackup" >> $HAPROXY_FILE
				if [ "$exports" != "0" ]; then
					failcount=0
					while [ "$failcount" -lt "10" ]
					do
						interface=`ifconfig | grep "$exports" | awk '{print $1}'`
						if [ -z "$interface" ];then
							echolog "找不到出口接口：$exports，1分钟后再重试" 
							let "failcount++"
							[ "$failcount" -ge 10 ] && exit 0
							sleep 1m
						else
							route add -host ${bips} dev ${exports}
							echolog "添加SS出口路由表：$exports" 
							echo "$bips" >> /tmp/balancing_ip
							break
						fi
					done
				fi
			done
			#生成负载均衡控制台
			adminstatus=$(config_t_get global_haproxy admin_enable)
			if [ "$adminstatus" = "1" ];then
				adminport=$(config_t_get global_haproxy admin_port)
				adminuser=$(config_t_get global_haproxy admin_user)
				adminpassword=$(config_t_get global_haproxy admin_password)
			cat <<-EOF >>$HAPROXY_FILE
		listen status
			bind 0.0.0.0:$adminport
			mode http                   
			stats refresh 30s
			stats uri  /  
			stats auth $adminuser:$adminpassword
			#stats hide-version
			stats admin if TRUE
		EOF
			fi
			nohup $haproxy_bin -f $HAPROXY_FILE 2>&1
			echolog "负载均衡服务运行成功！" 
		}
	}
} 

add_vps_port() {
	multiwan=$(config_t_get global_dns wan_port 0)
	if [ "$multiwan" != "0" ]; then
		failcount=0
		while [ "$failcount" -lt "10" ]
		do
			interface=`ifconfig | grep "$multiwan" | awk '{print $1}'`
			if [ -z "$interface" ];then
				echolog "找不到出口接口：$multiwan，1分钟后再重试" 
				let "failcount++"
				[ "$failcount" -ge 10 ] && exit 0
				sleep 1m
			else
				route add -host ${TCP_REDIR_SERVER_IP} dev ${multiwan}
				route add -host ${UDP_REDIR_SERVER_IP} dev ${multiwan}
				echolog "添加SS出口路由表：$multiwan" 
				echo "$TCP_REDIR_SERVER_IP" > $CONFIG_PATH/tcp_ip
				echo "$UDP_REDIR_SERVER_IP" > $CONFIG_PATH/udp_ip
				break
			fi
		done
	fi
}

del_vps_port() {
	tcp_ip=$(cat $CONFIG_PATH/tcp_ip 2> /dev/null)
	udp_ip=$(cat $CONFIG_PATH/udp_ip 2> /dev/null)
	[ -n "$tcp_ip" ] && route del -host ${tcp_ip}
	[ -n "$udp_ip" ] && route del -host ${udp_ip}
}

dns_hijack(){
	dnshijack=$(config_t_get global_dns dns_53)
	if [ "$dnshijack" = "1" -o "$1" = "force" ];then
		chromecast_nu=`$iptables_nat -L SS -v -n --line-numbers|grep "dpt:53"|awk '{print $1}'`
		is_right_lanip=`$iptables_nat -L SS -v -n --line-numbers|grep "dpt:53" |grep "$lanip"`
		if [ -z "$chromecast_nu" ]; then
			echolog "添加接管局域网DNS解析规则..." 
			$iptables_nat -I SS -i br-lan -p udp --dport 53 -j DNAT --to $lanip 2>/dev/null
		else
			if [ -z "$is_right_lanip" ]; then
				echolog "添加接管局域网DNS解析规则..." 
				$iptables_nat -D SS $chromecast_nu >/dev/null 2>&1 &
				$iptables_nat -I SS -i br-lan -p udp --dport 53 -j DNAT --to $lanip 2>/dev/null
			else
				echolog " DNS劫持规则已经添加，跳过~" >>$LOG_FILE
			fi
		fi
	fi
}

load_acl(){
	local enabled
	local aclremarks
	local ipaddr
	local macaddr
	local proxy_mode
	local tcp_redir_ports
	local udp_redir_ports
	config_get enabled $1 enabled
	config_get aclremarks $1 aclremarks
	config_get ipaddr $1 ipaddr
	config_get macaddr $1 macaddr
	config_get proxy_mode $1 proxy_mode
	config_get tcp_redir_ports $1 tcp_redir_ports
	config_get udp_redir_ports $1 udp_redir_ports
	[ -z "$proxy_mode" -o "$proxy_mode" = "default" ] && proxy_mode=$PROXY_MODE
	[ -z "$tcp_redir_ports" -o "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
	[ -z "$udp_redir_ports" -o "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS
	local ip_mark=`get_ip_mark $ipaddr`								 
	[ "$enabled" == "1" -a -n "$proxy_mode" ] && {
		if [ -n "$ipaddr" ] || [ -n "$macaddr" ]; then
			if [ -n "$ipaddr" -a -n "$macaddr" ]; then
				echolog "访问控制：IP：$ipaddr，MAC：$macaddr，代理模式：$(get_action_chain_name $proxy_mode)" 
			else
				[ -n "$ipaddr" ] && echolog "访问控制：IP：$ipaddr，代理模式：$(get_action_chain_name $proxy_mode)" 
				[ -n "$macaddr" ] && echolog "访问控制：MAC：$macaddr，代理模式：$(get_action_chain_name $proxy_mode)" 
			fi
			$iptables_mangle -A SS_ACL $(factor $ipaddr "-s") -p tcp $(factor $macaddr "-m mac --mac-source") $(factor $tcp_redir_ports "-m multiport --dport") -m comment --comment "$aclremarks" -$(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			[ "$UDP_REDIR_SERVER" != "nil" ] && $iptables_mangle -A SS_ACL $(factor $ipaddr "-s") -p udp $(factor $macaddr "-m mac --mac-source") $(factor $udp_redir_ports "-m multiport --dport") -m comment --comment "$aclremarks" -$(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			[ -z "$ipaddr" ] && {
				lower_macaddr=`echo $macaddr | tr '[A-Z]' '[a-z]'`
				ipaddr=`ip neigh show | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep $lower_macaddr | awk '{print $1}'`
				[ -z "$ipaddr" ] && {
					dhcp_index=`uci show dhcp | grep $lower_macaddr |awk -F'.' '{print $2}'`
					ipaddr=`uci -q get dhcp.$dhcp_index.ip`
				}
				[ -z "$ipaddr" ] && ipaddr=`cat /tmp/dhcp.leases | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" |grep $lower_macaddr |awk '{print $3}'`
			}
		fi
	}
}

filter_vpsip(){
	local server_host server_ip use_ipv6 network_type
	server_host=$(config_get $1 server)
	use_ipv6=$(config_get $1 use_ipv6)
	network_type="ipv4"
	[ "$use_ipv6" == "1" ] && network_type="ipv6"
	server_ip=$(get_host_ip $network_type $server_host)
	
	[ -n "$server_ip" -a "$server_ip" != "$TCP_REDIR_SERVER_IP" ] && {
		[ "$network_type" == "ipv4" ] && ipset add $IPSET_VPSIPLIST $server_ip >/dev/null 2>&1 &
	}
}

add_firewall_rule() {
	echolog "开始加载防火墙规则..." 
	echolog "默认代理模式：$(get_action_chain_name $PROXY_MODE)" 
	ipset -! create $IPSET_LANIPLIST nethash && ipset flush $IPSET_LANIPLIST
	ipset -! create $IPSET_VPSIPLIST nethash && ipset flush $IPSET_VPSIPLIST
	ipset -! create $IPSET_ROUTER nethash && ipset flush $IPSET_ROUTER
	ipset -! create $IPSET_GFW nethash && ipset flush $IPSET_GFW
	ipset -! create $IPSET_CHN nethash && ipset flush $IPSET_CHN
	ipset -! create $IPSET_BLACKLIST nethash && ipset flush $IPSET_BLACKLIST
	ipset -! create $IPSET_WHITELIST nethash && ipset flush $IPSET_WHITELIST
	
	sed -e "s/^/add $IPSET_CHN &/g" $SS_PATH_RULE/chnroute | awk '{print $0} END{print "COMMIT"}' | ipset -R
	sed -e "s/^/add $IPSET_BLACKLIST &/g" $SS_PATH_RULE/blacklist_ip | awk '{print $0} END{print "COMMIT"}' | ipset -R
	sed -e "s/^/add $IPSET_WHITELIST &/g" $SS_PATH_RULE/whitelist_ip | awk '{print $0} END{print "COMMIT"}' | ipset -R
	
	ipset -! -R <<-EOF || return 1
			$(gen_laniplist | sed -e "s/^/add $IPSET_LANIPLIST /")
EOF
	
	ISP_DNS=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u |grep -v 0.0.0.0 |grep -v 127.0.0.1`
	[ -n "$ISP_DNS" ] && {
		for ispip in $ISP_DNS
		do
			ipset -! add $IPSET_WHITELIST $ispip >/dev/null 2>&1 &
		done
	}
		
	#	忽略特殊IP段
	lan_ip=`ifconfig br-lan | grep "inet addr" | awk '{print $2}' | awk -F : '{print $2}'` #路由器lan IP
	lan_ipv4=`ip address show br-lan | grep -w "inet" |awk '{print $2}'`  #当前LAN IPv4段
	[ -n "$lan_ipv4" ] && ipset add $IPSET_LANIPLIST $lan_ipv4 >/dev/null 2>&1 &
	
	#  过滤所有节点IP
		config_foreach filter_vpsip "servers"
	
	$iptables_mangle -N SS
	$iptables_mangle -A SS -m set --match-set $IPSET_LANIPLIST dst -j RETURN
	$iptables_mangle -A SS -m set --match-set $IPSET_VPSIPLIST dst -j RETURN
	$iptables_mangle -A SS -m set --match-set $IPSET_WHITELIST dst -j RETURN
	$iptables_mangle -N SS_ACL
	$iptables_mangle -N SS_GLO
	$iptables_mangle -N SS_GFW
	$iptables_mangle -N SS_CHN
	$iptables_mangle -N SS_HOME
	$iptables_mangle -N SS_GAME
	
	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100
	
	#	生成TCP转发规则
	if [ "$TCP_REDIR_SERVER" != "nil" ];then
		[ -n "$SOCKS5_PROXY_SERVER_IP" -a -n "$SOCKS5_PROXY_SERVER_PORT" ] && $iptables_mangle -A SS -p tcp -d $SOCKS5_PROXY_SERVER_IP -m multiport --dports $SOCKS5_PROXY_SERVER_PORT -j RETURN
		[ -n "$TCP_REDIR_SERVER_IP" -a -n "$TCP_REDIR_SERVER_PORT" ] && $iptables_mangle -A SS -p tcp -d $TCP_REDIR_SERVER_IP -m multiport --dports $TCP_REDIR_SERVER_PORT -j RETURN
		if [ "$TCP_REDIR_SERVER_TYPE" == "brook" ]; then
			$iptables_mangle -A PREROUTING -p tcp -m socket -j MARK --set-mark 1
			$iptables_mangle -A PREROUTING -p tcp -j SS
			
			$iptables_mangle -A SS -p tcp -m set --match-set $IPSET_BLACKLIST dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			#	全局模式
			$iptables_mangle -A SS_GLO -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port $TCP_REDIR_PORT
			
			#	GFWLIST模式
			$iptables_mangle -A SS_GFW -p tcp -m set --match-set $IPSET_GFW dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			$iptables_mangle -A SS_GFW -p tcp -m set --match-set $IPSET_ROUTER dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	大陆白名单模式
			$iptables_mangle -A SS_CHN -p tcp -m set --match-set $IPSET_CHN dst -j RETURN
			$iptables_mangle -A SS_CHN -p tcp -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	回国模式
			$iptables_mangle -A SS_HOME -p tcp -m set --match-set $IPSET_CHN dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	游戏模式
			$iptables_mangle -A SS_GAME -p tcp -m set --match-set $IPSET_CHN dst -j RETURN
			
			#	用于本机流量转发，默认只走router
			$iptables_mangle -A SS -s $lan_ip -p tcp -m set --match-set $IPSET_ROUTER dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			$iptables_mangle -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_ROUTER dst -j MARK --set-mark 1
		else
			$iptables_mangle -A PREROUTING -j SS
			$iptables_mangle -A SS -p tcp -m set --match-set $IPSET_BLACKLIST dst -j TTL --ttl-set 188
			#	全局模式
			$iptables_mangle -A SS_GLO -p tcp -j TTL --ttl-set 188
			
			#	GFWLIST模式
			$iptables_mangle -A SS_GFW -p tcp -m set --match-set $IPSET_GFW dst -j TTL --ttl-set 188
			$iptables_mangle -A SS_GFW -p tcp -m set --match-set $IPSET_ROUTER dst -j TTL --ttl-set 188
			
			#	大陆白名单模式
			$iptables_mangle -A SS_CHN -p tcp -m set --match-set $IPSET_CHN dst -j RETURN
			#$iptables_mangle -A SS_CHN -p tcp -m geoip ! --destination-country CN -j TTL --ttl-set 188
			$iptables_mangle -A SS_CHN -p tcp -j TTL --ttl-set 188
			
			#	回国模式
			#$iptables_mangle -A SS_HOME -p tcp -m geoip --destination-country CN -j TTL --ttl-set 188
			$iptables_mangle -A SS_HOME -p tcp -m set --match-set $IPSET_CHN dst -j TTL --ttl-set 188
			
			#	游戏模式
			$iptables_mangle -A SS_GAME -p tcp -m set --match-set $IPSET_CHN dst -j RETURN
			
			#	重定所有流量到透明代理端口
			$iptables_nat -N SS
			$iptables_nat -A SS -p tcp -m ttl --ttl-eq 188 -j REDIRECT --to $TCP_REDIR_PORT
			
			is_add_prerouting=0
			
			KP_INDEX=`$iptables_nat -L PREROUTING|tail -n +3|sed -n -e '/^KOOLPROXY/='`
			if [ -n "$KP_INDEX" ]; then
				let KP_INDEX+=1
				#确保添加到KOOLPROXY规则之后
				$iptables_nat -I PREROUTING $KP_INDEX -j SS
				is_add_prerouting=1
			fi
			
			ADBYBY_INDEX=`$iptables_nat -L PREROUTING|tail -n +3|sed -n -e '/^ADBYBY/='`
			if [ -n "$ADBYBY_INDEX" ]; then
				let ADBYBY_INDEX+=1
				#确保添加到ADBYBY规则之后
				$iptables_nat -I PREROUTING $ADBYBY_INDEX -j SS
				is_add_prerouting=1
			fi
			
			if [ "$is_add_prerouting" == 0 ]; then
				#如果去广告没有运行，确保添加到prerouting_rule规则之后
				PR_INDEX=`$iptables_nat -L PREROUTING|tail -n +3|sed -n -e '/^prerouting_rule/='`
				if [ -z "$PR_INDEX" ]; then
					PR_INDEX=1
				else
					let PR_INDEX+=1
				fi
				$iptables_nat -I PREROUTING $PR_INDEX -j SS
			fi
		
			#  用于本机流量转发，默认只走router
			#$iptables_nat -I OUTPUT -j SS
			$iptables_nat -A OUTPUT -m set --match-set $IPSET_LANIPLIST dst -j RETURN
			$iptables_nat -A OUTPUT -m set --match-set $IPSET_VPSIPLIST dst -j RETURN
			$iptables_nat -A OUTPUT -m set --match-set $IPSET_WHITELIST dst -j RETURN
			$iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_ROUTER dst -j REDIRECT --to-ports $TCP_REDIR_PORT
			$iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_BLACKLIST dst -j REDIRECT --to-ports $TCP_REDIR_PORT
			
			[ "$LOCALHOST_PROXY_MODE" == "global" ] && $iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -j REDIRECT --to-ports $TCP_REDIR_PORT
			[ "$LOCALHOST_PROXY_MODE" == "gfwlist" ] && $iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_GFW dst -j REDIRECT --to-ports $TCP_REDIR_PORT
			[ "$LOCALHOST_PROXY_MODE" == "chnroute" ] && {
				$iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_CHN dst -j RETURN
				$iptables_nat -A OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -j REDIRECT --to-ports $TCP_REDIR_PORT
			}
			
			echolog "IPv4 防火墙TCP转发规则加载完成！" 
		fi
	else
		echolog "主服务器未选择，无法转发TCP！" 
	fi
		
	#  生成UDP转发规则
	if [ "$UDP_REDIR_SERVER" != "nil" ];then
		[ -n "$UDP_REDIR_SERVER_IP" -a -n "$UDP_REDIR_SERVER_PORT" ] && $iptables_mangle -A SS -p udp -d $UDP_REDIR_SERVER_IP -m multiport --dports $UDP_REDIR_SERVER_PORT -j RETURN
		if [ "$UDP_REDIR_SERVER_TYPE" == "brook" ]; then
			$iptables_mangle -A PREROUTING -p udp -m socket -j MARK --set-mark 1
			$iptables_mangle -A PREROUTING -p udp -j SS
		fi
		$iptables_mangle -A SS -p udp -m set --match-set $IPSET_BLACKLIST dst -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		#  全局模式
		$iptables_mangle -A SS_GLO -p udp -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		
		#  GFWLIST模式
		$iptables_mangle -A SS_GFW -p udp -m set --match-set $IPSET_GFW dst -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		$iptables_mangle -A SS_GFW -p udp -m set --match-set $IPSET_ROUTER dst -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		
		#  大陆白名单模式
		$iptables_mangle -A SS_CHN -p udp -m set --match-set $IPSET_CHN dst -j RETURN
		$iptables_mangle -A SS_CHN -p udp -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		
		#  回国模式
		$iptables_mangle -A SS_HOME -p udp -m set --match-set $IPSET_CHN dst -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		
		#  游戏模式
		$iptables_mangle -A SS_GAME -p udp -m set --match-set $IPSET_CHN dst -j RETURN
		$iptables_mangle -A SS_GAME -p udp -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
		#$iptables_mangle -A SS_GAME -p udp -m geoip ! --destination-country CN -j TTL --ttl-set 188
		
		echolog "IPv4 防火墙UDP转发规则加载完成！" 
	else
		echolog "UDP服务器未选择，无法转发UDP！" 
	fi
		
	#  加载ACLS
		$iptables_mangle -A SS -j SS_ACL
		config_foreach load_acl "acl_rule"
		
	#  加载默认代理模式
		if [ "$PROXY_MODE" == "disable" ];then
			[ "$TCP_REDIR_SERVER" != "nil" ] && $iptables_mangle -A SS_ACL -p tcp -m comment --comment "Default" -j $(get_action_chain $PROXY_MODE)
			[ "$UDP_REDIR_SERVER" != "nil" ] && $iptables_mangle -A SS_ACL -p udp -m comment --comment "Default" -j $(get_action_chain $PROXY_MODE)
		else
			[ "$PROXY_MODE" == "gfwlist" ] && dns_hijack "force"
			[ "$TCP_REDIR_SERVER" != "nil" ] && $iptables_mangle -A SS_ACL -p tcp -m multiport --dport $TCP_REDIR_PORTS -m comment --comment "Default" -j $(get_action_chain $PROXY_MODE)
			[ "$UDP_REDIR_SERVER" != "nil" ] && $iptables_mangle -A SS_ACL -p udp -m multiport --dport $UDP_REDIR_PORTS -m comment --comment "Default" -j $(get_action_chain $PROXY_MODE)
		fi
	
	if [ "$PROXY_IPV6" == "1" ];then
		lan_ipv6=`ip address show br-lan | grep -w "inet6" |awk '{print $2}'`  #当前LAN IPv6段
		$ip6tables_nat -N SS
		$ip6tables_nat -N SS_ACL
		$ip6tables_nat -A PREROUTING -j SS
		[ -n "$lan_ipv6" ] && {
			for ip in $lan_ipv6
			do
				$ip6tables_nat -A SS -d $ip -j RETURN
			done
		}
		[ "$use_ipv6" == "1" -a -n "$server_ip" ] && $ip6tables_nat -A SS -d $server_ip -j RETURN
		$ip6tables_nat -N SS_GLO
		$ip6tables_nat -N SS_GFW
		$ip6tables_nat -N SS_CHN
		$ip6tables_nat -N SS_HOME
		$ip6tables_nat -A SS_GLO -p tcp -j REDIRECT --to $TCP_REDIR_PORT
		$ip6tables_nat -A SS -j SS_GLO
		$ip6tables_nat -I OUTPUT -p tcp -j SS
		echolog "IPv6防火墙规则加载完成！" 
	fi
}

del_firewall_rule() {
	echolog "删除所有防火墙规则..."
	ipv4_output_exist=`$iptables_nat -L OUTPUT 2>/dev/null | grep -c -E "SS|$TCP_REDIR_PORTS|$IPSET_LANIPLIST|$IPSET_VPSIPLIST|$IPSET_WHITELIST|$IPSET_ROUTER|$IPSET_BLACKLIST|$IPSET_GFW|$IPSET_CHN"`
	[ -n "$ipv4_output_exist" ] && {
		until [ "$ipv4_output_exist" = 0 ]
		do
			rules=`$iptables_nat -L OUTPUT --line-numbers | grep -E "SS|$TCP_REDIR_PORTS|$IPSET_LANIPLIST|$IPSET_VPSIPLIST|$IPSET_WHITELIST|$IPSET_ROUTER|$IPSET_BLACKLIST|$IPSET_GFW|$IPSET_CHN" | awk '{print $1}'`
			for rule in $rules
			do
				$iptables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv4_output_exist=`expr $ipv4_output_exist - 1`
		done
	}
	
	ipv6_output_ss_exist=`$ip6tables_nat -L OUTPUT 2>/dev/null | grep -c "SS"`
	[ -n "$ipv6_output_ss_exist" ] && {
		until [ "$ipv6_output_ss_exist" = 0 ]
		do
			rules=`$ip6tables_nat -L OUTPUT --line-numbers | grep "SS" | awk '{print $1}'`
			for rule in $rules
			do
				$ip6tables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv6_output_ss_exist=`expr $ipv6_output_ss_exist - 1`
		done
	}
	$iptables_mangle -D PREROUTING -p tcp -m socket -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D PREROUTING -p udp -m socket -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_ROUTER dst -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -m set --match-set $IPSET_GFW dst -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D OUTPUT -p tcp -m multiport --dport $TCP_REDIR_PORTS -j MARK --set-mark 1 2>/dev/null
	
	$iptables_nat -D PREROUTING -j SS 2> /dev/null
	$iptables_nat -F SS 2>/dev/null && $iptables_nat -X SS 2>/dev/null
	$iptables_mangle -D PREROUTING -j SS 2>/dev/null
	$iptables_mangle -F SS 2>/dev/null && $iptables_mangle -X SS 2>/dev/null
	$iptables_mangle -F SS_ACL 2>/dev/null && $iptables_mangle -X SS_ACL 2>/dev/null
	$iptables_mangle -F SS_GLO 2>/dev/null && $iptables_mangle -X SS_GLO 2>/dev/null
	$iptables_mangle -F SS_GFW 2>/dev/null && $iptables_mangle -X SS_GFW 2>/dev/null
	$iptables_mangle -F SS_CHN 2>/dev/null && $iptables_mangle -X SS_CHN 2>/dev/null
	$iptables_mangle -F SS_GAME 2>/dev/null && $iptables_mangle -X SS_GAME 2>/dev/null
	$iptables_mangle -F SS_HOME 2>/dev/null && $iptables_mangle -X SS_HOME 2>/dev/null
	
	$ip6tables_nat -D PREROUTING -j SS 2>/dev/null
	$ip6tables_nat -F SS 2>/dev/null && $ip6tables_nat -X SS 2>/dev/null
	$ip6tables_nat -F SS_ACL 2>/dev/null && $ip6tables_nat -X SS_ACL 2>/dev/null
	$ip6tables_nat -F SS_GLO 2>/dev/null && $ip6tables_nat -X SS_GLO 2>/dev/null
	$ip6tables_nat -F SS_GFW 2>/dev/null && $ip6tables_nat -X SS_GFW 2>/dev/null
	$ip6tables_nat -F SS_CHN 2>/dev/null && $ip6tables_nat -X SS_CHN 2>/dev/null
	$ip6tables_nat -F SS_HOME 2>/dev/null && $ip6tables_nat -X SS_HOME 2>/dev/null
	ip_rule_exist=`ip rule show | grep "from all fwmark 0x1 lookup 100" | grep -c 100`
	if [ ! -z "$ip_rule_exist" ];then
		until [ "$ip_rule_exist" = 0 ]
		do 
			ip rule del fwmark 1 lookup 100
			ip_rule_exist=`expr $ip_rule_exist - 1`
		done
	fi
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
}

kill_all() {
	kill -9 $(pidof $@) >/dev/null 2>&1 &
}

boot() {
	local delay=$(config_t_get global_delay start_delay 0)
	if [ "$delay" -gt 0 ]; then
		[ "$TCP_REDIR_SERVER" != "nil" -o "$UDP_REDIR_SERVER" != "nil" ] && {
			echolog "执行启动延时 $delay 秒后再启动!" 
			sleep $delay && start >/dev/null 2>&1 &
		}
	else
		start
	fi
	return 0
}

start() {
	echolog "开始运行脚本！" 
	! load_config && return 1
	add_vps_port
	start_haproxy
	#防止并发开启服务
	[ -f "$LOCK_FILE" ] && return 3
	touch "$LOCK_FILE"
	start_tcp_redir
	start_udp_redir
	start_socks5_proxy
	start_dns
	add_dnsmasq
	add_firewall_rule
	dns_hijack
	/etc/init.d/dnsmasq restart >/dev/null 2>&1 &
	start_crontab
	set_cru
	rm -f "$LOCK_FILE"
	echolog "运行完成！" 
	return 0
}

stop() {
	while [ -f "$LOCK_FILE" ]; do
		sleep 1s
	done
	clean_log
	del_firewall_rule
	del_vps_port
	ipset -F $IPSET_ROUTER >/dev/null 2>&1 && ipset -X $IPSET_ROUTER >/dev/null 2>&1 &
	ipset -F $IPSET_GFW >/dev/null 2>&1 && ipset -X $IPSET_GFW >/dev/null 2>&1 &
	#ipset -F $IPSET_CHN >/dev/null 2>&1 && ipset -X $IPSET_CHN >/dev/null 2>&1 &
	ipset -F $IPSET_BLACKLIST >/dev/null 2>&1 && ipset -X $IPSET_BLACKLIST >/dev/null 2>&1 &
	ipset -F $IPSET_WHITELIST >/dev/null 2>&1 && ipset -X $IPSET_WHITELIST >/dev/null 2>&1 &
	ipset -F $IPSET_VPSIPLIST >/dev/null 2>&1 && ipset -X $IPSET_VPSIPLIST >/dev/null 2>&1 &
	ipset -F $IPSET_LANIPLIST >/dev/null 2>&1 && ipset -X $IPSET_LANIPLIST >/dev/null 2>&1 &
	kill_all pdnsd Pcap_DNSProxy brook dns2socks haproxy dns-forwarder chinadns dnsproxy redsocks2
	ps -w | grep -E "$CONFIG_TCP_FILE|$CONFIG_UDP_FILE|$CONFIG_SOCKS5_FILE" | grep -v "grep" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	ps -w | grep "kcptun_client" | grep "$KCPTUN_REDIR_PORT" | grep -v "grep" | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1 &
	rm -rf /var/pdnsd/pdnsd.cache
	rm -rf $TMP_DNSMASQ_PATH
	rm -rf $CONFIG_PATH
	stop_dnsmasq
	stop_crontab
	echolog "关闭相关服务，清理相关文件和缓存完成。\n"
	sleep 1s
}

case $1 in
stop)
	stop
	;;
start)
	start
	;;
boot)
	boot
	;;
*)
esac
