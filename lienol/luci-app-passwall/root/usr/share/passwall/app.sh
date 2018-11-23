#!/bin/sh

. $IPKG_INSTROOT/lib/functions.sh
. $IPKG_INSTROOT/lib/functions/service.sh

CONFIG=passwall
CONFIG_TCP_FILE=/var/etc/${CONFIG}_TCP.json
CONFIG_UDP_FILE=/var/etc/${CONFIG}_UDP.json
CONFIG_SOCKS5_FILE=/var/etc/${CONFIG}_SOCKS5.json
LOCK_FILE=/var/lock/$CONFIG.lock
lb_FILE=/var/etc/haproxy.cfg
RUN_PID_PATH=/var/run/$CONFIG
LOG_FILE=/var/log/$CONFIG.log
SS_PATH=/usr/share/$CONFIG
SS_PATH_RULE=$SS_PATH/rule
SS_PATH_DNSMASQ=$SS_PATH/dnsmasq.d
TMP_DNSMASQ_PATH=/var/dnsmasq.d
DNSMASQ_PATH=/etc/dnsmasq.d
lanip=$(uci get network.lan.ipaddr)
ip_prefix_hex=$(echo $lanip | awk -F "." '{printf ("0x%02x", $1)} {printf ("%02x", $2)} {printf ("%02x", $3)} {printf ("00/0xffffff00")}')
Date=$(date "+%Y-%m-%d %H:%M:%S")
IPSET_LANIPLIST="laniplist"
IPSET_ROUTER="router"	
IPSET_GFW="gfwlist"
IPSET_CHN="chnroute"
IPSET_BLACKLIST="blacklist"
IPSET_WHITELIST="whitelist"
iptables_nat="iptables -t nat"
iptables_mangle="iptables -t mangle"
ip6tables_nat="ip6tables -t nat"

find_bin(){
	name=$1
	result=`find /usr/*bin -iname "$name" -type f`
	if [ -z "$result" ]; then
		echo ""
	else
		echo "$result"
	fi
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

echolog()
{
	echo -e "$Date: $1" >> $LOG_FILE
}

TCP_REDIR=$(config_t_get global tcp_redir 0)
TCP_REDIR_SERVER=""
UDP_REDIR=$(config_t_get global udp_redir 0)
UDP_REDIR_SERVER=""
SOCKS5_PROXY=$(config_t_get global socks5_proxy 0)
SOCKS5_PROXY_SERVER=""

if [ "$TCP_REDIR" == "1" ]; then
	TCP_REDIR_SERVER=$(config_t_get global tcp_redir_server nil)
else
	TCP_REDIR_SERVER="nil"
fi

if [ "$UDP_REDIR" == "1" ]; then
	UDP_REDIR_SERVER=$(config_t_get global udp_redir_server nil)
	[ "$UDP_REDIR_SERVER" == "default" ] && UDP_REDIR_SERVER=$TCP_REDIR_SERVER
else
	UDP_REDIR_SERVER="nil"
fi

if [ "$SOCKS5_PROXY" == "1" ]; then
	SOCKS5_PROXY_SERVER=$(config_t_get global socks5_proxy_server nil)
	[ "$SOCKS5_PROXY_SERVER" == "default" ] && SOCKS5_PROXY_SERVER=$TCP_REDIR_SERVER
else
	SOCKS5_PROXY_SERVER="nil"
fi
TCPSSBIN=""
UDPSSBIN=""
SOCKS5SSBIN=""
TCP_REDIR_SERVER_IP=""
UDP_REDIR_SERVER_IP=""
SOCKS5_PROXY_SERVER_IP=""
TCP_REDIR_SERVER_IPV6=""
UDP_REDIR_SERVER_IPV6=""
SOCKS5_PROXY_SERVER_IPV6=""

load_config() {
	[ "$TCP_REDIR_SERVER" == "nil" -a "$UDP_REDIR_SERVER" == "nil" -a "$SOCKS5_PROXY_SERVER" == "nil" ] && {
		echolog "没有选择服务器！" 
		return 1
	}
	PROXY_MODE=$(config_t_get global proxy_mode gfwlist)
	DNS_MODE=$(config_t_get global dns_mode ChinaDNS)
	UP_DNS_MODE=$(config_t_get global up_dns_mode OpenDNS_443)
	SSR_SERVER_PASSWALL=$(config_t_get global ssr_server_passwall 0)
	DNS_FORWARD=$(config_t_get global_dns dns_forward 208.67.222.222:443)
	DNS_FORWARD_IP=$(echo "$DNS_FORWARD" | awk -F':' '{print $1}')
	DNS_FORWARD_PORT=$(echo "$DNS_FORWARD" | awk -F':' '{print $2}')
	DNS1=$(config_t_get global_dns dns_1)
	DNS2=$(config_t_get global_dns dns_2)
	TCP_REDIR_PORT=$(config_t_get global_proxy tcp_redir_port 1031)
	UDP_REDIR_PORT=$(config_t_get global_proxy udp_redir_port 1032)
	SOCKS5_PROXY_PORT=$(config_t_get global_proxy socks5_proxy_port 1033)
	KCPTUN_REDIR_PORT=$(config_t_get global_proxy kcptun_port 11183)
	PROXY_IPV6=$(config_t_get global_proxy proxy_ipv6 0)
	config_load $CONFIG
	[ "$TCP_REDIR_SERVER" != "nil" ] && gen_config_file $TCP_REDIR_SERVER TCP
	[ "$UDP_REDIR_SERVER" != "nil" ] && gen_config_file $UDP_REDIR_SERVER UDP
	[ "$SOCKS5_PROXY_SERVER" != "nil" ] && gen_config_file $SOCKS5_PROXY_SERVER Socks5
	return 0
}

gen_ss_ssr_config_file() {
	local server_port encrypt_method
	server_port=$(config_get $2 server_port)
	encrypt_method=$(config_get $2 ss_encrypt_method)
	[ "$1" == "ssr" ] && encrypt_method=$(config_get $2 ssr_encrypt_method)
	[ "$4" == "kcptun" ] && {
		server_ip=127.0.0.1
		server_host=127.0.0.1
		server_port=$KCPTUN_REDIR_PORT
	}
	cat <<-EOF >$3
	{
		"server": "$server_host",
		"_comment": "$server_ip",
		"server_port": $server_port,
		"local_address": "0.0.0.0",
		"local_port": $REDIR_PORT,
		"password": "$(config_get $2 password)",
		"timeout": $(config_get $2 timeout),
		"method": "$encrypt_method",
		"fast_open": $(config_get $2 fast_open),
		"reuse_port": true,
	EOF
	[ "$1" == "ssr" ] && {
		cat <<-EOF >>$3
		"protocol": "$(config_get $2 protocol)",
		"protocol_param": "$(config_get $2 protocol_param)",
		"obfs": "$(config_get $2 obfs)",
		"obfs_param": "$(config_get $2 obfs_param)"
		EOF
	}
	echo -e "}" >> $3
}

gen_config_file() {
	local server_host server_ip server_type use_ipv6 network_type
	server_host=$(config_get $1 server)
	use_ipv6=$(config_get $1 use_ipv6)
	network_type="ipv4"
	[ "$use_ipv6" == "1" ] && network_type="ipv6"
	server_ip=$(get_host_ip $network_type $server_host)
	server_type=$(config_get $1 server_type)
	echolog "$2服务器IP地址:$server_ip"
	
	if [ "$2" == "UDP" ]; then
		if [ "$network_type" == "ipv6" ];then
			UDP_REDIR_SERVER_IPV6=$server_ip
		else
			UDP_REDIR_SERVER_IP=$server_ip
		fi
		REDIR_PORT=$UDP_REDIR_PORT
		echolog "生成$2转发配置文件" 
		if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
			UDPSSBIN=$server_type
			gen_ss_ssr_config_file $server_type $UDP_REDIR_SERVER $CONFIG_UDP_FILE
		fi
		if [ "$server_type" == "v2ray" ]; then
			lua $SS_PATH/genv2config.lua $UDP_REDIR_SERVER udp $REDIR_PORT nil > $CONFIG_UDP_FILE
		fi
	fi
	
	if [ "$2" == "Socks5" ]; then
		if [ "$network_type" == "ipv6" ];then
			SOCKS5_PROXY_SERVER_IPV6=$server_ip
		else
			SOCKS5_PROXY_SERVER_IP=$server_ip
		fi
		REDIR_PORT=$SOCKS5_PROXY_PORT
		echolog "生成$2代理配置文件" 
		if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
			SOCKS5SSBIN=$server_type
			gen_ss_ssr_config_file $server_type $SOCKS5_PROXY_SERVER $CONFIG_SOCKS5_FILE
		fi
		if [ "$server_type" == "v2ray" ]; then
			lua $SS_PATH/genv2config.lua $SOCKS5_PROXY_SERVER nil nil $REDIR_PORT > $CONFIG_SOCKS5_FILE
		fi
	fi
	
	if [ "$2" == "TCP" ]; then
		if [ "$network_type" == "ipv6" ];then
			TCP_REDIR_SERVER_IPV6=$server_ip
		else
			TCP_REDIR_SERVER_IP=$server_ip
		fi
		if [ "$server_type" == "v2ray" ]; then
			lua $SS_PATH/genv2config.lua $TCP_REDIR_SERVER tcp $TCP_REDIR_PORT nil > $CONFIG_TCP_FILE
		else
			local kcptun_use kcptun_server_host kcptun_port kcptun_config
			kcptun_use=$(config_get $1 use_kcp)
			kcptun_server_host=$(config_get $1 kcp_server)
			kcptun_port=$(config_get $1 kcp_port)
			kcptun_config=$(config_get $1 kcp_opts)
			
			lbenabled=$(config_t_get global_haproxy balancing_enable 0)
			USEKCP=$kcptun_use
			kcptun_path=""
			if [ "$kcptun_use" == "1" ] && ([ -z "$kcptun_port" ] || [ -z "$kcptun_config" ]); then
				echolog "【检测到启用KCP，但未配置KCP参数】，跳过~"
			fi
			if [ "$kcptun_use" == "1" -a -n "$kcptun_port" -a -n "$kcptun_config" -a "$lbenabled" == "1" ];then
				echolog "【检测到启用KCP，但KCP与负载均衡二者不能同时开启】，跳过~"
			fi
			
			if [ -f "$(config_t_get global_kcptun kcptun_client_file)" ];then
				kcptun_path=$(config_t_get global_kcptun kcptun_client_file)
			else
				temp=$(find_bin kcptun_client)
				[ -n "$temp" ] && kcptun_path=$temp
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
					echolog "生成KCP加速$2转发配置文件"
					TCPSSBIN=$server_type
					REDIR_PORT=$TCP_REDIR_PORT
					gen_ss_ssr_config_file $server_type $TCP_REDIR_SERVER $CONFIG_TCP_FILE "kcptun"
				fi
			else
				if [ "$server_type" == "ss" -o "$server_type" == "ssr" ]; then
					echolog "生成$2转发配置文件"
					TCPSSBIN=$server_type
					REDIR_PORT=$TCP_REDIR_PORT
					gen_ss_ssr_config_file $server_type $TCP_REDIR_SERVER $CONFIG_TCP_FILE
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
		$kcptun_bin -l 0.0.0.0:$KCPTUN_REDIR_PORT -r $2:$3 $4 >/dev/null 2>&1 &
	fi
}

start_tcp_redir() {
	config_load $CONFIG
	config_get server_type $TCP_REDIR_SERVER server_type
	config_get server_port $TCP_REDIR_SERVER server_port
	config_get server_password $TCP_REDIR_SERVER password
	config_get kcptun_use $TCP_REDIR_SERVER use_kcp 0
	fail=0
	if [ "$server_type" == "v2ray" ]; then
		v2ray_bin=$(find_bin v2ray)
		if [ -z "$v2ray_bin" ]; then
			echolog "找不到V2ray主程序，无法启用！！！" 
			fail=1
		else
			$v2ray_bin -config=$CONFIG_TCP_FILE > /var/log/v2ray_tcp.log &
		fi
	elif [ "$server_type" == "brook" ]; then
		brook_bin=$(find_bin brook)
		if [ -z "$brook_bin" ]; then
			echolog "找不到Brook主程序，无法启用！！！" 
			fail=1
		else
			if [ "$kcptun_use" == "1" ]; then
				$brook_bin tproxy -l 0.0.0.0:$TCP_REDIR_PORT -s 127.0.0.1:$KCPTUN_REDIR_PORT -p $server_password &>/dev/null &
			else
				$brook_bin tproxy -l 0.0.0.0:$TCP_REDIR_PORT -s $server_host:$server_port -p $server_password &>/dev/null &
			fi
		fi
	else
		ss_bin=$(find_bin "$TCPSSBIN"-redir)
		if [ -z "$ss_bin" ]; then
			echolog "找不到SS主程序，无法启用！！！" 
			fail=1
		else
			$ss_bin -c $CONFIG_TCP_FILE > /dev/null 2>&1 &
		fi
	fi
	[ "$fail" == "0" ] && echolog "运行$server_type TCP透明代理..." 
	[ "$fail" == "1" ] && {
		uci set $CONFIG.@global[0].tcp_redir_server=nil
		uci commit $CONFIG
	}
}

start_udp_redir() {
	if [ "$UDP_REDIR_SERVER" != "nil" ];then
		config_load $CONFIG
		config_get server_type $UDP_REDIR_SERVER server_type
		fail=0
		if [ "$server_type" == "v2ray" ]; then
			v2ray_bin=$(find_bin v2ray)
			if [ -z "$v2ray_bin" ]; then
				echolog "找不到V2ray主程序，无法启用！！！" 
				fail=1
			else
				$v2ray_bin -config=$CONFIG_UDP_FILE > /var/log/v2ray_udp.log &
			fi
		elif [ "$server_type" == "brook" ]; then
			brook_bin=$(find_bin brook)
			if [ -z "$brook_bin" ]; then
				echolog "找不到Brook主程序，无法启用！！！" 
				fail=1
			else
				$brook_bin tproxy -l 0.0.0.0:$UDP_REDIR_PORT -s $server_host:$server_port -p $server_password &>/dev/null &
			fi
		else
			ss_bin=$(find_bin "$UDPSSBIN"-redir)
			if [ -z "$ss_bin" ]; then
				echolog "找不到SS主程序，无法启用！！！" 
				fail=1
			else
				$ss_bin -c $CONFIG_UDP_FILE -U > /dev/null 2>&1 &
			fi
		fi
		[ "$fail" == "0" ] && echolog "运行$server_type UDP透明代理..." 
		[ "$fail" == "1" ] && {
			uci set $CONFIG.@global[0].udp_redir=0
			uci commit $CONFIG
		}
	fi
}

start_socks5_proxy() {
	if [ "$SOCKS5_PROXY_SERVER" != "nil" ];then
		config_load $CONFIG
		config_get server_type $SOCKS5_PROXY_SERVER server_type
		fail=0
		if [ "$server_type" == "v2ray" ]; then
			v2ray_bin=$(find_bin v2ray)
			if [ -z "$v2ray_bin" ]; then
				echolog "找不到V2ray主程序，无法启用！！！" 
				fail=1
			else
				$v2ray_bin -config=$CONFIG_SOCKS5_FILE > /var/log/v2ray_socks5.log &
			fi
		elif [ "$server_type" == "brook" ]; then
			brook_bin=$(find_bin brook)
			if [ -z "$brook_bin" ]; then
				echolog "找不到Brook主程序，无法启用！！！" 
				fail=1
			else
				$brook_bin client -l 0.0.0.0:$SOCKS5_PROXY_PORT -i 0.0.0.0 -s $server_host:$server_port -p $server_password &>/dev/null &
			fi
		else
			ss_bin=$(find_bin "$SOCKS5SSBIN"-local)
			if [ -z "$ss_bin" ]; then
				echolog "找不到SS主程序，无法启用！！！" 
				fail=1
			else
				$ss_bin -c $CONFIG_SOCKS5_FILE -b 0.0.0.0 > /dev/null 2>&1 &
			fi
		fi
		[ "$fail" == "0" ] && echolog "运行$server_type Socks5代理..." 
		[ "$fail" == "1" ] && {
			uci set $CONFIG.@global[0].socks5_proxy=0
			uci commit $CONFIG
		}
	fi
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	if [ "$logsnum" -gt 300 ];then
		rm -f $LOG_FILE >/dev/null 2>&1 &
		echolog "日志文件过长，清空处理！" 
	fi
}

stop_cru() {
	sed -i "/$CONFIG/d" /etc/crontabs/root >/dev/null 2>&1 &
	#sed -i "/reconnection.sh/d" /etc/crontabs/root >/dev/null 2>&1 &
	#sed -i "/ssruleupdate.sh/d" /etc/crontabs/root >/dev/null 2>&1 &
	#sed -i "/onlineconfig.sh/d" /etc/crontabs/root >/dev/null 2>&1 &
	echolog "清理自动更新规则。" 
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
			echo "0 $dayupdatesubscribe * * * $SS_PATH/onlineconfig.sh" >> /etc/crontabs/root
			echolog "设置服务器订阅自动更新规则在每天 $dayupdatesubscribe 点。" 
		else
			echo "0 $dayupdatesubscribe * * $weekupdate $SS_PATH/onlineconfig.sh" >> /etc/crontabs/root
			echolog "设置服务器订阅自动更新规则在星期 $weekupdate 的 $dayupdatesubscribe 点。" 
		fi
	else
		sed -i '/onlineconfig.sh/d' /etc/crontabs/root >/dev/null 2>&1 &
	fi
}

auto_stop() {
	auto_on=$(config_t_get global_delay auto_on)
	if [ "$auto_on" = "0" ];then
		sed -i '/$CONFIG stop/d' /etc/crontabs/root >/dev/null 2>&1 &
		sed -i '/$CONFIG start/d' /etc/crontabs/root >/dev/null 2>&1 &
		sed -i '/$CONFIG restart/d' /etc/crontabs/root >/dev/null 2>&1 &
	fi
	disconnect_reconnect_on=$(config_t_get global_delay disconnect_reconnect_on)
	if [ "$disconnect_reconnect_on" = "0" ];then
		sed -i '$SS_PATH/reconnection.sh/d' /etc/crontabs/root >/dev/null 2>&1 &
	fi
	/etc/init.d/cron restart
	echolog "清理定时自动开关设置。" 
}

auto_start() {
	auto_on=$(config_t_get global_delay auto_on)
	sed -i '/$CONFIG/d' /etc/crontabs/root >/dev/null 2>&1 &
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
	
	disconnect_reconnect_on=$(config_t_get global_delay disconnect_reconnect_on)
	if [ "$disconnect_reconnect_on" = "1" ];then
		disconnect_reconnect_time=$(config_t_get global_delay disconnect_reconnect_time)
		[ -n "$disconnect_reconnect_time" ] && {
			echo "*/$disconnect_reconnect_time * * * * $SS_PATH/reconnection.sh" >> /etc/crontabs/root
			echolog "设置每$disconnect_reconnect_time分钟检测一次是否断线。" 
		}
	fi
	/etc/init.d/cron restart
}

start_dns() {
	case "$DNS_MODE" in
		dns2socks)
			dns2socks_bin=$(find_bin dns2socks)
			sslocal_bin=$(find_bin "$TCPSSBIN"-local)
			if [ -z "$dns2socks_bin" ] || [ -z "$sslocal_bin" ]; then
				echolog "找不到dns2socks或$TCPSSBIN-local主程序，无法启用！！！" 
			else
				nohup $sslocal_bin \
				-c $CONFIG_TCP_FILE \
				-l 3080 \
				-f $RUN_PID_PATH/$TCPSSBIN-local.pid \
				>/dev/null 2>&1 &
				nohup $dns2socks_bin \
				127.0.0.1:3080 \
				$DNS_FORWARD \
				127.0.0.1:7913 \
				>/dev/null 2>&1 &
				echolog "运行DNS转发方案：dns2socks+$TCPSSBIN-local..." 
			fi
		;;
		Pcap_DNSProxy)
			pcapDnsproxy_bin=$(find_bin Pcap_DNSProxy)
			if [ -z "$pcapDnsproxy_bin" ]; then
				echolog "找不到Pcap_DNSProxy主程序，无法启用！！！" 
			else
				nohup $pcapDnsproxy_bin -c /etc/pcap-dnsproxy >/dev/null 2>&1 &
				echolog "运行DNS转发方案：Pcap_DNSProxy..." 
			fi
		;;
		pdnsd)
			start_pdnsd		
			echolog "运行DNS转发方案：Pdnsd..." 
		;;
		cdns)
			cdns_bin=$(find_bin cdns)
			if [ -z "$cdns_bin" ]; then
				echolog "找不到cdns主程序，无法启用！！！" 
			else
				nohup $cdns_bin -c /etc/cdns.json >/dev/null 2>&1 &
				echolog "运行DNS转发方案：cdns..." 
			fi
		;;
		chinadns)
			chinadns_bin=$(find_bin chinadns)
			if [ -z "$chinadns_bin" ]; then
				echolog "找不到ChinaDNS主程序，无法启用！！！" 
			else
				other=1
				echolog "运行DNS转发方案：ChinaDNS..." 
				case "$UP_DNS_MODE" in
					OpenDNS_443)
						other=0
						nohup $chinadns_bin \
						-p 7913 \
						-c $SS_PATH_RULE/chnroute \
						-m -d \
						-s $DNS1,208.67.222.222:443 \
						>/dev/null 2>&1 &
						echolog "运行ChinaDNS上游转发方案：OpenDNS：208.67.222.222:443..." 
					;;
					OpenDNS_5353)
						other=0
						nohup $chinadns_bin \
						-p 7913 \
						-c $SS_PATH_RULE/chnroute \
						-m -d \
						-s $DNS1,208.67.222.222:5353 \
						>/dev/null 2>&1 &
						echolog "运行ChinaDNS上游转发方案：OpenDNS：208.67.222.222:5353..." 
					;;
					dnsproxy)
						dnsproxy_bin=$(find_bin dnsproxy)
						if [ -z "$dnsproxy_bin" ]; then
							echolog "找不到dnsproxy主程序，无法启用！！！" 
						else
							nohup $dnsproxy_bin \
							-d -T \
							-p 7913 \
							-R $DNS_FORWARD_IP \
							-P $DNS_FORWARD_PORT \
							>/dev/null 2>&1 &
							echolog "运行ChinaDNS上游转发方案：dnsproxy..." 
						fi
					;;
					dns-forwarder)
						dnsforwarder_bin=$(find_bin dns-forwarder)
						if [ -z "$dnsforwarder_bin" ]; then
							echolog "找不到dns-forwarder主程序，无法启用！！！" 
						else
							nohup $dnsforwarder_bin \
							-p 7913 \
							-s $DNS_FORWARD \
							>/dev/null 2>&1 &
							echolog "运行ChinaDNS上游转发方案：dns-forwarder..." 
						fi
					;;
				esac
				if [ "$other" = "1" ];then
					nohup $chinadns_bin \
					-p 7923 \
					-c $SS_PATH_RULE/chnroute \
					-m -d \
					-s $DNS1,127.0.0.1:7913 \
					>/dev/null 2>&1 &
				fi
			fi
		;;
	esac
	echolog "若无法使用，请尝试其他方案！" 
}

add_dnsmasq() {
	mkdir -p $TMP_DNSMASQ_PATH
	mkdir -p $DNSMASQ_PATH
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
			isp_dns=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" |sort -u |grep -v 0.0.0.0 |grep -v 127.0.0.1`
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
							route add -net ${isp_ip} netmask 255.255.255.255 ${dnsport}
							echolog "添加运营商DNS出口路由表：$dnsport" 
						done
					}
					[ "$DNS1" != "dnsbyisp" ] && {
						route add -net ${DNS1} netmask 255.255.255.255 ${dnsport}
						echolog "添加DNS1出口路由表：$dnsport" 
						echo server=$DNS1 >> /etc/dnsmasq.conf
					}
					[ "$DNS2" != "dnsbyisp" ] && {
						route add -net ${DNS2} netmask 255.255.255.255 ${dnsport}
						echolog "添加DNS2出口路由表：$dnsport" 
						echo server=$DNS2 >> /etc/dnsmasq.conf
					}
					break
				fi
			done
		else
			isp_dns=`cat /tmp/resolv.conf.auto 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" |sort -u |grep -v 0.0.0.0 |grep -v 127.0.0.1`
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
					route add -net ${DNS1} netmask 255.255.255.255 ${dnsport}
					echolog "添加DNS1出口路由表：$dnsport" 
					route add -net ${DNS2} netmask 255.255.255.255 ${dnsport}
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
	
	cp -pR $TMP_DNSMASQ_PATH/* $DNSMASQ_PATH
	if [ "$restdns" == 1 ];then
		echolog "重启Dnsmasq。。。" 
		/etc/init.d/dnsmasq restart  2>/dev/null
	fi
}

start_pdnsd() {
	pdnsd_bin=$(find_bin pdnsd)
	if [ -z "$pdnsd_bin" ]; then
		echolog "找不到pdnsd主程序，无法启用！！！" 
	else
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
	$pdnsd_bin --daemon -c $CACHEDIR/pdnsd.conf -p $RUN_PID_PATH/pdnsd.pid -d
	fi
}

stop_dnsmasq() {
	if [ "$TCP_REDIR_SERVER" == "nil" ]; then
		rm -rf $TMP_DNSMASQ_PATH/*
		rm -rf $DNSMASQ_PATH/*
		/etc/init.d/dnsmasq restart  2>/dev/null
		echolog "没有选择服务器！" 
	fi
}

gen_basecfg(){
	bport=$(config_t_get global_haproxy haproxy_port)
	cat <<-EOF >$lb_FILE
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
}

gen_lbsscfg(){
	echolog "负载均衡服务启动中..." 
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
		echo "    server ss$i $bips:$bports weight $bweight check inter 1500 rise 1 fall 3 $bbackup" >> $lb_FILE
		
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
					route add -net ${bips} netmask 255.255.255.255 ${exports}
					echolog "添加SS出口路由表：$exports" 
					echo "$bips" >> /tmp/balancing_ip
					break
				fi
			done
		fi
	done
}
gen_lbadmincfg(){
	adminstatus=$(config_t_get global_haproxy admin_enable)
	if [ "$adminstatus" = "1" ];then
		adminport=$(config_t_get global_haproxy admin_port)
		adminuser=$(config_t_get global_haproxy admin_user)
		adminpassword=$(config_t_get global_haproxy admin_password)
	cat <<-EOF >>$lb_FILE
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
}

start_sslb(){
	lbenabled=$(config_t_get global_haproxy balancing_enable 0)
	if [ "$lbenabled" = "1" ];then
		haproxy_bin=$(find_bin haproxy)
		if [ -z "$haproxy_bin" ]; then
			echolog "找不到haproxy主程序，无法启用！！！" 
		else
			gen_basecfg
			gen_lbsscfg
			gen_lbadmincfg
			nohup $haproxy_bin -f $lb_FILE 2>&1 &
			echolog "负载均衡服务运行成功！" 
		fi
	else
		echolog "负载均衡服务未启用！"     
	fi
} 

add_vps_port() {
	multiwan=$(config_t_get global_dns wan_port 0)
	lbenabled=$(config_t_get global_haproxy balancing_enable 0)
	if [ "$lbenabled" == "0" ] && [ "$multiwan" != "0" ]; then
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
				route add -net ${server_ip} netmask 255.255.255.255 ${multiwan}
				echolog "添加SS出口路由表：$multiwan" 
				echo "$server_ip" > /tmp/ss_ip
				break
			fi
		done
	fi
}

del_vps_port() {
	ssip=$(cat /tmp/ss_ip 2> /dev/null)
	if [ ! -z "$ssip" ]; then
		route del -net ${ssip} netmask 255.255.255.255
		echolog "删除SS出口路由表：$multiwan" 
		rm /tmp/ss_ip
	fi
}

dns_hijack(){
	dnshijack=$(config_t_get global_dns dns_53)
	if [ "$dnshijack" = "1" ];then
		chromecast_nu=`$iptables_nat -L PREROUTING -v -n --line-numbers|grep "dpt:53"|awk '{print $1}'`
		is_right_lanip=`$iptables_nat -L PREROUTING -v -n --line-numbers|grep "dpt:53" |grep "$lanip"`
		if [ -z "$chromecast_nu" ]; then
			echolog "添加接管局域网DNS解析规则..." 
			$iptables_nat -A PREROUTING -i br-lan -p udp --dport 53 -j DNAT --to $lanip 2>/dev/null
		else
			if [ -z "$is_right_lanip" ]; then
				echolog "添加接管局域网DNS解析规则..." 
				$iptables_nat -D PREROUTING $chromecast_nu >/dev/null 2>&1
				$iptables_nat -A PREROUTING -i br-lan -p udp --dport 53 -j DNAT --to $lanip 2>/dev/null
			else
				echolog " DNS劫持规则已经添加，跳过~" >>$LOG_FILE
			fi
		fi
	fi
}

load_acl(){
	local enabled
	local ipaddr
	local macaddr
	local proxy_mode
	local tcp_redir_ports
	local udp_redir_ports
	config_get enabled $1 enabled
	config_get ipaddr $1 ipaddr
	config_get macaddr $1 macaddr
	config_get acl_mode $1 proxy_mode
	config_get tcp_redir_ports $1 tcp_redir_ports
	config_get udp_redir_ports $1 udp_redir_ports
	[ -z "$tcp_redir_ports" ] && tcp_redir_ports="1:65535"
	[ -z "$udp_redir_ports" ] && udp_redir_ports="1:65535"
	local ip_mark=`get_ip_mark $ipaddr`								 
	[ "$enabled" == "1" -a -n "$acl_mode" ] && {
		if [ -n "$ipaddr" ] || [ -n "$macaddr" ]; then
			if [ -n "$ipaddr" -a -n "$macaddr" ]; then
				echolog "加载ACL规则：IP为$ipaddr，MAC为$macaddr，TCP代理转发端口为$tcp_redir_ports，UDP代理转发端口为$udp_redir_ports，模式为：$acl_mode" 
			else
				[ -n "$ipaddr" ] && echolog "加载ACL规则：IP为$ipaddr，TCP代理转发端口为$tcp_redir_ports，UDP代理转发端口为$udp_redir_ports，模式为：$acl_mode" 
				[ -n "$macaddr" ] && echolog "加载ACL规则：MAC为$macaddr，TCP代理转发端口为$tcp_redir_ports，UDP代理转发端口为$udp_redir_ports，模式为：$acl_mode" 
			fi
			$iptables_mangle -A SS $(factor $ipaddr "-s") -p tcp $(factor $macaddr "-m mac --mac-source") $(factor $tcp_redir_ports "-m multiport --dport") -$(get_jump_mode $acl_mode) $(get_action_chain $acl_mode)
			$iptables_mangle -A SS $(factor $ipaddr "-s") -p udp $(factor $macaddr "-m mac --mac-source") $(factor $udp_redir_ports "-m multiport --dport") -$(get_jump_mode $acl_mode) $(get_action_chain $acl_mode)
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

add_firewall_rule() {
	echolog "开始加载防火墙规则..." 
	echolog "默认模式：$PROXY_MODE" 
	ipset -! create $IPSET_LANIPLIST nethash && ipset flush $IPSET_LANIPLIST
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
			ipset -! add $IPSET_WHITELIST $ispip >/dev/null 2>&1
		done
	}
		
	#	忽略特殊IP段
	lan_ip=`ifconfig br-lan | grep "inet addr" | awk '{print $2}' | awk -F : '{print $2}'` #路由器lan IP
	lan_ipv4=`ip address show br-lan | grep -w "inet" |awk '{print $2}'`  #当前LAN IPv4段
	[ -n "$lan_ipv4" ] && {
		ipset add $IPSET_LANIPLIST $lan_ipv4
	}
	[ "$use_ipv6" != "1" ] && {
		[ -n "$TCP_REDIR_SERVER_IP" ] && ipset add $IPSET_LANIPLIST $TCP_REDIR_SERVER_IP
		[ -n "$UDP_REDIR_SERVER_IP" ] && ipset add $IPSET_LANIPLIST $UDP_REDIR_SERVER_IP
		[ -n "$SOCKS5_PROXY_SERVER_IP" ] && ipset add $IPSET_LANIPLIST $SOCKS5_PROXY_SERVER_IP
	}
	
	$iptables_mangle -N SS
	$iptables_mangle -A SS -m set --match-set $IPSET_LANIPLIST dst -j RETURN
	$iptables_mangle -A SS -m set --match-set $IPSET_WHITELIST dst -j RETURN
	$iptables_mangle -N SS_GLO
	$iptables_mangle -N SS_GFW
	$iptables_mangle -N SS_CHN
	$iptables_mangle -N SS_HOME
	$iptables_mangle -N SS_GAME
	
	tcp_redir_ports=$(config_t_get global tcp_redir_ports)
	udp_redir_ports=$(config_t_get global udp_redir_ports)
	
	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100
	
	#	生成TCP转发规则
	if [ "$TCP_REDIR_SERVER" != "nil" ];then
		if [ "$server_type" == "brook" ]; then
			$iptables_mangle -A PREROUTING -p tcp -m socket -j MARK --set-mark 1
			$iptables_mangle -A PREROUTING -p tcp -j SS
			
			$iptables_mangle -A SS -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_BLACKLIST dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			#	全局模式
			$iptables_mangle -A SS_GLO -p tcp -m multiport -–dport $tcp_redir_ports -j TPROXY --tproxy-mark 0x1/0x1 --on-port $TCP_REDIR_PORT
			
			#	GFWLIST模式
			$iptables_mangle -A SS_GFW -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_GFW dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			$iptables_mangle -A SS_GFW -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_ROUTER dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	大陆白名单模式
			$iptables_mangle -A SS_CHN -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_CHN dst -j RETURN
			$iptables_mangle -A SS_CHN -p tcp -m multiport -–dport $tcp_redir_ports -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	回国模式
			$iptables_mangle -A SS_HOME -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_CHN dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			
			#	游戏模式
			$iptables_mangle -A SS_GAME -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_CHN dst -j RETURN
			
			#	用于本机流量转发，默认只走router
			$iptables_mangle -A SS -s $lan_ip -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_ROUTER dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
			$iptables_mangle -A OUTPUT -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_ROUTER dst -j MARK --set-mark 1
			[ "$SSR_SERVER_PASSWALL" == "1" ] && {
				$iptables_mangle -A SS -s $lan_ip -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_GFW dst -j TPROXY --on-port $TCP_REDIR_PORT --tproxy-mark 0x1/0x1
				$iptables_mangle -A OUTPUT -p tcp -m multiport -–dport $tcp_redir_ports -m set --match-set $IPSET_GFW dst -j MARK --set-mark 1
			}
		else
			$iptables_mangle -A PREROUTING -j SS
			#$iptables_mangle -A SS -p tcp -d $server_ip -m multiport --dports 22 -j TTL --ttl-set 188
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
			$iptables_nat -I OUTPUT -j SS
			$iptables_nat -A OUTPUT -p tcp -m multiport --dport $tcp_redir_ports -m set --match-set $IPSET_ROUTER dst -j REDIRECT --to-ports $TCP_REDIR_PORT
			
			if [ "$SSR_SERVER_PASSWALL" == "1" ];then
				$iptables_nat -A OUTPUT -p tcp -m multiport --dport $tcp_redir_ports -m set --match-set $IPSET_GFW dst -j REDIRECT --to-ports $TCP_REDIR_PORT
			fi
			echolog "IPv4 防火墙TCP转发规则加载完成！" 
		fi
	else
		echolog "主服务器未选择，无法转发TCP！" 
	fi
		
	#  生成UDP转发规则
	if [ "$UDP_REDIR_SERVER" != "nil" ];then
		if [ "$server_type" == "brook" ]; then
			$iptables_mangle -A PREROUTING -p udp -m socket -j MARK --set-mark 1
			$iptables_mangle -A PREROUTING -p udp -j SS
		fi
		$iptables_mangle -I SS 4 -p udp -m set --match-set $IPSET_BLACKLIST dst -j TPROXY --on-port $UDP_REDIR_PORT --tproxy-mark 0x1/0x1
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
		config_foreach load_acl acl_rule
		
	#  加载默认代理模式
		$iptables_mangle -A SS -p tcp -m multiport --dport $tcp_redir_ports -j $(get_action_chain $PROXY_MODE)
		$iptables_mangle -A SS -p udp -m multiport --dport $udp_redir_ports -j $(get_action_chain $PROXY_MODE)
	
	if [ "$PROXY_IPV6" == "1" ];then
		lan_ipv6=`ip address show br-lan | grep -w "inet6" |awk '{print $2}'`  #当前LAN IPv6段
		$ip6tables_nat -N SS
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
		$ip6tables_nat -A PREROUTING -j SS
		$ip6tables_nat -A SS -j SS_GLO
		$ip6tables_nat -I OUTPUT -p tcp -j SS
		echolog "IPv6防火墙规则加载完成！" 
	fi

}

del_firewall_rule() {
	echolog "删除所有防火墙规则..." 

	ipv4_nat_exist=`$iptables_nat -L PREROUTING 2>/dev/null | grep -c "SS"`
	[ -n "$ipv4_nat_exist" ] && {
		until [ "$ipv4_nat_exist" = 0 ]
		do
			rules=`$iptables_nat -L PREROUTING --line-num 2> /dev/null|grep "SS" |awk '{print $1}'`
			for rule in $rules
			do
				$iptables_nat -D PREROUTING $rule 2> /dev/null
				break
			done
			ipv4_nat_exist=`expr $ipv4_nat_exist - 1`
		done
	}
	
	ipv4_output_gfw_exist=`$iptables_nat -L OUTPUT 2>/dev/null | grep -c "$IPSET_GFW"`
	[ -n "$ipv4_output_gfw_exist" ] && {
		until [ "$ipv4_output_gfw_exist" = 0 ]
		do
			rules=`$iptables_nat -L OUTPUT --line-numbers | grep "$IPSET_GFW" | awk '{print $1}'`
			for rule in $rules
			do
				$iptables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv4_output_gfw_exist=`expr $ipv4_output_gfw_exist - 1`
		done
	}
	
	ipv4_output_router_exist=`$iptables_nat -L OUTPUT 2>/dev/null | grep -c "$IPSET_ROUTER"`
	[ -n "$ipv4_output_router_exist" ] && {
		until [ "$ipv4_output_router_exist" = 0 ]
		do
			rules=`$iptables_nat -L OUTPUT --line-numbers | grep "$IPSET_ROUTER" | awk '{print $1}'`
			for rule in $rules
			do
				$iptables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv4_output_router_exist=`expr $ipv4_output_router_exist - 1`
		done
	}
	
	ipv4_output_ss_exist=`$iptables_nat -L OUTPUT 2>/dev/null | grep -c "SS"`
	[ -n "$ipv4_output_ss_exist" ] && {
		until [ "$ipv4_output_ss_exist" = 0 ]
		do
			rules=`$iptables_nat -L OUTPUT --line-numbers | grep "SS" | awk '{print $1}'`
			for rule in $rules
			do
				$iptables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv4_output_ss_exist=`expr $ipv4_output_ss_exist - 1`
		done
	}
	
	ipv6_nat_exist=`$ip6tables_nat -L PREROUTING 2>/dev/null | grep -c "SS"`
	[ -n "$ipv6_nat_exist" ] && {
		until [ "$ipv6_nat_exist" = 0 ]
		do
			rules=`$iptables_nat -L PREROUTING --line-numbers | grep "SS" | awk '{print $1}'`
			for rule in $rules
			do
				$ip6tables_nat -D PREROUTING $rule 2> /dev/null
				break
			done
			ipv6_nat_exist=`expr $ipv6_nat_exist - 1`
		done
	}
	
	ipv6_output_ss_exist=`$ip6tables_nat -L OUTPUT 2>/dev/null | grep -c "SS"`
	[ -n "$ipv6_output_ss_exist" ] && {
		until [ "$ipv6_output_ss_exist" = 0 ]
		do
			rules=`$iptables_nat -L OUTPUT --line-numbers | grep "SS" | awk '{print $1}'`
			for rule in $rules
			do
				$ip6tables_nat -D OUTPUT $rule 2> /dev/null
				break
			done
			ipv6_output_ss_exist=`expr $ipv6_output_ss_exist - 1`
		done
	}
	
	ipv4_chromecast_nu=`$iptables_nat -L PREROUTING 2>/dev/null | grep "dpt:53"|awk '{print $1}'`
	[ -n "$ipv4_chromecast_nu" ] && $iptables_nat -D PREROUTING $ipv4_chromecast_nu 2>/dev/null
	
	ss_nums=`$iptables_mangle -L PREROUTING 2>/dev/null | grep -c "SS"`
	if [ -n "$ss_nums" ]; then
		until [ "$ss_nums" = 0 ]
		do
			rules=`$iptables_mangle -L PREROUTING --line-num 2> /dev/null|grep "SS" |awk '{print $1}'`
			for rule in $rules
			do
				$iptables_mangle -D PREROUTING $rule 2> /dev/null
				break
			done
			ss_nums=`expr $ss_nums - 1`
		done
	fi
	$iptables_mangle -D PREROUTING -p tcp -m socket -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D PREROUTING -p udp -m socket -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D OUTPUT -p tcp -m set --match-set $IPSET_ROUTER dst -j MARK --set-mark 1 2>/dev/null
	$iptables_mangle -D OUTPUT -p tcp -m set --match-set $IPSET_GFW dst -j MARK --set-mark 1 2>/dev/null
	
	$iptables_nat -F SS 2>/dev/null && $iptables_nat -X SS 2>/dev/null
	$iptables_mangle -D PREROUTING -j SS 2>/dev/null
	$iptables_mangle -F SS 2>/dev/null && $iptables_mangle -X SS 2>/dev/null
	$iptables_mangle -F SS_GLO 2>/dev/null && $iptables_mangle -X SS_GLO 2>/dev/null
	$iptables_mangle -F SS_GFW 2>/dev/null && $iptables_mangle -X SS_GFW 2>/dev/null
	$iptables_mangle -F SS_CHN 2>/dev/null && $iptables_mangle -X SS_CHN 2>/dev/null
	$iptables_mangle -F SS_GAME 2>/dev/null && $iptables_mangle -X SS_GAME 2>/dev/null
	$iptables_mangle -F SS_HOME 2>/dev/null && $iptables_mangle -X SS_HOME 2>/dev/null
	#for temp in $(seq 1 $($iptables_mangle -L PREROUTING | grep -c SS)) do $iptables_mangle -D PREROUTING -p udp -j SS >/dev/null; done
	
	$ip6tables_nat -D PREROUTING -j SS 2>/dev/null
	$ip6tables_nat -F SS 2>/dev/null && $ip6tables_nat -X SS 2>/dev/null
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
	kill -9 $(pidof $@) >/dev/null 2>&1
}

boot() {
	local delay=$(config_t_get global_delay start_delay 0)
	if [ "$delay" -gt 0 ]; then
		[ "$TCP_REDIR_SERVER" != "nil" -o "$UDP_REDIR_SERVER" != "nil" ] && {
			echolog "执行启动延时 $delay 秒后再启动!" 
			sleep $delay && start >/dev/null 2>&1
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
	start_sslb
	#防止并发开启服务
	[ -f "$LOCK_FILE" ] && return 3
	touch "$LOCK_FILE"
	mkdir -p $RUN_PID_PATH /var/etc
	start_tcp_redir
	start_udp_redir
	start_socks5_proxy
	start_dns
	add_dnsmasq
	add_firewall_rule
	dns_hijack
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	auto_start
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
	ipset -F $IPSET_ROUTER >/dev/null 2>&1 &
	ipset -X $IPSET_ROUTER >/dev/null 2>&1 &
	ipset -F $IPSET_GFW >/dev/null 2>&1 &
	ipset -X $IPSET_GFW >/dev/null 2>&1 &		
	kill_all pdnsd cdns Pcap_DNSProxy ss-redir ss-local ssr-redir ssr-local v2ray v2ctl brook dns2socks kcptun_client haproxy dns-forwarder chinadns dnsproxy redsocks2
	rm -rf /var/pdnsd/pdnsd.cache
	rm -rf $RUN_PID_PATH
	rm -rf $CONFIG_TCP_FILE
	rm -rf $CONFIG_UDP_FILE
	rm -rf $CONFIG_SOCKS5_FILE
	stop_dnsmasq
	stop_cru
	auto_stop
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
