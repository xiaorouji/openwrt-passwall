#!/bin/sh
# Copyright (C) 2016 monokoo <realstones2012@gmail.com>

CONFIG=passwall
LOCK_FILE=/var/lock/onlineconfig.lock
Date=$(date "+%Y-%m-%d %H:%M:%S")

config_t_get() {
	local index=0
	[ -n "$3" ] && index=$3
	local ret=$(uci get $CONFIG.@$1[$index].$2 2>/dev/null)
	#echo ${ret:=$3}
	echo $ret
}

config_t_set() {
	index=$3
	uci set $CONFIG.@$1[$index].$2=$4
}

decode_url_link(){
	link=$1
	num=$2
	len=$((${#link}-$num))
	mod4=$(($len%4))
	if [ "$mod4" -gt 0 ]; then
		var="===="
		newlink=${link}${var:$mod4}
		echo -n "$newlink" | sed 's/-/+/g; s/_/\//g' | /usr/bin/base64 -d -i 2> /dev/null
	else
		echo -n "$link" | sed 's/-/+/g; s/_/\//g' | /usr/bin/base64 -d -i 2> /dev/null
	fi
}

get_server_index(){
	[ -f "/etc/config/$CONFIG" ] && {
        ssindex=$(uci show $CONFIG | grep -c "=servers")
	}	
}

get_local_servers(){
	[ -f "/etc/config/$CONFIG" ] && [ "`uci show $CONFIG|grep -c "group="`" -gt 0 ] && {
		get_server_index
		for i in `seq $ssindex -1 1`
		do
			[ "$(uci show $CONFIG.@servers[$(($i-1))]|grep -c "group=")" -eq 1 ] && {
				if [ ! -f "/usr/share/$CONFIG/serverconfig/all_localservers" ]; then
					echo $(config_t_get servers server $(($i-1))) > /usr/share/$CONFIG/serverconfig/all_localservers
				else
					echo $(config_t_get servers server $(($i-1))) >> /usr/share/$CONFIG/serverconfig/all_localservers
				fi
			}
		done
	}
}

add_servers(){
	get_server_index
	uci add $CONFIG servers >/dev/null
	if [ -z "$1" ];then
		config_t_set servers remarks $ssindex $remarks
		config_t_set servers group $ssindex $group
	else
		config_t_set servers remarks $ssindex $remarks
	fi
	config_t_set servers server $ssindex $server
	config_t_set servers use_ipv6 $ssindex 0
	config_t_set servers parsing_ip $ssindex 0
	config_t_set servers server_port $ssindex $server_port
	config_t_set servers protocol $ssindex $protocol
	config_t_set servers protocol_param $ssindex $protoparam
	config_t_set servers ssr_encrypt_method $ssindex $ssr_encrypt_method
	config_t_set servers obfs $ssindex $obfs
	config_t_set servers password $ssindex $password
	config_t_set servers obfs_param $ssindex $obfsparam
	config_t_set servers timeout $ssindex 300
	config_t_set servers local_port $ssindex 1080
	config_t_set servers fast_open $ssindex false
	config_t_set servers server_type $ssindex ssr
	uci commit $CONFIG
}

get_remote_config(){
	decode_link=$1
	server=$(echo "$decode_link" |awk -F':' '{print $1}')
	server_port=$(echo "$decode_link" |awk -F':' '{print $2}')
	protocol=$(echo "$decode_link" |awk -F':' '{print $3}')
	ssr_encrypt_method=$(echo "$decode_link" |awk -F':' '{print $4}')
	obfs=$(echo "$decode_link" |awk -F':' '{print $5}')
	password=$(decode_url_link $(echo "$decode_link" |awk -F':' '{print $6}'|awk -F'/' '{print $1}') 0)
	
	obfsparm_temp=$(echo "$decode_link" |grep -Eo "obfsparam.+" |sed 's/obfsparam=//g'|awk -F'&' '{print $1}')
	[ -n "$obfsparm_temp" ] && obfsparam=$(decode_url_link $obfsparm_temp 0) || obfsparam=''
	protoparam_temp=$(echo "$decode_link" |grep -Eo "protoparam.+" |sed 's/protoparam=//g'|awk -F'&' '{print $1}')
	[ -n "$protoparam_temp" ] && protoparam=$(decode_url_link $protoparam_temp 0) || protoparam=''
	remarks_temp=$(echo "$decode_link" |grep -Eo "remarks.+" |sed 's/remarks=//g'|awk -F'&' '{print $1}')
	[ -n "$remarks_temp" ] && remarks=$(decode_url_link $remarks_temp 0) || remarks='AutoSuB'
	group_temp=$(echo "$decode_link" |grep -Eo "group.+" |sed 's/group=//g'|awk -F'&' '{print $1}')
	[ -n "$group_temp" ] && group=$(decode_url_link $group_temp 0) || group='AutoSuBGroup'
	
	##把全部服务器节点写入文件 /usr/share/$CONFIG/serverconfig/all_onlineservers
	if [ ! -f "/usr/share/$CONFIG/serverconfig/all_onlineservers" ]; then
		echo $server > /usr/share/$CONFIG/serverconfig/all_onlineservers
	else
		echo $server >> /usr/share/$CONFIG/serverconfig/all_onlineservers
	fi
	
}

update_config(){

	isadded_server=$(uci show $CONFIG | grep -c "server='$server'")
	if [ "$isadded_server" -eq 0 ]; then
		add_servers
		let addnum+=1

	else
		index=$(uci show $CONFIG|grep -w "server='$server'" | cut -d '[' -f2|cut -d ']' -f1)
		local_server_port=$(config_t_get servers server_port $index)
		local_protocol=$(config_t_get servers protocol $index)
		local_protocol_param=$(config_t_get servers protocol_param $index)
		local_ssr_encrypt_method=$(config_t_get servers ssr_encrypt_method $index)
		local_obfs=$(config_t_get servers obfs $index)
		local_password=$(config_t_get servers password $index)
		local_group=$(config_t_get servers group $index)
		local_remarks=$(config_t_get servers remarks $index)
		local i=0
		[ "$(uci show $CONFIG.@servers[$index] | grep -c "obfs_param")" -eq 0 ] && \
			config_t_set servers obfs_param $index $obfsparam

		if [ -n "$local_protocol_param" ]; then
			if [ -n "$protoparam" ]; then
				[ "$local_protocol_param" != "$protoparam" ] && config_t_set servers protocol_param $index $protoparam && let i+=1
			else
				config_t_set servers protocol_param $index $protoparam && let i+=1
			fi
		else
			config_t_set servers protocol_param $index $protoparam && [ -n "$protoparam" ] && let i+=1
		fi
		[ "$local_server_port" != "$server_port" ] && config_t_set servers server_port $index $server_port && let i+=1
		[ "$local_protocol" != "$protocol" ] && config_t_set servers protocol $index $protocol && let i+=1
		[ "$local_ssr_encrypt_method" != "$ssr_encrypt_method" ] && config_t_set servers ssr_encrypt_method $index $ssr_encrypt_method && let i+=1
		[ "$local_obfs" != "$obfs" ] && config_t_set servers obfs $index $obfs && let i+=1
		[ "$local_password" != "$password" ] && config_t_set servers password $index $password && let i+=1
		[ "$local_group" != "$group" ] && config_t_set servers group $index $group
		[ "$local_remarks" != "$remarks" ] && config_t_set servers remarks $index $remarks
		[ "$i" -gt 0 ] && uci commit $CONFIG && let updatenum+=1
	fi

}

del_config(){
	##删除订阅服务器已经不存在的节点
	for localserver in $(cat /usr/share/$CONFIG/serverconfig/all_localservers)
	do
		[ "`cat /usr/share/$CONFIG/serverconfig/all_onlineservers |grep -c "$localserver"`" -eq 0 ] && {
			for localindex in $(uci show $CONFIG|grep -w "$localserver" |grep -w "server=" |cut -d '[' -f2|cut -d ']' -f1)
			do
				uci delete $CONFIG.@servers[$localindex]
				uci commit $CONFIG
				let delnum+=1 #删除该节点
			done
		}
	done
}

del_all_config(){
	get_server_index
	[ "`uci show $CONFIG|grep -c "group="`" -eq 0 ] && exit 0
	current_global_server=$(config_t_get global global_server)
	is_sub_server=`uci -q get $CONFIG.$current_global_server.group`
	for i in `seq $ssindex -1 1`
	do
		[ "$(uci show $CONFIG.@servers[$(($i-1))]|grep -c "group=")" -eq 1 ] && uci delete $CONFIG.@servers[$(($i-1))] && uci commit $CONFIG
	done
	[ -n "$is_sub_server" ] && {
		config_t_set global global_server 0 'nil'
		uci commit $CONFIG && /etc/init.d/$CONFIG stop
	}
}

set_firstserver(){

	serverindex=$(uci show $CONFIG|grep "group=" | head -1 | awk -F'.' '{print $2}')
	[ -n "$serverindex" ] && new_global_server=$(uci show $CONFIG.$serverindex.server | awk -F'.' '{print $2}') || exit 0
	config_t_set global global_server 0 $new_global_server
	uci commit $CONFIG
	echo "$Date: 原服务器已被删除，更换使用新的服务器地址：$(uci get $CONFIG.$serverindex.server)" >> $LOG_FILE
	/etc/init.d/$CONFIG restart
}

update_global_server(){
	current_global_server=$(config_t_get global global_server)
	if [ "$current_global_server" != "nil" ]; then
		[ -f "/var/etc/$CONFIG.json" ] && current_server=$(cat /var/etc/$CONFIG.json| grep "_comment\""| awk -F'"' '{print $4}') || exit 0
		tempindex=$(uci show $CONFIG|grep "$current_server" | awk -F'.' '{print $2}')
		if [ -n "$tempindex" ]; then
			for tindex in $tempindex
			do
				[ -n "$(uci get $CONFIG.$tindex.remarks| grep "group=")" ] && \
					[ "$(cat /usr/share/$CONFIG/serverconfig/all_onlineservers |grep -c "$current_server")" -eq 0 ] && \
						set_firstserver
			done
		else
			set_firstserver
		fi
	fi
}
get_ss_config(){
	decode_link=$1
	server=$(echo "$decode_link" |awk -F':' '{print $2}'|awk -F'@' '{print $2}')
	server_port=$(echo "$decode_link" |awk -F':' '{print $3}')
	ssr_encrypt_method=$(echo "$decode_link" |awk -F':' '{print $1}')
	password=$(echo "$decode_link" |awk -F':' '{print $2}'|awk -F'@' '{print $1}')
}


add() {
	SSR_LINKS=$(cat /usr/share/$CONFIG/ssr_link.conf 2>/dev/null)
	[ -n "$SSR_LINKS" ] && {
		[ -f "$LOCK_FILE" ] && return 3
		touch "$LOCK_FILE"
		mkdir -p /usr/share/$CONFIG/serverconfig
		rm -f /usr/share/$CONFIG/serverconfig/*
		for ssrlink in $SSR_LINKS
		do
			if [ -n "`echo -n "$ssrlink" | grep "ssr://"`" ]; then
				new_ssrlink=`echo -n "$ssrlink" | sed 's/ssr:\/\///g'`
				decode_ssrlink=$(decode_url_link $new_ssrlink 1)
				get_remote_config $decode_ssrlink
				is_added=$(uci show $CONFIG | grep -v "group=" | grep -c "server='$server'")
				[ "$is_added" -gt 0 ] && continue
				add_servers 1
			else
				
				if [ -n "`echo -n "$ssrlink" | grep "#"`" ]; then
					new_sslink=`echo -n "$ssrlink" | awk -F'#' '{print $1}' | sed 's/ss:\/\///g'`
					remarks=`echo -n "$ssrlink" | awk -F'#' '{print $2}'`
					
				else
					new_sslink=`echo -n "$ssrlink" | sed 's/ss:\/\///g'`
					remarks='AddedByLink'
				fi
				decode_sslink=$(decode_url_link $new_sslink 1)
				get_ss_config $decode_sslink
				is_added=$(uci show $CONFIG | grep -v "group=" | grep -c "server='$server'")
				[ "$is_added" -gt 0 ] && continue
			fi
		done
		[ -f "/usr/share/$CONFIG/serverconfig/all_onlineservers" ] && rm -f /usr/share/$CONFIG/serverconfig/all_onlineservers
		rm -f "$LOCK_FILE"
	}
}


LOG_FILE=/var/log/$CONFIG.log

start() {
	local addnum=0
	local updatenum=0
	local delnum=0
	echo "$Date: =============================================================================================" >> $LOG_FILE
	echo "$Date:                                                               服务器订阅程序(Shell by stones)" >> $LOG_FILE
	echo "$Date: =============================================================================================" >> $LOG_FILE
	echo "$Date: 开始更新在线订阅列表..." >> $LOG_FILE
	baseurl=$(uci get $CONFIG.@global_subscribe[0].baseurl)  ##订阅地址
	[ -z "$baseurl" ] && echo "$Date: 请先输入订阅地址保存提交之后再更新！" >> $LOG_FILE && exit 0
	
	#防止并发开启服务
	[ -f "$LOCK_FILE" ] && return 3
	touch "$LOCK_FILE"

	[ ! -d "/usr/share/$CONFIG/onlineurl" ] && mkdir -p /usr/share/$CONFIG/onlineurl
	[ ! -d "/usr/share/$CONFIG/serverconfig" ] && mkdir -p /usr/share/$CONFIG/serverconfig
	rm -f /usr/share/$CONFIG/onlineurl/*
	/usr/bin/wget --timeout=8 -t 2 $baseurl -P /usr/share/$CONFIG/onlineurl
	[ ! -d "/usr/share/$CONFIG/onlineurl" ] || [ "$(ls /usr/share/$CONFIG/onlineurl |wc -l)" -eq 0 ] && echo "$Date: 订阅链接下载失败，请重试！" >> $LOG_FILE && rm -f "$LOCK_FILE" && exit 0
	rm -f /usr/share/$CONFIG/serverconfig/*
	get_local_servers
	for file in /usr/share/$CONFIG/onlineurl/*
	do
		[ -z "$(du -sh $file 2> /dev/null)" ] && echo "$Date: 订阅链接下载 $file 失败，请重试！" >> $LOG_FILE && continue
		maxnum=$(cat "$file" | /usr/bin/base64 -d 2> /dev/null| grep "MAX=" |awk -F"=" '{print $2}')
		if [ -n "$maxnum" ]; then
			urllinks=$(cat "$file" | /usr/bin/base64 -d 2> /dev/null| sed '/MAX=/d' | shuf -n${maxnum} | sed 's/ssr:\/\///g')
		else
			urllinks=$(cat "$file" | /usr/bin/base64 -d 2> /dev/null| sed 's/ssr:\/\///g')
		fi
		[ -z "$urllinks" ] && continue
		for link in $urllinks
		do
			decode_link=$(decode_url_link $link 1)
			get_remote_config $decode_link
			update_config
		done
	done
	[ -f "/usr/share/$CONFIG/serverconfig/all_localservers" ] && del_config
	echo "$Date: 本次更新，新增服务器节点 $addnum 个，修改 $updatenum 个，删除 $delnum 个；现共有节点：$(uci show $CONFIG|grep -c "group=") 个。" >> $LOG_FILE
	echo "$Date: 在线订阅列表更新完成" >> $LOG_FILE
	update_global_server
	rm -f "$LOCK_FILE"
}

stop() {
	[ "`uci show $CONFIG|grep -c "group="`" -gt 0 ] && {
		while [ -f "$LOCK_FILE" ]; do
			sleep 1s
		done
		echo "$Date: =============================================================================================" >> $LOG_FILE
		echo "$Date:                                                               服务器订阅程序(Shell by stones)" >> $LOG_FILE
		echo "$Date: =============================================================================================" >> $LOG_FILE
		echo "$Date: 在线订阅节点已全部删除" >> $LOG_FILE
		del_all_config
	}
}

case $1 in
stop)
	stop
	;;
add)
	add
	;;
*)
	start
	;;
esac
