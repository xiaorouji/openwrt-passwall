#!/bin/sh
# Copyright (C) 2019 Lienol <lawlienol@gmail.com>

CONFIG=passwall
LOCK_FILE=/var/lock/onlineconfig.lock
Date=$(date "+%Y-%m-%d %H:%M:%S")
LOG_FILE=/var/log/$CONFIG.log

config_t_get() {
	local index=0
	[ -n "$3" ] && index=$3
	local ret=$(uci get $CONFIG.@$1[$index].$2 2>/dev/null)
	#echo ${ret:=$3}
	echo $ret
}

start() {
	echo "$Date: 开始执行在线订阅脚本..." >> $LOG_FILE
	baseurl_ssr=$(config_t_get global_subscribe baseurl_ssr)  ##SSR订阅地址
	baseurl_v2ray=$(config_t_get global_subscribe baseurl_v2ray)  ##V2ray订阅地址
	[ -z "$baseurl_ssr" -a -z "$baseurl_v2ray" ] && echo "$Date: 请先输入订阅地址保存提交之后再更新！" >> $LOG_FILE && exit 0
	
	#防止并发开启服务
	[ -f "$LOCK_FILE" ] && return 3
	touch "$LOCK_FILE"
	/usr/share/$CONFIG/subscription_ssr.sh start
	/usr/share/$CONFIG/subscription_v2ray.sh start
	echo "$Date: 在线订阅脚本执行完毕..." >> $LOG_FILE
	rm -f "$LOCK_FILE"
	exit 0
}

stop() {
	/usr/share/$CONFIG/subscription_ssr.sh stop
	/usr/share/$CONFIG/subscription_v2ray.sh stop
	rm -f "$LOCK_FILE"
	exit 0
}

case $1 in
stop)
	stop
	;;
*)
	start
	;;
esac
