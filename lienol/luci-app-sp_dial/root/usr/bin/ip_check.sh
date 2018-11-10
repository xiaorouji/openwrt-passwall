#!/bin/sh /etc/rc.common

enable=$(uci get sp_dial.@config[0].enable)
wait_time=$(uci get sp_dial.@config[0].wait_time)
num=$(uci get sp_dial.@config[0].num)
boot_delay=$(uci get sp_dial.@config[0].boot_delay)
begin_a=$(uci get sp_dial.@config[0].begin_a)
begin_b=$(uci get sp_dial.@config[0].begin_b)
begin_c=$(uci get sp_dial.@config[0].begin_c)

start() {
state=`ps|grep -c ip_check.sh`
[ "$state" -ge "4" ] && echo "Another ip_check.sh is running,exit"
[ "$state" -ge "4" ] && exit

local count=0
while :; do
	let "count = $count + 1"
	for a in `grep wan /etc/config/network |awk -F "['']" '{print $2}' |sed '/^wwan$/d'`
	do

		if ifconfig |grep -A1 "pppoe-$a" | grep -E "inet addr:$begin_a|inet addr:$begin_b|inet addr:$begin_c"; then
			#echo "外网IP正常，$wait_time 秒后进行下一次检查！" && 
			sleep "$wait_time"
			count=0
		else
			#echo "内网IP，正在进行$a 第 $count 次重拨！$num 次失败后，将中止。" 
			ifdown $a
			sleep 2
			ifup $a
			if [ $count = $num ]; then
				#echo "已失败 $num 次，退出拨号！" && 
				exit
			fi
		fi
		sleep 4
	done
done
}

