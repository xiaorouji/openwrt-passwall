#!/bin/sh
LOCK_FILE=/var/lock/passwall_reconnection.lock

get_date(){
	echo "$(date "+%Y-%m-%d %H:%M:%S")"
}

#防止并发执行
if [ -f "$LOCK_FILE" ];then
    exit 1
else
    touch $LOCK_FILE
fi

failcount=1
while [ "$failcount" -lt "6" ]
do
	status=`curl -I -o /dev/null -s --connect-timeout 5 -w %{http_code} 'https://www.google.com' |grep 200 `
	if [ -z "$status" -o "$status" != "200" ];then
		echo "$(get_date): 掉线重连检测：第$failcount次检测异常" >> /var/log/passwall.log
		let "failcount++"
		[ "$failcount" -ge 6 ] && {
			echo "$(get_date): 掉线重连检测：检测异常，重启服务" >> /var/log/passwall.log
			rm -f $LOCK_FILE
			/etc/init.d/passwall restart
			exit 1
		}
		sleep 5s
	else
		echo "$(get_date): 掉线重连检测：检测正常" >> /var/log/passwall.log
		break
	fi
done

rm -f $LOCK_FILE
exit
