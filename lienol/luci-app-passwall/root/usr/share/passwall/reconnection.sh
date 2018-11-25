#!/bin/sh
Date=$(date "+%Y-%m-%d %H:%M:%S")
failcount=1
while [ "$failcount" -lt "6" ]
do
	status=`curl -I -o /dev/null -s --connect-timeout 5 -w %{http_code} 'https://www.google.com.tw' |grep 200 `
	if [ -z "$status" -o "$status" != "200" ];then
		echo "$Date: 掉线重连检测：第$failcount次检测异常" >> /var/log/passwall.log
		let "failcount++"
		[ "$failcount" -ge 6 ] && {
			echo "$Date: 掉线重连检测：检测异常，重启服务" >> /var/log/passwall.log
			/etc/init.d/passwall restart
			exit 0
		}
		sleep 5s
	else
		echo "$Date: 掉线重连检测：检测正常" >> /var/log/passwall.log
		break
	fi
done
exit
