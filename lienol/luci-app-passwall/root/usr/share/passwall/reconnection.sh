#!/bin/sh
failcount=0
while [ "$failcount" -lt "5" ]
do
	status=`curl -I -o /dev/null -s --connect-timeout 5 -w %{http_code} 'https://www.google.com.tw' |grep 200 `
	if [ -z "$status" -o "$status" != "200" ];then
		#echo "$(data): 检测异常" >> /var/log/passwall.log
		let "failcount++"
		[ "$failcount" -ge 5 ] && {
			#echo "$(data): 检测异常，重启服务" >> /var/log/passwall.log
			/etc/init.d/passwall restart
			exit 0
		}
		sleep 5s
	else
		#echo "$(data): 检测正常" >> /var/log/passwall.log
		break
	fi
done
exit
