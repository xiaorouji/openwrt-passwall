#!/bin/sh
Date=$(date "+%Y-%m-%d %H:%M:%S")
TCP_REDIR_SERVER=`cat /var/etc/passwall/tcp_server_id`
failcount=1
while [ "$failcount" -lt "6" ]
do
	status=`curl -I -o /dev/null -s --connect-timeout 5 -w %{http_code} 'https://www.google.com.tw' |grep 200 `
	if [ -z "$status" -o "$status" != "200" ];then
		echo "$Date: 自动切换检测：第$failcount次检测异常" >> /var/log/passwall.log
		let "failcount++"
		[ "$failcount" -ge 6 ] && {
			echo "$Date: 自动切换检测：检测异常，切换节点" >> /var/log/passwall.log
			TCP_REDIR_SERVERS=`uci get passwall.@auto_switch[0].tcp_redir_server`
			has_backup_server=`echo $TCP_REDIR_SERVERS | grep $TCP_REDIR_SERVER`
			setserver=
			if [ -z "$has_backup_server" ];then
				setserver=`echo $TCP_REDIR_SERVERS | awk -F ' ' '{print $1}'`
			else
				flag=0
				for server in $has_backup_server
				do
					if [ "$flag" == 0 ];then
						if [ "$TCP_REDIR_SERVER" == "$server" ];then
							flag=1
							continue
						fi
					fi
					if [ "$flag" == 1 ];then
						flag=2
						continue
					fi
					if [ "$flag" == 2 ];then
						setserver=$server
						break
					fi
				done
			fi
			uci set passwall.@global[0].tcp_redir_server=$setserver
			uci commit passwall
			/etc/init.d/passwall restart
			exit 0
		}
		sleep 5s
	else
		echo "$Date: 自动切换检测：检测正常" >> /var/log/passwall.log
		break
	fi
done
exit
