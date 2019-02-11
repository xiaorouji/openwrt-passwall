#!/bin/sh
LOCK_FILE=/var/lock/passwall_auto_switch.lock
TCP_REDIR_SERVER=

get_date(){
	echo "$(date "+%Y-%m-%d %H:%M:%S")"
}

#防止并发执行
if [ -f "$LOCK_FILE" ];then
    exit 1
else
    touch $LOCK_FILE
fi

if [ -f "/var/etc/passwall/tcp_server_id" ];then
	TCP_REDIR_SERVER=`cat /var/etc/passwall/tcp_server_id`
else
	rm -f $LOCK_FILE
	exit 1
fi

echo "$(get_date): 运行自动切换检测脚本" >> /var/log/passwall.log
failcount=1
while [ "$failcount" -lt "6" ]
do
	status=`curl -I -o /dev/null -s --connect-timeout 5 -w %{http_code} 'https://www.google.com' |grep 200 `
	if [ -z "$status" -o "$status" != "200" ];then
		echo "$(get_date): 自动切换检测：第$failcount次检测异常" >> /var/log/passwall.log
		let "failcount++"
		[ "$failcount" -ge 6 ] && {
			echo "$(get_date): 自动切换检测：检测异常，切换节点" >> /var/log/passwall.log
			TCP_REDIR_SERVERS=`uci get passwall.@auto_switch[0].tcp_redir_server`
			has_backup_server=`echo $TCP_REDIR_SERVERS | grep $TCP_REDIR_SERVER`
			setserver=
			if [ -z "$has_backup_server" ];then
				setserver=`echo $TCP_REDIR_SERVERS | awk -F ' ' '{print $1}'`
			else
				setserver=$TCP_REDIR_SERVER
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
			rm -f $LOCK_FILE
			uci set passwall.@global[0].tcp_redir_server=$setserver
			uci commit passwall
			/etc/init.d/passwall restart
			exit 1
		}
		sleep 5s
	else
		echo "$(get_date): 自动切换检测：检测正常" >> /var/log/passwall.log
		break
	fi
done

rm -f $LOCK_FILE
exit
