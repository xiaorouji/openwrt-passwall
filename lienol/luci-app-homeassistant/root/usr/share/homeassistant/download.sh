#!/bin/sh
CONFIG=homeassistant
LOG_FILE=/var/log/$CONFIG.log
Date=$(date "+%Y-%m-%d %H:%M:%S")

save_directory=`uci get $CONFIG.@global[0].save_directory`

[ -z "$save_directory" ] && {
	echo $Date: 未设置存放路径，停止下载... >> $LOG_FILE
	exit
}

uci_get_by_type() {
	local index=0
	if [ -n $4 ]; then
		index=$4
	fi
	local ret=$(uci get $CONFIG.@$1[$index].$2 2>/dev/null)
	echo ${ret:=$3}
}

isinstallpy3=`opkg list-installed | grep python3`
if [ -z "$isinstallpy3" ];then
	echo $Date: 正在下载并安装Python3环境... >> $LOG_FILE
	opkg update >> $LOG_FILE
	opkg install python3 python3-pip python3-dev python3-cffi >> $LOG_FILE
	echo $Date: 安装Python3环境完成... >> $LOG_FILE
else
	echo $Date: 已安装Python3环境，不需要再安装... >> $LOG_FILE
fi

echo $Date: 开始下载HomeAssistant环境... >> $LOG_FILE
pip3 install --upgrade pip >> $LOG_FILE
pip3 install setuptools >> $LOG_FILE
pip3 install virtualenv >> $LOG_FILE
virtualenv $save_directory -p /usr/bin/python3 >> $LOG_FILE
source $save_directory/bin/activate >> $LOG_FILE
#暂时不支持最新版HA，研究中。。。
pip3 install homeassistant==0.75.2 >> $LOG_FILE
echo $Date: 进程运行完毕！ >> $LOG_FILE
exit
