#!/bin/sh

case "$1" in
	"xray-core")
		xray version 2>&1 | grep "${2#*v}"
		;;
esac
