module("luci.controller.homeassistant", package.seeall)

local http = require "luci.http"

function index()
	if not nixio.fs.access("/etc/config/homeassistant") then
		return
	end

	entry({"admin","services","homeassistant"},alias("admin","services","homeassistant","settings"),_("HomeAssistant"),999).dependent=true
	entry({"admin","services","homeassistant","settings"},cbi("homeassistant/settings"),_("Basic Settings"),1).dependent=true
	entry({"admin","services","homeassistant","log"},cbi("homeassistant/log"),_("Watch Logs"),2).leaf=true
	entry({"admin","services","homeassistant","status"},call("act_status")).leaf=true
	entry({"admin","services","homeassistant","download"},call("download")).leaf=true
	entry({"admin","services","homeassistant","get_log"},call("get_log")).leaf=true
	entry({"admin","services","homeassistant","clear_log"},call("clear_log")).leaf=true
end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or { code = 1 })
end

function act_status()
	local nginx="nginx"
	local php_fpm="php-fpm"
	local e={}
	e.nginx_status=luci.sys.call("ps | grep -v grep | grep '"..nginx.."' >/dev/null")==0
	e.php_status=luci.sys.call("ps | grep -v grep | grep '"..php_fpm.."' >/dev/null")==0
	http_write_json(e)
end

function download()
	luci.sys.call("nohup /usr/share/homeassistant/download.sh 2>&1 &")
end

function get_log()
	luci.http.write(luci.sys.exec("cat /var/log/homeassistant.log"))
end

function clear_log()
	luci.sys.exec("rm -rf > /var/log/homeassistant.log")
end