module("luci.controller.server_center",package.seeall)
local appname = "server_center"
local http = require "luci.http"
local v2ray  = require "luci.model.cbi.server_center.api.v2ray"

function index()
	if not nixio.fs.access("/etc/config/server_center")then
		return
	end
	entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false
	entry({"admin","vpn","server_center"},alias("admin","vpn","server_center","ssr_python"),_("Server Center"),3).dependent=true
	if nixio.fs.access("/usr/share/ssr_python") then
		entry({"admin","vpn","server_center","ssr_python"},cbi("server_center/ssr_python"),_("SSR Python Server"),1).dependent=true
	end
	if nixio.fs.access("/usr/bin/ssr-server") then
		entry({"admin","vpn","server_center","ssr_libev"},cbi("server_center/ssr_libev"),_("SSR Libev Server"),2).dependent=true
	end
	if nixio.fs.access("/usr/bin/v2ray/v2ray") then
		entry({"admin","vpn","server_center","v2ray"},cbi("server_center/v2ray"),_("V2ray Server"),3).dependent=true
	end
	entry({"admin","vpn","server_center","ssr_libev_config"},cbi("server_center/ssr_libev_config")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_config"},cbi("server_center/ssr_python_config")).leaf=true
	entry({"admin","vpn","server_center","v2ray_config"},cbi("server_center/v2ray_config")).leaf=true
	
	entry({"admin","vpn","server_center","ssr_libev_users_status"},call("act_ssr_libev_users_status")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_status"},call("act_ssr_python_status")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_users_status"},call("act_ssr_python_users_status")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_get_link"},call("act_ssr_python_get_link")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_clear_traffic"},call("act_ssr_python_clear_traffic")).leaf=true
	entry({"admin","vpn","server_center","ssr_python_clear_traffic_all_users"},call("act_ssr_python_clear_traffic_all_users")).leaf=true
	entry({"admin","vpn","server_center","v2ray_users_status"},call("act_v2ray_users_status")).leaf=true
	entry({"admin", "vpn", "server_center", "v2ray_check"}, call("v2ray_check")).leaf = true
	entry({"admin", "vpn", "server_center", "v2ray_update"}, call("v2ray_update")).leaf = true
end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or { code = 1 })
end

function act_ssr_libev_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("ps -w| grep -v grep | grep '/var/etc/server_center/ssr_libev-server_" .. luci.http.formvalue("id") .. "' >/dev/null")==0
	http_write_json(e)
end

function act_ssr_python_status()
	local e={}
	e.status=luci.sys.call("ps -w | grep -v grep | grep '/usr/share/ssr_python/server.py' >/dev/null")==0
	http_write_json(e)
end

function act_ssr_python_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("netstat -an | grep '" .. luci.http.formvalue("port") .. "' >/dev/null")==0
	http_write_json(e)
end

function act_ssr_python_get_link()
	local e={}
	local link = luci.sys.exec("cd /usr/share/ssr_python && ./mujson_mgr.py -l -I " .. luci.http.formvalue("section") .. " | sed -n 21p"):gsub("^%s*(.-)%s*$", "%1")
	if link ~= "" then e.link = link end
	http_write_json(e)
end

function act_ssr_python_clear_traffic()
	local e={}
	e.status=luci.sys.call("cd /usr/share/ssr_python && ./mujson_mgr.py -c -I '"..luci.http.formvalue("id").."' >/dev/null")==0
	http_write_json(e)
end

function act_ssr_python_clear_traffic_all_users()
	local e={}
	e.status=luci.sys.call("/usr/share/ssr_python/sh/clear_traffic_all_users.sh >/dev/null")==0
	http_write_json(e)
end

function act_v2ray_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("ps -w| grep -v grep | grep '/var/etc/server_center/v2ray-server_" .. luci.http.formvalue("id") .. "' >/dev/null")==0
	http_write_json(e)
end

function v2ray_check()
	local json = v2ray.to_check("")
	http_write_json(json)
end

function v2ray_update()
	local json = nil
	local task = http.formvalue("task")
	if task == "extract" then
		json = v2ray.to_extract(http.formvalue("file"), http.formvalue("subfix"))
	elseif task == "move" then
		json = v2ray.to_move(http.formvalue("file"))
	else
		json = v2ray.to_download(http.formvalue("url"))
	end

	http_write_json(json)
end