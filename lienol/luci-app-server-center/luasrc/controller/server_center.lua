module("luci.controller.server_center",package.seeall)

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
	entry({"admin","vpn","server_center","v2ray_users_status"},call("act_v2ray_users_status")).leaf=true
end

function act_ssr_libev_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("ps -w| grep -v grep | grep '/var/etc/server_center/ssr_libev-server_" .. luci.http.formvalue("id") .. "' >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function act_ssr_python_status()
	local e={}
	e.status=luci.sys.call("ps -w | grep -v grep | grep '/usr/share/ssr_python/server.py' >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function act_ssr_python_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("netstat -an | grep '" .. luci.http.formvalue("port") .. "' >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function act_v2ray_users_status()
	local e={}
	e.index=luci.http.formvalue("index")
	e.status=luci.sys.call("ps -w| grep -v grep | grep '/var/etc/server_center/v2ray-server_" .. luci.http.formvalue("id") .. "' >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end