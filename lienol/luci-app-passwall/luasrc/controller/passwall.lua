module("luci.controller.passwall",package.seeall)
local appname = "passwall"
local http = require "luci.http"
local kcptun  = require "luci.model.cbi.passwall.kcptun"

function index()
	if not nixio.fs.access("/etc/config/passwall") then
		return
	end
	entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false
	entry({"admin","vpn","passwall"},alias("admin","vpn","passwall","settings"),_("Pass Wall"),2).dependent=true
	entry({"admin","vpn","passwall","settings"},cbi("passwall/global"),_("Basic Settings"),1).dependent=true
	entry({"admin","vpn","passwall","server_list"},cbi("passwall/server_list"),_("Server List"),2).dependent=true
	entry({"admin","vpn","passwall","auto_switch"},cbi("passwall/auto_switch"),_("Auto Switch"),3).leaf=true
	entry({"admin","vpn","passwall","other"},cbi("passwall/other"),_("Other Settings"),94).leaf=true
	if luci.model.ipkg.installed("haproxy") or nixio.fs.access("/usr/bin/haproxy") or nixio.fs.access("/usr/sbin/haproxy") then
		entry({"admin","vpn","passwall","balancing"},cbi("passwall/balancing"),_("Load Balancing"),95).leaf=true
	end
	entry({"admin","vpn","passwall","rule"},cbi("passwall/rule"),_("Rule Update"),96).leaf=true
	entry({"admin","vpn","passwall","acl"},cbi("passwall/acl"),_("Access control"),97).leaf=true
	entry({"admin","vpn","passwall","rulelist"},cbi("passwall/rulelist"),_("Set Blacklist And Whitelist"),98).leaf=true
	entry({"admin","vpn","passwall","log"},cbi("passwall/log"),_("Watch Logs"),99).leaf=true
	entry({"admin","vpn","passwall","serverconfig"},cbi("passwall/serverconfig")).leaf=true
	
	entry({"admin","vpn","passwall","get_log"},call("get_log")).leaf=true
	entry({"admin","vpn","passwall","clear_log"},call("clear_log")).leaf=true
	entry({"admin","vpn","passwall","server_status"},call("server_status")).leaf=true
	entry({"admin","vpn","passwall","connect_status"},call("connect_status")).leaf=true
	entry({"admin","vpn","passwall","check_port"},call("check_port")).leaf=true
	entry({"admin","vpn","passwall","ping"},call("act_ping")).leaf=true
	entry({"admin","vpn","passwall","update_rules"},call("update_rules")).leaf=true
	entry({"admin", "vpn", "passwall", "kcptun_check"}, call("kcptun_check")).leaf = true
	entry({"admin", "vpn", "passwall", "kcptun_update"}, call("kcptun_update")).leaf = true
end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or { code = 1 })
end

function get_log()
	--luci.sys.exec("[ -f /var/log/passwall.log ] && sed '1!G;h;$!d' /var/log/passwall.log > /var/log/passwall_show.log")
	luci.http.write(luci.sys.exec("cat /var/log/passwall.log"))
end

function clear_log()
	luci.sys.exec("rm -rf > /var/log/passwall.log")
end

function server_status()
	local tcp_redir_port = luci.sys.exec("echo -n `uci get " .. appname .. ".@global_proxy[0].tcp_redir_port`")
	local udp_redir_port = luci.sys.exec("echo -n `uci get " .. appname .. ".@global_proxy[0].udp_redir_port`")
	local dns_mode = luci.sys.exec("echo -n `uci get " .. appname .. ".@global[0].dns_mode`")
	local e={}
	e.tcp_redir_status=luci.sys.call("ps | grep -v grep | grep -i -E '" .. appname .. "/TCP|brook tproxy -l 0.0.0.0:" .. tcp_redir_port .. "' >/dev/null")==0
	e.udp_redir_status=luci.sys.call("ps | grep -v grep | grep -i -E '" .. appname .. "/UDP|brook tproxy -l 0.0.0.0:" .. udp_redir_port .. "' >/dev/null")==0
	e.socks5_proxy_status=luci.sys.call("ps | grep -v grep | grep -i -E '" .. appname .. "/SOCKS5|brook client' >/dev/null")==0
	e.dns_mode_status=luci.sys.call("ps | grep -v grep | grep -i "..dns_mode.." >/dev/null")==0
	e.haproxy_status=luci.sys.call("pgrep haproxy >/dev/null")==0
	e.kcptun_status=luci.sys.call("pgrep kcptun >/dev/null")==0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function connect_status()
	local e={}
	if luci.http.formvalue("type") == "foreign" then
		e.status=luci.sys.call("echo `curl -I -o /dev/null -s -m 10 --connect-timeout 5 -w %{http_code} 'https://www.google.com.tw'`|grep 200 >/dev/null")==0
	else
		e.status=luci.sys.call("echo `curl -I -o /dev/null -s -m 10 --connect-timeout 2 -w %{http_code} 'http://www.baidu.com'`|grep 200 >/dev/null")==0
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function act_ping()
	local e={}
	e.index=luci.http.formvalue("index")
	e.ping=luci.sys.exec("ping -c 1 -W 1 %q 2>&1|grep -o 'time=[0-9]*.[0-9]'|awk -F '=' '{print$2}'"%luci.http.formvalue("domain"))
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function check_port()
	local retstring = "<br /><br />"
	retstring = retstring.."<font color='red'>暂时不支持UDP检测</font><br />"
	local s
	local server_name = ""
	local uci = luci.model.uci.cursor()

	uci:foreach("passwall", "servers", function(s)
		local ret=""
		local tcp_socket
		local udp_socket
		if (s.use_kcp and s.use_kcp == "1" and s.kcp_port) or (s.v2ray_transport and s.v2ray_transport == "mkcp" and s.server_port) then
			--[[local port = (s.use_kcp == "1" and s.kcp_port) and s.kcp_port or (s.v2ray_transport == "mkcp" and s.server_port) and s.server_port or nil
			if port then
				udp_socket = nixio.socket("inet", "dgram")
				udp_socket:setopt("socket", "rcvtimeo", 3)
				udp_socket:setopt("socket", "sndtimeo", 3)
				udp_socket:sendto("test", s.server, port)
				r,c,d=udp_socket:recvfrom(10)
				ret=""
			end--]]
		else
			if s.server_type and s.server and s.server_port and s.remarks then
				server_name = "%s：[%s] %s:%s"%{s.server_type , s.remarks , s.server , s.server_port}
			end
			tcp_socket = nixio.socket("inet", "stream")
			tcp_socket:setopt("socket", "rcvtimeo", 3)
			tcp_socket:setopt("socket", "sndtimeo", 3)
			ret=tcp_socket:connect(s.server,s.server_port)
			if tostring(ret) == "true" then
				retstring = retstring .. "<font color='green'>" .. server_name .. "   OK.</font><br />"
			else
				retstring = retstring .. "<font color='red'>" .. server_name .. "   Error.</font><br />"
			end
			ret=""
		end
		if tcp_socket then tcp_socket:close() end
		if udp_socket then udp_socket:close() end
	end)
	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret=retstring })
end

function update_rules()
	local update=luci.http.formvalue("update")
	luci.sys.call("nohup /usr/share/passwall/rule_update.sh '"..update.."' 2>&1 &")
end

function kcptun_check(type)
	local json = nil
	if type == "kcptun" then
		json = kcptun.check_kcptun("")
	else
		http.status(500, "Bad address")
		return
	end

	http_write_json(json)
end

function kcptun_update(type)
	local json = nil
	local task = http.formvalue("task")
	if task == "extract" then
		json = kcptun.extract_kcptun(http.formvalue("file"), http.formvalue("subfix"))
	elseif task == "move" then
		json = kcptun.move_kcptun(http.formvalue("file"))
	else
		json = kcptun.download_kcptun(http.formvalue("url"))
	end

	http_write_json(json)
end