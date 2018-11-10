module("luci.controller.passwall",package.seeall)
local http = require "luci.http"
local kcp  = require "luci.model.cbi.passwall.kcptun"

function index()
	if not nixio.fs.access("/etc/config/passwall") then
		return
	end
	entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false
	entry({"admin","vpn","passwall"},alias("admin","vpn","passwall","settings"),_("Pass Wall"),2).dependent=true
	entry({"admin","vpn","passwall","settings"},cbi("passwall/global"),_("Basic Settings"),1).dependent=true
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
	entry({"admin", "vpn", "passwall", "kcp_check"}, call("kcp_check")).leaf = true
	entry({"admin", "vpn", "passwall", "kcp_update"}, call("kcp_update")).leaf = true
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
	local e={}
	e.ss_redir_status=luci.sys.call("pgrep ss-redir >/dev/null || pgrep ssr-redir >/dev/null || pgrep v2ray >/dev/null || pgrep brook >/dev/null")==0
	e.haproxy_status=luci.sys.call("pgrep haproxy >/dev/null")==0
	e.kcp_status=luci.sys.call("pgrep kcp >/dev/null")==0
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
	local set=""
	local retstring="<br /><br />"
	local s
	local server_name = ""
	local server_host = ""
	local uci = luci.model.uci.cursor()

	uci:foreach("passwall", "servers", function(s)
		if s.remarks then
			server_name = s.remarks
		end
		if s.server and s.server_port then
			server_host = "%s:%s" %{s.server, s.server_port}
		end
		socket = nixio.socket("inet", "stream")
		socket:setopt("socket", "rcvtimeo", 3)
		socket:setopt("socket", "sndtimeo", 3)
		ret=socket:connect(s.server,s.server_port)
		if tostring(ret) == "true" then
			socket:close()
			retstring =retstring .. "<font color='green'>[" .. server_name .. "] " .. server_host .. " OK.</font><br />"
		else
			retstring =retstring .. "<font color='red'>[" .. server_name .. "] " .. server_host .. " Error.</font><br />"
		end
	end)
	luci.http.prepare_content("application/json")
	luci.http.write_json({ ret=retstring })
end

function update_rules()
	local update=luci.http.formvalue("update")
	luci.sys.call("nohup /usr/share/passwall/rule_update.sh '"..update.."' 2>&1 &")
end

function kcp_check(type)
	local json = nil
	if type == "kcptun" then
		json = kcp.check_kcptun("")
	else
		http.status(500, "Bad address")
		return
	end

	http_write_json(json)
end

function kcp_update(type)
	local json = nil
	local task = http.formvalue("task")
	if task == "extract" then
		json = kcp.extract_kcptun(http.formvalue("file"), http.formvalue("subfix"))
	elseif task == "move" then
		json = kcp.move_kcptun(http.formvalue("file"))
	else
		json = kcp.download_kcptun(http.formvalue("url"))
	end

	http_write_json(json)
end