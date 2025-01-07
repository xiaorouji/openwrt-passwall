-- Copyright (C) 2018-2020 L-WRT Team
-- Copyright (C) 2021-2025 xiaorouji

module("luci.controller.passwall", package.seeall)
local api = require "luci.passwall.api"
local appname = "passwall"	-- not available
local uci = api.uci			-- in funtion index()
local fs = api.fs
local http = require "luci.http"
local util = require "luci.util"
local i18n = require "luci.i18n"

function index()
	if not nixio.fs.access("/etc/config/passwall") then
		if nixio.fs.access("/usr/share/passwall/0_default_config") then
			luci.sys.call('cp -f /usr/share/passwall/0_default_config /etc/config/passwall')
		else return end
	end
	local api = require "luci.passwall.api"
	local appname = "passwall"	-- global definitions not available
	local uci = api.uci			-- in function index()
	local fs = api.fs
	entry({"admin", "services", appname}).dependent = true
	entry({"admin", "services", appname, "reset_config"}, call("reset_config")).leaf = true
	entry({"admin", "services", appname, "show"}, call("show_menu")).leaf = true
	entry({"admin", "services", appname, "hide"}, call("hide_menu")).leaf = true
	local e
	if uci:get(appname, "@global[0]", "hide_from_luci") ~= "1" then
		e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), _("Pass Wall"), -1)
	else
		e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), nil, -1)
	end
	e.dependent = true
	e.acl_depends = { "luci-app-passwall" }
	--[[ Client ]]
	entry({"admin", "services", appname, "settings"}, cbi(appname .. "/client/global"), _("Basic Settings"), 1).dependent = true
	entry({"admin", "services", appname, "node_list"}, cbi(appname .. "/client/node_list"), _("Node List"), 2).dependent = true
	entry({"admin", "services", appname, "node_subscribe"}, cbi(appname .. "/client/node_subscribe"), _("Node Subscribe"), 3).dependent = true
	entry({"admin", "services", appname, "other"}, cbi(appname .. "/client/other", {autoapply = true}), _("Other Settings"), 92).leaf = true
	if fs.access("/usr/sbin/haproxy") then
		entry({"admin", "services", appname, "haproxy"}, cbi(appname .. "/client/haproxy"), _("Load Balancing"), 93).leaf = true
	end
	entry({"admin", "services", appname, "app_update"}, cbi(appname .. "/client/app_update"), _("App Update"), 95).leaf = true
	entry({"admin", "services", appname, "rule"}, cbi(appname .. "/client/rule"), _("Rule Manage"), 96).leaf = true
	entry({"admin", "services", appname, "rule_list"}, cbi(appname .. "/client/rule_list", {autoapply = true}), _("Rule List"), 97).leaf = true
	entry({"admin", "services", appname, "node_subscribe_config"}, cbi(appname .. "/client/node_subscribe_config")).leaf = true
	entry({"admin", "services", appname, "node_config"}, cbi(appname .. "/client/node_config")).leaf = true
	entry({"admin", "services", appname, "shunt_rules"}, cbi(appname .. "/client/shunt_rules")).leaf = true
	entry({"admin", "services", appname, "socks_config"}, cbi(appname .. "/client/socks_config")).leaf = true
	entry({"admin", "services", appname, "acl"}, cbi(appname .. "/client/acl"), _("Access control"), 98).leaf = true
	entry({"admin", "services", appname, "acl_config"}, cbi(appname .. "/client/acl_config")).leaf = true
	entry({"admin", "services", appname, "log"}, form(appname .. "/client/log"), _("Log Maint"), 999).leaf = true

	--[[ Server ]]
	entry({"admin", "services", appname, "server"}, cbi(appname .. "/server/index"), _("Server-Side"), 99).leaf = true
	entry({"admin", "services", appname, "server_user"}, cbi(appname .. "/server/user")).leaf = true

	--[[ API ]]
	entry({"admin", "services", appname, "server_user_status"}, call("server_user_status")).leaf = true
	entry({"admin", "services", appname, "server_user_log"}, call("server_user_log")).leaf = true
	entry({"admin", "services", appname, "server_get_log"}, call("server_get_log")).leaf = true
	entry({"admin", "services", appname, "server_clear_log"}, call("server_clear_log")).leaf = true
	entry({"admin", "services", appname, "link_add_node"}, call("link_add_node")).leaf = true
	entry({"admin", "services", appname, "socks_autoswitch_add_node"}, call("socks_autoswitch_add_node")).leaf = true
	entry({"admin", "services", appname, "socks_autoswitch_remove_node"}, call("socks_autoswitch_remove_node")).leaf = true
	entry({"admin", "services", appname, "get_now_use_node"}, call("get_now_use_node")).leaf = true
	entry({"admin", "services", appname, "get_redir_log"}, call("get_redir_log")).leaf = true
	entry({"admin", "services", appname, "get_socks_log"}, call("get_socks_log")).leaf = true
	entry({"admin", "services", appname, "get_chinadns_log"}, call("get_chinadns_log")).leaf = true
	entry({"admin", "services", appname, "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", appname, "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", appname, "index_status"}, call("index_status")).leaf = true
	entry({"admin", "services", appname, "haproxy_status"}, call("haproxy_status")).leaf = true
	entry({"admin", "services", appname, "socks_status"}, call("socks_status")).leaf = true
	entry({"admin", "services", appname, "connect_status"}, call("connect_status")).leaf = true
	entry({"admin", "services", appname, "ping_node"}, call("ping_node")).leaf = true
	entry({"admin", "services", appname, "urltest_node"}, call("urltest_node")).leaf = true
	entry({"admin", "services", appname, "set_node"}, call("set_node")).leaf = true
	entry({"admin", "services", appname, "copy_node"}, call("copy_node")).leaf = true
	entry({"admin", "services", appname, "clear_all_nodes"}, call("clear_all_nodes")).leaf = true
	entry({"admin", "services", appname, "delete_select_nodes"}, call("delete_select_nodes")).leaf = true
	entry({"admin", "services", appname, "update_rules"}, call("update_rules")).leaf = true

	--[[rule_list]]
	entry({"admin", "services", appname, "read_rulelist"}, call("read_rulelist")).leaf = true

	--[[Components update]]
	entry({"admin", "services", appname, "check_passwall"}, call("app_check")).leaf = true
	local coms = require "luci.passwall.com"
	local com
	for com, _ in pairs(coms) do
		entry({"admin", "services", appname, "check_" .. com}, call("com_check", com)).leaf = true
		entry({"admin", "services", appname, "update_" .. com}, call("com_update", com)).leaf = true
	end

	--[[Backup]]
	entry({"admin", "services", appname, "backup"}, call("create_backup")).leaf = true
end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write_json(content or {code = 1})
end

function reset_config()
	luci.sys.call('/etc/init.d/passwall stop')
	luci.sys.call('[ -f "/usr/share/passwall/0_default_config" ] && cp -f /usr/share/passwall/0_default_config /etc/config/passwall')
	luci.http.redirect(api.url())
end

function show_menu()
	api.sh_uci_del(appname, "@global[0]", "hide_from_luci", true)
	luci.sys.call("rm -rf /tmp/luci-*")
	luci.sys.call("/etc/init.d/rpcd restart >/dev/null")
	luci.http.redirect(api.url())
end

function hide_menu()
	api.sh_uci_set(appname, "@global[0]", "hide_from_luci", "1", true)
	luci.sys.call("rm -rf /tmp/luci-*")
	luci.sys.call("/etc/init.d/rpcd restart >/dev/null")
	luci.http.redirect(luci.dispatcher.build_url("admin", "status", "overview"))
end

function link_add_node()
	local lfile = "/tmp/links.conf"
	local link = luci.http.formvalue("link")
	luci.sys.call('echo \'' .. link .. '\' > ' .. lfile)
	luci.sys.call("lua /usr/share/passwall/subscribe.lua add log")
end

function socks_autoswitch_add_node()
	local id = luci.http.formvalue("id")
	local key = luci.http.formvalue("key")
	if id and id ~= "" and key and key ~= "" then
		uci:set(appname, id, "enable_autoswitch", "1")
		local new_list = uci:get(appname, id, "autoswitch_backup_node") or {}
		for i = #new_list, 1, -1 do
			if (uci:get(appname, new_list[i], "remarks") or ""):find(key) then
				table.remove(new_list, i)
			end
		end
		for k, e in ipairs(api.get_valid_nodes()) do
			if e.node_type == "normal" and e["remark"]:find(key) then
				table.insert(new_list, e.id)
			end
		end
		uci:set_list(appname, id, "autoswitch_backup_node", new_list)
		api.uci_save(uci, appname)
	end
	luci.http.redirect(api.url("socks_config", id))
end

function socks_autoswitch_remove_node()
	local id = luci.http.formvalue("id")
	local key = luci.http.formvalue("key")
	if id and id ~= "" and key and key ~= "" then
		uci:set(appname, id, "enable_autoswitch", "1")
		local new_list = uci:get(appname, id, "autoswitch_backup_node") or {}
		for i = #new_list, 1, -1 do
			if (uci:get(appname, new_list[i], "remarks") or ""):find(key) then
				table.remove(new_list, i)
			end
		end
		uci:set_list(appname, id, "autoswitch_backup_node", new_list)
		api.uci_save(uci, appname)
	end
	luci.http.redirect(api.url("socks_config", id))
end

function get_now_use_node()
	local path = "/tmp/etc/passwall/acl/default"
	local e = {}
	local tcp_node = api.get_cache_var("ACL_GLOBAL_TCP_node")
	if tcp_node then
		e["TCP"] = tcp_node
	end
	local udp_node = api.get_cache_var("ACL_GLOBAL_UDP_node")
	if udp_node then
		e["UDP"] = udp_node
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_redir_log()
	local name = luci.http.formvalue("name")
	local proto = luci.http.formvalue("proto")
	local path = "/tmp/etc/passwall/acl/" .. name
	proto = proto:upper()
	if proto == "UDP" and (uci:get(appname, "@global[0]", "udp_node") or "nil") == "tcp" and not fs.access(path .. "/" .. proto .. ".log") then
		proto = "TCP"
	end
	if fs.access(path .. "/" .. proto .. ".log") then
		local content = luci.sys.exec("cat ".. path .. "/" .. proto .. ".log")
		content = content:gsub("\n", "<br />")
		luci.http.write(content)
	else
		luci.http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_socks_log()
	local name = luci.http.formvalue("name")
	local path = "/tmp/etc/passwall/SOCKS_" .. name .. ".log"
	if fs.access(path) then
		local content = luci.sys.exec("cat ".. path)
		content = content:gsub("\n", "<br />")
		luci.http.write(content)
	else
		luci.http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_chinadns_log()
	local flag = luci.http.formvalue("flag")
	local path = "/tmp/etc/passwall/acl/" .. flag .. "/chinadns_ng.log"
	if fs.access(path) then
		local content = luci.sys.exec("cat ".. path)
		content = content:gsub("\n", "<br />")
		luci.http.write(content)
	else
		luci.http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_log()
	-- luci.sys.exec("[ -f /tmp/log/passwall.log ] && sed '1!G;h;$!d' /tmp/log/passwall.log > /tmp/log/passwall_show.log")
	luci.http.write(luci.sys.exec("[ -f '/tmp/log/passwall.log' ] && cat /tmp/log/passwall.log"))
end

function clear_log()
	luci.sys.call("echo '' > /tmp/log/passwall.log")
end

function index_status()
	local e = {}
	local dns_shunt = uci:get(appname, "@global[0]", "dns_shunt") or "dnsmasq"
	if dns_shunt == "smartdns" then
		e.dns_mode_status = luci.sys.call("pidof smartdns >/dev/null") == 0
	elseif dns_shunt == "chinadns-ng" then
		e.dns_mode_status = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep 'default' | grep 'chinadns_ng' >/dev/null") == 0
	else
		e.dns_mode_status = luci.sys.call("netstat -apn | grep ':15353 ' >/dev/null") == 0
	end

	e.haproxy_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v grep | grep '%s/bin/' | grep haproxy >/dev/null", appname)) == 0
	e["tcp_node_status"] = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep 'default' | grep 'TCP' >/dev/null") == 0

	if (uci:get(appname, "@global[0]", "udp_node") or "nil") == "tcp" then
		e["udp_node_status"] = e["tcp_node_status"]
	else
		e["udp_node_status"] = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep 'default' | grep 'UDP' >/dev/null") == 0
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function haproxy_status()
	local e = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v grep | grep '%s/bin/' | grep haproxy >/dev/null", appname)) == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function socks_status()
	local e = {}
	local index = luci.http.formvalue("index")
	local id = luci.http.formvalue("id")
	e.index = index
	e.socks_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep -v '_acl_' | grep '%s' | grep 'SOCKS_' > /dev/null", id)) == 0
	local use_http = uci:get(appname, id, "http_port") or 0
	e.use_http = 0
	if tonumber(use_http) > 0 then
		e.use_http = 1
		e.http_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall/bin/' | grep -v '_acl_' | grep '%s' | grep -E 'HTTP_|HTTP2SOCKS' > /dev/null", id)) == 0
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function connect_status()
	local e = {}
	e.use_time = ""
	local url = luci.http.formvalue("url")
	local baidu = string.find(url, "baidu")
	local chn_list = uci:get(appname, "@global[0]", "chn_list") or "direct"
	local gfw_list = uci:get(appname, "@global[0]", "use_gfw_list") or "1"
	local proxy_mode = uci:get(appname, "@global[0]", "tcp_proxy_mode") or "proxy"
	local socks_server = api.get_cache_var("GLOBAL_TCP_SOCKS_server")

	-- 兼容 curl 8.6 time_starttransfer 错误
	local curl_ver = luci.sys.exec("curl -V 2>/dev/null | head -n 1 | awk '{print $2}' | cut -d. -f1,2 | tr -d ' \n'") or "0"
	url = (curl_ver == "8.6") and "-w %{http_code}:%{time_appconnect} https://" .. url
		or "-w %{http_code}:%{time_starttransfer} http://" .. url

	if socks_server and socks_server ~= "" then
		if (chn_list == "proxy" and gfw_list == "0" and proxy_mode ~= "proxy" and baidu ~= nil) or (chn_list == "0" and gfw_list == "0" and proxy_mode == "proxy") then
		-- 中国列表+百度 or 全局
			url = "-x socks5h://" .. socks_server .. " " .. url
		elseif baidu == nil then
		-- 其他代理模式+百度以外网站
			url = "-x socks5h://" .. socks_server .. " " .. url
		end
	end
	local result = luci.sys.exec('curl --connect-timeout 3 -o /dev/null -I -sk ' .. url)
	local code = tonumber(luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $1}'") or "0")
	if code ~= 0 then
		local use_time = luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $2}'")
		if use_time:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
		e.ping_type = "curl"
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function ping_node()
	local index = luci.http.formvalue("index")
	local address = luci.http.formvalue("address")
	local port = luci.http.formvalue("port")
	local type = luci.http.formvalue("type") or "icmp"
	local e = {}
	e.index = index
	if type == "tcping" and luci.sys.exec("echo -n $(command -v tcping)") ~= "" then
		if api.is_ipv6(address) then
			address = api.get_ipv6_only(address)
		end
		e.ping = luci.sys.exec(string.format("echo -n $(tcping -q -c 1 -i 1 -t 2 -p %s %s 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null", port, address))
	else
		e.ping = luci.sys.exec("echo -n $(ping -c 1 -W 1 %q 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null" % address)
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function urltest_node()
	local index = luci.http.formvalue("index")
	local id = luci.http.formvalue("id")
	local e = {}
	e.index = index
	local result = luci.sys.exec(string.format("/usr/share/passwall/test.sh url_test_node %s %s", id, "urltest_node"))
	local code = tonumber(luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $1}'") or "0")
	if code ~= 0 then
		local use_time = luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $2}'")
		if use_time:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function set_node()
	local protocol = luci.http.formvalue("protocol")
	local section = luci.http.formvalue("section")
	uci:set(appname, "@global[0]", protocol .. "_node", section)
	api.uci_save(uci, appname, true, true)
	luci.http.redirect(api.url("log"))
end

function copy_node()
	local section = luci.http.formvalue("section")
	local uuid = api.gen_short_uuid()
	uci:section(appname, "nodes", uuid)
	for k, v in pairs(uci:get_all(appname, section)) do
		local filter = k:find("%.")
		if filter and filter == 1 then
		else
			xpcall(function()
				uci:set(appname, uuid, k, v)
			end,
			function(e)
			end)
		end
	end
	uci:delete(appname, uuid, "add_from")
	uci:set(appname, uuid, "add_mode", 1)
	api.uci_save(uci, appname)
	luci.http.redirect(api.url("node_config", uuid))
end

function clear_all_nodes()
	uci:set(appname, '@global[0]', "enabled", "0")
	uci:delete(appname, '@global[0]', "tcp_node")
	uci:delete(appname, '@global[0]', "udp_node")
	uci:foreach(appname, "socks", function(t)
		uci:delete(appname, t[".name"])
		uci:set_list(appname, t[".name"], "autoswitch_backup_node", {})
	end)
	uci:foreach(appname, "haproxy_config", function(t)
		uci:delete(appname, t[".name"])
	end)
	uci:foreach(appname, "acl_rule", function(t)
		uci:delete(appname, t[".name"], "tcp_node")
		uci:delete(appname, t[".name"], "udp_node")
	end)
	uci:foreach(appname, "nodes", function(node)
		uci:delete(appname, node['.name'])
	end)

	api.uci_save(uci, appname, true)
	luci.sys.call("/etc/init.d/" .. appname .. " stop")
end

function delete_select_nodes()
	local ids = luci.http.formvalue("ids")
	string.gsub(ids, '[^' .. "," .. ']+', function(w)
		if (uci:get(appname, "@global[0]", "tcp_node") or "") == w then
			uci:delete(appname, '@global[0]', "tcp_node")
		end
		if (uci:get(appname, "@global[0]", "udp_node") or "") == w then
			uci:delete(appname, '@global[0]', "udp_node")
		end
		uci:foreach(appname, "socks", function(t)
			if t["node"] == w then
				uci:delete(appname, t[".name"])
			end
			local auto_switch_node_list = uci:get(appname, t[".name"], "autoswitch_backup_node") or {}
			for i = #auto_switch_node_list, 1, -1 do
				if w == auto_switch_node_list[i] then
					table.remove(auto_switch_node_list, i)
				end
			end
			uci:set_list(appname, t[".name"], "autoswitch_backup_node", auto_switch_node_list)
		end)
		uci:foreach(appname, "haproxy_config", function(t)
			if t["lbss"] == w then
				uci:delete(appname, t[".name"])
			end
		end)
		uci:foreach(appname, "acl_rule", function(t)
			if t["tcp_node"] == w then
				uci:delete(appname, t[".name"], "tcp_node")
			end
			if t["udp_node"] == w then
				uci:delete(appname, t[".name"], "udp_node")
			end
		end)
		uci:foreach(appname, "nodes", function(t)
			if t["preproxy_node"] == w then
				uci:delete(appname, t[".name"], "preproxy_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
			if t["to_node"] == w then
				uci:delete(appname, t[".name"], "to_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
		end)
		uci:delete(appname, w)
	end)
	api.uci_save(uci, appname, true)
	luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
end

function update_rules()
	local update = luci.http.formvalue("update")
	luci.sys.call("lua /usr/share/passwall/rule_update.lua log '" .. update .. "' > /dev/null 2>&1 &")
	http_write_json()
end

function server_user_status()
	local e = {}
	e.index = luci.http.formvalue("index")
	e.status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v 'grep' | grep '%s/bin/' | grep -i '%s' >/dev/null", appname .. "_server", luci.http.formvalue("id"))) == 0
	http_write_json(e)
end

function server_user_log()
	local id = luci.http.formvalue("id")
	if fs.access("/tmp/etc/passwall_server/" .. id .. ".log") then
		local content = luci.sys.exec("cat /tmp/etc/passwall_server/" .. id .. ".log")
		content = content:gsub("\n", "<br />")
		luci.http.write(content)
	else
		luci.http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function server_get_log()
	luci.http.write(luci.sys.exec("[ -f '/tmp/log/passwall_server.log' ] && cat /tmp/log/passwall_server.log"))
end

function server_clear_log()
	luci.sys.call("echo '' > /tmp/log/passwall_server.log")
end

function app_check()
	local json = api.to_check_self()
	http_write_json(json)
end

function com_check(comname)
	local json = api.to_check("",comname)
	http_write_json(json)
end

function com_update(comname)
	local json = nil
	local task = http.formvalue("task")
	if task == "extract" then
		json = api.to_extract(comname, http.formvalue("file"), http.formvalue("subfix"))
	elseif task == "move" then
		json = api.to_move(comname, http.formvalue("file"))
	else
		json = api.to_download(comname, http.formvalue("url"), http.formvalue("size"))
	end

	http_write_json(json)
end

function read_rulelist()
	local rule_type = http.formvalue("type")
	local rule_path
	if rule_type == "gfw" then
		rule_path = "/usr/share/passwall/rules/gfwlist"
	elseif rule_type == "chn" then
		rule_path = "/usr/share/passwall/rules/chnlist"
	elseif rule_type == "chnroute" then
		rule_path = "/usr/share/passwall/rules/chnroute"
	else
		http.status(400, "Invalid rule type")
		return
	end
	if fs.access(rule_path) then
		http.prepare_content("text/plain")
		http.write(fs.readfile(rule_path))
	end
end

function create_backup()
	local backup_files = {
		"/etc/config/passwall",
		"/etc/config/passwall_server",
		"/usr/share/passwall/rules/block_host",
		"/usr/share/passwall/rules/block_ip",
		"/usr/share/passwall/rules/direct_host",
		"/usr/share/passwall/rules/direct_ip",
		"/usr/share/passwall/rules/proxy_host",
		"/usr/share/passwall/rules/proxy_ip"
	}
	local date = os.date("%Y%m%d")
	local tar_file = "/tmp/passwall-" .. date .. "-backup.tar.gz"
	fs.remove(tar_file)
	local cmd = "tar -czf " .. tar_file .. " " .. table.concat(backup_files, " ")
	api.sys.call(cmd)
	http.header("Content-Disposition", "attachment; filename=passwall-" .. date .. "-backup.tar.gz")
	http.header("X-Backup-Filename", "passwall-" .. date .. "-backup.tar.gz")
	http.prepare_content("application/octet-stream")
	http.write(fs.readfile(tar_file))
	fs.remove(tar_file)
end
