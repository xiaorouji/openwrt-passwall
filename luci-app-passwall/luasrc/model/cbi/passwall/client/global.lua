local api = require "luci.passwall.api"
local appname = api.appname
local uci = api.uci
local datatypes = api.datatypes
local has_v2ray = api.is_finded("v2ray")
local has_xray = api.is_finded("xray")
local has_chnlist = api.fs.access("/usr/share/passwall/rules/chnlist")

m = Map(appname)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local tcp_socks_server = "127.0.0.1" .. ":" .. (uci:get(appname, "@global[0]", "tcp_node_socks_port") or "1070")
local socks_table = {}
socks_table[#socks_table + 1] = {
	id = tcp_socks_server,
	remarks = tcp_socks_server .. " - " .. translate("TCP Node")
}
uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		local id, remarks
		for k, n in pairs(nodes_table) do
			if (s.node == n.id) then
				remarks = n["remark"]; break
			end
		end
		id = "127.0.0.1" .. ":" .. s.port
		socks_table[#socks_table + 1] = {
			id = id,
			remarks = id .. " - " .. (remarks or translate("Misconfigured"))
		}
	end
end)

local doh_validate = function(self, value, t)
	if value ~= "" then
		value = api.trim(value)
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not datatypes.ipmask4(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
end

local redir_mode_validate = function(self, value, t)
	local tcp_proxy_mode_v = tcp_proxy_mode:formvalue(t) or ""
	local udp_proxy_mode_v = udp_proxy_mode:formvalue(t) or ""
	local localhost_tcp_proxy_mode_v = localhost_tcp_proxy_mode:formvalue(t) or ""
	local localhost_udp_proxy_mode_v = localhost_udp_proxy_mode:formvalue(t) or ""
	local s = tcp_proxy_mode_v .. udp_proxy_mode_v .. localhost_tcp_proxy_mode_v .. localhost_udp_proxy_mode_v
	if s:find("returnhome") then
		if s:find("chnroute") or s:find("gfwlist") then
			return nil, translate("China list or gfwlist cannot be used together with outside China list!")
		end
	end
	return value
end

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

local auto_switch_tip
local auto_switch_flag
local current_tcp_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/TCP' ] && echo -n $(cat /tmp/etc/%s/id/TCP)", appname, appname))
if current_tcp_node and current_tcp_node ~= "" and current_tcp_node ~= "nil" then
	local n = uci:get_all(appname, current_tcp_node)
	if n then
		if tonumber(m:get("@auto_switch[0]", "enable") or 0) == 1 then
			auto_switch_flag = ""
			if n.protocol == "_shunt" then
				local shunt_logic = tonumber(m:get("@auto_switch[0]", "shunt_logic"))
				if shunt_logic == 1 then
					auto_switch_flag = "default"
				elseif shunt_logic == 2 then
					auto_switch_flag = "main"
				end
				current_tcp_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/TCP_%s' ] && echo -n $(cat /tmp/etc/%s/id/TCP_%s)", appname, auto_switch_flag, appname, auto_switch_flag))
				if current_tcp_node and current_tcp_node ~= "" and current_tcp_node ~= "nil" then
					n = uci:get_all(appname, current_tcp_node)
				end
			end
			local remarks = api.get_node_remarks(n)
			local url = api.url("node_config", n[".name"])
			auto_switch_tip = translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
		end
	end
end

---- TCP Node
tcp_node = s:taboption("Main", ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
tcp_node:value("nil", translate("Close"))
if auto_switch_flag == "" and auto_switch_tip then
	tcp_node.description = auto_switch_tip
end

---- UDP Node
udp_node = s:taboption("Main", ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
udp_node:value("nil", translate("Close"))
udp_node:value("tcp", translate("Same as the tcp node"))

-- 分流
if (has_v2ray or has_xray) and #nodes_table > 0 then
	local normal_list = {}
	local balancing_list = {}
	local shunt_list = {}
	for k, v in pairs(nodes_table) do
		if v.node_type == "normal" then
			normal_list[#normal_list + 1] = v
		end
		if v.protocol and v.protocol == "_balancing" then
			balancing_list[#balancing_list + 1] = v
		end
		if v.protocol and v.protocol == "_shunt" then
			shunt_list[#shunt_list + 1] = v
		end
	end

	local function get_cfgvalue(shunt_node_id, option)
		return function(self, section)
			return m:get(shunt_node_id, option) or "nil"
		end
	end
	local function get_write(shunt_node_id, option)
		return function(self, section, value)
			m:set(shunt_node_id, option, value)
		end
	end
	if #normal_list > 0 then
		for k, v in pairs(shunt_list) do
			local vid = v.id:sub(1, 8)
			-- shunt node type, V2ray or Xray
			local type = s:taboption("Main", ListValue, vid .. "-type", translate("Type"))
			if has_v2ray then
				type:value("V2ray", translate("V2ray"))
			end
			if has_xray then
				type:value("Xray", translate("Xray"))
			end
			type.cfgvalue = get_cfgvalue(v.id, "type")
			type.write = get_write(v.id, "type")
			
			-- pre-proxy
			o = s:taboption("Main", Flag, vid .. "-preproxy_enabled", translate("Preproxy"))
			o:depends("tcp_node", v.id)
			o.rmempty = false
			o.cfgvalue = get_cfgvalue(v.id, "preproxy_enabled")
			o.write = get_write(v.id, "preproxy_enabled")

			o = s:taboption("Main", ListValue, vid .. "-main_node", string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
			o:depends(vid .. "-preproxy_enabled", "1")
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end
			o.cfgvalue = get_cfgvalue(v.id, "main_node")
			o.write = get_write(v.id, "main_node")
			if auto_switch_flag == "main" and auto_switch_tip then
				o.description = auto_switch_tip
			end

			if (has_v2ray and has_xray) or (v.type == "V2ray" and not has_v2ray) or (v.type == "Xray" and not has_xray) then
				type:depends("tcp_node", v.id)
			else
				type:depends("tcp_node", "hide") --不存在的依赖，即始终隐藏
			end

			uci:foreach(appname, "shunt_rules", function(e)
				local id = e[".name"]
				local node_option = vid .. "-" .. id .. "_node"
				if id and e.remarks then
					o = s:taboption("Main", ListValue, node_option, string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
					o.cfgvalue = get_cfgvalue(v.id, id)
					o.write = get_write(v.id, id)
					o:depends("tcp_node", v.id)
					o:value("nil", translate("Close"))
					o:value("_default", translate("Default"))
					o:value("_direct", translate("Direct Connection"))
					o:value("_blackhole", translate("Blackhole"))

					local pt = s:taboption("Main", ListValue, vid .. "-".. id .. "_proxy_tag", string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
					pt.cfgvalue = get_cfgvalue(v.id, id .. "_proxy_tag")
					pt.write = get_write(v.id, id .. "_proxy_tag")
					pt:value("nil", translate("Close"))
					pt:value("main", translate("Preproxy Node"))
					pt.default = "nil"
					for k1, v1 in pairs(balancing_list) do
						o:value(v1.id, v1.remark)
					end
					for k1, v1 in pairs(normal_list) do
						o:value(v1.id, v1.remark)
						pt:depends({ [node_option] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
					end
				end
			end)

			local id = "default_node"
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default")))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:depends("tcp_node", v.id)
			o:value("_direct", translate("Direct Connection"))
			o:value("_blackhole", translate("Blackhole"))
			for k1, v1 in pairs(balancing_list) do
				o:value(v1.id, v1.remark)
			end
			for k1, v1 in pairs(normal_list) do
				o:value(v1.id, v1.remark)
			end
			if auto_switch_flag == "default" and auto_switch_tip then
				o.description = auto_switch_tip
			end

			local id = "default_proxy_tag"
			o = s:taboption("Main", ListValue, vid .. "-" .. id, string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
			o.cfgvalue = get_cfgvalue(v.id, id)
			o.write = get_write(v.id, id)
			o:value("nil", translate("Close"))
			o:value("main", translate("Preproxy Node"))
			for k1, v1 in pairs(normal_list) do
				if v1.protocol ~= "_balancing" then
					o:depends({ [vid .. "-default_node"] = v1.id, [vid .. "-preproxy_enabled"] = "1" })
				end
			end
		end
	else
		local tips = s:taboption("Main", DummyValue, "tips", " ")
		tips.rawhtml = true
		tips.cfgvalue = function(t, n)
			return string.format('<a style="color: red">%s</a>', translate("There are no available nodes, please add or subscribe nodes first."))
		end
		tips:depends({ tcp_node = "nil", ["!reverse"] = true })
		for k, v in pairs(shunt_list) do
			tips:depends("udp_node", v.id)
		end
		for k, v in pairs(balancing_list) do
			tips:depends("udp_node", v.id)
		end
	end
end

tcp_node_socks_port = s:taboption("Main", Value, "tcp_node_socks_port", translate("TCP Node") .. " Socks " .. translate("Listen Port"))
tcp_node_socks_port.default = 1070
tcp_node_socks_port.datatype = "port"
tcp_node_socks_port:depends({ tcp_node = "nil", ["!reverse"] = true })
--[[
if has_v2ray or has_xray then
	tcp_node_http_port = s:taboption("Main", Value, "tcp_node_http_port", translate("TCP Node") .. " HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	tcp_node_http_port.default = 0
	tcp_node_http_port.datatype = "port"
end
]]--


s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"

---- DNS Forward Mode
dns_mode = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
dns_mode.rmempty = false
dns_mode:reset_values()
if api.is_finded("dns2tcp") then
	dns_mode:value("dns2tcp", translatef("Requery DNS By %s", "TCP"))
end
if api.is_finded("dns2socks") then
	dns_mode:value("dns2socks", "dns2socks")
end
if has_xray then
	dns_mode:value("xray", "Xray")
end
dns_mode:value("udp", translatef("Requery DNS By %s", "UDP"))

o = s:taboption("DNS", ListValue, "v2ray_dns_mode", " ")
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("fakedns", "FakeDNS")
o:depends("dns_mode", "xray")
o.validate = function(self, value, t)
	if value == "fakedns" then
		local _dns_mode = dns_mode:formvalue(t)
		local _tcp_node = tcp_node:formvalue(t)
		if m:get(_tcp_node, "type"):lower() ~= _dns_mode then
			return nil, translatef("TCP node must be '%s' type to use FakeDNS.", _dns_mode)
		end
	end
	return value
end

o = s:taboption("DNS", Value, "socks_server", translate("Socks Server"), translate("Make sure socks service is available on this address."))
for k, v in pairs(socks_table) do o:value(v.id, v.remarks) end
o.default = socks_table[1].id
o.validate = function(self, value, t)
	if not datatypes.ipaddrport(value) then
		return nil, translate("Socks Server") .. " " .. translate("Not valid IP format, please re-enter!")
	end
	return value
end
o:depends({dns_mode = "dns2socks"})

---- DNS Forward
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({dns_mode = "dns2tcp"})
o:depends({dns_mode = "udp"})
o:depends({v2ray_dns_mode = "tcp"})

---- DoH
o = s:taboption("DNS", Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.default = "https://1.1.1.1/dns-query"
o:value("https://1.1.1.1/dns-query", "CloudFlare")
o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
o:value("https://8.8.4.4/dns-query", "Google 8844")
o:value("https://8.8.8.8/dns-query", "Google 8888")
o:value("https://9.9.9.9/dns-query", "Quad9-Recommended")
o:value("https://208.67.222.222/dns-query", "OpenDNS")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o.validate = doh_validate
o:depends("v2ray_dns_mode", "doh")

o = s:taboption("DNS", Value, "dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends("v2ray_dns_mode", "tcp")
o:depends("v2ray_dns_mode", "doh")

o = s:taboption("DNS", Flag, "dns_cache", translate("Cache Resolved"))
o.default = "1"
o:depends({dns_mode = "dns2socks"})
o:depends({dns_mode = "xray", v2ray_dns_mode = "tcp"})
o:depends({dns_mode = "xray", v2ray_dns_mode = "doh"})
o.rmempty = false

if api.is_finded("chinadns-ng") then
	o = s:taboption("DNS", Flag, "chinadns_ng", translate("ChinaDNS-NG"), translate("The effect is better, but will increase the memory."))
	o.default = "0"
	o:depends({dns_mode = "dns2socks"})
	o:depends({dns_mode = "dns2tcp"})
	o:depends({dns_mode = "xray", v2ray_dns_mode = "tcp"})
	o:depends({dns_mode = "xray", v2ray_dns_mode = "doh"})
	o:depends({dns_mode = "udp"})
end

if has_chnlist then
	when_chnroute_default_dns = s:taboption("DNS", ListValue, "when_chnroute_default_dns", translate("When using the chnroute list the default DNS"))
	when_chnroute_default_dns.default = "direct"
	when_chnroute_default_dns:value("remote", translate("Remote DNS"))
	when_chnroute_default_dns:value("direct", translate("Direct DNS"))
	when_chnroute_default_dns.description = "<ul>"
	.. "<li>" .. translate("Remote DNS can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
	.. "<li>" .. translate("Direct DNS Internet experience may be better, but DNS will be leaked!") .. "</li>"
	.. "</ul>"
end

o = s:taboption("DNS", Button, "clear_ipset", translate("Clear IPSET"), translate("Try this feature if the rule modification does not take effect."))
o.inputstyle = "remove"
function o.write(e, e)
	luci.sys.call("[ -n \"$(nft list sets 2>/dev/null | grep \"gfwlist\")\" ] && /usr/share/" .. appname .. "/nftables.sh flush_nftset || /usr/share/" .. appname .. "/iptables.sh flush_ipset > /dev/null 2>&1 &")
	luci.http.redirect(api.url("log"))
end

s:tab("Proxy", translate("Mode"))

---- TCP Default Proxy Mode
tcp_proxy_mode = s:taboption("Proxy", ListValue, "tcp_proxy_mode", "TCP " .. translate("Default Proxy Mode"))
tcp_proxy_mode:value("disable", translate("No Proxy"))
tcp_proxy_mode:value("global", translate("Global Proxy"))
tcp_proxy_mode:value("gfwlist", translate("GFW List"))
tcp_proxy_mode:value("chnroute", translate("Not China List"))
if has_chnlist then
	tcp_proxy_mode:value("returnhome", translate("China List"))
end
tcp_proxy_mode:value("direct/proxy", translate("Only use direct/proxy list"))
tcp_proxy_mode.default = "chnroute"
--tcp_proxy_mode.validate = redir_mode_validate

---- UDP Default Proxy Mode
udp_proxy_mode = s:taboption("Proxy", ListValue, "udp_proxy_mode", "UDP " .. translate("Default Proxy Mode"))
udp_proxy_mode:value("disable", translate("No Proxy"))
udp_proxy_mode:value("global", translate("Global Proxy"))
udp_proxy_mode:value("gfwlist", translate("GFW List"))
udp_proxy_mode:value("chnroute", translate("Not China List"))
if has_chnlist then
	udp_proxy_mode:value("returnhome", translate("China List"))
end
udp_proxy_mode:value("direct/proxy", translate("Only use direct/proxy list"))
udp_proxy_mode.default = "chnroute"
--udp_proxy_mode.validate = redir_mode_validate

---- Localhost TCP Proxy Mode
localhost_tcp_proxy_mode = s:taboption("Proxy", ListValue, "localhost_tcp_proxy_mode", translate("Router Localhost") .. " TCP " .. translate("Proxy Mode"))
localhost_tcp_proxy_mode:value("default", translatef("Same as the %s default proxy mode", "TCP"))
localhost_tcp_proxy_mode:value("global", translate("Global Proxy"))
localhost_tcp_proxy_mode:value("gfwlist", translate("GFW List"))
localhost_tcp_proxy_mode:value("chnroute", translate("Not China List"))
if has_chnlist then
	localhost_tcp_proxy_mode:value("returnhome", translate("China List"))
end
localhost_tcp_proxy_mode:value("disable", translate("No Proxy"))
localhost_tcp_proxy_mode:value("direct/proxy", translate("Only use direct/proxy list"))
localhost_tcp_proxy_mode.default = "default"
--localhost_tcp_proxy_mode.validate = redir_mode_validate

---- Localhost UDP Proxy Mode
localhost_udp_proxy_mode = s:taboption("Proxy", ListValue, "localhost_udp_proxy_mode", translate("Router Localhost") .. " UDP " .. translate("Proxy Mode"))
localhost_udp_proxy_mode:value("default", translatef("Same as the %s default proxy mode", "UDP"))
localhost_udp_proxy_mode:value("global", translate("Global Proxy"))
localhost_udp_proxy_mode:value("gfwlist", translate("GFW List"))
localhost_udp_proxy_mode:value("chnroute", translate("Not China List"))
if has_chnlist then
	localhost_udp_proxy_mode:value("returnhome", translate("China List"))
end
localhost_udp_proxy_mode:value("disable", translate("No Proxy"))
localhost_udp_proxy_mode:value("direct/proxy", translate("Only use direct/proxy list"))
localhost_udp_proxy_mode.default = "default"
localhost_udp_proxy_mode.validate = redir_mode_validate

tips = s:taboption("Proxy", DummyValue, "tips", " ")
tips.rawhtml = true
tips.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="%s">%s</a>', api.url("acl"), translate("Want different devices to use different proxy modes/ports/nodes? Please use access control."))
end

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "close_log_tcp", translatef("%s Node Log Close", "TCP"))
o.rmempty = false

o = s:taboption("log", Flag, "close_log_udp", translatef("%s Node Log Close", "UDP"))
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", "V2ray/Xray " .. translate("Log Level"))
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

trojan_loglevel = s:taboption("log", ListValue, "trojan_loglevel", "Trojan " ..  translate("Log Level"))
trojan_loglevel.default = "2"
trojan_loglevel:value("0", "all")
trojan_loglevel:value("1", "info")
trojan_loglevel:value("2", "warn")
trojan_loglevel:value("3", "error")
trojan_loglevel:value("4", "fatal")

o = s:taboption("log", Flag, "advanced_log_feature", translate("Advanced log feature"), translate("For professionals only."))
o.default = "0"
o.rmempty = false
local syslog = s:taboption("log", Flag, "sys_log", translate("Logging to system log"), translate("Logging to the system log for more advanced functions. For example, send logs to a dedicated log server."))
syslog:depends("advanced_log_feature", "1")
syslog.default = "0"
syslog.rmempty = false
local logpath = s:taboption("log", Value, "persist_log_path", translate("Persist log file directory"), translate("The path to the directory used to store persist log files, the \"/\" at the end can be omitted. Leave it blank to disable this feature."))
logpath:depends({ ["advanced_log_feature"] = 1, ["sys_log"] = 0 })

s:tab("faq", "FAQ")

o = s:taboption("faq", DummyValue, "")
o.template = appname .. "/global/faq"

-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s = m:section(TypedSection, "socks", translate("Socks Config"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
function s.create(e, t)
	TypedSection.create(e, api.gen_uuid())
end

o = s:option(DummyValue, "status", translate("Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<div class="_status" socks_id="%s"></div>', n)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

socks_node = s:option(ListValue, "node", translate("Socks Node"))

local n = 1
uci:foreach(appname, "socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_v2ray or has_xray then
	o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end

for k, v in pairs(nodes_table) do
	tcp_node:value(v.id, v["remark"])
	udp_node:value(v.id, v["remark"])
	if v.type == "Socks" then
		if has_v2ray or has_xray then
			socks_node:value(v.id, v["remark"])
		end
	else
		socks_node:value(v.id, v["remark"])
	end
end

m:append(Template(appname .. "/global/footer"))

return m
