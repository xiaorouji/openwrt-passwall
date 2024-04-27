local api = require "luci.passwall.api"
local appname = "passwall"
local uci = api.uci
local sys = api.sys
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")
local has_gfwlist = api.fs.access("/usr/share/passwall/rules/gfwlist")
local has_chnlist = api.fs.access("/usr/share/passwall/rules/chnlist")
local has_chnroute = api.fs.access("/usr/share/passwall/rules/chnroute")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

m = Map(appname)
api.set_apply_on_parse(m)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
end

-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = true

local mac_t = {}
sys.net.mac_hints(function(e, t)
	mac_t[#mac_t + 1] = {
		ip = t,
		mac = e
	}
end)
table.sort(mac_t, function(a,b)
	if #a.ip < #b.ip then
		return true
	elseif #a.ip == #b.ip then
		if a.ip < b.ip then
			return true
		else
			return #a.ip < #b.ip
		end
	end
	return false
end)

---- Source
sources = s:option(DynamicList, "sources", translate("Source"))
sources.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("MAC") .. ": 00:00:00:FF:FF:FF"
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("IP range") .. ": 192.168.1.100-192.168.1.200"
.. "</li><li>" .. translate("IPSet") .. ": ipset:lanlist"
.. "</li></ul>"
sources.cast = "string"
for _, key in pairs(mac_t) do
	sources:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end
sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
sources.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if v:find("ipset:") and v:find("ipset:") == 1 then
			local ipset = v:gsub("ipset:", "")
			if ipset and ipset ~= "" then
				flag = true
			end
		end

		if flag == false and datatypes.macaddr(v) then
			flag = true
		end

		if flag == false and datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and api.iprange(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end
sources.write = dynamicList_write

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
			 "<font color='red'>" .. translate(
				 "Fill in the ports you don't want to be forwarded by the agent, with the highest priority.") ..
				 "</font>")
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate

o = s:option(Flag, "use_global_config", translatef("Use global config"))
o.default = "0"
o.rmempty = false

tcp_node = s:option(ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
tcp_node.default = ""
tcp_node:value("", translate("Close"))
tcp_node:depends("use_global_config", false)

udp_node = s:option(ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
udp_node.default = ""
udp_node:value("", translate("Close"))
udp_node:value("tcp", translate("Same as the tcp node"))
udp_node:depends({ tcp_node = "",  ['!reverse'] = true })

for k, v in pairs(nodes_table) do
	tcp_node:value(v.id, v["remark"])
	udp_node:value(v.id, v["remark"])
end

---- TCP Proxy Drop Ports
local TCP_PROXY_DROP_PORTS = uci:get(appname, "@global_forwarding[0]", "tcp_proxy_drop_ports")
o = s:option(Value, "tcp_proxy_drop_ports", translate("TCP Proxy Drop Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. TCP_PROXY_DROP_PORTS .. ")")
o.validate = port_validate

---- UDP Proxy Drop Ports
local UDP_PROXY_DROP_PORTS = uci:get(appname, "@global_forwarding[0]", "udp_proxy_drop_ports")
o = s:option(Value, "udp_proxy_drop_ports", translate("UDP Proxy Drop Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Use global config") .. "(" .. UDP_PROXY_DROP_PORTS .. ")")
o:value("443", translate("QUIC"))
o.validate = port_validate

---- TCP Redir Ports
local TCP_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "tcp_redir_ports")
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"), translatef("Only work with using the %s node.", "TCP"))
o.default = "default"
o:value("default", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))
o.validate = port_validate

---- UDP Redir Ports
local UDP_REDIR_PORTS = uci:get(appname, "@global_forwarding[0]", "udp_redir_ports")
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"), translatef("Only work with using the %s node.", "UDP"))
o.default = "default"
o:value("default", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("53", "53")
o.validate = port_validate

o = s:option(Flag, "use_direct_list", translatef("Use %s", translate("Direct List")))
o.default = "1"
o:depends({ tcp_node = "",  ['!reverse'] = true })

o = s:option(Flag, "use_proxy_list", translatef("Use %s", translate("Proxy List")))
o.default = "1"
o:depends({ tcp_node = "",  ['!reverse'] = true })

o = s:option(Flag, "use_block_list", translatef("Use %s", translate("Block List")))
o.default = "1"
o:depends({ tcp_node = "",  ['!reverse'] = true })

if has_gfwlist then
	o = s:option(Flag, "use_gfw_list", translatef("Use %s", translate("GFW List")))
	o.default = "1"
	o:depends({ tcp_node = "",  ['!reverse'] = true })
end

if has_chnlist or has_chnroute then
	o = s:option(ListValue, "chn_list", translate("China List"))
	o:value("0", translate("Close(Not use)"))
	o:value("direct", translate("Direct Connection"))
	o:value("proxy", translate("Proxy"))
	o.default = "direct"
	o:depends({ tcp_node = "",  ['!reverse'] = true })
end

o = s:option(ListValue, "tcp_proxy_mode", "TCP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ tcp_node = "",  ['!reverse'] = true })

o = s:option(ListValue, "udp_proxy_mode", "UDP " .. translate("Proxy Mode"))
o:value("disable", translate("No Proxy"))
o:value("proxy", translate("Proxy"))
o:depends({ udp_node = "",  ['!reverse'] = true })

o = s:option(DummyValue, "switch_mode", " ")
o.template = appname .. "/global/proxy"
o:depends({ tcp_node = "",  ['!reverse'] = true })

---- DNS
o = s:option(ListValue, "dns_shunt", "DNS " .. translate("Shunt"))
o:depends({ tcp_node = "",  ['!reverse'] = true })
o:value("dnsmasq", "Dnsmasq")
o:value("chinadns-ng", "Dnsmasq + ChinaDNS-NG")

o = s:option(Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"
o:depends({ tcp_node = "",  ['!reverse'] = true })

---- DNS Forward Mode
o = s:option(ListValue, "dns_mode", translate("Filter Mode"))
o:depends({ tcp_node = "",  ['!reverse'] = true })
if api.is_finded("dns2socks") then
	o:value("dns2socks", "dns2socks")
end
if has_singbox then
	o:value("sing-box", "Sing-Box")
end
if has_xray then
	o:value("xray", "Xray")
end

o = s:option(ListValue, "xray_dns_mode", " ")
o:value("tcp", "TCP")
o:value("tcp+doh", "TCP + DoH (" .. translate("A/AAAA type") .. ")")
o:depends("dns_mode", "xray")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "xray" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

o = s:option(ListValue, "singbox_dns_mode", " ")
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:depends("dns_mode", "sing-box")
o.cfgvalue = function(self, section)
	return m:get(section, "v2ray_dns_mode")
end
o.write = function(self, section, value)
	if s.fields["dns_mode"]:formvalue(section) == "sing-box" then
		return m:set(section, "v2ray_dns_mode", value)
	end
end

---- DNS Forward
o = s:option(Value, "remote_dns", translate("Remote DNS"))
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends({dns_mode = "dns2socks"})
o:depends({xray_dns_mode = "tcp"})
o:depends({xray_dns_mode = "tcp+doh"})
o:depends({singbox_dns_mode = "tcp"})

if has_singbox or has_xray then
	o = s:option(Value, "remote_dns_doh", translate("Remote DNS DoH"))
	o:value("https://1.1.1.1/dns-query", "CloudFlare")
	o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
	o:value("https://8.8.4.4/dns-query", "Google 8844")
	o:value("https://8.8.8.8/dns-query", "Google 8888")
	o:value("https://9.9.9.9/dns-query", "Quad9-Recommended")
	o:value("https://208.67.222.222/dns-query", "OpenDNS")
	o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
	o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
	o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
	o.default = "https://1.1.1.1/dns-query"
	o.validate = function(self, value, t)
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
					if not api.datatypes.ipmask4(v) then
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
	o:depends({xray_dns_mode = "tcp+doh"})
	o:depends({singbox_dns_mode = "doh"})

	if has_xray then
		o = s:option(Value, "dns_client_ip", translate("EDNS Client Subnet"))
		o.datatype = "ipaddr"
		o:depends({dns_mode = "xray"})
	end
end

o = s:option(ListValue, "chinadns_ng_default_tag", translate("ChinaDNS-NG Domain Default Tag"))
o.default = "none"
o:value("none", translate("Default"))
o:value("gfw", translate("Remote DNS"))
o:value("chn", translate("Direct DNS"))
o.description = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Default: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China ip, then use the direct result, otherwise use the remote result.") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
		.. "</ul>"
o:depends({dns_shunt = "chinadns-ng", tcp_proxy_mode = "proxy", chn_list = "direct"})

o = s:option(ListValue, "use_default_dns", translate("Default DNS"))
o.default = "direct"
o:value("remote", translate("Remote DNS"))
o:value("direct", translate("Direct DNS"))
o.description = "<ul>"
		.. "<li>" .. translate("When not matching any domain name list:") .. "</li>"
		.. "<li>" .. translate("Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!") .. "</li>"
		.. "<li>" .. translate("Direct DNS: Internet experience may be better, but DNS will be leaked!") .. "</li>"
		.. "</ul>"
o:depends({dns_shunt = "dnsmasq", tcp_proxy_mode = "proxy", chn_list = "direct"})

return m
