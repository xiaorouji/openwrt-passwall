local api = require "luci.model.cbi.passwall.api.api"
local appname = api.appname
local sys = api.sys

m = Map(appname)

local global_proxy_mode = (m:get("@global[0]", "tcp_proxy_mode") or "") .. (m:get("@global[0]", "udp_proxy_mode") or "")

-- [[ ACLs Settings ]]--
s = m:section(TypedSection, "acl_rule", translate("ACLs"), "<font color='red'>" .. translate("ACLs is a tools which used to designate specific IP proxy mode, IP or MAC address can be entered.") .. "</font>")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.rmempty = true

o = s:option(Value, "ip_mac", translate("IP/MAC"))
o.datatype = "or(ip4addr,macaddr)"
o.rmempty = false

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
for _, key in pairs(mac_t) do
    o:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end

---- TCP Proxy Mode
tcp_proxy_mode = s:option(ListValue, "tcp_proxy_mode", translatef("%s Proxy Mode", "TCP"))
tcp_proxy_mode.default = "default"
tcp_proxy_mode.rmempty = false
tcp_proxy_mode:value("default", translate("Default"))
tcp_proxy_mode:value("disable", translate("No Proxy"))
tcp_proxy_mode:value("global", translate("Global Proxy"))
if global_proxy_mode:find("returnhome") then
    tcp_proxy_mode:value("returnhome", translate("China List"))
else
    tcp_proxy_mode:value("gfwlist", translate("GFW List"))
    tcp_proxy_mode:value("chnroute", translate("Not China List"))
end

---- UDP Proxy Mode
udp_proxy_mode = s:option(ListValue, "udp_proxy_mode", translatef("%s Proxy Mode", "UDP"))
udp_proxy_mode.default = "default"
udp_proxy_mode.rmempty = false
udp_proxy_mode:value("default", translate("Default"))
udp_proxy_mode:value("disable", translate("No Proxy"))
udp_proxy_mode:value("global", translate("Global Proxy"))
if global_proxy_mode:find("returnhome") then
    udp_proxy_mode:value("returnhome", translate("China List"))
else
    udp_proxy_mode:value("gfwlist", translate("GFW List"))
    udp_proxy_mode:value("chnroute", translate("Game Mode"))
end

---- TCP No Redir Ports
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))

---- UDP No Redir Ports
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"))
o.default = "default"
o:value("disable", translate("No patterns are used"))
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))

---- TCP Redir Ports
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"))
o.default = "default"
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))
o:value("80,443", "80,443")
o:value("80:65535", "80 " .. translate("or more"))
o:value("1:443", "443 " .. translate("or less"))

---- UDP Redir Ports
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"))
o.default = "default"
o:value("default", translate("Default"))
o:value("1:65535", translate("All"))
o:value("53", "53")

return m
