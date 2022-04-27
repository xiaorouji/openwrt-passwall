local api = require "luci.model.cbi.passwall.api.api"
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

local socks_table = {}
uci:foreach(appname, "socks", function(s)
    if s.enabled == "1" and s.node then
        local id, remarks
        local same, i = s.node:match("^(tcp)")
        if same then
            remarks = translatef("Same as the tcp node")
        else
            for k, n in pairs(nodes_table) do
                if (s.node == n.id) then
                    remarks = n["remark"]; break
                end
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

---- TCP Node
tcp_node = s:taboption("Main", ListValue, "tcp_node", "<a style='color: red'>" .. translate("TCP Node") .. "</a>")
tcp_node.description = ""
local current_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/TCP' ] && echo -n $(cat /tmp/etc/%s/id/TCP)", appname, appname))
if current_node and current_node ~= "" and current_node ~= "nil" then
    local n = uci:get_all(appname, current_node)
    if n then
        if tonumber(m:get("@auto_switch[0]", "enable") or 0) == 1 then
            local remarks = api.get_full_node_remarks(n)
            local url = api.url("node_config", current_node)
            tcp_node.description = tcp_node.description .. translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
        end
    end
end
tcp_node:value("nil", translate("Close"))

-- 分流
if (has_v2ray or has_xray) and #nodes_table > 0 then
    local normal_list = {}
    local shunt_list = {}
    for k, v in pairs(nodes_table) do
        if v.node_type == "normal" then
            normal_list[#normal_list + 1] = v
        end
        if v.protocol and v.protocol == "_shunt" then
            shunt_list[#shunt_list + 1] = v
        end
    end
    for k, v in pairs(shunt_list) do
        uci:foreach(appname, "shunt_rules", function(e)
            local id = e[".name"]
            if id and e.remarks then
                o = s:taboption("Main", ListValue, v.id .. "." .. id .. "_node", string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
                o:depends("tcp_node", v.id)
                o:value("nil", translate("Close"))
                o:value("_default", translate("Default"))
                o:value("_direct", translate("Direct Connection"))
                o:value("_blackhole", translate("Blackhole"))
                for k1, v1 in pairs(normal_list) do
                    o:value(v1.id, v1["remark"])
                end
                o.cfgvalue = function(self, section)
                    return m:get(v.id, id) or "nil"
                end
                o.write = function(self, section, value)
                    m:set(v.id, id, value)
                end
            end
        end)

        local id = "default_node"
        o = s:taboption("Main", ListValue, v.id .. "." .. id, string.format('* <a style="color:red">%s</a>', translate("Default")))
        o:depends("tcp_node", v.id)
        o:value("_direct", translate("Direct Connection"))
        o:value("_blackhole", translate("Blackhole"))
        for k1, v1 in pairs(normal_list) do
            o:value(v1.id, v1["remark"])
        end
        o.cfgvalue = function(self, section)
            return m:get(v.id, id) or "nil"
        end
        o.write = function(self, section, value)
            m:set(v.id, id, value)
        end
        
        local id = "main_node"
        o = s:taboption("Main", ListValue, v.id .. "." .. id, string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
        o:depends("tcp_node", v.id)
        o:value("nil", translate("Close"))
        for k1, v1 in pairs(normal_list) do
            o:value(v1.id, v1["remark"])
        end
        o.cfgvalue = function(self, section)
            return m:get(v.id, id) or "nil"
        end
        o.write = function(self, section, value)
            m:set(v.id, id, value)
        end
    end
end

udp_node = s:taboption("Main", ListValue, "udp_node", "<a style='color: red'>" .. translate("UDP Node") .. "</a>")
udp_node:value("nil", translate("Close"))
udp_node:value("tcp", translate("Same as the tcp node"))

s:tab("DNS", translate("DNS"))

if api.is_finded("smartdns") then
    dns_shunt = s:taboption("DNS", ListValue, "dns_shunt", translate("DNS Shunt"))
    dns_shunt:value("dnsmasq", "Dnsmasq")
    dns_shunt:value("smartdns", "SmartDNS")

    group_domestic = s:taboption("DNS", Value, "group_domestic", translate("Domestic group name"))
    group_domestic.placeholder = "local"
    group_domestic:depends("dns_shunt", "smartdns")
    group_domestic.description = translate("You only need to configure domestic DNS packets in SmartDNS and set it redirect or as Dnsmasq upstream, and fill in the domestic DNS group name here.")
    group_domestic.description = group_domestic.description .. string.format('<a href="%s" target="_blank">%s</a>', "https://github.com/luckyyyyy/blog/issues/57", translate("Guide"))
end

o = s:taboption("DNS", Flag, "filter_proxy_ipv6", translate("Filter Proxy Host IPv6"), translate("Experimental feature."))
o.default = "0"

---- DNS Forward Mode
dns_mode = s:taboption("DNS", ListValue, "dns_mode", translate("Filter Mode"))
dns_mode.rmempty = false
dns_mode:reset_values()
if api.is_finded("pdnsd") then
    dns_mode:value("pdnsd", "pdnsd " .. translatef("Requery DNS By %s", translate("TCP Node")))
end
if api.is_finded("dns2socks") then
    dns_mode:value("dns2socks", "dns2socks")
end
if has_v2ray then
    dns_mode:value("v2ray", "V2ray")
end
if has_xray then
    dns_mode:value("xray", "Xray")
end
dns_mode:value("udp", translatef("Requery DNS By %s", "UDP"))

o = s:taboption("DNS", ListValue, "v2ray_dns_mode", " ")
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("fakedns", "FakeDNS")
o:depends("dns_mode", "v2ray")
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
o:depends({dns_mode = "pdnsd"})
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
o:depends({dns_mode = "pdnsd"})
o:depends({dns_mode = "v2ray", v2ray_dns_mode = "tcp"})
o:depends({dns_mode = "v2ray", v2ray_dns_mode = "doh"})
o:depends({dns_mode = "xray", v2ray_dns_mode = "tcp"})
o:depends({dns_mode = "xray", v2ray_dns_mode = "doh"})
o.rmempty = false

if has_chnlist and api.is_finded("chinadns-ng") then
    o = s:taboption("DNS", Flag, "chinadns_ng", translate("ChinaDNS-NG"), translate("The effect is better, but will increase the memory."))
    o.default = "0"
    if api.is_finded("smartdns") then
        o:depends({dns_shunt = "dnsmasq", dns_mode = "dns2socks"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "pdnsd"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "v2ray", v2ray_dns_mode = "tcp"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "v2ray", v2ray_dns_mode = "doh"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "xray", v2ray_dns_mode = "tcp"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "xray", v2ray_dns_mode = "doh"})
        o:depends({dns_shunt = "dnsmasq", dns_mode = "udp"})
    else
        o:depends({dns_mode = "dns2socks"})
        o:depends({dns_mode = "pdnsd"})
        o:depends({dns_mode = "v2ray", v2ray_dns_mode = "tcp"})
        o:depends({dns_mode = "v2ray", v2ray_dns_mode = "doh"})
        o:depends({dns_mode = "xray", v2ray_dns_mode = "tcp"})
        o:depends({dns_mode = "xray", v2ray_dns_mode = "doh"})
        o:depends({dns_mode = "udp"})
    end
end

o = s:taboption("DNS", Button, "clear_ipset", translate("Clear IPSET"), translate("Try this feature if the rule modification does not take effect."))
o.inputstyle = "remove"
function o.write(e, e)
    luci.sys.call("/usr/share/" .. appname .. "/iptables.sh flush_ipset > /dev/null 2>&1 &")
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
socks_node:value("tcp", translate("Same as the tcp node"))

local n = 0
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
