local api = require "luci.model.cbi.passwall2.api.api"
local appname = api.appname
local uci = api.uci
local datatypes = api.datatypes
local has_v2ray = api.is_finded("v2ray")
local has_xray = api.is_finded("xray")

m = Map(appname)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
    nodes_table[#nodes_table + 1] = e
end

local socks_table = {}
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

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- Node
node = s:taboption("Main", ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
node.description = ""
local current_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/TCP' ] && echo -n $(cat /tmp/etc/%s/id/TCP)", appname, appname))
if current_node and current_node ~= "" and current_node ~= "nil" then
    local n = uci:get_all(appname, current_node)
    if n then
        if tonumber(m:get("@auto_switch[0]", "enable") or 0) == 1 then
            local remarks = api.get_full_node_remarks(n)
            local url = api.url("node_config", current_node)
            node.description = node.description .. translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
        end
    end
end
node:value("nil", translate("Close"))

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
                o:depends("node", v.id)
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
        o:depends("node", v.id)
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
        o:depends("node", v.id)
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

s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", ListValue, "dns_protocol", translate("DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("fakedns", "FakeDNS")

---- DoH
o = s:taboption("DNS", Value, "up_trust_doh", translate("DoH request address"))
o:value("https://cloudflare-dns.com/dns-query,1.1.1.1", "CloudFlare")
o:value("https://security.cloudflare-dns.com/dns-query,1.1.1.2", "CloudFlare-Security")
o:value("https://doh.opendns.com/dns-query,208.67.222.222", "OpenDNS")
o:value("https://dns.google/dns-query,8.8.8.8", "Google")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o:value("https://dns.quad9.net/dns-query,9.9.9.9", "Quad9-Recommended")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o.default = "https://cloudflare-dns.com/dns-query,1.1.1.1"
o.validate = doh_validate
o:depends("dns_protocol", "doh")

---- DNS Forward
o = s:taboption("DNS", Value, "dns_forward", translate("Remote DNS"))
--o.description = translate("IP:Port mode acceptable, multi value split with english comma.") .. " " .. translate("If you use dns2socks, only the first one is valid.")
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare DNS)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare DNS)")
o:value("8.8.8.8", "8.8.8.8 (Google DNS)")
o:value("8.8.4.4", "8.8.4.4 (Google DNS)")
o:value("208.67.222.222", "208.67.222.222 (Open DNS)")
o:value("208.67.220.220", "208.67.220.220 (Open DNS)")
o:depends("dns_protocol", "tcp")

o = s:taboption("DNS", Value, "dns_client_ip", translate("EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
                translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends("dns_protocol", "tcp")
o:depends("dns_protocol", "doh")

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "close_log", translate("Close Node Log"))
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", translate("Log Level"))
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

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
    node:value(v.id, v["remark"])
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
