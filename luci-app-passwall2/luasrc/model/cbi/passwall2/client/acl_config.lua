local api = require "luci.model.cbi.passwall2.api.api"
local appname = api.appname
local sys = api.sys

m = Map(appname)

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

node = s:option(ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
node.default = "default"
node:value("default", translate("Default"))

for k, v in pairs(nodes_table) do
    node:value(v.id, v["remark"])
end

o = s:option(ListValue, "dns_protocol", translate("DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:depends({ node = "default",  ['!reverse'] = true })

---- DNS Forward
o = s:option(Value, "dns_forward", translate("Remote DNS"))
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare DNS)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare DNS)")
o:value("8.8.8.8", "8.8.8.8 (Google DNS)")
o:value("8.8.4.4", "8.8.4.4 (Google DNS)")
o:value("208.67.222.222", "208.67.222.222 (Open DNS)")
o:value("208.67.220.220", "208.67.220.220 (Open DNS)")
o:depends("dns_protocol", "tcp")

---- DoH
o = s:option(Value, "dns_doh", translate("DoH request address"))
o:value("https://cloudflare-dns.com/dns-query,1.1.1.1", "CloudFlare")
o:value("https://security.cloudflare-dns.com/dns-query,1.1.1.2", "CloudFlare-Security")
o:value("https://doh.opendns.com/dns-query,208.67.222.222", "OpenDNS")
o:value("https://dns.google/dns-query,8.8.8.8", "Google")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o:value("https://dns.quad9.net/dns-query,9.9.9.9", "Quad9-Recommended")
o:value("https://dns.adguard.com/dns-query,176.103.130.130", "AdGuard")
o.default = "https://cloudflare-dns.com/dns-query,1.1.1.1"
o.validate = function(self, value, t)
    if value ~= "" then
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
o:depends("dns_protocol", "doh")

o = s:option(Value, "dns_client_ip", translate("EDNS Client Subnet"))
o.datatype = "ipaddr"
o:depends("dns_protocol", "tcp")
o:depends("dns_protocol", "doh")

return m
