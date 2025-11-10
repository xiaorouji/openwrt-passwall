local api = require "luci.passwall.api"
local appname = "passwall"
local datatypes = api.datatypes

m = Map(appname, "Sing-Box/Xray " .. translate("Shunt Rule"))
m.redirect = api.url("rule")
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

function m.on_before_save(self)
	m:set("@global[0]", "flush_set", "1")
end

-- Add inline CSS to map description
m.description = (m.description or "") .. "\n" .. [[
	<style>
		div[id^="cbid.passwall."] .cbi-value-field {
			display: flex;
			flex-wrap: wrap;
			gap: 1em;
		}
		div[id^="cbid.passwall."] .cbi-checkbox {
			display: inline-flex;
			align-items: center;
		}
	</style>
]]

function clean_text(text)
	local nbsp = string.char(0xC2, 0xA0) -- 不间断空格（U+00A0）
	local fullwidth_space = string.char(0xE3, 0x80, 0x80) -- 全角空格（U+3000）
	return text
		:gsub("\t", " ")
		:gsub(nbsp, " ")
		:gsub(fullwidth_space, " ")
		:gsub("^%s+", "")
		:gsub("%s+$", "\n")
		:gsub("\r\n", "\n")
		:gsub("[ \t]*\n[ \t]*", "\n")
end

s = m:section(NamedSection, arg[1], "shunt_rules", "")
s.addremove = false
s.dynamic = false

remarks = s:option(Value, "remarks", translate("Remarks"))
remarks.default = arg[1]
remarks.rmempty = false

protocol = s:option(MultiValue, "protocol", translate("Protocol"))
protocol:value("http")
protocol:value("tls")
protocol:value("bittorrent")
protocol.widget = "checkbox"
protocol.default = nil

o = s:option(MultiValue, "inbound", translate("Inbound Tag"))
o:value("tproxy", translate("Transparent proxy"))
o:value("socks", "Socks")
o.widget = "checkbox"
o.default = nil

network = s:option(ListValue, "network", translate("Network"))
network:value("tcp,udp", "TCP UDP")
network:value("tcp", "TCP")
network:value("udp", "UDP")

source = s:option(DynamicList, "source", translate("Source"))
source.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("GeoIP") .. ": geoip:private"
.. "</li></ul>"
source.cast = "string"
source.cfgvalue = function(self, section)
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
source.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and v:find("geoip:") and v:find("geoip:") == 1 then
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

source.write = dynamicList_write

sourcePort = s:option(Value, "sourcePort", translate("Source port"))

port = s:option(Value, "port", translate("port"))

domain_list = s:option(TextValue, "domain_list", translate("Domain"))
domain_list.rows = 10
domain_list.wrap = "off"
domain_list.validate = function(self, value)
	local hosts= {}
	value = clean_text(value)
	string.gsub(value, "[^\r\n]+", function(w) table.insert(hosts, w) end)
	for index, host in ipairs(hosts) do
		local flag = 1
		local tmp_host = host
		if not host:find("#") and host:find("%s") then
		elseif host:find("regexp:") and host:find("regexp:") == 1 then
			flag = 0
		elseif host:find("domain:.") and host:find("domain:.") == 1 then
			tmp_host = host:gsub("domain:", "")
		elseif host:find("full:.") and host:find("full:.") == 1 then
			tmp_host = host:gsub("full:", "")
		elseif host:find("geosite:") and host:find("geosite:") == 1 then
			flag = 0
		elseif host:find("ext:") and host:find("ext:") == 1 then
			flag = 0
		elseif host:find("#") and host:find("#") == 1 then
			flag = 0
		end
		if flag == 1 then
			if not datatypes.hostname(tmp_host) then
				return nil, tmp_host .. " " .. translate("Not valid domain name, please re-enter!")
			end
		end
	end
	return value
end
domain_list.description = "<br /><ul><li>" .. translate("Plaintext: If this string matches any part of the targeting domain, this rule takes effet. Example: rule 'sina.com' matches targeting domain 'sina.com', 'sina.com.cn' and 'www.sina.com', but not 'sina.cn'.")
.. "</li><li>" .. translate("Regular expression: Begining with 'regexp:', the rest is a regular expression. When the regexp matches targeting domain, this rule takes effect. Example: rule 'regexp:\\.goo.*\\.com$' matches 'www.google.com' and 'fonts.googleapis.com', but not 'google.com'.")
.. "</li><li>" .. translate("Subdomain (recommended): Begining with 'domain:' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule 'domain:v2ray.com' matches 'www.v2ray.com', 'v2ray.com', but not 'xv2ray.com'.")
.. "</li><li>" .. translate("Full domain: Begining with 'full:' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule 'domain:v2ray.com' matches 'v2ray.com', but not 'www.v2ray.com'.")
.. "</li><li>" .. translate("Pre-defined domain list: Begining with 'geosite:' and the rest is a name, such as geosite:google or geosite:cn.")
.. "</li><li>" .. translate("Annotation: Begining with #")
.. "</li></ul>"
ip_list = s:option(TextValue, "ip_list", "IP")
ip_list.rows = 10
ip_list.wrap = "off"
ip_list.validate = function(self, value)
	local ipmasks= {}
	value = clean_text(value)
	string.gsub(value, "[^\r\n]+", function(w) table.insert(ipmasks, w) end)
	for index, ipmask in ipairs(ipmasks) do
		if ipmask:find("geoip:") and ipmask:find("geoip:") == 1 and not ipmask:find("%s") then
		elseif ipmask:find("ext:") and ipmask:find("ext:") == 1 and not ipmask:find("%s") then
		elseif ipmask:find("#") and ipmask:find("#") == 1 then
		else
			if not (datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask)) then
				return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
			end
		end
	end
	return value
end
ip_list.description = "<br /><ul><li>" .. translate("IP: such as '127.0.0.1'.")
.. "</li><li>" .. translate("CIDR: such as '127.0.0.0/8'.")
.. "</li><li>" .. translate("GeoIP: such as 'geoip:cn'. It begins with geoip: (lower case) and followed by two letter of country code.")
.. "</li><li>" .. translate("Annotation: Begining with #")
.. "</li></ul>"

return m
