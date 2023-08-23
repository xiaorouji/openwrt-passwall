local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("naive") then
	return
end

local option_prefix = "naive_"

local function option_name(name)
	return option_prefix .. name
end

local function rm_prefix_cfgvalue(self, section)
	if self.option:find(option_prefix) == 1 then
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end
local function rm_prefix_write(self, section, value)
	if self.option:find(option_prefix) == 1 then
		m:set(section, self.option:sub(1 + #option_prefix), value)
	end
end

-- [[ Naive ]]

s.fields["type"]:value("Naiveproxy", translate("NaiveProxy"))

o = s:option(ListValue, "naive_protocol", translate("Protocol"))
o:value("https", translate("HTTPS"))
o:value("quic", translate("QUIC"))

o = s:option(Value, "naive_address", translate("Address (Support Domain Name)"))

o = s:option(Value, "naive_port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "naive_username", translate("Username"))

o = s:option(Value, "naive_password", translate("Password"))
o.password = true

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "Naiveproxy"
			end
		else
			s.fields[key]:depends({ type = "Naiveproxy" })
		end
	end
end
