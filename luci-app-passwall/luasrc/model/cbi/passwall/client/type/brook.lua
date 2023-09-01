local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("brook") then
	return
end

local type_name = "Brook"

local option_prefix = "brook_"

local function option_name(name)
	return option_prefix .. name
end

local function rm_prefix_cfgvalue(self, section)
	if self.option:find(option_prefix) == 1 then
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end
local function rm_prefix_write(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:set(section, self.option:sub(1 + #option_prefix), value)
		end
	end
end
local function rm_prefix_remove(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:del(section, self.option:sub(1 + #option_prefix))
		end
	end
end

-- [[ Brook ]]

s.fields["type"]:value(type_name, translate("Brook"))

o = s:option(ListValue, option_name("protocol"), translate("Protocol"))
o:value("client", translate("Brook"))
o:value("wsclient", translate("WebSocket"))

o = s:option(Value, option_name("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, option_name("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, option_name("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [option_name("protocol")] = "wsclient" })

o = s:option(Flag, option_name("tls"), translate("Use TLS"))
o:depends({ [option_name("protocol")] = "wsclient" })

o = s:option(Value, option_name("password"), translate("Password"))
o.password = true

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
			s.fields[key].remove = rm_prefix_remove
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = type_name
			end
		else
			s.fields[key]:depends({ type = type_name })
		end
	end
end
