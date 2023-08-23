local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("brook") then
	return
end

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
	if self.option:find(option_prefix) == 1 then
		m:set(section, self.option:sub(1 + #option_prefix), value)
	end
end

-- [[ Brook ]]

s.fields["type"]:value("Brook", translate("Brook"))

o = s:option(Value, "brook_port", translate("Listen Port"))
o.datatype = "port"

o = s:option(ListValue, "brook_protocol", translate("Protocol"))
o:value("server", "Brook")
o:value("wsserver", "WebSocket")

--o = s:option(Flag, "brook_tls", translate("Use TLS"))
--o:depends({ brook_protocol = "wsserver" })

o = s:option(Value, "brook_password", translate("Password"))
o.password = true

o = s:option(Value, "brook_ws_path", translate("WebSocket Path"))
o:depends({ brook_protocol = "wsserver" })

o = s:option(Flag, "brook_log", translate("Log"))
o.default = "1"

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "Brook"
			end
		else
			s.fields[key]:depends({ type = "Brook" })
		end
	end
end