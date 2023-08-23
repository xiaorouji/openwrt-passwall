local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("microsocks") then
	return
end

local option_prefix = "socks_"

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

-- [[ microsocks ]]

s.fields["type"]:value("Socks", translate("Socks"))

o = s:option(Value, "socks_port", "socks" ..  translate("Listen Port"))
o.datatype = "port"

o = s:option(Flag, "socks_auth", translate("Auth"))
o.validate = function(self, value, t)
	if value and value == "1" then
		local user_v = s.fields["socks_username"]:formvalue(t) or ""
		local pass_v = s.fields["socks_password"]:formvalue(t) or ""
		if user_v == "" or pass_v == "" then
			return nil, translate("Username and Password must be used together!")
		end
	end
	return value
end

o = s:option(Value, "socks_username", translate("Username"))
o:depends({ socks_auth = true })

o = s:option(Value, "socks_password", translate("Password"))
o.password = true
o:depends({ socks_auth = true })

o = s:option(Flag, "socks_log", translate("Log"))
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
				deps[index]["type"] = "Socks"
			end
		else
			s.fields[key]:depends({ type = "Socks" })
		end
	end
end